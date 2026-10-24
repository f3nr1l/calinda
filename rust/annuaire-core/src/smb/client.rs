// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! An SMB 3 client session on one share: negotiation, Kerberos session, tree, and the
//! exchange of compound requests in batches (ADR 0017, § 1 to 3). SMB 2.1 and 2.0.2, signed
//! only, when the options allow them (ADR 0021).
//!
//! Blocking, like the Python session it replaces: a reader thread only cuts the TCP stream
//! into frames; the calling thread writes a batch of compounds, then reads the frames,
//! decrypts and checks them, and matches the responses to their requests by message id.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::auth::{AuthError, Authenticator};
use super::crypto::{self, SessionKeys};
use super::msg::{
    self, CAP_ENCRYPTION, CAP_LARGE_MTU, HEADER_LEN, Header, Malformed, NegotiateOffer, Request,
    SESSION_FLAG_ENCRYPT_DATA, SESSION_FLAG_IS_GUEST, SESSION_FLAG_IS_NULL,
    SHARE_FLAG_ENCRYPT_DATA, cipher, command, dialect, flag, signing, status,
};
use super::wire::{Writer, bytes_at};

/// Requests in flight at most (Samba grants at least that many credits: ADR 0002).
pub const MAX_IN_FLIGHT: u32 = 60;
/// Credits asked for with each request.
const CREDIT_REQUEST: u16 = 64;
/// The delay allowed for the responses of a batch grows by an eighth of the base delay for
/// each compound beyond the first, up to `MAX_ALLOWANCE` times the base (J8.8): a compound
/// answers when all its requests are done, and a server with saturated storage takes them
/// one after the other.
const ALLOWANCE_STEP: u32 = 8;
const MAX_ALLOWANCE: u32 = 4;

/// Trials of the lab (J8.8): the batch of writes, counted from 1, that is not waited for.
static WRITE_BATCH_NOT_WAITED: AtomicU64 = AtomicU64::new(0);

/// Trials of the lab (J8.8): the `n`-th batch of writes (`SET_INFO`) sent from now on, by any
/// session of the process, is not waited for: its requests reach the server, which writes
/// them, and the session times out as with a server too slow to answer. Once; 0 cancels it.
/// Not for the unit tests, which run side by side (the fake server has its `pause`).
#[doc(hidden)]
pub fn time_out_write_batch(n: u64) {
    WRITE_BATCH_NOT_WAITED.store(n, Ordering::SeqCst);
}

/// Is this batch of writes the one not to wait for? (`time_out_write_batch`)
fn not_waited() -> bool {
    let mut n = WRITE_BATCH_NOT_WAITED.load(Ordering::SeqCst);
    while n > 0 {
        match WRITE_BATCH_NOT_WAITED.compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => return n == 1,
            Err(now) => n = now,
        }
    }
    false
}
const PORT: u16 = 445;

/// What went wrong, as `sysvol._traduire` sorts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorKind {
    /// No TCP connection, or the connection was lost.
    Unreachable,
    /// The server did not answer in time.
    Timeout,
    /// No usable Kerberos ticket.
    Ticket,
    /// Kerberos refused (by GSSAPI or by the server).
    Kerberos,
    /// The server cannot encrypt (no SMB 3 cipher in common).
    NoEncryption,
    /// The server knows SMB 2.x only, which the options do not allow (signing only).
    Smb2Only,
    /// The server refused an operation: its NTSTATUS.
    Status(u32),
    /// A response the client cannot accept (malformed, bad signature, not encrypted…).
    Protocol,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbError {
    pub kind: ErrorKind,
    pub detail: String,
}

impl SmbError {
    pub fn new(kind: ErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    fn protocol(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::Protocol, detail)
    }

    /// The NTSTATUS of a refused operation.
    pub fn status(&self) -> Option<u32> {
        match self.kind {
            ErrorKind::Status(s) => Some(s),
            _ => None,
        }
    }
}

impl std::fmt::Display for SmbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::Status(s) => write!(f, "NTSTATUS 0x{s:08X}: {}", self.detail),
            _ => write!(f, "{:?}: {}", self.kind, self.detail),
        }
    }
}

impl std::error::Error for SmbError {}

impl From<Malformed> for SmbError {
    fn from(m: Malformed) -> Self {
        Self::protocol(m.to_string())
    }
}

impl From<openssl::error::ErrorStack> for SmbError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::protocol(format!("OpenSSL: {e}"))
    }
}

impl From<AuthError> for SmbError {
    fn from(e: AuthError) -> Self {
        match e {
            AuthError::Ticket(d) => Self::new(ErrorKind::Ticket, d),
            AuthError::Kerberos(d) => Self::new(ErrorKind::Kerberos, d),
        }
    }
}

fn io_error(e: &io::Error) -> SmbError {
    let kind = match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ErrorKind::Timeout,
        _ => ErrorKind::Unreachable,
    };
    SmbError::new(kind, e.to_string())
}

/// A response, whole (header and body: the parsers of `msg` count offsets from the header).
#[derive(Debug, Clone)]
pub struct Response {
    pub header: Header,
    pub msg: Vec<u8>,
}

impl Response {
    pub fn status(&self) -> u32 {
        self.header.status
    }

    /// The response, or the refusal of the server as an error.
    pub fn ok(&self) -> Result<&Self, SmbError> {
        match self.header.status {
            status::SUCCESS => Ok(self),
            s => Err(SmbError::new(
                ErrorKind::Status(s),
                command_name(self.header.command),
            )),
        }
    }
}

fn command_name(c: u16) -> &'static str {
    match c {
        command::NEGOTIATE => "NEGOTIATE",
        command::SESSION_SETUP => "SESSION_SETUP",
        command::TREE_CONNECT => "TREE_CONNECT",
        command::CREATE => "CREATE",
        command::CLOSE => "CLOSE",
        command::READ => "READ",
        command::WRITE => "WRITE",
        command::IOCTL => "IOCTL",
        command::QUERY_DIRECTORY => "QUERY_DIRECTORY",
        command::QUERY_INFO => "QUERY_INFO",
        command::SET_INFO => "SET_INFO",
        _ => "request",
    }
}

/// Session options.
#[derive(Debug, Clone)]
pub struct Options {
    /// Require SMB 3 encryption (default); otherwise signing only.
    pub encrypt: bool,
    /// Also offer SMB 2.1 and 2.0.2, signed only, for DCs that know no SMB 3 (profile
    /// option, ADR 0021). SMB 3 stays encrypted if `encrypt` asks for it.
    pub smb2: bool,
    /// Connection and response delay.
    pub timeout: Duration,
    /// TCP port (445; another one for the tests).
    pub port: u16,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            encrypt: true,
            smb2: false,
            timeout: Duration::from_secs(30),
            port: PORT,
        }
    }
}

/// What the session negotiated, for the logs and the tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub dialect: u16,
    pub cipher: Option<u16>,
    pub signing: u16,
    pub encrypted: bool,
}

#[derive(Default)]
struct Inbox {
    frames: VecDeque<Vec<u8>>,
    closed: Option<io::Error>,
}

#[derive(Default)]
struct Shared {
    inbox: Mutex<Inbox>,
    ready: Condvar,
}

/// Cuts the stream into direct-TCP frames (MS-SMB2 2.1) until it closes.
fn read_frames(mut stream: TcpStream, shared: Arc<Shared>) {
    loop {
        let mut head = [0u8; 4];
        let frame = stream.read_exact(&mut head).and_then(|()| {
            let [zero, a, b, c] = head;
            if zero != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "not an SMB frame",
                ));
            }
            let len = (a as usize) << 16 | (b as usize) << 8 | c as usize;
            let mut frame = vec![0u8; len];
            stream.read_exact(&mut frame)?;
            Ok(frame)
        });
        let mut inbox = shared.inbox.lock().unwrap_or_else(PoisonError::into_inner);
        let end = match frame {
            Ok(f) => {
                inbox.frames.push_back(f);
                false
            }
            Err(e) => {
                inbox.closed = Some(e);
                true
            }
        };
        drop(inbox);
        shared.ready.notify_all();
        if end {
            return;
        }
    }
}

/// An open session on `\\<server>\<share>`.
pub struct Client {
    pub server: String,
    stream: TcpStream,
    shared: Arc<Shared>,
    reader: Option<JoinHandle<()>>,
    timeout: Duration,
    dialect: u16,
    cipher: Option<u16>,
    signing: u16,
    keys: Option<SessionKeys>,
    session_id: u64,
    tree_id: u32,
    encrypt: bool,
    large_mtu: bool,
    next_id: u64,
    credits: u32,
    nonce: u64,
    nonce_salt: [u8; 4],
    responses: HashMap<u64, Response>,
    pub max_read: u32,
    pub max_write: u32,
    /// Batches sent (one round trip each) since the session opened.
    pub round_trips: u64,
    /// An error of the session (time, connection, protocol) left requests without their
    /// responses: their message ids and credits are lost, the session is not used again.
    broken: Option<String>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("server", &self.server)
            .field("dialect", &self.dialect)
            .field("encrypt", &self.encrypt)
            .finish_non_exhaustive()
    }
}

fn random<const N: usize>() -> Result<[u8; N], SmbError> {
    let mut b = [0u8; N];
    openssl::rand::rand_bytes(&mut b)?;
    Ok(b)
}

impl Client {
    /// Connects to `server`, negotiates, authenticates with `auth` and connects the tree
    /// `share`. Blocking.
    pub fn connect(
        server: &str,
        share: &str,
        options: &Options,
        auth: &mut dyn Authenticator,
    ) -> Result<Client, SmbError> {
        let mut client = Self::open(server, options)?;
        let offered_encrypt = client.negotiate(options)?;
        client.authenticate(auth, offered_encrypt)?;
        client.tree_connect(&format!("\\\\{server}\\{share}"))?;
        // Round trips are those of the work done on the tree, as in the Python session.
        client.round_trips = 0;
        Ok(client)
    }

    fn open(server: &str, options: &Options) -> Result<Client, SmbError> {
        let addresses = (server, options.port)
            .to_socket_addrs()
            .map_err(|e| SmbError::new(ErrorKind::Unreachable, format!("{server}: {e}")))?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{server}: no address"));
        let mut stream = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, options.timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let stream = stream.ok_or_else(|| io_error(&last))?;
        stream.set_nodelay(true).map_err(|e| io_error(&e))?;
        let shared = Arc::new(Shared::default());
        let reading = stream.try_clone().map_err(|e| io_error(&e))?;
        let for_reader = Arc::clone(&shared);
        let reader = std::thread::Builder::new()
            .name("smb-reader".into())
            .spawn(move || read_frames(reading, for_reader))
            .map_err(|e| io_error(&e))?;
        Ok(Client {
            server: server.to_owned(),
            stream,
            shared,
            reader: Some(reader),
            timeout: options.timeout,
            dialect: 0,
            cipher: None,
            signing: signing::AES_CMAC,
            keys: None,
            session_id: 0,
            tree_id: 0,
            encrypt: false,
            large_mtu: false,
            next_id: 0,
            credits: 1,
            nonce: u64::from_le_bytes(random()?),
            nonce_salt: random()?,
            responses: HashMap::new(),
            max_read: 65536,
            max_write: 65536,
            round_trips: 0,
            broken: None,
        })
    }

    pub fn negotiated(&self) -> Negotiated {
        Negotiated {
            dialect: self.dialect,
            cipher: self.cipher,
            signing: self.signing,
            encrypted: self.encrypt,
        }
    }

    /// Credits granted and not yet spent.
    pub fn credits(&self) -> u32 {
        self.credits
    }

    pub fn large_mtu(&self) -> bool {
        self.large_mtu
    }

    /// Can the session still be used? Not after an error of the session: a caller opens a
    /// new one (J8.8).
    pub fn usable(&self) -> bool {
        self.broken.is_none()
    }

    /// The base delay of the responses from now on (probes and tests that make a server
    /// look slow).
    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    // -- Set-up ------------------------------------------------------------------------

    /// NEGOTIATE; returns the preauthentication hash of the connection.
    fn negotiate(&mut self, options: &Options) -> Result<[u8; 64], SmbError> {
        let mut dialects = vec![dialect::SMB300, dialect::SMB302, dialect::SMB311];
        if options.smb2 {
            dialects.splice(0..0, [dialect::SMB202, dialect::SMB210]);
        }
        let offer = NegotiateOffer {
            dialects,
            capabilities: CAP_LARGE_MTU | CAP_ENCRYPTION,
            client_guid: random()?,
            salt: random()?,
            ciphers: vec![cipher::AES_128_GCM, cipher::AES_128_CCM],
            signing: vec![signing::AES_GMAC, signing::AES_CMAC],
        };
        let request = msg::negotiate(&offer);
        let (sent, id) = self.plain_message(&request, 0)?;
        let response = self.single(&sent, id)?;
        // No dialect in common: a server of SMB 2.x only, when the options leave them out.
        if response.status() == status::NOT_SUPPORTED && !options.smb2 {
            return Err(SmbError::new(
                ErrorKind::Smb2Only,
                "no SMB 3 dialect in common (NEGOTIATE: STATUS_NOT_SUPPORTED)",
            ));
        }
        response.ok()?;
        let n = msg::parse_negotiate(&response.msg)?;
        if dialect::is_smb2(n.dialect) && !options.smb2 {
            return Err(SmbError::new(
                ErrorKind::Smb2Only,
                format!("dialect 0x{:04X} not offered", n.dialect),
            ));
        }
        if !offer.dialects.contains(&n.dialect) {
            return Err(SmbError::protocol(format!(
                "dialect 0x{:04X} not offered",
                n.dialect
            )));
        }
        self.dialect = n.dialect;
        self.max_read = n.max_read;
        self.max_write = n.max_write;
        self.large_mtu = n.capabilities & CAP_LARGE_MTU != 0;
        if n.dialect == dialect::SMB311 {
            if !n.preauth_sha512 {
                return Err(SmbError::protocol("no SHA-512 preauthentication integrity"));
            }
            self.cipher = n.cipher.filter(|c| offer.ciphers.contains(c));
            self.signing = match n.signing {
                Some(s) if offer.signing.contains(&s) => s,
                _ => signing::AES_CMAC,
            };
        } else if dialect::is_smb2(n.dialect) {
            // Signed only, by HMAC-SHA256 with the session key (MS-SMB2 3.1.4.1).
            self.cipher = None;
            self.signing = signing::HMAC_SHA256;
        } else {
            self.cipher = (n.capabilities & CAP_ENCRYPTION != 0).then_some(cipher::AES_128_CCM);
            self.signing = signing::AES_CMAC;
        }
        let encrypt = options.encrypt && !dialect::is_smb2(n.dialect);
        if encrypt && self.cipher.is_none() {
            return Err(SmbError::new(
                ErrorKind::NoEncryption,
                format!("dialect 0x{:04X} without a common cipher", n.dialect),
            ));
        }
        // Encryption is final once the session and tree flags are known.
        self.encrypt = encrypt;
        let hash = crypto::preauth_next(&[0; 64], &sent)?;
        Ok(crypto::preauth_next(&hash, &response.msg)?)
    }

    /// SESSION_SETUP until the server accepts, then keys and the check of the signature of
    /// its last response.
    fn authenticate(
        &mut self,
        auth: &mut dyn Authenticator,
        connection_hash: [u8; 64],
    ) -> Result<(), SmbError> {
        let mut hash = connection_hash;
        let mut token = auth
            .step(None)?
            .ok_or_else(|| SmbError::new(ErrorKind::Kerberos, "no initial token"))?;
        loop {
            let request = msg::session_setup(&token);
            let (sent, id) = self.plain_message(&request, self.session_id)?;
            hash = crypto::preauth_next(&hash, &sent)?;
            let response = self.single(&sent, id)?;
            self.session_id = response.header.session_id;
            match response.status() {
                status::MORE_PROCESSING_REQUIRED => {
                    hash = crypto::preauth_next(&hash, &response.msg)?;
                    let r = msg::parse_session_setup(&response.msg)?;
                    token = auth.step(Some(&r.token))?.ok_or_else(|| {
                        SmbError::new(
                            ErrorKind::Kerberos,
                            "the server asks for more, Kerberos has no more",
                        )
                    })?;
                }
                status::SUCCESS => {
                    let r = msg::parse_session_setup(&response.msg)?;
                    if !auth.complete() {
                        auth.step(Some(&r.token))?;
                    }
                    if !auth.complete() {
                        return Err(SmbError::new(
                            ErrorKind::Kerberos,
                            "the server accepted a session Kerberos did not complete",
                        ));
                    }
                    if r.session_flags & (SESSION_FLAG_IS_GUEST | SESSION_FLAG_IS_NULL) != 0 {
                        return Err(SmbError::new(
                            ErrorKind::Kerberos,
                            "guest or anonymous session",
                        ));
                    }
                    let keys = crypto::session_keys(self.dialect, &auth.session_key()?, &hash)?;
                    let signed = response.header.flags & flag::SIGNED != 0;
                    if !signed || !crypto::verify(self.signing, &keys.signing, &response.msg)? {
                        return Err(SmbError::new(
                            ErrorKind::Kerberos,
                            "the last SESSION_SETUP response is not signed with the session key",
                        ));
                    }
                    self.keys = Some(keys);
                    if r.session_flags & SESSION_FLAG_ENCRYPT_DATA != 0 {
                        if self.cipher.is_none() {
                            return Err(SmbError::new(
                                ErrorKind::NoEncryption,
                                "session requires encryption",
                            ));
                        }
                        self.encrypt = true;
                    }
                    return Ok(());
                }
                s => {
                    return Err(SmbError::new(
                        ErrorKind::Kerberos,
                        format!("SESSION_SETUP refused: NTSTATUS 0x{s:08X}"),
                    ));
                }
            }
        }
    }

    fn tree_connect(&mut self, path: &str) -> Result<(), SmbError> {
        let responses = self.exchange(&[vec![msg::tree_connect(path)]])?;
        let response = responses
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(|| SmbError::protocol("no TREE_CONNECT response"))?;
        response.ok()?;
        let tree = msg::parse_tree_connect(&response.msg)?;
        self.tree_id = response.header.tree_id;
        if tree.share_flags & SHARE_FLAG_ENCRYPT_DATA != 0 && !self.encrypt {
            if self.cipher.is_none() {
                return Err(SmbError::new(
                    ErrorKind::NoEncryption,
                    "share requires encryption",
                ));
            }
            self.encrypt = true;
        }
        Ok(())
    }

    // -- Messages ------------------------------------------------------------------------

    /// One unsigned, unencrypted message (negotiation and session setup).
    fn plain_message(
        &mut self,
        request: &Request,
        session_id: u64,
    ) -> Result<(Vec<u8>, u64), SmbError> {
        let id = self.next_id;
        // CreditCharge is reserved in 2.0.2 (MS-SMB2 2.2.1.2).
        let charge = if matches!(self.dialect, 0 | dialect::SMB202) {
            0
        } else {
            1
        };
        let mut w = Writer::new();
        Header {
            credit_charge: charge,
            command: request.command,
            credits: CREDIT_REQUEST,
            message_id: id,
            session_id,
            ..Header::default()
        }
        .write(&mut w);
        w.bytes(&request.body);
        self.next_id += 1;
        self.credits = self.credits.saturating_sub(1);
        Ok((w.buf, id))
    }

    /// Sends one message and waits for its response.
    fn single(&mut self, message: &[u8], id: u64) -> Result<Response, SmbError> {
        self.write_frame(message)?;
        self.wait(&[vec![id]])?;
        self.responses
            .remove(&id)
            .ok_or_else(|| SmbError::protocol("response lost"))
    }

    /// The bytes of a compound: each message with its header, padded to 8 bytes before the
    /// next one, related to the first, signed if the session signs; and the message ids.
    fn compound(&mut self, requests: &[Request]) -> Result<(Vec<u8>, Vec<u64>), SmbError> {
        let sign = !self.encrypt && self.keys.is_some();
        let mut out = Vec::new();
        let mut ids = Vec::with_capacity(requests.len());
        let count = requests.len();
        for (i, request) in requests.iter().enumerate() {
            let charge = request.credit_charge();
            let mut flags = 0;
            if i > 0 {
                flags |= flag::RELATED_OPERATIONS;
            }
            if sign {
                flags |= flag::SIGNED;
            }
            let mut w = Writer::new();
            Header {
                credit_charge: if self.dialect == dialect::SMB202 {
                    0
                } else {
                    charge
                },
                command: request.command,
                credits: CREDIT_REQUEST,
                flags,
                message_id: self.next_id,
                tree_id: self.tree_id,
                session_id: self.session_id,
                ..Header::default()
            }
            .write(&mut w);
            w.bytes(&request.body);
            if i + 1 < count {
                w.align(8);
                let len = super::wire::to_u32(w.len());
                w.set_u32(20, len);
            }
            if sign {
                if let Some(keys) = &self.keys {
                    crypto::sign(self.signing, &keys.signing, &mut w.buf)?;
                }
            }
            ids.push(self.next_id);
            self.next_id += u64::from(charge);
            self.credits = self.credits.saturating_sub(u32::from(charge));
            out.extend_from_slice(&w.buf);
        }
        Ok((out, ids))
    }

    fn write_frame(&mut self, plain: &[u8]) -> Result<(), SmbError> {
        let frame = match (self.encrypt, &self.keys, self.cipher) {
            (true, Some(keys), Some(c)) => {
                self.nonce = self.nonce.wrapping_add(1);
                let mut nonce = [0u8; 16];
                for (slot, byte) in nonce.iter_mut().zip(
                    self.nonce
                        .to_le_bytes()
                        .iter()
                        .chain(self.nonce_salt.iter()),
                ) {
                    *slot = *byte;
                }
                crypto::encrypt(c, &keys.encryption, self.session_id, &nonce, plain)?
            }
            _ => plain.to_vec(),
        };
        let len = frame.len();
        if len > 0x00FF_FFFF {
            return Err(SmbError::protocol("message too long"));
        }
        let mut out = Vec::with_capacity(len + 4);
        out.push(0);
        out.extend_from_slice(
            super::wire::to_u32(len)
                .to_be_bytes()
                .get(1..)
                .unwrap_or(&[]),
        );
        out.extend_from_slice(&frame);
        self.stream.write_all(&out).map_err(|e| io_error(&e))
    }

    /// Waits until a response to each id of each compound has arrived (interim responses are
    /// not one). The delay runs from the last frame received, not from the sending: a slow
    /// server that answers one compound after the other is waited for, and it grows with the
    /// compounds still awaited (`allowance`).
    fn wait(&mut self, compounds: &[Vec<u64>]) -> Result<(), SmbError> {
        let started = Instant::now();
        let mut deadline = started + allowance(self.timeout, compounds.len());
        loop {
            let awaited = compounds
                .iter()
                .filter(|ids| !ids.iter().all(|id| self.responses.contains_key(id)))
                .count();
            if awaited == 0 {
                return Ok(());
            }
            let frame = {
                let mut inbox = self
                    .shared
                    .inbox
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                loop {
                    if let Some(f) = inbox.frames.pop_front() {
                        break f;
                    }
                    if let Some(e) = &inbox.closed {
                        return Err(SmbError::new(
                            ErrorKind::Unreachable,
                            format!("connection closed: {e}"),
                        ));
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(SmbError::new(
                            ErrorKind::Timeout,
                            format!(
                                "no response from {} in {:?} ({awaited} of {} compound(s) awaited for {:?})",
                                self.server,
                                allowance(self.timeout, awaited),
                                compounds.len(),
                                now - started,
                            ),
                        ));
                    }
                    inbox = self
                        .shared
                        .ready
                        .wait_timeout(inbox, deadline - now)
                        .unwrap_or_else(PoisonError::into_inner)
                        .0;
                }
            };
            self.receive(&frame)?;
            let awaited = compounds
                .iter()
                .filter(|ids| !ids.iter().all(|id| self.responses.contains_key(id)))
                .count();
            deadline = Instant::now() + allowance(self.timeout, awaited);
        }
    }

    /// Decrypts and checks a frame, then files each response of its chain.
    fn receive(&mut self, frame: &[u8]) -> Result<(), SmbError> {
        let established = self.keys.is_some();
        let (plain, encrypted) = match crypto::transform_session(frame) {
            Some(session) => {
                let (Some(keys), Some(c)) = (&self.keys, self.cipher) else {
                    return Err(SmbError::protocol(
                        "encrypted response before the session keys",
                    ));
                };
                if session != self.session_id {
                    return Err(SmbError::protocol("encrypted response for another session"));
                }
                let plain = crypto::decrypt(c, &keys.decryption, frame)
                    .ok_or_else(|| SmbError::protocol("response that does not decrypt"))?;
                (plain, true)
            }
            None => (frame.to_vec(), false),
        };
        let mut at = 0usize;
        loop {
            let rest = plain.get(at..).unwrap_or(&[]);
            let header =
                Header::read(rest).ok_or_else(|| SmbError::protocol("not an SMB2 response"))?;
            let len = match header.next_command as usize {
                0 => rest.len(),
                n if n >= HEADER_LEN && n <= rest.len() => n,
                _ => return Err(SmbError::protocol("bad NextCommand in a response")),
            };
            let message = bytes_at(rest, 0, len).unwrap_or(rest).to_vec();
            self.credits = self.credits.saturating_add(u32::from(header.credits));
            let interim =
                header.status == status::PENDING && header.flags & flag::ASYNC_COMMAND != 0;
            if established && !encrypted && header.command != command::SESSION_SETUP {
                if self.encrypt {
                    return Err(SmbError::protocol("response not encrypted"));
                }
                if header.flags & flag::SIGNED != 0 {
                    let key = self.keys.as_ref().map(|k| k.signing).unwrap_or_default();
                    if !crypto::verify(self.signing, &key, &message)? {
                        return Err(SmbError::protocol("response with a bad signature"));
                    }
                } else if !interim {
                    return Err(SmbError::protocol("response not signed"));
                }
            }
            if !interim {
                self.responses.insert(
                    header.message_id,
                    Response {
                        header: header.clone(),
                        msg: message,
                    },
                );
            }
            if header.next_command == 0 {
                return Ok(());
            }
            at += len;
        }
    }

    // -- Exchanges ---------------------------------------------------------------------

    /// Sends each compound (requests related to the first one) and returns the responses of
    /// each, in order. Compounds go in batches bounded by the credits and `MAX_IN_FLIGHT`,
    /// one round trip per batch. A refused request is a response with its status, not an
    /// error; errors are those of the session (connection, time, protocol).
    ///
    /// After an error of the session, the requests sent are left without their responses:
    /// the session refuses any other exchange (`usable`).
    pub fn exchange(&mut self, compounds: &[Vec<Request>]) -> Result<Vec<Vec<Response>>, SmbError> {
        if let Some(cause) = &self.broken {
            return Err(SmbError::new(
                ErrorKind::Unreachable,
                format!(
                    "session with {} abandoned after an error: {cause}",
                    self.server
                ),
            ));
        }
        let exchanged = self.exchange_batches(compounds);
        if let Err(e) = &exchanged {
            self.broken = Some(e.to_string());
        }
        exchanged
    }

    fn exchange_batches(
        &mut self,
        compounds: &[Vec<Request>],
    ) -> Result<Vec<Vec<Response>>, SmbError> {
        let mut results = Vec::with_capacity(compounds.len());
        let mut pending = compounds.iter().peekable();
        while pending.peek().is_some() {
            let budget = self.credits.clamp(1, MAX_IN_FLIGHT);
            let mut spent = 0u32;
            let mut batch: Vec<Vec<u64>> = Vec::new();
            let mut writes = false;
            while let Some(requests) = pending.peek() {
                let charge: u32 = requests.iter().map(|r| u32::from(r.credit_charge())).sum();
                if !batch.is_empty() && spent + charge > budget {
                    break;
                }
                if charge > self.credits {
                    return Err(SmbError::protocol(format!(
                        "{charge} credits needed, {} granted",
                        self.credits
                    )));
                }
                spent += charge;
                writes |= requests.iter().any(|r| r.command == command::SET_INFO);
                let (bytes, ids) = self.compound(requests)?;
                self.write_frame(&bytes)?;
                batch.push(ids);
                pending.next();
            }
            self.round_trips += 1;
            if writes && not_waited() {
                return Err(SmbError::new(
                    ErrorKind::Timeout,
                    format!(
                        "no response from {} (trial: batch not waited for)",
                        self.server
                    ),
                ));
            }
            self.wait(&batch)?;
            for ids in batch {
                let mut responses = Vec::with_capacity(ids.len());
                for id in ids {
                    responses.push(
                        self.responses
                            .remove(&id)
                            .ok_or_else(|| SmbError::protocol("response lost"))?,
                    );
                }
                results.push(responses);
            }
        }
        Ok(results)
    }

    /// One request alone. Not counted in `round_trips`: the caller counts what the Python
    /// session counts (the reads and listings that bring data, not their CREATE and CLOSE).
    pub fn request(&mut self, request: Request) -> Result<Response, SmbError> {
        let counted = self.round_trips;
        let responses = self.exchange(&[vec![request]]);
        self.round_trips = counted;
        responses?
            .into_iter()
            .flatten()
            .next()
            .ok_or_else(|| SmbError::protocol("no response"))
    }

    /// Tree disconnect and logoff, at best, then the connection closes.
    pub fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.reader.is_none() {
            return;
        }
        // An abandoned session refuses the exchanges: the connection only is closed.
        if self.tree_id != 0 {
            let _ = self.exchange(&[vec![msg::tree_disconnect()]]);
            self.tree_id = 0;
        }
        if self.keys.is_some() {
            let _ = self.exchange(&[vec![msg::logoff()]]);
        }
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

/// The delay allowed for the responses of `compounds` compounds still awaited: the base delay,
/// one eighth more for each compound beyond the first, at most four times the base (J8.8).
pub fn allowance(base: Duration, compounds: usize) -> Duration {
    let extra = u32::try_from(compounds.saturating_sub(1)).unwrap_or(u32::MAX);
    let steps = ALLOWANCE_STEP
        .saturating_add(extra)
        .min(ALLOWANCE_STEP * MAX_ALLOWANCE);
    base.saturating_mul(steps) / ALLOWANCE_STEP
}

impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::super::fake_server::{Config, FakeAuth, FakeServer, Fs, SESSION_ID};
    use super::*;
    use crate::smb::msg::{Create, RELATED_FILE_ID};

    fn connect(grant: u16) -> (FakeServer, Client) {
        let server = FakeServer::start(
            grant,
            Fs::with(&[("Policies", None), ("Policies\\GPT.INI", Some(b"hello"))]),
        );
        let options = Options {
            port: server.port,
            ..Options::default()
        };
        let client = Client::connect("127.0.0.1", "SYSVOL", &options, &mut FakeAuth::default())
            .expect("session with the fake server");
        (server, client)
    }

    fn open(path: &str) -> Request {
        msg::create(&Create {
            path,
            access: 0x81,
            share: 7,
            disposition: 1,
            ..Create::default()
        })
    }

    #[test]
    fn session_compounds_batches_and_encryption() {
        let (server, mut client) = connect(4);
        assert_eq!(client.session_id, SESSION_ID);
        assert_eq!(client.tree_id, super::super::fake_server::TREE_ID);
        let n = client.negotiated();
        assert_eq!(
            (n.dialect, n.cipher, n.signing, n.encrypted),
            (0x0311, Some(2), 2, true)
        );
        assert_eq!(client.round_trips, 0);
        let listing = || {
            vec![
                open("Policies"),
                msg::query_directory(&RELATED_FILE_ID, 0, "*", 65536),
                msg::close(&RELATED_FILE_ID),
            ]
        };
        let compounds = vec![listing(), listing(), listing(), listing(), listing()];
        let results = client.exchange(&compounds).unwrap();
        assert_eq!(results.len(), 5);
        for r in &results {
            assert!(r.iter().all(|x| x.status() == status::SUCCESS));
            let names: Vec<_> = msg::parse_directory(&msg::parse_output(&r[1].msg, "QD").unwrap())
                .unwrap()
                .into_iter()
                .map(|e| e.name)
                .collect();
            assert_eq!(names, [".", "..", "GPT.INI"]);
        }
        // 7 credits after the tree: two compounds of three per batch at first.
        assert!(
            client.round_trips >= 2,
            "{} round trips",
            client.round_trips
        );
        // A refused CREATE refuses the rest of its compound; the next compound is not affected.
        let r = client
            .exchange(&[
                vec![open("missing\\x"), msg::close(&RELATED_FILE_ID)],
                vec![
                    open("Policies\\GPT.INI"),
                    msg::read(&RELATED_FILE_ID, 0, 65536),
                    msg::close(&RELATED_FILE_ID),
                ],
            ])
            .unwrap();
        assert_eq!(r[0][0].status(), status::OBJECT_PATH_NOT_FOUND);
        assert_eq!(r[0][1].status(), status::OBJECT_PATH_NOT_FOUND);
        // The READ answered first STATUS_PENDING: its final response is the one kept.
        assert_eq!(
            msg::parse_read(&r[1][1].ok().unwrap().msg).unwrap(),
            b"hello"
        );
        assert_eq!(
            r[1][0]
                .ok()
                .map(|x| msg::parse_create(&x.msg).unwrap().attributes)
                .unwrap(),
            0x20
        );
        client.close();
        let seen = server.seen.lock().unwrap();
        // NEGOTIATE and SESSION_SETUP in clear, everything after encrypted.
        assert_eq!(seen.encrypted[..2], [false, false]);
        assert!(seen.encrypted[2..].iter().all(|e| *e));
        assert!(seen.frames.contains(&vec![
            command::CREATE,
            command::QUERY_DIRECTORY,
            command::CLOSE
        ]));
        assert_eq!(seen.frames.last(), Some(&vec![command::LOGOFF]));
        drop(seen);
        server.join();
    }

    fn fs() -> Fs {
        Fs::with(&[("Policies", None), ("Policies\\GPT.INI", Some(b"hello"))])
    }

    /// A session with a server of `config`, the client allowing SMB 2.x or not.
    fn try_connect(config: Config, smb2: bool) -> (FakeServer, Result<Client, SmbError>) {
        let server = FakeServer::start_with(8, fs(), config);
        let options = Options {
            port: server.port,
            smb2,
            ..Options::default()
        };
        let client = Client::connect("127.0.0.1", "SYSVOL", &options, &mut FakeAuth::default());
        (server, client)
    }

    #[test]
    fn smb2_signed_only_when_allowed() {
        for d in [dialect::SMB210, dialect::SMB202] {
            let config = Config {
                dialect: d,
                ..Config::default()
            };
            let (server, client) = try_connect(config, true);
            let mut client = client.expect("SMB 2 session");
            assert_eq!(
                client.negotiated(),
                Negotiated {
                    dialect: d,
                    cipher: None,
                    signing: signing::HMAC_SHA256,
                    encrypted: false,
                }
            );
            let r = client
                .exchange(&[vec![
                    open("Policies\\GPT.INI"),
                    msg::read(&RELATED_FILE_ID, 0, 65536),
                    msg::close(&RELATED_FILE_ID),
                ]])
                .unwrap();
            assert_eq!(
                msg::parse_read(&r[0][1].ok().unwrap().msg).unwrap(),
                b"hello"
            );
            client.close();
            let seen = server.seen.lock().unwrap();
            assert_eq!(
                seen.dialects,
                [
                    dialect::SMB202,
                    dialect::SMB210,
                    dialect::SMB300,
                    dialect::SMB302,
                    dialect::SMB311
                ]
            );
            // Nothing encrypted; every request after the session setup signed with the
            // session key (HMAC-SHA256), checked by the server.
            assert!(seen.encrypted.iter().all(|e| !e));
            assert_eq!(seen.signed[..2], [false, false]);
            assert!(seen.signed[2..].iter().all(|s| *s), "{:?}", seen.signed);
            drop(seen);
            server.join();
        }
    }

    #[test]
    fn smb2_refused_without_the_option() {
        let config = Config {
            dialect: dialect::SMB210,
            ..Config::default()
        };
        let (server, client) = try_connect(config, false);
        assert_eq!(client.unwrap_err().kind, ErrorKind::Smb2Only);
        assert_eq!(
            server.seen.lock().unwrap().dialects,
            [dialect::SMB300, dialect::SMB302, dialect::SMB311]
        );
        server.join();
    }

    #[test]
    fn smb2_unsigned_response_refused() {
        let config = Config {
            dialect: dialect::SMB210,
            unsigned: true,
            ..Config::default()
        };
        let (server, client) = try_connect(config, true);
        let error = client.unwrap_err();
        assert_eq!(
            (error.kind, error.detail.as_str()),
            (ErrorKind::Protocol, "response not signed")
        );
        server.join();
    }

    #[test]
    fn allowance_grows_with_the_compounds_and_is_capped() {
        let base = Duration::from_secs(30);
        assert_eq!(allowance(base, 0), base);
        assert_eq!(allowance(base, 1), base);
        assert_eq!(allowance(base, 9), Duration::from_secs(60));
        // 20 compounds of three requests: what 60 credits in flight allow.
        assert_eq!(allowance(base, 20), Duration::from_millis(101_250));
        assert_eq!(allowance(base, 25), Duration::from_secs(120));
        assert_eq!(allowance(base, 10_000), Duration::from_secs(120));
    }

    fn writing(path: &str) -> Vec<Request> {
        vec![
            msg::create(&Create {
                path,
                access: 0x0004_0000,
                share: 7,
                disposition: 1,
                ..Create::default()
            }),
            msg::set_info(&RELATED_FILE_ID, msg::INFO_SECURITY, 0, 4, b"descriptor"),
            msg::close(&RELATED_FILE_ID),
        ]
    }

    /// A server that answers each write late, one compound after the other: the batch takes
    /// far longer than the base delay, each response comes within it (J8.8).
    #[test]
    fn slow_server_waited_for_while_it_answers() {
        let (server, mut client) = connect(64);
        client.set_timeout(Duration::from_millis(400));
        *server.pause.lock().unwrap() = Duration::from_millis(100);
        let compounds: Vec<Vec<Request>> = (0..8).map(|_| writing("Policies\\GPT.INI")).collect();
        let start = Instant::now();
        let results = client.exchange(&compounds).unwrap();
        assert!(start.elapsed() >= Duration::from_millis(800));
        assert_eq!(client.round_trips, 1);
        assert!(
            results
                .iter()
                .flatten()
                .all(|r| r.status() == status::SUCCESS)
        );
        assert!(client.usable());
        client.close();
        server.join();
    }

    /// A response later than the delay: the session times out and refuses any other exchange
    /// (its credits and message ids are those of requests without responses); the server
    /// wrote all the same. A new session works.
    #[test]
    fn session_abandoned_after_a_timeout() {
        let server = FakeServer::start_with(
            64,
            fs(),
            Config {
                connections: 2,
                ..Config::default()
            },
        );
        let options = Options {
            port: server.port,
            ..Options::default()
        };
        let mut client =
            Client::connect("127.0.0.1", "SYSVOL", &options, &mut FakeAuth::default()).unwrap();
        client.set_timeout(Duration::from_millis(100));
        *server.pause.lock().unwrap() = Duration::from_millis(600);
        let error = client
            .exchange(&[writing("Policies\\GPT.INI")])
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::Timeout);
        assert!(error.detail.contains("1 of 1 compound(s)"), "{error}");
        assert!(!client.usable());
        let start = Instant::now();
        let again = client.exchange(&[vec![open("Policies")]]).unwrap_err();
        assert_eq!(again.kind, ErrorKind::Unreachable);
        assert!(again.detail.contains("abandoned"), "{again}");
        assert!(start.elapsed() < Duration::from_millis(50));
        *server.pause.lock().unwrap() = Duration::ZERO;
        drop(client);
        let mut fresh =
            Client::connect("127.0.0.1", "SYSVOL", &options, &mut FakeAuth::default()).unwrap();
        let r = fresh
            .exchange(&[vec![
                open("Policies\\GPT.INI"),
                msg::read(&RELATED_FILE_ID, 0, 65536),
                msg::close(&RELATED_FILE_ID),
            ]])
            .unwrap();
        assert_eq!(r[0][1].status(), status::SUCCESS);
        assert_eq!(
            server
                .fs
                .lock()
                .unwrap()
                .get("Policies\\GPT.INI")
                .unwrap()
                .descriptor,
            b"descriptor"
        );
        fresh.close();
        server.join();
    }

    #[test]
    fn smb3_stays_encrypted_with_the_option() {
        let (server, client) = try_connect(Config::default(), true);
        let client = client.expect("SMB 3.1.1 session");
        let n = client.negotiated();
        assert_eq!((n.dialect, n.encrypted), (dialect::SMB311, true));
        client.close();
        let seen = server.seen.lock().unwrap();
        assert!(seen.encrypted[2..].iter().all(|e| *e));
        drop(seen);
        server.join();
    }
}

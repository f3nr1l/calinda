// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! SMB2 messages (MS-SMB2 2.2): the header, the requests the client sends and the responses
//! it reads. Only what the SYSVOL needs. Offsets in a message are counted from the start of
//! its header, so the bodies are written knowing that the header takes 64 bytes.

use super::wire::{
    Writer, array16_at, bytes_at, from_utf16, to_u16, to_u32, u8_at, u16_at, u32_at, u64_at, utf16,
};

pub const HEADER_LEN: usize = 64;
const PROTOCOL_ID: [u8; 4] = [0xFE, b'S', b'M', b'B'];
/// Transform header of an encrypted message (MS-SMB2 2.2.41).
pub const TRANSFORM_ID: [u8; 4] = [0xFD, b'S', b'M', b'B'];
pub const TRANSFORM_LEN: usize = 52;

/// Commands (MS-SMB2 2.2.1.2).
pub mod command {
    pub const NEGOTIATE: u16 = 0x00;
    pub const SESSION_SETUP: u16 = 0x01;
    pub const LOGOFF: u16 = 0x02;
    pub const TREE_CONNECT: u16 = 0x03;
    pub const TREE_DISCONNECT: u16 = 0x04;
    pub const CREATE: u16 = 0x05;
    pub const CLOSE: u16 = 0x06;
    pub const READ: u16 = 0x08;
    pub const WRITE: u16 = 0x09;
    pub const QUERY_DIRECTORY: u16 = 0x0E;
    pub const QUERY_INFO: u16 = 0x10;
    pub const SET_INFO: u16 = 0x11;
}

/// Header flags (MS-SMB2 2.2.1.2).
pub mod flag {
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
    pub const ASYNC_COMMAND: u32 = 0x0000_0002;
    pub const RELATED_OPERATIONS: u32 = 0x0000_0004;
    pub const SIGNED: u32 = 0x0000_0008;
}

/// NTSTATUS values the client acts on (MS-ERREF 2.3.1).
pub mod status {
    pub const SUCCESS: u32 = 0x0000_0000;
    pub const PENDING: u32 = 0x0000_0103;
    pub const NO_MORE_FILES: u32 = 0x8000_0006;
    pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
    pub const END_OF_FILE: u32 = 0xC000_0011;
    pub const BUFFER_OVERFLOW: u32 = 0x8000_0005;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
    pub const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
    pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
    pub const SHARING_VIOLATION: u32 = 0xC000_0043;
    pub const DELETE_PENDING: u32 = 0xC000_0056;
    pub const FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
    pub const DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
    pub const NOT_A_DIRECTORY: u32 = 0xC000_0103;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const NETWORK_SESSION_EXPIRED: u32 = 0xC000_035C;
    pub const USER_SESSION_DELETED: u32 = 0xC000_0203;
}

/// Dialects (MS-SMB2 2.2.3).
pub mod dialect {
    /// SMB 2.x, signed only (no encryption): the profile option for old DCs (ADR 0021).
    pub const SMB202: u16 = 0x0202;
    pub const SMB210: u16 = 0x0210;
    pub const SMB300: u16 = 0x0300;
    pub const SMB302: u16 = 0x0302;
    pub const SMB311: u16 = 0x0311;

    /// SMB 2.0.2 or 2.1: neither key derivation nor encryption, HMAC-SHA256 signing.
    pub fn is_smb2(d: u16) -> bool {
        matches!(d, SMB202 | SMB210)
    }
}

/// Security mode, capabilities and session flags.
pub const SIGNING_ENABLED: u16 = 0x0001;
pub const SIGNING_REQUIRED: u16 = 0x0002;
pub const CAP_DFS: u32 = 0x0000_0001;
pub const CAP_LARGE_MTU: u32 = 0x0000_0004;
pub const CAP_ENCRYPTION: u32 = 0x0000_0040;
pub const SESSION_FLAG_IS_GUEST: u16 = 0x0001;
pub const SESSION_FLAG_IS_NULL: u16 = 0x0002;
pub const SESSION_FLAG_ENCRYPT_DATA: u16 = 0x0004;
pub const SHARE_FLAG_ENCRYPT_DATA: u32 = 0x0000_8000;

/// Ciphers and signing algorithms of the 3.1.1 negotiate contexts (MS-SMB2 2.2.3.1).
pub mod cipher {
    pub const AES_128_CCM: u16 = 0x0001;
    pub const AES_128_GCM: u16 = 0x0002;
}
pub mod signing {
    pub const HMAC_SHA256: u16 = 0x0000;
    pub const AES_CMAC: u16 = 0x0001;
    pub const AES_GMAC: u16 = 0x0002;
}
const CONTEXT_PREAUTH: u16 = 0x0001;
const CONTEXT_ENCRYPTION: u16 = 0x0002;
const CONTEXT_SIGNING: u16 = 0x0008;
const HASH_SHA512: u16 = 0x0001;

/// File id of a related request: the one the preceding CREATE of the compound opened.
pub const RELATED_FILE_ID: [u8; 16] = [0xFF; 16];

/// The 64-byte header (sync form; the async form only appears in interim responses).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub async_id: u64,
    pub tree_id: u32,
    pub session_id: u64,
    pub signature: [u8; 16],
}

impl Header {
    pub(crate) fn write(&self, w: &mut Writer) {
        w.bytes(&PROTOCOL_ID)
            .u16(HEADER_LEN as u16)
            .u16(self.credit_charge)
            .u32(self.status)
            .u16(self.command)
            .u16(self.credits)
            .u32(self.flags)
            .u32(self.next_command)
            .u64(self.message_id);
        if self.flags & flag::ASYNC_COMMAND != 0 {
            w.u64(self.async_id);
        } else {
            w.u32(0).u32(self.tree_id);
        }
        w.u64(self.session_id).bytes(&self.signature);
    }

    pub fn read(b: &[u8]) -> Option<Header> {
        if bytes_at(b, 0, 4)? != PROTOCOL_ID || u16_at(b, 4)? != HEADER_LEN as u16 {
            return None;
        }
        let flags = u32_at(b, 16)?;
        let async_form = flags & flag::ASYNC_COMMAND != 0;
        Some(Header {
            credit_charge: u16_at(b, 6)?,
            status: u32_at(b, 8)?,
            command: u16_at(b, 12)?,
            credits: u16_at(b, 14)?,
            flags,
            next_command: u32_at(b, 20)?,
            message_id: u64_at(b, 24)?,
            async_id: if async_form { u64_at(b, 32)? } else { 0 },
            tree_id: if async_form { 0 } else { u32_at(b, 36)? },
            session_id: u64_at(b, 40)?,
            signature: array16_at(b, 48)?,
        })
    }
}

/// Offset of the signature in a message.
pub const SIGNATURE_AT: usize = 48;

/// A request body, without its header: the command and what follows the header.
#[derive(Debug, Clone)]
pub struct Request {
    pub command: u16,
    pub body: Vec<u8>,
    /// Bytes this request reads or writes beyond the message, for its credit charge.
    pub payload: usize,
}

impl Request {
    /// Credits it costs (MS-SMB2 3.1.5.2): one per started 64 KiB of payload.
    pub fn credit_charge(&self) -> u16 {
        to_u16(self.payload.saturating_sub(1) / 65536 + 1)
    }
}

// -- Requests -------------------------------------------------------------------------------

/// The 3.1.1 contexts the client offers.
#[derive(Debug, Clone)]
pub struct NegotiateOffer {
    pub dialects: Vec<u16>,
    pub capabilities: u32,
    pub client_guid: [u8; 16],
    pub salt: [u8; 32],
    pub ciphers: Vec<u16>,
    pub signing: Vec<u16>,
}

pub fn negotiate(offer: &NegotiateOffer) -> Request {
    let mut w = Writer::new();
    let with_contexts = offer.dialects.contains(&dialect::SMB311);
    w.u16(36)
        .u16(to_u16(offer.dialects.len()))
        .u16(SIGNING_ENABLED | SIGNING_REQUIRED)
        .u16(0)
        .u32(offer.capabilities)
        .bytes(&offer.client_guid);
    let contexts_field = w.len();
    w.u32(0).u16(0).u16(0); // NegotiateContextOffset, Count, Reserved2 (or ClientStartTime)
    for d in &offer.dialects {
        w.u16(*d);
    }
    if with_contexts {
        w.align(8);
        w.set_u32(contexts_field, to_u32(HEADER_LEN + w.len()));
        w.set_u16(contexts_field + 4, 3);
        let mut preauth = Writer::new();
        preauth.u16(1).u16(32).u16(HASH_SHA512).bytes(&offer.salt);
        let mut ciphers = Writer::new();
        ciphers.u16(to_u16(offer.ciphers.len()));
        for c in &offer.ciphers {
            ciphers.u16(*c);
        }
        let mut signing = Writer::new();
        signing.u16(to_u16(offer.signing.len()));
        for s in &offer.signing {
            signing.u16(*s);
        }
        let contexts = [
            (CONTEXT_PREAUTH, preauth.buf),
            (CONTEXT_ENCRYPTION, ciphers.buf),
            (CONTEXT_SIGNING, signing.buf),
        ];
        let count = contexts.len();
        for (i, (kind, data)) in contexts.into_iter().enumerate() {
            w.u16(kind).u16(to_u16(data.len())).u32(0).bytes(&data);
            if i + 1 < count {
                w.align(8);
            }
        }
    }
    Request {
        command: command::NEGOTIATE,
        body: w.buf,
        payload: 0,
    }
}

pub fn session_setup(token: &[u8]) -> Request {
    let mut w = Writer::new();
    w.u16(25)
        .u8(0)
        .u8(SIGNING_ENABLED as u8 | SIGNING_REQUIRED as u8)
        .u32(0)
        .u32(0)
        .u16(to_u16(HEADER_LEN + 24))
        .u16(to_u16(token.len()))
        .u64(0)
        .bytes(token);
    Request {
        command: command::SESSION_SETUP,
        body: w.buf,
        payload: 0,
    }
}

pub fn tree_connect(path: &str) -> Request {
    let name = utf16(path);
    let mut w = Writer::new();
    w.u16(9)
        .u16(0)
        .u16(to_u16(HEADER_LEN + 8))
        .u16(to_u16(name.len()))
        .bytes(&name);
    Request {
        command: command::TREE_CONNECT,
        body: w.buf,
        payload: 0,
    }
}

pub fn tree_disconnect() -> Request {
    let mut w = Writer::new();
    w.u16(4).u16(0);
    Request {
        command: command::TREE_DISCONNECT,
        body: w.buf,
        payload: 0,
    }
}

pub fn logoff() -> Request {
    let mut w = Writer::new();
    w.u16(4).u16(0);
    Request {
        command: command::LOGOFF,
        body: w.buf,
        payload: 0,
    }
}

/// Impersonation level of a CREATE.
const IMPERSONATION: u32 = 2;
/// Name of the create context that carries a security descriptor (MS-SMB2 2.2.13.2).
const CONTEXT_SD: &[u8; 4] = b"SecD";

/// What a CREATE asks for (MS-SMB2 2.2.13).
#[derive(Debug, Clone, Default)]
pub struct Create<'a> {
    pub path: &'a str,
    pub access: u32,
    pub attributes: u32,
    pub share: u32,
    pub disposition: u32,
    pub options: u32,
    /// Security descriptor of the created element (`SMB2_CREATE_SD_BUFFER`).
    pub descriptor: Option<&'a [u8]>,
}

pub fn create(c: &Create<'_>) -> Request {
    let name = utf16(c.path);
    let mut w = Writer::new();
    w.u16(57)
        .u8(0)
        .u8(0)
        .u32(IMPERSONATION)
        .u64(0)
        .u64(0)
        .u32(c.access)
        .u32(c.attributes)
        .u32(c.share)
        .u32(c.disposition)
        .u32(c.options)
        .u16(to_u16(HEADER_LEN + 56))
        .u16(to_u16(name.len()));
    let contexts_field = w.len();
    w.u32(0).u32(0);
    w.bytes(&name);
    if name.is_empty() {
        w.u8(0); // the buffer is at least one byte long
    }
    if let Some(sd) = c.descriptor {
        w.align(8);
        let start = w.len();
        // Next, NameOffset, NameLength, Reserved, DataOffset, DataLength, name (padded), data.
        w.u32(0)
            .u16(16)
            .u16(4)
            .u16(0)
            .u16(24)
            .u32(to_u32(sd.len()))
            .bytes(CONTEXT_SD)
            .u32(0)
            .bytes(sd);
        w.set_u32(contexts_field, to_u32(HEADER_LEN + start));
        w.set_u32(contexts_field + 4, to_u32(w.len() - start));
    }
    Request {
        command: command::CREATE,
        body: w.buf,
        payload: 0,
    }
}

pub fn close(file_id: &[u8; 16]) -> Request {
    let mut w = Writer::new();
    w.u16(24).u16(0).u32(0).bytes(file_id);
    Request {
        command: command::CLOSE,
        body: w.buf,
        payload: 0,
    }
}

pub fn read(file_id: &[u8; 16], offset: u64, length: u32) -> Request {
    let mut w = Writer::new();
    w.u16(49)
        .u8(0x50)
        .u8(0)
        .u32(length)
        .u64(offset)
        .bytes(file_id)
        .u32(0)
        .u32(0)
        .u32(0)
        .u16(0)
        .u16(0)
        .u8(0);
    Request {
        command: command::READ,
        body: w.buf,
        payload: length as usize,
    }
}

pub fn write(file_id: &[u8; 16], offset: u64, data: &[u8]) -> Request {
    let mut w = Writer::new();
    w.u16(49)
        .u16(to_u16(HEADER_LEN + 48))
        .u32(to_u32(data.len()))
        .u64(offset)
        .bytes(file_id)
        .u32(0)
        .u32(0)
        .u16(0)
        .u16(0)
        .u32(0)
        .bytes(data);
    Request {
        command: command::WRITE,
        body: w.buf,
        payload: data.len(),
    }
}

/// `FileDirectoryInformation` (MS-FSCC 2.4.10).
pub const FILE_DIRECTORY_INFORMATION: u8 = 0x01;
pub const RESTART_SCANS: u8 = 0x01;

pub fn query_directory(file_id: &[u8; 16], flags: u8, pattern: &str, output: u32) -> Request {
    let name = utf16(pattern);
    let mut w = Writer::new();
    w.u16(33)
        .u8(FILE_DIRECTORY_INFORMATION)
        .u8(flags)
        .u32(0)
        .bytes(file_id)
        .u16(to_u16(HEADER_LEN + 32))
        .u16(to_u16(name.len()))
        .u32(output)
        .bytes(&name);
    Request {
        command: command::QUERY_DIRECTORY,
        body: w.buf,
        payload: output as usize,
    }
}

/// Info types (MS-SMB2 2.2.37).
pub const INFO_FILE: u8 = 0x01;
pub const INFO_SECURITY: u8 = 0x03;
/// `FileDispositionInformation` (MS-FSCC 2.4.11).
pub const FILE_DISPOSITION_INFORMATION: u8 = 13;

pub fn query_info(
    file_id: &[u8; 16],
    info_type: u8,
    class: u8,
    additional: u32,
    output: u32,
) -> Request {
    let mut w = Writer::new();
    w.u16(41)
        .u8(info_type)
        .u8(class)
        .u32(output)
        .u16(0)
        .u16(0)
        .u32(0)
        .u32(additional)
        .u32(0)
        .bytes(file_id)
        .u8(0);
    Request {
        command: command::QUERY_INFO,
        body: w.buf,
        payload: output as usize,
    }
}

pub fn set_info(
    file_id: &[u8; 16],
    info_type: u8,
    class: u8,
    additional: u32,
    buffer: &[u8],
) -> Request {
    let mut w = Writer::new();
    w.u16(33)
        .u8(info_type)
        .u8(class)
        .u32(to_u32(buffer.len()))
        .u16(to_u16(HEADER_LEN + 32))
        .u16(0)
        .u32(additional)
        .bytes(file_id)
        .bytes(buffer);
    Request {
        command: command::SET_INFO,
        body: w.buf,
        payload: buffer.len(),
    }
}

// -- Responses ------------------------------------------------------------------------------

/// A response that does not have the shape its command calls for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed {} response", self.0)
    }
}

impl std::error::Error for Malformed {}

/// The buffer at `offset` (from the header) of `len` bytes.
fn buffer(msg: &[u8], offset: usize, len: usize, what: &'static str) -> Result<Vec<u8>, Malformed> {
    if len == 0 {
        return Ok(Vec::new());
    }
    bytes_at(msg, offset, len)
        .map(<[u8]>::to_vec)
        .ok_or(Malformed(what))
}

#[derive(Debug, Clone, Default)]
pub struct NegotiateResponse {
    pub security_mode: u16,
    pub dialect: u16,
    pub capabilities: u32,
    pub max_transact: u32,
    pub max_read: u32,
    pub max_write: u32,
    pub token: Vec<u8>,
    pub cipher: Option<u16>,
    pub signing: Option<u16>,
    pub preauth_sha512: bool,
}

pub fn parse_negotiate(msg: &[u8]) -> Result<NegotiateResponse, Malformed> {
    let m = Malformed("NEGOTIATE");
    let b = HEADER_LEN;
    let field16 = |at| u16_at(msg, b + at).ok_or(m.clone());
    let field32 = |at| u32_at(msg, b + at).ok_or(m.clone());
    if field16(0)? != 65 {
        return Err(m);
    }
    let dialect = field16(4)?;
    let mut r = NegotiateResponse {
        security_mode: field16(2)?,
        dialect,
        capabilities: field32(24)?,
        max_transact: field32(28)?,
        max_read: field32(32)?,
        max_write: field32(36)?,
        token: buffer(
            msg,
            field16(56)? as usize,
            field16(58)? as usize,
            "NEGOTIATE",
        )?,
        ..NegotiateResponse::default()
    };
    if dialect == dialect::SMB311 {
        let count = field16(6)?;
        let mut at = field32(60)? as usize;
        for _ in 0..count {
            let kind = u16_at(msg, at).ok_or(m.clone())?;
            let len = u16_at(msg, at + 2).ok_or(m.clone())? as usize;
            let data = bytes_at(msg, at + 8, len).ok_or(m.clone())?;
            match kind {
                CONTEXT_PREAUTH => {
                    r.preauth_sha512 =
                        u16_at(data, 0) == Some(1) && u16_at(data, 4) == Some(HASH_SHA512);
                }
                CONTEXT_ENCRYPTION if u16_at(data, 0) == Some(1) => {
                    r.cipher = u16_at(data, 2).filter(|c| *c != 0);
                }
                CONTEXT_SIGNING if u16_at(data, 0) == Some(1) => {
                    r.signing = u16_at(data, 2);
                }
                _ => {}
            }
            at = (at + 8 + len).next_multiple_of(8);
        }
    }
    Ok(r)
}

#[derive(Debug, Clone)]
pub struct SessionSetupResponse {
    pub session_flags: u16,
    pub token: Vec<u8>,
}

pub fn parse_session_setup(msg: &[u8]) -> Result<SessionSetupResponse, Malformed> {
    let m = Malformed("SESSION_SETUP");
    let b = HEADER_LEN;
    if u16_at(msg, b) != Some(9) {
        return Err(m);
    }
    Ok(SessionSetupResponse {
        session_flags: u16_at(msg, b + 2).ok_or(m.clone())?,
        token: buffer(
            msg,
            u16_at(msg, b + 4).ok_or(m.clone())? as usize,
            u16_at(msg, b + 6).ok_or(m)? as usize,
            "SESSION_SETUP",
        )?,
    })
}

#[derive(Debug, Clone)]
pub struct TreeConnectResponse {
    pub share_type: u8,
    pub share_flags: u32,
    pub capabilities: u32,
}

pub fn parse_tree_connect(msg: &[u8]) -> Result<TreeConnectResponse, Malformed> {
    let m = Malformed("TREE_CONNECT");
    let b = HEADER_LEN;
    if u16_at(msg, b) != Some(16) {
        return Err(m);
    }
    Ok(TreeConnectResponse {
        share_type: u8_at(msg, b + 2).ok_or(m.clone())?,
        share_flags: u32_at(msg, b + 4).ok_or(m.clone())?,
        capabilities: u32_at(msg, b + 8).ok_or(m)?,
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CreateResponse {
    pub last_write_time: u64,
    pub end_of_file: u64,
    pub attributes: u32,
    pub file_id: [u8; 16],
}

pub fn parse_create(msg: &[u8]) -> Result<CreateResponse, Malformed> {
    let m = Malformed("CREATE");
    let b = HEADER_LEN;
    if u16_at(msg, b) != Some(89) {
        return Err(m);
    }
    Ok(CreateResponse {
        last_write_time: u64_at(msg, b + 24).ok_or(m.clone())?,
        end_of_file: u64_at(msg, b + 48).ok_or(m.clone())?,
        attributes: u32_at(msg, b + 56).ok_or(m.clone())?,
        file_id: array16_at(msg, b + 64).ok_or(m)?,
    })
}

pub fn parse_read(msg: &[u8]) -> Result<Vec<u8>, Malformed> {
    let m = Malformed("READ");
    let b = HEADER_LEN;
    if u16_at(msg, b) != Some(17) {
        return Err(m);
    }
    let offset = u8_at(msg, b + 2).ok_or(m.clone())? as usize;
    let len = u32_at(msg, b + 4).ok_or(m)? as usize;
    buffer(msg, offset, len, "READ")
}

/// Bytes the server wrote.
pub fn parse_write(msg: &[u8]) -> Result<u32, Malformed> {
    let m = Malformed("WRITE");
    if u16_at(msg, HEADER_LEN) != Some(17) {
        return Err(m);
    }
    u32_at(msg, HEADER_LEN + 4).ok_or(m)
}

/// Output buffer of QUERY_DIRECTORY and QUERY_INFO (same layout, MS-SMB2 2.2.34 and 2.2.38).
pub fn parse_output(msg: &[u8], what: &'static str) -> Result<Vec<u8>, Malformed> {
    let b = HEADER_LEN;
    if u16_at(msg, b) != Some(9) {
        return Err(Malformed(what));
    }
    let offset = u16_at(msg, b + 2).ok_or(Malformed(what))? as usize;
    let len = u32_at(msg, b + 4).ok_or(Malformed(what))? as usize;
    buffer(msg, offset, len, what)
}

/// The body of a response without data (CLOSE, SET_INFO, TREE_DISCONNECT…) is not read.
pub fn check_structure(msg: &[u8], size: u16, what: &'static str) -> Result<(), Malformed> {
    if u16_at(msg, HEADER_LEN) == Some(size) {
        Ok(())
    } else {
        Err(Malformed(what))
    }
}

/// An entry of a `FileDirectoryInformation` listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: String,
    pub last_write_time: u64,
    pub end_of_file: u64,
    pub attributes: u32,
}

pub const ATTRIBUTE_DIRECTORY: u32 = 0x10;

/// Entries of a QUERY_DIRECTORY output buffer, `.` and `..` included.
pub fn parse_directory(buf: &[u8]) -> Result<Vec<DirectoryEntry>, Malformed> {
    let m = Malformed("QUERY_DIRECTORY");
    let mut entries = Vec::new();
    let mut at = 0usize;
    while at < buf.len() {
        let next = u32_at(buf, at).ok_or(m.clone())? as usize;
        let name_len = u32_at(buf, at + 60).ok_or(m.clone())? as usize;
        let name = bytes_at(buf, at + 64, name_len)
            .and_then(from_utf16)
            .ok_or(m.clone())?;
        entries.push(DirectoryEntry {
            name,
            last_write_time: u64_at(buf, at + 24).ok_or(m.clone())?,
            end_of_file: u64_at(buf, at + 40).ok_or(m.clone())?,
            attributes: u32_at(buf, at + 56).ok_or(m.clone())?,
        });
        if next == 0 {
            break;
        }
        at = at.checked_add(next).ok_or(m.clone())?;
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_header(body: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        Header::default().write(&mut w);
        w.bytes(body);
        w.buf
    }

    #[test]
    fn header_round_trip() {
        let h = Header {
            credit_charge: 1,
            status: status::PENDING,
            command: command::CREATE,
            credits: 64,
            flags: flag::RELATED_OPERATIONS | flag::SIGNED,
            next_command: 128,
            message_id: 7,
            tree_id: 9,
            session_id: 0x1122_3344,
            signature: [5; 16],
            ..Header::default()
        };
        let mut w = Writer::new();
        h.write(&mut w);
        assert_eq!(w.len(), HEADER_LEN);
        assert_eq!(Header::read(&w.buf), Some(h));
        let mut async_form = Header {
            flags: flag::ASYNC_COMMAND | flag::SERVER_TO_REDIR,
            async_id: 0xAB,
            ..Header::default()
        };
        let mut w = Writer::new();
        async_form.write(&mut w);
        async_form.tree_id = 0;
        assert_eq!(Header::read(&w.buf), Some(async_form));
        assert_eq!(Header::read(&w.buf[..63]), None);
    }

    #[test]
    fn negotiate_has_contexts_at_their_offsets() {
        let offer = NegotiateOffer {
            dialects: vec![dialect::SMB300, dialect::SMB302, dialect::SMB311],
            capabilities: CAP_ENCRYPTION | CAP_LARGE_MTU,
            client_guid: [1; 16],
            salt: [2; 32],
            ciphers: vec![cipher::AES_128_GCM, cipher::AES_128_CCM],
            signing: vec![signing::AES_GMAC, signing::AES_CMAC],
        };
        let body = negotiate(&offer).body;
        assert_eq!(u16_at(&body, 0), Some(36));
        assert_eq!(u16_at(&body, 2), Some(3));
        let offset = u32_at(&body, 28).unwrap() as usize - HEADER_LEN;
        assert_eq!(offset % 8, 0);
        assert_eq!(u16_at(&body, 32), Some(3));
        assert_eq!(u16_at(&body, 36 + 4), Some(dialect::SMB311));
        assert_eq!(u16_at(&body, offset), Some(CONTEXT_PREAUTH));
        assert_eq!(u16_at(&body, offset + 2), Some(38));
        let second = (offset + 8 + 38).next_multiple_of(8);
        assert_eq!(u16_at(&body, second), Some(CONTEXT_ENCRYPTION));
        assert_eq!(u16_at(&body, second + 10), Some(cipher::AES_128_GCM));
    }

    #[test]
    fn create_carries_the_descriptor_context() {
        let sd = [
            1u8, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let body = create(&Create {
            path: "a\\b",
            descriptor: Some(&sd),
            ..Create::default()
        })
        .body;
        assert_eq!(u16_at(&body, 44), Some(120));
        assert_eq!(u16_at(&body, 46), Some(6));
        let at = u32_at(&body, 48).unwrap() as usize - HEADER_LEN;
        assert_eq!(at % 8, 0);
        assert_eq!(u32_at(&body, 52), Some(24 + 20));
        assert_eq!(bytes_at(&body, at + 16, 4), Some(&b"SecD"[..]));
        assert_eq!(bytes_at(&body, at + 24, 20), Some(&sd[..]));
        let empty = create(&Create::default()).body;
        assert_eq!(empty.len(), 57);
    }

    #[test]
    fn create_response_fields() {
        let mut w = Writer::new();
        w.u16(89)
            .u8(0)
            .u8(0)
            .u32(1)
            .u64(0)
            .u64(0)
            .u64(0x1234)
            .u64(0)
            .u64(0)
            .u64(22)
            .u32(0x10)
            .u32(0);
        w.bytes(&[7; 16]).u32(0).u32(0);
        let r = parse_create(&with_header(&w.buf)).unwrap();
        assert_eq!(r.last_write_time, 0x1234);
        assert_eq!(r.end_of_file, 22);
        assert_eq!(r.attributes, 0x10);
        assert_eq!(r.file_id, [7; 16]);
        assert!(parse_create(&with_header(&w.buf[..60])).is_err());
    }

    #[test]
    fn directory_entries() {
        let mut buf = Vec::new();
        for (i, name) in ["..", "GPT.INI"].iter().enumerate() {
            let n = utf16(name);
            let mut w = Writer::new();
            let len = (64 + n.len()).next_multiple_of(8);
            w.u32(if i == 0 { to_u32(len) } else { 0 })
                .u32(0)
                .u64(0)
                .u64(0)
                .u64(99)
                .u64(0)
                .u64(22)
                .u64(0)
                .u32(if i == 0 { ATTRIBUTE_DIRECTORY } else { 0x20 })
                .u32(to_u32(n.len()))
                .bytes(&n);
            if i == 0 {
                w.align(8);
            }
            buf.extend(w.buf);
        }
        let entries = parse_directory(&buf).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].name, "GPT.INI");
        assert_eq!(entries[1].end_of_file, 22);
        assert_eq!(entries[0].attributes, ATTRIBUTE_DIRECTORY);
        assert!(parse_directory(&buf[..100]).is_err());
    }

    #[test]
    fn credit_charges() {
        assert_eq!(read(&[0; 16], 0, 65536).credit_charge(), 1);
        assert_eq!(read(&[0; 16], 0, 65537).credit_charge(), 2);
        assert_eq!(write(&[0; 16], 0, &[0; 262_144]).credit_charge(), 4);
        assert_eq!(close(&[0; 16]).credit_charge(), 1);
    }
}

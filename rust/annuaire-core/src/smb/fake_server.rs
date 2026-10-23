// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A fake SMB 3.1.1 (or 2.1) server on a local socket, for the tests of the client and of the
//! SYSVOL session without a DC: negotiation, a signed one-round session, encryption both ways
//! or signing only (requests checked, responses signed),
//! compound requests and responses, an interim `STATUS_PENDING` before each READ, credits
//! granted sparingly so that batches split, and a small file system in memory (folders,
//! files, descriptors, `SecD` context, disposition, listings cut at the output size).

#![allow(clippy::indexing_slicing)]

use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use super::auth::{AuthError, Authenticator};
use super::crypto::{self, SessionKeys};
use super::msg::{
    HEADER_LEN, Header, RELATED_FILE_ID, cipher, command, dialect, flag, signing, status,
};
use super::wire::{Writer, from_utf16, u8_at, u16_at, u32_at, u64_at, utf16};

pub const SESSION_ID: u64 = 0x77;
pub const TREE_ID: u32 = 5;
const KEY: [u8; 16] = [0x42; 16];
/// Descriptor of an element created without one (inherited, in a real server).
pub const DEFAULT_SD: &[u8] = b"inherited descriptor";

/// An authenticator that sends one token and accepts the server's answer.
#[derive(Debug, Default)]
pub struct FakeAuth {
    steps: usize,
}

impl Authenticator for FakeAuth {
    fn step(&mut self, _input: Option<&[u8]>) -> Result<Option<Vec<u8>>, AuthError> {
        self.steps += 1;
        Ok((self.steps == 1).then(|| b"token".to_vec()))
    }
    fn complete(&self) -> bool {
        self.steps >= 2
    }
    fn session_key(&self) -> Result<Vec<u8>, AuthError> {
        Ok(KEY.to_vec())
    }
}

/// An element of the file system; paths without a leading separator, "" for the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub path: String,
    pub directory: bool,
    pub content: Vec<u8>,
    pub descriptor: Vec<u8>,
    /// An open that asks to write its descriptor (`WRITE_DAC`, `WRITE_OWNER`) is refused,
    /// as an element whose DACL gives the account nothing.
    pub locked: bool,
}

/// The file system, by lower-case path.
#[derive(Debug, Default)]
pub struct Fs {
    pub nodes: BTreeMap<String, Node>,
}

impl Fs {
    pub fn with(paths: &[(&str, Option<&[u8]>)]) -> Fs {
        let mut fs = Fs::default();
        fs.put("", None);
        for (p, content) in paths {
            fs.put(p, *content);
        }
        fs
    }

    /// A folder (`None`) or a file.
    pub fn put(&mut self, path: &str, content: Option<&[u8]>) {
        self.nodes.insert(
            path.to_lowercase(),
            Node {
                path: path.to_owned(),
                directory: content.is_none(),
                content: content.unwrap_or_default().to_vec(),
                descriptor: DEFAULT_SD.to_vec(),
                locked: false,
            },
        );
    }

    pub fn get(&self, path: &str) -> Option<&Node> {
        self.nodes.get(&path.to_lowercase())
    }

    fn children(&self, path: &str) -> Vec<Node> {
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{}\\", path.to_lowercase())
        };
        self.nodes
            .iter()
            .filter(|(k, _)| {
                !k.is_empty() && k.starts_with(&prefix) && !k[prefix.len()..].contains('\\')
            })
            .map(|(_, n)| n.clone())
            .collect()
    }
}

/// What the server saw: for each frame received, the commands it held.
#[derive(Debug, Default)]
pub struct Seen {
    pub frames: Vec<Vec<u16>>,
    pub encrypted: Vec<bool>,
    /// Whether each request of the frame bore a valid signature.
    pub signed: Vec<bool>,
    /// The dialects the client offered.
    pub dialects: Vec<u16>,
    /// Each CREATE: path, access asked, create options.
    pub creates: Vec<(String, u32, u32)>,
}

/// What the server speaks.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// `SMB311` (encrypted, unless the client signs only) or `SMB210`/`SMB202` (signed
    /// only); a client that does not offer it gets `STATUS_NOT_SUPPORTED`.
    pub dialect: u16,
    /// The responses after the session setup go unsigned.
    pub unsigned: bool,
    /// The account does not hold `SeSecurityPrivilege`: an open that asks
    /// `ACCESS_SYSTEM_SECURITY` gets `STATUS_PRIVILEGE_NOT_HELD`.
    pub no_security_privilege: bool,
    /// Names given by a QUERY_DIRECTORY at most, the buffer far from full: Windows answers so
    /// (J8.7).
    pub directory_entries: Option<usize>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            dialect: dialect::SMB311,
            unsigned: false,
            no_security_privilege: false,
            directory_entries: None,
        }
    }
}

pub struct FakeServer {
    pub port: u16,
    pub seen: Arc<Mutex<Seen>>,
    pub fs: Arc<Mutex<Fs>>,
    handle: Option<JoinHandle<()>>,
}

impl FakeServer {
    /// Serves `fs` in SMB 3.1.1, granting `grant` credits with each response after the
    /// negotiation.
    pub fn start(grant: u16, fs: Fs) -> FakeServer {
        Self::start_with(grant, fs, Config::default())
    }

    pub fn start_with(grant: u16, fs: Fs, config: Config) -> FakeServer {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Seen::default()));
        let fs = Arc::new(Mutex::new(fs));
        let (s, f) = (Arc::clone(&seen), Arc::clone(&fs));
        let handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            Server {
                stream,
                grant,
                config,
                seen: s,
                fs: f,
                keys: None,
                hash: [0; 64],
                opens: HashMap::new(),
                next_id: 1,
            }
            .serve();
        });
        FakeServer {
            port,
            seen,
            fs,
            handle: Some(handle),
        }
    }

    pub fn join(mut self) {
        if let Some(h) = self.handle.take() {
            h.join().unwrap();
        }
    }
}

fn read_frame(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).ok()?;
    let len = (head[1] as usize) << 16 | (head[2] as usize) << 8 | head[3] as usize;
    let mut frame = vec![0u8; len];
    stream.read_exact(&mut frame).ok()?;
    Some(frame)
}

fn write_frame(stream: &mut TcpStream, frame: &[u8]) {
    let len = frame.len() as u32;
    let mut out = vec![0, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    out.extend_from_slice(frame);
    stream.write_all(&out).unwrap();
}

fn error_body() -> Vec<u8> {
    vec![9, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn negotiate_body(dialect_: u16) -> Vec<u8> {
    let smb3 = dialect_ == dialect::SMB311;
    let mut w = Writer::new();
    w.u16(65)
        .u16(3)
        .u16(dialect_)
        .u16(if smb3 { 3 } else { 0 })
        .bytes(&[9; 16])
        .u32(match dialect_ {
            dialect::SMB311 => 0x4 | 0x40,
            dialect::SMB210 => 0x4,
            _ => 0,
        })
        .u32(1 << 20)
        .u32(1 << 20)
        .u32(1 << 20)
        .u64(0)
        .u64(0)
        .u16(0)
        .u16(0);
    let contexts_at = w.len();
    w.u32(0);
    if !smb3 {
        return w.buf;
    }
    w.align(8);
    let offset = HEADER_LEN + w.len();
    w.set_u32(contexts_at, offset as u32);
    w.u16(1)
        .u16(38)
        .u32(0)
        .u16(1)
        .u16(32)
        .u16(1)
        .bytes(&[3; 32]);
    w.align(8);
    w.u16(2).u16(4).u32(0).u16(1).u16(cipher::AES_128_GCM);
    w.align(8);
    w.u16(8).u16(4).u32(0).u16(1).u16(signing::AES_GMAC);
    w.buf
}

fn create_body(node: &Node, id: u64) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(89).u8(0).u8(0).u32(1);
    w.u64(0)
        .u64(0)
        .u64(0x1234)
        .u64(0)
        .u64(0)
        .u64(node.content.len() as u64);
    w.u32(if node.directory { 0x10 } else { 0x20 }).u32(0);
    w.u64(id).u64(id).u32(0).u32(0);
    w.buf
}

fn output_body(data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(9)
        .u16((HEADER_LEN + 8) as u16)
        .u32(data.len() as u32)
        .bytes(data);
    w.buf
}

fn read_body(data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u16(17)
        .u8((HEADER_LEN + 16) as u8)
        .u8(0)
        .u32(data.len() as u32)
        .u32(0)
        .u32(0)
        .bytes(data);
    w.buf
}

fn entry(name: &str, node: Option<&Node>) -> Vec<u8> {
    let n = utf16(name);
    let mut w = Writer::new();
    let (directory, size) = node.map_or((true, 0), |n| (n.directory, n.content.len() as u64));
    w.u32(0)
        .u32(0)
        .u64(0)
        .u64(0)
        .u64(99)
        .u64(0)
        .u64(size)
        .u64(0);
    w.u32(if directory { 0x10 } else { 0x20 })
        .u32(n.len() as u32)
        .bytes(&n);
    w.align(8);
    w.buf
}

/// The requests of a frame, each with its bytes.
fn split(plain: &[u8]) -> Vec<(Header, Vec<u8>)> {
    let mut out = Vec::new();
    let mut at = 0;
    loop {
        let rest = &plain[at..];
        let h = Header::read(rest).unwrap();
        let len = if h.next_command == 0 {
            rest.len()
        } else {
            h.next_command as usize
        };
        out.push((h.clone(), rest[..len].to_vec()));
        if h.next_command == 0 {
            return out;
        }
        at += len;
    }
}

/// Joins response messages into one compound response, signing those marked so.
fn chain(messages: Vec<(Vec<u8>, bool)>, sign: impl Fn(Vec<u8>) -> Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    let count = messages.len();
    for (i, (mut m, signed)) in messages.into_iter().enumerate() {
        if i + 1 < count {
            while m.len() % 8 != 0 {
                m.push(0);
            }
            let len = m.len() as u32;
            m[20..24].copy_from_slice(&len.to_le_bytes());
        }
        out.extend(if signed { sign(m) } else { m });
    }
    out
}

/// An open: its path, deletion on close, and where its listing stands.
struct Open {
    path: String,
    delete: bool,
    listed: usize,
}

struct Server {
    stream: TcpStream,
    grant: u16,
    config: Config,
    seen: Arc<Mutex<Seen>>,
    fs: Arc<Mutex<Fs>>,
    keys: Option<SessionKeys>,
    hash: [u8; 64],
    opens: HashMap<u64, Open>,
    next_id: u64,
}

const B: usize = HEADER_LEN;

impl Server {
    fn response(&self, request: &Header, status_: u32, body: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        Header {
            credit_charge: request.credit_charge,
            status: status_,
            command: request.command,
            credits: if request.command == command::NEGOTIATE {
                1
            } else {
                self.grant
            },
            flags: flag::SERVER_TO_REDIR | (request.flags & flag::RELATED_OPERATIONS),
            message_id: request.message_id,
            tree_id: if request.command == command::TREE_CONNECT {
                TREE_ID
            } else {
                request.tree_id
            },
            session_id: if request.command == command::NEGOTIATE {
                0
            } else {
                SESSION_ID
            },
            ..Header::default()
        }
        .write(&mut w);
        w.bytes(body);
        w.buf
    }

    fn signing(&self) -> u16 {
        if dialect::is_smb2(self.config.dialect) {
            signing::HMAC_SHA256
        } else {
            signing::AES_GMAC
        }
    }

    fn seal(&self, plain: &[u8], nonce: u8) -> Vec<u8> {
        let k = self.keys.as_ref().unwrap();
        crypto::encrypt(
            cipher::AES_128_GCM,
            &k.decryption,
            SESSION_ID,
            &[nonce; 16],
            plain,
        )
        .unwrap()
    }

    fn serve(mut self) {
        let mut nonce = 0u8;
        while let Some(frame) = read_frame(&mut self.stream) {
            let encrypted = crypto::transform_session(&frame).is_some();
            let plain = if encrypted {
                let k = self.keys.as_ref().unwrap();
                crypto::decrypt(cipher::AES_128_GCM, &k.encryption, &frame).unwrap()
            } else {
                frame.clone()
            };
            let requests = split(&plain);
            let signed = requests.iter().all(|(h, bytes)| {
                h.flags & flag::SIGNED != 0
                    && self
                        .keys
                        .as_ref()
                        .is_some_and(|k| crypto::verify(self.signing(), &k.signing, bytes).unwrap())
            });
            {
                let mut s = self.seen.lock().unwrap();
                s.frames
                    .push(requests.iter().map(|(h, _)| h.command).collect());
                s.encrypted.push(encrypted);
                s.signed.push(signed);
            }
            let mut replies = Vec::new();
            // A refused CREATE makes the rest of its compound refused, as Samba does.
            let mut refused: Option<u32> = None;
            let mut related: Option<u64> = None;
            for (h, bytes) in &requests {
                if h.flags & flag::RELATED_OPERATIONS == 0 {
                    refused = None;
                    related = None;
                }
                let reply = if let Some(s) = refused {
                    self.response(h, s, &error_body())
                } else {
                    let (s, body) = self.handle(h, bytes, &mut related, &mut nonce);
                    if h.command == command::CREATE {
                        refused = (s != status::SUCCESS).then_some(s);
                    }
                    self.response(h, s, &body)
                };
                if h.command == command::NEGOTIATE {
                    let first = crypto::preauth_next(&[0; 64], bytes).unwrap();
                    self.hash = crypto::preauth_next(&first, &reply).unwrap();
                }
                // Signing only: a signed request has a signed response.
                let sign = h.command == command::SESSION_SETUP
                    || (!encrypted && h.flags & flag::SIGNED != 0 && !self.config.unsigned);
                replies.push((reply, sign));
            }
            // Signed once padded and chained: the signature covers the padding.
            let out = chain(replies, |m| self.signed(m));
            if encrypted {
                nonce = nonce.wrapping_add(1);
                let sealed = self.seal(&out, nonce);
                write_frame(&mut self.stream, &sealed);
            } else {
                write_frame(&mut self.stream, &out);
            }
        }
    }

    fn signed(&self, mut reply: Vec<u8>) -> Vec<u8> {
        let flags = u32_at(&reply, 16).unwrap() | flag::SIGNED;
        reply[16..20].copy_from_slice(&flags.to_le_bytes());
        let k = self.keys.as_ref().unwrap();
        crypto::sign(self.signing(), &k.signing, &mut reply).unwrap();
        reply
    }

    fn file_id(&self, bytes: &[u8], at: usize, related: Option<u64>) -> Option<u64> {
        let id = &bytes[B + at..B + at + 16];
        if id == RELATED_FILE_ID {
            related
        } else {
            u64_at(id, 0)
        }
    }

    /// Status and body of the response to one request.
    fn handle(
        &mut self,
        h: &Header,
        bytes: &[u8],
        related: &mut Option<u64>,
        nonce: &mut u8,
    ) -> (u32, Vec<u8>) {
        let fs = Arc::clone(&self.fs);
        let mut fs = fs.lock().unwrap();
        match h.command {
            command::NEGOTIATE => {
                let count = u16_at(bytes, B + 2).unwrap() as usize;
                let offered: Vec<u16> = (0..count)
                    .map(|i| u16_at(bytes, B + 36 + 2 * i).unwrap())
                    .collect();
                let known = offered.contains(&self.config.dialect);
                self.seen.lock().unwrap().dialects = offered;
                if !known {
                    return (status::NOT_SUPPORTED, error_body());
                }
                (status::SUCCESS, negotiate_body(self.config.dialect))
            }
            command::SESSION_SETUP => {
                self.hash = crypto::preauth_next(&self.hash, bytes).unwrap();
                self.keys =
                    Some(crypto::session_keys(self.config.dialect, &KEY, &self.hash).unwrap());
                let mut w = Writer::new();
                w.u16(9)
                    .u16(0)
                    .u16((HEADER_LEN + 8) as u16)
                    .u16(2)
                    .bytes(b"ok");
                (status::SUCCESS, w.buf)
            }
            command::TREE_CONNECT => {
                let mut w = Writer::new();
                w.u16(16).u8(1).u8(0).u32(0).u32(0).u32(0x1F01FF);
                (status::SUCCESS, w.buf)
            }
            command::TREE_DISCONNECT | command::LOGOFF => (status::SUCCESS, vec![4, 0, 0, 0]),
            command::CREATE => {
                let access = u32_at(bytes, B + 24).unwrap();
                let disposition = u32_at(bytes, B + 36).unwrap();
                let options = u32_at(bytes, B + 40).unwrap();
                let name_len = u16_at(bytes, B + 46).unwrap() as usize;
                let path = from_utf16(&bytes[B + 56..B + 56 + name_len]).unwrap();
                self.seen
                    .lock()
                    .unwrap()
                    .creates
                    .push((path.clone(), access, options));
                // ACCESS_SYSTEM_SECURITY
                if access & 0x0100_0000 != 0 && self.config.no_security_privilege {
                    return (0xC000_0061, error_body());
                }
                // WRITE_DAC, WRITE_OWNER
                if access & 0x000C_0000 != 0 && fs.get(&path).is_some_and(|n| n.locked) {
                    return (status::ACCESS_DENIED, error_body());
                }
                let contexts = u32_at(bytes, B + 48).unwrap() as usize;
                let descriptor = (contexts != 0).then(|| {
                    let data = u16_at(bytes, contexts + 10).unwrap() as usize;
                    let len = u32_at(bytes, contexts + 12).unwrap() as usize;
                    bytes[contexts + data..contexts + data + len].to_vec()
                });
                let want_dir = options & 0x1 != 0;
                let want_file = options & 0x40 != 0;
                let parent = path.rsplit_once('\\').map_or("", |(p, _)| p).to_owned();
                let parent_ok = fs.get(&parent).is_some_and(|n| n.directory);
                let existing = fs.get(&path).cloned();
                let node = match (disposition, existing) {
                    (2, Some(_)) => return (status::OBJECT_NAME_COLLISION, error_body()),
                    (2, None) if !parent_ok => {
                        return (status::OBJECT_PATH_NOT_FOUND, error_body());
                    }
                    (2, None) => {
                        fs.put(&path, (!want_dir).then_some(&[][..]));
                        if let Some(sd) = descriptor {
                            fs.nodes.get_mut(&path.to_lowercase()).unwrap().descriptor = sd;
                        }
                        fs.get(&path).unwrap().clone()
                    }
                    (_, None) if !parent_ok => {
                        return (status::OBJECT_PATH_NOT_FOUND, error_body());
                    }
                    (_, None) => return (status::OBJECT_NAME_NOT_FOUND, error_body()),
                    (_, Some(n)) if want_dir && !n.directory => {
                        return (status::NOT_A_DIRECTORY, error_body());
                    }
                    (_, Some(n)) if want_file && n.directory => {
                        return (status::FILE_IS_A_DIRECTORY, error_body());
                    }
                    (4, Some(_)) => {
                        let n = fs.nodes.get_mut(&path.to_lowercase()).unwrap();
                        n.content.clear();
                        n.clone()
                    }
                    (_, Some(n)) => n,
                };
                let id = self.next_id;
                self.next_id += 1;
                self.opens.insert(
                    id,
                    Open {
                        path: node.path.clone(),
                        delete: options & 0x1000 != 0,
                        listed: 0,
                    },
                );
                *related = Some(id);
                (status::SUCCESS, create_body(&node, id))
            }
            command::CLOSE => {
                let Some(open) = self
                    .file_id(bytes, 8, *related)
                    .and_then(|id| self.opens.remove(&id))
                else {
                    return (0xC000_0008, error_body()); // STATUS_INVALID_HANDLE
                };
                // Like Samba, DELETE_ON_CLOSE on a full folder is ignored.
                if open.delete && fs.children(&open.path).is_empty() {
                    fs.nodes.remove(&open.path.to_lowercase());
                }
                let mut w = Writer::new();
                w.u16(60).u16(0).u32(0).bytes(&[0; 52]);
                (status::SUCCESS, w.buf)
            }
            command::READ => {
                let length = u32_at(bytes, B + 4).unwrap() as usize;
                let offset = u64_at(bytes, B + 8).unwrap() as usize;
                let Some(path) = self
                    .file_id(bytes, 16, *related)
                    .and_then(|id| self.opens.get(&id))
                    .map(|o| o.path.clone())
                else {
                    return (0xC000_0008, error_body());
                };
                // An interim response first: the client must wait for the final one.
                let mut interim = self.response(h, status::PENDING, &error_body());
                let flags = u32_at(&interim, 16).unwrap() | flag::ASYNC_COMMAND;
                interim[16..20].copy_from_slice(&flags.to_le_bytes());
                interim[14..16].copy_from_slice(&0u16.to_le_bytes());
                if h.flags & flag::SIGNED != 0 {
                    write_frame(&mut self.stream, &interim);
                } else {
                    *nonce = nonce.wrapping_add(1);
                    let sealed = self.seal(&interim, *nonce);
                    write_frame(&mut self.stream, &sealed);
                }
                let content = &fs.get(&path).unwrap().content;
                if offset >= content.len() {
                    return (status::END_OF_FILE, error_body());
                }
                let end = content.len().min(offset + length);
                (status::SUCCESS, read_body(&content[offset..end]))
            }
            command::WRITE => {
                let data_at = u16_at(bytes, B + 2).unwrap() as usize;
                let len = u32_at(bytes, B + 4).unwrap() as usize;
                let offset = u64_at(bytes, B + 8).unwrap() as usize;
                let Some(open) = self
                    .file_id(bytes, 16, *related)
                    .and_then(|id| self.opens.get(&id))
                else {
                    return (0xC000_0008, error_body());
                };
                let node = fs.nodes.get_mut(&open.path.to_lowercase()).unwrap();
                if node.content.len() < offset + len {
                    node.content.resize(offset + len, 0);
                }
                node.content[offset..offset + len].copy_from_slice(&bytes[data_at..data_at + len]);
                let mut w = Writer::new();
                w.u16(17).u16(0).u32(len as u32).u32(0).u16(0).u16(0);
                (status::SUCCESS, w.buf)
            }
            command::QUERY_DIRECTORY => {
                let flags = u8_at(bytes, B + 3).unwrap();
                let output = u32_at(bytes, B + 28).unwrap() as usize;
                let Some(id) = self.file_id(bytes, 8, *related) else {
                    return (0xC000_0008, error_body());
                };
                let open = self.opens.get_mut(&id).unwrap();
                if flags & 1 != 0 {
                    open.listed = 0;
                }
                let mut all = vec![entry(".", None), entry("..", None)];
                for child in fs.children(&open.path) {
                    let name = child.path.rsplit('\\').next().unwrap().to_owned();
                    all.push(entry(&name, Some(&child)));
                }
                let mut buf: Vec<u8> = Vec::new();
                let mut last = 0;
                let mut given = 0;
                while let Some(e) = all.get(open.listed) {
                    if !buf.is_empty() && buf.len() + e.len() > output {
                        break;
                    }
                    if self.config.directory_entries.is_some_and(|n| given >= n) {
                        break;
                    }
                    given += 1;
                    let start = buf.len();
                    if start > 0 {
                        let next = (start - last) as u32;
                        buf[last..last + 4].copy_from_slice(&next.to_le_bytes());
                    }
                    last = start;
                    buf.extend_from_slice(e);
                    open.listed += 1;
                }
                if buf.is_empty() {
                    return (status::NO_MORE_FILES, error_body());
                }
                (status::SUCCESS, output_body(&buf))
            }
            command::QUERY_INFO => {
                let Some(open) = self
                    .file_id(bytes, 24, *related)
                    .and_then(|id| self.opens.get(&id))
                else {
                    return (0xC000_0008, error_body());
                };
                let sd = fs.get(&open.path).unwrap().descriptor.clone();
                (status::SUCCESS, output_body(&sd))
            }
            command::SET_INFO => {
                let info_type = u8_at(bytes, B + 2).unwrap();
                let len = u32_at(bytes, B + 4).unwrap() as usize;
                let buffer = bytes[B + 32..B + 32 + len].to_vec();
                let Some(id) = self.file_id(bytes, 16, *related) else {
                    return (0xC000_0008, error_body());
                };
                let path = self.opens.get(&id).unwrap().path.clone();
                if info_type == 1 {
                    if !fs.children(&path).is_empty() {
                        return (status::DIRECTORY_NOT_EMPTY, error_body());
                    }
                    self.opens.get_mut(&id).unwrap().delete = buffer.first() == Some(&1);
                } else {
                    // The parts named by AdditionalInformation replace those of the
                    // descriptor kept, as a server does; bytes that are not a descriptor
                    // replace it whole.
                    let info = u32_at(bytes, B + 12).unwrap();
                    let node = fs.nodes.get_mut(&path.to_lowercase()).unwrap();
                    node.descriptor = merged(&node.descriptor, &buffer, info);
                }
                (status::SUCCESS, vec![2, 0])
            }
            _ => (0xC000_0002, error_body()),
        }
    }
}

/// The descriptor `old` with the parts `info` of `new` (owner 1, group 2, DACL 4, SACL 8).
fn merged(old: &[u8], new: &[u8], info: u32) -> Vec<u8> {
    use annuaire_codecs::sd::{self, SecurityDescriptor};
    let (Ok(mut kept), Ok(given)) = (
        SecurityDescriptor::decode(old),
        SecurityDescriptor::decode(new),
    ) else {
        return new.to_vec();
    };
    if info & 1 != 0 {
        kept.owner = given.owner;
    }
    if info & 2 != 0 {
        kept.group = given.group;
    }
    let dacl_bits = sd::SE_DACL_PRESENT | sd::SE_DACL_PROTECTED | sd::SE_DACL_AUTO_INHERITED;
    if info & 4 != 0 {
        kept.dacl = given.dacl;
        kept.control = (kept.control & !dacl_bits) | (given.control & dacl_bits);
    }
    let sacl_bits = sd::SE_SACL_PRESENT | sd::SE_SACL_PROTECTED | sd::SE_SACL_AUTO_INHERITED;
    if info & 8 != 0 {
        kept.sacl = given.sacl;
        kept.control = (kept.control & !sacl_bits) | (given.control & sacl_bits);
    }
    kept.encode().unwrap_or_else(|_| new.to_vec())
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The SYSVOL of a DC over SMB: port of `SessionSysvol` (`annuaire/core/sysvol.py`, ADR 0002,
//! 0012 and 0017).
//!
//! Kerberos only, SMB 3 encryption required (SMB 2.x signed only if the profile allows it,
//! ADR 0021), the DC always named. Every walk and
//! every read in number goes in **compound and batched** requests: CREATE + QUERY_DIRECTORY
//! (or READ, QUERY_INFO…) + CLOSE as one related compound, all those of a level sent before
//! the first response, in batches bounded by the credits. A folder whose listing fills the
//! buffer is read again on its own; a file longer than the first read is read to its end.
//!
//! The steps of a changeset (`states`, `create`, `replace`, `set`, `erase`) do their work and
//! read the element back in the same compound, and read the states of the paths of `then`
//! (the guard of the next operation) in the same batch: one round trip.
//!
//! Paths are relative to the share (`lab.test\Policies\{…}\GPT.INI`).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::smb::msg::{
    self, ATTRIBUTE_DIRECTORY, Create, CreateResponse, FILE_DISPOSITION_INFORMATION, INFO_FILE,
    INFO_SECURITY, RELATED_FILE_ID, RESTART_SCANS, Request, status,
};
use crate::smb::{Client, ErrorKind, Kerberos, Options, Response, SmbError};

pub const SHARE: &str = "SYSVOL";
/// Response size asked of QUERY_DIRECTORY; beyond `DIRECTORY_FULL` bytes received, the folder
/// is listed again on its own (some may be left).
pub const DIRECTORY_BUFFER: u32 = 65536;
pub const DIRECTORY_FULL: usize = 60000;
/// Bytes asked by the first read of a file; GPT.INI holds 22 to 60.
pub const FIRST_READ: u32 = 65536;
/// Large files are written in pieces of 256 KiB (4 credits each).
const PIECE: usize = 262_144;
const SEPARATOR: char = '\\';

/// Parts of a descriptor (MS-DTYP 2.4.7).
pub const INFO_OWNER: u32 = 0x1;
pub const INFO_GROUP: u32 = 0x2;
pub const INFO_DACL: u32 = 0x4;
pub const INFO_OGD: u32 = INFO_OWNER | INFO_GROUP | INFO_DACL;

// Access rights of an open (MS-SMB2 2.2.13.1).
const READ_DATA: u32 = 0x0000_0001;
const WRITE_DATA: u32 = 0x0000_0002;
const READ_ATTRIBUTES: u32 = 0x0000_0080;
const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
const DELETE: u32 = 0x0001_0000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const SYNCHRONIZE: u32 = 0x0010_0000;
const LIST_DIRECTORY: u32 = READ_DATA;
const NORMAL: u32 = 0x80;
const SHARE_ALL: u32 = 0x7;
const SHARE_READ_WRITE: u32 = 0x3;
// Dispositions and options.
const OPEN: u32 = 1;
const CREATE: u32 = 2;
const OVERWRITE: u32 = 4;
const DIRECTORY_FILE: u32 = 0x0000_0001;
const NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const DELETE_ON_CLOSE: u32 = 0x0000_1000;

/// NTSTATUS of an absent path.
pub fn absent(s: u32) -> bool {
    s == status::OBJECT_NAME_NOT_FOUND || s == status::OBJECT_PATH_NOT_FOUND
}

// -- Paths ----------------------------------------------------------------------------------

/// `a\b\c` from pieces, empty ones left out, separators trimmed.
pub fn join(pieces: &[&str]) -> String {
    pieces
        .iter()
        .map(|p| p.trim_matches(SEPARATOR))
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("\\")
}

pub fn parent(path: &str) -> &str {
    path.rsplit_once(SEPARATOR).map_or("", |(p, _)| p)
}

/// Comparable form of a path: the SYSVOL ignores case.
pub fn key(path: &str) -> String {
    path.trim_matches(SEPARATOR).to_lowercase()
}

// -- Results --------------------------------------------------------------------------------

/// What went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysvolError {
    /// The session itself (connection, time, Kerberos, protocol).
    Session(SmbError),
    /// The server refused an operation on `path`.
    Status {
        status: u32,
        path: String,
        detail: String,
    },
    /// The step was accepted but the element could not be read back.
    Reread {
        status: u32,
        path: String,
        detail: String,
    },
}

impl SysvolError {
    pub fn status(status: u32, path: &str) -> Self {
        Self::Status {
            status,
            path: path.to_owned(),
            detail: format!("NTSTATUS 0x{status:08X}"),
        }
    }

    fn reread(status: u32, path: &str) -> Self {
        Self::Reread {
            status,
            path: path.to_owned(),
            detail: format!("NTSTATUS 0x{status:08X}"),
        }
    }

    /// NTSTATUS of a refusal.
    pub fn ntstatus(&self) -> Option<u32> {
        match self {
            Self::Status { status, .. } | Self::Reread { status, .. } => Some(*status),
            Self::Session(e) => e.status(),
        }
    }
}

impl From<SmbError> for SysvolError {
    fn from(e: SmbError) -> Self {
        Self::Session(e)
    }
}

impl std::fmt::Display for SysvolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Session(e) => e.fmt(f),
            Self::Status { status, path, .. } => write!(f, "{path}: NTSTATUS 0x{status:08X}"),
            Self::Reread { status, path, .. } => {
                write!(f, "{path} not read back: NTSTATUS 0x{status:08X}")
            }
        }
    }
}

impl std::error::Error for SysvolError {}

pub type Result<T> = std::result::Result<T, SysvolError>;

/// A file or a folder under the root of a walk (`EntreeSysvol`); `path` relative to the root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub path: String,
    pub directory: bool,
    pub size: u64,
    /// FILETIME of the last write (0 if unknown).
    pub modified: u64,
}

/// The walk of a root (`Arborescence`): `present` false if the root does not exist;
/// `unreadable`: folders the account could not list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub root: String,
    pub present: bool,
    pub entries: Vec<Entry>,
    pub unreadable: Vec<String>,
}

/// An element of a survey (`Element`): path relative to the share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub path: String,
    pub directory: bool,
    pub size: u64,
    pub content: Option<Vec<u8>>,
    pub descriptor: Option<Vec<u8>>,
}

/// What a compound reads of an element (`Etat`): its nature (true for a folder, false for a
/// file, `None` if it does not exist), descriptor, content of a file, children of a folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub path: String,
    pub nature: Option<bool>,
    pub descriptor: Option<Vec<u8>>,
    pub content: Option<Vec<u8>>,
    pub children: Option<Vec<String>>,
}

impl State {
    fn bare(path: &str, nature: Option<bool>) -> Self {
        Self {
            path: path.to_owned(),
            nature,
            descriptor: None,
            content: None,
            children: None,
        }
    }
}

/// Paths to read with what is known of their nature: `Some(true)` folder (descriptor and
/// listing), `Some(false)` file (descriptor and content), `None` (descriptor only).
pub type Hints = [(String, Option<bool>)];

// -- Compounds ------------------------------------------------------------------------------

/// The CREATE of a compound, as `_preparer` builds it.
fn open(
    path: &str,
    access: u32,
    directory: Option<bool>,
    disposition: u32,
    options: u32,
    descriptor: Option<&[u8]>,
) -> Request {
    let options = options
        | match directory {
            Some(true) => DIRECTORY_FILE,
            Some(false) => NON_DIRECTORY_FILE,
            None => 0,
        };
    msg::create(&Create {
        path,
        access,
        attributes: if directory == Some(false) { NORMAL } else { 0 },
        share: SHARE_ALL,
        disposition,
        options,
        descriptor,
    })
}

fn query_security(info: u32) -> Request {
    msg::query_info(&RELATED_FILE_ID, INFO_SECURITY, 0, info, 65536)
}

fn set_security(info: u32, descriptor: &[u8]) -> Request {
    msg::set_info(&RELATED_FILE_ID, INFO_SECURITY, 0, info, descriptor)
}

fn close() -> Request {
    msg::close(&RELATED_FILE_ID)
}

fn list() -> Request {
    msg::query_directory(&RELATED_FILE_ID, 0, "*", DIRECTORY_BUFFER)
}

fn read_first() -> Request {
    msg::read(&RELATED_FILE_ID, 0, FIRST_READ)
}

/// The first refusal among responses, as an error on `path`.
fn first_refusal(responses: &[Response], path: &str) -> Result<()> {
    match responses.iter().find(|r| r.status() != status::SUCCESS) {
        Some(r) => Err(SysvolError::status(r.status(), path)),
        None => Ok(()),
    }
}

fn get(responses: &[Response], i: usize) -> Result<&Response> {
    responses
        .get(i)
        .ok_or_else(|| SmbError::new(ErrorKind::Protocol, "missing response").into())
}

/// Attributes from the CREATE response.
fn attributes(r: &Response) -> Result<u32> {
    Ok(msg::parse_create(&r.msg)
        .map_err(SmbError::from)?
        .attributes)
}

/// Bytes of a QUERY_INFO response; a refusal as an error of class `reread` or not.
fn output(r: &Response, path: &str, reread: bool) -> Result<Vec<u8>> {
    match r.status() {
        status::SUCCESS => Ok(msg::parse_output(&r.msg, "QUERY_INFO").map_err(SmbError::from)?),
        s if reread => Err(SysvolError::reread(s, path)),
        s => Err(SysvolError::status(s, path)),
    }
}

/// Bytes of a READ response (`END_OF_FILE` is empty).
fn read_bytes(r: &Response, path: &str, reread: bool) -> Result<Vec<u8>> {
    match r.status() {
        status::SUCCESS => Ok(msg::parse_read(&r.msg).map_err(SmbError::from)?),
        status::END_OF_FILE => Ok(Vec::new()),
        s if reread => Err(SysvolError::reread(s, path)),
        s => Err(SysvolError::status(s, path)),
    }
}

/// A listing: entries and whether the buffer was full; or the refusal of the server.
type Listing = std::result::Result<(Vec<msg::DirectoryEntry>, bool), u32>;

/// Entries of a QUERY_DIRECTORY response (`NO_MORE_FILES` is empty), or its refusal; an
/// error if the response is malformed.
fn listing(r: &Response) -> Result<Listing> {
    match r.status() {
        status::SUCCESS => {
            let buf = msg::parse_output(&r.msg, "QUERY_DIRECTORY").map_err(SmbError::from)?;
            let full = buf.len() >= DIRECTORY_FULL;
            let entries = msg::parse_directory(&buf).map_err(SmbError::from)?;
            Ok(Ok((entries, full)))
        }
        status::NO_MORE_FILES => Ok(Ok((Vec::new(), false))),
        s => Ok(Err(s)),
    }
}

/// The listing of the CREATE + QUERY_DIRECTORY + CLOSE compound of a folder.
fn listing_of(chain: &[Response]) -> Result<Listing> {
    let created = get(chain, 0)?;
    if created.status() == status::SUCCESS {
        listing(get(chain, 1)?)
    } else {
        Ok(Err(created.status()))
    }
}

fn named(entries: Vec<msg::DirectoryEntry>) -> impl Iterator<Item = msg::DirectoryEntry> {
    entries
        .into_iter()
        .filter(|e| e.name != "." && e.name != "..")
}

/// How to read back the state of a path (`_chaine_etat`).
fn state_chain(path: &str, nature: Option<bool>) -> Vec<Request> {
    let access = READ_ATTRIBUTES | READ_CONTROL | if nature.is_some() { READ_DATA } else { 0 };
    let mut chain = vec![
        open(path, access, nature, OPEN, 0, None),
        query_security(INFO_OGD),
    ];
    match nature {
        Some(true) => chain.push(list()),
        Some(false) => chain.push(read_first()),
        None => {}
    }
    chain.push(close());
    chain
}

// -- Session --------------------------------------------------------------------------------

/// How a session is protected (ADR 0017 § 3, ADR 0021).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protection {
    /// SMB 3, encrypted (default).
    #[default]
    Encrypted,
    /// SMB 3 encrypted; SMB 2.1 or 2.0.2 signed only, with a DC that knows no SMB 3 (profile
    /// option “Allow SMB 2 with signing only”).
    AllowSmb2,
    /// SMB 3 signed only (probes and tests).
    Signed,
}

impl Protection {
    /// The protection a profile asks for.
    pub fn of_profile(smb2_signing: bool) -> Self {
        if smb2_signing {
            Self::AllowSmb2
        } else {
            Self::Encrypted
        }
    }

    pub fn options(self, timeout: Duration) -> Options {
        Options {
            encrypt: self != Self::Signed,
            smb2: self == Self::AllowSmb2,
            timeout,
            ..Options::default()
        }
    }
}

/// A session on `\\<dc>\SYSVOL`, opened by `open`, closed by `close` (or when dropped).
#[derive(Debug)]
pub struct Session {
    pub dc: String,
    client: Client,
}

/// Kerberos realm of a DC: its domain (the name without the first label) in capitals,
/// always true for AD (ADR 0017, § 2).
pub fn realm_of(dc: &str) -> String {
    dc.split_once('.').map_or(dc, |(_, d)| d).to_uppercase()
}

impl Session {
    /// Negotiation, Kerberos session, SYSVOL tree. Blocking.
    pub fn open(dc: &str, protection: Protection, timeout: Duration) -> Result<Session> {
        let mut auth = Kerberos::new(dc, &realm_of(dc)).map_err(SmbError::from)?;
        let options = protection.options(timeout);
        let client = Client::connect(dc, SHARE, &options, &mut auth)?;
        Ok(Session {
            dc: dc.to_owned(),
            client,
        })
    }

    /// A session on a client already connected (tests).
    #[cfg(test)]
    pub(crate) fn from_client(dc: &str, client: Client) -> Session {
        Session {
            dc: dc.to_owned(),
            client,
        }
    }

    /// Batches sent (one round trip each) since the session opened.
    pub fn round_trips(&self) -> u64 {
        self.client.round_trips
    }

    pub fn negotiated(&self) -> crate::smb::Negotiated {
        self.client.negotiated()
    }

    pub fn close(self) {
        self.client.close();
    }

    fn send(&mut self, compounds: &[Vec<Request>]) -> Result<Vec<Vec<Response>>> {
        Ok(self.client.exchange(compounds)?)
    }

    /// One compound; the first refusal as an error (`_executer`).
    fn execute(&mut self, path: &str, chain: Vec<Request>) -> Result<Vec<Response>> {
        let responses = self.send(&[chain])?.into_iter().next().unwrap_or_default();
        first_refusal(&responses, path)?;
        Ok(responses)
    }

    /// Per path, the CREATE + (QUERY_DIRECTORY | READ) + CLOSE responses (`_groupe`).
    fn group(&mut self, paths: &[String], directory: bool) -> Result<Vec<Vec<Response>>> {
        let compounds: Vec<Vec<Request>> = paths
            .iter()
            .map(|p| {
                if directory {
                    vec![
                        open(
                            p,
                            LIST_DIRECTORY | READ_ATTRIBUTES,
                            Some(true),
                            OPEN,
                            0,
                            None,
                        ),
                        list(),
                        close(),
                    ]
                } else {
                    vec![
                        open(p, READ_DATA | READ_ATTRIBUTES, Some(false), OPEN, 0, None),
                        read_first(),
                        close(),
                    ]
                }
            })
            .collect();
        self.send(&compounds)
    }

    // -- Walks ------------------------------------------------------------------------------

    /// Complete trees of several roots, level by level, all together.
    pub fn walk(&mut self, roots: &[String]) -> Result<Vec<Tree>> {
        let mut trees: Vec<Tree> = roots
            .iter()
            .map(|r| Tree {
                root: r.clone(),
                present: true,
                entries: Vec::new(),
                unreadable: Vec::new(),
            })
            .collect();
        // (index of the root, path relative to the root) of the folders of this level.
        let mut level: Vec<(usize, String)> =
            (0..roots.len()).map(|i| (i, String::new())).collect();
        while !level.is_empty() {
            let full: Vec<String> = level
                .iter()
                .map(|(i, rel)| {
                    let root = roots.get(*i).map_or("", String::as_str);
                    if rel.is_empty() {
                        root.to_owned()
                    } else {
                        format!("{root}\\{rel}")
                    }
                })
                .collect();
            let responses = self.group(&full, true)?;
            let mut next = Vec::new();
            for (((i, relative), complete), chain) in level.iter().zip(&full).zip(responses) {
                let Some(tree) = trees.get_mut(*i) else {
                    continue;
                };
                let entries = match listing_of(&chain)? {
                    Ok((_, true)) => self.list_alone(complete)?,
                    Ok((entries, false)) => entries,
                    Err(_) => {
                        if relative.is_empty() {
                            tree.present = false;
                        } else {
                            tree.unreadable.push(relative.clone());
                        }
                        continue;
                    }
                };
                for e in named(entries) {
                    let path = if relative.is_empty() {
                        e.name.clone()
                    } else {
                        format!("{relative}\\{}", e.name)
                    };
                    let directory = e.attributes & ATTRIBUTE_DIRECTORY != 0;
                    tree.entries.push(Entry {
                        path: path.clone(),
                        directory,
                        size: if directory { 0 } else { e.end_of_file },
                        modified: e.last_write_time,
                    });
                    if directory {
                        next.push((*i, path));
                    }
                }
            }
            level = next;
        }
        for tree in &mut trees {
            tree.entries.sort_by_key(|e| e.path.to_lowercase());
        }
        Ok(trees)
    }

    /// A folder too large for one response: QUERY_DIRECTORY repeated to the end.
    fn list_alone(&mut self, path: &str) -> Result<Vec<msg::DirectoryEntry>> {
        let created = self.client.request(msg::create(&Create {
            path,
            access: LIST_DIRECTORY | READ_ATTRIBUTES,
            share: SHARE_READ_WRITE,
            disposition: OPEN,
            options: DIRECTORY_FILE,
            ..Create::default()
        }))?;
        if created.status() != status::SUCCESS {
            return Err(SysvolError::status(created.status(), path));
        }
        let id = msg::parse_create(&created.msg)
            .map_err(SmbError::from)?
            .file_id;
        let mut all = Vec::new();
        let mut flags = RESTART_SCANS;
        let result = loop {
            let r =
                match self
                    .client
                    .request(msg::query_directory(&id, flags, "*", DIRECTORY_BUFFER))
                {
                    Ok(r) => r,
                    Err(e) => break Err(e.into()),
                };
            flags = 0;
            match listing(&r) {
                Err(e) => break Err(e),
                Ok(Ok((entries, _))) if !entries.is_empty() => {
                    // Counted like the Python session: the requests that brought names.
                    self.client.round_trips += 1;
                    all.extend(entries);
                }
                Ok(Ok(_)) => break Ok(all),
                Ok(Err(s)) => break Err(SysvolError::status(s, path)),
            }
        };
        let _ = self.client.request(msg::close(&id));
        result
    }

    // -- Reads -------------------------------------------------------------------------------

    /// Content of several files; `None` for a file absent or unreadable.
    pub fn read(&mut self, paths: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
        let responses = self.group(paths, false)?;
        let mut out = Vec::with_capacity(paths.len());
        for (path, chain) in paths.iter().zip(responses) {
            let created = get(&chain, 0)?;
            if created.status() != status::SUCCESS {
                out.push(None);
                continue;
            }
            let r = get(&chain, 1)?;
            out.push(match r.status() {
                status::SUCCESS => {
                    let bytes = msg::parse_read(&r.msg).map_err(SmbError::from)?;
                    Some(if bytes.len() >= FIRST_READ as usize {
                        self.read_alone(path, bytes)?
                    } else {
                        bytes
                    })
                }
                status::END_OF_FILE => Some(Vec::new()),
                _ => None,
            });
        }
        Ok(out)
    }

    /// The rest of a file whose `start` is read, in pieces as large as the server allows
    /// (1 MiB at most): a store of administrative templates holds ADML files of several
    /// hundred KiB (J7.2).
    fn read_alone(&mut self, path: &str, start: Vec<u8>) -> Result<Vec<u8>> {
        let created = self.client.request(msg::create(&Create {
            path,
            access: READ_DATA,
            share: SHARE_READ_WRITE,
            disposition: OPEN,
            options: NON_DIRECTORY_FILE,
            ..Create::default()
        }))?;
        if created.status() != status::SUCCESS {
            return Err(SysvolError::status(created.status(), path));
        }
        let id = msg::parse_create(&created.msg)
            .map_err(SmbError::from)?
            .file_id;
        let mut piece = self.client.max_read.clamp(FIRST_READ, 1 << 20);
        if !self.client.large_mtu() {
            piece = FIRST_READ;
        }
        let mut content = start;
        let result = loop {
            let offset = content.len() as u64;
            let r = match self.client.request(msg::read(&id, offset, piece)) {
                Ok(r) => r,
                Err(e) => break Err(e.into()),
            };
            match r.status() {
                status::END_OF_FILE => break Ok(()),
                status::SUCCESS => {
                    let bytes = msg::parse_read(&r.msg).map_err(SmbError::from)?;
                    if bytes.is_empty() {
                        break Ok(());
                    }
                    // Counted like the Python session: the reads that brought bytes.
                    self.client.round_trips += 1;
                    content.extend(bytes);
                }
                s => break Err(SysvolError::status(s, path)),
            }
        };
        let _ = self.client.request(msg::close(&id));
        result.map(|()| content)
    }

    /// Descriptor of each path, `None` if it does not exist, grouped like `read`.
    pub fn read_descriptors(
        &mut self,
        paths: &[String],
        info: u32,
    ) -> Result<Vec<Option<Vec<u8>>>> {
        let compounds: Vec<Vec<Request>> = paths
            .iter()
            .map(|p| {
                vec![
                    open(p, READ_CONTROL, None, OPEN, 0, None),
                    query_security(info),
                    close(),
                ]
            })
            .collect();
        let responses = self.send(&compounds)?;
        let mut out = Vec::with_capacity(paths.len());
        for (path, chain) in paths.iter().zip(responses) {
            match first_refusal(&chain, path) {
                Err(e) if e.ntstatus().is_some_and(absent) => out.push(None),
                Err(e) => return Err(e),
                Ok(()) => out.push(Some(output(get(&chain, 1)?, path, false)?)),
            }
        }
        Ok(out)
    }

    /// Paths of the elements directly in the folder `path`.
    pub fn list(&mut self, path: &str) -> Result<Vec<String>> {
        let chain = self
            .group(&[path.to_owned()], true)?
            .into_iter()
            .next()
            .unwrap_or_default();
        let entries = match listing_of(&chain)? {
            Ok((_, true)) => self.list_alone(path)?,
            Ok((entries, false)) => entries,
            Err(s) => return Err(SysvolError::status(s, path)),
        };
        Ok(named(entries).map(|e| join(&[path, &e.name])).collect())
    }

    /// Survey of a folder (backup, deletion, ACL): its tree, then contents and descriptors,
    /// each in grouped requests; parents before children.
    pub fn survey(
        &mut self,
        root: &str,
        contents: bool,
        descriptors: bool,
    ) -> Result<Vec<Element>> {
        let root = root.trim_matches(SEPARATOR).to_owned();
        let tree = self
            .walk(std::slice::from_ref(&root))?
            .into_iter()
            .next()
            .ok_or_else(|| SmbError::new(ErrorKind::Protocol, "no tree"))?;
        if !tree.present {
            return Err(SysvolError::status(status::OBJECT_NAME_NOT_FOUND, &root));
        }
        if let Some(first) = tree.unreadable.first() {
            return Err(SysvolError::status(
                status::ACCESS_DENIED,
                &join(&[&root, first]),
            ));
        }
        let mut all: Vec<(String, bool, u64)> = vec![(root.clone(), true, 0)];
        all.extend(
            tree.entries
                .iter()
                .map(|e| (join(&[&root, &e.path]), e.directory, e.size)),
        );
        let files: Vec<String> = all
            .iter()
            .filter(|(_, d, _)| !d)
            .map(|(p, _, _)| p.clone())
            .collect();
        let read: HashMap<String, Option<Vec<u8>>> = if contents && !files.is_empty() {
            files.iter().cloned().zip(self.read(&files)?).collect()
        } else {
            HashMap::new()
        };
        let paths: Vec<String> = all.iter().map(|(p, _, _)| p.clone()).collect();
        let sds: HashMap<String, Option<Vec<u8>>> = if descriptors {
            paths
                .iter()
                .cloned()
                .zip(self.read_descriptors(&paths, INFO_OGD)?)
                .collect()
        } else {
            HashMap::new()
        };
        let mut elements = Vec::with_capacity(all.len());
        for (path, directory, size) in all {
            let mut content = None;
            if contents && !directory {
                content = read.get(&path).cloned().flatten();
                if content.is_none() {
                    return Err(SysvolError::status(status::ACCESS_DENIED, &path));
                }
            }
            let descriptor = sds.get(&path).cloned().flatten();
            elements.push(Element {
                path,
                directory,
                size,
                content,
                descriptor,
            });
        }
        elements.sort_by_key(|e| {
            e.path
                .split(SEPARATOR)
                .map(str::to_lowercase)
                .collect::<Vec<_>>()
        });
        Ok(elements)
    }

    /// True for a folder, false for a file, `None` if it does not exist.
    pub fn nature(&mut self, path: &str) -> Result<Option<bool>> {
        match self.execute(
            path,
            vec![open(path, READ_ATTRIBUTES, None, OPEN, 0, None), close()],
        ) {
            Ok(responses) => Ok(Some(
                attributes(get(&responses, 0)?)? & ATTRIBUTE_DIRECTORY != 0,
            )),
            Err(e) if e.ntstatus().is_some_and(absent) => Ok(None),
            Err(e) => Err(e),
        }
    }

    // -- Writes and descriptors (J5.4 to J5.6) -----------------------------------------------

    pub fn create_directory(&mut self, path: &str) -> Result<()> {
        let chain = vec![
            open(
                path,
                READ_ATTRIBUTES | SYNCHRONIZE,
                Some(true),
                CREATE,
                0,
                None,
            ),
            close(),
        ];
        self.execute(path, chain).map(drop)
    }

    /// Writes the whole file: `create` requires it not to exist, otherwise it must exist and
    /// its content is replaced.
    pub fn write(&mut self, path: &str, content: &[u8], create: bool) -> Result<()> {
        let disposition = if create { CREATE } else { OVERWRITE };
        let access = WRITE_DATA | READ_ATTRIBUTES | WRITE_ATTRIBUTES;
        let creation = open(path, access, Some(false), disposition, 0, None);
        if content.len() <= FIRST_READ as usize {
            let mut chain = vec![creation];
            if !content.is_empty() {
                chain.push(msg::write(&RELATED_FILE_ID, 0, content));
            }
            chain.push(close());
            return self.execute(path, chain).map(drop);
        }
        let responses = self.execute(path, vec![creation])?;
        let id = parse_id(get(&responses, 0)?)?;
        let written = self.write_pieces(path, &id, content);
        let _ = self.client.request(msg::close(&id));
        written
    }

    /// `content` written in pieces on an open file, one round trip each.
    fn write_pieces(&mut self, path: &str, id: &[u8; 16], content: &[u8]) -> Result<()> {
        let piece = if self.client.large_mtu() {
            PIECE.min(self.client.max_write as usize).max(65536)
        } else {
            65536
        };
        for (n, chunk) in content.chunks(piece).enumerate() {
            let r = self
                .client
                .request(msg::write(id, (n * piece) as u64, chunk))?;
            self.client.round_trips += 1;
            if r.status() != status::SUCCESS {
                return Err(SysvolError::status(r.status(), path));
            }
        }
        Ok(())
    }

    /// Deletes a file, or an empty folder.
    pub fn delete(&mut self, path: &str, directory: bool) -> Result<()> {
        let chain = vec![
            open(
                path,
                DELETE | READ_ATTRIBUTES,
                Some(directory),
                OPEN,
                DELETE_ON_CLOSE,
                None,
            ),
            close(),
        ];
        self.execute(path, chain).map(drop)
    }

    pub fn set_descriptor(&mut self, path: &str, descriptor: &[u8], info: u32) -> Result<()> {
        let mut access = READ_CONTROL | WRITE_DAC;
        if info & (INFO_OWNER | INFO_GROUP) != 0 {
            access |= WRITE_OWNER;
        }
        let chain = vec![
            open(path, access, None, OPEN, 0, None),
            set_security(info, descriptor),
            close(),
        ];
        self.execute(path, chain).map(drop)
    }

    // -- Steps of a changeset: the step and its reading back in one compound -----------------

    /// State of a path from the responses of its `state_chain`.
    fn read_state(&mut self, path: &str, nature: Option<bool>, r: &[Response]) -> Result<State> {
        let created = get(r, 0)?;
        match created.status() {
            status::SUCCESS => {}
            s if absent(s) || s == status::DELETE_PENDING => return Ok(State::bare(path, None)),
            status::NOT_A_DIRECTORY => return Ok(State::bare(path, Some(false))),
            status::FILE_IS_A_DIRECTORY => return Ok(State::bare(path, Some(true))),
            s => return Err(SysvolError::status(s, path)),
        }
        let is_directory = attributes(created)? & ATTRIBUTE_DIRECTORY != 0;
        let descriptor = output(get(r, 1)?, path, false)?;
        let mut state = State::bare(path, Some(is_directory));
        state.descriptor = Some(descriptor);
        match nature {
            Some(true) => {
                let entries = match listing(get(r, 2)?)? {
                    Ok((_, true)) => self.list_alone(path)?,
                    Ok((entries, false)) => entries,
                    Err(s) => return Err(SysvolError::status(s, path)),
                };
                state.children = Some(named(entries).map(|e| join(&[path, &e.name])).collect());
            }
            Some(false) => {
                let mut content = read_bytes(get(r, 2)?, path, false)?;
                if content.len() >= FIRST_READ as usize {
                    content = self.read_alone(path, Vec::new())?;
                }
                state.content = Some(content);
            }
            None => {}
        }
        Ok(state)
    }

    /// State of each path, in one batch of compounds.
    pub fn states(&mut self, hints: &Hints) -> Result<Vec<State>> {
        let compounds: Vec<Vec<Request>> = hints.iter().map(|(p, n)| state_chain(p, *n)).collect();
        let responses = self.send(&compounds)?;
        let mut out = Vec::with_capacity(hints.len());
        for ((path, nature), r) in hints.iter().zip(responses) {
            out.push(self.read_state(path, *nature, &r)?);
        }
        Ok(out)
    }

    /// The step (one compound) and, in the same batch, the states of `then`, each in its own
    /// compound (an absent guard must not make the rest refused). A state of `then` that
    /// cannot be read is left out: the next operation reads it itself.
    fn step(&mut self, chain: Vec<Request>, then: &Hints) -> Result<(Vec<Response>, Vec<State>)> {
        let mut compounds = vec![chain];
        compounds.extend(then.iter().map(|(p, n)| state_chain(p, *n)));
        let mut responses = self.send(&compounds)?.into_iter();
        let first = responses.next().unwrap_or_default();
        let mut states = Vec::new();
        for ((path, nature), r) in then.iter().zip(responses) {
            if let Ok(state) = self.read_state(path, *nature, &r) {
                states.push(state);
            }
        }
        Ok((first, states))
    }

    /// CREATE (descriptor included) + WRITE + QUERY_INFO + READ + CLOSE: one round trip. A
    /// step refused after the creation removes the created element, then fails.
    pub fn create(
        &mut self,
        path: &str,
        directory: bool,
        content: &[u8],
        descriptor: Option<&[u8]>,
        then: &Hints,
    ) -> Result<(State, Vec<State>)> {
        if !directory && content.len() > FIRST_READ as usize {
            return self.create_large(path, content, descriptor, then);
        }
        let mut access = READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE;
        if !directory {
            access |= READ_DATA | WRITE_DATA | WRITE_ATTRIBUTES;
        }
        let mut chain = vec![open(path, access, Some(directory), CREATE, 0, descriptor)];
        if !content.is_empty() {
            chain.push(msg::write(&RELATED_FILE_ID, 0, content));
        }
        chain.push(query_security(INFO_OGD));
        if !directory {
            chain.push(read_first());
        }
        chain.push(close());
        let (r, states) = self.step(chain, then)?;
        let created = get(&r, 0)?;
        if created.status() != status::SUCCESS {
            return Err(SysvolError::status(created.status(), path)); // nothing was created
        }
        let mut at = 1;
        if !content.is_empty() {
            let written = get(&r, 1)?;
            if written.status() != status::SUCCESS {
                self.remove(path, directory);
                return Err(SysvolError::status(written.status(), path));
            }
            at = 2;
        }
        let mut state = State::bare(path, Some(directory));
        state.descriptor = Some(output(get(&r, at)?, path, true)?);
        if !directory {
            state.content = Some(read_bytes(get(&r, at + 1)?, path, true)?);
        }
        Ok((state, states))
    }

    /// A file longer than one read: creation, writing in pieces, then reading back.
    fn create_large(
        &mut self,
        path: &str,
        content: &[u8],
        descriptor: Option<&[u8]>,
        then: &Hints,
    ) -> Result<(State, Vec<State>)> {
        let access = READ_ATTRIBUTES | WRITE_DATA | WRITE_ATTRIBUTES | SYNCHRONIZE;
        let responses = self.execute(
            path,
            vec![open(path, access, Some(false), CREATE, 0, descriptor)],
        )?;
        let id = parse_id(get(&responses, 0)?)?;
        let written = self.write_pieces(path, &id, content);
        let _ = self.client.request(msg::close(&id));
        if let Err(e) = written {
            self.remove(path, false);
            return Err(e);
        }
        self.reread(path, Some(false), then)
    }

    fn reread(
        &mut self,
        path: &str,
        nature: Option<bool>,
        then: &Hints,
    ) -> Result<(State, Vec<State>)> {
        let mut hints = vec![(path.to_owned(), nature)];
        hints.extend(then.iter().cloned());
        let mut states = match self.states(&hints) {
            Ok(s) => s.into_iter(),
            Err(SysvolError::Status { status, detail, .. }) => {
                return Err(SysvolError::Reread {
                    status,
                    path: path.to_owned(),
                    detail,
                });
            }
            Err(e) => return Err(e),
        };
        let first = states
            .next()
            .ok_or_else(|| SmbError::new(ErrorKind::Protocol, "no state"))?;
        Ok((first, states.collect()))
    }

    /// Removes at best an element this step has just created (if this fails too, the check
    /// of the recovery will decide).
    fn remove(&mut self, path: &str, directory: bool) {
        let _ = self.erase(path, directory, &[]);
    }

    /// CREATE (FILE_OVERWRITE) + WRITE + READ + CLOSE: one round trip.
    pub fn replace(
        &mut self,
        path: &str,
        content: &[u8],
        then: &Hints,
    ) -> Result<(State, Vec<State>)> {
        if content.len() > FIRST_READ as usize {
            self.write(path, content, false)?;
            return self.reread(path, Some(false), then);
        }
        let access = READ_DATA | WRITE_DATA | READ_ATTRIBUTES | WRITE_ATTRIBUTES;
        let mut chain = vec![open(path, access, Some(false), OVERWRITE, 0, None)];
        if !content.is_empty() {
            chain.push(msg::write(&RELATED_FILE_ID, 0, content));
        }
        chain.push(read_first());
        chain.push(close());
        let len = chain.len();
        let (r, states) = self.step(chain, then)?;
        first_refusal(r.get(..len - 2).unwrap_or(&[]), path)?;
        let mut state = State::bare(path, Some(false));
        state.content = Some(read_bytes(get(&r, len - 2)?, path, true)?);
        Ok((state, states))
    }

    /// CREATE + SET_INFO + QUERY_INFO + CLOSE: one round trip.
    pub fn set(
        &mut self,
        path: &str,
        descriptor: &[u8],
        info: u32,
        then: &Hints,
    ) -> Result<(State, Vec<State>)> {
        let mut access = READ_CONTROL | WRITE_DAC | READ_ATTRIBUTES;
        if info & (INFO_OWNER | INFO_GROUP) != 0 {
            access |= WRITE_OWNER;
        }
        let chain = vec![
            open(path, access, None, OPEN, 0, None),
            set_security(info, descriptor),
            query_security(INFO_OGD),
            close(),
        ];
        let (r, states) = self.step(chain, then)?;
        first_refusal(r.get(..2).unwrap_or(&[]), path)?;
        let is_directory = attributes(get(&r, 0)?)? & ATTRIBUTE_DIRECTORY != 0;
        let mut state = State::bare(path, Some(is_directory));
        state.descriptor = Some(output(get(&r, 2)?, path, true)?);
        Ok((state, states))
    }

    /// CREATE + SET_INFO (FileDispositionInformation) + CLOSE, then CREATE + CLOSE of the
    /// same path to see it gone, in one compound: one round trip. On a full folder, Samba
    /// refuses the disposition (`STATUS_DIRECTORY_NOT_EMPTY`); it is `FILE_DELETE_ON_CLOSE`
    /// it ignores silently (trial of 2026-10-14).
    pub fn erase(
        &mut self,
        path: &str,
        directory: bool,
        then: &Hints,
    ) -> Result<(State, Vec<State>)> {
        let chain = vec![
            open(
                path,
                DELETE | READ_ATTRIBUTES,
                Some(directory),
                OPEN,
                0,
                None,
            ),
            msg::set_info(
                &RELATED_FILE_ID,
                INFO_FILE,
                FILE_DISPOSITION_INFORMATION,
                0,
                &[1],
            ),
            close(),
            open(path, READ_ATTRIBUTES, None, OPEN, 0, None), // last: its expected refusal
            close(),
        ];
        let (r, states) = self.step(chain, then)?;
        first_refusal(r.get(..3).unwrap_or(&[]), path)?;
        let check = get(&r, 3)?;
        match check.status() {
            status::SUCCESS => {
                let is_directory = attributes(check)? & ATTRIBUTE_DIRECTORY != 0;
                Ok((State::bare(path, Some(is_directory)), states))
            }
            s if absent(s) => Ok((State::bare(path, None), states)),
            status::DELETE_PENDING => {
                // Windows: deletion accepted, done when DFS-R releases the element (under a
                // second, seen on 2026-10-14). Waited for, so that deleting the folder next
                // does not find it still there.
                self.wait_gone(path, Duration::from_secs(5));
                Ok((State::bare(path, None), states))
            }
            s => Err(SysvolError::reread(s, path)),
        }
    }

    /// Waits until an element under deferred deletion is no longer listed by its folder (at
    /// most `delay`; beyond, what follows will tell).
    fn wait_gone(&mut self, path: &str, delay: Duration) {
        let end = Instant::now() + delay;
        let folder = parent(path).to_owned();
        let wanted = key(path);
        while Instant::now() < end {
            let listed = self
                .states(&[(folder.clone(), Some(true))])
                .ok()
                .and_then(|s| s.into_iter().next())
                .and_then(|s| s.children);
            match listed {
                Some(children) if children.iter().any(|c| key(c) == wanted) => {}
                _ => return,
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn parse_id(r: &Response) -> Result<[u8; 16]> {
    let CreateResponse { file_id, .. } = msg::parse_create(&r.msg).map_err(SmbError::from)?;
    Ok(file_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smb::fake_server::{DEFAULT_SD, FakeAuth, FakeServer, Fs};

    fn session(fs: Fs) -> (FakeServer, Session) {
        let server = FakeServer::start(16, fs);
        let options = Options {
            port: server.port,
            ..Options::default()
        };
        let client = Client::connect("127.0.0.1", SHARE, &options, &mut FakeAuth::default())
            .expect("fake server");
        (server, Session::from_client("127.0.0.1", client))
    }

    fn s(p: &str) -> String {
        p.to_owned()
    }

    fn lab() -> Fs {
        let big = vec![7u8; 70_000];
        let mut fs = Fs::with(&[
            ("d", None),
            ("d\\Policies", None),
            ("d\\Policies\\{A}", None),
            (
                "d\\Policies\\{A}\\GPT.INI",
                Some(&b"[General]\r\nVersion=3\r\n"[..]),
            ),
            ("d\\Policies\\{A}\\Machine", None),
            ("d\\Policies\\{A}\\Machine\\Registry.pol", Some(&big[..])),
            ("d\\Policies\\{A}\\User", None),
            ("d\\Policies\\{B}", None),
            ("d\\Policies\\{B}\\GPT.INI", Some(&b""[..])),
            ("d\\Big", None),
        ]);
        for i in 0..700 {
            fs.put(&format!("d\\Big\\file-{i:04}.txt"), Some(&b"x"[..]));
        }
        fs
    }

    #[test]
    fn walks_reads_and_surveys() {
        let (server, mut sv) = session(lab());
        let trees = sv
            .walk(&[s("d\\Policies\\{A}"), s("d\\Policies\\{B}"), s("d\\Absent")])
            .unwrap();
        let a: Vec<_> = trees[0]
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.directory, e.size))
            .collect();
        assert_eq!(
            a,
            [
                ("GPT.INI", false, 22),
                ("Machine", true, 0),
                ("Machine\\Registry.pol", false, 70_000),
                ("User", true, 0),
            ]
        );
        assert!(trees[0].present && trees[1].present && !trees[2].present);
        assert_eq!(trees[1].entries.len(), 1);
        // A batch per level: the roots, then Machine and User.
        assert_eq!(sv.round_trips(), 2);

        let read = sv
            .read(&[
                s("d\\Policies\\{A}\\GPT.INI"),
                s("d\\Policies\\{A}\\Machine\\Registry.pol"),
                s("d\\Policies\\{B}\\GPT.INI"),
                s("d\\Policies\\nothing"),
            ])
            .unwrap();
        assert_eq!(read[0].as_deref(), Some(&b"[General]\r\nVersion=3\r\n"[..]));
        assert_eq!(read[1].as_ref().map(Vec::len), Some(70_000));
        assert_eq!(read[2].as_deref(), Some(&b""[..]));
        assert_eq!(read[3], None);

        // A listing larger than one response is read again on its own.
        let big = sv.list("d\\Big").unwrap();
        assert_eq!(big.len(), 700);
        assert_eq!(big[0], "d\\Big\\file-0000.txt");
        assert!(
            matches!(sv.list("d\\Absent"), Err(SysvolError::Status { status: s, .. }) if absent(s))
        );

        let survey = sv.survey("\\d\\Policies\\{A}\\", true, true).unwrap();
        let paths: Vec<_> = survey.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "d\\Policies\\{A}",
                "d\\Policies\\{A}\\GPT.INI",
                "d\\Policies\\{A}\\Machine",
                "d\\Policies\\{A}\\Machine\\Registry.pol",
                "d\\Policies\\{A}\\User",
            ]
        );
        assert!(
            survey
                .iter()
                .all(|e| e.descriptor.as_deref() == Some(DEFAULT_SD))
        );
        assert_eq!(survey[3].content.as_ref().map(Vec::len), Some(70_000));
        assert!(survey[2].content.is_none());
        assert!(matches!(
            sv.survey("d\\Absent", true, true),
            Err(SysvolError::Status {
                status: status::OBJECT_NAME_NOT_FOUND,
                ..
            })
        ));

        let sds = sv
            .read_descriptors(&[s("d\\Policies\\{B}"), s("d\\Policies\\{C}")], INFO_OGD)
            .unwrap();
        assert_eq!(sds, [Some(DEFAULT_SD.to_vec()), None]);
        assert_eq!(sv.nature("d\\Policies\\{B}").unwrap(), Some(true));
        assert_eq!(sv.nature("d\\Policies\\{B}\\GPT.INI").unwrap(), Some(false));
        assert_eq!(sv.nature("d\\Policies\\{C}").unwrap(), None);
        sv.close();
        server.join();
    }

    #[test]
    fn steps_of_a_changeset() {
        let (server, mut sv) = session(lab());
        let g = "d\\Policies\\{N}";
        let ini = "d\\Policies\\{N}\\GPT.INI";
        // Folder created with its descriptor; the guard of the next step read in the batch.
        let (state, then) = sv
            .create(g, true, b"", Some(b"SD of N"), &[(s(ini), Some(false))])
            .unwrap();
        assert_eq!(state.nature, Some(true));
        assert_eq!(state.descriptor.as_deref(), Some(&b"SD of N"[..]));
        assert_eq!(then.len(), 1);
        assert_eq!(then[0].nature, None);
        let trips = sv.round_trips();
        let (state, _) = sv.create(ini, false, b"[General]", None, &[]).unwrap();
        assert_eq!(sv.round_trips(), trips + 1);
        assert_eq!(state.content.as_deref(), Some(&b"[General]"[..]));
        assert_eq!(state.descriptor.as_deref(), Some(DEFAULT_SD));
        assert!(matches!(
            sv.create(ini, false, b"again", None, &[]),
            Err(SysvolError::Status {
                status: status::OBJECT_NAME_COLLISION,
                ..
            })
        ));
        let (state, _) = sv.replace(ini, b"[General]\r\nVersion=1", &[]).unwrap();
        assert_eq!(
            state.content.as_deref(),
            Some(&b"[General]\r\nVersion=1"[..])
        );
        let (state, _) = sv.set(ini, b"new SD", INFO_DACL, &[]).unwrap();
        assert_eq!(
            (state.nature, state.descriptor.as_deref()),
            (Some(false), Some(&b"new SD"[..]))
        );
        // States: a wrong guess of the nature still says what the element is.
        let states = sv
            .states(&[
                (s(g), Some(true)),
                (s(ini), Some(true)),
                (s("d\\Policies\\{Z}"), None),
            ])
            .unwrap();
        assert_eq!(states[0].children.as_deref(), Some(&[s(ini)][..]));
        assert_eq!(states[1].nature, Some(false));
        assert_eq!(states[2].nature, None);
        // A full folder is not deleted.
        assert!(matches!(
            sv.erase(g, true, &[]),
            Err(SysvolError::Status {
                status: status::DIRECTORY_NOT_EMPTY,
                ..
            })
        ));
        // A large file: created, written in pieces, read back.
        let large: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let big = "d\\Policies\\{N}\\Machine.bin";
        let (state, _) = sv.create(big, false, &large, None, &[]).unwrap();
        assert_eq!(state.content.as_deref(), Some(&large[..]));
        let (state, _) = sv.erase(big, false, &[]).unwrap();
        assert_eq!(state.nature, None);
        let (state, _) = sv.erase(ini, false, &[(s(g), Some(true))]).unwrap();
        assert_eq!(state.nature, None);
        let (state, _) = sv.erase(g, true, &[]).unwrap();
        assert_eq!(state.nature, None);
        // The simple writes.
        sv.create_directory("d\\essai").unwrap();
        sv.write("d\\essai\\f", &large, true).unwrap();
        sv.write("d\\essai\\f", b"short", false).unwrap();
        sv.set_descriptor("d\\essai\\f", b"sd", INFO_OGD).unwrap();
        assert_eq!(
            sv.read(&[s("d\\essai\\f")]).unwrap()[0].as_deref(),
            Some(&b"short"[..])
        );
        sv.delete("d\\essai\\f", false).unwrap();
        sv.delete("d\\essai", true).unwrap();
        sv.close();
        let fs = server.fs.lock().unwrap();
        assert!(fs.get(g).is_none() && fs.get("d\\essai").is_none());
        drop(fs);
        server.join();
    }

    /// A DC of SMB 2.x only, with the profile option: signed session, the same work.
    #[test]
    fn smb2_signed_session() {
        use crate::smb::fake_server::Config;
        for d in [msg::dialect::SMB210, msg::dialect::SMB202] {
            let config = Config {
                dialect: d,
                ..Config::default()
            };
            let server = FakeServer::start_with(16, lab(), config);
            let options = Options {
                port: server.port,
                ..Protection::AllowSmb2.options(Duration::from_secs(30))
            };
            let client = Client::connect("127.0.0.1", SHARE, &options, &mut FakeAuth::default())
                .expect("SMB 2 session");
            let mut sv = Session::from_client("127.0.0.1", client);
            assert_eq!(
                (sv.negotiated().dialect, sv.negotiated().encrypted),
                (d, false)
            );
            let large: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
            let path = "d\\Policies\\{A}\\Machine\\big.bin";
            let (state, _) = sv.create(path, false, &large, None, &[]).unwrap();
            assert_eq!(state.content.as_deref(), Some(&large[..]));
            assert_eq!(
                sv.read(&[s("d\\Policies\\{A}\\Machine\\Registry.pol")])
                    .unwrap()[0]
                    .as_ref()
                    .map(Vec::len),
                Some(70_000)
            );
            let (state, _) = sv.erase(path, false, &[]).unwrap();
            assert_eq!(state.nature, None);
            sv.close();
            let seen = server.seen.lock().unwrap();
            assert!(seen.encrypted.iter().all(|e| !e));
            assert!(seen.signed[2..].iter().all(|s| *s));
            drop(seen);
            server.join();
        }
    }

    #[test]
    fn paths() {
        assert_eq!(
            join(&["lab.test\\", "Policies", "", "\\{X}"]),
            "lab.test\\Policies\\{X}"
        );
        assert_eq!(parent("a\\b\\c"), "a\\b");
        assert_eq!(parent("a"), "");
        assert_eq!(key("\\Lab.Test\\GPT.INI"), "lab.test\\gpt.ini");
        assert_eq!(realm_of("dc1.lab.test"), "LAB.TEST");
        assert_eq!(realm_of("wdc1.win.test"), "WIN.TEST");
    }

    #[test]
    fn state_chains() {
        let commands = |c: Vec<Request>| c.iter().map(|r| r.command).collect::<Vec<_>>();
        use crate::smb::msg::command as c;
        assert_eq!(
            commands(state_chain("x", Some(true))),
            [c::CREATE, c::QUERY_INFO, c::QUERY_DIRECTORY, c::CLOSE]
        );
        assert_eq!(
            commands(state_chain("x", Some(false))),
            [c::CREATE, c::QUERY_INFO, c::READ, c::CLOSE]
        );
        assert_eq!(
            commands(state_chain("x", None)),
            [c::CREATE, c::QUERY_INFO, c::CLOSE]
        );
    }
}

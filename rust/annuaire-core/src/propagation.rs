// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Propagation of the inheritance under a folder of a share (ADR 0023 § 5), done by the client
//! as `SetNamedSecurityInfo` does it: neither Windows nor Samba propagates a DACL written over
//! SMB.
//!
//! The tree is walked level by level, a level's folders listed in one batch, the descriptors
//! of their elements read in batches; each element whose DACL is not protected (or every one
//! with « replace ») gets its inherited ACEs recomputed from its parent (`ntfs::recompute`).
//! As `SetNamedSecurityInfo`, the walk does not go under a protected folder (measured from a
//! Windows workstation on fs1), unless « replace » lifts the protection.
//! An element whose permissions do not change is not written: a propagation stopped then run
//! again goes on where it was. Before a batch is written, the descriptor of each element to
//! write is appended, with the new one, to the backup file of the propagation
//! (`$XDG_STATE_HOME/calinda/propagations/<id>.jsonl`, one JSON object per line, flushed to
//! the disk): what is written is always saved, even if the application stops in between. The
//! batch is then written in one go of compounds and read back. A refusal (an element the
//! account may not read or change) is reported and does not stop the others; `Control` gives
//! the progress and takes the request to stop, between two batches.
//!
//! The changeset journals one operation (`Operation::PropagateInheritance`) that names the
//! backup; its inverse writes the saved descriptors back (`rewrite`), each only if the element
//! is still as the propagation left it.
//!
//! A backup the journal names is never removed: Ctrl+Z, the history and resuming read it.
//! The others (their journal entry gone with the rotation of the journal) are removed after a
//! retention, or at once by hand (`inventory`, `purge`).

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sid::Sid;
use serde_json::{Map, Value, json};

use crate::changes::{base64_decode, base64_encode};
use crate::ntfs;
use crate::smb::msg::status;
use crate::storage;
use crate::sysvol::{
    self, BACKUP_INTENT, INFO_DACL, INFO_OGD, INFO_OWNER, INFO_SACL, Session, SysvolError,
};

/// Folder of the backups, under the state of the application.
pub const DIR: &str = "propagations";
/// Elements read, saved and written together: the step at which a request to stop is seen.
pub const BATCH: usize = 256;
/// Version of the backups written; those of version 1 (J8.4: the DACL only) are still read.
const VERSION: u64 = 2;

/// What an operation of propagation does with its backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Recompute the descendants, saving each one changed.
    Compute,
    /// Write back the descriptors saved before the propagation.
    Undo,
    /// Write again the descriptors the propagation wrote.
    Redo,
}

impl Direction {
    pub fn inverse(self) -> Self {
        match self {
            Self::Compute | Self::Redo => Self::Undo,
            Self::Undo => Self::Redo,
        }
    }

    /// Its journaled name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Compute => "calcul",
            Self::Undo => "annulation",
            Self::Redo => "retablissement",
        }
    }

    pub fn of_name(name: &str) -> Option<Self> {
        match name {
            "calcul" => Some(Self::Compute),
            "annulation" => Some(Self::Undo),
            "retablissement" => Some(Self::Redo),
            _ => None,
        }
    }
}

// --- Errors -----------------------------------------------------------------------------------

#[derive(Debug)]
pub enum Error {
    /// The share cannot be read or written as a whole (session, root).
    Smb(SysvolError),
    /// The backup cannot be written or read: `path`, and why.
    Backup { path: PathBuf, detail: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smb(e) => write!(f, "{e}"),
            Self::Backup { path, detail } => write!(f, "{}: {detail}", path.display()),
        }
    }
}

impl std::error::Error for Error {}

impl From<SysvolError> for Error {
    fn from(e: SysvolError) -> Self {
        Self::Smb(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn backup_error(path: &Path, e: impl std::fmt::Display) -> Error {
    Error::Backup {
        path: path.to_path_buf(),
        detail: e.to_string(),
    }
}

// --- Progress and stop ------------------------------------------------------------------------

/// Why an element was left as it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    /// Its folder could not be listed (NTSTATUS).
    Unlisted(u32),
    /// Its descriptor could not be read (NTSTATUS).
    Unreadable(u32),
    /// The server refused the write (NTSTATUS).
    Refused(u32),
    /// The server accepted the write, but the descriptor read back is not the one written.
    NotAsWritten,
    /// Undo or redo: the element changed since the propagation, it is not overwritten.
    Changed,
    /// Undo: its descriptor could not be read before its owner was replaced (J8.7), there is
    /// nothing to write back.
    NotSaved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// Path relative to the share.
    pub path: String,
    pub reason: Reason,
}

/// Where a propagation is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    /// Elements expected (counted before), 0 if unknown.
    pub total: usize,
    pub examined: usize,
    pub written: usize,
    pub refused: usize,
    pub stopped: bool,
    pub finished: bool,
}

/// Progress of a propagation, read by the interface while it runs, and its request to stop.
#[derive(Debug, Default)]
pub struct Control {
    stop: AtomicBool,
    stopped: AtomicBool,
    finished: AtomicBool,
    total: AtomicUsize,
    examined: AtomicUsize,
    written: AtomicUsize,
    refused: Mutex<Vec<Refusal>>,
}

impl Control {
    /// Asks to stop after the batch being written.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    pub fn progress(&self) -> Progress {
        Progress {
            total: self.total.load(Ordering::SeqCst),
            examined: self.examined.load(Ordering::SeqCst),
            written: self.written.load(Ordering::SeqCst),
            refused: self.refused.lock().map_or(0, |r| r.len()),
            stopped: self.stopped.load(Ordering::SeqCst),
            finished: self.finished.load(Ordering::SeqCst),
        }
    }

    pub fn refusals(&self) -> Vec<Refusal> {
        self.refused.lock().map(|r| r.clone()).unwrap_or_default()
    }

    /// A request to stop made before the start is kept: the propagation stops at once.
    fn start(&self, total: usize) {
        self.stopped.store(false, Ordering::SeqCst);
        self.finished.store(false, Ordering::SeqCst);
        self.total.store(total, Ordering::SeqCst);
        self.examined.store(0, Ordering::SeqCst);
        self.written.store(0, Ordering::SeqCst);
        if let Ok(mut r) = self.refused.lock() {
            r.clear();
        }
    }

    fn refuse(&self, path: &str, reason: Reason) {
        if let Ok(mut r) = self.refused.lock() {
            r.push(Refusal {
                path: path.to_owned(),
                reason,
            });
        }
    }

    fn examined(&self, n: usize) {
        self.examined.fetch_add(n, Ordering::SeqCst);
    }

    fn wrote(&self, n: usize) {
        self.written.fetch_add(n, Ordering::SeqCst);
    }

    /// Seen between two batches: true if the propagation must stop there.
    fn halt(&self) -> bool {
        let stop = self.stopping();
        if stop {
            self.stopped.store(true, Ordering::SeqCst);
        }
        stop
    }

    fn finish(&self) {
        self.finished.store(true, Ordering::SeqCst);
    }
}

fn controls() -> &'static Mutex<HashMap<String, Arc<Control>>> {
    static CONTROLS: OnceLock<Mutex<HashMap<String, Arc<Control>>>> = OnceLock::new();
    CONTROLS.get_or_init(Mutex::default)
}

/// The control of the propagation `id`, created at the first call: the interface takes it
/// before the write to follow it, the writer finds the same one.
pub fn control(id: &str) -> Arc<Control> {
    let Ok(mut all) = controls().lock() else {
        return Arc::new(Control::default());
    };
    all.entry(id.to_owned()).or_default().clone()
}

/// Forgets the control of `id` once its result is shown.
pub fn forget(id: &str) {
    if let Ok(mut all) = controls().lock() {
        all.remove(id);
    }
}

// --- Backups ----------------------------------------------------------------------------------

/// A new identifier of propagation: the date, then random hex (a file name).
pub fn new_id() -> String {
    let date: String = crate::writer::timestamp()
        .chars()
        .take(19)
        .filter(char::is_ascii_digit)
        .collect();
    let random = crate::writer::new_id();
    format!("{date}-{}", random.get(..8).unwrap_or(&random))
}

/// An identifier read from a journal names a file of the folder, nothing else.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Folder of the backups (`$XDG_STATE_HOME/calinda/propagations`).
pub fn backup_dir() -> PathBuf {
    storage::state_home().join(storage::APP_DIR).join(DIR)
}

pub fn backup_path(id: &str, dir: Option<&Path>) -> PathBuf {
    dir.map_or_else(backup_dir, Path::to_path_buf)
        .join(format!("{id}.jsonl"))
}

/// What a propagation changes on the descendants (J8.7): their DACL recomputed from their
/// parent (J8.4), their SACL recomputed the same way (`sacl`: `Some(replace)`, « Replace all
/// child object auditing entries »), their owner replaced (« Replace owner on subcontainers
/// and objects »).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Parts {
    pub dacl: bool,
    pub sacl: Option<bool>,
    pub owner: Option<Sid>,
}

impl Default for Parts {
    /// The DACL alone, as every propagation of J8.4.
    fn default() -> Self {
        Self {
            dacl: true,
            sacl: None,
            owner: None,
        }
    }
}

impl Parts {
    /// Do `a` and `b` agree on the parts propagated?
    fn same(&self, a: &SecurityDescriptor, b: &SecurityDescriptor) -> bool {
        (!self.dacl || ntfs::same_permissions(a, b))
            && (self.sacl.is_none() || ntfs::same_audit(a, b))
            && (self.owner.is_none() || a.owner == b.owner)
    }

    /// The parts of a descriptor to write to go from `present` to `wanted`.
    fn information(&self, present: &SecurityDescriptor, wanted: &SecurityDescriptor) -> u32 {
        let mut info = 0;
        if self.dacl && !ntfs::same_permissions(present, wanted) {
            info |= INFO_DACL;
        }
        if self.sacl.is_some() && !ntfs::same_audit(present, wanted) {
            info |= INFO_SACL;
        }
        if self.owner.is_some() && present.owner != wanted.owner {
            info |= INFO_OWNER;
        }
        info
    }

    /// The parts read of each element: the SACL only when it is propagated (it asks
    /// `SeSecurityPrivilege`).
    fn read(&self) -> u32 {
        if self.sacl.is_some() {
            INFO_OGD | INFO_SACL
        } else {
            INFO_OGD
        }
    }

    /// The fields of the journal and of the backup that say them, those of J8.4 left out.
    pub fn to_json(&self, into: &mut Map<String, Value>) {
        if !self.dacl {
            into.insert("droits".into(), false.into());
        }
        if let Some(replace) = self.sacl {
            into.insert("audit".into(), true.into());
            into.insert("remplacer_audit".into(), replace.into());
        }
        if let Some(owner) = &self.owner {
            into.insert("proprietaire".into(), owner.to_string().into());
        }
    }

    /// Read back; what is missing is as J8.4 wrote it (the DACL alone).
    pub fn from_json(from: &Value) -> Option<Self> {
        let owner = match from.get("proprietaire") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_str()?.parse().ok()?),
        };
        let sacl = (from.get("audit").and_then(Value::as_bool) == Some(true))
            .then(|| from.get("remplacer_audit").and_then(Value::as_bool) == Some(true));
        Some(Self {
            dacl: from.get("droits").and_then(Value::as_bool) != Some(false),
            sacl,
            owner,
        })
    }
}

/// What a backup says of its propagation (its first line).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub server: String,
    pub share: String,
    /// The folder whose descendants are recomputed, relative to the share.
    pub root: String,
    pub replace: bool,
    pub parts: Parts,
}

/// One element saved: its descriptor before, and the one written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub path: String,
    pub directory: bool,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

/// The backup being written: each line flushed to the disk before the batch it saves is
/// written.
struct Writer {
    file: std::fs::File,
    path: PathBuf,
}

impl Writer {
    fn create(path: &Path, header: &Header) -> Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| backup_error(path, e))?;
        }
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| backup_error(path, e))?;
        let mut writer = Self {
            file,
            path: path.to_path_buf(),
        };
        let mut head = json!({
            "version": VERSION,
            "serveur": header.server,
            "partage": header.share,
            "chemin": header.root,
            "remplacer": header.replace,
            "cree": crate::writer::timestamp(),
        });
        if let Value::Object(fields) = &mut head {
            header.parts.to_json(fields);
        }
        writer.line(&head)?;
        writer.sync()?;
        Ok(writer)
    }

    fn line(&mut self, value: &Value) -> Result<()> {
        let mut text = value.to_string();
        text.push('\n');
        self.file
            .write_all(text.as_bytes())
            .map_err(|e| backup_error(&self.path, e))
    }

    fn save(&mut self, saved: &[Saved]) -> Result<()> {
        for s in saved {
            self.line(&json!({
                "chemin": s.path,
                "dossier": s.directory,
                "avant": base64_encode(&s.before),
                "apres": base64_encode(&s.after),
            }))?;
        }
        self.sync()
    }

    fn sync(&mut self) -> Result<()> {
        self.file
            .sync_data()
            .map_err(|e| backup_error(&self.path, e))
    }
}

/// The elements of a backup, read line by line in the order they were saved (J8.7): an undo
/// of a large tree holds a batch, not the whole backup. A last line cut by a stop of the
/// application is left aside (its batch was not written); a bad line before it is an error.
pub struct Elements {
    lines: std::iter::Peekable<std::io::Lines<BufReader<std::fs::File>>>,
    path: PathBuf,
    /// Number of the next line, the header being the first.
    line: usize,
}

impl std::fmt::Debug for Elements {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Elements")
            .field("path", &self.path)
            .field("line", &self.line)
            .finish_non_exhaustive()
    }
}

impl Iterator for Elements {
    type Item = Result<Saved>;

    fn next(&mut self) -> Option<Result<Saved>> {
        let line = match self.lines.next()? {
            Ok(line) => line,
            Err(e) => return Some(Err(backup_error(&self.path, e))),
        };
        self.line += 1;
        let last = self.lines.peek().is_none();
        let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
        let parsed = serde_json::from_str::<Value>(&line).ok().and_then(|v| {
            Some(Saved {
                path: text(&v, "chemin")?,
                directory: v.get("dossier").and_then(Value::as_bool)?,
                before: base64_decode(&text(&v, "avant")?).ok()?,
                after: base64_decode(&text(&v, "apres")?).ok()?,
            })
        });
        match parsed {
            Some(saved) => Some(Ok(saved)),
            None if last => None,
            None => Some(Err(backup_error(&self.path, format!("line {}", self.line)))),
        }
    }
}

/// A backup opened: its header (its first line), and its elements to read.
pub fn open_backup(path: &Path) -> Result<(Header, Elements)> {
    let file = std::fs::File::open(path).map_err(|e| backup_error(path, e))?;
    let mut lines = BufReader::new(file).lines();
    let first = lines
        .next()
        .ok_or_else(|| backup_error(path, "empty"))?
        .map_err(|e| backup_error(path, e))?;
    let head: Value = serde_json::from_str(&first).map_err(|e| backup_error(path, e))?;
    let version = head.get("version").and_then(Value::as_u64);
    if !matches!(version, Some(1 | VERSION)) {
        return Err(backup_error(path, "unknown version"));
    }
    let text = |v: &Value, key: &str| v.get(key).and_then(Value::as_str).map(str::to_owned);
    let header = Header {
        server: text(&head, "serveur").ok_or_else(|| backup_error(path, "server"))?,
        share: text(&head, "partage").ok_or_else(|| backup_error(path, "share"))?,
        root: text(&head, "chemin").unwrap_or_default(),
        replace: head.get("remplacer").and_then(Value::as_bool) == Some(true),
        parts: Parts::from_json(&head).ok_or_else(|| backup_error(path, "parts"))?,
    };
    let elements = Elements {
        lines: lines.peekable(),
        path: path.to_path_buf(),
        line: 1,
    };
    Ok((header, elements))
}

/// A backup read back whole: its header and its elements, in the order they were saved.
pub fn read_backup(path: &Path) -> Result<(Header, Vec<Saved>)> {
    let (header, elements) = open_backup(path)?;
    Ok((header, elements.collect::<Result<Vec<_>>>()?))
}

/// The header of a backup alone.
pub fn read_header(path: &Path) -> Result<Header> {
    open_backup(path).map(|(header, _)| header)
}

/// Elements of a backup, counted without being decoded: its complete lines after the header
/// (a last line cut by a stop has no end). What the progress of a rewrite announces.
pub fn saved_count(path: &Path) -> Result<usize> {
    let mut file = BufReader::new(std::fs::File::open(path).map_err(|e| backup_error(path, e))?);
    let mut lines = 0usize;
    loop {
        let buffer = file.fill_buf().map_err(|e| backup_error(path, e))?;
        if buffer.is_empty() {
            break;
        }
        lines += buffer.iter().filter(|b| **b == b'\n').count();
        let n = buffer.len();
        file.consume(n);
    }
    Ok(lines.saturating_sub(1))
}

/// The next batch of `elements` (empty at the end).
fn next_batch(elements: &mut impl Iterator<Item = Result<Saved>>) -> Result<Vec<Saved>> {
    let mut batch = Vec::with_capacity(BATCH);
    for saved in elements.by_ref().take(BATCH) {
        batch.push(saved?);
    }
    Ok(batch)
}

// --- Retention of the backups -----------------------------------------------------------------

/// The backups named by the journal: those its undo (Ctrl+Z, the history) and resuming still
/// read. Every report counts, undone or not: its inverse names the same backup.
pub fn referenced(reports: &[crate::changes::Report]) -> HashSet<String> {
    reports
        .iter()
        .flat_map(|r| {
            r.changeset
                .operations
                .iter()
                .chain(r.rollback.iter().flat_map(|c| &c.operations))
        })
        .filter_map(|op| match op {
            crate::changes::Operation::PropagateInheritance { backup, .. } => Some(backup.clone()),
            _ => None,
        })
        .collect()
}

/// A backup of the folder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    pub id: String,
    pub size: u64,
    pub modified: SystemTime,
    /// Named by the journal: never removed.
    pub referenced: bool,
}

/// The backups of the folder (`dir`, or the one of the application), and whether the journal
/// (`journal`, read once the folder is listed) still names them. A backup is created only once
/// the intention that names it is journaled: one listed first and not named after is not the
/// backup of a write starting in another instance of the application.
pub fn inventory(
    dir: Option<&Path>,
    journal: impl FnOnce() -> Vec<crate::changes::Report>,
) -> std::io::Result<Vec<Stored>> {
    let dir = dir.map_or_else(backup_dir, Path::to_path_buf);
    let mut found = Vec::new();
    let listing = match std::fs::read_dir(&dir) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(found),
        Err(e) => return Err(e),
    };
    for entry in listing {
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name.to_str().and_then(|n| n.strip_suffix(".jsonl")) else {
            continue;
        };
        let meta = entry.metadata()?;
        if !valid_id(id) || !meta.is_file() {
            continue;
        }
        found.push(Stored {
            id: id.to_owned(),
            size: meta.len(),
            modified: meta.modified()?,
            referenced: false,
        });
    }
    let named = referenced(&journal());
    for s in &mut found {
        s.referenced = named.contains(&s.id);
    }
    found.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(found)
}

/// What a purge removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Purged {
    pub removed: usize,
    pub bytes: u64,
}

/// Removes the backups of `stored` the journal no longer names and not changed for
/// `older_than` (all of them with `Duration::ZERO`); one whose propagation this process
/// follows is kept.
pub fn purge(
    dir: Option<&Path>,
    stored: &[Stored],
    older_than: Duration,
    now: SystemTime,
) -> std::io::Result<Purged> {
    let followed: HashSet<String> = controls()
        .lock()
        .map(|all| all.keys().cloned().collect())
        .unwrap_or_default();
    let mut purged = Purged::default();
    for s in stored {
        let old = now
            .duration_since(s.modified)
            .is_ok_and(|age| age >= older_than);
        if s.referenced || !old || followed.contains(&s.id) {
            continue;
        }
        match std::fs::remove_file(backup_path(&s.id, dir)) {
            Ok(()) => {
                purged.removed += 1;
                purged.bytes += s.size;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(purged)
}

// --- Propagation ------------------------------------------------------------------------------

fn decode(bytes: &[u8]) -> Option<SecurityDescriptor> {
    SecurityDescriptor::decode(bytes).ok()
}

fn encode(descriptor: &SecurityDescriptor) -> Option<Vec<u8>> {
    descriptor.encode().ok()
}

/// What a batch decided for one element: the parts to write (`INFO_DACL`, `INFO_OWNER`);
/// `blind` for an element whose descriptor could not be read, given its owner all the same
/// (taking ownership is what opens it): it is not read back.
struct Pending {
    saved: Saved,
    wanted: SecurityDescriptor,
    info: u32,
    blind: bool,
}

/// The descriptor that carries only an owner: what is written on an element that cannot be
/// read (the server takes the owner alone from it, `OWNER_SECURITY_INFORMATION`).
fn owner_only(owner: Sid) -> SecurityDescriptor {
    SecurityDescriptor {
        revision: annuaire_codecs::sd::REVISION,
        control: annuaire_codecs::sd::SE_SELF_RELATIVE,
        owner: Some(owner),
        group: None,
        sacl: None,
        dacl: None,
    }
}

impl Pending {
    /// An element that cannot be read, given `owner`: saved without its « before ».
    fn blind(entry: &sysvol::Entry, owner: Sid) -> Option<Self> {
        let wanted = owner_only(owner);
        Some(Self {
            saved: Saved {
                path: entry.path.clone(),
                directory: entry.directory,
                before: Vec::new(),
                after: encode(&wanted)?,
            },
            wanted,
            info: INFO_OWNER,
            blind: true,
        })
    }
}

/// Writes the pending elements of a batch (already saved), reads them back, counts and
/// reports; the descriptor each one has now (to be the parent of the next level). The owner
/// goes first, on its own, with `FILE_OPEN_FOR_BACKUP_INTENT` (a Windows server applies then
/// the restore privilege of the account, ADR 0023 § 5); the DACL after, which the new owner
/// may write even if the DACL gave it nothing.
fn write_batch(
    session: &mut Session,
    pending: &[Pending],
    parts: &Parts,
    control: &Control,
) -> sysvol::Result<HashMap<String, SecurityDescriptor>> {
    let mut now = HashMap::new();
    if pending.is_empty() {
        return Ok(now);
    }
    let mut refused: Vec<Option<u32>> = vec![None; pending.len()];
    // The owner alone, then the elements by the rest they write (DACL, SACL, both).
    let steps = [
        (INFO_OWNER, INFO_OWNER, BACKUP_INTENT),
        (INFO_DACL | INFO_SACL, INFO_DACL, 0),
        (INFO_DACL | INFO_SACL, INFO_SACL, 0),
        (INFO_DACL | INFO_SACL, INFO_DACL | INFO_SACL, 0),
    ];
    for (mask, step, options) in steps {
        let chosen: Vec<(&Pending, &mut Option<u32>)> = pending
            .iter()
            .zip(refused.iter_mut())
            .filter(|(p, r)| p.info & mask == step && r.is_none())
            .collect();
        if chosen.is_empty() {
            continue;
        }
        let items: Vec<(String, Vec<u8>)> = chosen
            .iter()
            .map(|(p, _)| (p.saved.path.clone(), p.saved.after.clone()))
            .collect();
        let statuses = session.set_descriptors_with(&items, step, options)?;
        for ((_, r), s) in chosen.into_iter().zip(statuses) {
            if s != status::SUCCESS {
                *r = Some(s);
            }
        }
    }
    let mut accepted = Vec::new();
    let mut written = 0;
    for (p, r) in pending.iter().zip(&refused) {
        match r {
            // Accepted, not read back: the account may still not read it.
            None if p.blind => written += 1,
            None => accepted.push(p),
            Some(s) => control.refuse(&p.saved.path, Reason::Refused(*s)),
        }
    }
    let paths: Vec<String> = accepted.iter().map(|p| p.saved.path.clone()).collect();
    let read = session.descriptors(&paths, parts.read())?;
    for (p, r) in accepted.iter().zip(read) {
        // Given to another owner, an element the DACL closes to the account can no longer
        // be read back: accepted, it counts as written.
        if r == Err(status::ACCESS_DENIED) && p.info & INFO_OWNER != 0 {
            written += 1;
            now.insert(p.saved.path.clone(), p.wanted.clone());
            continue;
        }
        match r.ok().and_then(|b| decode(&b)) {
            Some(d) if parts.same(&d, &p.wanted) => {
                written += 1;
                now.insert(p.saved.path.clone(), d);
            }
            other => {
                control.refuse(&p.saved.path, Reason::NotAsWritten);
                if let Some(d) = other {
                    now.insert(p.saved.path.clone(), d);
                }
            }
        }
    }
    control.wrote(written);
    Ok(now)
}

/// A SACL is written with the DACL (as it is), the request of automatic inheritance on both:
/// Samba (`acl_xattr`) takes the control bits of the descriptor sent only with the DACL, and
/// drops the protection and the automatic inheritance of a SACL written alone (ADR 0023 § 5).
fn with_dacl(info: u32, wanted: &mut SecurityDescriptor) -> u32 {
    use annuaire_codecs::sd;
    if info & INFO_SACL == 0 {
        return info;
    }
    if wanted.control & sd::SE_DACL_AUTO_INHERITED != 0 {
        wanted.control |= sd::SE_DACL_AUTO_INHERIT_REQ;
    }
    if wanted.control & sd::SE_SACL_AUTO_INHERITED != 0 {
        wanted.control |= sd::SE_SACL_AUTO_INHERIT_REQ;
    }
    info | INFO_DACL
}

/// What is recomputed under a folder.
#[derive(Debug, Clone, Copy, Default)]
struct Below {
    dacl: bool,
    sacl: bool,
}

/// The bits of the control that go with the SACL.
const SACL_BITS: u16 = annuaire_codecs::sd::SE_SACL_PRESENT
    | annuaire_codecs::sd::SE_SACL_PROTECTED
    | annuaire_codecs::sd::SE_SACL_AUTO_INHERITED
    | annuaire_codecs::sd::SE_SACL_AUTO_INHERIT_REQ;

/// Recomputes the descendants of `header.root` from its present descriptor, saving in `backup`
/// (a new file) each one changed before writing it. `total`: the elements counted before, for
/// the progress. Ends early, with what is written saved, when `control` is asked to stop.
pub fn propagate(
    session: &mut Session,
    header: &Header,
    backup: &Path,
    total: usize,
    control: &Control,
) -> Result<()> {
    control.start(total);
    let root = header.root.clone();
    let read = session
        .descriptors(std::slice::from_ref(&root), header.parts.read())?
        .into_iter()
        .next()
        .unwrap_or(Err(status::OBJECT_NAME_NOT_FOUND));
    let root_sd = match read {
        Ok(bytes) => decode(&bytes).ok_or_else(|| {
            SysvolError::Session(crate::smb::SmbError::new(
                crate::smb::ErrorKind::Protocol,
                "unreadable descriptor",
            ))
        })?,
        Err(s) => return Err(SysvolError::status(s, &root).into()),
    };
    let mut saving = Writer::create(backup, header)?;
    let parts = &header.parts;
    // Folders of the level, their descriptor as they are now (parents of the next level), and
    // whether the DACL and the SACL of their children are recomputed (not under a folder
    // where they are protected).
    let first = Below {
        dacl: parts.dacl,
        sacl: parts.sacl.is_some(),
    };
    let mut level: Vec<(String, SecurityDescriptor, Below)> = vec![(root, root_sd, first)];
    while !level.is_empty() {
        let mut next: Vec<(String, SecurityDescriptor, Below)> = Vec::new();
        for folders in level.chunks(BATCH) {
            let names: Vec<String> = folders.iter().map(|(p, _, _)| p.clone()).collect();
            let listed = session.children(&names)?;
            // (element, is a folder, index of its parent in `folders`)
            let mut elements: Vec<(sysvol::Entry, usize)> = Vec::new();
            for (index, ((path, _, _), found)) in folders.iter().zip(listed).enumerate() {
                match found {
                    Ok(entries) => elements.extend(entries.into_iter().map(|e| (e, index))),
                    Err(s) => control.refuse(path, Reason::Unlisted(s)),
                }
            }
            for batch in elements.chunks(BATCH) {
                if control.halt() {
                    control.finish();
                    return Ok(());
                }
                let paths: Vec<String> = batch.iter().map(|(e, _)| e.path.clone()).collect();
                let read = session.descriptors(&paths, parts.read())?;
                let mut pending = Vec::new();
                let mut kept: Vec<(String, SecurityDescriptor, Below)> = Vec::new();
                // Folders written: what is recomputed under them.
                let mut below: HashMap<String, Below> = HashMap::new();
                for ((entry, parent), r) in batch.iter().zip(read) {
                    let present = match r {
                        Ok(bytes) => match decode(&bytes) {
                            Some(d) => (bytes, d),
                            None => {
                                control.refuse(&entry.path, Reason::Unreadable(0));
                                continue;
                            }
                        },
                        Err(s) => {
                            // Unreadable, but its owner replaced: taking ownership is what
                            // opens an element whose DACL gives the account nothing.
                            match parts.owner.and_then(|o| Pending::blind(entry, o)) {
                                Some(p) => {
                                    if entry.directory {
                                        below.insert(entry.path.clone(), Below::default());
                                    }
                                    pending.push(p);
                                }
                                None => control.refuse(&entry.path, Reason::Unreadable(s)),
                            }
                            continue;
                        }
                    };
                    let Some((_, parent_sd, active)) = folders.get(*parent) else {
                        continue;
                    };
                    let mut wanted = if active.dacl {
                        ntfs::recompute(&present.1, parent_sd, entry.directory, header.replace)
                    } else {
                        present.1.clone()
                    };
                    let replace_sacl = parts.sacl == Some(true);
                    if active.sacl {
                        let audit = ntfs::recompute_sacl(
                            &present.1,
                            parent_sd,
                            entry.directory,
                            replace_sacl,
                        );
                        wanted.sacl = audit.sacl;
                        wanted.control =
                            (wanted.control & !SACL_BITS) | (audit.control & SACL_BITS);
                    }
                    if let Some(owner) = parts.owner {
                        wanted.owner = Some(owner);
                    }
                    // Windows does not go under a folder whose DACL is protected: what is
                    // under it inherits from it, and it does not change; the same for the
                    // SACL. The owner, it replaces everywhere.
                    let under = Below {
                        dacl: active.dacl && (header.replace || !ntfs::is_protected(&present.1)),
                        sacl: active.sacl && (replace_sacl || !ntfs::is_sacl_protected(&present.1)),
                    };
                    let descend = under.dacl || under.sacl || parts.owner.is_some();
                    let info = with_dacl(parts.information(&present.1, &wanted), &mut wanted);
                    if info == 0 {
                        if entry.directory && descend {
                            kept.push((entry.path.clone(), present.1, under));
                        }
                        continue;
                    }
                    if entry.directory {
                        below.insert(entry.path.clone(), under);
                    }
                    let Some(after) = encode(&wanted) else {
                        control.refuse(&entry.path, Reason::Unreadable(0));
                        continue;
                    };
                    pending.push(Pending {
                        saved: Saved {
                            path: entry.path.clone(),
                            directory: entry.directory,
                            before: present.0,
                            after,
                        },
                        wanted,
                        info,
                        blind: false,
                    });
                }
                let saved: Vec<Saved> = pending.iter().map(|p| p.saved.clone()).collect();
                saving.save(&saved)?;
                let now = write_batch(session, &pending, parts, control)?;
                for p in pending.iter().filter(|p| p.saved.directory) {
                    // A folder whose write was refused passes on what it has now.
                    let present = now
                        .get(&p.saved.path)
                        .cloned()
                        .or_else(|| decode(&p.saved.before))
                        .or_else(|| p.blind.then(|| p.wanted.clone()));
                    let under = below.get(&p.saved.path).copied().unwrap_or_default();
                    if let Some(d) = present
                        && (under.dacl || under.sacl || parts.owner.is_some())
                    {
                        next.push((p.saved.path.clone(), d, under));
                    }
                }
                next.extend(kept);
                control.examined(batch.len());
            }
        }
        level = next;
    }
    control.finish();
    Ok(())
}

/// Writes back the descriptors of a backup (`saved`, `total` elements, read batch by batch):
/// those saved before the propagation (`Undo`), or those it wrote (`Redo`). An element is
/// written only if it is as the other side left it; already as wanted, it is counted as
/// examined; changed since, it is reported and kept.
pub fn rewrite(
    session: &mut Session,
    saved: impl IntoIterator<Item = Result<Saved>>,
    total: usize,
    parts: &Parts,
    direction: Direction,
    control: &Control,
) -> Result<()> {
    control.start(total);
    let mut saved = saved.into_iter();
    loop {
        if control.halt() {
            break;
        }
        let batch = next_batch(&mut saved)?;
        if batch.is_empty() {
            break;
        }
        let paths: Vec<String> = batch.iter().map(|s| s.path.clone()).collect();
        let read = session.descriptors(&paths, parts.read())?;
        let mut pending = Vec::new();
        for (s, r) in batch.iter().zip(read) {
            let (from, to) = match direction {
                Direction::Undo => (&s.after, &s.before),
                Direction::Compute | Direction::Redo => (&s.before, &s.after),
            };
            // An element given its owner without being read (J8.7): nothing to write back;
            // written again, its owner alone.
            if s.before.is_empty() {
                match (direction, decode(&s.after).and_then(|d| d.owner)) {
                    (Direction::Undo, _) | (_, None) => control.refuse(&s.path, Reason::NotSaved),
                    (_, Some(owner)) => {
                        let entry = sysvol::Entry {
                            path: s.path.clone(),
                            directory: s.directory,
                            size: 0,
                            modified: 0,
                        };
                        let as_owner = r.ok().and_then(|b| decode(&b)).and_then(|d| d.owner);
                        if as_owner != Some(owner)
                            && let Some(p) = Pending::blind(&entry, owner)
                        {
                            pending.push(p);
                        }
                    }
                }
                continue;
            }
            let present = match r {
                Ok(bytes) => decode(&bytes),
                Err(st) => {
                    control.refuse(&s.path, Reason::Unreadable(st));
                    continue;
                }
            };
            let (Some(present), Some(from_sd), Some(to_sd)) = (present, decode(from), decode(to))
            else {
                control.refuse(&s.path, Reason::Unreadable(0));
                continue;
            };
            if parts.same(&present, &to_sd) {
                continue;
            }
            if !parts.same(&present, &from_sd) {
                control.refuse(&s.path, Reason::Changed);
                continue;
            }
            // Written with the inheritance flags `SetSecurityInfo` sets.
            let mut wanted =
                ntfs::written(&to_sd, ntfs::dacl_of(&to_sd), ntfs::is_protected(&to_sd));
            if parts.sacl.is_some() {
                wanted = ntfs::with_sacl(
                    &wanted,
                    &ntfs::explicit_sacl(&to_sd),
                    &ntfs::inherited_sacl(&to_sd),
                    ntfs::is_sacl_protected(&to_sd),
                );
            }
            let info = with_dacl(parts.information(&present, &wanted), &mut wanted);
            let Some(after) = encode(&wanted) else {
                control.refuse(&s.path, Reason::Unreadable(0));
                continue;
            };
            pending.push(Pending {
                saved: Saved {
                    path: s.path.clone(),
                    directory: s.directory,
                    before: from.clone(),
                    after,
                },
                wanted,
                info,
                blind: false,
            });
        }
        write_batch(session, &pending, parts, control)?;
        control.examined(batch.len());
    }
    control.finish();
    Ok(())
}

/// Did a rewrite of these elements (`Undo` or `Redo`) cut by a stop of the application take
/// place? True as soon as one element is as it had to become in the `parts` propagated, false
/// if every one is still as it was, `None` if they do not tell (none read, or each changed
/// since). An element whose two descriptors agree on these parts tells nothing, nor one given
/// its owner without being read; a backup of such elements only had nothing to write: done.
pub fn rewritten(
    session: &mut Session,
    saved: impl IntoIterator<Item = Result<Saved>>,
    parts: &Parts,
    direction: Direction,
) -> Result<Option<bool>> {
    let differs = |s: &Saved| match (decode(&s.before), decode(&s.after)) {
        (Some(a), Some(b)) => !parts.same(&a, &b),
        _ => !s.before.is_empty(),
    };
    let (mut telling, mut untouched, mut differing) = (0, 0, false);
    let mut saved = saved.into_iter();
    loop {
        let batch = next_batch(&mut saved)?;
        if batch.is_empty() {
            break;
        }
        let paths: Vec<String> = batch.iter().map(|s| s.path.clone()).collect();
        let read = session.descriptors(&paths, parts.read())?;
        for (s, r) in batch.iter().zip(read) {
            if !differs(s) {
                continue;
            }
            differing = true;
            let (from, to) = match direction {
                Direction::Undo => (&s.after, &s.before),
                Direction::Compute | Direction::Redo => (&s.before, &s.after),
            };
            let (Some(present), Some(from), Some(to)) =
                (r.ok().and_then(|b| decode(&b)), decode(from), decode(to))
            else {
                continue;
            };
            telling += 1;
            if parts.same(&present, &to) {
                return Ok(Some(true));
            }
            if parts.same(&present, &from) {
                untouched += 1;
            }
        }
    }
    Ok(if telling == 0 && !differing {
        Some(true)
    } else {
        (untouched > 0).then_some(false)
    })
}

/// Elements under `root` (the root itself not counted), walked level by level: what the
/// confirmation of a propagation announces; folders and files apart. A level is listed by
/// batches of folders, and only the folders of the next level are kept: the memory follows the
/// folders of a level, not the whole tree (J8.7). A folder that cannot be listed is not
/// counted under; the root, the error.
pub fn count(session: &mut Session, root: &str) -> sysvol::Result<(usize, usize)> {
    let (mut folders, mut files) = (0, 0);
    let mut level = vec![root.to_owned()];
    let mut first = true;
    while !level.is_empty() {
        let mut next = Vec::new();
        for chunk in level.chunks(BATCH) {
            for (folder, listed) in chunk.iter().zip(session.children(chunk)?) {
                match listed {
                    Ok(entries) => {
                        for e in entries {
                            if e.directory {
                                folders += 1;
                                next.push(e.path);
                            } else {
                                files += 1;
                            }
                        }
                    }
                    Err(s) if first => return Err(SysvolError::status(s, folder)),
                    Err(_) => {}
                }
            }
        }
        first = false;
        level = next;
    }
    Ok((folders, files))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "annuaire-propagation-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn identifiers() {
        let id = new_id();
        assert!(valid_id(&id), "{id}");
        assert_eq!(id.len(), 14 + 1 + 8, "{id}");
        assert!(!valid_id("../etc/passwd"));
        assert!(!valid_id(""));
        assert!(!valid_id("a/b"));
        assert_eq!(
            backup_path("x", Some(Path::new("/tmp/p"))),
            PathBuf::from("/tmp/p/x.jsonl")
        );
    }

    #[test]
    fn directions() {
        assert_eq!(Direction::Compute.inverse(), Direction::Undo);
        assert_eq!(Direction::Undo.inverse(), Direction::Redo);
        assert_eq!(Direction::Redo.inverse(), Direction::Undo);
        for d in [Direction::Compute, Direction::Undo, Direction::Redo] {
            assert_eq!(Direction::of_name(d.name()), Some(d));
        }
        assert_eq!(Direction::of_name("autre"), None);
    }

    #[test]
    fn backup_round_trip_and_cut_line() {
        let dir = scratch("backup");
        let path = backup_path("essai", Some(&dir));
        let header = Header {
            server: "fs1.lab.test".into(),
            share: "Commun".into(),
            root: "a\\b".into(),
            replace: true,
            parts: Parts {
                dacl: false,
                sacl: None,
                owner: Some("S-1-5-32-544".parse().unwrap()),
            },
        };
        let one = Saved {
            path: "a\\b\\c".into(),
            directory: true,
            before: vec![1, 2, 3],
            after: vec![4, 5],
        };
        let mut w = Writer::create(&path, &header).unwrap();
        w.save(std::slice::from_ref(&one)).unwrap();
        drop(w);
        // A second creation does not overwrite the backup.
        assert!(Writer::create(&path, &header).is_err());
        let (h, saved) = read_backup(&path).unwrap();
        assert_eq!(h, header);
        assert_eq!(saved, vec![one.clone()]);
        assert_eq!(read_header(&path).unwrap(), header);
        assert_eq!(saved_count(&path).unwrap(), 1);
        // A last line cut by a stop is left aside; a bad line before the end is an error.
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"chemin\":\"a\\\\b\\\\d\",\"dos");
        std::fs::write(&path, &text).unwrap();
        assert_eq!(read_backup(&path).unwrap().1, vec![one.clone()]);
        assert_eq!(saved_count(&path).unwrap(), 1);
        text.push_str("\n{}\n");
        std::fs::write(&path, &text).unwrap();
        assert!(read_backup(&path).is_err());
        // Read line by line: the good element first, then the bad line, said by its number.
        let (_, mut elements) = open_backup(&path).unwrap();
        assert_eq!(elements.next().unwrap().unwrap(), one);
        let bad = elements.next().unwrap();
        assert!(
            matches!(&bad, Err(Error::Backup { detail, .. }) if detail == "line 3"),
            "{bad:?}"
        );
        // A backup of J8.4 (version 1): the DACL alone.
        let old = backup_path("ancienne", Some(&dir));
        std::fs::write(
            &old,
            "{\"version\":1,\"serveur\":\"fs1\",\"partage\":\"C\",\"chemin\":\"a\",\"remplacer\":false}\n",
        )
        .unwrap();
        let (h, saved) = read_backup(&old).unwrap();
        assert_eq!(h.parts, Parts::default());
        assert!(saved.is_empty());
        std::fs::write(
            &old,
            "{\"version\":3,\"serveur\":\"fs1\",\"partage\":\"C\"}\n",
        )
        .unwrap();
        assert!(read_backup(&old).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn propagation(backup: &str) -> crate::changes::Operation {
        crate::changes::Operation::PropagateInheritance {
            unc: "\\\\fs1\\Commun\\a".into(),
            server: "fs1".into(),
            share: "Commun".into(),
            path: "a".into(),
            replace: false,
            parts: Parts::default(),
            backup: backup.into(),
            direction: Direction::Compute,
            count: 3,
        }
    }

    fn report(operations: Vec<crate::changes::Operation>) -> crate::changes::Report {
        crate::changes::Report {
            id: "r".into(),
            timestamp: String::new(),
            domain: "lab.test".into(),
            dc: "dc1".into(),
            user: String::new(),
            changeset: crate::changes::Changeset {
                operations,
                remarks: Vec::new(),
            },
            applied: Vec::new(),
            issue: crate::changes::Issue::Applied,
            error: None,
            rollback: None,
            origins: Vec::new(),
            rollback_applied: Vec::new(),
            rollback_error: None,
            doubtful: None,
            doubtful_rollback: None,
            resumes: None,
            resumed_by: None,
        }
    }

    #[test]
    fn purge_keeps_what_the_journal_names() {
        let dir = scratch("purge");
        std::fs::create_dir_all(&dir).unwrap();
        for id in ["ancienne", "nommee", "retour", "suivie", "recente"] {
            std::fs::write(backup_path(id, Some(&dir)), b"{}\n").unwrap();
        }
        // Not a backup: left alone.
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        let mut rolled_back = report(Vec::new());
        rolled_back.rollback = Some(crate::changes::Changeset {
            operations: vec![propagation("retour")],
            remarks: Vec::new(),
        });
        let journal = vec![report(vec![propagation("nommee")]), rolled_back];
        let stored = inventory(Some(&dir), || journal.clone()).unwrap();
        let ids: Vec<(&str, bool)> = stored
            .iter()
            .map(|s| (s.id.as_str(), s.referenced))
            .collect();
        assert_eq!(
            ids,
            [
                ("ancienne", false),
                ("nommee", true),
                ("recente", false),
                ("retour", true),
                ("suivie", false)
            ]
        );
        // Every file was just written: « recente » is younger than a day, the others are
        // seen as older by moving the clock.
        let day = Duration::from_secs(86_400);
        let now = SystemTime::now();
        let old: Vec<Stored> = stored
            .iter()
            .cloned()
            .map(|mut s| {
                if s.id != "recente" {
                    s.modified = now - 2 * day;
                }
                s
            })
            .collect();
        let follow = control("suivie");
        let purged = purge(Some(&dir), &old, day, now).unwrap();
        assert_eq!(
            purged,
            Purged {
                removed: 1,
                bytes: 3
            }
        );
        assert!(!backup_path("ancienne", Some(&dir)).exists());
        for kept in ["nommee", "retour", "suivie", "recente"] {
            assert!(backup_path(kept, Some(&dir)).exists(), "{kept}");
        }
        // The manual purge takes every backup the journal does not name, whatever its age,
        // but not one of a propagation under way.
        let stored = inventory(Some(&dir), || journal.clone()).unwrap();
        let purged = purge(Some(&dir), &stored, Duration::ZERO, SystemTime::now()).unwrap();
        assert_eq!(purged.removed, 1);
        assert!(backup_path("suivie", Some(&dir)).exists());
        drop(follow);
        forget("suivie");
        assert!(dir.join("notes.txt").exists());
        // No folder yet: nothing to list.
        assert!(
            inventory(Some(&dir.join("absent")), Vec::new)
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A share served by the fake server: `a` holds `b` (protected DACL) and `f.txt`, `b`
    /// holds `g.txt`; `a\\b\\g.txt` refuses to be written if `locked`.
    fn share(locked: bool) -> (crate::smb::fake_server::FakeServer, Session) {
        share_with(locked, crate::smb::fake_server::Config::default())
    }

    fn share_with(
        locked: bool,
        config: crate::smb::fake_server::Config,
    ) -> (crate::smb::fake_server::FakeServer, Session) {
        use crate::smb::fake_server::{FakeAuth, FakeServer, Fs};
        let sd = |text: &str| {
            annuaire_codecs::sddl::sd_from_sddl(text, None, false)
                .unwrap()
                .encode()
                .unwrap()
        };
        let mut fs = Fs::with(&[
            ("a", None),
            ("a\\b", None),
            ("a\\f.txt", Some(&b"x"[..])),
            ("a\\b\\g.txt", Some(&b"x"[..])),
        ]);
        for (path, text) in [
            ("a", "O:SYG:SYD:PAI(A;OICI;FA;;;BA)"),
            ("a\\b", "O:SYG:SYD:PAI(A;OICI;FA;;;SY)"),
            ("a\\f.txt", "O:SYG:SYD:AI(A;ID;FA;;;BA)"),
            ("a\\b\\g.txt", "O:SYG:SYD:AI(A;ID;FA;;;SY)"),
        ] {
            fs.nodes.get_mut(&path.to_lowercase()).unwrap().descriptor = sd(text);
        }
        fs.nodes.get_mut("a\\b\\g.txt").unwrap().locked = locked;
        let server = FakeServer::start_with(64, fs, config);
        let options = crate::smb::Options {
            port: server.port,
            ..crate::smb::Options::default()
        };
        let client =
            crate::smb::Client::connect("127.0.0.1", "Commun", &options, &mut FakeAuth::default())
                .unwrap();
        (server, Session::from_client("127.0.0.1", client))
    }

    fn owner_of(server: &crate::smb::fake_server::FakeServer, path: &str) -> String {
        let fs = server.fs.lock().unwrap();
        let d = SecurityDescriptor::decode(&fs.get(path).unwrap().descriptor).unwrap();
        d.owner.map(|o| o.to_string()).unwrap_or_default()
    }

    #[test]
    fn owner_replaced_everywhere_then_undone() {
        let dir = scratch("proprietaire");
        let backup = backup_path("essai", Some(&dir));
        let (server, mut session) = share(false);
        let owner: Sid = "S-1-5-32-544".parse().unwrap();
        let header = Header {
            server: "127.0.0.1".into(),
            share: "Commun".into(),
            root: "a".into(),
            replace: false,
            parts: Parts {
                dacl: false,
                sacl: None,
                owner: Some(owner),
            },
        };
        let control = Control::default();
        propagate(&mut session, &header, &backup, 3, &control).unwrap();
        let p = control.progress();
        // Under the protected folder too: the owner is replaced everywhere.
        assert_eq!((p.examined, p.written, p.refused), (3, 3, 0), "{p:?}");
        for path in ["a\\b", "a\\f.txt", "a\\b\\g.txt"] {
            assert_eq!(owner_of(&server, path), "S-1-5-32-544", "{path}");
        }
        // The root keeps its owner: the operation of the root writes it.
        assert_eq!(owner_of(&server, "a"), "S-1-5-18");
        // Each write asked WRITE_OWNER alone, with FILE_OPEN_FOR_BACKUP_INTENT.
        let writes: Vec<(String, u32, u32)> = server
            .seen
            .lock()
            .unwrap()
            .creates
            .iter()
            .filter(|(_, access, _)| access & 0x000C_0000 != 0)
            .cloned()
            .collect();
        assert_eq!(writes.len(), 3, "{writes:?}");
        assert!(
            writes
                .iter()
                .all(|(_, a, o)| *a == 0x0008_0000 && o & BACKUP_INTENT != 0),
            "{writes:?}"
        );
        let (read, saved) = read_backup(&backup).unwrap();
        assert_eq!(read, header);
        assert_eq!(saved.len(), 3);
        // Undone from the backup: the owners of before, the DACL untouched.
        let control = Control::default();
        rewrite(
            &mut session,
            saved.iter().cloned().map(Ok),
            saved.len(),
            &header.parts,
            Direction::Undo,
            &control,
        )
        .unwrap();
        assert_eq!(control.progress().written, 3);
        for path in ["a\\b", "a\\f.txt", "a\\b\\g.txt"] {
            assert_eq!(owner_of(&server, path), "S-1-5-18", "{path}");
        }
        session.close();
        server.join();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn owner_and_dacl_owner_first_and_refusals() {
        let dir = scratch("proprietaire-dacl");
        let backup = backup_path("essai", Some(&dir));
        let (server, mut session) = share(true);
        let owner: Sid = "S-1-5-32-544".parse().unwrap();
        // The root gets a new inheritable entry: the files below recompute their DACL, the
        // protected folder keeps its own, all get the new owner.
        {
            let mut fs = server.fs.lock().unwrap();
            let root = annuaire_codecs::sddl::sd_from_sddl(
                "O:SYG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)",
                None,
                false,
            )
            .unwrap();
            fs.nodes.get_mut("a").unwrap().descriptor = root.encode().unwrap();
        }
        let header = Header {
            server: "127.0.0.1".into(),
            share: "Commun".into(),
            root: "a".into(),
            replace: false,
            parts: Parts {
                dacl: true,
                sacl: None,
                owner: Some(owner),
            },
        };
        let control = Control::default();
        propagate(&mut session, &header, &backup, 3, &control).unwrap();
        let p = control.progress();
        assert_eq!((p.written, p.refused), (2, 1), "{p:?}");
        assert_eq!(
            control.refusals(),
            vec![Refusal {
                path: "a\\b\\g.txt".into(),
                reason: Reason::Refused(status::ACCESS_DENIED),
            }]
        );
        let fs = server.fs.lock().unwrap();
        let file = SecurityDescriptor::decode(&fs.get("a\\f.txt").unwrap().descriptor).unwrap();
        assert_eq!(file.owner, Some(owner));
        assert_eq!(ntfs::dacl_of(&file).len(), 2);
        let folder = SecurityDescriptor::decode(&fs.get("a\\b").unwrap().descriptor).unwrap();
        assert!(ntfs::is_protected(&folder) && ntfs::dacl_of(&folder).len() == 1);
        drop(fs);
        // For the file, the owner first (WRITE_OWNER, backup intent), then the DACL
        // (WRITE_DAC, without it); the protected folder, its owner only.
        let writes: Vec<(String, u32, u32)> = server
            .seen
            .lock()
            .unwrap()
            .creates
            .iter()
            .filter(|(_, access, _)| access & 0x000C_0000 != 0)
            .cloned()
            .collect();
        let of = |path: &str| -> Vec<(u32, u32)> {
            writes
                .iter()
                .filter(|(p, _, _)| p == path)
                .map(|(_, a, o)| (*a, *o & BACKUP_INTENT))
                .collect()
        };
        assert_eq!(
            of("a\\f.txt"),
            [(0x0008_0000, BACKUP_INTENT), (0x0006_0000, 0)]
        );
        assert_eq!(of("a\\b"), [(0x0008_0000, BACKUP_INTENT)]);
        session.close();
        server.join();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rewrite_cut_by_a_stop_is_ascertained() {
        use crate::smb::fake_server::{FakeAuth, FakeServer, Fs};
        let sd = |text: &str| {
            annuaire_codecs::sddl::sd_from_sddl(text, None, false)
                .unwrap()
                .encode()
                .unwrap()
        };
        let (old, new, other) = (
            sd("O:BAG:BAD:AI(A;ID;FA;;;BA)"),
            sd("O:BAG:BAD:AI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;AU)"),
            sd("O:BAG:BAD:AI(A;;FA;;;SY)"),
        );
        let mut fs = Fs::with(&[
            ("a", None),
            ("a\\f1", Some(&b"x"[..])),
            ("a\\f2", Some(&b"y"[..])),
        ]);
        let saved: Vec<Saved> = ["a\\f1", "a\\f2"]
            .iter()
            .map(|p| Saved {
                path: (*p).into(),
                directory: false,
                before: old.clone(),
                after: new.clone(),
            })
            .collect();
        let state = |fs: &mut Fs, f1: &[u8], f2: &[u8]| {
            fs.nodes.get_mut("a\\f1").unwrap().descriptor = f1.to_vec();
            fs.nodes.get_mut("a\\f2").unwrap().descriptor = f2.to_vec();
        };
        state(&mut fs, &old, &old);
        let server = FakeServer::start(16, fs);
        let options = crate::smb::Options {
            port: server.port,
            ..crate::smb::Options::default()
        };
        let client = crate::smb::Client::connect(
            "127.0.0.1",
            sysvol::SHARE,
            &options,
            &mut FakeAuth::default(),
        )
        .unwrap();
        let mut session = Session::from_client("127.0.0.1", client);
        let mut ask = |f1: &[u8], f2: &[u8], direction| {
            state(&mut server.fs.lock().unwrap(), f1, f2);
            rewritten(
                &mut session,
                saved.iter().cloned().map(Ok),
                &Parts::default(),
                direction,
            )
            .unwrap()
        };
        // Nothing redone yet; the undo found everything as it had to become.
        assert_eq!(ask(&old, &old, Direction::Redo), Some(false));
        assert_eq!(ask(&old, &old, Direction::Undo), Some(true));
        // One element written before the stop is enough.
        assert_eq!(ask(&new, &old, Direction::Redo), Some(true));
        // Changed since by someone else: they do not tell.
        assert_eq!(ask(&other, &other, Direction::Redo), None);
        // A backup with nothing to write was done.
        let same: Vec<Saved> = saved
            .iter()
            .cloned()
            .map(|mut s| {
                s.after = s.before.clone();
                s
            })
            .collect();
        assert_eq!(
            rewritten(
                &mut session,
                same.iter().cloned().map(Ok),
                &Parts::default(),
                Direction::Undo
            )
            .unwrap(),
            Some(true)
        );
        session.close();
    }

    #[test]
    fn auditing_entries_propagated_where_they_are_not_protected() {
        use annuaire_codecs::sddl;
        let dir = scratch("audit");
        let backup = backup_path("essai", Some(&dir));
        let set = |server: &crate::smb::fake_server::FakeServer, path: &str, text: &str| {
            let d = sddl::sd_from_sddl(text, None, false)
                .unwrap()
                .encode()
                .unwrap();
            server
                .fs
                .lock()
                .unwrap()
                .nodes
                .get_mut(path)
                .unwrap()
                .descriptor = d;
        };
        let (server, mut session) = share(false);
        set(
            &server,
            "a",
            "O:SYG:SYD:PAI(A;OICI;FA;;;BA)S:PAI(AU;OICISA;FA;;;WD)",
        );
        set(
            &server,
            "a\\b",
            "O:SYG:SYD:PAI(A;OICI;FA;;;SY)S:PAI(AU;FA;FR;;;BU)",
        );
        let header = Header {
            server: "127.0.0.1".into(),
            share: "Commun".into(),
            root: "a".into(),
            replace: false,
            parts: Parts {
                dacl: false,
                sacl: Some(false),
                owner: None,
            },
        };
        let control = Control::default();
        propagate(&mut session, &header, &backup, 3, &control).unwrap();
        let p = control.progress();
        // The file gets the entry; the folder whose SACL is protected keeps its own, and
        // nothing under it changes.
        assert_eq!((p.written, p.refused), (1, 0), "{p:?}");
        let read = |path: &str| {
            let fs = server.fs.lock().unwrap();
            SecurityDescriptor::decode(&fs.get(path).unwrap().descriptor).unwrap()
        };
        assert_eq!(
            sddl::sd_to_sddl(&read("a\\f.txt"), None).unwrap(),
            "O:SYG:SYD:AI(A;ID;FA;;;BA)S:AI(AU;IDSA;FA;;;WD)"
        );
        assert_eq!(ntfs::sacl_of(&read("a\\b\\g.txt")).len(), 0);
        // The SACL written with the DACL (READ_CONTROL, WRITE_DAC, ACCESS_SYSTEM_SECURITY).
        let seen = server.seen.lock().unwrap().creates.clone();
        assert!(
            seen.iter()
                .any(|(p, a, _)| p == "a\\f.txt" && *a == 0x0106_0000),
            "{seen:?}"
        );
        assert!(
            seen.iter()
                .all(|(_, a, _)| a & 0x0100_0000 == 0 || a & 0x0006_0000 != 0)
        );
        drop(seen);
        // Undone: the SACL of before, the DACL as it was; the backup read as it is written
        // back.
        let (_, elements) = open_backup(&backup).unwrap();
        let control = Control::default();
        rewrite(
            &mut session,
            elements,
            saved_count(&backup).unwrap(),
            &header.parts,
            Direction::Undo,
            &control,
        )
        .unwrap();
        assert_eq!(control.progress().written, 1);
        assert!(ntfs::sacl_of(&read("a\\f.txt")).is_empty());
        session.close();
        server.join();
        std::fs::remove_dir_all(&dir).unwrap();
        // Without SeSecurityPrivilege, the root cannot be read: the propagation stops at once.
        let config = crate::smb::fake_server::Config {
            no_security_privilege: true,
            ..crate::smb::fake_server::Config::default()
        };
        let (server, mut session) = share_with(false, config);
        let refused = propagate(&mut session, &header, &backup, 3, &Control::default());
        assert!(
            matches!(&refused, Err(Error::Smb(e)) if e.ntstatus() == Some(0xC000_0061)),
            "{refused:?}"
        );
        session.close();
        server.join();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn counted_level_by_level() {
        use crate::smb::fake_server::{FakeAuth, FakeServer, Fs};
        let (server, mut session) = share(false);
        assert_eq!(count(&mut session, "a").unwrap(), (1, 2));
        assert_eq!(count(&mut session, "a\\b").unwrap(), (0, 1));
        let absent = count(&mut session, "z");
        assert!(
            matches!(&absent, Err(e) if e.ntstatus() == Some(status::OBJECT_NAME_NOT_FOUND)),
            "{absent:?}"
        );
        session.close();
        server.join();
        // A level of more folders than a batch: listed batch by batch, nothing left out.
        let mut fs = Fs::with(&[("r", None)]);
        for i in 0..BATCH + 44 {
            fs.put(&format!("r\\d{i}"), None);
            fs.put(&format!("r\\d{i}\\f.txt"), Some(&b"x"[..]));
            if i % 100 == 0 {
                fs.put(&format!("r\\d{i}\\s"), None);
            }
        }
        let server = FakeServer::start(64, fs);
        let options = crate::smb::Options {
            port: server.port,
            ..crate::smb::Options::default()
        };
        let client =
            crate::smb::Client::connect("127.0.0.1", "Commun", &options, &mut FakeAuth::default())
                .unwrap();
        let mut session = Session::from_client("127.0.0.1", client);
        assert_eq!(
            count(&mut session, "r").unwrap(),
            (BATCH + 44 + 3, BATCH + 44)
        );
        session.close();
        server.join();
    }

    #[test]
    fn folder_listed_to_the_end_when_the_server_answers_in_part() {
        use crate::smb::fake_server::{Config, FakeAuth, FakeServer, Fs};
        // As Windows: 40 names a response, the buffer far from full (J8.7: 633 of 3 000).
        let mut fs = Fs::with(&[("r", None), ("r\\grand", None)]);
        for i in 0..300 {
            fs.put(&format!("r\\grand\\f{i}.txt"), Some(&b"x"[..]));
        }
        let parent =
            annuaire_codecs::sddl::sd_from_sddl("O:SYG:SYD:PAI(A;OICI;FA;;;BA)", None, false)
                .unwrap();
        let child = annuaire_codecs::sddl::sd_from_sddl("O:SYG:SYD:(A;;FA;;;SY)", None, false)
            .unwrap()
            .encode()
            .unwrap();
        for node in fs.nodes.values_mut() {
            node.descriptor = child.clone();
        }
        fs.nodes.get_mut("r").unwrap().descriptor = parent.encode().unwrap();
        let config = Config {
            directory_entries: Some(40),
            ..Config::default()
        };
        let server = FakeServer::start_with(64, fs, config);
        let options = crate::smb::Options {
            port: server.port,
            ..crate::smb::Options::default()
        };
        let client =
            crate::smb::Client::connect("127.0.0.1", "Commun", &options, &mut FakeAuth::default())
                .unwrap();
        let mut session = Session::from_client("127.0.0.1", client);
        assert_eq!(count(&mut session, "r").unwrap(), (1, 300));
        let listed = session.children(&["r\\grand".to_owned()]).unwrap();
        assert_eq!(listed[0].as_ref().map(Vec::len), Ok(300));
        let dir = scratch("en-partie");
        let control = Control::default();
        let header = Header {
            server: "127.0.0.1".into(),
            share: "Commun".into(),
            root: "r".into(),
            replace: true,
            parts: Parts::default(),
        };
        propagate(
            &mut session,
            &header,
            &backup_path("essai", Some(&dir)),
            301,
            &control,
        )
        .unwrap();
        let p = control.progress();
        assert_eq!(
            (p.examined, p.written, p.refused),
            (301, 301, 0),
            "{p:?} {:?}",
            control.refusals()
        );
        session.close();
        server.join();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn control_counts_and_stops() {
        let c = control("essai-controle");
        assert!(Arc::ptr_eq(&c, &control("essai-controle")));
        c.start(10);
        c.examined(4);
        c.wrote(3);
        c.refuse("x", Reason::Refused(status::ACCESS_DENIED));
        assert!(!c.halt());
        c.stop();
        assert!(c.halt());
        let p = c.progress();
        assert_eq!(
            p,
            Progress {
                total: 10,
                examined: 4,
                written: 3,
                refused: 1,
                stopped: true,
                finished: false
            }
        );
        forget("essai-controle");
        assert!(!Arc::ptr_eq(&c, &control("essai-controle")));
        forget("essai-controle");
    }
}

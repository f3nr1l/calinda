// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Operations of a changeset on the SYSVOL: verification, writing, ascertaining (ADR 0012,
//! `annuaire.core.ecriture_sysvol`).
//!
//! `writer` handles them as the LDAP operations, in the same order, with the same journal
//! and the same rollback; this module is their SMB part. The SYSVOL written is the one of the
//! DC of the write connection (the PDC emulator by default, as the GPMC): the directory half
//! and the file half of a GPO are written on the same DC.
//!
//! Guard: a file has no `uSNChanged`. Each operation carries the state read for the preview
//! (content, descriptor); the prior verification compares it with the SYSVOL, then again just
//! before the write. A file modified meanwhile makes the changeset refused, as an object of
//! the directory. After the write, the state is read back and compared with the state wanted.
//!
//! Descriptors are compared by their content (owner, group, ACEs of the DACL and its flags):
//! the bit `SE_SACL_PRESENT` varies with what is asked (ADR 0002).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use annuaire_codecs::sd::{self, SecurityDescriptor};

use crate::changes::{ErrorRecord, Operation, parent_dn, sysvol_path};
use crate::connection::Link;
use crate::error::LdapError;
use crate::search;
use crate::session::Entry;
use crate::smb::msg::status;
use crate::sysvol::{self, Protection, Session, State, SysvolError};
use crate::writer::{ProblemKind, WriteCatalog, WriteMsg};

/// Time allowed to a SYSVOL session (`sysvol.DELAI`).
pub const DELAY: Duration = Duration::from_secs(30);

/// Opens a session on the SYSVOL of a DC (DNS name) (`OuvrirSysvol`).
pub type Opener = Arc<dyn Fn(&str) -> sysvol::Result<Session> + Send + Sync>;

/// Session protected as the profile asks, `DELAY` (`sysvol.ouvrir`).
pub fn opener(protection: Protection) -> Opener {
    Arc::new(move |dc: &str| Session::open(dc, protection, DELAY))
}

// SE_DACL_AUTO_INHERITED is not part of it: a Windows server (NTFS) computes it itself and
// clears it from a DACL set over SMB; Samba keeps the one it is given.
pub(crate) const DACL_BITS: u16 =
    sd::SE_DACL_PRESENT | sd::SE_DACL_PROTECTED | sd::SE_DACL_AUTO_INHERIT_REQ;

/// ACEs of the DACL, each once: NTFS does not keep a repeated ACE (the form of
/// `dsacl2fsacl`, which the tool writes as Samba does, has one), which changes nothing to the
/// access.
pub(crate) fn aces(descriptor: &SecurityDescriptor) -> Option<Vec<&sd::Ace>> {
    let dacl = descriptor.dacl.as_ref()?;
    let mut seen: Vec<&sd::Ace> = Vec::new();
    for ace in &dacl.aces {
        if !seen.contains(&ace) {
            seen.push(ace);
        }
    }
    Some(seen)
}

/// Same owner, same group, same DACL (ACEs and flags), as the SYSVOL of a Samba DC and of a
/// Windows DC see it: repeated ACEs and the « automatic inheritance » bit aside
/// (`meme_descripteur`).
pub fn same_descriptor(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    let (Some(a), Some(b)) = (a, b) else {
        return a.is_none() && b.is_none();
    };
    let (Ok(x), Ok(y)) = (SecurityDescriptor::decode(a), SecurityDescriptor::decode(b)) else {
        return a == b;
    };
    x.owner == y.owner
        && x.group == y.group
        && aces(&x) == aces(&y)
        && x.control & DACL_BITS == y.control & DACL_BITS
}

/// Parts to write to go from `before` to `after`: the DACL if it changes, the owner or the
/// group only if they change (writing the owner asks one more right, and taking ownership of
/// an element does not give `WRITE_DAC`) (`informations`); the DACL when nothing changes.
pub fn information(before: &[u8], after: &[u8]) -> u32 {
    let (Ok(x), Ok(y)) = (
        SecurityDescriptor::decode(before),
        SecurityDescriptor::decode(after),
    ) else {
        return sysvol::INFO_OGD;
    };
    let mut info = 0;
    // `SE_DACL_AUTO_INHERIT_REQ` is sent, never read back: alone, it does not change the DACL.
    let state = sd::SE_DACL_PRESENT | sd::SE_DACL_PROTECTED;
    if x.dacl != y.dacl || x.control & state != y.control & state {
        info |= sysvol::INFO_DACL;
    }
    // The SACL, when the descriptor to write carries one (it was read, J8.7) and it changes;
    // a Windows server gives none for an element without auditing entries.
    let audit = sd::SE_SACL_PROTECTED;
    let carried = y.control & sd::SE_SACL_PRESENT != 0 || y.sacl.is_some();
    let entries =
        |d: &SecurityDescriptor| d.sacl.as_ref().map(|a| a.aces.clone()).unwrap_or_default();
    if carried && (entries(&x) != entries(&y) || x.control & audit != y.control & audit) {
        info |= sysvol::INFO_SACL;
    }
    if x.owner != y.owner {
        info |= sysvol::INFO_OWNER;
    }
    if x.group != y.group {
        info |= sysvol::INFO_GROUP;
    }
    if info == 0 {
        info = sysvol::INFO_DACL;
    }
    info
}

// --- PDC emulator ---------------------------------------------------------------------------

type ServerNames = HashMap<(String, u64, String), Option<String>>;

/// By bound connection: DN of a server object → `dNSHostName`, which does not change; the
/// role itself is read again each time (`fSMORoleOwner`).
fn server_names() -> &'static Mutex<ServerNames> {
    static NAMES: std::sync::OnceLock<Mutex<ServerNames>> = std::sync::OnceLock::new();
    NAMES.get_or_init(Mutex::default)
}

fn first_text(entry: &Entry, attribute: &str) -> Option<String> {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// DNS name of the PDC emulator (`fSMORoleOwner` of the domain), None if unreadable
/// (`emulateur_pdc`). `domain`: the domain object already read with `fSMORoleOwner`.
pub fn pdc_emulator(link: &mut Link, domain: Option<&Entry>) -> Result<Option<String>, LdapError> {
    let read;
    let domain = match domain {
        Some(d) => Some(d),
        None => {
            let base = link.state.root_dse.default_naming_context.clone();
            read = read_one(link, &base, "fSMORoleOwner")?;
            read.as_ref()
        }
    };
    let Some(owner) = domain.and_then(|d| first_text(d, "fSMORoleOwner")) else {
        return Ok(None);
    };
    let server = parent_dn(&owner).unwrap_or_default(); // parent of « NTDS Settings »
    let k = (
        link.state.dc.clone(),
        link.state.generation,
        server.to_lowercase(),
    );
    if let Some(known) = server_names()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&k)
    {
        return Ok(known.clone());
    }
    let name = read_one(link, &server, "dNSHostName")?.and_then(|e| first_text(&e, "dNSHostName"));
    server_names()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(k, name.clone());
    Ok(name)
}

fn read_one(link: &mut Link, dn: &str, attribute: &str) -> Result<Option<Entry>, LdapError> {
    search::read_entry(
        link.session.as_mut(),
        dn,
        &[attribute.to_owned()],
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )
}

/// Why a write of the SYSVOL is refused on this DC, or None (`hors_pdc`).
///
/// Samba does not replicate the SYSVOL, and under Windows the GPMC writes only on the PDC
/// emulator: a write connection that moved to another DC (PDC unreachable a moment) would
/// write the directory, replicated, and a SYSVOL the PDC does not have (seen on 2026-10-14: a
/// deletion made so on dc2 left the folder of the GPO on dc1). A write DC imposed by the
/// profile stays allowed: the administrator chose it.
pub fn off_pdc(
    link: &mut Link,
    imposed: bool,
    domain: Option<&Entry>,
) -> Result<Option<WriteMsg>, LdapError> {
    if imposed {
        return Ok(None);
    }
    let Some(pdc) = pdc_emulator(link, domain)? else {
        return Ok(None);
    };
    if pdc.eq_ignore_ascii_case(&link.state.dc) {
        return Ok(None);
    }
    Ok(Some(WriteMsg::NotOnPdc {
        pdc,
        dc: link.state.dc.clone(),
    }))
}

// --- Session ------------------------------------------------------------------------------------

/// The SYSVOL session of an application: opened at the first need on the DC of the LDAP
/// connection, closed at the end (`Session`).
pub struct SysvolSession {
    opener: Opener,
    pub dc: String,
    client: Option<Session>,
    /// The file servers of operations on shares (ADR 0023), protected as the SYSVOL.
    pub shares: crate::share_write::Shares,
}

impl std::fmt::Debug for SysvolSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SysvolSession")
            .field("dc", &self.dc)
            .field("open", &self.client.is_some())
            .finish()
    }
}

impl SysvolSession {
    pub fn new(opener: Opener, dc: &str) -> Self {
        Self {
            opener,
            dc: dc.to_owned(),
            client: None,
            shares: crate::share_write::Shares::default(),
        }
    }

    /// Same, operations on shares protected as `protection` (the option of the profile).
    pub fn with_protection(opener: Opener, dc: &str, protection: Protection) -> Self {
        let mut session = Self::new(opener, dc);
        session.shares = crate::share_write::Shares::new(protection);
        session
    }

    /// The session, opened at the first need, and again after an error of the session (J8.8).
    pub fn client(&mut self) -> sysvol::Result<&mut Session> {
        if self.client.as_ref().is_some_and(|c| !c.usable())
            && let Some(abandoned) = self.client.take()
        {
            abandoned.close();
        }
        if self.client.is_none() {
            self.client = Some((self.opener)(&self.dc)?);
        }
        self.client.as_mut().ok_or_else(|| {
            SysvolError::Session(crate::smb::SmbError::new(
                crate::smb::ErrorKind::Protocol,
                "no session",
            ))
        })
    }

    pub fn close(&mut self) {
        if let Some(client) = self.client.take() {
            client.close();
        }
        self.shares.close();
    }
}

impl Drop for SysvolSession {
    fn drop(&mut self) {
        self.close();
    }
}

// --- Prior verification -----------------------------------------------------------------------

/// Nature of the element the operation supposes: folder, file, or unknown (`indication`).
pub fn hint(op: &Operation) -> Option<bool> {
    match op {
        Operation::CreateFolder { .. } | Operation::DeleteFolder { .. } => Some(true),
        Operation::WriteFile { .. } | Operation::DeleteFile { .. } => Some(false),
        _ => None,
    }
}

/// A creation: a folder, or a file written without an old content.
fn creates(op: &Operation) -> bool {
    matches!(
        op,
        Operation::CreateFolder { .. } | Operation::WriteFile { old: None, .. }
    )
}

/// The operation carries a state to compare just before the write (its guard); a creation
/// has none: it fails by itself if the element exists (`garde_requise`).
pub fn guard_required(op: &Operation) -> bool {
    op.is_sysvol() && !creates(op)
}

/// The SYSVOL as it will be after the operations of the changeset already checked (`Vue`).
pub(crate) struct View<'s> {
    session: &'s mut SysvolSession,
    /// Changed by the changeset, by key.
    natures: HashMap<String, Option<bool>>,
    /// Content or descriptor changed by the changeset.
    touched: HashSet<String>,
    /// Read on the server, by key.
    states: HashMap<String, State>,
}

impl<'s> View<'s> {
    pub(crate) fn new(session: &'s mut SysvolSession) -> Self {
        Self {
            session,
            natures: HashMap::new(),
            touched: HashSet::new(),
            states: HashMap::new(),
        }
    }

    /// Everything the verification will compare (natures, contents, descriptors, contents
    /// of the folders), paths of the operations and their parents, in a single batch of
    /// compound requests: one round trip (`prelire`).
    pub(crate) fn preload(&mut self, operations: &[&Operation]) -> sysvol::Result<()> {
        let mut paths: Vec<(String, Option<bool>)> = Vec::new();
        let set =
            |paths: &mut Vec<(String, Option<bool>)>, path: &str, h, replace: bool| match paths
                .iter_mut()
                .find(|(p, _)| p == path)
            {
                Some((_, existing)) if replace => *existing = h,
                Some(_) => {}
                None => paths.push((path.to_owned(), h)),
            };
        for op in operations {
            let path = op.path().unwrap_or_default();
            let parent = sysvol::parent(path);
            if !parent.is_empty() && !self.states.contains_key(&sysvol::key(parent)) {
                set(&mut paths, parent, None, false);
            }
            set(&mut paths, path, hint(op), true);
        }
        let mut unique: Vec<(String, Option<bool>)> = Vec::new();
        for (path, h) in paths {
            let k = sysvol::key(&path);
            if !self.states.contains_key(&k) && !unique.iter().any(|(p, _)| sysvol::key(p) == k) {
                unique.push((path, h));
            }
        }
        if !unique.is_empty() {
            let states = self.session.client()?.states(&unique)?;
            for state in states {
                self.states.insert(sysvol::key(&state.path), state);
            }
        }
        Ok(())
    }

    /// The element read on the server (once) (`etat`).
    pub(crate) fn state(&mut self, path: &str, directory: Option<bool>) -> sysvol::Result<State> {
        let k = sysvol::key(path);
        let stale = match self.states.get(&k) {
            None => true,
            Some(s) => {
                (directory == Some(true) && s.nature == Some(true) && s.children.is_none())
                    || (directory == Some(false) && s.nature == Some(false) && s.content.is_none())
            }
        };
        if stale {
            let state = self
                .session
                .client()?
                .states(&[(path.to_owned(), directory)])?
                .into_iter()
                .next()
                .unwrap_or_else(|| State {
                    path: path.to_owned(),
                    nature: None,
                    descriptor: None,
                    content: None,
                    children: None,
                });
            self.states.insert(k.clone(), state);
        }
        Ok(self.states.get(&k).cloned().unwrap_or_else(|| State {
            path: path.to_owned(),
            nature: None,
            descriptor: None,
            content: None,
            children: None,
        }))
    }

    fn nature(&mut self, path: &str) -> sysvol::Result<Option<bool>> {
        let k = sysvol::key(path);
        if let Some(n) = self.natures.get(&k) {
            return Ok(*n);
        }
        let parent = sysvol::parent(path);
        if !parent.is_empty() && self.natures.get(&sysvol::key(parent)) == Some(&None) {
            return Ok(None); // parent deleted by the changeset
        }
        Ok(self.state(path, None)?.nature)
    }

    fn untouched(&self, path: &str) -> bool {
        let k = sysvol::key(path);
        !self.natures.contains_key(&k) && !self.touched.contains(&k)
    }

    fn content(&mut self, path: &str) -> sysvol::Result<Option<Vec<u8>>> {
        Ok(self.state(path, Some(false))?.content)
    }

    fn descriptor(&mut self, path: &str) -> sysvol::Result<Option<Vec<u8>>> {
        let state = self.state(path, None)?;
        Ok(if state.nature.is_some() {
            state.descriptor
        } else {
            None
        })
    }

    /// Content of the folder after the operations already checked (`enfants`): its keys.
    fn children(&mut self, path: &str) -> sysvol::Result<Vec<String>> {
        let k = sysvol::key(path);
        let on_server = if self.natures.contains_key(&k) {
            Vec::new()
        } else {
            self.state(path, Some(true))?.children.unwrap_or_default()
        };
        let mut out: Vec<String> = Vec::new();
        for c in on_server {
            if self.nature(&c)?.is_some() {
                out.push(sysvol::key(&c));
            }
        }
        for (c, n) in &self.natures {
            if n.is_some() && sysvol::key(sysvol::parent(c)) == k && !out.contains(c) {
                out.push(c.clone());
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Checks `op` against the view, then carries its effect into it (`verifier`).
pub(crate) fn check(
    view: &mut View<'_>,
    index: usize,
    op: &Operation,
    signal: &mut dyn FnMut(usize, &str, ProblemKind, WriteMsg),
) -> sysvol::Result<()> {
    let path = op.path().unwrap_or_default().to_owned();
    let k = sysvol::key(&path);
    let shown = sysvol_path(&path);
    let mut problem = |kind: ProblemKind, msg: WriteMsg| signal(index, &shown, kind, msg);

    let nature = view.nature(&path)?;
    if creates(op) {
        if nature.is_some() {
            problem(
                ProblemKind::Exists,
                WriteMsg::SysvolExists {
                    path: shown.clone(),
                },
            );
        }
        let parent = sysvol::parent(&path);
        if !parent.is_empty() && view.nature(parent)? != Some(true) {
            problem(
                ProblemKind::Target,
                WriteMsg::SysvolFolderMissing {
                    parent: parent.to_owned(),
                },
            );
        }
        view.natures
            .insert(k, Some(matches!(op, Operation::CreateFolder { .. })));
        return Ok(());
    }

    if nature.is_none() {
        problem(
            ProblemKind::Missing,
            WriteMsg::SysvolMissing {
                path: shown.clone(),
            },
        );
        view.natures.insert(k, None);
        return Ok(());
    }
    let folder = matches!(op, Operation::DeleteFolder { .. });
    let file = matches!(
        op,
        Operation::WriteFile { .. } | Operation::DeleteFile { .. }
    );
    if (folder && nature != Some(true)) || (file && nature != Some(false)) {
        problem(
            ProblemKind::Values,
            WriteMsg::SysvolNotA {
                path: shown.clone(),
                folder,
            },
        );
    }
    let untouched = view.untouched(&path);
    let content_changed = |view: &mut View<'_>, expected: Option<&[u8]>| -> sysvol::Result<bool> {
        Ok(untouched && view.content(&path)?.as_deref() != expected)
    };
    let descriptor_changed =
        |view: &mut View<'_>, expected: Option<&[u8]>| -> sysvol::Result<bool> {
            Ok(untouched
                && expected.is_some()
                && !same_descriptor(view.descriptor(&path)?.as_deref(), expected))
        };
    match op {
        Operation::WriteFile { old, .. } => {
            if content_changed(view, old.as_deref())? {
                problem(
                    ProblemKind::Version,
                    WriteMsg::SysvolContentChanged {
                        path: shown.clone(),
                    },
                );
            }
            view.touched.insert(k);
        }
        Operation::DeleteFile {
            content,
            descriptor,
            ..
        } => {
            if content_changed(view, Some(content))? {
                problem(
                    ProblemKind::Version,
                    WriteMsg::SysvolContentChanged {
                        path: shown.clone(),
                    },
                );
            }
            if descriptor_changed(view, descriptor.as_deref())? {
                problem(
                    ProblemKind::Version,
                    WriteMsg::SysvolPermissionsChanged {
                        path: shown.clone(),
                    },
                );
            }
            view.natures.insert(k, None);
        }
        Operation::DeleteFolder { descriptor, .. } => {
            if descriptor_changed(view, descriptor.as_deref())? {
                problem(
                    ProblemKind::Version,
                    WriteMsg::SysvolPermissionsChanged {
                        path: shown.clone(),
                    },
                );
            }
            if !view.children(&path)?.is_empty() {
                problem(
                    ProblemKind::NotLeaf,
                    WriteMsg::SysvolNotEmpty {
                        path: shown.clone(),
                    },
                );
            }
            view.natures.insert(k, None);
        }
        Operation::SetDescriptor { before, .. } => {
            if descriptor_changed(view, Some(before))? {
                problem(
                    ProblemKind::Version,
                    WriteMsg::SysvolPermissionsChanged {
                        path: shown.clone(),
                    },
                );
            }
            view.touched.insert(k);
        }
        _ => {}
    }
    Ok(())
}

// --- Writing --------------------------------------------------------------------------------------

/// Why a SYSVOL step failed: nothing was done (`Conflict`), the write was done but not seen
/// (`Verification`), or another refusal.
#[derive(Debug, Clone)]
pub enum StepError {
    Conflict(ErrorRecord),
    Verification(ErrorRecord),
    Other(ErrorRecord),
}

fn record(class: &str, message: String, detail: impl Into<String>) -> ErrorRecord {
    ErrorRecord {
        class: class.into(),
        message,
        detail: detail.into(),
    }
}

/// A refusal that means « the SYSVOL is no longer as in the preview » is a conflict; a step
/// accepted but not read back, an effect not seen (`_conflit`).
fn conflict(e: &SysvolError, shown: &str, catalog: &dyn WriteCatalog, dc: &str) -> StepError {
    let said = catalog.sysvol_error(e, dc);
    if let SysvolError::Reread { .. } = e {
        return StepError::Verification(record(
            "ErreurVerification",
            catalog.write_text(&WriteMsg::SysvolNotReread {
                path: shown.to_owned(),
            }),
            said.message,
        ));
    }
    let changed = e.ntstatus().is_some_and(|s| {
        sysvol::absent(s) || s == status::OBJECT_NAME_COLLISION || s == status::DIRECTORY_NOT_EMPTY
    });
    if matches!(e, SysvolError::Status { .. }) && changed {
        return StepError::Conflict(record(
            "ErreurConflit",
            catalog.write_text(&WriteMsg::SysvolChangedReadAgain {
                path: shown.to_owned(),
            }),
            said.message,
        ));
    }
    StepError::Other(said)
}

fn verified(
    condition: bool,
    shown: &str,
    what: &str,
    catalog: &dyn WriteCatalog,
) -> Result<(), StepError> {
    if condition {
        return Ok(());
    }
    Err(StepError::Verification(record(
        "ErreurVerification",
        catalog.write_text(&WriteMsg::SysvolNotInState {
            path: shown.to_owned(),
        }),
        what,
    )))
}

fn guarded(
    condition: bool,
    shown: &str,
    what: &str,
    catalog: &dyn WriteCatalog,
) -> Result<(), StepError> {
    if condition {
        return Ok(());
    }
    Err(StepError::Conflict(record(
        "ErreurConflit",
        catalog.write_text(&WriteMsg::SysvolModified {
            path: shown.to_owned(),
        }),
        what,
    )))
}

/// The guard: the element is still as the preview read it (`_controler`).
fn control(
    op: &Operation,
    state: &State,
    shown: &str,
    catalog: &dyn WriteCatalog,
) -> Result<(), StepError> {
    if state.nature.is_none() {
        return Err(StepError::Conflict(record(
            "ErreurConflit",
            catalog.write_text(&WriteMsg::SysvolNoLongerExists {
                path: shown.to_owned(),
            }),
            "absent",
        )));
    }
    let content = state.content.as_deref();
    let sd = state.descriptor.as_deref();
    match op {
        Operation::WriteFile { old, .. } => {
            guarded(content == old.as_deref(), shown, "contenu", catalog)
        }
        Operation::DeleteFile {
            content: expected,
            descriptor,
            ..
        } => {
            guarded(
                content == Some(expected.as_slice()),
                shown,
                "contenu",
                catalog,
            )?;
            match descriptor {
                Some(d) => guarded(same_descriptor(sd, Some(d)), shown, "descripteur", catalog),
                None => Ok(()),
            }
        }
        Operation::DeleteFolder {
            descriptor: Some(d),
            ..
        } => guarded(same_descriptor(sd, Some(d)), shown, "descripteur", catalog),
        Operation::SetDescriptor { before, .. } => guarded(
            same_descriptor(sd, Some(before)),
            shown,
            "descripteur",
            catalog,
        ),
        _ => Ok(()),
    }
}

/// Guard, write and read back (`appliquer`). `guard`: the state of the element read just
/// before (by the prior verification, or with the read back of the previous operation);
/// otherwise it is read here (one round trip). The step and its read back form one compound
/// (one round trip); `then`: paths whose state is read in the same batch, returned (the guard
/// of the next operation).
pub(crate) fn apply(
    session: &mut SysvolSession,
    op: &Operation,
    guard: Option<State>,
    then: &sysvol::Hints,
    catalog: &dyn WriteCatalog,
) -> Result<Vec<State>, StepError> {
    let dc = session.dc.clone();
    let path = op.path().unwrap_or_default().to_owned();
    let shown = sysvol_path(&path);
    let fail = |e: SysvolError| conflict(&e, &shown, catalog, &dc);
    let client = session.client().map_err(fail)?;
    if guard_required(op) {
        let guard = match guard {
            Some(g) => g,
            None => client
                .states(&[(path.clone(), hint(op))])
                .map_err(fail)?
                .into_iter()
                .next()
                .unwrap_or_else(|| State {
                    path: path.clone(),
                    nature: None,
                    descriptor: None,
                    content: None,
                    children: None,
                }),
        };
        control(op, &guard, &shown, catalog)?;
    }
    match op {
        Operation::CreateFolder { descriptor, .. }
        | Operation::WriteFile {
            old: None,
            descriptor,
            ..
        } => {
            let folder = matches!(op, Operation::CreateFolder { .. });
            let content: &[u8] = match op {
                Operation::WriteFile { content, .. } => content,
                _ => &[],
            };
            let (read, next) = client
                .create(&path, folder, content, descriptor.as_deref(), then)
                .map_err(fail)?;
            verified(
                read.nature == Some(folder),
                &shown,
                "élément absent",
                catalog,
            )?;
            verified(
                folder || read.content.as_deref() == Some(content),
                &shown,
                "contenu",
                catalog,
            )?;
            if let Some(d) = descriptor {
                verified(
                    same_descriptor(read.descriptor.as_deref(), Some(d)),
                    &shown,
                    "descripteur",
                    catalog,
                )?;
            }
            Ok(next)
        }
        Operation::WriteFile { content, .. } => {
            let (read, next) = client.replace(&path, content, then).map_err(fail)?;
            verified(
                read.content.as_deref() == Some(content.as_slice()),
                &shown,
                "contenu",
                catalog,
            )?;
            Ok(next)
        }
        Operation::DeleteFile { .. } | Operation::DeleteFolder { .. } => {
            let folder = matches!(op, Operation::DeleteFolder { .. });
            let (read, next) = client.erase(&path, folder, then).map_err(fail)?;
            verified(
                read.nature.is_none(),
                &shown,
                "élément encore présent",
                catalog,
            )?;
            Ok(next)
        }
        Operation::SetDescriptor { before, after, .. } => {
            let info = information(before, after);
            let (read, next) = client.set(&path, after, info, then).map_err(fail)?;
            verified(
                same_descriptor(read.descriptor.as_deref(), Some(after)),
                &shown,
                "descripteur",
                catalog,
            )?;
            Ok(next)
        }
        _ => Ok(Vec::new()),
    }
}

// --- Ascertaining (resuming after an abrupt stop) -------------------------------------------------

/// Did the operation take place? True, false, or None if the SYSVOL does not tell
/// (`constater`).
pub fn ascertain(session: &mut SysvolSession, op: &Operation) -> sysvol::Result<Option<bool>> {
    let client = session.client()?;
    let path = op.path().unwrap_or_default().to_owned();
    let nature = client.nature(&path)?;
    let paths = std::slice::from_ref(&path);
    match op {
        Operation::CreateFolder { .. } => Ok(Some(nature == Some(true))),
        Operation::DeleteFolder { .. } | Operation::DeleteFile { .. } => Ok(Some(nature.is_none())),
        Operation::WriteFile { content, old, .. } => {
            if nature.is_none() {
                return Ok(if old.is_none() { Some(false) } else { None });
            }
            let read = client
                .read(paths)?
                .into_iter()
                .next()
                .flatten()
                .ok_or_else(|| SysvolError::status(status::OBJECT_NAME_NOT_FOUND, &path))?;
            if read == *content {
                return Ok(Some(true));
            }
            Ok((old.as_deref() == Some(read.as_slice())).then_some(false))
        }
        Operation::SetDescriptor { before, after, .. } => {
            if nature.is_none() {
                return Ok(None);
            }
            let read = client
                .read_descriptors(paths, sysvol::INFO_OGD)?
                .into_iter()
                .next()
                .flatten()
                .ok_or_else(|| SysvolError::status(status::OBJECT_NAME_NOT_FOUND, &path))?;
            if same_descriptor(Some(&read), Some(after)) {
                return Ok(Some(true));
            }
            Ok(same_descriptor(Some(&read), Some(before)).then_some(false))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests;

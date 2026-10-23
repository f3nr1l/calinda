// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Writing of a changeset, « all or nothing » as far as LDAP allows (ADR 0006, J1.10,
//! `annuaire.core.ecriture`). AD and Samba have no transaction between objects. Three
//! mechanisms stand in for it:
//!
//! 1. **Prior verification** of every operation before the first write: existence, version
//!    (`uSNChanged`), values to remove still present, targets of the creations and moves,
//!    free DNs, deletion of a leaf, effective rights (`allowedAttributesEffective`,
//!    `allowedChildClassesEffective`). The changeset is evaluated in order, on a supposed
//!    state that accounts for the previous operations. A problem: nothing is written, issue
//!    `Refused`.
//! 2. **Automatic rollback**: if a write fails all the same, the inverse of the part done is
//!    applied at once. Issue `Cancelled` if it succeeds; `Incomplete` otherwise, and the
//!    report says exactly what stays applied.
//! 3. **Resume journal**: each step is written and synced in the journal before or after the
//!    write it describes (`intention` → (`avant` →) `fait` … → [`echec` → `retour` → …] →
//!    `bilan`), the same records as the Python application: one journal for both.
//!
//! The reads go out together (`Burst`): one round trip for the verification, and the read
//! back of each write carries the guard of the next operation. The operations on the SYSVOL
//! (`sysvol_write`) go in the same order, with the same journal and the same rollback, on the
//! SYSVOL of the DC of the connection (the PDC emulator, unless the profile imposes a write
//! DC). The rollback of a DNS write never lowers the serial number of a SOA
//! (`dns_write::soa_on_rollback`).

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::sync::{Arc, Mutex, PoisonError};

use annuaire_codecs::integer::{self, Width};
use serde_json::{Map, Value, json};

use crate::changes::{
    self, Applied, AttributeMap, Change, ChangeError, Changeset, ErrorRecord, Issue, Operation,
    Read, Report, Values, dn_key, is_sensitive, parent_dn, text_value,
};
use crate::connection::{Connection, Failure, Link};
use crate::dn::{self, Component};
use crate::error::{LdapError, code};
use crate::journal::Journal;
use crate::messages::Catalog;
use crate::profile::Profile;
use crate::search::{self, SD_DACL, SD_WITHOUT_SACL, Value as FilterValue};
use crate::session::{Entry, Modification, MsgId, Scope, SearchRequest};
use crate::sysvol::{self, State, SysvolError};
use crate::sysvol_write::{self, StepError, SysvolSession, View as SysvolView};

pub const APPLICATION: &str = "application";
pub const ROLLBACK: &str = "retour";
/// Attempts at most when `apply` gets a `retry`.
pub const ATTEMPTS: usize = 3;

/// Transformed by the DC (inheritance in a descriptor, `pwdLastSet = -1` become a date):
/// not checked, written by « replace ».
const UNCHECKABLE: [&str; 2] = ["ntsecuritydescriptor", "pwdlastset"];

const OBJECT_ATTRIBUTES: [&str; 4] = [
    "uSNChanged",
    "objectClass",
    "allowedAttributesEffective",
    "allowedChildClassesEffective",
];

const ALL: &str = "(objectClass=*)";

// --- Messages ------------------------------------------------------------------------------

/// What the prior verification found (`GenreProbleme`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProblemKind {
    Version,
    Missing,
    Exists,
    Target,
    Values,
    Rights,
    NotLeaf,
}

/// A problem of the prior verification (`Probleme`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Rank of the operation in the changeset.
    pub index: usize,
    pub dn: String,
    pub kind: ProblemKind,
    pub message: String,
}

/// Messages of the writer, said by the interface (its catalogue).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteMsg {
    Missing {
        dn: String,
    },
    ReadOnDc {
        dn: String,
        read: String,
        dc: String,
    },
    ChangedSincePreview {
        dn: String,
        read: i64,
        usn: i64,
    },
    ContainerMissing {
        parent: String,
    },
    ClassNotAllowed {
        class: String,
        parent: String,
    },
    AttributesRefused {
        attributes: String,
        dn: String,
    },
    AlreadyExists {
        dn: String,
    },
    ValuesNotAsExpected {
        dn: String,
    },
    NameTaken {
        dn: String,
    },
    NotLeaf {
        dn: String,
    },
    NothingWritten {
        n: usize,
    },
    ExistsOrSameIdentifier {
        dn: String,
    },
    ChangedReadAgain {
        dn: String,
    },
    ReadOnOtherDc {
        dn: String,
    },
    NoLongerExists {
        dn: String,
    },
    ModifiedReadAgain {
        dn: String,
    },
    NotInWantedState {
        dn: String,
    },
    StillExists {
        dn: String,
    },
    NoVersion,
    JournalNotWritten,
    JournalNothingModified,
    ReadOnly {
        domain: String,
    },
    /// The write connection is not on the PDC emulator (`hors_pdc`).
    NotOnPdc {
        pdc: String,
        dc: String,
    },
    SysvolExists {
        path: String,
    },
    SysvolFolderMissing {
        parent: String,
    },
    SysvolMissing {
        path: String,
    },
    SysvolNotA {
        path: String,
        folder: bool,
    },
    SysvolContentChanged {
        path: String,
    },
    SysvolPermissionsChanged {
        path: String,
    },
    SysvolNotEmpty {
        path: String,
    },
    SysvolNotReread {
        path: String,
    },
    SysvolChangedReadAgain {
        path: String,
    },
    SysvolNotInState {
        path: String,
    },
    SysvolModified {
        path: String,
    },
    SysvolNoLongerExists {
        path: String,
    },
    /// Shares of a file server (ADR 0023): `unc` names the share, `path` a file or folder.
    ShareExists {
        unc: String,
    },
    ShareMissing {
        unc: String,
    },
    ShareChanged {
        unc: String,
    },
    ShareNotInState {
        unc: String,
    },
    /// The share is as wanted but for its options or its connection limit, which the server
    /// keeps (a share of Samba's smb.conf; those of its registry are written, J8.7).
    ShareOptionsKept {
        unc: String,
    },
    /// A share created as a key of Samba's registry configuration is not served: the server
    /// does not read its shares from the registry; the key is removed (J8.7).
    ShareRegistryIgnored {
        unc: String,
    },
    FileNotInState {
        path: String,
    },
    /// The backup of a propagation (ADR 0023 § 5) cannot be written or read.
    BackupUnusable {
        file: String,
    },
    /// The server refused to write the owner of a file or folder (J8.7), with `status`.
    OwnerRefused {
        path: String,
        status: u32,
    },
    /// The server refused to write the auditing entries (SACL) of a file or folder (J8.7).
    AuditRefused {
        path: String,
        status: u32,
    },
}

/// The catalogue of the interface, for the messages of the writer and of the inverse.
pub trait WriteCatalog: Catalog + Send + Sync {
    fn write_text(&self, msg: &WriteMsg) -> String;
    /// An LDAP error as the interface says it (`traduire`): class, message, detail.
    fn ldap_error(&self, error: &LdapError, dc: &str) -> ErrorRecord;
    /// A SYSVOL error as the interface says it (`ErreurSysvol`, `erreur_session`).
    fn sysvol_error(&self, error: &SysvolError, dc: &str) -> ErrorRecord {
        let class = match error {
            SysvolError::Session(_) => "ErreurAnnuaire",
            _ => "ErreurSysvol",
        };
        record(class, error.to_string(), dc)
    }
    /// An error of a file or folder of a share (ADR 0023 § 5): as a SYSVOL error, the
    /// interface naming the file server rather than the SYSVOL of a DC.
    fn file_error(&self, error: &SysvolError, server: &str) -> ErrorRecord {
        self.sysvol_error(error, server)
    }
    /// An error of the share service of a file server (ADR 0023 § 4).
    fn share_error(&self, error: &crate::srvsvc::Error, server: &str) -> ErrorRecord {
        record("ErreurPartage", error.to_string(), server)
    }
}

fn record(class: &str, message: String, detail: impl Into<String>) -> ErrorRecord {
    ErrorRecord {
        class: class.into(),
        message,
        detail: detail.into(),
    }
}

/// An error that stops the writing of an operation.
#[derive(Debug, Clone)]
enum OpError {
    /// The write was accepted but its effect could not be seen.
    Verification(ErrorRecord),
    Record(ErrorRecord),
    Ldap(LdapError),
    Journal(String),
    /// The SYSVOL could not be read for the prior verification: nothing is written.
    Sysvol(ErrorRecord),
}

impl From<LdapError> for OpError {
    fn from(e: LdapError) -> Self {
        Self::Ldap(e)
    }
}

// --- Reads sent together ---------------------------------------------------------------------

/// Reads sent together **on the thread of the connection**: every request goes before the
/// first answer (`Rafale`). `read` and `search` send and return the rank of the answer;
/// `receive` waits for them all, in order: for each request its entries (empty if the object
/// does not exist or does not satisfy the filter), or None past the size limit. Any other
/// error is returned once every answer received.
pub(crate) struct Burst {
    ids: Vec<MsgId>,
}

impl Burst {
    pub(crate) fn new() -> Self {
        Self { ids: Vec::new() }
    }

    pub(crate) fn read(
        &mut self,
        link: &mut Link,
        dn_text: &str,
        attributes: &[&str],
        filter: &str,
        sd_flags: Option<i64>,
    ) -> Result<usize, LdapError> {
        self.search(link, dn_text, Scope::Base, filter, attributes, 0, sd_flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn search(
        &mut self,
        link: &mut Link,
        base: &str,
        scope: Scope,
        filter: &str,
        attributes: &[&str],
        limit: i32,
        sd_flags: Option<i64>,
    ) -> Result<usize, LdapError> {
        let id = link.session.search(SearchRequest {
            base: base.to_owned(),
            scope,
            filter: filter.to_owned(),
            attributes: attributes.iter().map(|&a| a.to_owned()).collect(),
            controls: sd_flags.map(search::sd_flags_control).into_iter().collect(),
            size_limit: limit,
        })?;
        self.ids.push(id);
        Ok(self.ids.len() - 1)
    }

    fn len(&self) -> usize {
        self.ids.len()
    }

    pub(crate) fn receive(
        &mut self,
        link: &mut Link,
    ) -> Result<Vec<Option<Vec<Entry>>>, LdapError> {
        let ids = std::mem::take(&mut self.ids);
        let mut answers = Vec::with_capacity(ids.len());
        let mut error: Option<LdapError> = None;
        for (rank, id) in ids.iter().enumerate() {
            match link.session.result(*id, Some(link.timeout)) {
                Ok(response) => answers.push(Some(response.into_entries())),
                Err(e) if e.code == code::NO_SUCH_OBJECT => answers.push(Some(Vec::new())),
                Err(e) if e.code == code::SIZELIMIT_EXCEEDED => answers.push(None),
                Err(e) if e.code == code::TIMEOUT => {
                    for rest in ids.iter().skip(rank + 1) {
                        let _ = link.session.abandon(*rest);
                    }
                    return Err(e);
                }
                Err(e) => {
                    error.get_or_insert(e);
                    answers.push(Some(Vec::new()));
                }
            }
        }
        match error {
            Some(e) => Err(e),
            None => Ok(answers),
        }
    }
}

fn first(answer: Option<&Option<Vec<Entry>>>) -> Option<Entry> {
    answer
        .and_then(Option::as_ref)
        .and_then(|entries| entries.first().cloned())
}

fn read_entry(
    link: &mut Link,
    dn_text: &str,
    attributes: &[&str],
    filter: &str,
) -> Result<Option<Entry>, LdapError> {
    let attributes: Vec<String> = attributes.iter().map(|&a| a.to_owned()).collect();
    search::read_entry(
        link.session.as_mut(),
        dn_text,
        &attributes,
        filter,
        None,
        Some(link.timeout),
    )
}

// --- Prior verification ------------------------------------------------------------------------

fn key(dn_text: &str) -> String {
    dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

fn parent_key(dn_text: &str) -> String {
    key(&parent_dn(dn_text).unwrap_or_default())
}

fn split(dn_text: &str) -> Vec<Component> {
    dn::split(dn_text).unwrap_or_default()
}

fn compose(components: &[Component]) -> String {
    dn::compose(components).unwrap_or_default()
}

fn lower_values(entry: Option<&Entry>, attribute: &str) -> HashSet<String> {
    entry
        .map(|e| {
            e.values(attribute)
                .iter()
                .map(|v| String::from_utf8_lossy(v).to_lowercase())
                .collect()
        })
        .unwrap_or_default()
}

/// The most derived class: the last of `objectClass`, as AD gives them.
fn class_of(values: &[Vec<u8>]) -> Option<String> {
    values
        .last()
        .map(|v| String::from_utf8_lossy(v).to_lowercase())
}

/// `uSNChanged` of an entry read (`usn_de`).
fn usn_of(entry: &Entry, catalog: &dyn WriteCatalog) -> Result<i64, OpError> {
    entry
        .values("uSNChanged")
        .first()
        .and_then(|v| integer::decode(v, Width::Bits64).ok())
        .ok_or_else(|| {
            OpError::Verification(record(
                "ErreurVerification",
                catalog.write_text(&WriteMsg::NoVersion),
                entry.dn.clone(),
            ))
        })
}

/// Filter true if the object carries `present` and none of `absent` (`_filtre_etat`). The
/// comparison is made by the server, with the matching rule of each attribute. Secrets and
/// attributes transformed by the DC are not tested.
pub fn state_filter(present: &AttributeMap, absent: &AttributeMap) -> String {
    let mut clauses: Vec<String> = Vec::new();
    let checkable = |a: &str| !is_sensitive(a) && !UNCHECKABLE.contains(&a.to_lowercase().as_str());
    for (attribute, values) in present {
        if checkable(attribute) {
            clauses.extend(
                values
                    .iter()
                    .filter_map(|v| search::eq(attribute, FilterValue::Bytes(v)).ok()),
            );
        }
    }
    for (attribute, values) in absent {
        if !checkable(attribute) {
            continue;
        }
        let kept: HashSet<String> = present
            .iter()
            .filter(|(a, _)| a == attribute)
            .flat_map(|(_, vs)| vs.iter())
            .filter_map(|v| text_value(v).map(str::to_lowercase))
            .collect();
        for v in values {
            if text_value(v).is_none_or(|t| !kept.contains(&t.to_lowercase())) {
                if let Ok(eq) = search::eq(attribute, FilterValue::Bytes(v)) {
                    clauses.push(search::not(&eq));
                }
            }
        }
    }
    if clauses.is_empty() {
        ALL.to_owned()
    } else {
        search::and(&clauses).unwrap_or_else(|_| ALL.to_owned())
    }
}

fn push(map: &mut AttributeMap, attribute: &str, values: &Values) {
    match map.iter_mut().find(|(a, _)| a == attribute) {
        Some((_, existing)) => existing.extend(values.iter().cloned()),
        None => map.push((attribute.to_owned(), values.clone())),
    }
}

/// (values added, values removed) by attribute (`_etats_modification`).
fn modification_states(changes: &[Change]) -> (AttributeMap, AttributeMap) {
    let (mut added, mut removed) = (Vec::new(), Vec::new());
    for c in changes {
        push(&mut added, &c.attribute, &c.added);
        push(&mut removed, &c.attribute, &c.removed);
    }
    (added, removed)
}

/// The directory as it will be after the operations of the changeset already checked
/// (`_Vue`).
#[derive(Default)]
struct View {
    created: HashSet<String>,
    arrived: HashSet<String>,
    removed: HashSet<String>,
    touched: HashSet<String>,
    renames: Vec<(Vec<Component>, Vec<Component>)>,
    read: HashMap<String, Option<Entry>>,
    filters: HashMap<usize, bool>,
    /// None: more than the limit.
    children: HashMap<String, Option<Vec<Entry>>>,
}

/// Where the answers of the preloading go.
struct Preload {
    reads: Vec<(String, usize)>,
    filters: Vec<(usize, usize)>,
    children: Vec<(String, usize)>,
}

impl View {
    /// Puts in `burst` the reads the verification will need (`precharger`).
    fn preload(
        &self,
        link: &mut Link,
        operations: &[Operation],
        burst: &mut Burst,
    ) -> Result<Preload, LdapError> {
        let mut preload = Preload {
            reads: Vec::new(),
            filters: Vec::new(),
            children: Vec::new(),
        };
        let mut touched: Vec<String> = Vec::new();
        let free = |dn_text: &str, touched: &[String]| {
            let k = key(dn_text);
            !touched
                .iter()
                .any(|t| k == *t || k.ends_with(&format!(",{t}")))
        };
        let read = |link: &mut Link,
                    preload: &mut Preload,
                    burst: &mut Burst,
                    dn_text: &str,
                    touched: &[String]|
         -> Result<(), LdapError> {
            if !preload.reads.iter().any(|(k, _)| *k == key(dn_text)) && free(dn_text, touched) {
                let rank = burst.read(link, dn_text, &OBJECT_ATTRIBUTES, ALL, None)?;
                preload.reads.push((key(dn_text), rank));
            }
            Ok(())
        };
        for (index, op) in operations.iter().enumerate() {
            if !op.is_ldap() {
                continue;
            }
            let dn_text = op.dn();
            if free(dn_text, &touched) {
                read(link, &mut preload, burst, dn_text, &touched)?;
                match op {
                    Operation::Add { .. } => {
                        let parent = parent_dn(dn_text).unwrap_or_default();
                        read(link, &mut preload, burst, &parent, &touched)?;
                    }
                    Operation::Modify { changes, .. } => {
                        let (added, removed) = modification_states(changes);
                        let filter = state_filter(&removed, &added);
                        if filter != ALL {
                            let rank = burst.read(link, dn_text, &["1.1"], &filter, None)?;
                            preload.filters.push((index, rank));
                        }
                    }
                    Operation::Rename { parent, .. } => {
                        let new_dn = op.dn_after().unwrap_or_default();
                        read(link, &mut preload, burst, &new_dn, &touched)?;
                        if let Some(parent) = parent {
                            read(link, &mut preload, burst, parent, &touched)?;
                        }
                    }
                    _ => {
                        if !preload.children.iter().any(|(k, _)| *k == key(dn_text)) {
                            // At most, as many children may go as the changeset has deletions
                            // and renames: one more is enough to decide.
                            let limit = 1 + operations
                                .iter()
                                .filter(|x| {
                                    matches!(x, Operation::Delete { .. } | Operation::Rename { .. })
                                        && parent_key(x.dn()) == key(dn_text)
                                })
                                .count();
                            let rank = burst.search(
                                link,
                                dn_text,
                                Scope::OneLevel,
                                ALL,
                                &["1.1"],
                                i32::try_from(limit).unwrap_or(i32::MAX),
                                None,
                            )?;
                            preload.children.push((key(dn_text), rank));
                        }
                    }
                }
            }
            touched.push(key(dn_text));
            if let Operation::Rename { .. } = op {
                touched.push(key(&op.dn_after().unwrap_or_default()));
            }
        }
        Ok(preload)
    }

    fn store(&mut self, preload: &Preload, answers: &[Option<Vec<Entry>>]) {
        for (k, rank) in &preload.reads {
            self.read.insert(k.clone(), first(answers.get(*rank)));
        }
        for (index, rank) in &preload.filters {
            self.filters
                .insert(*index, first(answers.get(*rank)).is_some());
        }
        for (k, rank) in &preload.children {
            self.children
                .insert(k.clone(), answers.get(*rank).cloned().flatten());
        }
    }

    /// Present DN, on the server, of an object named by its DN after the renames.
    fn on_server(&self, dn_text: &str) -> String {
        let mut components = split(dn_text);
        for (old, new) in self.renames.iter().rev() {
            let n = new.len();
            if components.len() >= n
                && key(&compose(
                    components.get(components.len() - n..).unwrap_or_default(),
                )) == key(&compose(new))
            {
                components.truncate(components.len() - n);
                components.extend(old.iter().cloned());
            }
        }
        compose(&components)
    }

    fn get(&mut self, link: &mut Link, dn_text: &str) -> Result<Option<Entry>, LdapError> {
        let server = self.on_server(dn_text);
        let k = key(&server);
        if let Some(entry) = self.read.get(&k) {
            return Ok(entry.clone());
        }
        let entry = read_entry(link, &server, &OBJECT_ATTRIBUTES, ALL)?;
        self.read.insert(k, entry.clone());
        Ok(entry)
    }

    fn exists(&mut self, link: &mut Link, dn_text: &str) -> Result<bool, LdapError> {
        let k = key(dn_text);
        if self.created.contains(&k) || self.arrived.contains(&k) {
            return Ok(true);
        }
        if self.removed.contains(&k) {
            return Ok(false);
        }
        let components = split(dn_text);
        for i in 1..components.len() {
            let ancestor = key(&compose(components.get(i..).unwrap_or_default()));
            if self.removed.contains(&ancestor) || self.created.contains(&ancestor) {
                return Ok(false); // gone with its parent, or new parent hence empty
            }
        }
        Ok(self.get(link, dn_text)?.is_some())
    }

    /// Object the changeset did not touch yet: its state is the one of the server.
    fn untouched(&self, dn_text: &str) -> bool {
        let k = key(dn_text);
        !self.touched.contains(&k) && !self.created.contains(&k) && !self.arrived.contains(&k)
    }

    /// True if `dn` will still have children (deleting asks for a leaf).
    fn children_left(&mut self, link: &mut Link, dn_text: &str) -> Result<bool, LdapError> {
        let k = key(dn_text);
        if self
            .created
            .iter()
            .chain(self.arrived.iter())
            .any(|x| parent_key(x) == k)
        {
            return Ok(true);
        }
        if self.created.contains(&k) {
            return Ok(false); // created by the changeset: empty on the server
        }
        let gone: HashSet<String> = self
            .removed
            .iter()
            .filter(|x| parent_key(x) == k)
            .map(|x| key(&self.on_server(x)))
            .collect();
        let server = key(&self.on_server(dn_text));
        if let Some(read) = self.children.get(&server) {
            return Ok(match read {
                None => true,
                Some(entries) => entries.iter().any(|e| !gone.contains(&key(&e.dn))),
            });
        }
        let request = SearchRequest {
            base: self.on_server(dn_text),
            scope: Scope::OneLevel,
            filter: ALL.into(),
            attributes: vec!["1.1".into()],
            controls: Vec::new(),
            size_limit: i32::try_from(gone.len() + 1).unwrap_or(i32::MAX),
        };
        match link.session.search_wait(request, Some(link.timeout)) {
            Ok(response) => Ok(response
                .into_entries()
                .iter()
                .any(|e| !gone.contains(&key(&e.dn)))),
            Err(e) if e.code == code::SIZELIMIT_EXCEEDED => Ok(true),
            Err(e) if e.code == code::NO_SUCH_OBJECT => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// The object of an operation read just before its write, for the version check (`_Garde`).
#[derive(Debug, Clone, Default)]
struct Guard {
    /// `uSNChanged`, and the whole object for a deletion; None if it does not exist.
    entry: Option<Entry>,
    /// The attributes `Delete.guards` (descriptor), read with the SD flags control.
    guards: Option<Entry>,
    /// A SYSVOL operation: the element read.
    sysvol: Option<State>,
}

/// Ranks of the reads of a guard in a burst.
struct GuardReads {
    entry: usize,
    guards: Option<usize>,
}

impl GuardReads {
    fn guard(&self, answers: &[Option<Vec<Entry>>]) -> Guard {
        Guard {
            entry: first(answers.get(self.entry)),
            guards: self.guards.and_then(|r| first(answers.get(r))),
            sysvol: None,
        }
    }
}

/// Puts in `burst` the reads of the guard of an LDAP operation; None if it has none
/// (creation, SYSVOL operation) (`_lire_garde`).
fn read_guard(
    op: &Operation,
    link: &mut Link,
    burst: &mut Burst,
) -> Result<Option<GuardReads>, LdapError> {
    match op {
        Operation::Modify { dn, .. } | Operation::Rename { dn, .. } => Ok(Some(GuardReads {
            entry: burst.read(link, dn, &["uSNChanged"], ALL, None)?,
            guards: None,
        })),
        Operation::Delete { dn, guards, .. } => {
            let entry = burst.read(link, dn, &["uSNChanged", "*", "memberOf"], ALL, None)?;
            let guards = if guards.is_empty() {
                None
            } else {
                let names: Vec<&str> = guards.iter().map(String::as_str).collect();
                Some(burst.read(link, dn, &names, ALL, Some(SD_WITHOUT_SACL))?)
            };
            Ok(Some(GuardReads { entry, guards }))
        }
        _ => Ok(None),
    }
}

/// Problems found, and the guard of the first operation (read in the same burst)
/// (`_preverifier`).
///
/// Every read goes out at once (`Burst`), and the SYSVOL is read meanwhile on its own
/// connection: one round trip in all.
fn preverify(
    link: &mut Link,
    changeset: &Changeset,
    catalog: &dyn WriteCatalog,
    session: Option<&mut SysvolSession>,
    imposed: bool,
) -> Result<(Vec<Problem>, Option<Guard>), OpError> {
    let mut view = View::default();
    let mut problems = Vec::new();
    // Shares of file servers first (ADR 0023): their own connections, nothing in the burst.
    let mut session = session;
    if changeset.touches_shares() {
        let Some(s) = session.as_deref_mut() else {
            return Err(OpError::Record(record(
                "ErreurAnnuaire",
                "opération sur un partage sans session".into(),
                "",
            )));
        };
        for (index, op) in changeset.operations.iter().enumerate() {
            if !op.is_file_share() {
                continue;
            }
            match crate::share_write::check(&mut s.shares, op, catalog) {
                Ok(Some((kind, msg))) => problems.push(Problem {
                    index,
                    dn: op.dn().to_owned(),
                    kind,
                    message: catalog.write_text(&msg),
                }),
                Ok(None) => {}
                Err(r) => return Err(OpError::Sysvol(r)),
            }
        }
    }
    let mut burst = Burst::new();
    let preload = view.preload(link, &changeset.operations, &mut burst)?;
    let first_op = changeset.operations.first();
    let guard_reads = match first_op {
        Some(op @ Operation::Delete { .. }) => read_guard(op, link, &mut burst)?,
        _ => None,
    };
    let dc = link.state.dc.clone();
    let sysvol_error = |e: SysvolError| OpError::Sysvol(catalog.sysvol_error(&e, &dc));
    let mut sysvol_view = session
        .filter(|_| changeset.touches_sysvol())
        .map(SysvolView::new);
    let pdc_rank = match &sysvol_view {
        Some(_) if !imposed => {
            let base = link.state.root_dse.default_naming_context.clone();
            Some(burst.read(link, &base, &["fSMORoleOwner"], ALL, None)?)
        }
        _ => None,
    };
    if let Some(v) = sysvol_view.as_mut() {
        let operations: Vec<&Operation> = changeset
            .operations
            .iter()
            .filter(|op| op.is_sysvol())
            .collect();
        if let Err(e) = v.preload(&operations) {
            let _ = burst.receive(link);
            return Err(sysvol_error(e));
        }
    }
    let answers = burst.receive(link)?;
    view.store(&preload, &answers);
    if sysvol_view.is_some() {
        let domain = pdc_rank.and_then(|r| first(answers.get(r)));
        if let Some(reason) = sysvol_write::off_pdc(link, imposed, domain.as_ref())? {
            let problem = Problem {
                index: 0,
                dn: dc.clone(),
                kind: ProblemKind::Target,
                message: catalog.write_text(&reason),
            };
            return Ok((vec![problem], None));
        }
    }
    let mut guard = guard_reads.map(|g| g.guard(&answers));
    let mut signal = |index: usize, dn_text: &str, kind: ProblemKind, msg: WriteMsg| {
        problems.push(Problem {
            index,
            dn: dn_text.to_owned(),
            kind,
            message: catalog.write_text(&msg),
        });
    };

    for (index, op) in changeset.operations.iter().enumerate() {
        match op {
            Operation::Add { dn, attributes } => {
                if view.exists(link, dn)? {
                    signal(
                        index,
                        dn,
                        ProblemKind::Exists,
                        WriteMsg::AlreadyExists { dn: dn.clone() },
                    );
                }
                let classes: Vec<Vec<u8>> = attributes
                    .iter()
                    .find(|(a, _)| a.eq_ignore_ascii_case("objectclass"))
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let parent = parent_dn(dn).unwrap_or_default();
                allowed_classes(
                    link,
                    &mut view,
                    (index, dn),
                    &parent,
                    class_of(&classes).as_deref(),
                    &mut signal,
                )?;
                view.created.insert(key(dn));
                view.removed.remove(&key(dn));
            }
            Operation::Modify {
                dn, changes, read, ..
            } => {
                let untouched = view.exists(link, dn)? && view.untouched(dn);
                let entry = version(
                    link,
                    &mut view,
                    (index, dn),
                    read.as_ref(),
                    &dc,
                    catalog,
                    &mut signal,
                )?;
                if index == 0 {
                    guard = Some(Guard {
                        entry: entry.clone(),
                        ..Guard::default()
                    });
                }
                if untouched && entry.is_some() {
                    let (added, removed) = modification_states(changes);
                    let filter = state_filter(&removed, &added);
                    let as_expected = match view.filters.get(&index) {
                        Some(found) => *found,
                        None if filter == ALL => true,
                        None => read_entry(link, &view.on_server(dn), &["1.1"], &filter)?.is_some(),
                    };
                    if filter != ALL && !as_expected {
                        signal(
                            index,
                            dn,
                            ProblemKind::Values,
                            WriteMsg::ValuesNotAsExpected { dn: dn.clone() },
                        );
                    }
                    // Samba never quotes objectClass in allowedAttributesEffective, nor the
                    // attributes of an auxiliary class not set yet: the DC will decide.
                    if !changes
                        .iter()
                        .any(|c| c.attribute.eq_ignore_ascii_case("objectclass"))
                    {
                        let names: Vec<String> =
                            changes.iter().map(|c| c.attribute.clone()).collect();
                        allowed_attributes((index, dn), entry.as_ref(), &names, &mut signal);
                    }
                }
                view.touched.insert(key(dn));
            }
            Operation::Rename {
                dn,
                rdn,
                parent,
                read,
            } => {
                let new_dn = op.dn_after().unwrap_or_default();
                let untouched = view.exists(link, dn)? && view.untouched(dn);
                let entry = version(
                    link,
                    &mut view,
                    (index, dn),
                    read.as_ref(),
                    &dc,
                    catalog,
                    &mut signal,
                )?;
                if index == 0 {
                    guard = Some(Guard {
                        entry: entry.clone(),
                        ..Guard::default()
                    });
                }
                if view.exists(link, &new_dn)? {
                    signal(
                        index,
                        dn,
                        ProblemKind::Exists,
                        WriteMsg::NameTaken { dn: new_dn.clone() },
                    );
                }
                if untouched && entry.is_some() {
                    allowed_attributes(
                        (index, dn),
                        entry.as_ref(),
                        std::slice::from_ref(&rdn.attribute),
                        &mut signal,
                    );
                }
                if let Some(parent) = parent {
                    let class = entry
                        .as_ref()
                        .and_then(|e| class_of(e.values("objectClass")));
                    allowed_classes(
                        link,
                        &mut view,
                        (index, dn),
                        parent,
                        class.as_deref(),
                        &mut signal,
                    )?;
                }
                view.renames.push((split(dn), split(&new_dn)));
                view.removed.insert(key(dn));
                view.arrived.insert(key(&new_dn));
                view.removed.remove(&key(&new_dn));
                view.touched.insert(key(&new_dn));
            }
            Operation::Delete { dn, read, .. } => {
                version(
                    link,
                    &mut view,
                    (index, dn),
                    read.as_ref(),
                    &dc,
                    catalog,
                    &mut signal,
                )?;
                if view.exists(link, dn)? && view.children_left(link, dn)? {
                    signal(
                        index,
                        dn,
                        ProblemKind::NotLeaf,
                        WriteMsg::NotLeaf { dn: dn.clone() },
                    );
                }
                view.removed.insert(key(dn));
                view.created.remove(&key(dn));
                view.arrived.remove(&key(dn));
            }
            share_op if share_op.is_file_share() => {}
            sysvol_op => {
                let Some(v) = sysvol_view.as_mut() else {
                    return Err(OpError::Record(record(
                        "ErreurAnnuaire",
                        "opération SYSVOL sans session SYSVOL".into(),
                        "",
                    )));
                };
                sysvol_write::check(v, index, sysvol_op, &mut signal).map_err(sysvol_error)?;
            }
        }
    }
    if let (Some(op), Some(v)) = (first_op.filter(|op| op.is_sysvol()), sysvol_view.as_mut()) {
        let state = v
            .state(op.path().unwrap_or_default(), sysvol_write::hint(op))
            .map_err(sysvol_error)?;
        guard = Some(Guard {
            sysvol: Some(state),
            ..Guard::default()
        });
    }
    Ok((problems, guard))
}

type Signal<'a> = dyn FnMut(usize, &str, ProblemKind, WriteMsg) + 'a;

/// Existence and version of an object the changeset will touch.
fn version(
    link: &mut Link,
    view: &mut View,
    (index, dn_text): (usize, &str),
    read: Option<&Read>,
    dc: &str,
    catalog: &dyn WriteCatalog,
    signal: &mut Signal<'_>,
) -> Result<Option<Entry>, OpError> {
    if !view.exists(link, dn_text)? {
        signal(
            index,
            dn_text,
            ProblemKind::Missing,
            WriteMsg::Missing {
                dn: dn_text.to_owned(),
            },
        );
        return Ok(None);
    }
    if !view.untouched(dn_text) {
        return Ok(None);
    }
    let entry = view.get(link, dn_text)?;
    if let (Some(entry), Some(read)) = (&entry, read) {
        if read.dc != dc {
            signal(
                index,
                dn_text,
                ProblemKind::Version,
                WriteMsg::ReadOnDc {
                    dn: dn_text.to_owned(),
                    read: read.dc.clone(),
                    dc: dc.to_owned(),
                },
            );
        } else {
            let usn = usn_of(entry, catalog)?;
            if usn != read.usn {
                signal(
                    index,
                    dn_text,
                    ProblemKind::Version,
                    WriteMsg::ChangedSincePreview {
                        dn: dn_text.to_owned(),
                        read: read.usn,
                        usn,
                    },
                );
            }
        }
    }
    Ok(entry)
}

/// The target exists and creating (or moving) an object of this class there is allowed.
fn allowed_classes(
    link: &mut Link,
    view: &mut View,
    (index, dn_text): (usize, &str),
    parent: &str,
    class: Option<&str>,
    signal: &mut Signal<'_>,
) -> Result<(), LdapError> {
    if !view.exists(link, parent)? {
        signal(
            index,
            dn_text,
            ProblemKind::Target,
            WriteMsg::ContainerMissing {
                parent: parent.to_owned(),
            },
        );
        return Ok(());
    }
    let entry = if view.untouched(parent) {
        view.get(link, parent)?
    } else {
        None
    };
    let allowed = lower_values(entry.as_ref(), "allowedChildClassesEffective");
    if let Some(class) = class
        && !allowed.is_empty()
        && !allowed.contains(class)
    {
        signal(
            index,
            dn_text,
            ProblemKind::Rights,
            WriteMsg::ClassNotAllowed {
                class: class.to_owned(),
                parent: parent.to_owned(),
            },
        );
    }
    Ok(())
}

fn allowed_attributes(
    (index, dn_text): (usize, &str),
    entry: Option<&Entry>,
    names: &[String],
    signal: &mut Signal<'_>,
) {
    let allowed = lower_values(entry, "allowedAttributesEffective");
    if allowed.is_empty() {
        return; // rights not readable: the write will decide
    }
    let mut missing: Vec<&String> = names
        .iter()
        .filter(|n| !allowed.contains(&n.to_lowercase()))
        .collect();
    missing.sort();
    missing.dedup();
    if !missing.is_empty() {
        signal(
            index,
            dn_text,
            ProblemKind::Rights,
            WriteMsg::AttributesRefused {
                attributes: missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                dn: dn_text.to_owned(),
            },
        );
    }
}

/// Prior verification only, without writing (to show with the preview) (`verifier`).
/// Blocking.
pub fn verify(
    connection: &Connection,
    changeset: &Changeset,
    catalog: Arc<dyn WriteCatalog>,
) -> Result<Vec<Problem>, Failure> {
    let changeset = changeset.clone();
    let imposed = connection.profile().write_dc.is_some();
    connection
        .run(true, move |link| {
            let mut session = SysvolSession::with_protection(
                sysvol_write::opener(link.sysvol),
                &link.state.dc,
                link.sysvol,
            );
            let found = preverify(
                link,
                &changeset,
                catalog.as_ref(),
                Some(&mut session),
                imposed,
            );
            session.close();
            match found {
                Ok((problems, _)) => Ok(Ok(problems)),
                Err(OpError::Ldap(e)) => Err(e),
                Err(OpError::Record(r) | OpError::Verification(r) | OpError::Sysvol(r)) => {
                    Ok(Err(r))
                }
                Err(OpError::Journal(detail)) => Ok(Err(record("ErreurJournal", detail, ""))),
            }
        })
        .map(|r| {
            r.unwrap_or_else(|e| {
                vec![Problem {
                    index: 0,
                    dn: String::new(),
                    kind: ProblemKind::Target,
                    message: e.message,
                }]
            })
        })
}

fn prior_error(problems: &[Problem], catalog: &dyn WriteCatalog) -> ErrorRecord {
    record(
        "ErreurPrealable",
        catalog.write_text(&WriteMsg::NothingWritten { n: problems.len() }),
        problems
            .iter()
            .map(|p| format!("{}. {}", p.index + 1, p.message))
            .collect::<Vec<_>>()
            .join(" ; "),
    )
}

// --- Writing of an operation ---------------------------------------------------------------------

/// Refusals that mean « the object is no longer as in the preview »: conflicts
/// (`_traduire_ecriture`).
fn translate_write(
    error: &LdapError,
    dc: &str,
    op: &Operation,
    catalog: &dyn WriteCatalog,
) -> ErrorRecord {
    let base = catalog.ldap_error(error, dc);
    let dn_text = op.dn().to_owned();
    if matches!(op, Operation::Add { .. }) && error.code == code::ALREADY_EXISTS {
        return record(
            "ErreurConflit",
            catalog.write_text(&WriteMsg::ExistsOrSameIdentifier { dn: dn_text }),
            base.message,
        );
    }
    if [
        code::NO_SUCH_OBJECT,
        code::ALREADY_EXISTS,
        code::NO_SUCH_ATTRIBUTE,
        code::TYPE_OR_VALUE_EXISTS,
    ]
    .contains(&error.code)
    {
        return record(
            "ErreurConflit",
            catalog.write_text(&WriteMsg::ChangedReadAgain { dn: dn_text }),
            base.message,
        );
    }
    base
}

type Followed = HashMap<String, (i64, i64)>;

/// Version check on the object read just before the write (`_controler_version`).
fn check_version(
    dc: &str,
    dn_text: &str,
    read: Option<&Read>,
    followed: &Followed,
    entry: Option<&Entry>,
    catalog: &dyn WriteCatalog,
) -> Result<Entry, OpError> {
    let conflict = |msg: WriteMsg, detail: String| {
        OpError::Record(record("ErreurConflit", catalog.write_text(&msg), detail))
    };
    if let Some(read) = read
        && read.dc != dc
    {
        return Err(conflict(
            WriteMsg::ReadOnOtherDc {
                dn: dn_text.to_owned(),
            },
            format!("lu sur {}, connexion sur {dc}", read.dc),
        ));
    }
    let Some(entry) = entry else {
        return Err(conflict(
            WriteMsg::NoLongerExists {
                dn: dn_text.to_owned(),
            },
            "objet absent avant écriture".into(),
        ));
    };
    if let Some(read) = read {
        let mut expected = read.usn;
        if let Some((initial, current)) = followed.get(&key(dn_text))
            && *initial == expected
        {
            expected = *current; // modified earlier by this same changeset
        }
        let usn = usn_of(entry, catalog)?;
        if usn != expected {
            return Err(conflict(
                WriteMsg::ModifiedReadAgain {
                    dn: dn_text.to_owned(),
                },
                format!("uSNChanged {expected} attendu, {usn} lu"),
            ));
        }
    }
    Ok(entry.clone())
}

fn class_name(op: &Operation) -> &'static str {
    match op {
        Operation::Add { .. } => "Ajouter",
        Operation::Modify { .. } => "Modifier",
        Operation::Rename { .. } => "Renommer",
        _ => "Supprimer",
    }
}

fn read_back(
    dc: &str,
    dn_text: &str,
    entry: Option<&Entry>,
    filter: &str,
    op: &Operation,
    catalog: &dyn WriteCatalog,
) -> Result<Read, OpError> {
    let Some(entry) = entry else {
        return Err(OpError::Verification(record(
            "ErreurVerification",
            catalog.write_text(&WriteMsg::NotInWantedState {
                dn: dn_text.to_owned(),
            }),
            format!("{} ; filtre de vérification {filter}", class_name(op)),
        )));
    };
    Ok(Read {
        dc: dc.to_owned(),
        usn: usn_of(entry, catalog)?,
    })
}

/// Keeps the version left by this changeset, for the next operations on the object
/// (`_suivre`).
fn follow(followed: &mut Followed, dn_text: &str, new_dn: &str, read: Option<&Read>, after: &Read) {
    let (initial, _) = followed
        .remove(&key(dn_text))
        .unwrap_or((read.map_or(after.usn, |r| r.usn), 0));
    followed.insert(key(new_dn), (initial, after.usn));
}

/// The LDAP modifications of a `Modify`, and its controls (`_requete_modification`): removed
/// then added, except where « replace » is a must (a secret set without the old one, the
/// descriptor that Samba cannot remove, `pwdLastSet` computed by the DC).
fn modification_request(changes: &[Change]) -> (Vec<Modification>, Vec<crate::session::Control>) {
    let mut mods = Vec::new();
    let mut controls = Vec::new();
    for c in changes {
        let lower = c.attribute.to_lowercase();
        let replace = UNCHECKABLE.contains(&lower.as_str())
            || (is_sensitive(&c.attribute) && c.removed.is_empty());
        if replace {
            mods.push(Modification::Replace(c.attribute.clone(), c.added.clone()));
            if lower == "ntsecuritydescriptor" {
                controls = vec![search::sd_flags_control(SD_DACL)];
            }
            continue;
        }
        if !c.removed.is_empty() {
            mods.push(Modification::Delete(c.attribute.clone(), c.removed.clone()));
        }
        if !c.added.is_empty() {
            mods.push(Modification::Add(c.attribute.clone(), c.added.clone()));
        }
    }
    (mods, controls)
}

/// Reads the guard of the next operation with the read back of the current one: one round
/// trip for both (`_Suite`). Its LDAP reads go with those of the read back, its SYSVOL reads
/// in the same batch of compounds (or while the read back is in flight).
struct Next<'a> {
    next: Option<&'a Operation>,
    burst: Burst,
    reads: Option<GuardReads>,
    /// The path of a next SYSVOL operation that has a guard, with its nature.
    then: Vec<(String, Option<bool>)>,
    states: Vec<State>,
}

impl<'a> Next<'a> {
    fn new(next: Option<&'a Operation>, sysvol: bool) -> Self {
        let then = match next {
            Some(op) if sysvol && sysvol_write::guard_required(op) => {
                vec![(
                    op.path().unwrap_or_default().to_owned(),
                    sysvol_write::hint(op),
                )]
            }
            _ => Vec::new(),
        };
        Self {
            next,
            burst: Burst::new(),
            reads: None,
            then,
            states: Vec::new(),
        }
    }

    /// LDAP reads of the next guard: after the present write (read before, they would not
    /// see its effect on the same object).
    fn send(&mut self, link: &mut Link) -> Result<(), LdapError> {
        if let Some(next) = self.next {
            self.reads = read_guard(next, link, &mut self.burst)?;
        }
        Ok(())
    }

    fn read_back(
        &mut self,
        link: &mut Link,
        session: Option<&mut SysvolSession>,
        dn_text: &str,
        attributes: &[&str],
        filter: &str,
    ) -> Result<Option<Entry>, LdapError> {
        let mut burst = Burst::new();
        let rank = burst.read(link, dn_text, attributes, filter, None)?;
        self.send(link)?;
        if let Some(session) = session.filter(|_| !self.then.is_empty()) {
            self.states = session
                .client()
                .and_then(|c| c.states(&self.then))
                .unwrap_or_default();
        }
        Ok(first(burst.receive(link)?.get(rank)))
    }

    /// An unreadable guard is not an error of the present operation: the next one reads it
    /// itself.
    fn guard(&mut self, link: &mut Link) -> Option<Guard> {
        if let Some(reads) = self.reads.take() {
            let answers = self.burst.receive(link).ok()?;
            return Some(reads.guard(&answers));
        }
        let (path, _) = self.then.first()?;
        let state = self
            .states
            .iter()
            .find(|s| sysvol::key(&s.path) == sysvol::key(path))?;
        Some(Guard {
            sysvol: Some(state.clone()),
            ..Guard::default()
        })
    }

    /// After a failure: the answers in flight are received and ignored.
    fn give_up(&mut self, link: &mut Link) {
        if self.burst.len() > 0 {
            let _ = self.burst.receive(link);
        }
    }
}

struct Context<'a> {
    catalog: &'a dyn WriteCatalog,
    journal: &'a Journal,
    id: &'a str,
}

impl Context<'_> {
    fn note(&self, step: &str, fields: Vec<(&str, Value)>) -> Result<(), String> {
        let mut map = Map::new();
        map.insert("version".into(), json!(changes::JOURNAL_VERSION));
        map.insert("id".into(), json!(self.id));
        map.insert("etape".into(), json!(step));
        for (k, v) in fields {
            map.insert(k.into(), v);
        }
        self.journal.write(&map).map_err(|e| e.to_string())
    }
}

/// Version check, write, read back (`_appliquer_une`).
// The read back of the last arm could take `session`; all arms read the same way.
#[allow(clippy::too_many_arguments, clippy::needless_option_as_deref)]
fn apply_one(
    link: &mut Link,
    op: &Operation,
    followed: &mut Followed,
    before_delete: &mut dyn FnMut(&AttributeMap) -> Result<(), String>,
    guard: Option<Guard>,
    next: Option<&Operation>,
    mut session: Option<&mut SysvolSession>,
    catalog: &dyn WriteCatalog,
) -> Result<(Applied, Option<Guard>), OpError> {
    let mut suite = Next::new(next, session.is_some());
    let result = (|| -> Result<Applied, OpError> {
        let dc = link.state.dc.clone();
        let timeout = Some(link.timeout);
        if op.is_file_share() {
            let Some(session) = session.as_deref_mut() else {
                return Err(OpError::Record(record(
                    "ErreurAnnuaire",
                    "opération sur un partage sans session".into(),
                    "",
                )));
            };
            suite.send(link)?;
            crate::share_write::apply(&mut session.shares, op, catalog).map_err(|e| match e {
                StepError::Verification(r) => OpError::Verification(r),
                StepError::Conflict(r) | StepError::Other(r) => OpError::Record(r),
            })?;
            return Ok(Applied {
                operation: op.clone(),
                after: None,
                before: None,
            });
        }
        if op.is_sysvol() {
            let Some(session) = session.as_deref_mut() else {
                return Err(OpError::Record(record(
                    "ErreurAnnuaire",
                    "opération SYSVOL sans session SYSVOL".into(),
                    "",
                )));
            };
            // This write does not touch the directory: the next guard is read meanwhile.
            suite.send(link)?;
            let sysvol_guard = guard.and_then(|g| g.sysvol);
            suite.states = sysvol_write::apply(session, op, sysvol_guard, &suite.then, catalog)
                .map_err(|e| match e {
                    StepError::Verification(r) => OpError::Verification(r),
                    StepError::Conflict(r) | StepError::Other(r) => OpError::Record(r),
                })?;
            return Ok(Applied {
                operation: op.clone(),
                after: None,
                before: None,
            });
        }
        let guard = match (guard, op) {
            (Some(g), _) => Some(g),
            (None, Operation::Add { .. }) => None,
            (None, _) => {
                let mut burst = Burst::new();
                let reads = read_guard(op, link, &mut burst)?;
                let answers = burst.receive(link)?;
                reads.map(|r| r.guard(&answers))
            }
        };
        match op {
            Operation::Add { dn, attributes } => {
                let id = link.session.add(dn, attributes.clone(), Vec::new())?;
                link.session.result(id, timeout)?;
                let filter = state_filter(attributes, &Vec::new());
                let read =
                    suite.read_back(link, session.as_deref_mut(), dn, &["uSNChanged"], &filter)?;
                let after = read_back(&dc, dn, read.as_ref(), &filter, op, catalog)?;
                followed.insert(key(dn), (after.usn, after.usn));
                Ok(Applied {
                    operation: op.clone(),
                    after: Some(after),
                    before: None,
                })
            }
            Operation::Modify { dn, changes, read } => {
                let entry = guard.and_then(|g| g.entry);
                check_version(&dc, dn, read.as_ref(), followed, entry.as_ref(), catalog)?;
                let (mods, controls) = modification_request(changes);
                let id = link.session.modify(dn, mods, controls)?;
                link.session.result(id, timeout)?;
                let (added, removed) = modification_states(changes);
                let filter = state_filter(&added, &removed);
                let back =
                    suite.read_back(link, session.as_deref_mut(), dn, &["uSNChanged"], &filter)?;
                let after = read_back(&dc, dn, back.as_ref(), &filter, op, catalog)?;
                follow(followed, dn, dn, read.as_ref(), &after);
                Ok(Applied {
                    operation: op.clone(),
                    after: Some(after),
                    before: None,
                })
            }
            Operation::Rename {
                dn,
                rdn,
                parent,
                read,
            } => {
                let entry = guard.and_then(|g| g.entry);
                check_version(&dc, dn, read.as_ref(), followed, entry.as_ref(), catalog)?;
                let rdn_text = compose(std::slice::from_ref(rdn));
                let id = link
                    .session
                    .rename(dn, &rdn_text, parent.as_deref(), true, Vec::new())?;
                link.session.result(id, timeout)?;
                let new_dn = op.dn_after().unwrap_or_default();
                let back =
                    suite.read_back(link, session.as_deref_mut(), &new_dn, &["uSNChanged"], ALL)?;
                let after = read_back(&dc, &new_dn, back.as_ref(), ALL, op, catalog)?;
                follow(followed, dn, &new_dn, read.as_ref(), &after);
                Ok(Applied {
                    operation: op.clone(),
                    after: Some(after),
                    before: None,
                })
            }
            Operation::Delete { dn, read, guards } => {
                let guard = guard.unwrap_or_default();
                let entry = check_version(
                    &dc,
                    dn,
                    read.as_ref(),
                    followed,
                    guard.entry.as_ref(),
                    catalog,
                )?;
                let mut before: AttributeMap = entry
                    .attributes
                    .iter()
                    .filter(|(a, _)| !a.eq_ignore_ascii_case("uSNChanged"))
                    .cloned()
                    .collect();
                if !guards.is_empty()
                    && let Some(kept) = &guard.guards
                {
                    for (a, v) in &kept.attributes {
                        match before.iter_mut().find(|(b, _)| b == a) {
                            Some((_, values)) => *values = v.clone(),
                            None => before.push((a.clone(), v.clone())),
                        }
                    }
                }
                before_delete(&before).map_err(OpError::Journal)?;
                let id = link.session.delete(dn, Vec::new())?;
                link.session.result(id, timeout)?;
                if suite
                    .read_back(link, session.as_deref_mut(), dn, &["1.1"], ALL)?
                    .is_some()
                {
                    return Err(OpError::Verification(record(
                        "ErreurVerification",
                        catalog.write_text(&WriteMsg::StillExists { dn: dn.clone() }),
                        "",
                    )));
                }
                followed.remove(&key(dn));
                Ok(Applied {
                    operation: op.clone(),
                    after: None,
                    before: Some(before),
                })
            }
            _ => Ok(Applied {
                operation: op.clone(),
                after: None,
                before: None,
            }),
        }
    })();
    match result {
        Ok(applied) => {
            let next_guard = suite.guard(link);
            Ok((applied, next_guard))
        }
        Err(e) => {
            suite.give_up(link);
            Err(e)
        }
    }
}

/// What `execute` did: the operations done, the error, the doubtful operation.
struct Executed {
    done: Vec<Applied>,
    error: Option<ErrorRecord>,
    doubtful: Option<Applied>,
}

/// Applies the operations in order up to the first error (`_executer`). `doubtful` is the
/// operation whose write was accepted without its effect being seen.
fn execute(
    link: &mut Link,
    operations: &[Operation],
    phase: &str,
    context: &Context<'_>,
    mut guard: Option<Guard>,
    strict: bool,
    mut session: Option<&mut SysvolSession>,
) -> Executed {
    let mut followed = Followed::new();
    let mut done: Vec<Applied> = Vec::new();
    let journal_error = |detail: String| {
        record(
            "ErreurJournal",
            context.catalog.write_text(&WriteMsg::JournalNotWritten),
            detail,
        )
    };
    for (index, op) in operations.iter().enumerate() {
        let mut snapshot: Option<AttributeMap> = None;
        let next = operations.get(index + 1);
        let mut before_delete = |before: &AttributeMap| -> Result<(), String> {
            snapshot = Some(before.clone());
            let noted = context.note(
                "avant",
                vec![
                    ("phase", json!(phase)),
                    ("indice", json!(index)),
                    ("avant", changes::attributes_to_json(before)),
                ],
            );
            if strict { noted } else { Ok(()) }
        };
        match apply_one(
            link,
            op,
            &mut followed,
            &mut before_delete,
            guard.take(),
            next,
            session.as_deref_mut(),
            context.catalog,
        ) {
            Ok((applied, next_guard)) => {
                guard = next_guard;
                let noted = context.note(
                    "fait",
                    vec![
                        ("phase", json!(phase)),
                        ("indice", json!(index)),
                        ("apres", changes::read_to_json(applied.after.as_ref())),
                    ],
                );
                done.push(applied);
                if let (Err(detail), true) = (noted, strict) {
                    return Executed {
                        done,
                        error: Some(journal_error(detail)),
                        doubtful: None,
                    };
                }
            }
            Err(OpError::Verification(e)) => {
                return Executed {
                    done,
                    error: Some(e),
                    doubtful: Some(Applied {
                        operation: op.clone(),
                        after: None,
                        before: snapshot,
                    }),
                };
            }
            Err(OpError::Record(e) | OpError::Sysvol(e)) => {
                return Executed {
                    done,
                    error: Some(e),
                    doubtful: None,
                };
            }
            Err(OpError::Ldap(e)) => {
                let dc = link.state.dc.clone();
                return Executed {
                    done,
                    error: Some(translate_write(&e, &dc, op, context.catalog)),
                    doubtful: None,
                };
            }
            Err(OpError::Journal(detail)) => {
                return Executed {
                    done,
                    error: Some(journal_error(detail)),
                    doubtful: None,
                };
            }
        }
    }
    Executed {
        done,
        error: None,
        doubtful: None,
    }
}

// --- Application ------------------------------------------------------------------------------------

/// The result of `apply`: the report as journaled, and the problems of the prior
/// verification when it refused.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub report: Report,
    pub problems: Vec<Problem>,
}

/// Why nothing was written and no report made (`appliquer` raises): read-only profile, empty
/// changeset, journal not writable, DC unreachable during the verification.
#[derive(Debug, Clone)]
pub enum ApplyError {
    Failure(Failure),
    Record(ErrorRecord),
}

/// After a conflict that left nothing written: the changeset to try again (read again on the
/// DC), or None to stop (`Reessai`, the serial number of a SOA).
pub type Retry = Box<dyn FnMut(&mut Link, &Changeset) -> Option<Changeset> + Send>;

fn identities() -> &'static Mutex<HashMap<(String, u64), String>> {
    static IDENTITIES: std::sync::OnceLock<Mutex<HashMap<(String, u64), String>>> =
        std::sync::OnceLock::new();
    IDENTITIES.get_or_init(Mutex::default)
}

/// `whoami` of the bound connection, kept while it lives (`_identite`).
fn identity(link: &mut Link) -> String {
    let k = (link.state.dc.clone(), link.state.generation);
    if let Some(known) = identities()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&k)
    {
        return known.clone();
    }
    let Ok(found) = link.session.whoami(Some(link.timeout)) else {
        return String::new();
    };
    identities()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(k, found.clone());
    found
}

/// A random identifier, as `uuid.uuid4().hex`.
pub(crate) fn new_id() -> String {
    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_err()
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes = nanos.to_le_bytes();
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `datetime.now(UTC).isoformat(timespec="seconds")`.
pub fn timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    let now = annuaire_codecs::time::unix_to_nttime(seconds)
        .ok()
        .and_then(|n| annuaire_codecs::time::nttime_to_utc(n).ok().flatten())
        .unwrap_or(annuaire_codecs::time::NT_EPOCH);
    let c = now.civil();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}+00:00",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

/// Nothing stayed written, and the cause is an object that changed meanwhile
/// (`_conflit_sans_trace`).
fn conflict_without_trace(outcome: &Outcome) -> bool {
    let report = &outcome.report;
    if report.issue == Issue::Refused
        && report
            .error
            .as_ref()
            .is_some_and(|e| e.class == "ErreurPrealable")
    {
        return !outcome.problems.is_empty()
            && outcome
                .problems
                .iter()
                .all(|p| matches!(p.kind, ProblemKind::Version | ProblemKind::Values));
    }
    report.issue == Issue::Cancelled
        && report
            .error
            .as_ref()
            .is_some_and(|e| e.class == "ErreurConflit")
}

fn issue_after_failure(report: &Report) -> Issue {
    let clean = report.remaining_indices().is_empty()
        && report.rollback_error.is_none()
        && report.doubtful.is_none()
        && report.doubtful_rollback.is_none();
    if clean {
        Issue::Cancelled
    } else {
        Issue::Incomplete
    }
}

/// One attempt (`tenter`).
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
fn attempt(
    link: &mut Link,
    changeset: &Changeset,
    user: &str,
    domain: &str,
    resumes: Option<&str>,
    journal: &Journal,
    catalog: &dyn WriteCatalog,
    session: &mut SysvolSession,
    imposed: bool,
) -> Result<Result<Outcome, ErrorRecord>, LdapError> {
    // Operations on shares are written on their file server, not on the DC.
    let target = changeset
        .operations
        .iter()
        .find_map(Operation::server)
        .map_or_else(|| link.state.dc.clone(), str::to_owned);
    let mut report = Report {
        id: new_id(),
        timestamp: timestamp(),
        domain: domain.to_owned(),
        dc: target,
        user: user.to_owned(),
        changeset: changeset.clone(),
        applied: Vec::new(),
        issue: Issue::Refused,
        error: None,
        rollback: None,
        origins: Vec::new(),
        rollback_applied: Vec::new(),
        rollback_error: None,
        doubtful: None,
        doubtful_rollback: None,
        resumes: resumes.map(str::to_owned),
        resumed_by: None,
    };
    let (problems, guard) = match preverify(link, changeset, catalog, Some(session), imposed) {
        Ok(found) => found,
        Err(OpError::Ldap(e)) => return Err(e),
        // SYSVOL unreachable: nothing is written.
        Err(OpError::Sysvol(r)) => {
            report.error = Some(r);
            return Ok(Ok(Outcome {
                report,
                problems: Vec::new(),
            }));
        }
        Err(OpError::Record(r) | OpError::Verification(r)) => return Ok(Err(r)),
        Err(OpError::Journal(d)) => return Ok(Err(record("ErreurJournal", d, ""))),
    };
    if !problems.is_empty() {
        report.error = Some(prior_error(&problems, catalog));
        return Ok(Ok(Outcome { report, problems }));
    }
    let id = report.id.clone();
    let context = Context {
        catalog,
        journal,
        id: &id,
    };
    let changeset_json = match changes::changeset_to_json(changeset) {
        Ok(v) => v,
        Err(e) => return Ok(Err(record("ErreurAnnuaire", e.to_string(), ""))),
    };
    if let Err(detail) = context.note(
        "intention",
        vec![
            ("horodatage", json!(report.timestamp)),
            ("domaine", json!(report.domain)),
            ("dc", json!(report.dc)),
            ("utilisateur", json!(report.user)),
            ("reprend", json!(resumes)),
            ("changeset", changeset_json),
        ],
    ) {
        return Ok(Err(record(
            "ErreurJournal",
            catalog.write_text(&WriteMsg::JournalNothingModified),
            detail,
        )));
    }
    let executed = execute(
        link,
        &changeset.operations,
        APPLICATION,
        &context,
        guard,
        true,
        Some(&mut *session),
    );
    report.applied = executed.done;
    report.error = executed.error;
    report.doubtful = executed.doubtful;
    if report.error.is_none() {
        report.issue = Issue::Applied;
    } else {
        let _ = context.note(
            "echec",
            vec![
                ("phase", json!(APPLICATION)),
                ("indice", json!(report.applied.len())),
                ("erreur", changes::error_to_json(report.error.as_ref())),
                ("douteuse", json!(report.doubtful.is_some())),
            ],
        );
        let applied: Vec<(usize, &Applied)> = report.applied.iter().enumerate().collect();
        if let Ok((rollback, origins)) = changes::invert(&applied, None, catalog) {
            // A serial number never goes down: the SOA gets a new increment (R4.7).
            let rollback = crate::dns_write::soa_on_rollback(rollback, catalog);
            if !rollback.operations.is_empty() {
                let rollback_json = changes::changeset_to_json(&rollback).unwrap_or(Value::Null);
                let _ = context.note(
                    "retour",
                    vec![("changeset", rollback_json), ("origines", json!(origins))],
                );
                let undone = execute(
                    link,
                    &rollback.operations,
                    ROLLBACK,
                    &context,
                    None,
                    false,
                    Some(&mut *session),
                );
                report.rollback = Some(rollback);
                report.origins = origins;
                report.rollback_applied = undone.done;
                report.rollback_error = undone.error;
                report.doubtful_rollback = undone.doubtful;
            }
        }
        report.issue = issue_after_failure(&report);
    }
    // If the disk refuses, the report returned stays exact; the journal read back will say
    // « interrupted ».
    if let Ok(Value::Object(map)) = changes::report_to_json(&report) {
        let _ = journal.write(&map);
    }
    Ok(Ok(Outcome {
        report,
        problems: Vec::new(),
    }))
}

/// Checks then applies `changeset` on the thread of the connection (`appliquer`). Blocking.
/// `resumes`: identifier of the report this application finishes or undoes. `retry`: after
/// a conflict that left nothing written, called with the changeset tried; at most
/// `ATTEMPTS` attempts, each journaled apart; the report returned is the one of the last.
pub fn apply(
    connection: &Connection,
    profile: &Profile,
    changeset: &Changeset,
    journal: Arc<Journal>,
    catalog: Arc<dyn WriteCatalog>,
    resumes: Option<String>,
    mut retry: Option<Retry>,
) -> Result<Outcome, ApplyError> {
    if profile.read_only {
        return Err(ApplyError::Record(record(
            "ErreurLectureSeule",
            catalog.write_text(&WriteMsg::ReadOnly {
                domain: profile.domain.clone(),
            }),
            "",
        )));
    }
    if changeset.operations.is_empty() {
        return Err(ApplyError::Record(record(
            "ErreurAnnuaire",
            "changeset vide".into(),
            "",
        )));
    }
    let (changeset, domain) = (changeset.clone(), profile.domain.clone());
    let imposed = profile.write_dc.is_some();
    connection
        .run(false, move |link| {
            let mut session = SysvolSession::with_protection(
                sysvol_write::opener(link.sysvol),
                &link.state.dc,
                link.sysvol,
            );
            let result = attempts(
                link,
                &changeset,
                &domain,
                resumes.as_deref(),
                &journal,
                catalog.as_ref(),
                retry.as_mut(),
                &mut session,
                imposed,
            );
            session.close();
            result
        })
        .map_err(ApplyError::Failure)?
        .map_err(ApplyError::Record)
}

/// The attempts of `apply`, on the thread of the connection.
#[allow(clippy::too_many_arguments)]
fn attempts(
    link: &mut Link,
    changeset: &Changeset,
    domain: &str,
    resumes: Option<&str>,
    journal: &Journal,
    catalog: &dyn WriteCatalog,
    mut retry: Option<&mut Retry>,
    session: &mut SysvolSession,
    imposed: bool,
) -> Result<Result<Outcome, ErrorRecord>, LdapError> {
    let user = identity(link);
    let mut tried = changeset.clone();
    let mut attempt_number = 1;
    loop {
        let outcome = match attempt(
            link, &tried, &user, domain, resumes, journal, catalog, session, imposed,
        )? {
            Ok(outcome) => outcome,
            Err(error) => return Ok(Err(error)),
        };
        let Some(retry) = retry.as_mut() else {
            return Ok(Ok(outcome));
        };
        if attempt_number == ATTEMPTS || !conflict_without_trace(&outcome) {
            return Ok(Ok(outcome));
        }
        match retry(link, &tried) {
            Some(next) if !next.operations.is_empty() => tried = next,
            _ => return Ok(Ok(outcome)),
        }
        attempt_number += 1;
    }
}

// --- Versions and modifications by difference ---------------------------------------------

/// Present version of the object (None if it does not exist), to put in the operation
/// (`lire_version`). Blocking.
pub fn read_version(connection: &Connection, dn_text: &str) -> Result<Option<Read>, Failure> {
    let dn_text = dn_text.to_owned();
    connection.run(true, move |link| {
        let Some(entry) = read_entry(link, &dn_text, &["uSNChanged"], ALL)? else {
            return Ok(None);
        };
        let usn = entry
            .values("uSNChanged")
            .first()
            .and_then(|v| integer::decode(v, Width::Bits64).ok())
            .ok_or_else(|| LdapError::new(code::DECODING_ERROR, "uSNChanged absent"))?;
        Ok(Some(Read {
            dc: link.state.dc.clone(),
            usn,
        }))
    })
}

/// Why `prepare_modification` could not build the operation.
#[derive(Debug, Clone)]
pub enum PrepareError {
    Failure(Failure),
    /// The object does not exist (`ErreurConflit`).
    Missing(String),
    /// A secret, or an attribute returned by ranges: an explicit `Change` is needed.
    Unsupported(String),
}

/// Reads the object and builds the `Modify` that gives each attribute the values wanted; an
/// empty list clears the attribute; None if nothing changes (`preparer_modification`).
/// Blocking.
pub fn prepare_modification(
    connection: &Connection,
    dn_text: &str,
    wanted: AttributeMap,
) -> Result<Option<Operation>, PrepareError> {
    for (attribute, _) in &wanted {
        if search::verify_attribute(attribute).is_err() || is_sensitive(attribute) {
            return Err(PrepareError::Unsupported(attribute.clone()));
        }
    }
    let dn_owned = dn_text.to_owned();
    let names: Vec<String> = std::iter::once("uSNChanged".to_owned())
        .chain(wanted.iter().map(|(a, _)| a.clone()))
        .collect();
    let read = connection
        .run(true, move |link| {
            let attributes: Vec<&str> = names.iter().map(String::as_str).collect();
            let entry = read_entry(link, &dn_owned, &attributes, ALL)?;
            Ok(entry.map(|e| (link.state.dc.clone(), e)))
        })
        .map_err(PrepareError::Failure)?;
    let Some((dc, entry)) = read else {
        return Err(PrepareError::Missing(dn_text.to_owned()));
    };
    if entry
        .attributes
        .iter()
        .any(|(a, _)| a.to_lowercase().contains(";range="))
    {
        return Err(PrepareError::Unsupported(dn_text.to_owned()));
    }
    let mut changes = Vec::new();
    for (attribute, new) in &wanted {
        let present = entry.values(attribute);
        let removed: Values = present
            .iter()
            .filter(|v| !new.contains(v))
            .cloned()
            .collect();
        let mut added: Values = Vec::new();
        for v in new {
            if !present.contains(v) && !added.contains(v) {
                added.push(v.clone());
            }
        }
        if !removed.is_empty() || !added.is_empty() {
            changes.push(
                Change::new(attribute, removed, added)
                    .map_err(|e| PrepareError::Unsupported(e.to_string()))?,
            );
        }
    }
    if changes.is_empty() {
        return Ok(None);
    }
    let usn = entry
        .values("uSNChanged")
        .first()
        .and_then(|v| integer::decode(v, Width::Bits64).ok())
        .unwrap_or(0);
    Operation::modify(dn_text, changes, Some(Read { dc, usn }))
        .map(Some)
        .map_err(|e| PrepareError::Unsupported(e.to_string()))
}

// --- Journal: reading back and resuming -----------------------------------------------------

/// Report of an application from its records; `Interrupted` without a final report
/// (`_reconstituer`).
fn reconstitute(records: &[&Map<String, Value>]) -> Result<Report, ChangeError> {
    let bad = |m: &str| ChangeError::Journal(m.to_owned());
    if let Some(last) = records
        .iter()
        .find(|e| e.get("etape").and_then(Value::as_str) == Some("bilan"))
    {
        return changes::report_from_json(&Value::Object((*last).clone()));
    }
    let intention = records
        .iter()
        .find(|e| e.get("etape").and_then(Value::as_str) == Some("intention"))
        .filter(|e| e.get("version") == Some(&Value::from(changes::JOURNAL_VERSION)))
        .ok_or_else(|| bad("application without a readable intention"))?;
    let text = |name: &str| -> Result<String, ChangeError> {
        intention
            .get(name)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| bad(name))
    };
    let index = |e: &Map<String, Value>| -> Result<usize, ChangeError> {
        e.get("indice")
            .and_then(Value::as_u64)
            .and_then(|i| usize::try_from(i).ok())
            .ok_or_else(|| bad("indice"))
    };
    let changeset =
        changes::changeset_from_json(intention.get("changeset").ok_or_else(|| bad("changeset"))?)?;
    let mut rollback: Option<Changeset> = None;
    let mut origins: Vec<usize> = Vec::new();
    let mut done: HashMap<&str, Vec<Applied>> = HashMap::new();
    let mut befores: HashMap<(String, usize), AttributeMap> = HashMap::new();
    let mut error: Option<ErrorRecord> = None;
    let mut doubtful_failure = false;
    for e in records {
        match e.get("etape").and_then(Value::as_str) {
            Some("avant") => {
                let phase = e
                    .get("phase")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("phase"))?;
                let before =
                    changes::attributes_from_json(e.get("avant").ok_or_else(|| bad("avant"))?)?;
                befores.insert((phase.to_owned(), index(e)?), before);
            }
            Some("fait") => {
                let phase = e
                    .get("phase")
                    .and_then(Value::as_str)
                    .ok_or_else(|| bad("phase"))?;
                let i = index(e)?;
                let source = if phase == APPLICATION {
                    Some(&changeset)
                } else {
                    rollback.as_ref()
                };
                let list = done
                    .entry(if phase == APPLICATION {
                        APPLICATION
                    } else {
                        ROLLBACK
                    })
                    .or_default();
                let operation = source
                    .filter(|_| i == list.len())
                    .and_then(|s| s.operations.get(i))
                    .ok_or_else(|| bad("inconsistent « fait » records"))?;
                list.push(Applied {
                    operation: operation.clone(),
                    after: changes::read_from_json(e.get("apres"))?,
                    before: befores.get(&(phase.to_owned(), i)).cloned(),
                });
            }
            Some("echec") => {
                error = changes::error_from_json(e.get("erreur"))?;
                doubtful_failure = e.get("douteuse").and_then(Value::as_bool).unwrap_or(false);
            }
            Some("retour") => {
                rollback = Some(changes::changeset_from_json(
                    e.get("changeset").ok_or_else(|| bad("changeset"))?,
                )?);
                origins = e
                    .get("origines")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_u64)
                            .filter_map(|o| usize::try_from(o).ok())
                            .collect()
                    })
                    .unwrap_or_default();
            }
            _ => {}
        }
    }
    let applied = done.remove(APPLICATION).unwrap_or_default();
    let rollback_applied = done.remove(ROLLBACK).unwrap_or_default();
    let in_progress = |phase: &str, source: &Changeset, rank: usize, maybe: bool| {
        if !maybe || rank >= source.operations.len() {
            return None;
        }
        source.operations.get(rank).map(|op| Applied {
            operation: op.clone(),
            after: None,
            before: befores.get(&(phase.to_owned(), rank)).cloned(),
        })
    };
    let doubtful = in_progress(
        APPLICATION,
        &changeset,
        applied.len(),
        error.is_none() || doubtful_failure,
    );
    let doubtful_rollback = rollback
        .as_ref()
        .and_then(|r| in_progress(ROLLBACK, r, rollback_applied.len(), true));
    Ok(Report {
        id: intention
            .get("id")
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned))
            .ok_or_else(|| bad("id"))?,
        timestamp: text("horodatage")?,
        domain: text("domaine")?,
        dc: text("dc")?,
        user: text("utilisateur")?,
        changeset,
        applied,
        issue: Issue::Interrupted,
        error,
        rollback,
        origins,
        rollback_applied,
        rollback_error: None,
        doubtful,
        doubtful_rollback,
        resumes: intention
            .get("reprend")
            .and_then(Value::as_str)
            .map(str::to_owned),
        resumed_by: None,
    })
}

/// Reports of the journal, from the oldest to the most recent; an application without a
/// final report (abrupt stop) is `Interrupted`, with what its steps say of it
/// (`lire_journal`).
pub fn read_journal(journal: &Journal) -> Vec<Report> {
    let records = journal.read();
    let mut order: Vec<String> = Vec::new();
    let mut groups: HashMap<String, Vec<&Map<String, Value>>> = HashMap::new();
    for record in &records {
        if let Some(id) = record.get("id").and_then(Value::as_str) {
            if !groups.contains_key(id) {
                order.push(id.to_owned());
            }
            groups.entry(id.to_owned()).or_default().push(record);
        }
    }
    let mut reports: Vec<Report> = order
        .iter()
        .filter_map(|id| reconstitute(groups.get(id)?).ok())
        .collect();
    // Records of another version or damaged: left out above.
    let resumed: Vec<(String, String)> = reports
        .iter()
        .filter_map(|r| Some((r.resumes.clone()?, r.id.clone())))
        .collect();
    for (target, by) in resumed {
        if let Some(r) = reports.iter_mut().find(|r| r.id == target) {
            r.resumed_by = Some(by);
        }
    }
    reports
}

/// Applications to settle at the start: interrupted, or whose rollback did not undo
/// everything, and that no application resumed since (`a_reprendre`).
pub fn to_resume(journal: &Journal) -> Vec<Report> {
    read_journal(journal)
        .into_iter()
        .filter(|r| {
            matches!(r.issue, Issue::Interrupted | Issue::Incomplete) && r.resumed_by.is_none()
        })
        .collect()
}

/// Did the operation take place? (true, false, or None if the directory or the SYSVOL does
/// not tell), and the version of the object if it did (`_constater_une`). A SYSVOL that cannot
/// be read leaves the operation doubtful.
fn ascertain_one(
    link: &mut Link,
    op: &Operation,
    session: &mut SysvolSession,
) -> Result<(Option<bool>, Option<Read>), LdapError> {
    if op.is_file_share() {
        return Ok((crate::share_write::ascertain(&mut session.shares, op), None));
    }
    if op.is_sysvol() {
        return Ok((sysvol_write::ascertain(session, op).unwrap_or(None), None));
    }
    let version =
        |link: &mut Link, dn_text: &str, filter: &str| -> Result<Option<Read>, LdapError> {
            let entry = read_entry(link, dn_text, &["uSNChanged"], filter)?;
            Ok(entry.map(|e| Read {
                dc: link.state.dc.clone(),
                usn: e
                    .values("uSNChanged")
                    .first()
                    .and_then(|v| integer::decode(v, Width::Bits64).ok())
                    .unwrap_or(0),
            }))
        };
    match op {
        Operation::Add { dn, .. } => {
            let after = version(link, dn, ALL)?;
            Ok((Some(after.is_some()), after))
        }
        Operation::Modify { dn, changes, .. } => {
            let (added, removed) = modification_states(changes);
            let after_filter = state_filter(&added, &removed);
            if after_filter == ALL {
                return Ok((None, None));
            }
            if let Some(after) = version(link, dn, &after_filter)? {
                return Ok((Some(true), Some(after)));
            }
            if version(link, dn, &state_filter(&removed, &added))?.is_some() {
                return Ok((Some(false), None));
            }
            Ok((None, None))
        }
        Operation::Rename { dn, .. } => {
            let Ok(new_dn) = op.dn_after() else {
                return Ok((None, None));
            };
            let (new, old) = (version(link, &new_dn, ALL)?, version(link, dn, ALL)?);
            match (new, old) {
                (Some(new), None) => Ok((Some(true), Some(new))),
                (None, Some(_)) => Ok((Some(false), None)),
                _ => Ok((None, None)),
            }
        }
        _ => Ok((Some(version(link, op.dn(), ALL)?.is_none()), None)),
    }
}

/// Reads the directory (and the SYSVOL of the same DC) to settle the doubtful operations of
/// the report (`constater`): an operation done joins `applied` (or `rollback_applied`); one
/// that did not take place disappears; if they do not tell, it stays doubtful (to check by
/// hand). Nothing is written. Blocking.
pub fn ascertain(connection: &Connection, report: &Report) -> Result<Report, Failure> {
    let report = report.clone();
    connection.run(true, move |link| {
        let mut session = SysvolSession::with_protection(
            sysvol_write::opener(link.sysvol),
            &link.state.dc,
            link.sysvol,
        );
        let mut result = report.clone();
        if let Some(d) = result.doubtful.clone() {
            let (done, after) = ascertain_one(link, &d.operation, &mut session)?;
            if let Some(done) = done {
                if done {
                    result.applied.push(Applied { after, ..d });
                }
                result.doubtful = None;
            }
        }
        if let Some(d) = result.doubtful_rollback.clone() {
            let (done, after) = ascertain_one(link, &d.operation, &mut session)?;
            if let Some(done) = done {
                if done {
                    result.rollback_applied.push(Applied { after, ..d });
                }
                result.doubtful_rollback = None;
            }
        }
        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_filters() {
        let present = vec![("description".to_owned(), vec![b"a".to_vec()])];
        let absent = vec![
            ("description".to_owned(), vec![b"A".to_vec(), b"b".to_vec()]),
            ("unicodePwd".to_owned(), vec![b"x".to_vec()]),
        ];
        // « A » differs from « a » by the case only: not tested; the secret neither.
        assert_eq!(
            state_filter(&present, &absent),
            "(&(description=\\61)(!(description=\\62)))"
        );
        assert_eq!(state_filter(&Vec::new(), &Vec::new()), ALL);
    }

    #[test]
    fn replace_where_needed() {
        let changes = vec![
            Change::new("pwdLastSet", vec![b"1".to_vec()], vec![b"0".to_vec()]).unwrap(),
            Change::new("description", vec![b"a".to_vec()], vec![b"b".to_vec()]).unwrap(),
        ];
        let (mods, controls) = modification_request(&changes);
        assert_eq!(
            mods,
            [
                Modification::Replace("pwdLastSet".into(), vec![b"0".to_vec()]),
                Modification::Delete("description".into(), vec![b"a".to_vec()]),
                Modification::Add("description".into(), vec![b"b".to_vec()]),
            ]
        );
        assert!(controls.is_empty());
    }

    #[test]
    fn identifiers_and_dates() {
        let id = new_id();
        assert_eq!(id.len(), 32);
        assert_ne!(id, new_id());
        let t = timestamp();
        assert!(t.ends_with("+00:00") && t.len() == 25, "{t}");
    }

    #[test]
    fn journal_read_back() {
        let dir = std::env::temp_dir().join(format!("annuaire-journal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let journal = Journal::new(Some(dir.join("changes.jsonl")), 1 << 20, 1);
        let op = |d: &str| {
            Operation::modify(
                "CN=a,DC=x",
                vec![Change::new("description", Vec::new(), vec![d.as_bytes().to_vec()]).unwrap()],
                None,
            )
            .unwrap()
        };
        let changeset = Changeset {
            operations: vec![op("1"), op("2")],
            remarks: Vec::new(),
        };
        let record = |pairs: Vec<(&str, Value)>| -> Map<String, Value> {
            let mut m = Map::new();
            m.insert("version".into(), json!(changes::JOURNAL_VERSION));
            m.insert("id".into(), json!("a1"));
            for (k, v) in pairs {
                m.insert(k.into(), v);
            }
            m
        };
        journal
            .write(&record(vec![
                ("etape", json!("intention")),
                ("horodatage", json!("2026-10-16T08:00:00+00:00")),
                ("domaine", json!("lab.test")),
                ("dc", json!("dc1")),
                ("utilisateur", json!("u:LAB\\x")),
                ("reprend", Value::Null),
                ("changeset", changes::changeset_to_json(&changeset).unwrap()),
            ]))
            .unwrap();
        journal
            .write(&record(vec![
                ("etape", json!("fait")),
                ("phase", json!(APPLICATION)),
                ("indice", json!(0)),
                ("apres", json!({"dc": "dc1", "usn": 7})),
            ]))
            .unwrap();
        let reports = read_journal(&journal);
        let [report] = reports.as_slice() else {
            panic!("one report expected");
        };
        assert_eq!(report.issue, Issue::Interrupted);
        assert_eq!(report.applied.len(), 1);
        assert_eq!(
            report.doubtful.as_ref().map(|d| &d.operation),
            changeset.operations.get(1)
        );
        assert_eq!(to_resume(&journal).len(), 1);
        let mut later = record(vec![
            ("etape", json!("intention")),
            ("horodatage", json!("2026-10-16T08:01:00+00:00")),
            ("domaine", json!("lab.test")),
            ("dc", json!("dc1")),
            ("utilisateur", json!("u:LAB\\x")),
            ("reprend", json!("a1")),
            ("changeset", changes::changeset_to_json(&changeset).unwrap()),
        ]);
        later.insert("id".into(), json!("b2"));
        journal.write(&later).unwrap();
        assert!(to_resume(&journal).iter().all(|r| r.id != "a1"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Synchronization of the local copy with the DC (JC.2, ADR 0008, `annuaire.core.synchro`).
//! Always against **the same DC**, the one of the landmark, through a connection that only
//! goes to it. Each time: read, **before** the data, what the DC says of itself
//! (`highestCommittedUSN`, `invocationId`); choose between delta and complete
//! resynchronization (first time, other DC, restoration, landmark older than the tombstone
//! lifetime, schema changed); read the delta `(uSNChanged>=landmark+1)` with « show
//! deleted » and « extended DN », or the whole domain; apply in **one transaction**,
//! landmark included. Under an account without access to `Deleted Objects`, the deletions
//! do not come with the delta: at the first synchronization of the session, the list of the
//! GUIDs of the domain is compared to the copy.

use std::collections::HashSet;
use std::time::Duration;

use annuaire_codecs::time::UtcTime;
use annuaire_codecs::{Guid, Sid};

use crate::connection::{Connection, Failure};
use crate::error::{LdapError, code};
use crate::profile::Profile;
use crate::search::{self, RANGE_SIZE, Search, SearchError};
use crate::session::{Control, Entry, Scope, SearchRequest};
use crate::source::{PAGE_SIZE, connection_to, search_blocking};
use crate::store::{
    Changes, Landmark, Line, LineError, Store, StoreError, cache_attributes, line_from_entry,
    split_extended_dn,
};

pub const OID_EXTENDED_DN: &str = "1.2.840.113556.1.4.529";
pub const OID_SHOW_DELETED: &str = "1.2.840.113556.1.4.417";

/// `tombstoneLifetime` absent: 60 days (forests before Windows 2003 SP1).
pub const DEFAULT_TOMBSTONE_DAYS: i64 = 60;

/// Extended DN, text form: `<GUID=…>;<SID=…>;CN=…` (value SEQUENCE { INTEGER 1 }).
pub fn extended_dn_control() -> Control {
    Control {
        oid: OID_EXTENDED_DN.into(),
        critical: false,
        value: Some(vec![0x30, 0x03, 0x02, 0x01, 0x01]),
    }
}

pub fn show_deleted_control() -> Control {
    Control {
        oid: OID_SHOW_DELETED.into(),
        critical: true,
        value: None,
    }
}

/// Why a complete resynchronization (`Motif`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    First,
    OtherDc,
    Restoration,
    Old,
    Schema,
}

impl Reason {
    /// Value of `Motif`.
    pub fn name(self) -> &'static str {
        match self {
            Self::First => "premiere",
            Self::OtherDc => "autre-dc",
            Self::Restoration => "restauration",
            Self::Old => "ancienne",
            Self::Schema => "schema",
        }
    }
}

/// What the DC says of itself, read before the data (`EtatDC`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DcState {
    pub dc: String,
    pub invocation: String,
    pub usn: i64,
    pub root: String,
    pub schema: String,
    pub configuration: String,
}

/// Why a complete resynchronization is needed; None: a delta is enough (`motif_complete`).
pub fn complete_reason(
    landmark: Option<&Landmark>,
    dc: &DcState,
    now: UtcTime,
    tombstone_days: i64,
    schema_changed: bool,
) -> Option<Reason> {
    let Some(landmark) = landmark else {
        return Some(Reason::First);
    };
    if !landmark.dc.eq_ignore_ascii_case(&dc.dc) || !landmark.root.eq_ignore_ascii_case(&dc.root) {
        return Some(Reason::OtherDc);
    }
    if landmark.invocation != dc.invocation || dc.usn < landmark.usn {
        return Some(Reason::Restoration);
    }
    if now.seconds_since(landmark.date) > tombstone_days * 86_400 {
        return Some(Reason::Old);
    }
    if schema_changed {
        return Some(Reason::Schema);
    }
    None
}

/// Why a synchronization failed.
#[derive(Debug)]
pub enum SyncError {
    Failure(Failure),
    Search(SearchError),
    Line(LineError),
    Store(StoreError),
    /// The RootDSE or the NTDS object of the DC could not be read.
    Unreadable(String),
    Closed,
}

impl From<Failure> for SyncError {
    fn from(f: Failure) -> Self {
        Self::Failure(f)
    }
}

impl From<SearchError> for SyncError {
    fn from(e: SearchError) -> Self {
        Self::Search(e)
    }
}

impl From<StoreError> for SyncError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

fn read_one(
    connection: &Connection,
    base: &str,
    attributes: &[&str],
    controls: Vec<Control>,
) -> Result<Option<Entry>, Failure> {
    let base = base.to_owned();
    let attributes: Vec<String> = attributes.iter().map(|&a| a.to_owned()).collect();
    connection.run(true, move |link| {
        let request = SearchRequest {
            base: base.clone(),
            scope: Scope::Base,
            filter: "(objectClass=*)".into(),
            attributes: attributes.clone(),
            controls: controls.clone(),
            size_limit: 0,
        };
        match link.session.search_wait(request, Some(link.timeout)) {
            Ok(response) => Ok(response.into_entries().into_iter().next()),
            Err(e) if e.code == code::NO_SUCH_OBJECT && !e.foreign => Ok(None),
            Err(e) => Err(e),
        }
    })
}

fn first_text(entry: &Entry, name: &str) -> String {
    entry
        .values(name)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

/// RootDSE (`highestCommittedUSN`, `dsServiceName`) then `invocationId` of the DC
/// (`lire_etat_dc`).
pub fn read_dc_state(connection: &Connection) -> Result<DcState, SyncError> {
    let dse = read_one(
        connection,
        "",
        &[
            "highestCommittedUSN",
            "dsServiceName",
            "defaultNamingContext",
            "schemaNamingContext",
            "configurationNamingContext",
        ],
        Vec::new(),
    )?
    .ok_or_else(|| SyncError::Unreadable("RootDSE".into()))?;
    let service = first_text(&dse, "dsServiceName");
    let ntds = read_one(connection, &service, &["invocationId"], Vec::new())?
        .ok_or_else(|| SyncError::Unreadable(service.clone()))?;
    let invocation = ntds
        .values("invocationId")
        .first()
        .and_then(|v| Guid::decode(v).ok())
        .map(|g| g.to_string())
        .ok_or_else(|| SyncError::Unreadable(format!("{service}: invocationId")))?;
    let dc = connection.state().map(|s| s.dc.clone()).unwrap_or_default();
    Ok(DcState {
        dc,
        invocation,
        usn: first_text(&dse, "highestCommittedUSN")
            .trim()
            .parse()
            .map_err(|_| SyncError::Unreadable("highestCommittedUSN".into()))?,
        root: first_text(&dse, "defaultNamingContext"),
        schema: first_text(&dse, "schemaNamingContext"),
        configuration: first_text(&dse, "configurationNamingContext"),
    })
}

/// True if an object of the schema changed on this DC after `usn` (indexed search, one
/// result at most). Only valid on the DC of the landmark: the USN is its own.
pub fn schema_changed(connection: &Connection, schema: &str, usn: i64) -> Result<bool, Failure> {
    let schema = schema.to_owned();
    connection.run(true, move |link| {
        let request = SearchRequest {
            base: schema.clone(),
            scope: Scope::Subtree,
            filter: format!("(uSNChanged>={})", usn + 1),
            attributes: vec!["1.1".into()],
            controls: Vec::new(),
            size_limit: 1,
        };
        match link.session.search_wait(request, Some(link.timeout)) {
            Ok(response) => Ok(!response.into_entries().is_empty()),
            Err(e) if e.code == code::SIZELIMIT_EXCEEDED => Ok(true),
            Err(e) => Err(e),
        }
    })
}

pub fn tombstone_days(connection: &Connection, configuration: &str) -> Result<i64, Failure> {
    let base = format!("CN=Directory Service,CN=Windows NT,CN=Services,{configuration}");
    let entry = read_one(connection, &base, &["tombstoneLifetime"], Vec::new())?;
    Ok(entry
        .map(|e| first_text(&e, "tombstoneLifetime"))
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or(DEFAULT_TOMBSTONE_DAYS))
}

/// True if the bound account is a member of BUILTIN\Administrators (`tokenGroups` of the
/// RootDSE): by default only this group lists `Deleted Objects`, and its deltas then give
/// the deletions (`acces_supprimes`).
pub fn deleted_access(connection: &Connection) -> Result<bool, Failure> {
    let administrators = "S-1-5-32-544"
        .parse::<Sid>()
        .map(|s| s.encode())
        .unwrap_or_default();
    let entry = read_one(connection, "", &["tokenGroups"], Vec::new())?;
    Ok(entry.is_some_and(|e| e.values("tokenGroups").contains(&administrators)))
}

/// `member;range=0-1499` (Windows beyond 1,500 values): the rest read by ranges, under the
/// same extended DN control (`_member_par_plages`).
fn member_by_ranges(connection: &Connection, entry: Entry) -> Result<Entry, Failure> {
    let ranged: Vec<String> = entry
        .attributes
        .iter()
        .map(|(n, _)| n.clone())
        .filter(|n| n.to_lowercase().starts_with("member;range="))
        .collect();
    if ranged.is_empty() {
        return Ok(entry);
    }
    let (_, dn) = split_extended_dn(&entry.dn);
    let dn = dn.to_owned();
    let (mut values, mut next) =
        search::parse_range(&entry.attributes, "member", 0).map_err(|_| Failure::Ldap {
            dc: String::new(),
            error: LdapError::new(code::DECODING_ERROR, format!("{dn}: member ranges")),
        })?;
    while let Some(start) = next {
        let base = dn.clone();
        let read = connection.run(true, move |link| {
            let request = SearchRequest {
                base: base.clone(),
                scope: Scope::Base,
                filter: "(objectClass=*)".into(),
                attributes: vec![search::range_request("member", start, RANGE_SIZE)],
                controls: vec![extended_dn_control()],
                size_limit: 0,
            };
            Ok(link
                .session
                .search_wait(request, Some(link.timeout))?
                .into_entries()
                .into_iter()
                .next())
        })?;
        let Some(more) = read else { break };
        let (received, following) = search::parse_range(&more.attributes, "member", start)
            .map_err(|_| Failure::Ldap {
                dc: String::new(),
                error: LdapError::new(code::DECODING_ERROR, format!("{dn}: member ranges")),
            })?;
        values.extend(received);
        next = following;
    }
    let mut attributes: Vec<(String, Vec<Vec<u8>>)> = entry
        .attributes
        .into_iter()
        .filter(|(n, _)| !ranged.contains(n))
        .collect();
    attributes.push(("member".into(), values));
    Ok(Entry {
        dn: entry.dn,
        attributes,
    })
}

/// The whole domain (`usn` None) or the objects changed since `usn`, tombstones included
/// (`lire_lignes`). Blocking.
pub fn read_lines(
    connection: &Connection,
    root: &str,
    usn: Option<i64>,
) -> Result<Vec<Line>, SyncError> {
    let mut controls = vec![extended_dn_control()];
    let mut attributes = cache_attributes();
    let mut filter = "(objectClass=*)".to_owned();
    if let Some(usn) = usn {
        controls.push(show_deleted_control());
        attributes.push("isDeleted".into());
        filter = format!("(uSNChanged>={})", usn + 1);
    }
    let search = Search {
        base: root.to_owned(),
        scope: Scope::Subtree,
        filter,
        attributes,
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls,
    };
    let mut entries = Vec::new();
    search_blocking(connection, search, &mut |page| {
        entries.extend(page);
        true
    })?;
    let mut lines = Vec::with_capacity(entries.len());
    for entry in entries {
        let entry = member_by_ranges(connection, entry)?;
        lines.push(line_from_entry(&entry).map_err(SyncError::Line)?);
    }
    Ok(lines)
}

/// GUID of an entry read with the extended DN control: from its DN, as `line_from_entry`
/// takes it, else from `objectGUID`. An ordinary account sees objects whose `objectGUID` it
/// cannot read (`CN=Keys`, the IPsec policies…): the extended DN still gives it.
pub fn guid_of_entry(entry: &Entry) -> Option<Vec<u8>> {
    split_extended_dn(&entry.dn)
        .0
        .or_else(|| entry.values("objectGUID").first().cloned())
}

/// GUID of every object of the domain (`lire_guids`). Read as the lines of the copy are (the
/// GUID of the extended DN): a GUID missing here deletes the object from the copy.
pub fn read_guids(connection: &Connection, root: &str) -> Result<HashSet<Vec<u8>>, SyncError> {
    let search = Search {
        base: root.to_owned(),
        scope: Scope::Subtree,
        filter: "(objectClass=*)".into(),
        attributes: vec!["objectGUID".into()],
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls: vec![extended_dn_control()],
    };
    let mut guids = HashSet::new();
    search_blocking(connection, search, &mut |page| {
        guids.extend(page.iter().filter_map(guid_of_entry));
        true
    })?;
    Ok(guids)
}

/// Phase of a synchronization, told to the source (`Phase`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Delta running.
    Reading,
    /// Complete resynchronization running.
    Complete,
    /// A transaction was just committed.
    Applied,
}

/// A step of a synchronization (`Avancement`).
#[derive(Debug, Clone)]
pub struct Progress {
    pub phase: Phase,
    pub landmark: Option<Landmark>,
    pub reason: Option<Reason>,
    pub changes: Option<Changes>,
}

/// Synchronizes a copy with the DC of its landmark. One call at a time (the source sees to
/// it); blocking, in a thread of its own (`Synchroniseur`).
#[derive(Debug)]
pub struct Synchronizer {
    profile: Profile,
    connection: Option<Connection>,
    dc: Option<String>,
    tombstone: Option<i64>,
    deleted_access: Option<bool>,
}

impl Synchronizer {
    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            connection: None,
            dc: None,
            tombstone: None,
            deleted_access: None,
        }
    }

    pub fn close(&mut self) {
        if let Some(c) = self.connection.take() {
            c.close();
        }
    }

    fn connection_to(&mut self, dc: Option<&str>) -> &Connection {
        let same = self.connection.is_some() && self.dc.as_deref() == dc;
        if !same {
            self.close();
            self.connection = Some(connection_to(&self.profile, dc));
            self.dc = dc.map(str::to_owned);
        }
        self.connection
            .get_or_insert_with(|| connection_to(&self.profile, dc))
    }

    /// Connection to the DC of the landmark and its state; if it does not answer, another DC
    /// (true: failover).
    fn state(&mut self, landmark: Option<&Landmark>) -> Result<(DcState, bool), SyncError> {
        if let Some(landmark) = landmark {
            let connection = self.connection_to(Some(&landmark.dc));
            match read_dc_state(connection) {
                Ok(state) => return Ok((state, false)),
                Err(SyncError::Failure(Failure::Connect(_))) => {}
                Err(SyncError::Failure(Failure::Ldap { error, .. }))
                    if crate::error::categorize(&error).unreachable() => {}
                Err(e) => return Err(e),
            }
        }
        let connection = self.connection_to(None);
        let state = read_dc_state(connection)?;
        self.dc = Some(state.dc.clone()); // from now on the DC of the copy
        Ok((state, landmark.is_some()))
    }

    /// One synchronization; returns the reason of a complete one, None for a delta.
    /// `check_deletions`: also compare the list of the GUIDs if the account does not see
    /// `Deleted Objects`.
    /// `spared(start)`: the GUIDs read again after a write since `start` (`epargnes`).
    pub fn synchronize(
        &mut self,
        store: &Store,
        report: &mut dyn FnMut(Progress),
        check_deletions: bool,
        spared: &dyn Fn(std::time::Instant) -> std::collections::HashSet<Vec<u8>>,
    ) -> Result<Option<Reason>, SyncError> {
        let landmark = store.landmark();
        let (dc, failover) = self.state(landmark.as_ref())?;
        let connection = self.connection.as_ref().ok_or(SyncError::Closed)?;
        let date = crate::store::now();
        let tombstone = match self.tombstone {
            Some(t) => t,
            None => {
                let t = tombstone_days(connection, &dc.configuration)?;
                self.tombstone = Some(t);
                t
            }
        };
        let mut schema = false;
        if let Some(l) = landmark
            .as_ref()
            .filter(|l| !failover && l.invocation == dc.invocation)
        {
            schema = schema_changed(connection, &dc.schema, l.usn)?;
        }
        let reason = if failover {
            Some(Reason::OtherDc)
        } else {
            complete_reason(landmark.as_ref(), &dc, date, tombstone, schema)
        };
        let new = Landmark {
            dc: dc.dc.clone(),
            invocation: dc.invocation.clone(),
            usn: dc.usn,
            date,
            root: dc.root.clone(),
        };
        report(Progress {
            phase: if reason.is_none() {
                Phase::Reading
            } else {
                Phase::Complete
            },
            landmark: landmark.clone(),
            reason,
            changes: None,
        });
        let since = match (reason, &landmark) {
            (None, Some(l)) => Some(l.usn),
            _ => None,
        };
        let start = std::time::Instant::now();
        let lines = read_lines(connection, &dc.root, since)?;
        let changes = store.apply(&lines, &new, reason.is_some(), &spared(start))?;
        drop(lines);
        report(Progress {
            phase: Phase::Applied,
            landmark: Some(new.clone()),
            reason,
            changes: Some(changes),
        });
        if check_deletions && reason.is_none() {
            let access = match self.deleted_access {
                Some(a) => a,
                None => {
                    let a = deleted_access(connection)?;
                    self.deleted_access = Some(a);
                    a
                }
            };
            if !access {
                let known = store.guids();
                let present = read_guids(connection, &dc.root)?;
                let removed = store.remove_absent(&present, &known)?;
                if !removed.is_empty() {
                    report(Progress {
                        phase: Phase::Applied,
                        landmark: Some(new),
                        reason: None,
                        changes: Some(removed),
                    });
                }
            }
        }
        Ok(reason)
    }
}

/// Time between two deltas while the domain is open (`INTERVALLE_SYNCHRO`).
pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{iso_parse, now};

    fn state() -> DcState {
        DcState {
            dc: "dc1.lab.test".into(),
            invocation: "inv".into(),
            usn: 100,
            root: "DC=lab,DC=test".into(),
            schema: String::new(),
            configuration: String::new(),
        }
    }

    #[test]
    fn guid_from_the_extended_dn() {
        let guid: annuaire_codecs::Guid = "6f5a3c3e-1b2d-4c5e-8f90-0a1b2c3d4e5f".parse().unwrap();
        let unreadable = Entry {
            dn: format!("<GUID={guid}>;<SID=S-1-5-21-1-2-3-500>;CN=Keys,DC=lab,DC=test"),
            attributes: Vec::new(),
        };
        assert_eq!(guid_of_entry(&unreadable), Some(guid.encode()));
        let plain = Entry {
            dn: "CN=Keys,DC=lab,DC=test".into(),
            attributes: vec![("objectGUID".into(), vec![guid.encode()])],
        };
        assert_eq!(guid_of_entry(&plain), Some(guid.encode()));
        let nothing = Entry {
            dn: "CN=Keys,DC=lab,DC=test".into(),
            attributes: Vec::new(),
        };
        assert_eq!(guid_of_entry(&nothing), None);
    }

    #[test]
    fn reasons() {
        let now = now();
        let mut landmark = Landmark {
            dc: "DC1.lab.test".into(),
            invocation: "inv".into(),
            usn: 90,
            date: now,
            root: "dc=lab,dc=test".into(),
        };
        assert_eq!(
            complete_reason(None, &state(), now, 60, false),
            Some(Reason::First)
        );
        assert_eq!(
            complete_reason(Some(&landmark), &state(), now, 60, false),
            None
        );
        assert_eq!(
            complete_reason(Some(&landmark), &state(), now, 60, true),
            Some(Reason::Schema)
        );
        landmark.usn = 200;
        assert_eq!(
            complete_reason(Some(&landmark), &state(), now, 60, false),
            Some(Reason::Restoration)
        );
        landmark.usn = 90;
        landmark.date = iso_parse("2020-01-01T00:00:00+00:00").unwrap();
        assert_eq!(
            complete_reason(Some(&landmark), &state(), now, 60, false),
            Some(Reason::Old)
        );
        landmark.dc = "dc2.lab.test".into();
        assert_eq!(
            complete_reason(Some(&landmark), &state(), now, 60, false),
            Some(Reason::OtherDc)
        );
    }
}

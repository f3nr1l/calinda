// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Source backed by the local copy (JC.2, ADR 0008, `annuaire.core.cache.SourceCache`), and
//! the trait both sources implement for the Rust interface (R4.4). The copy serves the tree,
//! the lists and the searches whose filter translates into SQL (`sql_filter`): the first page
//! comes out in milliseconds, whatever the size of the domain. At the opening, then every
//! minute and at each refresh, a delta is asked in the background to the DC of the copy
//! (`sync`); the interface hears what changed (`listen`). The DC still serves what the copy
//! does not hold: untranslatable filters, the survey of the activity (`lastLogon` of each
//! DC), the policy. Until there is a copy (first opening), everything goes to the DC.
//! **The copy never serves writes** (ADR 0006).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use annuaire_codecs::time::UtcTime;

use crate::connection::{Connection, Failure};
use crate::dns::{NodePages, Zone};
use crate::membership::{Membership, MembershipError};
use crate::model::DomainPolicy;
use crate::profile::Profile;
use crate::reread::Reread;
use crate::schema::{Schema, SchemaError};
use crate::security::{Nomenclature, SecurityReading};
use crate::session::Entry;
use crate::source::{
    CAPACITY, Cancelled, DirectSource, Item, KEEP_WRITTEN, Notifier, ObjectFlux, Record, Survey,
    SurveyError, containers_filter, contents_filter,
};
use crate::sql_filter::translate;
use crate::store::{
    Changes, Landmark, Store, closure, entry_from_row, escape_like, primary_group_sid,
    read_connection, select_object,
};
use crate::sync::{Phase, Progress, Reason, SyncError, Synchronizer};

/// What a reading gives: its pages, and the date of the copy that served them (None: read on
/// the DC, fresh by construction).
#[derive(Debug, Clone)]
pub struct Pages {
    pub flux: ObjectFlux,
    pub copy_date: Option<UtcTime>,
}

impl Pages {
    fn direct(flux: ObjectFlux) -> Self {
        Self {
            flux,
            copy_date: None,
        }
    }
}

/// Where the local copy stands (`EtatSynchro`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// First copy being made: the readings go to the DC meanwhile.
    Preparing,
    /// Delta running; the copy stays shown.
    Synchronizing,
    /// Copy made anew (other DC, schema…); the old one stays shown, dated.
    Resynchronizing,
    UpToDate,
    Failed,
}

/// State of the local copy, told at each step of a synchronization (`Synchro`).
#[derive(Debug, Clone)]
pub struct SyncState {
    pub phase: SyncPhase,
    /// Date of the copy (None: no copy yet).
    pub date: Option<UtcTime>,
    /// Why a complete resynchronization, None for a delta.
    pub reason: Option<Reason>,
    /// What the applied delta changed (None: nothing).
    pub changes: Option<Changes>,
    /// The copy was just made anew entirely: the display is read again.
    pub complete: bool,
    pub error: Option<Arc<SyncError>>,
}

impl SyncState {
    fn new(phase: SyncPhase, date: Option<UtcTime>, reason: Option<Reason>) -> Self {
        Self {
            phase,
            date,
            reason,
            changes: None,
            complete: false,
            error: None,
        }
    }
}

/// What the interface reads, from the DC or from the local copy (`SourceAnnuaire`).
pub trait Source: Send + Sync + std::fmt::Debug {
    fn profile(&self) -> &Profile;
    /// Binds (blocking) and returns the DN of the domain.
    fn open(&self) -> Result<String, Failure>;
    fn root(&self) -> Option<String>;
    fn containers(&self, dn: &str, advanced: bool, notifier: Notifier) -> Pages;
    fn contents(&self, dn: &str, advanced: bool, notifier: Notifier) -> Pages;
    fn search_under(&self, filter: String, base: Option<&str>, notifier: Notifier) -> Pages;
    /// Survey of the activity on every DC (blocking): always on the DCs.
    fn survey(&self, filter: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError>;
    fn policy(&self) -> Result<DomainPolicy, Failure>;
    /// An object for its sheet (blocking): always on the DC.
    fn record(&self, dn: &str, extra: &[&str]) -> Result<Option<Record>, Failure>;
    /// Last activity of an account on every DC (blocking).
    fn activity(&self, dn: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError>;
    /// Groups of an object (blocking).
    fn groups(&self, dn: &str) -> Result<Membership, MembershipError>;
    /// Direct members of a group.
    fn members(&self, dn: &str, notifier: Notifier) -> Pages;
    /// The schema, read on the DC once per source (blocking).
    fn schema(&self) -> Result<Arc<Schema>, SchemaError>;
    /// Names of the GUIDs and SIDs of the domain, read once per source (blocking).
    fn nomenclature(&self) -> Result<Arc<Nomenclature>, SchemaError>;
    /// The descriptor of an object and what explains it (blocking): always on the DC.
    fn security(&self, dn: &str) -> Result<Option<SecurityReading>, Failure>;
    /// DNS zones of the three places (J3.3), read on the DC (blocking).
    fn dns_zones(&self) -> Result<Vec<Zone>, Failure>;
    /// Names of a zone (`dnsNode`) with their records, read on the DC, never in the local
    /// copy (ADR 0010, 7).
    fn dns_nodes(&self, zone: &Zone, notifier: Notifier) -> NodePages;
    /// Date of the copy, None without a copy.
    fn synced_at(&self) -> Option<UtcTime> {
        None
    }
    /// Asks a delta in the background; nothing without a copy.
    fn synchronize(&self) {}
    /// `listener` hears each state of the copy, from the thread of the synchronization (it
    /// must only relay); the current state at once.
    fn listen(&self, _listener: Box<dyn Fn(SyncState) + Send + Sync>) {}
    /// After a write: the objects read again on the DC of the writes (through `connection`)
    /// hold for their present state (J2.11, ADR 0009). Blocking (the local copy writes them).
    fn note_written(&self, _reread: &Reread, _connection: Arc<Connection>) {}
    /// What a delta of the copy changed, as a reading again of the objects from the copy
    /// (blocking); None without a copy.
    fn delta_reread(&self, _changes: &Changes) -> Option<Reread> {
        None
    }
    fn close(&self);
}

impl Source for DirectSource {
    fn profile(&self) -> &Profile {
        DirectSource::profile(self)
    }
    fn open(&self) -> Result<String, Failure> {
        DirectSource::open(self)
    }
    fn root(&self) -> Option<String> {
        DirectSource::root(self)
    }
    fn containers(&self, dn: &str, advanced: bool, notifier: Notifier) -> Pages {
        Pages::direct(DirectSource::containers(self, dn, advanced, notifier))
    }
    fn contents(&self, dn: &str, advanced: bool, notifier: Notifier) -> Pages {
        Pages::direct(DirectSource::contents(self, dn, advanced, notifier))
    }
    fn search_under(&self, filter: String, base: Option<&str>, notifier: Notifier) -> Pages {
        Pages::direct(DirectSource::search_under(self, filter, base, notifier))
    }
    fn survey(&self, filter: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError> {
        DirectSource::survey(self, filter, cancelled)
    }
    fn policy(&self) -> Result<DomainPolicy, Failure> {
        DirectSource::policy(self)
    }
    fn record(&self, dn: &str, extra: &[&str]) -> Result<Option<Record>, Failure> {
        DirectSource::record(self, dn, extra)
    }
    fn activity(&self, dn: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError> {
        DirectSource::activity(self, dn, cancelled)
    }
    fn groups(&self, dn: &str) -> Result<Membership, MembershipError> {
        DirectSource::groups(self, dn)
    }
    fn members(&self, dn: &str, notifier: Notifier) -> Pages {
        Pages::direct(DirectSource::members(self, dn, notifier))
    }
    fn schema(&self) -> Result<Arc<Schema>, SchemaError> {
        DirectSource::schema(self)
    }
    fn nomenclature(&self) -> Result<Arc<Nomenclature>, SchemaError> {
        DirectSource::nomenclature(self)
    }
    fn security(&self, dn: &str) -> Result<Option<SecurityReading>, Failure> {
        DirectSource::security(self, dn)
    }
    fn dns_zones(&self) -> Result<Vec<Zone>, Failure> {
        DirectSource::dns_zones(self)
    }
    fn dns_nodes(&self, zone: &Zone, notifier: Notifier) -> NodePages {
        DirectSource::dns_nodes(self, zone, notifier)
    }
    fn note_written(&self, reread: &Reread, connection: Arc<Connection>) {
        DirectSource::note_written(self, reread, connection);
    }
    fn close(&self) {
        DirectSource::close(self);
    }
}

type Job = Box<dyn FnOnce(&rusqlite::Connection) + Send>;

/// Thread reading the copy: a SQLite connection of its own, jobs one by one.
#[derive(Debug)]
struct Reader {
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
}

impl Reader {
    fn new(store: &Store) -> Self {
        let (sender, receiver) = mpsc::channel::<Job>();
        let path = store.path.clone();
        std::thread::Builder::new()
            .name("annuaire copie locale".into())
            .spawn(move || {
                let Ok(base) = read_connection(&path) else {
                    return;
                };
                while let Ok(job) = receiver.recv() {
                    job(&base);
                }
            })
            .ok();
        Self {
            jobs: Mutex::new(Some(sender)),
        }
    }

    /// Rows of a query as objects, in pages of the size of a search, into a flux.
    fn query(
        &self,
        sql: String,
        parameters: Vec<rusqlite::types::Value>,
        notifier: Notifier,
    ) -> ObjectFlux {
        self.query_rows(sql, parameters, notifier, entry_from_row)
    }

    /// `query`, each row read by `convert`.
    fn query_rows(
        &self,
        sql: String,
        parameters: Vec<rusqlite::types::Value>,
        notifier: Notifier,
        convert: fn(&rusqlite::Row<'_>) -> rusqlite::Result<Entry>,
    ) -> ObjectFlux {
        let flux = ObjectFlux::new(CAPACITY, Some(notifier));
        let out = flux.clone();
        let job: Job = Box::new(move |base| {
            let items: Result<Vec<Item>, rusqlite::Error> = (|| {
                let mut statement = base.prepare(&sql)?;
                let rows = statement.query_map(rusqlite::params_from_iter(parameters), convert)?;
                let mut items = Vec::new();
                for entry in rows {
                    items.push(Item::from_entry(&entry?));
                }
                Ok(items)
            })();
            match items {
                Ok(items) => {
                    let mut pages: Vec<Vec<Item>> = items
                        .chunks(usize::try_from(crate::source::PAGE_SIZE).unwrap_or(1000))
                        .map(<[Item]>::to_vec)
                        .collect();
                    let last = pages.pop().unwrap_or_default();
                    for page in pages {
                        out.put(page, Some(Box::new(|| {})));
                    }
                    out.put(last, None);
                }
                Err(error) => out.finish(Some(crate::search::SearchError::Ldap {
                    dc: String::new(),
                    error: crate::error::LdapError::new(
                        crate::error::code::LOCAL_ERROR,
                        format!("copie locale : {error}"),
                    ),
                })),
            }
        });
        let sent = self
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|s| s.send(job).is_ok());
        if !sent {
            flux.finish(Some(crate::search::SearchError::Closed));
        }
        flux
    }

    /// Runs `job` on the connection of the reader and waits for its result (`executer`);
    /// None if the reader is closed.
    fn run<T: Send + 'static>(
        &self,
        job: impl FnOnce(&rusqlite::Connection) -> T + Send + 'static,
    ) -> Option<T> {
        let (sender, receiver) = mpsc::channel();
        let job: Job = Box::new(move |base| {
            let _ = sender.send(job(base));
        });
        let sent = self
            .jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|s| s.send(job).is_ok());
        if !sent {
            return None;
        }
        receiver.recv().ok()
    }

    fn close(&self) {
        self.jobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
    }
}

type Listener = Box<dyn Fn(SyncState) + Send + Sync>;

#[derive(Default)]
struct SyncControl {
    running: bool,
    again: bool,
    first: bool,
    closed: bool,
    state: Option<SyncState>,
    listeners: Vec<Arc<Listener>>,
}

/// A source that reads the local copy and keeps it up to date (`SourceCache`).
pub struct CacheSource {
    direct: Arc<DirectSource>,
    store: Arc<Store>,
    reader: Reader,
    landmark: Arc<Mutex<Option<Landmark>>>,
    synchronizer: Arc<Mutex<Synchronizer>>,
    control: Arc<Mutex<SyncControl>>,
    closed: Arc<AtomicBool>,
    /// GUID → instant of the reading again written in the copy (`_relus`).
    reread: Arc<Mutex<HashMap<Vec<u8>, Instant>>>,
}

impl std::fmt::Debug for CacheSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheSource")
            .field("path", &self.store.path)
            .finish_non_exhaustive()
    }
}

/// The source of a profile: the local copy if the profile keeps one and its file opens,
/// else the direct reading (`source_pour`).
pub fn source_for(profile: Profile) -> Arc<dyn Source> {
    let direct = Arc::new(DirectSource::new(profile.clone()));
    if !profile.cache {
        return direct;
    }
    match Store::open(&crate::storage::cache_path(&profile.domain, None)) {
        Ok(store) => Arc::new(CacheSource::new(direct, store)),
        Err(_) => direct,
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl CacheSource {
    pub fn new(direct: Arc<DirectSource>, store: Store) -> Self {
        let landmark = store.landmark();
        let state = landmark
            .as_ref()
            .map(|l| SyncState::new(SyncPhase::UpToDate, Some(l.date), None));
        let profile = direct.profile().clone();
        let reader = Reader::new(&store);
        Self {
            direct,
            store: Arc::new(store),
            reader,
            landmark: Arc::new(Mutex::new(landmark)),
            synchronizer: Arc::new(Mutex::new(Synchronizer::new(profile))),
            control: Arc::new(Mutex::new(SyncControl {
                first: true,
                state,
                ..SyncControl::default()
            })),
            closed: Arc::new(AtomicBool::new(false)),
            reread: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn landmark(&self) -> Option<Landmark> {
        lock(&self.landmark).clone()
    }

    /// The search served by the copy; None if it must go to the DC.
    fn served_by_copy(
        &self,
        base: &str,
        filter: &str,
        scope: crate::session::Scope,
        notifier: Notifier,
    ) -> Result<Pages, Notifier> {
        let Some(landmark) = self.landmark() else {
            return Err(notifier);
        };
        let Ok(condition) = translate(filter) else {
            return Err(notifier);
        };
        let mut sql = format!("{} WHERE {}", select_object(), condition.sql);
        let mut parameters = condition.parameters;
        match scope {
            crate::session::Scope::OneLevel => {
                sql.push_str(" AND o.parent = ?");
                parameters.push(rusqlite::types::Value::Text(base.to_lowercase()));
            }
            crate::session::Scope::Base => {
                sql.push_str(" AND o.dn = ?");
                parameters.push(rusqlite::types::Value::Text(base.to_owned()));
            }
            crate::session::Scope::Subtree => {
                if !base.eq_ignore_ascii_case(&landmark.root) {
                    sql.push_str(" AND (o.dn = ? OR o.dn LIKE ? ESCAPE '\\')");
                    parameters.push(rusqlite::types::Value::Text(base.to_owned()));
                    parameters.push(rusqlite::types::Value::Text(format!(
                        "%,{}",
                        escape_like(base)
                    )));
                }
            }
        }
        Ok(Pages {
            flux: self.reader.query(sql, parameters, notifier),
            copy_date: Some(landmark.date),
        })
    }

    fn publish(control: &Mutex<SyncControl>, state: SyncState) {
        let listeners = {
            let mut c = lock(control);
            if c.closed {
                return;
            }
            c.state = Some(state.clone());
            c.listeners.clone()
        };
        for listener in listeners {
            listener(state.clone());
        }
    }
}

/// Row of `members`: the object, or, for a member outside of the copy (other domain), an
/// entry reduced to the name taken from its DN, as the direct reading (`_membre_depuis_rang`).
fn member_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    if row.get::<_, Option<String>>(0)?.is_some() {
        return entry_from_row(row);
    }
    let dn: String = row.get(row.as_ref().column_count() - 1)?;
    Ok(Entry {
        attributes: vec![(
            "name".into(),
            vec![crate::source::name_from_dn(&dn).into_bytes()],
        )],
        dn,
    })
}

/// Groups of the object `dn` computed on the copy, as `membership::groups_of` on the DC:
/// direct (`memberOf` deduced from the links), primary group (found by its SID), and every
/// group reached from the direct ones and the primary, sorted. None if the object is not in
/// the copy (`stockage.appartenance`).
fn membership_in_copy(
    base: &rusqlite::Connection,
    dn: &str,
) -> rusqlite::Result<Option<Membership>> {
    use rusqlite::OptionalExtension;
    /// GUID, SID and `primaryGroupID` of the object.
    type Account = (Vec<u8>, Option<Vec<u8>>, Option<i64>);
    let row: Option<Account> = base
        .query_row(
            "SELECT guid, sid, groupe_principal FROM objets WHERE dn = ?",
            [dn],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((guid, sid, rid)) = row else {
        return Ok(None);
    };
    let direct: Vec<String> = base
        .prepare("SELECT g.dn FROM liens l JOIN objets g ON g.guid = l.groupe WHERE l.membre = ?")?
        .query_map([&guid], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut primary: Option<String> = None;
    let mut primary_guid: Option<Vec<u8>> = None;
    if let Some(primary_sid) = sid
        .zip(rid)
        .and_then(|(sid, rid)| primary_group_sid(&sid, rid))
    {
        let found: Option<(Vec<u8>, String)> = base
            .query_row(
                "SELECT guid, dn FROM objets \
                 WHERE sid = ? AND (' ' || classes || ' ') LIKE '% group %'",
                [&primary_sid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((g, d)) = found {
            primary_guid = Some(g);
            primary = Some(d);
        }
    }
    // Start: the direct groups and the primary group; then those that contain them.
    let start = "SELECT groupe FROM liens WHERE membre = ?1 UNION SELECT ?2";
    let sql = format!(
        "SELECT o.dn FROM objets o WHERE o.guid IN (SELECT groupe FROM liens WHERE membre = ?1) \
         OR o.guid = ?2 OR o.guid IN ({})",
        closure(start, false)
    );
    let mut all: Vec<String> = base
        .prepare(&sql)?
        .query_map(rusqlite::params![guid, primary_guid], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    all.sort_by_key(|d| d.to_lowercase());
    Ok(Some(Membership {
        direct,
        primary,
        recursive: Some(all),
    }))
}

impl Source for CacheSource {
    fn profile(&self) -> &Profile {
        self.direct.profile()
    }

    /// Opens the direct reading (ticket, DC reachable), then starts the first delta in the
    /// background, with the search of the deletions.
    fn open(&self) -> Result<String, Failure> {
        let root = self.direct.open()?;
        self.synchronize();
        Ok(root)
    }

    fn root(&self) -> Option<String> {
        self.direct
            .root()
            .or_else(|| self.landmark().map(|l| l.root))
    }

    fn containers(&self, dn: &str, advanced: bool, notifier: Notifier) -> Pages {
        match self.served_by_copy(
            dn,
            &containers_filter(advanced),
            crate::session::Scope::OneLevel,
            notifier,
        ) {
            Ok(pages) => pages,
            Err(notifier) => Pages::direct(self.direct.containers(dn, advanced, notifier)),
        }
    }

    fn contents(&self, dn: &str, advanced: bool, notifier: Notifier) -> Pages {
        match self.served_by_copy(
            dn,
            &contents_filter(advanced),
            crate::session::Scope::OneLevel,
            notifier,
        ) {
            Ok(pages) => pages,
            Err(notifier) => Pages::direct(self.direct.contents(dn, advanced, notifier)),
        }
    }

    fn search_under(&self, filter: String, base: Option<&str>, notifier: Notifier) -> Pages {
        let root = base
            .map(str::to_owned)
            .or_else(|| self.root())
            .unwrap_or_default();
        match self.served_by_copy(&root, &filter, crate::session::Scope::Subtree, notifier) {
            Ok(pages) => pages,
            Err(notifier) => Pages::direct(self.direct.search_under(filter, base, notifier)),
        }
    }

    fn survey(&self, filter: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError> {
        self.direct.survey(filter, cancelled)
    }

    fn policy(&self) -> Result<DomainPolicy, Failure> {
        self.direct.policy()
    }

    /// The sheet and the activity are read on the DC; the groups and the members are
    /// computed on the copy (`liens`), as in `cache.py`.
    fn record(&self, dn: &str, extra: &[&str]) -> Result<Option<Record>, Failure> {
        self.direct.record(dn, extra)
    }

    fn activity(&self, dn: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError> {
        self.direct.activity(dn, cancelled)
    }

    /// Computed on the copy (`stockage.appartenance`), same result as the direct reading;
    /// the DC if the object is not there, or if it was written (added to a group, for
    /// example) and is still read on the DC of the writes (`groupes`).
    fn groups(&self, dn: &str) -> Result<Membership, MembershipError> {
        if self.landmark().is_none() || self.direct.read_elsewhere(dn) {
            return self.direct.groups(dn);
        }
        let owned = dn.to_owned();
        match self
            .reader
            .run(move |base| membership_in_copy(base, &owned))
        {
            Some(Ok(Some(membership))) => Ok(membership),
            _ => self.direct.groups(dn),
        }
    }

    /// The links of the copy; the DC without a copy, for an object written meanwhile, or a
    /// group outside of the copy (`membres`). A member outside of the copy (other domain)
    /// comes named after its DN, as in the direct reading.
    fn members(&self, dn: &str, notifier: Notifier) -> Pages {
        let Some(landmark) = self.landmark() else {
            return Pages::direct(self.direct.members(dn, notifier));
        };
        let owned = dn.to_owned();
        let in_copy = !self.direct.read_elsewhere(dn)
            && self
                .reader
                .run(move |base| {
                    base.query_row("SELECT 1 FROM objets WHERE dn = ?", [&owned], |_| Ok(()))
                        .is_ok()
                })
                .unwrap_or(false);
        if !in_copy {
            return Pages::direct(self.direct.members(dn, notifier));
        }
        let sql = select_object().replace(
            " FROM objets o",
            ", l.dn FROM liens l JOIN objets g ON g.guid = l.groupe \
             LEFT JOIN objets o ON o.guid = l.membre WHERE g.dn = ?",
        );
        Pages {
            flux: self.reader.query_rows(
                sql,
                vec![rusqlite::types::Value::Text(dn.to_owned())],
                notifier,
                member_from_row,
            ),
            copy_date: Some(landmark.date),
        }
    }

    /// Read on the DC, kept in memory: the schema does not go into the copy.
    fn schema(&self) -> Result<Arc<Schema>, SchemaError> {
        self.direct.schema()
    }

    /// Read on the DC, as the descriptors: they do not go into the copy (ADR 0011).
    fn nomenclature(&self) -> Result<Arc<Nomenclature>, SchemaError> {
        self.direct.nomenclature()
    }

    fn security(&self, dn: &str) -> Result<Option<SecurityReading>, Failure> {
        self.direct.security(dn)
    }

    /// The DNS is read on the DC (ADR 0010, 7).
    fn dns_zones(&self) -> Result<Vec<Zone>, Failure> {
        self.direct.dns_zones()
    }

    fn dns_nodes(&self, zone: &Zone, notifier: Notifier) -> NodePages {
        self.direct.dns_nodes(zone, notifier)
    }

    fn synced_at(&self) -> Option<UtcTime> {
        self.landmark().map(|l| l.date)
    }

    /// A delta in the background (or a complete resynchronization); one at a time: a call
    /// during a synchronization makes it start another at its end.
    fn synchronize(&self) {
        let first = {
            let mut c = lock(&self.control);
            if c.closed {
                return;
            }
            if c.running {
                c.again = true;
                return;
            }
            c.running = true;
            std::mem::replace(&mut c.first, false)
        };
        let (store, landmark, synchronizer, control, closed, reread) = (
            self.store.clone(),
            self.landmark.clone(),
            self.synchronizer.clone(),
            self.control.clone(),
            self.closed.clone(),
            self.reread.clone(),
        );
        std::thread::Builder::new()
            .name("annuaire synchronisation".into())
            .spawn(move || {
                let mut first = first;
                loop {
                    let date = || lock(&landmark).as_ref().map(|l| l.date);
                    let mut report = |progress: Progress| {
                        if progress.phase != Phase::Applied {
                            let phase = if date().is_none() {
                                SyncPhase::Preparing
                            } else if progress.phase == Phase::Complete {
                                SyncPhase::Resynchronizing
                            } else {
                                SyncPhase::Synchronizing
                            };
                            let state = SyncState::new(phase, date(), progress.reason);
                            CacheSource::publish(&control, state);
                            return;
                        }
                        *lock(&landmark) = progress.landmark.clone();
                        let changes = progress.changes.unwrap_or_default();
                        let mut state =
                            SyncState::new(SyncPhase::UpToDate, date(), progress.reason);
                        state.complete = changes.complete;
                        state.changes = (!changes.is_empty()).then_some(changes);
                        CacheSource::publish(&control, state);
                    };
                    // Objects read again after a write since the start of the reading on the
                    // DC: the delta read before must not bring them back to the state before
                    // (`_epargnes`).
                    let spared = |start: Instant| -> HashSet<Vec<u8>> {
                        let mut kept = lock(&reread);
                        kept.retain(|_, at| at.elapsed() <= KEEP_WRITTEN);
                        kept.iter()
                            .filter(|(_, at)| **at >= start)
                            .map(|(g, _)| g.clone())
                            .collect()
                    };
                    let result =
                        lock(&synchronizer).synchronize(&store, &mut report, first, &spared);
                    let failed = result.is_err();
                    if let Err(error) = result {
                        let mut state = SyncState::new(SyncPhase::Failed, date(), None);
                        state.error = Some(Arc::new(error));
                        CacheSource::publish(&control, state);
                    }
                    let mut c = lock(&control);
                    if !c.again || c.closed || closed.load(Ordering::Relaxed) || failed {
                        c.again = false;
                        c.running = false;
                        return;
                    }
                    c.again = false;
                    first = false;
                }
            })
            .ok();
    }

    fn listen(&self, listener: Box<dyn Fn(SyncState) + Send + Sync>) {
        let listener = Arc::new(listener);
        let state = {
            let mut c = lock(&self.control);
            c.listeners.push(listener.clone());
            c.state.clone()
        };
        if let Some(state) = state {
            listener(state);
        }
    }

    /// `SourceDirecte.relire_ecrits`, then the reading again written in the copy (one
    /// transaction): the lists read afterwards are up to date (`relire_ecrits`).
    fn note_written(&self, reread: &Reread, connection: Arc<Connection>) {
        self.direct.note_written(reread, connection);
        // On failure, the copy catches up at the delta.
        if let Ok(written) = self.store.write_reread(&reread.entries) {
            let now = Instant::now();
            lock(&self.reread).extend(written.into_iter().map(|g| (g, now)));
        }
        let gone: Vec<String> = reread
            .absent
            .iter()
            .filter(|dn| !reread.moved.contains_key(&crate::reread::key(dn)))
            .cloned()
            .collect();
        let _ = self.store.remove_dns(&gone);
    }

    /// The objects a delta changed, read from the copy (`_appliquer_delta`, whose
    /// `Relecture` the Python synchronization builds).
    fn delta_reread(&self, changes: &Changes) -> Option<Reread> {
        let base = read_connection(&self.store.path).ok()?;
        let mut objects = HashMap::new();
        let mut entries = Vec::new();
        let mut moved = HashMap::new();
        let mut appeared = HashSet::new();
        let mut forms = HashSet::new();
        let mut absent = Vec::new();
        let sql = format!("{} WHERE o.guid = ?", select_object());
        for (guid, (before, after)) in &changes.objects {
            if let Some(before) = before {
                forms.insert(before.to_lowercase());
            }
            match (before, after) {
                (Some(b), Some(a)) if crate::reread::key(b) != crate::reread::key(a) => {
                    moved.insert(crate::reread::key(b), a.clone());
                    objects.insert(crate::reread::key(b), None);
                    appeared.insert(crate::reread::key(a));
                }
                (None, Some(a)) => {
                    appeared.insert(crate::reread::key(a));
                }
                (Some(b), None) => {
                    objects.insert(crate::reread::key(b), None);
                    absent.push(b.clone());
                }
                _ => {}
            }
            let Some(after) = after else { continue };
            forms.insert(after.to_lowercase());
            let entry = base
                .query_row(&sql, rusqlite::params![guid], entry_from_row)
                .ok();
            if let Some(entry) = entry {
                objects.insert(crate::reread::key(after), Some(Item::from_entry(&entry)));
                entries.push(entry);
            }
        }
        Some(Reread {
            dc: String::new(),
            date: std::time::SystemTime::now(),
            objects,
            entries,
            absent,
            moved,
            appeared,
            forms,
        })
    }

    fn close(&self) {
        {
            let mut c = lock(&self.control);
            c.closed = true;
            c.listeners.clear();
        }
        self.closed.store(true, Ordering::Relaxed);
        lock(&self.synchronizer).close();
        self.direct.close();
        self.reader.close();
    }
}

#[cfg(test)]
mod tests {
    use rusqlite::types::Value;

    use super::*;
    use crate::store::{COLUMNS, Line, now};

    fn dns(pages: &Pages) -> Vec<String> {
        let mut dns = Vec::new();
        while let Some(page) = pages.flux.next_page() {
            dns.extend(page.unwrap().iter().map(|i| i.dn().to_owned()));
        }
        dns.sort();
        dns
    }

    #[test]
    fn served_by_the_copy() {
        let dir = std::env::temp_dir().join(format!("annuaire-cache-{}", std::process::id()));
        let store = Store::open(&dir.join("lab.test.sqlite")).unwrap();
        let line = |n: u8, dn: &str, classes: &str| Line {
            guid: vec![n; 16],
            dn: dn.into(),
            classes: classes.into(),
            values: vec![Value::Null; COLUMNS.len()],
            members: None,
            deleted: false,
        };
        let landmark = Landmark {
            dc: "dc1.lab.test".into(),
            invocation: "x".into(),
            usn: 10,
            date: now(),
            root: "DC=lab,DC=test".into(),
        };
        let lines = [
            line(1, "OU=A,DC=lab,DC=test", "top organizationalUnit"),
            line(
                2,
                "CN=u,OU=A,DC=lab,DC=test",
                "top person organizationalPerson user",
            ),
            line(
                3,
                "CN=v,DC=lab,DC=test",
                "top person organizationalPerson user",
            ),
            // g holds u and a member outside of the copy; h holds g.
            Line {
                members: Some(vec![
                    (vec![2; 16], "CN=u,OU=A,DC=lab,DC=test".into()),
                    (vec![9; 16], "CN=x,DC=other,DC=test".into()),
                ]),
                ..line(4, "CN=g,OU=A,DC=lab,DC=test", "top group")
            },
            Line {
                members: Some(vec![(vec![4; 16], "CN=g,OU=A,DC=lab,DC=test".into())]),
                ..line(5, "CN=h,DC=lab,DC=test", "top group")
            },
        ];
        store
            .apply(&lines, &landmark, true, &HashSet::new())
            .unwrap();
        let direct = Arc::new(DirectSource::new(Profile::new("lab.test")));
        let source = CacheSource::new(direct, store);
        assert_eq!(source.synced_at(), Some(landmark.date));
        let notifier = || -> Notifier { Box::new(|| {}) };

        let containers = source.containers("DC=lab,DC=test", false, notifier());
        assert_eq!(containers.copy_date, Some(landmark.date));
        assert_eq!(dns(&containers), ["OU=A,DC=lab,DC=test"]);
        let contents = source.contents("OU=A,DC=lab,DC=test", false, notifier());
        assert_eq!(
            dns(&contents),
            ["CN=g,OU=A,DC=lab,DC=test", "CN=u,OU=A,DC=lab,DC=test"]
        );
        let under = source.search_under(
            "(objectClass=user)".into(),
            Some("OU=A,DC=lab,DC=test"),
            notifier(),
        );
        assert_eq!(dns(&under), ["CN=u,OU=A,DC=lab,DC=test"]);
        let everywhere = source.search_under(
            "(objectClass=user)".into(),
            Some("DC=lab,DC=test"),
            notifier(),
        );
        assert_eq!(
            dns(&everywhere),
            ["CN=u,OU=A,DC=lab,DC=test", "CN=v,DC=lab,DC=test"]
        );

        // Groups and members computed on the copy (`test_groupes_comme_le_dc`).
        let groups = source.groups("CN=u,OU=A,DC=lab,DC=test").unwrap();
        assert_eq!(groups.direct, ["CN=g,OU=A,DC=lab,DC=test"]);
        assert_eq!(groups.primary, None);
        assert_eq!(
            groups.recursive.unwrap(),
            ["CN=g,OU=A,DC=lab,DC=test", "CN=h,DC=lab,DC=test"]
        );
        let members = source.members("CN=g,OU=A,DC=lab,DC=test", notifier());
        assert_eq!(members.copy_date, Some(landmark.date));
        assert_eq!(
            dns(&members),
            ["CN=u,OU=A,DC=lab,DC=test", "CN=x,DC=other,DC=test"]
        );

        // The first state heard is the current one.
        let heard = Arc::new(Mutex::new(Vec::new()));
        let into = heard.clone();
        source.listen(Box::new(move |s| lock(&into).push(s.phase)));
        assert_eq!(*lock(&heard), [SyncPhase::UpToDate]);
        source.close();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

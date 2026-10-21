// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! What the interface reads, without knowing where it comes from (`annuaire.core.source`),
//! for the Rust interface: the direct reading on the DC (`SourceDirecte`, R4.3), the sheet
//! of an object, its groups, the members of a group and the activity of an account (R4.5),
//! and, after a write, the objects written held for the present state until the DC of reading
//! has them (R4.6, J2.11, ADR 0009). The local copy is in `cache` (R4.4).
//!
//! The pages of objects are decoded on the thread of the connection, before the interface
//! takes them: in Rust, nothing makes the decoding cheaper on the interface thread (ADR 0007
//! and `vue/alimentation.py` said so in advance).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use annuaire_codecs::Guid;
use annuaire_codecs::integer::{self, Width};

use crate::connection::{Connection, DnsResolver, Failure, ResolveError, Resolver};
use crate::dn;
use crate::ldap3_session::Ldap3Dialer;
use crate::membership::{self, Membership, MembershipError};
use crate::model::{self, DomainPolicy, LastActivity, Object, compute_activity};
use crate::profile::{Delays, Profile};
use crate::queries;
use crate::reread::{Reread, key, parent_key};
use crate::schema::{self, Schema, SchemaError};
use crate::search::{self, Flux, Next, Pages, Search, SearchError};
use crate::security::{self, Nomenclature, SecurityReading};
use crate::session::{Entry, Scope};

/// Attributes read for the tree, the lists and the search (`ATTRIBUTS_AFFICHAGE`). Never
/// `member` nor `memberOf`, which can be huge: the sheet of an object reads them apart.
pub const DISPLAY_ATTRIBUTES: [&str; 11] = [
    "objectClass",
    "name",
    "description",
    "whenChanged",
    "sAMAccountName",
    "userPrincipalName",
    "userAccountControl",
    "lastLogonTimestamp",
    "displayName",
    "mail",
    "groupType",
];

/// Classes shown in the tree.
pub const CONTAINER_CLASSES: [&str; 4] = [
    "organizationalUnit",
    "container",
    "builtinDomain",
    "lostAndFound",
];

/// Size of a page of a search (`TAILLE_PAGE`).
pub const PAGE_SIZE: i32 = 1000;

/// Pages kept ahead of the consumer (`Flux(capacite=2)`).
pub const CAPACITY: usize = 2;

const NOT_ADVANCED: &str = "(!(showInAdvancedViewOnly=TRUE))";

/// The containers, without the objects reserved to the advanced mode unless asked
/// (`filtre_conteneurs`).
pub fn containers_filter(advanced: bool) -> String {
    let classes: String = CONTAINER_CLASSES
        .iter()
        .map(|c| format!("(objectClass={c})"))
        .collect();
    let containers = format!("(|{classes})");
    if advanced {
        containers
    } else {
        format!("(&{containers}{NOT_ADVANCED})")
    }
}

/// Every object, same rule for those marked `showInAdvancedViewOnly` (`filtre_contenu`).
pub fn contents_filter(advanced: bool) -> String {
    if advanced {
        "(objectClass=*)".into()
    } else {
        NOT_ADVANCED.into()
    }
}

/// Value of the first RDN, or the whole DN if it cannot be read (`nom_depuis_dn`).
pub fn name_from_dn(dn: &str) -> String {
    match dn::split(dn) {
        Ok(components) => components
            .first()
            .map_or_else(|| dn.to_owned(), |c| c.value.clone()),
        Err(_) => dn.to_owned(),
    }
}

/// An object of a list: decoded, or reported as unreadable rather than stopping the list
/// (`ObjetIllisible`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Object(Box<Object>),
    Unreadable {
        dn: String,
        name: String,
        error: String,
    },
}

impl Item {
    /// `objet_ou_illisible`.
    pub fn from_entry(entry: &Entry) -> Self {
        match model::object_from_entry(entry) {
            Ok(object) => Self::Object(Box::new(object)),
            Err(error) => Self::Unreadable {
                dn: entry.dn.clone(),
                name: name_from_dn(&entry.dn),
                error: error.to_string(),
            },
        }
    }

    pub fn dn(&self) -> &str {
        match self {
            Self::Object(object) => &object.common().dn,
            Self::Unreadable { dn, .. } => dn,
        }
    }
}

/// An object read for its sheet: the object of the model and the raw attributes received
/// (`Fiche`).
#[derive(Debug, Clone)]
pub struct Record {
    pub item: Item,
    /// As received (names in the case of the server): those of the model and those asked.
    pub entry: Entry,
    pub date: SystemTime,
}

impl Record {
    /// Values of an attribute, name without case; empty if absent.
    pub fn values(&self, attribute: &str) -> &[Vec<u8>] {
        self.entry.values(attribute)
    }

    /// First value as UTF-8 text (invalid bytes replaced), empty if absent.
    pub fn text(&self, attribute: &str) -> String {
        self.values(attribute)
            .first()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default()
    }
}

/// What `record` always reads: the whole model, except `member` (read by ranges, `members`)
/// (`ATTRIBUTS_FICHE`).
pub fn record_attributes() -> Vec<&'static str> {
    model::attributes()
        .into_iter()
        .filter(|&a| a != "member")
        .collect()
}

/// Members of a group read again per search (filter `|` on `distinguishedName`): Samba
/// evaluates it in more than linear time; for 5,000 members, 1.9 s by batches of 25, 2.9 s
/// by 100, 16 s by 1,000 (`LOT_MEMBRES`).
pub const MEMBER_BATCH: usize = 25;

/// Entries of the members `dns`, in their order; a DN not found gives an entry reduced to
/// its name (member outside of the domain, or phantom being replicated) (`_lot_membres`).
fn member_batch(
    connection: &Connection,
    base: &str,
    dns: &[String],
) -> Result<Vec<Item>, SearchError> {
    let filters: Vec<String> = dns
        .iter()
        .filter_map(|dn| search::eq("distinguishedName", search::Value::Text(dn)).ok())
        .collect();
    let attributes = DISPLAY_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect();
    let found: HashMap<String, Entry> = membership::search_all(
        connection,
        base,
        search::or(&filters).unwrap_or_default(),
        attributes,
    )?
    .into_iter()
    .map(|e| (e.dn.to_lowercase(), e))
    .collect();
    Ok(dns
        .iter()
        .map(|dn| match found.get(&dn.to_lowercase()) {
            Some(entry) => Item::from_entry(entry),
            None => Item::from_entry(&Entry {
                dn: dn.clone(),
                attributes: vec![("name".into(), vec![name_from_dn(dn).into_bytes()])],
            }),
        })
        .collect())
}

/// Pages of objects, decoded as they arrive.
pub type ObjectFlux = Flux<Vec<Item>, SearchError>;

struct ObjectPages(ObjectFlux);

// --- Objects written (J2.11) ----------------------------------------------------------------

/// Longest time a written object stays read on the DC of the writes and corrects the lists of
/// the DC of reading (`GARDE_ECRITS`). It ends sooner as soon as the DC of reading gives the
/// object with a `whenChanged` at least as recent (replication arrived, or a more recent write
/// made elsewhere). In a site, replication takes a few seconds; between sites, more.
pub const KEEP_WRITTEN: Duration = Duration::from_secs(30 * 60);

impl Item {
    fn modified(&self) -> Option<annuaire_codecs::time::UtcTime> {
        match self {
            Self::Object(o) => o.common().modified,
            Self::Unreadable { .. } => None,
        }
    }

    fn is_container(&self) -> bool {
        match self {
            Self::Object(o) => o
                .common()
                .classes
                .iter()
                .any(|c| CONTAINER_CLASSES.iter().any(|k| k.eq_ignore_ascii_case(c))),
            Self::Unreadable { .. } => false,
        }
    }
}

/// True if the object read on the DC of reading is at least as recent as the one read again on
/// the DC of the writes. `whenChanged` is not replicated: each DC sets it when it applies the
/// change, its own or the one it receives, hence after the original write (`_rattrape`).
fn caught_up(read: &Item, written: &Item) -> bool {
    matches!((read.modified(), written.modified()), (Some(r), Some(w)) if r >= w)
}

/// Objects written not yet replicated, by key of DN (`_ecrits`, `_deplaces`, `_apparus`).
#[derive(Debug, Default)]
struct Written {
    objects: HashMap<String, (Instant, Option<Item>)>,
    moved: HashMap<String, (String, Instant)>,
    appeared: HashMap<String, Instant>,
    /// Connection to the DC of the writes, that reads the written objects meanwhile.
    connection: Option<Arc<Connection>>,
}

impl Written {
    /// Forgets the writes older than `KEEP_WRITTEN` (`_purger`).
    fn purge(&mut self) {
        let now = Instant::now();
        let old = |since: &Instant| now.duration_since(*since) > KEEP_WRITTEN;
        self.objects.retain(|_, (since, _)| !old(since));
        self.moved.retain(|_, (_, since)| !old(since));
        self.appeared.retain(|_, since| !old(since));
    }
}

type Keep = fn(&Item) -> bool;

/// Corrects a list of the DC of reading by the objects written not yet replicated
/// (`_Correction`). Built when the reading starts, on a snapshot of the objects written.
/// `parent`: list of a container (one level), to which the objects created or arrived that
/// are not there yet are added; None for a search, where whether a new object satisfies the
/// filter is unknown.
struct Correction {
    written: HashMap<String, Option<Item>>,
    moved: HashMap<String, String>,
    appeared: HashSet<String>,
    parent: Option<String>,
    keep: Keep,
    seen: HashSet<String>,
    state: Arc<Mutex<Written>>,
}

impl Correction {
    /// The object to show in place of `item`; None to drop it (`corriger`).
    fn correct(&mut self, item: Item) -> Option<Item> {
        let mut k = key(item.dn());
        let new = self.moved.get(&k).cloned();
        if let Some(new) = &new {
            if self.parent.is_some() {
                return None; // gone: it appears in the list of its new container
            }
            k = key(new);
            if !self.written.contains_key(&k) {
                return Some(item);
            }
        }
        let Some(written) = self.written.get(&k) else {
            self.seen.insert(k);
            return Some(item);
        };
        let Some(written) = written.clone() else {
            return None; // deleted
        };
        self.seen.insert(k.clone());
        if new.is_none() && caught_up(&item, &written) {
            // The DC of reading shows the object up to date: it is read there again.
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            if state
                .objects
                .get(&k)
                .is_some_and(|(_, o)| o.as_ref() == Some(&written))
            {
                state.objects.remove(&k);
                state.appeared.remove(&k);
            }
            return Some(item);
        }
        Some(written)
    }

    /// Objects created or arrived in the container, that the DC of reading did not give.
    /// After every page (`ajouts`).
    fn additions(&mut self) -> Vec<Item> {
        let Some(parent) = self.parent.clone() else {
            return Vec::new();
        };
        let mut keys: Vec<&String> = self.appeared.iter().collect();
        keys.sort();
        let mut out = Vec::new();
        for k in keys {
            if let Some(Some(item)) = self.written.get(k)
                && !self.seen.contains(k)
                && parent_key(item.dn()) == parent
                && (self.keep)(item)
            {
                self.seen.insert(k.clone());
                out.push(item.clone());
            }
        }
        out
    }
}

/// `ObjectPages` with a `Correction` (`FluxObjets` with `_Correction`): the objects written
/// not yet replicated replace those of the DC of reading, and the objects added to a
/// container come in the last page.
struct CorrectedPages {
    flux: ObjectFlux,
    correction: Mutex<Correction>,
    added: Mutex<bool>,
}

impl CorrectedPages {
    fn additions(&self) -> Option<Vec<Item>> {
        let mut added = self.added.lock().unwrap_or_else(PoisonError::into_inner);
        if *added {
            return None;
        }
        *added = true;
        Some(
            self.correction
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .additions(),
        )
    }
}

impl Pages for CorrectedPages {
    fn deliver(&self, entries: Vec<Entry>, next: Option<Next>) {
        let mut items: Vec<Item> = {
            let mut correction = self
                .correction
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            entries
                .iter()
                .map(Item::from_entry)
                .filter_map(|i| correction.correct(i))
                .collect()
        };
        if next.is_none() {
            items.extend(self.additions().unwrap_or_default());
        }
        self.flux.put(items, next);
    }
    fn fail(&self, error: SearchError) {
        self.flux.finish(Some(error));
    }
    fn finish(&self) {
        if let Some(additions) = self.additions().filter(|a| !a.is_empty()) {
            self.flux.put(additions, None);
        }
        self.flux.finish(None);
    }
    fn cancelled(&self) -> bool {
        self.flux.cancelled()
    }
}

impl Pages for ObjectPages {
    fn deliver(&self, entries: Vec<Entry>, next: Option<Next>) {
        self.0
            .put(entries.iter().map(Item::from_entry).collect(), next);
    }
    fn fail(&self, error: SearchError) {
        self.0.finish(Some(error));
    }
    fn finish(&self) {
        self.0.finish(None);
    }
    fn cancelled(&self) -> bool {
        self.0.cancelled()
    }
}

/// A DC that could not be read during a survey of activity (`EchecDC`).
#[derive(Debug, Clone)]
pub struct DcFailure {
    pub dc: String,
    pub error: SearchError,
}

/// Result of a survey (`ReleveActivite`): the accounts and their last activity on every DC.
#[derive(Debug, Clone)]
pub struct Survey {
    pub date: SystemTime,
    /// Objects read on the DC of the main connection, in the order received.
    pub objects: Vec<Object>,
    /// By DN; only for accounts (users, computers).
    pub activities: HashMap<String, LastActivity>,
    /// `lastLogon` of each account, by DN then by DC (the detail of a sheet).
    pub last_logons: HashMap<String, BTreeMap<String, i64>>,
    /// DCs whose `lastLogon` was read, the main one first.
    pub dcs: Vec<String>,
    pub failures: Vec<DcFailure>,
}

impl Survey {
    /// The accounts with their activity (`comptes`).
    pub fn accounts(&self) -> Vec<queries::Surveyed> {
        self.objects
            .iter()
            .filter(|o| o.account().is_some())
            .filter_map(|o| {
                let activity = self.activities.get(&o.common().dn)?.clone();
                Some((o.clone(), activity))
            })
            .collect()
    }
}

/// Why a survey did not end.
#[derive(Debug, Clone)]
pub enum SurveyError {
    Failure(Failure),
    Search(SearchError),
    Cancelled,
}

/// `lastLogon` of each account of `objects`, by DC (`last_logons_par_compte`): the main DC
/// from the objects themselves, the others by `objectGUID` (the DN may differ during the
/// replication of a rename, not the GUID).
pub fn last_logons_by_account(
    objects: &[Object],
    main_dc: &str,
    read: &BTreeMap<String, HashMap<Guid, i64>>,
) -> HashMap<String, BTreeMap<String, i64>> {
    let mut by_account = HashMap::new();
    for object in objects {
        let Some(account) = object.account() else {
            continue;
        };
        let mut logons = BTreeMap::new();
        if let Some(n) = account.last_logon {
            logons.insert(main_dc.to_owned(), n);
        }
        if let Some(guid) = object.common().guid {
            for (dc, values) in read {
                if let Some(&n) = values.get(&guid) {
                    logons.insert(dc.clone(), n);
                }
            }
        }
        by_account.insert(object.common().dn.clone(), logons);
    }
    by_account
}

/// Last activity of each account (`combiner`): `lastLogonTimestamp`, `lastLogon` on every
/// DC, and `pwdLastSet` for a computer.
pub fn combine_activity(
    objects: &[Object],
    main_dc: &str,
    read: &BTreeMap<String, HashMap<Guid, i64>>,
) -> HashMap<String, LastActivity> {
    let by_account = last_logons_by_account(objects, main_dc, read);
    let mut activities = HashMap::new();
    for object in objects {
        let Some(account) = object.account() else {
            continue;
        };
        let pwd = matches!(object, Object::Computer { .. })
            .then_some(account.pwd_last_set)
            .flatten();
        let dn = &object.common().dn;
        let empty = BTreeMap::new();
        let logons = by_account.get(dn).unwrap_or(&empty);
        activities.insert(
            dn.clone(),
            compute_activity(account.last_logon_timestamp, logons, pwd),
        );
    }
    activities
}

/// Tells a long reading to stop at its next page (`Annulation`).
pub type Cancelled = dyn Fn() -> bool + Sync;

/// A resolver that announces nothing: the connection only knows its preferred DC (no
/// failover: `lastLogon` is proper to each DC, `ouvrir_sur`).
#[derive(Debug, Clone, Copy)]
struct OnlyPreferred;

impl Resolver for OnlyPreferred {
    fn dcs(&self, _: &str) -> Result<Vec<String>, ResolveError> {
        Ok(Vec::new())
    }
    fn pdc(&self, _: &str) -> Result<Option<String>, ResolveError> {
        Ok(None)
    }
}

/// A paged search read page by page on the calling thread (blocking: off the interface);
/// `on_page` returns false to stop (the cursor is freed).
pub fn search_blocking(
    connection: &Connection,
    search: Search,
    on_page: &mut dyn FnMut(Vec<Entry>) -> bool,
) -> Result<(), SearchError> {
    let flux: Flux<Vec<Entry>, SearchError> = Flux::new(CAPACITY, None);
    search::search(&connection.submitter(), search, Arc::new(flux.clone()));
    while let Some(page) = flux.next_page() {
        match page {
            Ok(page) => {
                if !on_page(page) {
                    flux.cancel();
                    return Ok(());
                }
            }
            Err(error) => return Err((*error).clone()),
        }
    }
    Ok(())
}

/// A connection to the only DC named, or to the DCs of the profile (None): `ouvrir_pour`.
pub fn connection_to(profile: &Profile, dc: Option<&str>) -> Connection {
    let delays = Delays::default();
    let mut profile = profile.clone();
    let resolver: Box<dyn Resolver> = match dc {
        Some(dc) => {
            profile.preferred_dc = Some(dc.to_owned());
            Box::new(OnlyPreferred)
        }
        None => Box::new(DnsResolver),
    };
    Connection::new(
        profile.clone(),
        delays,
        false,
        Box::new(Ldap3Dialer { profile, delays }),
        resolver,
    )
}

/// The connection of the writes and of the group policies: the PDC emulator first, then the
/// other DCs (`Connexion(profil, vers_pdc=True)`, ADR 0012).
pub fn pdc_connection(profile: &Profile) -> Connection {
    let delays = Delays::default();
    Connection::new(
        profile.clone(),
        delays,
        true,
        Box::new(Ldap3Dialer {
            profile: profile.clone(),
            delays,
        }),
        Box::new(DnsResolver),
    )
}

/// A notifier of a flux: called on the thread of the connection, it must only relay.
pub type Notifier = Box<dyn Fn() + Send + Sync>;

/// Reading on a DC of the domain (`SourceDirecte`).
#[derive(Debug)]
pub struct DirectSource {
    profile: Profile,
    connection: Arc<Connection>,
    root: Mutex<Option<String>>,
    /// Read once per source, kept in memory (`schema`).
    schema: Mutex<Option<Arc<Schema>>>,
    /// Names of the GUIDs and SIDs of the domain, read once per source (ADR 0011).
    nomenclature: Mutex<Option<Arc<Nomenclature>>>,
    /// Objects written not yet replicated (J2.11).
    written: Arc<Mutex<Written>>,
}

impl DirectSource {
    pub fn new(profile: Profile) -> Self {
        let delays = Delays::default();
        let dialer = Ldap3Dialer {
            profile: profile.clone(),
            delays,
        };
        let connection = Connection::new(
            profile.clone(),
            delays,
            false,
            Box::new(dialer),
            Box::new(DnsResolver),
        );
        Self::with_connection(profile, connection)
    }

    /// On a given connection (tests: fake DCs).
    pub fn with_connection(profile: Profile, connection: Connection) -> Self {
        Self {
            profile,
            connection: Arc::new(connection),
            root: Mutex::new(None),
            schema: Mutex::new(None),
            nomenclature: Mutex::new(None),
            written: Arc::new(Mutex::new(Written::default())),
        }
    }

    // --- Objects written (J2.11) ------------------------------------------------------------

    /// After a write: the objects read again on the DC of the writes (through `connection`)
    /// are the present state of these objects, until the DC of reading has them; their reads
    /// go to that DC meanwhile (`relire_ecrits`, the reading itself being done by the caller
    /// on the write connection).
    pub fn note_written(&self, reread: &Reread, connection: Arc<Connection>) {
        let since = Instant::now();
        let mut written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        written.purge();
        for (k, item) in &reread.objects {
            written.objects.insert(k.clone(), (since, item.clone()));
        }
        for (k, new) in &reread.moved {
            written.moved.insert(k.clone(), (new.clone(), since));
        }
        for k in &reread.appeared {
            written.appeared.insert(k.clone(), since);
        }
        written.connection = Some(connection);
    }

    /// True if `dn` was written and is still read on the DC of the writes (ADR 0009)
    /// (`lu_ailleurs`).
    pub fn read_elsewhere(&self, dn: &str) -> bool {
        let mut written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        written.purge();
        written.objects.contains_key(&key(dn))
    }

    /// The connection that reads `dn`: the one of the DC of the writes if the object was
    /// written there and the DC of reading did not show it up to date yet (`_pour`).
    fn connection_for(&self, dn: &str) -> Arc<Connection> {
        let mut written = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        written.purge();
        match (&written.connection, written.objects.contains_key(&key(dn))) {
            (Some(connection), true) => connection.clone(),
            _ => self.connection.clone(),
        }
    }

    /// Snapshot of the objects written read again, to correct a list; None if there is
    /// nothing to correct (`_correction`).
    fn correction(&self, parent: Option<&str>, keep: Keep) -> Option<Correction> {
        let mut state = self.written.lock().unwrap_or_else(PoisonError::into_inner);
        state.purge();
        if state.objects.is_empty() && state.moved.is_empty() {
            return None;
        }
        Some(Correction {
            written: state
                .objects
                .iter()
                .map(|(k, (_, o))| (k.clone(), o.clone()))
                .collect(),
            moved: state
                .moved
                .iter()
                .map(|(k, (n, _))| (k.clone(), n.clone()))
                .collect(),
            appeared: state.appeared.keys().cloned().collect(),
            parent: parent.map(key),
            keep,
            seen: HashSet::new(),
            state: self.written.clone(),
        })
    }

    pub fn profile(&self) -> &Profile {
        &self.profile
    }

    /// DN of the root of the domain, once the source is open.
    pub fn root(&self) -> Option<String> {
        self.root
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Binds (blocking: off the interface thread) and returns the DN of the domain.
    pub fn open(&self) -> Result<String, Failure> {
        let root = self.connection.run(true, |link| {
            Ok(link.state.root_dse.default_naming_context.clone())
        })?;
        *self.root.lock().unwrap_or_else(PoisonError::into_inner) = Some(root.clone());
        Ok(root)
    }

    fn search(
        &self,
        base: &str,
        filter: String,
        scope: Scope,
        notifier: Notifier,
        correction: Option<Correction>,
    ) -> ObjectFlux {
        let flux = ObjectFlux::new(CAPACITY, Some(notifier));
        let search = Search {
            base: base.to_owned(),
            scope,
            filter,
            attributes: DISPLAY_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect(),
            page_size: PAGE_SIZE,
            sd_flags: None,
            controls: Vec::new(),
        };
        let pages: Arc<dyn Pages> = match correction {
            None => Arc::new(ObjectPages(flux.clone())),
            Some(correction) => Arc::new(CorrectedPages {
                flux: flux.clone(),
                correction: Mutex::new(correction),
                added: Mutex::new(false),
            }),
        };
        search::search(&self.connection.submitter(), search, pages);
        flux
    }

    /// The containers directly under `dn` (a level of the tree).
    pub fn containers(&self, dn: &str, advanced: bool, notifier: Notifier) -> ObjectFlux {
        let correction = self.correction(Some(dn), Item::is_container);
        self.search(
            dn,
            containers_filter(advanced),
            Scope::OneLevel,
            notifier,
            correction,
        )
    }

    /// The objects directly under `dn` (the table).
    pub fn contents(&self, dn: &str, advanced: bool, notifier: Notifier) -> ObjectFlux {
        let correction = self.correction(Some(dn), |_| true);
        self.search(
            dn,
            contents_filter(advanced),
            Scope::OneLevel,
            notifier,
            correction,
        )
    }

    /// A search under the root of the domain, or under `base`.
    pub fn search_under(
        &self,
        filter: String,
        base: Option<&str>,
        notifier: Notifier,
    ) -> ObjectFlux {
        let base = base.map(str::to_owned).or_else(|| self.root());
        let correction = self.correction(None, |_| true);
        self.search(
            &base.unwrap_or_default(),
            filter,
            Scope::Subtree,
            notifier,
            correction,
        )
    }

    fn blocking_search(
        connection: &Connection,
        (base, scope): (&str, Scope),
        filter: &str,
        attributes: Vec<String>,
        cancelled: &Cancelled,
    ) -> Result<Vec<Entry>, SurveyError> {
        let search = Search {
            base: base.to_owned(),
            scope,
            filter: filter.to_owned(),
            attributes,
            page_size: PAGE_SIZE,
            sd_flags: None,
            controls: Vec::new(),
        };
        let mut entries = Vec::new();
        let mut stopped = false;
        search_blocking(connection, search, &mut |page| {
            if cancelled() {
                stopped = true;
                return false;
            }
            entries.extend(page);
            true
        })
        .map_err(SurveyError::Search)?;
        if stopped {
            return Err(SurveyError::Cancelled);
        }
        Ok(entries)
    }

    /// The connection of the source (the synchronization of the local copy reads the
    /// state of the domain through it).
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Names of the DCs of the domain (computer accounts of DCs and RODCs), sorted
    /// (`lister_dcs`). Blocking.
    pub fn list_dcs(&self, cancelled: &Cancelled) -> Result<Vec<String>, SurveyError> {
        let root = self.open().map_err(SurveyError::Failure)?;
        let entries = Self::blocking_search(
            &self.connection,
            (&root, Scope::Subtree),
            queries::DCS,
            vec!["dNSHostName".into()],
            cancelled,
        )?;
        let mut names: Vec<String> = entries
            .iter()
            .filter_map(|e| e.values("dNSHostName").first())
            .map(|v| String::from_utf8_lossy(v).to_lowercase())
            .collect();
        names.sort();
        names.dedup();
        Ok(names)
    }

    /// Reads the objects of `filter` under the root of the domain and their `lastLogon` on
    /// each DC, in parallel (`relever_activite`). Blocking. The main DC is read by the
    /// connection of the source; each other DC by a connection opened for the occasion,
    /// without failover. A DC that does not answer does not fail the survey but is reported
    /// (`failures`): the date found may then be too old. `cancelled` stops it at the next
    /// page.
    pub fn survey(&self, filter: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError> {
        self.survey_at(None, filter, cancelled)
    }

    /// Last activity of an account, `lastLogon` read on each DC (survey J1.6, of one
    /// object). Blocking.
    pub fn activity(&self, dn: &str, cancelled: &Cancelled) -> Result<Survey, SurveyError> {
        self.survey_at(Some(dn), "(objectClass=*)", cancelled)
    }

    /// Survey under the root of the domain (None), or of the only object `dn`.
    fn survey_at(
        &self,
        dn: Option<&str>,
        filter: &str,
        cancelled: &Cancelled,
    ) -> Result<Survey, SurveyError> {
        let date = SystemTime::now();
        let root = self.open().map_err(SurveyError::Failure)?;
        let (root, extent) = match dn {
            Some(dn) => (dn.to_owned(), Scope::Base),
            None => (root, Scope::Subtree),
        };
        let main = self
            .connection
            .state()
            .map(|s| s.dc.clone())
            .unwrap_or_default();
        let others: Vec<String> = self
            .list_dcs(cancelled)?
            .into_iter()
            .filter(|dc| *dc != main)
            .collect();
        let attributes: Vec<String> = model::attributes().iter().map(|&a| a.to_owned()).collect();
        let (objects, read) = std::thread::scope(|scope| {
            let handles: Vec<_> = others
                .iter()
                .map(|dc| {
                    let (root, filter) = (root.clone(), filter.to_owned());
                    let profile = &self.profile;
                    scope.spawn(move || {
                        let connection = connection_to(profile, Some(dc));
                        let read = Self::blocking_search(
                            &connection,
                            (&root, extent),
                            &filter,
                            vec!["objectGUID".into(), "lastLogon".into()],
                            cancelled,
                        );
                        connection.close();
                        read
                    })
                })
                .collect();
            let objects = Self::blocking_search(
                &self.connection,
                (&root, extent),
                filter,
                attributes,
                cancelled,
            )
            .map(|entries| {
                entries
                    .iter()
                    .filter_map(|e| model::object_from_entry(e).ok())
                    .collect::<Vec<Object>>()
            });
            let read: Vec<_> = handles
                .into_iter()
                .map(|h| h.join().unwrap_or(Err(SurveyError::Cancelled)))
                .collect();
            (objects, read)
        });
        let objects = objects?;
        let mut logons = BTreeMap::new();
        let mut failures = Vec::new();
        for (dc, result) in others.into_iter().zip(read) {
            match result {
                Ok(entries) => {
                    let values: HashMap<Guid, i64> = entries
                        .iter()
                        .filter_map(|e| {
                            let guid = Guid::decode(e.values("objectGUID").first()?).ok()?;
                            let logon =
                                integer::decode(e.values("lastLogon").first()?, Width::Bits64)
                                    .ok()?;
                            Some((guid, logon))
                        })
                        .collect();
                    logons.insert(dc, values);
                }
                Err(SurveyError::Cancelled) => return Err(SurveyError::Cancelled),
                Err(SurveyError::Search(error)) => failures.push(DcFailure { dc, error }),
                Err(SurveyError::Failure(failure)) => failures.push(DcFailure {
                    dc,
                    error: match failure {
                        Failure::Connect(f) => SearchError::Connect(f),
                        Failure::Ldap { dc, error } => SearchError::Ldap { dc, error },
                    },
                }),
            }
        }
        let activities = combine_activity(&objects, &main, &logons);
        let last_logons = last_logons_by_account(&objects, &main, &logons);
        let mut dcs = vec![main];
        dcs.extend(logons.keys().cloned());
        Ok(Survey {
            date,
            objects,
            activities,
            last_logons,
            dcs,
            failures,
        })
    }

    /// The password and lockout policy of the domain, read on its root (`politique`).
    /// Blocking.
    pub fn policy(&self) -> Result<DomainPolicy, Failure> {
        let root = self.open()?;
        let attributes: Vec<String> = model::POLICY_ATTRIBUTES
            .iter()
            .map(|&a| a.to_owned())
            .collect();
        self.connection.run(true, move |link| {
            let entry = search::read_entry(
                link.session.as_mut(),
                &root,
                &attributes,
                "(objectClass=*)",
                None,
                Some(link.timeout),
            )?;
            let attributes = entry.map(|e| e.attributes).unwrap_or_default();
            Ok(model::policy_from_attributes(&attributes).unwrap_or_default())
        })
    }

    /// An object for its sheet: `record_attributes` plus `extra`; None if it does not exist
    /// (`fiche`). Blocking.
    pub fn record(&self, dn: &str, extra: &[&str]) -> Result<Option<Record>, Failure> {
        let date = SystemTime::now();
        let mut attributes: Vec<String> = Vec::new();
        for name in record_attributes().into_iter().chain(extra.iter().copied()) {
            if !attributes.iter().any(|a| a.eq_ignore_ascii_case(name)) {
                attributes.push(name.to_owned());
            }
        }
        let dn = dn.to_owned();
        let entry = self.connection_for(&dn).run(true, move |link| {
            search::read_entry(
                link.session.as_mut(),
                &dn,
                &attributes,
                "(objectClass=*)",
                None,
                Some(link.timeout),
            )
        })?;
        Ok(entry.map(|entry| Record {
            item: Item::from_entry(&entry),
            entry,
            date,
        }))
    }

    /// The schema of the directory, read on the DC once per source (a failure is not kept).
    /// Blocking.
    pub fn schema(&self) -> Result<Arc<Schema>, SchemaError> {
        let mut kept = self.schema.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(schema) = kept.as_ref() {
            return Ok(schema.clone());
        }
        let schema = Arc::new(schema::read_schema(&self.connection)?);
        *kept = Some(schema.clone());
        Ok(schema)
    }

    /// Nomenclature of the domain: the schema and the complements (`lire_nomenclature`),
    /// read once per source. Blocking.
    pub fn nomenclature(&self) -> Result<Arc<Nomenclature>, SchemaError> {
        let schema = self.schema()?;
        let mut kept = self
            .nomenclature
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(nomenclature) = kept.as_ref() {
            return Ok(nomenclature.clone());
        }
        let complements =
            security::read_complements(&self.connection).map_err(SchemaError::Failure)?;
        let nomenclature = Arc::new(security::nomenclature_from(&schema, &complements));
        *kept = Some(nomenclature.clone());
        Ok(nomenclature)
    }

    /// The descriptor of an object, the DACLs of its ancestors and the names of its SIDs
    /// (`securite`); None if the object does not exist. Blocking.
    /// DNS zones of the three places (J3.3), read on the DC. Blocking.
    pub fn dns_zones(&self) -> Result<Vec<crate::dns::Zone>, Failure> {
        crate::dns::zones(&self.connection)
    }

    /// Names of a zone with their records, page by page, on the DC (ADR 0010, 7).
    pub fn dns_nodes(&self, zone: &crate::dns::Zone, notifier: Notifier) -> crate::dns::NodePages {
        crate::dns::search_nodes(&self.connection, zone, Some(notifier))
    }

    pub fn security(&self, dn: &str) -> Result<Option<SecurityReading>, Failure> {
        security::read_security(&self.connection, dn)
    }

    /// Direct, primary and recursive groups of an object (J1.7). Blocking.
    pub fn groups(&self, dn: &str) -> Result<Membership, MembershipError> {
        membership::groups_of(&self.connection_for(dn), dn, true)
    }

    /// Direct members of a group (`member`, read by ranges with an explicit bound); a member
    /// not found (outside of the domain, phantom) comes as an unknown object named after its
    /// DN (`membres`). The batches are read in a thread of their own.
    pub fn members(&self, dn: &str, notifier: Notifier) -> ObjectFlux {
        let flux = ObjectFlux::new(CAPACITY, Some(notifier));
        let (out, connection, dn) = (flux.clone(), self.connection_for(dn), dn.to_owned());
        let produce = move || -> Result<(), SearchError> {
            let failure = |f: Failure| match f {
                Failure::Connect(f) => SearchError::Connect(f),
                Failure::Ldap { dc, error } => SearchError::Ldap { dc, error },
            };
            let base = connection
                .run(true, |link| {
                    Ok(link.state.root_dse.default_naming_context.clone())
                })
                .map_err(failure)?;
            let dns: Vec<String> = membership::read_ranges(&connection, &dn, "member")
                .map_err(failure)?
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect();
            if dns.is_empty() {
                out.put(Vec::new(), None);
            }
            let batches: Vec<&[String]> = dns.chunks(MEMBER_BATCH).collect();
            for (i, batch) in batches.iter().enumerate() {
                if out.cancelled() {
                    break;
                }
                let items = member_batch(&connection, &base, batch)?;
                let last = i + 1 == batches.len();
                out.put(items, (!last).then(|| Box::new(|| {}) as Next));
            }
            Ok(())
        };
        std::thread::Builder::new()
            .name("annuaire membres".into())
            .spawn({
                let flux = flux.clone();
                move || match produce() {
                    Ok(()) => flux.finish(None),
                    Err(error) => flux.finish(Some(error)),
                }
            })
            .ok();
        flux
    }

    /// When the data of a reading date from: now, read on the DC.
    pub fn freshness(&self) -> SystemTime {
        SystemTime::now()
    }

    pub fn close(&self) {
        self.connection.close();
    }
}

impl Drop for DirectSource {
    fn drop(&mut self) {
        self.connection.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert_eq!(
            containers_filter(true),
            "(|(objectClass=organizationalUnit)(objectClass=container)\
             (objectClass=builtinDomain)(objectClass=lostAndFound))"
        );
        assert_eq!(
            containers_filter(false),
            "(&(|(objectClass=organizationalUnit)(objectClass=container)\
             (objectClass=builtinDomain)(objectClass=lostAndFound))\
             (!(showInAdvancedViewOnly=TRUE)))"
        );
        assert_eq!(contents_filter(false), "(!(showInAdvancedViewOnly=TRUE))");
        assert_eq!(contents_filter(true), "(objectClass=*)");
    }

    #[test]
    fn names() {
        assert_eq!(name_from_dn("OU=Société,DC=lab,DC=test"), "Société");
        assert_eq!(name_from_dn("pas un DN"), "pas un DN");
    }
}

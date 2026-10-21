// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS health (J3.5, `annuaire.core.sante_dns`): anomalies of the zones integrated in the
//! directory, and their fixes.
//!
//! It automates the cleaning done by hand on example.local on 2026-10-12 after a DC left (NS,
//! SRV, A of the root and of the DNS partitions that still named it). Two steps:
//!
//! - [`read_state`] reads **on the DC** (as every DNS reading, ADR 0010, 7) the zones and
//!   their nodes, the controllers (`nTDSDSA` objects of `CN=Sites` and their server), the
//!   sites and the DNS names of the computer accounts;
//! - [`diagnose`] is pure: it returns the anomalies, each with its explanation, its
//!   severity, the records targeted and its fix (requests of `dns_write`, never applied
//!   here: `dns_write::build` makes of them a changeset read on the DC of the writes, which
//!   goes through the preview).
//!
//! The core says nothing: titles, explanations, labels of the fixes and remarks are values
//! ([`Title`], [`Explanation`], [`FixLabel`], [`HealthRemark`]), said by the interface.
//!
//! An ordinary account does not read everything: with Samba, a node a machine created by
//! secure dynamic update (DCs included) grants reading only to it and to the administrators
//! (seen on example.local on 2026-10-14: the object shows, no attribute; 55 nodes out of 139,
//! all read by an account of the Domain Admins). These names are kept apart
//! ([`DnsState::unreadable`]) and never deemed absent; the addresses of the DCs then come
//! from the resolver of the computer. The diagnosis says it in its remarks.
//!
//! Rules, in the order they take the records (a record belongs to one anomaly only: the
//! first that takes it):
//!
//! 1. `NsOutsideDc` (critical; information in an internal zone of Windows such as
//!    `..TrustAnchors`, which Samba does not serve): NS of a zone or of a delegation naming a
//!    server that is not a DC. The name of the domain counts as a DC (samba-tool writes
//!    `NS <domain>` in the zones it creates, and its A are the list of the DCs, checked by
//!    rule 3), as a name whose addresses are all those of DCs. The SOA is rule 10's.
//! 2. `RemovedDc` (critical): SRV of the DC locator (`_ldap._tcp`, `_kerberos`, `_kpasswd`,
//!    `_gc`, under the domain, its sites, its DNS partitions and `_msdcs`) to a host that is
//!    not a DC; CNAME `<guid>._msdcs` of an `nTDSDSA` that no longer exists.
//! 3. `AOutsideDc` (critical): A or AAAA of the root of the domain, of `DomainDnsZones`,
//!    `ForestDnsZones` and `gc._msdcs` to an address that is not one of a DC (of a global
//!    catalog for `gc`). `MissingDc` (warning): a DC none of whose addresses is there.
//! 4. `VanishedHost` (warning): **dynamic** A or AAAA of a name without computer account,
//!    with the PTR that point to it: a machine deleted from the directory. Static records
//!    are not targeted (printers, devices outside the domain written by hand), except with
//!    [`Settings::statics`], as mere information.
//! 5. `PtrWithoutName` (warning): PTR to a name of a zone of the directory that has neither
//!    A nor AAAA. `InconsistentPtr`: the name has addresses, but not the one of the PTR.
//! 6. `MissingTarget` (warning): CNAME, SRV or MX to a name of a zone of the directory that
//!    does not exist (for SRV and MX: that has no address). A target outside the zones of
//!    the directory, unreadable or that is a DC is not judged.
//! 7. `NotRefreshed` (warning): dynamic records their machine did not refresh for
//!    [`Settings::days`] (180 by default, the rule « inactive for 6 months » of the
//!    project); if the aging of the zone is on, never before the deadline of the zone
//!    (no-refresh + refresh). Not the names the DCs hold themselves (root, partitions,
//!    `_msdcs`, locator): Samba does not refresh their timestamp, and removing them would
//!    cut the domain. The name (or the target of a PTR) of a computer account active for
//!    less than the threshold stays in service: only an information, without fix (device
//!    that writes its name once, NAS or Samba server; seen on example.local, where deleting it
//!    would have cut two machines in service).
//! 8. `WithoutPtr` (information): A or AAAA of a DC, or static A of a computer (server with a
//!    fixed address), whose address falls in a reverse zone of the directory without PTR to
//!    it. Not the workstations (dynamic A): a missing PTR is common there and harmless.
//! 9. `OldTombstone` (information): node in tombstone for more than
//!    [`Settings::tombstone_days`] (14, the interval of Windows); Samba does not purge them
//!    without scavenging. Fix: deletion of the object (ADR 0003, point 2).
//! 10. `SoaOutsideDc` (information): SOA of a zone whose primary server (MNAME) is not a DC,
//!     leftover of a removed DC (seen on example.local: three zones still named an old DC).
//!     Samba answers with its own name whatever the object says, hence the information; but
//!     the DNS window, a copy of the zone or a Windows DC added later read the stored value.
//!     Fixed by hand (the SOA is not written by the requests).
//! 11. `DuplicateZone` (critical; information for the root hints): zone of the same name in
//!     two places (`DomainDnsZones`, `ForestDnsZones`, `CN=System`): the server serves only
//!     one, and which one is not defined. Fixed by hand. The root hints in `CN=System` and
//!     one application partition are not reported: a Windows DC writes both at its promotion
//!     (seen on Windows Server 2025).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use annuaire_codecs::Guid;
use annuaire_codecs::dns_record::{self, Record, RecordData};
use annuaire_codecs::time::{self, UtcTime};
use annuaire_codecs::uac::UserAccountControl;

use crate::connection::{Connection, Failure};
use crate::dn;
use crate::dns::{
    self, NAMES_FILTER, NODE_ATTRIBUTES, Node, Partition, ROOT, Zone, fqdn, node_from_entry,
};
use crate::dns_write::{DEFAULT_TTL, Request, reverse_zone};
use crate::search::{PAGE_SIZE, Search, SearchError};
use crate::session::{Entry, Scope};
use crate::source::search_blocking;

/// Default threshold of the dynamic records not refreshed (rule of the 6 months).
pub const DAYS_NOT_REFRESHED: i64 = 180;
/// Age of a tombstone past which the Windows DNS server would have purged it.
pub const DAYS_TOMBSTONE: i64 = 14;
/// Bit `IS_GC` of `options` on an `nTDSDSA`: the DC is a global catalog.
pub const NTDSDSA_GC: i64 = 0x1;
const DC_SERVICES: [&str; 6] = [
    "_ldap._tcp",
    "_kerberos._tcp",
    "_kerberos._udp",
    "_kpasswd._tcp",
    "_kpasswd._udp",
    "_gc._tcp",
];
const DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Information = 0,
    Warning = 1,
    Critical = 2,
}

/// The rules, in the order of the sort of the anomalies (`Regle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    NsOutsideDc,
    RemovedDc,
    AOutsideDc,
    MissingDc,
    VanishedHost,
    PtrWithoutName,
    InconsistentPtr,
    MissingTarget,
    NotRefreshed,
    WithoutPtr,
    OldTombstone,
    SoaOutsideDc,
    DuplicateZone,
}

impl Rule {
    /// The value of the Python enumeration.
    pub fn value(self) -> &'static str {
        match self {
            Self::NsOutsideDc => "ns-hors-dc",
            Self::RemovedDc => "dc-disparu",
            Self::AOutsideDc => "a-hors-dc",
            Self::MissingDc => "a-dc-manquant",
            Self::VanishedHost => "hote-disparu",
            Self::PtrWithoutName => "ptr-sans-nom",
            Self::InconsistentPtr => "ptr-incoherent",
            Self::MissingTarget => "cible-absente",
            Self::NotRefreshed => "non-rafraichi",
            Self::WithoutPtr => "sans-ptr",
            Self::OldTombstone => "tombstone-ancien",
            Self::SoaOutsideDc => "soa-hors-dc",
            Self::DuplicateZone => "zone-en-double",
        }
    }
}

// ---------------------------------------------------------------------------
// State read

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Controller {
    /// DNS name (`dNSHostName` of the server object), in lower case.
    pub name: String,
    /// `objectGUID` of its `nTDSDSA`, lower-case text (name of the CNAME `<guid>._msdcs`).
    pub guid: String,
    pub site: String,
    pub catalog: bool,
}

/// What [`read_state`] reads; built by hand too (tests) (`EtatDns`).
#[derive(Debug, Clone, Default)]
pub struct DnsState {
    pub domain: String,
    pub forest: String,
    pub zones: Vec<Zone>,
    /// By DN of zone.
    pub nodes: HashMap<String, Vec<Node>>,
    pub controllers: Vec<Controller>,
    /// `dNSHostName` of the computer accounts, lower case (DCs included).
    pub computers: HashSet<String>,
    /// Names of the sites, lower case.
    pub sites: HashSet<String>,
    /// By DN of zone: names (lower case) of the nodes the account sees without reading them
    /// (rights: with Samba, for an ordinary account, those a machine registered itself).
    /// Never deemed absent.
    pub unreadable: HashMap<String, HashSet<String>>,
    /// Addresses of the DCs given by the resolver of the computer, when their node is
    /// unreadable.
    pub resolved: HashMap<String, HashSet<String>>,
    pub dc: String,
    pub read_at: Option<UtcTime>,
    /// `dNSHostName` (lower case) of the enabled computer accounts → their last known
    /// activity: the most recent of `lastLogonTimestamp` (14 days late at most) and of
    /// `pwdLastSet` (changed every 30 days by the machine). Without date, absent.
    pub activity: HashMap<String, UtcTime>,
}

/// `DC=lab,DC=test` → `lab.test` (`nom_dns`).
pub fn dns_name(nc: &str) -> String {
    dn::split(nc)
        .map(|c| {
            c.iter()
                .filter(|x| x.attribute.eq_ignore_ascii_case("DC"))
                .map(|x| x.value.clone())
                .collect::<Vec<_>>()
                .join(".")
        })
        .unwrap_or_default()
        .to_lowercase()
}

fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

/// Addresses of the name by the resolver of the computer (empty if it fails).
fn resolve(name: &str) -> HashSet<String> {
    (name, 0)
        .to_socket_addrs()
        .map(|addresses| addresses.map(|a| a.ip().to_string()).collect())
        .unwrap_or_default()
}

/// Last activity of an enabled computer account ([`DnsState::activity`]).
pub fn activity_of(entry: &Entry) -> Option<UtcTime> {
    let uac: i32 = text(entry, "userAccountControl").parse().unwrap_or(0);
    if UserAccountControl::decode(uac).contains(UserAccountControl::ACCOUNTDISABLE) {
        return None;
    }
    let mut dates = Vec::new();
    for attribute in ["lastLogonTimestamp", "pwdLastSet"] {
        let t = text(entry, attribute);
        let value: i64 = if t.is_empty() { 0 } else { t.parse().ok()? };
        if let Some(date) = time::nttime_to_utc(value).ok()? {
            dates.push(date);
        }
    }
    dates.into_iter().max()
}

fn now() -> UtcTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    time::unix_to_nttime(seconds)
        .ok()
        .and_then(|n| time::nttime_to_utc(n).ok().flatten())
        .unwrap_or(time::NT_EPOCH)
}

fn search(
    connection: &Connection,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<Entry>, SearchError> {
    let request = Search {
        base: base.to_owned(),
        scope,
        filter: filter.to_owned(),
        attributes: attributes.iter().map(|&a| a.to_owned()).collect(),
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls: Vec::new(),
    };
    let mut entries = Vec::new();
    search_blocking(connection, request, &mut |page| {
        entries.extend(page);
        true
    })?;
    Ok(entries)
}

/// Why the state could not be read.
#[derive(Debug, Clone)]
pub enum ReadError {
    Failure(Failure),
    Search(SearchError),
}

impl From<SearchError> for ReadError {
    fn from(e: SearchError) -> Self {
        Self::Search(e)
    }
}

/// Reads on the DC of the connection everything the diagnosis needs (`lire_etat`).
/// Blocking: off the interface.
pub fn read_state(connection: &Connection) -> Result<DnsState, ReadError> {
    let (root, dc) = connection
        .run(true, |link| {
            Ok((link.state.root_dse.clone(), link.state.dc.clone()))
        })
        .map_err(ReadError::Failure)?;
    let domain = root.default_naming_context.clone();
    let forest = if root.root_domain_naming_context.is_empty() {
        domain.clone()
    } else {
        root.root_domain_naming_context.clone()
    };
    let zones = dns::zones(connection).map_err(ReadError::Failure)?;
    let mut nodes: HashMap<String, Vec<Node>> = HashMap::new();
    let mut unreadable: HashMap<String, HashSet<String>> = HashMap::new();
    for zone in zones.iter().filter(|z| !z.root_hints()) {
        // Every object under the zone, as the DNS window: a node unreadable for the account
        // is kept apart, never taken for a name without record.
        let mut read = Vec::new();
        let mut hidden = HashSet::new();
        for e in search(
            connection,
            &zone.dn,
            Scope::OneLevel,
            NAMES_FILTER,
            &NODE_ATTRIBUTES,
        )? {
            let node = node_from_entry(&e, &zone.name);
            if node.unreadable {
                hidden.insert(node.name.to_lowercase());
            } else {
                read.push(node);
            }
        }
        nodes.insert(zone.dn.clone(), read);
        if !hidden.is_empty() {
            unreadable.insert(zone.dn.clone(), hidden);
        }
    }
    let mut servers: HashMap<String, String> = HashMap::new();
    let mut dsas: Vec<Entry> = Vec::new();
    let mut sites = HashSet::new();
    for e in search(
        connection,
        &format!("CN=Sites,{}", root.configuration_naming_context),
        Scope::Subtree,
        "(|(objectClass=site)(objectClass=server)(objectClass=nTDSDSA))",
        &["objectClass", "dNSHostName", "objectGUID", "options"],
    )? {
        let classes: HashSet<String> = e
            .values("objectClass")
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_lowercase())
            .collect();
        if classes.contains("ntdsdsa") {
            dsas.push(e);
        } else if classes.contains("server") {
            servers.insert(key(&e.dn), text(&e, "dNSHostName").to_lowercase());
        } else if classes.contains("site") {
            if let Some(first) = dn::split(&e.dn).ok().and_then(|c| c.first().cloned()) {
                sites.insert(first.value.to_lowercase());
            }
        }
    }
    let mut controllers = Vec::new();
    for e in &dsas {
        let parent = dn::parent(&e.dn).map(|p| key(&p)).unwrap_or_default();
        let name = servers.get(&parent).cloned().unwrap_or_default();
        let Some(guid) = e.values("objectGUID").first() else {
            continue;
        };
        let Ok(guid) = Guid::decode(guid) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let components = dn::split(&e.dn).unwrap_or_default();
        let options: i64 = text(e, "options").parse().unwrap_or(0);
        controllers.push(Controller {
            name,
            guid: guid.to_string().to_lowercase(),
            site: components
                .get(3)
                .map(|c| c.value.clone())
                .unwrap_or_default(),
            catalog: options & NTDSDSA_GC != 0,
        });
    }
    controllers.sort_by(|a, b| a.name.cmp(&b.name));
    let mut computers = HashSet::new();
    let mut activity = HashMap::new();
    for e in search(
        connection,
        &domain,
        Scope::Subtree,
        "(&(objectCategory=computer)(dNSHostName=*))",
        &[
            "dNSHostName",
            "userAccountControl",
            "lastLogonTimestamp",
            "pwdLastSet",
        ],
    )? {
        let name = text(&e, "dNSHostName").to_lowercase();
        if let Some(date) = activity_of(&e) {
            activity.insert(name.clone(), date);
        }
        computers.insert(name);
    }
    let resolved = controllers
        .iter()
        .map(|c| (c.name.clone(), resolve(&c.name)))
        .collect();
    Ok(DnsState {
        domain: dns_name(&domain),
        forest: dns_name(&forest),
        zones,
        nodes,
        controllers,
        computers,
        sites,
        unreadable,
        resolved,
        dc,
        read_at: Some(now()),
        activity,
    })
}

fn key(dn_text: &str) -> String {
    dn::key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

// ---------------------------------------------------------------------------
// Anomalies

/// A record targeted (`value`), or a whole node (`value` None: tombstone) (`Vise`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub zone: Zone,
    /// Relative to the zone, `@` for its root.
    pub name: String,
    pub value: Option<Vec<u8>>,
}

impl Target {
    pub fn fqdn(&self) -> String {
        fqdn(&self.zone.name, &self.name)
    }

    pub fn record(&self) -> Option<Record> {
        Record::decode(self.value.as_ref()?).ok()
    }

    fn key(&self) -> (String, String, Option<Vec<u8>>) {
        (
            self.zone.dn.to_lowercase(),
            self.name.to_lowercase(),
            self.value.clone(),
        )
    }
}

/// What a fix does, in one sentence (« Delete these 2 records »).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixLabel {
    Delete { n: usize },
    ReplaceNs { zone: String, dcs: Vec<String> },
    RemoveNs { target: String },
    AddAddress { address: String, name: String },
    AddPtr { address: String, name: String },
    Purge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fix {
    pub label: FixLabel,
    pub requests: Vec<Request>,
}

/// Title of an anomaly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Title {
    NsNotDc {
        target: String,
    },
    SrvNotDc {
        name: String,
        target: String,
    },
    ReplicationCname {
        target: String,
    },
    ANotDc {
        name: String,
        address: String,
    },
    DcMissingFrom {
        dc: String,
        name: String,
    },
    HostWithoutAccount {
        name: String,
    },
    StaticWithoutAccount {
        name: String,
    },
    PtrToNothing {
        name: String,
        target: String,
    },
    PtrOtherAddress {
        address: String,
        target: String,
    },
    TargetMissing {
        rtype: String,
        name: String,
        target: String,
    },
    NotRefreshed {
        name: String,
        days: i64,
    },
    NotRefreshedInService {
        name: String,
        days: i64,
    },
    WithoutPtr {
        name: String,
        address: String,
    },
    SoaNotDc {
        zone: String,
        server: String,
    },
    DuplicateZone {
        zone: String,
        n: usize,
    },
    OldTombstone {
        name: String,
        days: i64,
    },
}

/// The phrase on the aging of the zone of a record not refreshed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aging {
    Enabled { days: i64 },
    Disabled,
}

/// Explanation of an anomaly. Lists are sorted; an empty one is said « none ».
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Explanation {
    NsNotDc {
        name: String,
        target: String,
        dcs: Vec<String>,
        /// The only server of a delegation: fixed by hand.
        only_server: bool,
        /// Internal zone of the Windows DNS server (`..TrustAnchors`).
        internal_zone: Option<String>,
    },
    SrvNotDc {
        target: String,
        dcs: Vec<String>,
        missing_site: Option<String>,
    },
    ReplicationCname {
        name: String,
        target: String,
    },
    ANotDc {
        name: String,
        catalog: bool,
        allowed: Vec<String>,
        address: String,
    },
    DcMissing {
        dc: String,
        addresses: Vec<String>,
        name: String,
    },
    Host {
        name: String,
        date: String,
        /// PTR that go with it.
        ptrs: usize,
    },
    Static {
        name: String,
    },
    PtrToNothing {
        address: String,
        target: String,
    },
    PtrOtherAddress {
        address: String,
        target: String,
        theirs: Vec<String>,
    },
    TargetMissing {
        name: String,
        target: String,
        /// SRV or MX: the target has no address.
        address: bool,
    },
    NotRefreshed {
        name: String,
        date: String,
        threshold: i64,
        aging: Aging,
    },
    InService {
        machine: String,
        name: String,
        date: String,
        seen: String,
    },
    WithoutPtr {
        zone: String,
        address: String,
        name: String,
    },
    SoaNotDc {
        zone: String,
        server: String,
        dcs: Vec<String>,
    },
    DuplicateZone {
        zone: String,
        places: Vec<String>,
        root_hints: bool,
    },
    OldTombstone {
        name: String,
        date: String,
        threshold: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    pub rule: Rule,
    pub severity: Severity,
    pub title: Title,
    pub explanation: Explanation,
    pub targets: Vec<Target>,
    /// None: no safe fix to propose (the explanation says what to do).
    pub fix: Option<Fix>,
}

/// What the diagnosis could not judge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthRemark {
    /// Addresses of these DCs taken from the resolver of the computer.
    Resolved {
        dcs: Vec<String>,
    },
    /// Names unreadable with this account.
    Unreadable {
        n: usize,
    },
    NoControllers,
    NoDcAddresses,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Age past which a dynamic record is « not refreshed ».
    pub days: i64,
    pub tombstone_days: i64,
    /// Report too (as information) the static A without computer account.
    pub statics: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            days: DAYS_NOT_REFRESHED,
            tombstone_days: DAYS_TOMBSTONE,
            statics: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Diagnosis {
    pub anomalies: Vec<Anomaly>,
    pub settings: Settings,
    pub now: UtcTime,
    pub zones: usize,
    pub nodes: usize,
    pub records: usize,
    pub remarks: Vec<HealthRemark>,
}

impl Diagnosis {
    pub fn of_severity(&self, severity: Severity) -> usize {
        self.anomalies
            .iter()
            .filter(|a| a.severity == severity)
            .count()
    }
}

// ---------------------------------------------------------------------------
// Index of the zones

fn is_forward(zone: &Zone) -> bool {
    !zone.root_hints() && !zone.reverse()
}

/// `10.1.168.192.in-addr.arpa` → 192.168.1.10 (full name only, otherwise None)
/// (`adresse_de_ptr`).
pub fn address_of_ptr(fqdn: &str) -> Option<IpAddr> {
    let name = fqdn.to_lowercase();
    let name = name.trim_end_matches('.');
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let octets: Vec<&str> = rest.split('.').collect();
        if octets.len() == 4 {
            let mut parsed = [0u8; 4];
            for (slot, o) in parsed.iter_mut().zip(octets.iter().rev()) {
                *slot = o.parse().ok()?;
            }
            return Some(IpAddr::V4(Ipv4Addr::from(parsed)));
        }
    } else if let Some(rest) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() == 32 {
            let digits: String = nibbles.iter().rev().copied().collect();
            return u128::from_str_radix(&digits, 16)
                .ok()
                .map(|v| IpAddr::V6(Ipv6Addr::from(v)));
        }
    }
    None
}

type Place = (String, String);
/// Name (lower case) → PTR that point to it: (reverse zone, node, value).
type PtrTo<'a> = HashMap<String, Vec<(Zone, &'a Node, Vec<u8>)>>;

struct Index<'a> {
    forward: Vec<&'a Zone>,
    reverse: Vec<Zone>,
    /// (DN of zone in lower case, relative name in lower case) → live nodes.
    live: HashMap<Place, Vec<&'a Node>>,
    unreadable: HashSet<Place>,
    /// (DN of zone, name) in lower case → name as written in the directory.
    names: HashMap<Place, String>,
}

impl<'a> Index<'a> {
    fn new(state: &'a DnsState) -> Self {
        let mut index = Self {
            forward: Vec::new(),
            reverse: Vec::new(),
            live: HashMap::new(),
            unreadable: HashSet::new(),
            names: HashMap::new(),
        };
        for zone in &state.zones {
            let zone_key = zone.dn.to_lowercase();
            for name in state.unreadable.get(&zone.dn).into_iter().flatten() {
                index
                    .unreadable
                    .insert((zone_key.clone(), name.to_lowercase()));
            }
            if is_forward(zone) {
                index.forward.push(zone);
            } else if zone.reverse() {
                index.reverse.push(zone.clone());
            }
            for n in state.nodes.get(&zone.dn).into_iter().flatten() {
                let place = (zone_key.clone(), n.name.to_lowercase());
                index
                    .names
                    .entry(place.clone())
                    .or_insert_with(|| n.name.clone());
                if !n.tombstone {
                    index.live.entry(place).or_default().push(n);
                }
            }
        }
        // The most precise zone first: `_msdcs.lab.test` before `lab.test`.
        index
            .forward
            .sort_by_key(|z| std::cmp::Reverse(z.name.chars().count()));
        index
    }

    /// The most precise forward zone of the directory that holds the name, and the relative
    /// name (written as in the directory if there is a node) (`localiser`).
    fn locate(&self, full: &str) -> Option<(&'a Zone, String)> {
        let name = full.to_lowercase();
        let name = name.trim_end_matches('.');
        for zone in &self.forward {
            let z = zone.name.to_lowercase();
            let z = z.trim_end_matches('.');
            if name == z {
                return Some((zone, ROOT.into()));
            }
            if let Some(relative) = name.strip_suffix(&format!(".{z}")) {
                let written = self
                    .names
                    .get(&(zone.dn.to_lowercase(), relative.to_owned()))
                    .cloned()
                    .unwrap_or_else(|| relative.to_owned());
                return Some((zone, written));
            }
        }
        None
    }

    fn records(&self, zone: &Zone, name: &str) -> Vec<(&'a Node, Record)> {
        self.live
            .get(&(zone.dn.to_lowercase(), name.to_lowercase()))
            .into_iter()
            .flatten()
            .flat_map(|n| {
                n.records()
                    .into_iter()
                    .filter(|e| e.rtype != dns_record::TOMBSTONE)
                    .map(move |e| (*n, e))
            })
            .collect()
    }

    /// The name located, unless it is outside the zones or its node unreadable.
    fn readable(&self, full: &str) -> Option<(&'a Zone, String)> {
        let (zone, name) = self.locate(full)?;
        if self
            .unreadable
            .contains(&(zone.dn.to_lowercase(), name.to_lowercase()))
        {
            return None;
        }
        Some((zone, name))
    }

    /// The name holds records; None if it cannot be known (`existe`).
    fn exists(&self, full: &str) -> Option<bool> {
        let (zone, name) = self.readable(full)?;
        Some(!self.records(zone, &name).is_empty())
    }

    /// Addresses (A, AAAA) of the name; None if it cannot be known (`adresses`).
    fn addresses(&self, full: &str) -> Option<HashSet<IpAddr>> {
        let (zone, name) = self.readable(full)?;
        Some(
            self.records(zone, &name)
                .into_iter()
                .filter_map(|(_, e)| match e.data {
                    RecordData::Address(a)
                        if e.rtype == dns_record::A || e.rtype == dns_record::AAAA =>
                    {
                        Some(a)
                    }
                    _ => None,
                })
                .collect(),
        )
    }
}

/// Values of the node that decode, type 0 excepted (`_valeurs`).
fn values(node: &Node) -> Vec<(Vec<u8>, Record)> {
    node.values
        .iter()
        .filter_map(|v| {
            let e = Record::decode(v).ok()?;
            (e.rtype != dns_record::TOMBSTONE).then(|| (v.clone(), e))
        })
        .collect()
}

/// Target of a record, lower case without final dot (`_cible`).
fn target_of(e: &Record) -> Option<String> {
    let name = match &e.data {
        RecordData::Name(n) => n,
        RecordData::Mx { target, .. } | RecordData::Srv { target, .. } => target,
        _ => return None,
    };
    Some(name.to_lowercase().trim_end_matches('.').to_owned())
}

fn record_date(e: &Record) -> Option<UtcTime> {
    if e.timestamp == 0 {
        return None;
    }
    dns_record::hours_to_utc(e.timestamp).ok().flatten()
}

/// `YYYY-MM-DD` in UTC (`_jour`).
pub fn day(date: UtcTime) -> String {
    let c = date.civil();
    format!("{:04}-{:02}-{:02}", c.year, c.month, c.day)
}

fn list(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut out: Vec<String> = names.into_iter().collect();
    out.sort();
    out.dedup();
    out
}

fn delete(targets: &[Target], label: Option<FixLabel>) -> Fix {
    let requests: Vec<Request> = targets
        .iter()
        .filter_map(|t| {
            Some(Request::Delete {
                zone: t.zone.clone(),
                name: t.name.clone(),
                value: t.value.clone()?,
            })
        })
        .collect();
    Fix {
        label: label.unwrap_or(FixLabel::Delete { n: requests.len() }),
        requests,
    }
}

fn is_guid(label: &str) -> bool {
    let parts: Vec<&str> = label.split('-').collect();
    parts.len() == 5
        && parts
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(p, n)| p.len() == n && p.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

/// What follows the service in a name of the locator (MS-ADTS 6.3.6), domain taken out.
fn locator_rest(rest: &str) -> bool {
    if rest.is_empty() {
        return true;
    }
    let mut labels: Vec<&str> = rest.split('.').collect();
    if labels.len() >= 2
        && labels.get(1) == Some(&"_sites")
        && labels.first().is_some_and(|l| !l.is_empty())
    {
        labels.drain(..2);
    }
    match labels.as_slice() {
        [] => true,
        ["dc" | "gc" | "pdc", "_msdcs"] | ["domaindnszones"] | ["forestdnszones"] => true,
        [guid, "domains", "_msdcs"] => is_guid(guid),
        _ => false,
    }
}

struct Diagnostician<'a> {
    state: &'a DnsState,
    settings: Settings,
    now: UtcTime,
    index: Index<'a>,
    taken: HashSet<(String, String, Option<Vec<u8>>)>,
    anomalies: Vec<Anomaly>,
    remarks: Vec<HealthRemark>,
    dcs: HashSet<String>,
    guids: HashSet<String>,
    dc_addresses: HashMap<String, HashSet<IpAddr>>,
    all_dc: HashSet<IpAddr>,
    catalogs: HashSet<IpAddr>,
}

impl<'a> Diagnostician<'a> {
    fn new(state: &'a DnsState, settings: Settings, now: UtcTime) -> Self {
        let index = Index::new(state);
        let mut remarks = Vec::new();
        let mut dc_addresses: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        let mut resolved = Vec::new();
        for c in &state.controllers {
            let mut found = index.addresses(&c.name).unwrap_or_default();
            if found.is_empty() {
                if let Some(given) = state.resolved.get(&c.name).filter(|g| !g.is_empty()) {
                    found = given.iter().filter_map(|a| a.parse().ok()).collect();
                    resolved.push(c.name.clone());
                }
            }
            dc_addresses.insert(c.name.clone(), found);
        }
        if !resolved.is_empty() {
            remarks.push(HealthRemark::Resolved {
                dcs: list(resolved),
            });
        }
        let hidden: usize = state.unreadable.values().map(HashSet::len).sum();
        if hidden > 0 {
            remarks.push(HealthRemark::Unreadable { n: hidden });
        }
        let all_dc: HashSet<IpAddr> = dc_addresses.values().flatten().copied().collect();
        let catalogs = if state.controllers.iter().any(|c| c.catalog) {
            state
                .controllers
                .iter()
                .filter(|c| c.catalog)
                .flat_map(|c| dc_addresses.get(&c.name).into_iter().flatten().copied())
                .collect()
        } else {
            all_dc.clone()
        };
        Self {
            state,
            settings,
            now,
            index,
            taken: HashSet::new(),
            anomalies: Vec::new(),
            remarks,
            dcs: state.controllers.iter().map(|c| c.name.clone()).collect(),
            guids: state.controllers.iter().map(|c| c.guid.clone()).collect(),
            dc_addresses,
            all_dc,
            catalogs,
        }
    }

    fn add(&mut self, anomaly: Anomaly) {
        for t in &anomaly.targets {
            self.taken.insert(t.key());
        }
        self.anomalies.push(anomaly);
    }

    fn free(&self, target: &Target) -> bool {
        !self.taken.contains(&target.key())
    }

    fn nodes(&self, zones: Vec<&'a Zone>) -> Vec<(&'a Zone, &'a Node)> {
        let state = self.state;
        zones
            .into_iter()
            .flat_map(|z| {
                state
                    .nodes
                    .get(&z.dn)
                    .into_iter()
                    .flatten()
                    .map(move |n| (z, n))
            })
            .collect()
    }

    fn zones(&self) -> Vec<&'a Zone> {
        self.state
            .zones
            .iter()
            .filter(|z| !z.root_hints())
            .collect()
    }

    fn dc_list(&self) -> Vec<String> {
        list(self.dcs.iter().cloned())
    }

    /// A DC, the name of the domain or of the forest (its A are the list of the DCs, and
    /// their errors the business of `AOutsideDc`), or a name whose addresses (one at least)
    /// are all those of DCs (`est_dc`).
    fn is_dc(&self, name: &str) -> bool {
        if self.dcs.contains(name) || name == self.state.domain || name == self.state.forest {
            return true;
        }
        let addresses = self.index.addresses(name).unwrap_or_default();
        !addresses.is_empty() && !self.all_dc.is_empty() && addresses.is_subset(&self.all_dc)
    }

    // -- 1. NS --------------------------------------------------------------

    fn ns(&mut self) {
        if self.dcs.is_empty() {
            self.remarks.push(HealthRemark::NoControllers);
            return;
        }
        for (zone, n) in self.nodes(self.zones()) {
            if n.tombstone {
                continue;
            }
            let all: Vec<(Vec<u8>, Record)> = values(n)
                .into_iter()
                .filter(|(_, e)| e.rtype == dns_record::NS)
                .collect();
            let wrong: Vec<&(Vec<u8>, Record)> = all
                .iter()
                .filter(|(_, e)| !self.is_dc(&target_of(e).unwrap_or_default()))
                .collect();
            if wrong.is_empty() {
                continue;
            }
            let targets: Vec<Target> = wrong
                .iter()
                .map(|(v, _)| Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v.clone()),
                })
                .collect();
            let replace = wrong.len() == all.len();
            let common = (replace && n.is_root()).then(|| {
                // No right NS left: one fix, that names the DCs and removes the others, so
                // that the zone is never without name server.
                let mut requests: Vec<Request> = self
                    .dc_list()
                    .into_iter()
                    .map(|dc| Request::Add {
                        zone: zone.clone(),
                        name: ROOT.into(),
                        rtype: dns_record::NS,
                        data: RecordData::Name(dc),
                        ttl: DEFAULT_TTL,
                    })
                    .collect();
                requests.extend(delete(&targets, None).requests);
                Fix {
                    label: FixLabel::ReplaceNs {
                        zone: zone.name.clone(),
                        dcs: self.dc_list(),
                    },
                    requests,
                }
            });
            for (target, (_, e)) in targets.iter().zip(&wrong) {
                let name = target_of(e).unwrap_or_else(|| "?".into());
                let fix = if replace {
                    common.clone()
                } else {
                    Some(delete(
                        std::slice::from_ref(target),
                        Some(FixLabel::RemoveNs {
                            target: name.clone(),
                        }),
                    ))
                };
                let internal = zone.name.starts_with("..");
                self.add(Anomaly {
                    rule: Rule::NsOutsideDc,
                    severity: if internal {
                        Severity::Information
                    } else {
                        Severity::Critical
                    },
                    title: Title::NsNotDc {
                        target: name.clone(),
                    },
                    explanation: Explanation::NsNotDc {
                        name: target.fqdn(),
                        target: name,
                        dcs: self.dc_list(),
                        only_server: replace && !n.is_root(),
                        internal_zone: internal.then(|| zone.name.clone()),
                    },
                    targets: vec![target.clone()],
                    fix,
                });
            }
        }
    }

    // -- 2. DC locator ------------------------------------------------------

    fn locator(&self, full: &str) -> bool {
        let name = full.to_lowercase();
        let suffixes: HashSet<&String> = [&self.state.domain, &self.state.forest].into();
        for suffix in suffixes {
            if let Some(head) = name.strip_suffix(&format!(".{suffix}")) {
                let labels: Vec<&str> = head.split('.').collect();
                let service = labels.iter().take(2).copied().collect::<Vec<_>>().join(".");
                let rest = labels.iter().skip(2).copied().collect::<Vec<_>>().join(".");
                if DC_SERVICES.contains(&service.as_str()) && locator_rest(&rest) {
                    return true;
                }
            }
        }
        false
    }

    fn removed_dcs(&mut self) {
        if self.dcs.is_empty() {
            return;
        }
        let forward = self.index.forward.clone();
        for (zone, n) in self.nodes(forward) {
            if n.tombstone {
                continue;
            }
            let full = n.fqdn();
            let low = full.to_lowercase();
            for (v, e) in values(n) {
                let target = Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v),
                };
                let aim = target_of(&e).unwrap_or_default();
                if e.rtype == dns_record::SRV && self.locator(&full) && !self.dcs.contains(&aim) {
                    let labels: Vec<&str> = low.split('.').collect();
                    let missing_site = labels
                        .iter()
                        .position(|l| *l == "_sites")
                        .and_then(|i| i.checked_sub(1))
                        .and_then(|i| labels.get(i))
                        .filter(|site| !self.state.sites.contains(**site))
                        .map(|site| (*site).to_owned());
                    let fix = delete(std::slice::from_ref(&target), None);
                    self.add(Anomaly {
                        rule: Rule::RemovedDc,
                        severity: Severity::Critical,
                        title: Title::SrvNotDc {
                            name: full.clone(),
                            target: aim.clone(),
                        },
                        explanation: Explanation::SrvNotDc {
                            target: aim,
                            dcs: self.dc_list(),
                            missing_site,
                        },
                        targets: vec![target],
                        fix: Some(fix),
                    });
                } else if e.rtype == dns_record::CNAME
                    && low.ends_with(&format!("._msdcs.{}", self.state.forest))
                    && low.split('.').next().is_some_and(is_guid)
                    && low.matches('.').count() == self.state.forest.matches('.').count() + 2
                    && low
                        .split('.')
                        .next()
                        .is_some_and(|g| !self.guids.contains(g))
                {
                    let fix = delete(std::slice::from_ref(&target), None);
                    self.add(Anomaly {
                        rule: Rule::RemovedDc,
                        severity: Severity::Critical,
                        title: Title::ReplicationCname {
                            target: aim.clone(),
                        },
                        explanation: Explanation::ReplicationCname {
                            name: full.clone(),
                            target: aim,
                        },
                        targets: vec![target],
                        fix: Some(fix),
                    });
                }
            }
        }
    }

    // -- 3. A of the root and of the partitions --------------------------------

    fn values_of(&self, zone: &Zone, name: &str) -> Vec<(&'a Node, Vec<u8>, Record)> {
        self.index
            .live
            .get(&(zone.dn.to_lowercase(), name.to_lowercase()))
            .into_iter()
            .flatten()
            .flat_map(|n| values(n).into_iter().map(move |(v, e)| (*n, v, e)))
            .collect()
    }

    fn specials(&self) -> HashSet<String> {
        let (domain, forest) = (&self.state.domain, &self.state.forest);
        [
            domain.clone(),
            forest.clone(),
            format!("domaindnszones.{domain}"),
            format!("forestdnszones.{forest}"),
            format!("gc._msdcs.{forest}"),
        ]
        .into()
    }

    fn roots(&mut self) {
        if self.dcs.is_empty() {
            return;
        }
        if self.all_dc.is_empty() {
            self.remarks.push(HealthRemark::NoDcAddresses);
            return;
        }
        let (domain, forest) = (self.state.domain.clone(), self.state.forest.clone());
        let names = [
            (domain.clone(), self.all_dc.clone(), false),
            (
                format!("domaindnszones.{domain}"),
                self.all_dc.clone(),
                false,
            ),
            (forest.clone(), self.all_dc.clone(), false),
            (
                format!("forestdnszones.{forest}"),
                self.all_dc.clone(),
                false,
            ),
            (format!("gc._msdcs.{forest}"), self.catalogs.clone(), true),
        ];
        let mut seen = HashSet::new();
        for (full, allowed, gc) in names {
            if !seen.insert(full.clone()) {
                continue;
            }
            let Some((zone, relative)) = self.index.locate(&full) else {
                continue;
            };
            let mut present = HashSet::new();
            for (n, v, e) in self.values_of(zone, &relative) {
                let RecordData::Address(address) = e.data else {
                    continue;
                };
                if e.rtype != dns_record::A && e.rtype != dns_record::AAAA {
                    continue;
                }
                present.insert(address);
                if allowed.contains(&address) {
                    continue;
                }
                let target = Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v),
                };
                if !self.free(&target) {
                    continue;
                }
                let fix = delete(std::slice::from_ref(&target), None);
                self.add(Anomaly {
                    rule: Rule::AOutsideDc,
                    severity: Severity::Critical,
                    title: Title::ANotDc {
                        name: full.clone(),
                        address: address.to_string(),
                    },
                    explanation: Explanation::ANotDc {
                        name: full.clone(),
                        catalog: gc,
                        allowed: list(allowed.iter().map(ToString::to_string)),
                        address: address.to_string(),
                    },
                    targets: vec![target],
                    fix: Some(fix),
                });
            }
            let state = self.state;
            let any_catalog = state.controllers.iter().any(|c| c.catalog);
            for c in &state.controllers {
                if gc && !c.catalog && any_catalog {
                    continue;
                }
                let theirs = self.dc_addresses.get(&c.name).cloned().unwrap_or_default();
                if theirs.is_empty() || !theirs.is_disjoint(&present) {
                    continue;
                }
                let mut addresses: Vec<IpAddr> = theirs.into_iter().collect();
                addresses.sort();
                let fix = match addresses.as_slice() {
                    [only] => Some(Fix {
                        label: FixLabel::AddAddress {
                            address: only.to_string(),
                            name: full.clone(),
                        },
                        requests: vec![Request::Add {
                            zone: zone.clone(),
                            name: relative.clone(),
                            rtype: if only.is_ipv4() {
                                dns_record::A
                            } else {
                                dns_record::AAAA
                            },
                            data: RecordData::Address(*only),
                            ttl: DEFAULT_TTL,
                        }],
                    }),
                    _ => None,
                };
                let anomaly = Anomaly {
                    rule: Rule::MissingDc,
                    severity: Severity::Warning,
                    title: Title::DcMissingFrom {
                        dc: c.name.clone(),
                        name: full.clone(),
                    },
                    explanation: Explanation::DcMissing {
                        dc: c.name.clone(),
                        addresses: list(addresses.iter().map(ToString::to_string)),
                        name: full.clone(),
                    },
                    targets: vec![Target {
                        zone: zone.clone(),
                        name: relative.clone(),
                        value: None,
                    }],
                    fix,
                };
                self.add(anomaly);
            }
        }
    }

    // -- 4. Vanished hosts ---------------------------------------------------------

    fn ptr_to(&self) -> PtrTo<'a> {
        let mut out: PtrTo<'a> = HashMap::new();
        let reverse: Vec<&'a Zone> = self.state.zones.iter().filter(|z| z.reverse()).collect();
        for (zone, n) in self.nodes(reverse) {
            if n.tombstone {
                continue;
            }
            for (v, e) in values(n) {
                if e.rtype == dns_record::PTR {
                    if let Some(aim) = target_of(&e) {
                        out.entry(aim).or_default().push((zone.clone(), n, v));
                    }
                }
            }
        }
        out
    }

    fn hosts(&mut self, ptr_to: &PtrTo<'a>) {
        let known: HashSet<String> = self
            .state
            .computers
            .iter()
            .chain(&self.dcs)
            .cloned()
            .collect();
        let specials = self.specials();
        let forward = self.index.forward.clone();
        for (zone, n) in self.nodes(forward) {
            let full = n.fqdn().to_lowercase();
            if n.tombstone
                || known.contains(&full)
                || specials.contains(&full)
                || n.name.starts_with('_')
            {
                continue;
            }
            let addresses: Vec<(Vec<u8>, Record)> = values(n)
                .into_iter()
                .filter(|(_, e)| e.rtype == dns_record::A || e.rtype == dns_record::AAAA)
                .collect();
            let dynamic: Vec<&(Vec<u8>, Record)> =
                addresses.iter().filter(|(_, e)| !e.is_static()).collect();
            let statics: Vec<&(Vec<u8>, Record)> =
                addresses.iter().filter(|(_, e)| e.is_static()).collect();
            let at = |v: &Vec<u8>| Target {
                zone: zone.clone(),
                name: n.name.clone(),
                value: Some(v.clone()),
            };
            if !dynamic.is_empty() {
                let mut targets: Vec<Target> = dynamic.iter().map(|(v, _)| at(v)).collect();
                for (z, p, v) in ptr_to.get(&full).into_iter().flatten() {
                    let t = Target {
                        zone: z.clone(),
                        name: p.name.clone(),
                        value: Some(v.clone()),
                    };
                    if self.free(&t) {
                        targets.push(t);
                    }
                }
                let last = dynamic
                    .iter()
                    .filter_map(|(_, e)| record_date(e))
                    .max()
                    .map_or_else(|| "?".to_owned(), day);
                let fix = delete(&targets, None);
                self.add(Anomaly {
                    rule: Rule::VanishedHost,
                    severity: Severity::Warning,
                    title: Title::HostWithoutAccount { name: n.fqdn() },
                    explanation: Explanation::Host {
                        name: n.fqdn(),
                        date: last,
                        ptrs: targets.len() - dynamic.len(),
                    },
                    targets,
                    fix: Some(fix),
                });
            } else if !statics.is_empty() && self.settings.statics {
                let targets: Vec<Target> = statics.iter().map(|(v, _)| at(v)).collect();
                let fix = delete(&targets, None);
                self.add(Anomaly {
                    rule: Rule::VanishedHost,
                    severity: Severity::Information,
                    title: Title::StaticWithoutAccount { name: n.fqdn() },
                    explanation: Explanation::Static { name: n.fqdn() },
                    targets,
                    fix: Some(fix),
                });
            }
        }
    }

    // -- 5. PTR ------------------------------------------------------------------

    fn ptr(&mut self) {
        let reverse: Vec<&'a Zone> = self.state.zones.iter().filter(|z| z.reverse()).collect();
        for (zone, n) in self.nodes(reverse) {
            if n.tombstone {
                continue;
            }
            let address = address_of_ptr(&n.fqdn());
            for (v, e) in values(n) {
                let target = Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v),
                };
                let Some(aim) = target_of(&e) else {
                    continue;
                };
                if e.rtype != dns_record::PTR || !self.free(&target) {
                    continue;
                }
                let Some(addresses) = self.index.addresses(&aim) else {
                    continue; // name outside the zones of the directory: not judged
                };
                let shown = address.map_or_else(|| n.fqdn(), |a| a.to_string());
                if addresses.is_empty() {
                    let fix = delete(std::slice::from_ref(&target), None);
                    self.add(Anomaly {
                        rule: Rule::PtrWithoutName,
                        severity: Severity::Warning,
                        title: Title::PtrToNothing {
                            name: shown.clone(),
                            target: aim.clone(),
                        },
                        explanation: Explanation::PtrToNothing {
                            address: shown,
                            target: aim,
                        },
                        targets: vec![target],
                        fix: Some(fix),
                    });
                } else if let Some(a) = address.filter(|a| !addresses.contains(a)) {
                    let fix = delete(std::slice::from_ref(&target), None);
                    self.add(Anomaly {
                        rule: Rule::InconsistentPtr,
                        severity: Severity::Warning,
                        title: Title::PtrOtherAddress {
                            address: a.to_string(),
                            target: aim.clone(),
                        },
                        explanation: Explanation::PtrOtherAddress {
                            address: a.to_string(),
                            target: aim,
                            theirs: list(addresses.iter().map(ToString::to_string)),
                        },
                        targets: vec![target],
                        fix: Some(fix),
                    });
                }
            }
        }
    }

    // -- 6. Missing targets ----------------------------------------------------------

    fn targets(&mut self) {
        let forward = self.index.forward.clone();
        for (zone, n) in self.nodes(forward) {
            if n.tombstone {
                continue;
            }
            for (v, e) in values(n) {
                let target = Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v),
                };
                let aim = target_of(&e).unwrap_or_default();
                if ![dns_record::CNAME, dns_record::SRV, dns_record::MX].contains(&e.rtype)
                    || aim.is_empty()
                    || !self.free(&target)
                {
                    continue;
                }
                if self.dcs.contains(&aim) {
                    continue; // the name of a DC is its own business (MissingDc, locator)
                }
                let missing = if e.rtype == dns_record::CNAME {
                    self.index.exists(&aim) == Some(false)
                } else {
                    self.index.addresses(&aim).is_some_and(|a| a.is_empty())
                };
                if !missing {
                    continue;
                }
                let fix = delete(std::slice::from_ref(&target), None);
                self.add(Anomaly {
                    rule: Rule::MissingTarget,
                    severity: Severity::Warning,
                    title: Title::TargetMissing {
                        rtype: e.type_name(),
                        name: n.fqdn(),
                        target: aim.clone(),
                    },
                    explanation: Explanation::TargetMissing {
                        name: n.fqdn(),
                        target: aim,
                        address: e.rtype != dns_record::CNAME,
                    },
                    targets: vec![target],
                    fix: Some(fix),
                });
            }
        }
    }

    // -- 7. Not refreshed ---------------------------------------------------------------

    /// Age (seconds) past which a dynamic record of the zone is no longer refreshed, and
    /// what the aging of the zone says (`seuil`).
    fn threshold(&self, zone: &Zone) -> (i64, Aging) {
        let days = self.settings.days.saturating_mul(DAY);
        let s = &zone.settings;
        if let (Some(true), Some(no_refresh), Some(refresh)) =
            (s.aging, s.no_refresh_interval, s.refresh_interval)
        {
            let hours = i64::try_from(no_refresh.saturating_add(refresh)).unwrap_or(i64::MAX);
            let seconds = hours.saturating_mul(3600);
            return (
                days.max(seconds),
                Aging::Enabled {
                    days: seconds.div_euclid(DAY),
                },
            );
        }
        (days, Aging::Disabled)
    }

    /// Names the DCs register themselves (root, partitions, `_msdcs`, locator, their own
    /// names): Samba does not refresh their timestamp (`_tenu_par_les_dc`).
    fn held_by_dcs(&self, n: &Node) -> bool {
        let full = n.fqdn().to_lowercase();
        self.specials().contains(&full)
            || self.dcs.contains(&full)
            || full.ends_with(&format!("._msdcs.{}", self.state.forest))
            || self.locator(&full)
    }

    fn age(&self, date: UtcTime) -> i64 {
        self.now.seconds_since(date)
    }

    fn not_refreshed(&mut self) {
        let mut zones = self.index.forward.clone();
        let reverse: Vec<&'a Zone> = self.state.zones.iter().filter(|z| z.reverse()).collect();
        zones.extend(reverse);
        for (zone, n) in self.nodes(zones) {
            if n.tombstone || self.held_by_dcs(n) {
                continue;
            }
            let (threshold, aging) = self.threshold(zone);
            let mut old: Vec<(Target, UtcTime)> = Vec::new();
            let mut in_service: BTreeMap<String, Vec<(Target, UtcTime)>> = BTreeMap::new();
            for (v, e) in values(n) {
                let target = Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v),
                };
                let Some(date) = record_date(&e) else {
                    continue;
                };
                if !self.free(&target) || self.age(date) <= threshold {
                    continue;
                }
                let machine = if e.rtype == dns_record::PTR {
                    target_of(&e).unwrap_or_default()
                } else {
                    n.fqdn().to_lowercase()
                };
                match self.state.activity.get(&machine) {
                    Some(seen) if self.age(*seen) <= threshold => {
                        in_service.entry(machine).or_default().push((target, date));
                    }
                    _ => old.push((target, date)),
                }
            }
            for (machine, items) in in_service {
                self.in_service(n, &machine, items);
            }
            let Some(recent) = old.iter().map(|(_, d)| *d).max() else {
                continue;
            };
            let targets: Vec<Target> = old.into_iter().map(|(t, _)| t).collect();
            let fix = delete(&targets, None);
            self.add(Anomaly {
                rule: Rule::NotRefreshed,
                severity: Severity::Warning,
                title: Title::NotRefreshed {
                    name: n.fqdn(),
                    days: self.age(recent).div_euclid(DAY),
                },
                explanation: Explanation::NotRefreshed {
                    name: n.fqdn(),
                    date: day(recent),
                    threshold: threshold.div_euclid(DAY),
                    aging,
                },
                targets,
                fix: Some(fix),
            });
        }
    }

    /// Old dynamic name of a computer that is active all the same: it still serves.
    fn in_service(&mut self, n: &Node, machine: &str, items: Vec<(Target, UtcTime)>) {
        let Some(recent) = items.iter().map(|(_, d)| *d).max() else {
            return;
        };
        let seen = self.state.activity.get(machine).copied().unwrap_or(recent);
        self.add(Anomaly {
            rule: Rule::NotRefreshed,
            severity: Severity::Information,
            title: Title::NotRefreshedInService {
                name: n.fqdn(),
                days: self.age(recent).div_euclid(DAY),
            },
            explanation: Explanation::InService {
                machine: machine.into(),
                name: n.fqdn(),
                date: day(recent),
                seen: day(seen),
            },
            targets: items.into_iter().map(|(t, _)| t).collect(),
            fix: None,
        });
    }

    // -- 8. Without PTR -------------------------------------------------------------------

    fn without_ptr(&mut self, ptr_to: &PtrTo<'a>) {
        if self.index.reverse.is_empty() {
            return;
        }
        let known: HashSet<String> = self
            .state
            .computers
            .iter()
            .chain(&self.dcs)
            .cloned()
            .collect();
        let forward = self.index.forward.clone();
        for (zone, n) in self.nodes(forward) {
            let full = n.fqdn().to_lowercase();
            if n.tombstone || !known.contains(&full) {
                continue;
            }
            for (v, e) in values(n) {
                let RecordData::Address(address) = e.data else {
                    continue;
                };
                if e.rtype != dns_record::A && e.rtype != dns_record::AAAA {
                    continue;
                }
                let target = Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: Some(v),
                };
                if !self.free(&target) {
                    continue;
                }
                // A workstation registers its PTR itself if it can, and its absence is
                // common and harmless; it matters for a DC or a server with a fixed address.
                if !e.is_static() && !self.dcs.contains(&full) {
                    continue;
                }
                let Some((reverse, relative)) = reverse_zone(&self.index.reverse, address) else {
                    continue;
                };
                if ptr_to
                    .get(&full)
                    .into_iter()
                    .flatten()
                    .any(|(_, p, _)| address_of_ptr(&p.fqdn()) == Some(address))
                {
                    continue;
                }
                self.add(Anomaly {
                    rule: Rule::WithoutPtr,
                    severity: Severity::Information,
                    title: Title::WithoutPtr {
                        name: n.fqdn(),
                        address: address.to_string(),
                    },
                    explanation: Explanation::WithoutPtr {
                        zone: reverse.name.clone(),
                        address: address.to_string(),
                        name: n.fqdn(),
                    },
                    targets: vec![target],
                    fix: Some(Fix {
                        label: FixLabel::AddPtr {
                            address: address.to_string(),
                            name: n.fqdn(),
                        },
                        requests: vec![Request::Add {
                            zone: reverse,
                            name: relative,
                            rtype: dns_record::PTR,
                            data: RecordData::Name(n.fqdn()),
                            ttl: DEFAULT_TTL,
                        }],
                    }),
                });
            }
        }
    }

    // -- 10. SOA ----------------------------------------------------------------------

    fn soa(&mut self) {
        if self.dcs.is_empty() {
            return;
        }
        for (zone, n) in self.nodes(self.zones()) {
            if !n.is_root() || n.tombstone {
                continue;
            }
            for (v, e) in values(n) {
                let RecordData::Soa { primary_server, .. } = &e.data else {
                    continue;
                };
                let server = primary_server
                    .to_lowercase()
                    .trim_end_matches('.')
                    .to_owned();
                if self.is_dc(&server) {
                    continue;
                }
                self.add(Anomaly {
                    rule: Rule::SoaOutsideDc,
                    severity: Severity::Information,
                    title: Title::SoaNotDc {
                        zone: zone.name.clone(),
                        server: server.clone(),
                    },
                    explanation: Explanation::SoaNotDc {
                        zone: zone.name.clone(),
                        server,
                        dcs: self.dc_list(),
                    },
                    targets: vec![Target {
                        zone: zone.clone(),
                        name: n.name.clone(),
                        value: Some(v),
                    }],
                    fix: None,
                });
            }
        }
    }

    // -- 11. Duplicate zones ------------------------------------------------------------

    fn duplicate_zones(&mut self) {
        let mut by_name: Vec<(String, Vec<&Zone>)> = Vec::new();
        for zone in &self.state.zones {
            let low = zone.name.to_lowercase();
            match by_name.iter_mut().find(|(n, _)| *n == low) {
                Some((_, copies)) => copies.push(zone),
                None => by_name.push((low, vec![zone])),
            }
        }
        for (_, copies) in by_name {
            if copies.len() < 2 {
                continue;
            }
            let root = copies.iter().all(|z| z.root_hints());
            if root && copies.len() == 2 && copies.iter().any(|z| z.partition == Partition::Legacy)
            {
                continue; // original state of a Windows forest, not a leftover
            }
            let Some(first) = copies.first() else {
                continue;
            };
            self.add(Anomaly {
                rule: Rule::DuplicateZone,
                severity: if root {
                    Severity::Information
                } else {
                    Severity::Critical
                },
                title: Title::DuplicateZone {
                    zone: first.name.clone(),
                    n: copies.len(),
                },
                explanation: Explanation::DuplicateZone {
                    zone: first.name.clone(),
                    places: list(copies.iter().map(|z| z.partition.value().to_owned())),
                    root_hints: root,
                },
                targets: copies
                    .iter()
                    .map(|z| Target {
                        zone: (*z).clone(),
                        name: ROOT.into(),
                        value: None,
                    })
                    .collect(),
                fix: None,
            });
        }
    }

    // -- 9. Old tombstones ---------------------------------------------------------

    fn tombstones(&mut self) {
        let threshold = self.settings.tombstone_days.saturating_mul(DAY);
        for (zone, n) in self.nodes(self.zones()) {
            if !n.tombstone {
                continue;
            }
            let dates: Vec<UtcTime> = n
                .records()
                .iter()
                .filter_map(|e| match e.data {
                    RecordData::Tombstone(nttime) => i64::try_from(nttime)
                        .ok()
                        .and_then(|t| time::nttime_to_utc(t).ok().flatten()),
                    _ => None,
                })
                .collect();
            let Some(since) = dates.into_iter().max().or(n.modified) else {
                continue;
            };
            if self.age(since) <= threshold {
                continue;
            }
            self.add(Anomaly {
                rule: Rule::OldTombstone,
                severity: Severity::Information,
                title: Title::OldTombstone {
                    name: n.fqdn(),
                    days: self.age(since).div_euclid(DAY),
                },
                explanation: Explanation::OldTombstone {
                    name: n.fqdn(),
                    date: day(since),
                    threshold: self.settings.tombstone_days,
                },
                targets: vec![Target {
                    zone: zone.clone(),
                    name: n.name.clone(),
                    value: None,
                }],
                fix: Some(Fix {
                    label: FixLabel::Purge,
                    requests: vec![Request::Purge {
                        zone: zone.clone(),
                        name: n.name.clone(),
                    }],
                }),
            });
        }
    }

    fn all(&mut self) {
        self.duplicate_zones();
        self.ns();
        self.soa();
        self.removed_dcs();
        self.roots();
        let ptr_to = self.ptr_to();
        self.hosts(&ptr_to);
        self.ptr();
        self.targets();
        self.not_refreshed();
        self.without_ptr(&ptr_to);
        self.tombstones();
    }
}

/// Anomalies of the state read (pure, without network) (`diagnostiquer`). Order: severity
/// from the highest, then rule, then name.
pub fn diagnose(state: &DnsState, settings: Settings, now: Option<UtcTime>) -> Diagnosis {
    let now = now.unwrap_or_else(self::now);
    let mut x = Diagnostician::new(state, settings, now);
    x.all();
    let mut anomalies = std::mem::take(&mut x.anomalies);
    anomalies.sort_by_key(|a| {
        (
            std::cmp::Reverse(a.severity),
            a.rule,
            a.targets
                .first()
                .map(|t| t.fqdn().to_lowercase())
                .unwrap_or_default(),
        )
    });
    Diagnosis {
        anomalies,
        settings,
        now,
        zones: state.zones.iter().filter(|z| !z.root_hints()).count(),
        nodes: state.nodes.values().map(Vec::len).sum(),
        records: state.nodes.values().flatten().map(|n| n.values.len()).sum(),
        remarks: x.remarks,
    }
}

/// Requests of the fixes of several anomalies, without duplicate (order kept) (`demandes`).
pub fn requests<'a>(anomalies: impl IntoIterator<Item = &'a Anomaly>) -> Vec<Request> {
    let mut out: Vec<Request> = Vec::new();
    for a in anomalies {
        for r in a.fix.iter().flat_map(|f| &f.requests) {
            if !out.contains(r) {
                out.push(r.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;

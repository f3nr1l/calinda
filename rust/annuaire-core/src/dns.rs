// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS zones integrated in the directory: reading (J3.3, `annuaire.core.dns`).
//!
//! A zone is a `dnsZone` object; each of its names is a `dnsNode` placed **directly** under
//! it, whatever the number of labels of the name (`DC=_ldap._tcp.dc._msdcs,DC=lab.test,…`);
//! the root of the zone is the node `@`. The zones live in three places (MS-DNSP 2.3.1):
//!
//! - `CN=MicrosoftDNS,DC=DomainDnsZones,<domain>`: replicated on the DCs of the domain;
//! - `CN=MicrosoftDNS,DC=ForestDnsZones,<forest root>`: on every DC of the forest
//!   (`_msdcs.<forest>`);
//! - `CN=MicrosoftDNS,CN=System,<domain>`: historical place (Windows 2000), in the domain
//!   partition.
//!
//! The nodes are always read on the DC, never in the local copy (ADR 0010, 7). As for the
//! objects of the directory, the entries are decoded by the consumer ([`NodePages`] gives
//! raw entries), and the `dnsRecord` values of a node are decoded only when read
//! ([`Node::records`]).

use std::sync::Arc;

use annuaire_codecs::dns_property::ZoneSettings;
use annuaire_codecs::dns_record::{self, Record};
use annuaire_codecs::time::{self, UtcTime};

use crate::connection::{Connection, Failure, Link};
use crate::dn;
use crate::error::{LdapError, code};
use crate::rootdse::RootDse;
use crate::search::{self, Flux, PAGE_SIZE, Search, SearchError};
use crate::session::{Entry, Scope, SearchRequest};

pub const ZONE_ATTRIBUTES: [&str; 3] = ["name", "dNSProperty", "whenChanged"];
pub const NODE_ATTRIBUTES: [&str; 4] = ["name", "dnsRecord", "dNSTombstoned", "whenChanged"];
pub const ZONES_FILTER: &str = "(objectClass=dnsZone)";
pub const NODES_FILTER: &str = "(objectClass=dnsNode)";
/// Any object under the zone: a node whose attributes the account cannot read
/// (`objectClass` included) would not come out of [`NODES_FILTER`], while the directory
/// shows that it exists ([`Node::unreadable`]).
pub const NAMES_FILTER: &str = "(objectClass=*)";
/// Name of the node that holds the records of the zone itself (SOA, NS…).
pub const ROOT: &str = "@";
/// « Zone » of the root hints (root servers of the Internet).
pub const ROOT_HINTS: &str = "RootDNSServers";
/// Pages waiting in a flux of nodes.
const CAPACITY: usize = 4;

/// Where a zone lives (`Partition`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Partition {
    Domain,
    Forest,
    Legacy,
}

impl Partition {
    /// The value of the Python enumeration (`DomainDnsZones`, `ForestDnsZones`, `System`).
    pub fn value(self) -> &'static str {
        match self {
            Self::Domain => "DomainDnsZones",
            Self::Forest => "ForestDnsZones",
            Self::Legacy => "System",
        }
    }
}

/// A container of zones (`Emplacement`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub partition: Partition,
    /// DN of the `CN=MicrosoftDNS` container under which the zones are.
    pub base: String,
}

/// The three containers of the zones, in the order of display (`emplacements`).
pub fn locations(root: &RootDse) -> Vec<Location> {
    let domain = &root.default_naming_context;
    let forest = if root.root_domain_naming_context.is_empty() {
        domain
    } else {
        &root.root_domain_naming_context
    };
    vec![
        Location {
            partition: Partition::Domain,
            base: format!("CN=MicrosoftDNS,DC=DomainDnsZones,{domain}"),
        },
        Location {
            partition: Partition::Forest,
            base: format!("CN=MicrosoftDNS,DC=ForestDnsZones,{forest}"),
        },
        Location {
            partition: Partition::Legacy,
            base: format!("CN=MicrosoftDNS,CN=System,{domain}"),
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    pub dn: String,
    pub name: String,
    pub partition: Partition,
    pub settings: ZoneSettings,
    pub modified: Option<UtcTime>,
}

impl Zone {
    pub fn root_hints(&self) -> bool {
        self.name.eq_ignore_ascii_case(ROOT_HINTS)
    }

    /// A reverse zone (`in-addr.arpa`, `ip6.arpa`), root hints excepted.
    pub fn reverse(&self) -> bool {
        let name = self.name.to_lowercase();
        !self.root_hints() && (name.ends_with("in-addr.arpa") || name.ends_with("ip6.arpa"))
    }
}

/// A name of the zone (`dnsNode`) and its own records only: never those of the names below,
/// which are other nodes (`NoeudDns`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub dn: String,
    /// Relative to the zone (`dc1`, `_ldap._tcp.dc._msdcs`), `@` for the root of the zone.
    pub name: String,
    pub zone: String,
    /// Raw values of `dnsRecord`.
    pub values: Vec<Vec<u8>>,
    pub tombstone: bool,
    pub modified: Option<UtcTime>,
    /// The object shows but the account reads none of its attributes (rights): its records
    /// are unknown, which does not mean it has none. With Samba, for an ordinary account,
    /// the nodes a machine registered itself by secure dynamic update, DCs included
    /// (seen on example.local on 2026-10-14).
    pub unreadable: bool,
}

impl Node {
    pub fn is_root(&self) -> bool {
        self.name == ROOT
    }

    pub fn fqdn(&self) -> String {
        fqdn(&self.zone, &self.name)
    }

    /// Labels of the relative name, from the closest to the zone to the leaf; empty for `@`.
    pub fn labels(&self) -> Vec<&str> {
        if self.is_root() {
            Vec::new()
        } else {
            self.name.split('.').rev().collect()
        }
    }

    /// Records decoded, in the order of the directory; a value whose header does not read
    /// is left out ([`Node::unreadable_values`]).
    pub fn records(&self) -> Vec<Record> {
        self.values
            .iter()
            .filter_map(|v| Record::decode(v).ok())
            .collect()
    }

    pub fn unreadable_values(&self) -> usize {
        self.values
            .iter()
            .filter(|v| Record::decode(v).is_err())
            .count()
    }
}

/// Full name of a name relative to the zone.
pub fn fqdn(zone: &str, name: &str) -> String {
    if name == ROOT {
        zone.to_owned()
    } else {
        format!("{name}.{zone}")
    }
}

/// Type of a raw value (`-1` if too short), without decoding it.
pub fn value_type(value: &[u8]) -> i32 {
    match value.get(2..4) {
        Some(&[a, b]) => i32::from(u16::from_le_bytes([a, b])),
        _ => -1,
    }
}

fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

fn date(entry: &Entry) -> Option<UtcTime> {
    let t = text(entry, "whenChanged");
    if t.is_empty() {
        return None;
    }
    time::decode_generalized_time(&t).ok()
}

fn name(entry: &Entry) -> String {
    let n = text(entry, "name");
    if !n.is_empty() {
        return n;
    }
    match dn::split(&entry.dn) {
        Ok(components) => components
            .first()
            .map_or_else(|| entry.dn.clone(), |c| c.value.clone()),
        Err(_) => entry.dn.clone(),
    }
}

pub fn zone_from_entry(entry: &Entry, partition: Partition) -> Zone {
    Zone {
        dn: entry.dn.clone(),
        name: name(entry),
        partition,
        settings: ZoneSettings::from_values(entry.values("dNSProperty").iter().map(Vec::as_slice)),
        modified: date(entry),
    }
}

/// A node of a zone (`noeud_depuis_entree`). A tombstone if `dNSTombstoned` is true, or if
/// all its records are of type 0 (form written by the dynamic updates). Without any attribute
/// received, unreadable for the account ([`Node::unreadable`]).
pub fn node_from_entry(entry: &Entry, zone: &str) -> Node {
    if entry.attributes.is_empty() {
        return Node {
            dn: entry.dn.clone(),
            name: name(entry),
            zone: zone.to_owned(),
            values: Vec::new(),
            tombstone: false,
            modified: None,
            unreadable: true,
        };
    }
    let values = entry.values("dnsRecord").to_vec();
    let tombstone = text(entry, "dNSTombstoned").eq_ignore_ascii_case("TRUE")
        || (!values.is_empty()
            && values
                .iter()
                .all(|v| v.len() >= 4 && value_type(v) == i32::from(dns_record::TOMBSTONE)));
    Node {
        dn: entry.dn.clone(),
        name: name(entry),
        zone: zone.to_owned(),
        values,
        tombstone,
        modified: date(entry),
        unreadable: false,
    }
}

/// Every zone of the three places, on the thread of the connection (`lire_zones`); a place
/// that does not exist (no DNS partition, no historical place) is skipped. Order: place,
/// then name, the root hints last.
pub fn read_zones(link: &mut Link) -> Result<Vec<Zone>, LdapError> {
    let mut zones = Vec::new();
    for location in locations(&link.state.root_dse) {
        let request = SearchRequest {
            base: location.base.clone(),
            scope: Scope::OneLevel,
            filter: ZONES_FILTER.to_owned(),
            attributes: ZONE_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect(),
            controls: Vec::new(),
            size_limit: 0,
        };
        let entries = match link.session.search_wait(request, Some(link.timeout)) {
            Ok(response) => response.into_entries(),
            Err(e) if e.code == code::NO_SUCH_OBJECT => continue,
            Err(e) => return Err(e),
        };
        let mut found: Vec<Zone> = entries
            .iter()
            .map(|e| zone_from_entry(e, location.partition))
            .collect();
        found.sort_by_key(|z| (z.root_hints(), z.name.to_lowercase()));
        zones.extend(found);
    }
    Ok(zones)
}

/// The zones, read on the DC of the connection. Blocking.
pub fn zones(connection: &Connection) -> Result<Vec<Zone>, Failure> {
    connection.run(true, read_zones)
}

/// Raw entries of the names of a zone, page by page: [`node_from_entry`] decodes them.
pub type NodePages = Flux<Vec<Entry>, SearchError>;

/// Every object under the zone ([`NAMES_FILTER`]), with [`NODE_ATTRIBUTES`], in pages on
/// the connection (`noeuds_dns`).
pub fn search_nodes(
    connection: &Connection,
    zone: &Zone,
    notifier: Option<Box<dyn Fn() + Send + Sync>>,
) -> NodePages {
    let flux = NodePages::new(CAPACITY, notifier);
    let request = Search {
        base: zone.dn.clone(),
        scope: Scope::OneLevel,
        filter: NAMES_FILTER.to_owned(),
        attributes: NODE_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect(),
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls: Vec::new(),
    };
    search::search(&connection.submitter(), request, Arc::new(flux.clone()));
    flux
}

/// DN of a `dnsNode`: `DC=<name>,DC=<zone>,CN=MicrosoftDNS,…` (`est_noeud_dns`).
pub fn is_node(dn_text: &str) -> bool {
    let Ok(c) = dn::split(dn_text) else {
        return false;
    };
    matches!(
        c.as_slice(),
        [name, zone, container, ..]
            if name.attribute.eq_ignore_ascii_case("DC")
                && zone.attribute.eq_ignore_ascii_case("DC")
                && container.attribute.eq_ignore_ascii_case("CN")
                && container.value.eq_ignore_ascii_case("MicrosoftDNS")
    )
}

/// DN of the node `name` of the zone `zone_dn`.
pub fn node_dn(zone_dn: &str, name: &str) -> String {
    let rdn =
        dn::compose(&[dn::Component::new("DC", name)]).unwrap_or_else(|_| format!("DC={name}"));
    format!("{rdn},{zone_dn}")
}

/// Name (first component) and zone (second component) of a node DN.
pub fn node_parts(dn_text: &str) -> Option<(String, String)> {
    let c = dn::split(dn_text).ok()?;
    Some((c.first()?.value.clone(), c.get(1)?.value.clone()))
}

/// The nodes read again on the connection (the DC that received the write): (DN, node or
/// None if it no longer exists) (`relire_noeuds`). Blocking.
pub fn reread_nodes(
    connection: &Connection,
    dns: &[String],
) -> Result<Vec<(String, Option<Node>)>, Failure> {
    let list: Vec<String> = dns.iter().filter(|d| is_node(d)).cloned().collect();
    connection.run(true, move |link| {
        let attributes: Vec<String> = NODE_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect();
        let mut out = Vec::with_capacity(list.len());
        for d in &list {
            let entry = search::read_entry(
                link.session.as_mut(),
                d,
                &attributes,
                NAMES_FILTER,
                None,
                Some(link.timeout),
            )?;
            let zone = node_parts(d).map(|(_, z)| z).unwrap_or_default();
            out.push((d.clone(), entry.map(|e| node_from_entry(&e, &zone))));
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use annuaire_codecs::dns_record::RecordData;

    fn entry(dn_text: &str, attributes: &[(&str, Vec<Vec<u8>>)]) -> Entry {
        Entry {
            dn: dn_text.into(),
            attributes: attributes
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect(),
        }
    }

    fn a(address: &str) -> Vec<u8> {
        Record::new(dns_record::A, RecordData::Address(address.parse().unwrap()))
            .encode()
            .unwrap()
    }

    #[test]
    fn places_and_nodes() {
        let root = RootDse {
            default_naming_context: "DC=lab,DC=test".into(),
            ..RootDse::default()
        };
        let places = locations(&root);
        assert_eq!(
            places[1].base,
            "CN=MicrosoftDNS,DC=ForestDnsZones,DC=lab,DC=test"
        );
        let zone_dn = "DC=lab.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=test";
        let n = node_from_entry(
            &entry(
                &node_dn(zone_dn, "_ldap._tcp"),
                &[
                    ("dnsRecord", vec![a("192.0.2.1"), vec![1, 2]]),
                    ("whenChanged", vec![b"20261014120000.0Z".to_vec()]),
                ],
            ),
            "lab.test",
        );
        assert_eq!(n.name, "_ldap._tcp");
        assert_eq!(n.labels(), ["_tcp", "_ldap"]);
        assert_eq!(n.fqdn(), "_ldap._tcp.lab.test");
        assert_eq!(n.records().len(), 1);
        assert_eq!(n.unreadable_values(), 1);
        assert!(n.modified.is_some() && !n.tombstone && !n.unreadable);
        assert!(is_node(&n.dn));
        assert!(!is_node(zone_dn));
        assert_eq!(
            node_parts(&n.dn),
            Some(("_ldap._tcp".into(), "lab.test".into()))
        );
        // Without attributes: unreadable, never empty.
        let hidden = node_from_entry(&entry(&node_dn(zone_dn, "dc1"), &[]), "lab.test");
        assert!(hidden.unreadable && hidden.name == "dc1");
        // Type 0 everywhere: tombstone, even without dNSTombstoned.
        let mut dead = Record::new(dns_record::TOMBSTONE, RecordData::Tombstone(1));
        dead.rank = 0;
        let gone = node_from_entry(
            &entry(
                &node_dn(zone_dn, "x"),
                &[("dnsRecord", vec![dead.encode().unwrap()])],
            ),
            "lab.test",
        );
        assert!(gone.tombstone);
        let marked = node_from_entry(
            &entry(
                &node_dn(zone_dn, "y"),
                &[
                    ("dnsRecord", vec![a("192.0.2.2")]),
                    ("dNSTombstoned", vec![b"TRUE".to_vec()]),
                ],
            ),
            "lab.test",
        );
        assert!(marked.tombstone);
    }

    #[test]
    fn zones_named_and_hints() {
        let z = zone_from_entry(
            &entry(
                "DC=RootDNSServers,CN=MicrosoftDNS,CN=System,DC=lab,DC=test",
                &[],
            ),
            Partition::Legacy,
        );
        assert_eq!(z.name, "RootDNSServers");
        assert!(z.root_hints() && !z.reverse());
        let r = zone_from_entry(
            &entry(
                "DC=1.168.192.in-addr.arpa,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=test",
                &[("name", vec![b"1.168.192.in-addr.arpa".to_vec()])],
            ),
            Partition::Domain,
        );
        assert!(r.reverse());
        assert_eq!(node_dn(&r.dn, "@"), format!("DC=@,{}", r.dn));
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS writing (J3.4, ADR 0003, `annuaire.core.actions_dns`): records added, modified,
//! deleted by direct LDAP on the `dnsNode` objects, turned into changesets.
//!
//! As for `actions`, nothing writes here: [`build`] reads the nodes and the SOA **on the DC
//! of the writes** (the PDC emulator of the write context) and returns a `Changeset` that the
//! interface shows in preview and applies through `writer::apply`. Rules, checked against
//! `samba-tool dns add/update/delete` on the lab (ADR 0003, 2):
//!
//! - each operation on a name is a `Modify(dnsRecord, removed, added)`; the value removed is
//!   the exact bytes **read again on the DC** (optimistic guard: the server refuses to remove
//!   a value that is gone), never a value from an old display;
//! - a name that does not exist yet is created (`Add`, `objectClass: top, dnsNode`); a name
//!   in tombstone is brought back into service (values of type 0 removed, `dNSTombstoned` to
//!   FALSE);
//! - when the last value of a node goes — all its values count, the NS of rank `NS_GLUE`
//!   included —, the node becomes a tombstone: record of type 0 (rank 0, TTL 0, FILETIME
//!   date) and `dNSTombstoned` to TRUE, as the DNS server of Samba and Windows do;
//! - header of the values written: rank ZONE (0xF0), flags 0, timestamp 0 (static), TTL 900
//!   by default, `Serial` = new serial number of the SOA;
//! - the SOA of each zone touched is incremented once per changeset, data and header; a
//!   conflict (another writer between reading and writing) is settled by reading again and
//!   starting over ([`rebuild`], `writer::apply` with a retry);
//! - an account that cannot write the node `@` (effective rights) writes without increment,
//!   and the preview says it (ADR 0003, point 3);
//! - a value of unknown rank, of a type not handled or unreadable is never written again;
//! - an NS is removed and added (fixes of the DNS health, J3.5), but not modified;
//! - `Purge` deletes the object of a node in tombstone (ADR 0003, point 2), without touching
//!   the SOA: the content of the zone does not change.
//!
//! The inverse of a DNS changeset (undo) puts back the original bytes of the records, but
//! **does not lower** the serial number: [`refresh_soa`] replaces the operation on the SOA
//! by a new increment, read at the time of the preview. The same for the automatic rollback
//! of a write that fails on the way ([`soa_on_rollback`], called by `writer`). The inverse
//! of the creation of a name (deletion of the object) becomes its tombstoning: the Windows
//! DNS server reads the directory by periodic polling and does not see a deleted `dnsNode`,
//! it would go on serving the name (checked against Windows Server 2025).

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use annuaire_codecs::dns_record::{self, HEADER_SIZE, RANK_ZONE, Record, RecordData};
use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::time::{TICKS_PER_SECOND, UNIX_OFFSET};

use crate::changes::{Change, ChangeError, Changeset, Operation, Read, dn_key, parent_dn};
use crate::connection::{Connection, Failure, Link};
use crate::dns::{self, NAMES_FILTER, ROOT, Zone, fqdn, node_dn, value_type};
use crate::error::LdapError;
use crate::messages::{Catalog, Msg};
use crate::session::Entry;
use crate::writer::{Burst, Retry};

/// Types added, modified and deleted from the DNS window (J3 criterion).
pub const WRITTEN_TYPES: [u16; 7] = [
    dns_record::A,
    dns_record::AAAA,
    dns_record::CNAME,
    dns_record::PTR,
    dns_record::MX,
    dns_record::SRV,
    dns_record::TXT,
];
/// Types the fixes of the DNS health (J3.5) add or remove: NS besides.
pub const FIX_TYPES: [u16; 8] = [
    dns_record::A,
    dns_record::AAAA,
    dns_record::CNAME,
    dns_record::PTR,
    dns_record::MX,
    dns_record::SRV,
    dns_record::TXT,
    dns_record::NS,
];
/// TTL of `samba-tool dns add` and of the DNS console.
pub const DEFAULT_TTL: u32 = 900;
pub const MAX_TTL: i64 = 0x7FFF_FFFF;
pub const DNS_RECORD: &str = "dnsRecord";
pub const TOMBSTONED: &str = "dNSTombstoned";
const ATTRIBUTES: [&str; 4] = [
    "uSNChanged",
    DNS_RECORD,
    TOMBSTONED,
    "allowedAttributesEffective",
];

// ---------------------------------------------------------------------------
// Errors

/// A number field of the input (`_entier`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Priority,
    Weight,
    Port,
    Ttl,
}

/// Why a DNS request is refused (`ErreurDns`); the interface says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    EmptyName,
    NameTooLong {
        name: String,
    },
    EmptyLabel {
        name: String,
    },
    WildcardFirstOnly,
    InvalidLabel {
        label: String,
    },
    EmptyNameUseAt,
    NotInZone {
        name: String,
        zone: String,
    },
    EmptyText,
    QuotedTextExpected {
        rest: String,
    },
    MissingQuote,
    StringTooLong,
    OutOfRange {
        field: Field,
        value: i64,
        max: i64,
    },
    TypeNotWritten {
        rtype: String,
    },
    Ipv4Expected,
    Ipv6Expected,
    TargetExpected,
    MxExpected,
    SrvExpected,
    TextExpected,
    InvalidInput {
        text: String,
        detail: String,
    },
    InvalidAddress {
        text: String,
    },
    UnreadableNode {
        name: String,
    },
    NoRootNode {
        zone: String,
        dc: String,
    },
    BadSoa {
        zone: String,
    },
    NoVersion {
        name: String,
    },
    RecordGone {
        name: String,
    },
    NotModifiable {
        rtype: String,
    },
    AlreadyThere {
        name: String,
        rtype: String,
    },
    CnameNotAlone {
        name: String,
        types: String,
    },
    IsAlias {
        name: String,
    },
    NoChange,
    NoRequest,
    WrittenAndPurged {
        name: String,
    },
    NoLongerExists {
        name: String,
    },
    NoLongerTombstone {
        name: String,
    },
    UnexpectedRootOperation {
        dn: String,
    },
    /// An operation refused by the model (a defect: the rules above prevent it).
    Change(String),
}

impl From<ChangeError> for DnsError {
    fn from(e: ChangeError) -> Self {
        Self::Change(e.to_string())
    }
}

/// Why a changeset could not be built on the DC.
#[derive(Debug, Clone)]
pub enum PrepareError {
    Dns(DnsError),
    Failure(Failure),
}

// ---------------------------------------------------------------------------
// Input: names and data, checked before any read

fn valid_label(label: &str) -> bool {
    if label == "*" {
        return true;
    }
    let bytes = label.as_bytes();
    let edge = |b: &u8| b.is_ascii_alphanumeric() || *b == b'_';
    let inner = |b: &u8| edge(b) || *b == b'-';
    match bytes {
        [] => false,
        [only] => edge(only),
        [first, middle @ .., last] => {
            bytes.len() <= 63 && edge(first) && edge(last) && middle.iter().all(inner)
        }
    }
}

/// DNS name (without final dot) whose every label is made of ASCII letters, digits, hyphens
/// and underscores (`_ldap._tcp`), without hyphen at an edge; `*` allowed as first label if
/// `wildcard`. Returns the name without final dot (`verifier_nom`).
pub fn verify_name(name: &str, wildcard: bool) -> Result<String, DnsError> {
    let name = name.trim();
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.is_empty() {
        return Err(DnsError::EmptyName);
    }
    if name.chars().count() > 253 {
        return Err(DnsError::NameTooLong { name: name.into() });
    }
    for (rank, label) in name.split('.').enumerate() {
        if label.is_empty() {
            return Err(DnsError::EmptyLabel { name: name.into() });
        }
        if label == "*" && !(wildcard && rank == 0) {
            return Err(DnsError::WildcardFirstOnly);
        }
        if !valid_label(label) {
            return Err(DnsError::InvalidLabel {
                label: label.into(),
            });
        }
    }
    Ok(name.to_owned())
}

/// Name typed → name relative to the zone (`@` for the zone itself) (`nom_relatif`).
///
/// `@`: the zone. An empty name is refused: writing at the root of the zone is asked
/// explicitly. A name ending with a dot is absolute and must be in the zone; a name ending
/// with the one of the zone is taken as absolute (one does not write
/// `host.lab.test.lab.test`).
pub fn relative_name(zone: &str, typed: &str) -> Result<String, DnsError> {
    let text = typed.trim();
    if text.is_empty() {
        return Err(DnsError::EmptyNameUseAt);
    }
    if text == ROOT {
        return Ok(ROOT.into());
    }
    let zone_low = zone.to_lowercase();
    let zone_low = zone_low.strip_suffix('.').unwrap_or(&zone_low);
    let low = text.to_lowercase();
    let mut text = text.to_owned();
    if text.ends_with('.') || low == zone_low || low.ends_with(&format!(".{zone_low}")) {
        let without = text.strip_suffix('.').unwrap_or(&text).to_owned();
        let without_low = without.to_lowercase();
        if without_low == zone_low {
            return Ok(ROOT.into());
        }
        if !without_low.ends_with(&format!(".{zone_low}")) {
            return Err(DnsError::NotInZone {
                name: text,
                zone: zone.into(),
            });
        }
        let keep = without.chars().count() - zone_low.chars().count() - 1;
        text = without.chars().take(keep).collect();
    }
    verify_name(&text, true)
}

/// Strings of a TXT (`lire_txt`). Starting with a quote: strings between quotes separated by
/// spaces (`\"` and `\\` escaped), the form the tool shows. Otherwise one string, cut in
/// pieces of 255 bytes at most (limit of a DNS string).
pub fn read_txt(text: &str) -> Result<Vec<String>, DnsError> {
    if text.trim().is_empty() {
        return Err(DnsError::EmptyText);
    }
    if !text.trim_start().starts_with('"') {
        return Ok(cut(text));
    }
    let chars: Vec<char> = text.chars().collect();
    let mut strings = Vec::new();
    let mut i = 0;
    while let Some(&c) = chars.get(i) {
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        if c != '"' {
            return Err(DnsError::QuotedTextExpected {
                rest: chars.get(i..).unwrap_or_default().iter().collect(),
            });
        }
        i += 1;
        let mut piece = String::new();
        loop {
            let Some(&c) = chars.get(i) else {
                return Err(DnsError::MissingQuote);
            };
            match (c, chars.get(i + 1)) {
                ('\\', Some(&next)) => {
                    piece.push(next);
                    i += 2;
                }
                ('"', _) => {
                    i += 1;
                    break;
                }
                _ => {
                    piece.push(c);
                    i += 1;
                }
            }
        }
        if piece.len() > 255 {
            return Err(DnsError::StringTooLong);
        }
        strings.push(piece);
    }
    Ok(strings)
}

fn cut(text: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = String::new();
    for c in text.chars() {
        if current.len() + c.len_utf8() > 255 {
            strings.push(std::mem::take(&mut current));
        }
        current.push(c);
    }
    strings.push(current);
    strings
}

fn bounded(value: i64, field: Field, max: i64) -> Result<i64, DnsError> {
    if (0..=max).contains(&value) {
        Ok(value)
    } else {
        Err(DnsError::OutOfRange { field, value, max })
    }
}

/// Data valid for the type; returns the written form (names without final dot)
/// (`verifier_donnees`).
pub fn verify_data(rtype: u16, data: &RecordData) -> Result<RecordData, DnsError> {
    if !FIX_TYPES.contains(&rtype) {
        return Err(DnsError::TypeNotWritten {
            rtype: dns_record::type_name(rtype),
        });
    }
    match (rtype, data) {
        (dns_record::A, RecordData::Address(IpAddr::V4(_)))
        | (dns_record::AAAA, RecordData::Address(IpAddr::V6(_))) => Ok(data.clone()),
        (dns_record::A, _) => Err(DnsError::Ipv4Expected),
        (dns_record::AAAA, _) => Err(DnsError::Ipv6Expected),
        (dns_record::CNAME | dns_record::PTR | dns_record::NS, RecordData::Name(n)) => {
            Ok(RecordData::Name(verify_name(n, false)?))
        }
        (dns_record::CNAME | dns_record::PTR | dns_record::NS, _) => Err(DnsError::TargetExpected),
        (dns_record::MX, RecordData::Mx { preference, target }) => Ok(RecordData::Mx {
            preference: *preference,
            target: verify_name(target, false)?,
        }),
        (dns_record::MX, _) => Err(DnsError::MxExpected),
        (
            dns_record::SRV,
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            },
        ) => Ok(RecordData::Srv {
            priority: *priority,
            weight: *weight,
            port: *port,
            target: verify_name(target, false)?,
        }),
        (dns_record::SRV, _) => Err(DnsError::SrvExpected),
        (_, RecordData::Txt(strings)) if !strings.is_empty() => {
            if strings.iter().any(|s| s.len() > 255) {
                return Err(DnsError::StringTooLong);
            }
            Ok(data.clone())
        }
        _ => Err(DnsError::TextExpected),
    }
}

fn number(piece: &str, text: &str, field: Field) -> Result<u16, DnsError> {
    let value: i64 =
        piece
            .parse()
            .map_err(|e: std::num::ParseIntError| DnsError::InvalidInput {
                text: text.into(),
                detail: e.to_string(),
            })?;
    let value = bounded(value, field, 0xFFFF)?;
    Ok(u16::try_from(value).unwrap_or(u16::MAX))
}

/// Data of a type from their text form (the one of `Record::data_text`: `10 mx`,
/// `0 100 389 target`, TXT strings between quotes), checked (`lire_saisie`).
pub fn read_input(rtype: u16, text: &str) -> Result<RecordData, DnsError> {
    let pieces: Vec<&str> = text.split_whitespace().collect();
    let invalid = |detail: String| DnsError::InvalidInput {
        text: text.into(),
        detail,
    };
    match rtype {
        dns_record::A | dns_record::AAAA => {
            let address: IpAddr = text
                .trim()
                .parse()
                .map_err(|e: std::net::AddrParseError| invalid(e.to_string()))?;
            verify_data(rtype, &RecordData::Address(address))
        }
        dns_record::CNAME | dns_record::PTR => verify_data(rtype, &RecordData::Name(text.into())),
        dns_record::MX => match pieces.as_slice() {
            [preference, target] => verify_data(
                rtype,
                &RecordData::Mx {
                    preference: number(preference, text, Field::Priority)?,
                    target: (*target).into(),
                },
            ),
            _ => Err(invalid(String::new())),
        },
        dns_record::SRV => match pieces.as_slice() {
            [priority, weight, port, target] => verify_data(
                rtype,
                &RecordData::Srv {
                    priority: number(priority, text, Field::Priority)?,
                    weight: number(weight, text, Field::Weight)?,
                    port: number(port, text, Field::Port)?,
                    target: (*target).into(),
                },
            ),
            _ => Err(invalid(String::new())),
        },
        dns_record::TXT => verify_data(rtype, &RecordData::Txt(read_txt(text)?)),
        // A type not written: a clear message.
        _ => verify_data(
            rtype,
            &RecordData::Raw {
                bytes: Vec::new(),
                error: None,
            },
        ),
    }
}

pub fn verify_ttl(ttl: i64) -> Result<u32, DnsError> {
    let ttl = bounded(ttl, Field::Ttl, MAX_TTL)?;
    Ok(u32::try_from(ttl).unwrap_or(u32::MAX))
}

// ---------------------------------------------------------------------------
// Reverse zones (option « also create the PTR »)

/// `192.168.1.10` → `10.1.168.192.in-addr.arpa` (`reverse_pointer`).
pub fn reverse_pointer(address: IpAddr) -> String {
    match address {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut nibbles: Vec<String> = Vec::with_capacity(32);
            for byte in v6.octets().iter().rev() {
                nibbles.push(format!("{:x}", byte & 0x0F));
                nibbles.push(format!("{:x}", byte >> 4));
            }
            format!("{}.ip6.arpa", nibbles.join("."))
        }
    }
}

/// The most precise reverse zone that holds the address, and the relative name of the PTR
/// (`10` for 192.168.1.10 in `1.168.192.in-addr.arpa`); None if there is none
/// (`zone_inverse`).
pub fn reverse_zone(zones: &[Zone], address: IpAddr) -> Option<(Zone, String)> {
    let pointer = reverse_pointer(address);
    let mut best: Option<(Zone, String)> = None;
    for zone in zones {
        let name = zone.name.to_lowercase();
        let name = name.strip_suffix('.').unwrap_or(&name);
        if zone.root_hints() || !(name.ends_with("in-addr.arpa") || name.ends_with("ip6.arpa")) {
            continue;
        }
        let relative = if pointer == name {
            ROOT.to_owned()
        } else if let Some(rest) = pointer.strip_suffix(&format!(".{name}")) {
            rest.to_owned()
        } else {
            continue;
        };
        if best.as_ref().is_none_or(|(b, _)| name.len() > b.name.len()) {
            best = Some((zone.clone(), relative));
        }
    }
    best
}

// ---------------------------------------------------------------------------
// Requests

/// What is asked (`Ajout`, `Modification`, `Suppression`, `Purge`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Add {
        zone: Zone,
        /// Relative to the zone, `@` for the zone itself.
        name: String,
        rtype: u16,
        data: RecordData,
        ttl: u32,
    },
    Modify {
        zone: Zone,
        name: String,
        /// Value shown; the one removed is read again on the DC (`find`).
        old: Vec<u8>,
        rtype: u16,
        data: RecordData,
        ttl: u32,
    },
    Delete {
        zone: Zone,
        name: String,
        /// Value shown; the one removed is read again on the DC (`find`).
        value: Vec<u8>,
    },
    /// Deletion of the object of a node in tombstone (DNS health, ADR 0003 point 2); refused
    /// if the node was brought back into service meanwhile.
    Purge { zone: Zone, name: String },
}

impl Request {
    pub fn zone(&self) -> &Zone {
        match self {
            Self::Add { zone, .. }
            | Self::Modify { zone, .. }
            | Self::Delete { zone, .. }
            | Self::Purge { zone, .. } => zone,
        }
    }

    pub fn name(&self) -> &str {
        match self {
            Self::Add { name, .. }
            | Self::Modify { name, .. }
            | Self::Delete { name, .. }
            | Self::Purge { name, .. } => name,
        }
    }
}

// ---------------------------------------------------------------------------
// Values

fn decode(value: &[u8]) -> Option<Record> {
    Record::decode(value).ok()
}

fn known_rank(rank: u8) -> bool {
    !dns_record::rank_name(rank).starts_with("0x")
}

/// `dnsRecord` value as samba-tool writes it: rank ZONE, flags 0, static (`encoder`).
pub fn encode(rtype: u16, data: RecordData, serial: u32, ttl: u32) -> Result<Vec<u8>, DnsError> {
    let mut record = Record::new(rtype, data);
    record.rank = RANK_ZONE;
    record.serial = serial;
    record.ttl = ttl;
    record.encode().map_err(|e| DnsError::Change(e.to_string()))
}

fn now_nttime() -> u64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ticks = u64::try_from(TICKS_PER_SECOND).unwrap_or(10_000_000);
    let offset = u64::try_from(UNIX_OFFSET).unwrap_or(0);
    (since.as_secs() + offset) * ticks + u64::from(since.subsec_nanos()) / 100
}

/// Record of type 0 of a node made a tombstone: rank 0, TTL 0, FILETIME date
/// (`valeur_tombstone`).
pub fn tombstone_value(serial: u32, nttime: Option<u64>) -> Vec<u8> {
    let mut record = Record::new(
        dns_record::TOMBSTONE,
        RecordData::Tombstone(nttime.unwrap_or_else(now_nttime)),
    );
    record.rank = 0;
    record.serial = serial;
    record.ttl = 0;
    record.encode().unwrap_or_default()
}

/// The value can be modified or deleted by the tool: type written, data read, known rank.
/// The others are never written again. `types`: [`FIX_TYPES`] for a removal (an NS is
/// removed, it is not modified) (`modifiable`).
pub fn modifiable(value: &[u8], types: &[u16]) -> bool {
    decode(value).is_some_and(|e| {
        types.contains(&e.rtype) && !matches!(e.data, RecordData::Raw { .. }) && known_rank(e.rank)
    })
}

/// Same type and same data (TTL, serial, timestamp ignored).
fn same_data(a: &[u8], b: &[u8]) -> bool {
    value_type(a) == value_type(b) && a.get(HEADER_SIZE..) == b.get(HEADER_SIZE..)
}

fn is_type(value: &[u8], rtype: u16) -> bool {
    value_type(value) == i32::from(rtype)
}

// ---------------------------------------------------------------------------
// Reading on the DC of the writes

#[derive(Debug, Clone)]
struct Soa {
    /// Name of the zone.
    zone: String,
    zone_dn: String,
    value: Vec<u8>,
    serial: u32,
    writable: bool,
}

impl Soa {
    fn new_serial(&self) -> u32 {
        if self.writable {
            self.serial.wrapping_add(1)
        } else {
            self.serial
        }
    }
}

#[derive(Debug, Clone)]
struct Pending {
    zone: Zone,
    name: String,
    dn: String,
    exists: bool,
    initial: Vec<Vec<u8>>,
    /// Raw value of `dNSTombstoned`, upper case (None: absent).
    tomb: Option<Vec<u8>>,
    read: Option<Read>,
    /// Values of a type other than 0, modified along the requests.
    live: Vec<Vec<u8>>,
}

impl Pending {
    fn in_tombstone(&self) -> bool {
        self.tomb.as_deref() == Some(b"TRUE")
            || (!self.initial.is_empty()
                && self
                    .initial
                    .iter()
                    .all(|v| is_type(v, dns_record::TOMBSTONE)))
    }
}

fn usn(entry: &Entry) -> Option<i64> {
    entry
        .values("uSNChanged")
        .first()
        .and_then(|v| integer::decode(v, Width::Bits64).ok())
}

/// The node after `entry` (None: it does not exist) (`_noeud`).
fn pending(entry: Option<&Entry>, dc: &str, zone: &Zone, name: &str) -> Result<Pending, DnsError> {
    let dn_text = node_dn(&zone.dn, name);
    let Some(entry) = entry else {
        return Ok(Pending {
            zone: zone.clone(),
            name: name.into(),
            dn: dn_text,
            exists: false,
            initial: Vec::new(),
            tomb: None,
            read: None,
            live: Vec::new(),
        });
    };
    if entry.attributes.is_empty() {
        // The node exists, but the account reads nothing of it (`Node::unreadable`):
        // writing without knowing its records, nor its version, is not allowed.
        return Err(DnsError::UnreadableNode {
            name: fqdn(&zone.name, name),
        });
    }
    let initial = entry.values(DNS_RECORD).to_vec();
    let tomb = entry
        .values(TOMBSTONED)
        .first()
        .map(|v| v.to_ascii_uppercase());
    let version = usn(entry).ok_or_else(|| DnsError::NoVersion {
        name: fqdn(&zone.name, name),
    })?;
    let live = initial
        .iter()
        .filter(|v| !is_type(v, dns_record::TOMBSTONE))
        .cloned()
        .collect();
    Ok(Pending {
        zone: zone.clone(),
        name: name.into(),
        dn: entry.dn.clone(),
        exists: true,
        initial,
        tomb,
        read: Some(Read {
            dc: dc.into(),
            usn: version,
        }),
        live,
    })
}

fn soa_of(entry: Option<&Entry>, zone: &str, zone_dn: &str, dc: &str) -> Result<Soa, DnsError> {
    let Some(entry) = entry else {
        return Err(DnsError::NoRootNode {
            zone: zone.into(),
            dc: dc.into(),
        });
    };
    let soas: Vec<&Vec<u8>> = entry
        .values(DNS_RECORD)
        .iter()
        .filter(|v| is_type(v, dns_record::SOA))
        .collect();
    let serial = match soas.as_slice() {
        [only] => match decode(only).map(|r| r.data) {
            Some(RecordData::Soa { serial, .. }) => Some(serial),
            _ => None,
        },
        _ => None,
    };
    let (Some(serial), Some(value)) = (serial, soas.first()) else {
        return Err(DnsError::BadSoa { zone: zone.into() });
    };
    let writable = entry
        .values("allowedAttributesEffective")
        .iter()
        .any(|v| v.eq_ignore_ascii_case(DNS_RECORD.as_bytes()));
    Ok(Soa {
        zone: zone.into(),
        zone_dn: zone_dn.into(),
        value: (*value).clone(),
        serial,
        writable,
    })
}

fn soa_value(soa: &Soa) -> Vec<u8> {
    soa_with_serial(&soa.value, soa.new_serial())
}

fn soa_with_serial(value: &[u8], serial: u32) -> Vec<u8> {
    let Some(mut record) = decode(value) else {
        return value.to_vec();
    };
    if let RecordData::Soa { serial: s, .. } = &mut record.data {
        *s = serial;
    }
    // As samba-tool: the number of the header follows the one of the data.
    record.serial = serial;
    record.encode().unwrap_or_else(|_| value.to_vec())
}

fn soa_serial(value: &[u8]) -> Option<u32> {
    match decode(value)?.data {
        RecordData::Soa { serial, .. } => Some(serial),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Construction

/// The value of the node read again that matches the one shown: the same, byte for byte,
/// or failing that the only one of same type and same data (TTL or serial changed since the
/// display) (`_trouver`).
fn find(n: &Pending, shown: &[u8], types: &[u16]) -> Result<Vec<u8>, DnsError> {
    let found = if n.live.iter().any(|v| v == shown) {
        shown.to_vec()
    } else {
        let similar: Vec<&Vec<u8>> = n.live.iter().filter(|v| same_data(v, shown)).collect();
        match similar.as_slice() {
            [only] => (*only).clone(),
            _ => {
                return Err(DnsError::RecordGone {
                    name: fqdn(&n.zone.name, &n.name),
                });
            }
        }
    };
    if !modifiable(&found, types) {
        return Err(DnsError::NotModifiable {
            rtype: decode(&found).map_or_else(|| "?".into(), |e| e.type_name()),
        });
    }
    Ok(found)
}

/// A CNAME alone on its name; not twice the same record (`_controler_ajout`).
fn check_add(n: &Pending, rtype: u16, value: &[u8], ignore: Option<&[u8]>) -> Result<(), DnsError> {
    let others: Vec<&Vec<u8>> = n
        .live
        .iter()
        .filter(|v| Some(v.as_slice()) != ignore)
        .collect();
    let name = fqdn(&n.zone.name, &n.name);
    if others.iter().any(|v| same_data(v, value)) {
        return Err(DnsError::AlreadyThere {
            name,
            rtype: dns_record::type_name(rtype),
        });
    }
    if rtype == dns_record::CNAME && !others.is_empty() {
        let mut types: Vec<String> = others
            .iter()
            .map(|v| {
                u16::try_from(value_type(v)).map_or_else(|_| "?".into(), dns_record::type_name)
            })
            .collect();
        types.sort();
        types.dedup();
        return Err(DnsError::CnameNotAlone {
            name,
            types: types.join(", "),
        });
    }
    if rtype != dns_record::CNAME && others.iter().any(|v| is_type(v, dns_record::CNAME)) {
        return Err(DnsError::IsAlias { name });
    }
    Ok(())
}

fn key(dn_text: &str) -> String {
    dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

/// Reads answered for [`build_from`]: by key of DN, the entry (None: no such object).
pub type Reads = HashMap<String, Option<Entry>>;

/// The DNs [`build_from`] needs, in order, without duplicate: the nodes `@` of the zones
/// written and the nodes named.
pub fn needed(requests: &[Request]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for r in requests {
        let names: &[&str] = if matches!(r, Request::Purge { .. }) {
            &[r.name()]
        } else {
            &[ROOT, r.name()]
        };
        for name in names {
            let d = node_dn(&r.zone().dn, name);
            let k = key(&d);
            if !seen.contains(&k) {
                seen.push(k);
                out.push(d);
            }
        }
    }
    out
}

fn check_requests(requests: &[Request]) -> Result<(), DnsError> {
    if requests.is_empty() {
        return Err(DnsError::NoRequest);
    }
    for r in requests {
        if r.name() != ROOT {
            verify_name(r.name(), true)?;
        }
        if let Request::Add {
            rtype, data, ttl, ..
        }
        | Request::Modify {
            rtype, data, ttl, ..
        } = r
        {
            verify_data(*rtype, data)?;
            verify_ttl(i64::from(*ttl))?;
        }
    }
    Ok(())
}

/// The changeset of the requests from the nodes read on `dc` (`construire`, without the
/// reading). `nttime`: date of the tombstoning (tests).
pub fn build_from(
    requests: &[Request],
    reads: &Reads,
    dc: &str,
    nttime: Option<u64>,
    catalog: &dyn Catalog,
) -> Result<Changeset, DnsError> {
    check_requests(requests)?;
    let entry = |d: &str| reads.get(&key(d)).and_then(Option::as_ref);
    let writes: Vec<&Request> = requests
        .iter()
        .filter(|r| !matches!(r, Request::Purge { .. }))
        .collect();
    let written: Vec<String> = writes
        .iter()
        .map(|r| key(&node_dn(&r.zone().dn, r.name())))
        .collect();
    let deletions = purges(requests, &written, &entry, dc)?;
    if writes.is_empty() {
        return Ok(Changeset {
            operations: deletions,
            remarks: Vec::new(),
        });
    }

    // Zones in the order met, their SOA, and the nodes by key.
    let mut soas: Vec<(String, Soa)> = Vec::new();
    let mut nodes: HashMap<String, Pending> = HashMap::new();
    for r in &writes {
        let zone = r.zone();
        let zone_key = key(&zone.dn);
        let root_dn = node_dn(&zone.dn, ROOT);
        if !soas.iter().any(|(k, _)| *k == zone_key) {
            let root_entry = entry(&root_dn);
            soas.push((zone_key, soa_of(root_entry, &zone.name, &zone.dn, dc)?));
            nodes.insert(key(&root_dn), pending(root_entry, dc, zone, ROOT)?);
        }
        let node_key = key(&node_dn(&zone.dn, r.name()));
        if let std::collections::hash_map::Entry::Vacant(slot) = nodes.entry(node_key) {
            slot.insert(pending(
                entry(&node_dn(&zone.dn, r.name())),
                dc,
                zone,
                r.name(),
            )?);
        }
    }
    let serial_of = |soas: &[(String, Soa)], zone: &Zone| {
        soas.iter()
            .find(|(k, _)| *k == key(&zone.dn))
            .map_or(0, |(_, s)| s.new_serial())
    };

    let mut touched: Vec<String> = Vec::new();
    for r in &writes {
        let zone = r.zone();
        let node_key = key(&node_dn(&zone.dn, r.name()));
        let serial = serial_of(&soas, zone);
        let Some(n) = nodes.get_mut(&node_key) else {
            continue;
        };
        if !touched.contains(&node_key) {
            touched.push(node_key.clone());
        }
        match r {
            Request::Add {
                rtype, data, ttl, ..
            } => {
                let value = encode(*rtype, verify_data(*rtype, data)?, serial, *ttl)?;
                check_add(n, *rtype, &value, None)?;
                n.live.push(value);
            }
            Request::Modify {
                old,
                rtype,
                data,
                ttl,
                ..
            } => {
                let previous = find(n, old, &WRITTEN_TYPES)?;
                let value = encode(*rtype, verify_data(*rtype, data)?, serial, *ttl)?;
                let before = decode(&previous).map(|e| e.ttl);
                if same_data(&previous, &value) && before == Some(*ttl) {
                    return Err(DnsError::NoChange);
                }
                check_add(n, *rtype, &value, Some(&previous))?;
                if let Some(place) = n.live.iter().position(|v| *v == previous) {
                    if let Some(slot) = n.live.get_mut(place) {
                        *slot = value;
                    }
                }
            }
            Request::Delete { value, .. } => {
                let found = find(n, value, &FIX_TYPES)?;
                if let Some(place) = n.live.iter().position(|v| *v == found) {
                    n.live.remove(place);
                }
            }
            Request::Purge { .. } => {}
        }
    }

    let mut remarks: Vec<String> = Vec::new();
    for (_, soa) in &soas {
        let root_key = key(&node_dn(&soa.zone_dn, ROOT));
        if soa.writable {
            if let Some(root) = nodes.get_mut(&root_key) {
                if let Some(slot) = root.live.iter_mut().find(|v| **v == soa.value) {
                    *slot = soa_value(soa);
                }
            }
            if !touched.contains(&root_key) {
                touched.push(root_key);
            }
        }
        remarks.push(soa_remark(soa, catalog));
    }

    // The nodes `@` (SOA) first: a conflict on the SOA stops everything before the first
    // write of a record.
    let roots: Vec<String> = soas
        .iter()
        .map(|(_, s)| key(&node_dn(&s.zone_dn, ROOT)))
        .filter(|k| touched.contains(k))
        .collect();
    let mut operations = Vec::new();
    for node_key in roots
        .iter()
        .chain(touched.iter().filter(|k| !roots.contains(k)))
    {
        let Some(n) = nodes.get(node_key) else {
            continue;
        };
        let serial = serial_of(&soas, &n.zone);
        if let Some(op) = operation(n, serial, nttime, &mut remarks, catalog)? {
            operations.push(op);
        }
    }
    operations.extend(deletions);
    Ok(Changeset {
        operations,
        remarks,
    })
}

/// One deletion of object per node to purge, read again on the DC: it must be in tombstone
/// and have no live value; its version read guards the deletion (`_purges`).
fn purges<'a>(
    requests: &[Request],
    written: &[String],
    entry: &dyn Fn(&str) -> Option<&'a Entry>,
    dc: &str,
) -> Result<Vec<Operation>, DnsError> {
    let mut operations = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for r in requests {
        let Request::Purge { zone, name } = r else {
            continue;
        };
        let n = pending(entry(&node_dn(&zone.dn, name)), dc, zone, name)?;
        let full = fqdn(&zone.name, name);
        if written.contains(&key(&n.dn)) {
            return Err(DnsError::WrittenAndPurged { name: full });
        }
        if !n.exists {
            return Err(DnsError::NoLongerExists { name: full });
        }
        if !n.live.is_empty() || !n.in_tombstone() {
            return Err(DnsError::NoLongerTombstone { name: full });
        }
        if !seen.contains(&key(&n.dn)) {
            seen.push(key(&n.dn));
            operations.push(Operation::delete(&n.dn, n.read.clone(), Vec::new())?);
        }
    }
    Ok(operations)
}

/// The beginning of every remark on the serial number (`_prefixe_soa`): `rafraichir_soa`
/// replaces them.
fn soa_prefix(catalog: &dyn Catalog) -> String {
    let text = catalog.text(&Msg::DnsZone {
        zone: "\u{1}".into(),
    });
    text.split('\u{1}').next().unwrap_or_default().to_owned()
}

/// Remark of the preview on the serial number (`_remarque_soa`).
fn soa_remark(soa: &Soa, catalog: &dyn Catalog) -> String {
    let text = if soa.writable {
        catalog.text(&Msg::DnsSerial {
            before: soa.serial,
            after: soa.new_serial(),
        })
    } else {
        catalog.text(&Msg::DnsSoaNotWritable { serial: soa.serial })
    };
    catalog.text(&Msg::DnsZone {
        zone: soa.zone.clone(),
    }) + &text
}

/// The operation that brings the node from its values read (`initial`) to `live`
/// (`_operation`).
fn operation(
    n: &Pending,
    serial: u32,
    nttime: Option<u64>,
    remarks: &mut Vec<String>,
    catalog: &dyn Catalog,
) -> Result<Option<Operation>, DnsError> {
    let name = fqdn(&n.zone.name, &n.name);
    if !n.exists {
        if n.live.is_empty() {
            return Ok(None);
        }
        return Ok(Some(Operation::add(
            &n.dn,
            vec![
                (
                    "objectClass".into(),
                    vec![b"top".to_vec(), b"dnsNode".to_vec()],
                ),
                (DNS_RECORD.into(), n.live.clone()),
            ],
        )?));
    }
    let mut changes: Vec<Change> = Vec::new();
    let tombs: Vec<Vec<u8>> = n
        .initial
        .iter()
        .filter(|v| is_type(v, dns_record::TOMBSTONE))
        .cloned()
        .collect();
    let tomb_values = || n.tomb.iter().cloned().collect::<Vec<_>>();
    let finals: Vec<Vec<u8>> = if !n.live.is_empty() && n.in_tombstone() {
        // Back into service: the values of type 0 go, `dNSTombstoned` becomes FALSE.
        if n.tomb.as_deref() != Some(b"FALSE") {
            changes.push(Change::new(
                TOMBSTONED,
                tomb_values(),
                vec![b"FALSE".to_vec()],
            )?);
        }
        remarks.push(catalog.text(&Msg::DnsBackInService { name }));
        n.live.clone()
    } else if n.live.is_empty() && !n.in_tombstone() {
        // Last value removed (all count, of any rank): tombstone.
        if n.tomb.as_deref() != Some(b"TRUE") {
            changes.push(Change::new(
                TOMBSTONED,
                tomb_values(),
                vec![b"TRUE".to_vec()],
            )?);
        }
        remarks.push(catalog.text(&Msg::DnsTombstoned { name }));
        vec![tombstone_value(serial, nttime)]
    } else {
        tombs.into_iter().chain(n.live.iter().cloned()).collect()
    };
    let removed: Vec<Vec<u8>> = n
        .initial
        .iter()
        .filter(|v| !finals.contains(v))
        .cloned()
        .collect();
    let added: Vec<Vec<u8>> = finals
        .iter()
        .filter(|v| !n.initial.contains(v))
        .cloned()
        .collect();
    if !removed.is_empty() || !added.is_empty() {
        changes.insert(0, Change::new(DNS_RECORD, removed, added)?);
    }
    if changes.is_empty() {
        return Ok(None);
    }
    Ok(Some(Operation::modify(&n.dn, changes, n.read.clone())?))
}

fn burst_reads(link: &mut Link, dns: &[String]) -> Result<Reads, LdapError> {
    let mut burst = Burst::new();
    let mut ranks = Vec::with_capacity(dns.len());
    for d in dns {
        ranks.push(burst.read(link, d, &ATTRIBUTES, NAMES_FILTER, None)?);
    }
    let answers = burst.receive(link)?;
    let mut reads = Reads::new();
    for (d, rank) in dns.iter().zip(ranks) {
        let first = answers
            .get(rank)
            .and_then(Option::as_ref)
            .and_then(|entries| entries.first().cloned());
        reads.insert(key(d), first);
    }
    Ok(reads)
}

/// Reads on the DC of the link the nodes and SOA concerned, all in one burst (one round
/// trip), and returns the changeset of the requests, on the thread of the connection
/// (`construire`).
pub fn build_on(
    link: &mut Link,
    requests: &[Request],
    nttime: Option<u64>,
    catalog: &dyn Catalog,
) -> Result<Result<Changeset, DnsError>, LdapError> {
    if let Err(e) = check_requests(requests) {
        return Ok(Err(e));
    }
    let reads = burst_reads(link, &needed(requests))?;
    let dc = link.state.dc.clone();
    Ok(build_from(requests, &reads, &dc, nttime, catalog))
}

/// [`build_on`] on the write connection (the one of the PDC) (`preparer`). Blocking.
pub fn build(
    connection: &Connection,
    requests: Vec<Request>,
    catalog: Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, PrepareError> {
    connection
        .run(true, move |link| {
            build_on(link, &requests, None, catalog.as_ref())
        })
        .map_err(PrepareError::Failure)?
        .map_err(PrepareError::Dns)
}

// ---------------------------------------------------------------------------
// New attempt after a conflict, and undo

/// Attribute, values removed, values added.
type ChangePrint = (String, Vec<Vec<u8>>, Vec<Vec<u8>>);

#[derive(Debug, PartialEq, Eq)]
enum Print {
    Add(String, Vec<(String, Vec<Option<Vec<u8>>>)>),
    Modify(String, Vec<ChangePrint>),
    Other(&'static str, String),
}

/// The value without what depends on the SOA: `Serial` to zero, date of a tombstone to
/// zero; None for the SOA itself (`_empreinte_valeur`).
fn value_print(attribute: &str, value: &[u8]) -> Option<Vec<u8>> {
    if !attribute.eq_ignore_ascii_case(DNS_RECORD) || value.len() < HEADER_SIZE {
        return Some(value.to_vec());
    }
    if is_type(value, dns_record::SOA) {
        return None;
    }
    let mut out = value.to_vec();
    if let Some(serial) = out.get_mut(8..12) {
        serial.fill(0);
    }
    if is_type(value, dns_record::TOMBSTONE) {
        if let Some(data) = out.get_mut(HEADER_SIZE..) {
            data.fill(0);
        }
    }
    Some(out)
}

fn prints(changeset: &Changeset) -> Vec<Print> {
    let mut out = Vec::new();
    for op in &changeset.operations {
        match op {
            Operation::Add { dn, attributes } => {
                let mut list: Vec<(String, Vec<Option<Vec<u8>>>)> = attributes
                    .iter()
                    .map(|(a, vs)| {
                        (
                            a.to_lowercase(),
                            vs.iter().map(|v| value_print(a, v)).collect(),
                        )
                    })
                    .collect();
                list.sort();
                out.push(Print::Add(key(dn), list));
            }
            Operation::Modify { dn, changes, .. } => {
                let mut list = Vec::new();
                for c in changes {
                    let keep = |vs: &[Vec<u8>]| -> Vec<Vec<u8>> {
                        vs.iter()
                            .filter_map(|v| value_print(&c.attribute, v))
                            .filter(|v| !v.is_empty())
                            .collect()
                    };
                    let (removed, added) = (keep(&c.removed), keep(&c.added));
                    if !removed.is_empty() || !added.is_empty() {
                        list.push((c.attribute.to_lowercase(), removed, added));
                    }
                }
                if !list.is_empty() {
                    out.push(Print::Modify(key(dn), list));
                }
            }
            Operation::Rename { dn, .. } => out.push(Print::Other("rename", key(dn))),
            Operation::Delete { dn, .. } => out.push(Print::Other("delete", key(dn))),
            other => out.push(Print::Other("sysvol", key(other.dn()))),
        }
    }
    out
}

/// Same operations but for the serial numbers (SOA, `Serial` of the values, date of a
/// tombstone): the only difference a conflict on the SOA may justify (`equivalents`).
pub fn equivalent(a: &Changeset, b: &Changeset) -> bool {
    prints(a) == prints(b)
}

/// After a conflict: reads again and builds again; None if the result is no longer the one
/// of the preview (something else than the serial number changed, a value added to the
/// node meanwhile for instance): the user must then read again and start over
/// (`reconstruire`).
pub fn rebuild(requests: Vec<Request>, catalog: Arc<dyn Catalog + Send + Sync>) -> Retry {
    Box::new(move |link, previous| {
        let new = build_on(link, &requests, None, catalog.as_ref())
            .ok()?
            .ok()?;
        equivalent(&new, previous).then_some(new)
    })
}

/// A DNS changeset: one of its operations is on a `dnsNode` (`touche_dns`).
pub fn touches_dns(changeset: &Changeset) -> bool {
    changeset.operations.iter().any(|op| dns::is_node(op.dn()))
}

/// Automatic rollback of an interrupted DNS write (`soa_au_retour`, called by `writer`).
///
/// The inverse would put the SOA back to its value from before: a serial number must never
/// go down (a secondary that read the number incremented would not see the zone again).
/// The SOA gets a new increment instead: the value written is removed, the same is put with
/// the next number. Without reading again (the guard stays the exact value removed), and
/// operation by operation (the `origins` of the report stay right). No effect outside DNS.
pub fn soa_on_rollback(rollback: Changeset, catalog: &dyn Catalog) -> Changeset {
    let mut changed = false;
    let mut operations = Vec::with_capacity(rollback.operations.len());
    for op in rollback.operations {
        let op = match op {
            Operation::Modify { dn, changes, read } if dns::is_node(&dn) => {
                let changes = changes
                    .into_iter()
                    .map(|c| {
                        let written: Vec<&Vec<u8>> = c
                            .removed
                            .iter()
                            .filter(|v| is_type(v, dns_record::SOA))
                            .collect();
                        let old: Vec<&Vec<u8>> = c
                            .added
                            .iter()
                            .filter(|v| is_type(v, dns_record::SOA))
                            .collect();
                        if !c.attribute.eq_ignore_ascii_case(DNS_RECORD)
                            || written.len() != 1
                            || old.len() != 1
                        {
                            return c;
                        }
                        let (Some(&w), Some(&o)) = (written.first(), old.first()) else {
                            return c;
                        };
                        let Some(serial) = soa_serial(w) else {
                            return c;
                        };
                        let next = soa_with_serial(w, serial.wrapping_add(1));
                        let (o, removed) = (o.clone(), c.removed.clone());
                        let added = c
                            .added
                            .iter()
                            .map(|v| if *v == o { next.clone() } else { v.clone() })
                            .collect();
                        changed = true;
                        Change {
                            attribute: c.attribute,
                            removed,
                            added,
                        }
                    })
                    .collect();
                Operation::Modify { dn, changes, read }
            }
            other => other,
        };
        operations.push(op);
    }
    if !changed {
        return Changeset {
            operations,
            remarks: rollback.remarks,
        };
    }
    let mut remarks = rollback.remarks;
    remarks.push(catalog.text(&Msg::DnsSoaNotRestored));
    Changeset {
        operations,
        remarks,
    }
}

/// The operation without the SOA values of `dnsRecord` (None if nothing is left)
/// (`_sans_soa`).
fn without_soa(op: &Operation) -> Result<Option<Operation>, DnsError> {
    let Operation::Modify { dn, changes, read } = op else {
        return Ok(Some(op.clone()));
    };
    if !dns::is_node(dn) {
        return Ok(Some(op.clone()));
    }
    let mut kept = Vec::new();
    for c in changes {
        if c.attribute.eq_ignore_ascii_case(DNS_RECORD) {
            let removed: Vec<Vec<u8>> = c
                .removed
                .iter()
                .filter(|v| !is_type(v, dns_record::SOA))
                .cloned()
                .collect();
            let added: Vec<Vec<u8>> = c
                .added
                .iter()
                .filter(|v| !is_type(v, dns_record::SOA))
                .cloned()
                .collect();
            if removed.is_empty() && added.is_empty() {
                continue;
            }
            kept.push(Change::new(&c.attribute, removed, added)?);
        } else {
            kept.push(c.clone());
        }
    }
    if kept.is_empty() {
        return Ok(None);
    }
    Ok(Some(Operation::Modify {
        dn: dn.clone(),
        changes: kept,
        read: read.clone(),
    }))
}

/// The deletion of a node still alive (inverse of its creation) turned into a tombstone, as
/// the removal of its last record. Guard: the exact values read and the version of the
/// inverse. A node already in tombstone keeps its deletion (`Purge` replayed); a node absent
/// or unreadable too: the write will say it (`_tombstone_au_lieu_de`).
fn tombstone_instead(
    link: &mut Link,
    op: Operation,
    serial: u32,
    remarks: &mut Vec<String>,
    catalog: &dyn Catalog,
) -> Result<Result<Operation, DnsError>, LdapError> {
    let Operation::Delete { dn, read, .. } = &op else {
        return Ok(Ok(op));
    };
    let reads = burst_reads(link, std::slice::from_ref(dn))?;
    let Some(Some(entry)) = reads.get(&key(dn)) else {
        return Ok(Ok(op));
    };
    if entry.attributes.is_empty() {
        return Ok(Ok(op));
    }
    let values = entry.values(DNS_RECORD).to_vec();
    let tomb = entry.values(TOMBSTONED).to_vec();
    let marked = tomb
        .first()
        .is_some_and(|t| t.eq_ignore_ascii_case(b"TRUE"));
    if marked || (!values.is_empty() && values.iter().all(|v| is_type(v, dns_record::TOMBSTONE))) {
        return Ok(Ok(op));
    }
    let build = || -> Result<Operation, DnsError> {
        let changes = vec![
            Change::new(
                DNS_RECORD,
                values.clone(),
                vec![tombstone_value(serial, None)],
            )?,
            Change::new(TOMBSTONED, tomb.clone(), vec![b"TRUE".to_vec()])?,
        ];
        Ok(Operation::modify(dn, changes, read.clone())?)
    };
    let new = match build() {
        Ok(new) => new,
        Err(e) => return Ok(Err(e)),
    };
    let name = dns::node_parts(dn).map_or_else(|| dn.clone(), |(n, z)| fqdn(&z, &n));
    remarks.push(catalog.text(&Msg::DnsUndoCreation { name }));
    Ok(Ok(new))
}

fn merge(op: Operation, soa: Change, read: Option<Read>) -> Result<Operation, DnsError> {
    let Operation::Modify { dn, changes, .. } = op else {
        return Err(DnsError::UnexpectedRootOperation { dn: op.dn().into() });
    };
    let mut changes = changes;
    if let Some(c) = changes
        .iter_mut()
        .find(|c| c.attribute.eq_ignore_ascii_case(DNS_RECORD))
    {
        let removed = soa.removed.iter().chain(&c.removed).cloned().collect();
        let added = soa.added.iter().chain(&c.added).cloned().collect();
        *c = Change::new(&c.attribute, removed, added)?;
    } else {
        changes.insert(0, soa);
    }
    Ok(Operation::modify(&dn, changes, read)?)
}

/// The changeset with, for each zone touched, an increment of the SOA read now in place of
/// the one it carried (undo, resume: the inverse of an increment would lower the serial
/// number) (`rafraichir_soa`). The values of the records do not change (exact inverse),
/// except the deletion of a live node, which becomes its tombstoning ([`tombstone_instead`]).
/// The node `@` is read again: each write in the zone changes its version; the guard there is
/// the exact value removed. On the thread of the connection.
pub fn refresh_soa_on(
    link: &mut Link,
    changeset: &Changeset,
    catalog: &dyn Catalog,
) -> Result<Result<Changeset, DnsError>, LdapError> {
    if !touches_dns(changeset) {
        return Ok(Ok(changeset.clone()));
    }
    let mut zones: Vec<(String, String)> = Vec::new(); // key, DN of the zone
    for op in &changeset.operations {
        if dns::is_node(op.dn()) {
            if let Ok(zone_dn) = parent_dn(op.dn()) {
                if !zones.iter().any(|(k, _)| *k == key(&zone_dn)) {
                    zones.push((key(&zone_dn), zone_dn));
                }
            }
        }
    }
    let mut rests = Vec::new();
    for op in &changeset.operations {
        match without_soa(op) {
            Ok(Some(op)) => rests.push(op),
            Ok(None) => {}
            Err(e) => return Ok(Err(e)),
        }
    }
    let prefix = soa_prefix(catalog);
    let mut remarks: Vec<String> = changeset
        .remarks
        .iter()
        .filter(|m| !m.starts_with(&prefix))
        .cloned()
        .collect();
    let roots: Vec<String> = zones.iter().map(|(_, z)| node_dn(z, ROOT)).collect();
    let reads = burst_reads(link, &roots)?;
    let dc = link.state.dc.clone();
    let mut front = Vec::new();
    for ((zone_key, zone_dn), root_dn) in zones.iter().zip(&roots) {
        let entry = reads.get(&key(root_dn)).and_then(Option::as_ref);
        let zone_name = dns::node_parts(root_dn).map(|(_, z)| z).unwrap_or_default();
        let soa = match soa_of(entry, &zone_name, zone_dn, &dc) {
            Ok(soa) => soa,
            Err(e) => return Ok(Err(e)),
        };
        let read = entry.and_then(usn).map(|usn| Read {
            dc: dc.clone(),
            usn,
        });
        remarks.push(soa_remark(&soa, catalog));
        let mut next = Vec::with_capacity(rests.len());
        for op in rests {
            let in_zone = matches!(op, Operation::Delete { .. })
                && parent_dn(op.dn()).is_ok_and(|p| key(&p) == *zone_key);
            if in_zone {
                match tombstone_instead(link, op, soa.new_serial(), &mut remarks, catalog)? {
                    Ok(op) => next.push(op),
                    Err(e) => return Ok(Err(e)),
                }
            } else {
                next.push(op);
            }
        }
        rests = next;
        let root = rests
            .iter()
            .position(|op| key(op.dn()) == key(root_dn))
            .map(|i| rests.remove(i));
        if let Some(op) = &root {
            if !matches!(op, Operation::Modify { .. }) {
                return Ok(Err(DnsError::UnexpectedRootOperation {
                    dn: op.dn().into(),
                }));
            }
        }
        if soa.writable {
            let change =
                match Change::new(DNS_RECORD, vec![soa.value.clone()], vec![soa_value(&soa)]) {
                    Ok(c) => c,
                    Err(e) => return Ok(Err(e.into())),
                };
            let op = match root {
                None => Operation::modify(root_dn, vec![change], read).map_err(DnsError::from),
                Some(op) => merge(op, change, read),
            };
            match op {
                Ok(op) => front.push(op),
                Err(e) => return Ok(Err(e)),
            }
        } else if let Some(Operation::Modify { dn, changes, .. }) = root {
            front.push(Operation::Modify { dn, changes, read });
        }
    }
    let mut unique: Vec<String> = Vec::new();
    for m in remarks {
        if !unique.contains(&m) {
            unique.push(m);
        }
    }
    front.extend(rests);
    Ok(Ok(Changeset {
        operations: front,
        remarks: unique,
    }))
}

/// [`refresh_soa_on`] on the write connection. Blocking.
pub fn refresh_soa(
    connection: &Connection,
    changeset: Changeset,
    catalog: Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, PrepareError> {
    connection
        .run(true, move |link| {
            refresh_soa_on(link, &changeset, catalog.as_ref())
        })
        .map_err(PrepareError::Failure)?
        .map_err(PrepareError::Dns)
}

/// Retry of an undo or of a resume: increment of the SOA read again at each attempt
/// (`soa_a_jour`).
pub fn soa_up_to_date(changeset: Changeset, catalog: Arc<dyn Catalog + Send + Sync>) -> Retry {
    Box::new(move |link, _previous| {
        refresh_soa_on(link, &changeset, catalog.as_ref())
            .ok()?
            .ok()
    })
}

#[cfg(test)]
mod tests;

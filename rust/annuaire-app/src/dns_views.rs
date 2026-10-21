// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS (J3.3, `annuaire.vue.dns`): tree zone → names, and records of the chosen name,
//! without GTK; the messages of the DNS writes (`ErreurDns`) and the sentence of the record
//! dialog.
//!
//! In the directory, every name of a zone is a node flat under it; the tree sorts them by
//! labels, as the Windows DNS console: `_ldap._tcp.dc._msdcs` under `_msdcs` → `dc` → `_tcp`.
//! An intermediate name (`_tcp`) may have no node of its own: it then holds no record.
//!
//! Reading rule, which prevents the mistake of 12/10 on the root of example.local (the A of the
//! names below the root taken for A of the root, `samba-tool dns query <zone> @ ALL` listing
//! both together): **the records shown for a name are those of its own node, and only
//! them**. The zone shows those of the node `@`; the names below are seen in the tree,
//! counted apart (`branch_summary`).

use std::collections::{BTreeMap, HashMap};
use std::rc::Rc;
use std::time::{Duration, SystemTime};

use annuaire_codecs::dns_property::{DynamicUpdate, Known, ZoneSettings, ZoneType};
use annuaire_codecs::dns_record::{self, RANK_ZONE, Record, RecordData};
use annuaire_codecs::time::UtcTime;
use annuaire_core::dns::{Node, Partition, ROOT, Zone, fqdn};
use annuaire_core::dns_write::{self, DnsError, Field, Request};

use crate::i18n::{fill, tr, tr_ctx, tr_n};
use crate::views::{format_unix, normalize, number};

pub const ZONE_ICON: &str = "network-server-symbolic";
pub const NAME_ICON: &str = "network-workgroup-symbolic";
pub const FOLDER_ICON: &str = "folder-symbolic";
pub const TOMBSTONE_ICON: &str = "user-trash-symbolic";
pub const UNREADABLE_ICON: &str = "action-unavailable-symbolic";

/// A name of the zone in the tree: its own node if it has one, and the names below
/// (`BrancheDns`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    pub zone: String,
    /// Labels from the zone (`["_msdcs", "dc", "_tcp"]`); empty for the zone itself.
    pub path: Vec<String>,
    pub node: Option<Node>,
    /// Shared with the rows of the tree that show them.
    pub children: Vec<Rc<Branch>>,
}

impl Branch {
    pub fn is_root(&self) -> bool {
        self.path.is_empty()
    }

    pub fn name(&self) -> &str {
        self.path.last().map_or(&self.zone, String::as_str)
    }

    /// Name relative to the zone, `@` for the zone itself.
    pub fn relative(&self) -> String {
        if self.path.is_empty() {
            ROOT.to_owned()
        } else {
            self.path
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>()
                .join(".")
        }
    }

    pub fn fqdn(&self) -> String {
        fqdn(&self.zone, &self.relative())
    }

    pub fn tombstone(&self) -> bool {
        self.node.as_ref().is_some_and(|n| n.tombstone)
    }

    /// Node unreadable for the account: records unknown (`Node::unreadable`).
    pub fn unreadable(&self) -> bool {
        self.node.as_ref().is_some_and(|n| n.unreadable)
    }

    pub fn icon(&self) -> &'static str {
        if self.is_root() {
            ZONE_ICON
        } else if self.tombstone() {
            TOMBSTONE_ICON
        } else if self.unreadable() {
            UNREADABLE_ICON
        } else if self.children.is_empty() {
            NAME_ICON
        } else {
            FOLDER_ICON
        }
    }

    /// Names below, at any depth.
    pub fn descendants(&self) -> usize {
        self.children.iter().map(|c| 1 + c.descendants()).sum()
    }

    /// Names unreadable for the account below, at any depth.
    pub fn unreadable_below(&self) -> usize {
        self.children
            .iter()
            .map(|c| usize::from(c.unreadable()) + c.unreadable_below())
            .sum()
    }
}

#[derive(Debug, Default)]
struct Building {
    label: String,
    node: Option<Node>,
    children: HashMap<String, Building>,
}

/// Numbers in numeric order (reverse zones), then alphabetical order without case nor
/// accents (`_cle_tri`).
fn sort_key(label: &str) -> (bool, u128, String, String) {
    let numeric = !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit());
    (
        !numeric,
        if numeric {
            label.parse().unwrap_or(u128::MAX)
        } else {
            0
        },
        normalize(label),
        label.to_owned(),
    )
}

/// Tree of the names of a zone (`arborescence`). The nodes in tombstone are left out
/// unless `tombstones`; an intermediate name exists only if a visible name stays below it.
pub fn tree<'a>(zone: &str, nodes: impl IntoIterator<Item = &'a Node>, tombstones: bool) -> Branch {
    let mut root = Building {
        label: zone.to_owned(),
        ..Building::default()
    };
    for node in nodes {
        if node.tombstone && !tombstones {
            continue;
        }
        let labels = node.labels();
        let mut current = &mut root;
        for label in &labels {
            // DNS names ignore case (`DC2` and `dc2` are one name).
            current = current
                .children
                .entry(label.to_lowercase())
                .or_insert_with(|| Building {
                    label: (*label).to_owned(),
                    ..Building::default()
                });
        }
        current.node = Some(node.clone());
        if let Some(last) = labels.last() {
            current.label = (*last).to_owned(); // the case of the node itself
        }
    }
    fn freeze(zone: &str, b: Building, path: Vec<String>) -> Branch {
        let mut children: Vec<Building> = b.children.into_values().collect();
        children.sort_by_key(|c| sort_key(&c.label));
        Branch {
            zone: zone.to_owned(),
            node: b.node,
            children: children
                .into_iter()
                .map(|c| {
                    let mut p = path.clone();
                    p.push(c.label.clone());
                    Rc::new(freeze(zone, c, p))
                })
                .collect(),
            path,
        }
    }
    freeze(zone, root, Vec::new())
}

// --- Records of the chosen name -------------------------------------------------------

/// A record of the chosen name, ready to show (`LigneDns`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLine {
    pub rtype: String,
    pub data: String,
    pub ttl: String,
    pub timestamp: String,
    pub remark: String,
    pub sort_key: (u8, String, String),
    /// Raw value of `dnsRecord`: what the tool removes or replaces (read again on the DC).
    pub value: Vec<u8>,
    /// Type written by the tool, data read, known rank (`dns_write::modifiable`).
    pub modifiable: bool,
}

/// `3600` → `3600 s (1 h)`; the short form only when it is exact (`texte_duree`).
pub fn duration_text(seconds: u32) -> String {
    for (unit, text) in [(86_400, tr("d")), (3600, tr("h")), (60, tr("min"))] {
        if seconds >= unit && seconds % unit == 0 {
            return fill(
                &tr("{s} s ({n} {u})"),
                &[
                    ("s", &seconds.to_string()),
                    ("n", &(seconds / unit).to_string()),
                    ("u", &text),
                ],
            );
        }
    }
    fill(&tr("{s} s"), &[("s", &seconds.to_string())])
}

fn remark(e: &Record) -> String {
    let mut pieces = Vec::new();
    if e.rtype == dns_record::TOMBSTONE {
        pieces.push(tr("deleted node (tombstone)"));
    } else if e.rank != RANK_ZONE {
        if e.rank == 0x80 || e.rank == 0x82 {
            pieces.push(fill(
                &tr("delegation or glue ({rang})"),
                &[("rang", &e.rank_name())],
            ));
        } else {
            pieces.push(fill(
                &tr("outside the zone ({rang})"),
                &[("rang", &e.rank_name())],
            ));
        }
    }
    if let RecordData::Raw {
        error: Some(error), ..
    } = &e.data
    {
        pieces.push(fill(
            &tr("unreadable data: {erreur}"),
            &[(
                "erreur",
                &crate::codec_texts::codec_message(&error.to_string()),
            )],
        ));
    }
    pieces.join(&tr("; "))
}

/// Local date and time of an instant, to the minute (`formater_date`).
pub fn format_time(date: UtcTime) -> String {
    format_unix(date.unix_seconds())
}

pub fn record_line(e: &Record, value: &[u8]) -> RecordLine {
    let mut data = e.data_text().unwrap_or_default();
    if let RecordData::Tombstone(nttime) = e.data {
        if let Some(date) = i64::try_from(nttime)
            .ok()
            .and_then(|t| annuaire_codecs::time::nttime_to_utc(t).ok().flatten())
        {
            data = fill(&tr("deleted on {date}"), &[("date", &format_time(date))]);
        }
    }
    let timestamp = if e.is_static() {
        tr("static")
    } else {
        e.date().ok().flatten().map(format_time).unwrap_or_default()
    };
    let order = match e.rtype {
        dns_record::SOA => 0,
        dns_record::NS => 1,
        _ => 2,
    };
    RecordLine {
        rtype: e.type_name(),
        sort_key: (order, e.type_name(), normalize(&data)),
        data,
        ttl: duration_text(e.ttl),
        timestamp,
        remark: remark(e),
        value: value.to_vec(),
        modifiable: !value.is_empty() && dns_write::modifiable(value, &dns_write::WRITTEN_TYPES),
    }
}

/// Records held by this name, **and by it alone**: those of its own node, never those of
/// the names below. SOA and NS first, then by type and data (`lignes_enregistrements`).
pub fn record_lines(branch: &Branch) -> Vec<RecordLine> {
    let Some(node) = &branch.node else {
        return Vec::new();
    };
    let mut lines: Vec<RecordLine> = node
        .values
        .iter()
        .filter_map(|v| Record::decode(v).ok().map(|e| record_line(&e, v)))
        .collect();
    lines.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
    lines
}

/// What the table shows, and what it does not show (`resume_branche`).
pub fn branch_summary(branch: &Branch) -> String {
    let n = branch.node.as_ref().map_or(0, |n| n.records().len());
    let below = branch.descendants();
    let first = if branch.unreadable() {
        tr("Records unreadable with this account (permissions)")
    } else if n == 0 {
        if branch.is_root() {
            tr("No record at the root of the zone (@)")
        } else {
            tr("No record at this name")
        }
    } else if branch.is_root() {
        tr_n(
            "{n} record at the root of the zone (@)",
            "{n} records at the root of the zone (@)",
            n as u64,
        )
    } else {
        tr_n(
            "{n} record at this name",
            "{n} records at this name",
            n as u64,
        )
    };
    let mut text = fill(&first, &[("n", &number(n as u64))]);
    if below > 0 {
        text += &fill(
            &tr_n(
                "; {s} name below, in the tree, not counted here",
                "; {s} names below, in the tree, not counted here",
                below as u64,
            ),
            &[("s", &number(below as u64))],
        );
    }
    let hidden = branch.unreadable_below();
    if hidden > 0 {
        text += &fill(
            &tr_n(
                ", {i} of which is unreadable with this account",
                ", {i} of which are unreadable with this account",
                hidden as u64,
            ),
            &[("i", &number(hidden as u64))],
        );
    }
    if let Some(node) = &branch.node {
        let bad = node.unreadable_values();
        if bad > 0 {
            text += &fill(&tr("; {i} unreadable value(s)"), &[("i", &bad.to_string())]);
        }
    }
    text
}

/// Title and description when the name has no record of its own (`texte_vide`).
pub fn empty_text(branch: &Branch) -> (String, String) {
    if branch.node.is_none() {
        return (
            tr("No record at this name"),
            tr("This name only exists through the names below it."),
        );
    }
    if branch.unreadable() {
        return (
            tr("Name unreadable with this account"),
            tr(
                "The directory shows that this name exists, but this account is not allowed to read its attributes: its records are unknown, which does not mean it has none. With Samba, this is the case for the names of the controllers for an ordinary account. An administration account sees them.",
            ),
        );
    }
    (tr("No record at this name"), String::new())
}

/// Status bar: the DNS is always read on the DC (ADR 0010, 7), at this date
/// (`decrire_lecture`).
pub fn read_text(date: SystemTime) -> String {
    let seconds = date
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    fill(
        &tr("Read on the controller on {date}"),
        &[("date", &format_unix(seconds))],
    )
}

// --- After a write (ADR 0009) --------------------------------------------------------

/// Past this, the reading of the DC holds even if it seems older (`GARDE_ECRITS`).
pub const KEEP_WRITTEN: Duration = Duration::from_secs(30 * 60);

/// A node read again on the DC of the writes just after a write (`Ecrit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Written {
    pub dn: String,
    /// None: the node no longer exists (undo of a creation).
    pub node: Option<Node>,
    pub read_at: SystemTime,
}

/// Nodes read by the source, corrected by those read again on the DC of the writes: the
/// source may aim at a DC that did not get the replication yet (`corriger`). A node of the
/// source whose `modified` is at least the one of the node read again holds (replication
/// received, or newer write); past [`KEEP_WRITTEN`], the source always holds.
pub fn correct(nodes: &[Node], written: &[Written], now: SystemTime) -> Vec<Node> {
    let mut fresh: BTreeMap<String, &Written> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for w in written {
        let recent = now
            .duration_since(w.read_at)
            .map_or(true, |age| age < KEEP_WRITTEN);
        if recent {
            let k = w.dn.to_lowercase();
            if !fresh.contains_key(&k) {
                order.push(k.clone());
            }
            fresh.insert(k, w);
        }
    }
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        let Some(w) = fresh.remove(&n.dn.to_lowercase()) else {
            out.push(n.clone());
            continue;
        };
        match &w.node {
            None => {}
            Some(again) => {
                let caught_up = n
                    .modified
                    .is_some_and(|m| again.modified.is_none_or(|a| m >= a));
                out.push(if caught_up { n.clone() } else { again.clone() });
            }
        }
    }
    out.extend(
        order
            .iter()
            .filter_map(|k| fresh.get(k))
            .filter_map(|w| w.node.clone()),
    );
    out
}

/// Nodes shown, where those just read again on the DC of the writes replace theirs (or are
/// added, or disappear if they no longer exist), without condition: they are the most
/// recent reading (`remplacer`).
pub fn replace(nodes: &[Node], written: &[Written]) -> Vec<Node> {
    let mut again: BTreeMap<String, &Written> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for w in written {
        let k = w.dn.to_lowercase();
        if !again.contains_key(&k) {
            order.push(k.clone());
        }
        again.insert(k, w);
    }
    let mut out = Vec::with_capacity(nodes.len());
    for n in nodes {
        match again.remove(&n.dn.to_lowercase()) {
            None => out.push(n.clone()),
            Some(w) => out.extend(w.node.clone()),
        }
    }
    out.extend(
        order
            .iter()
            .filter_map(|k| again.get(k))
            .filter_map(|w| w.node.clone()),
    );
    out
}

// --- Zone ------------------------------------------------------------------------------

pub fn partition_label(partition: Partition) -> &'static str {
    match partition {
        Partition::Domain => "DomainDnsZones",
        Partition::Forest => "ForestDnsZones",
        Partition::Legacy => "CN=System",
    }
}

/// Place of the zone (partition), for the tree (`sous_titre_zone`).
pub fn zone_subtitle(zone: &Zone) -> String {
    if zone.root_hints() {
        return fill(
            &tr("root hints, {p}"),
            &[("p", partition_label(zone.partition))],
        );
    }
    partition_label(zone.partition).to_owned()
}

fn hours(h: u64) -> String {
    if h != 0 && h % 24 == 0 {
        fill(
            &tr("{h} h ({j} d)"),
            &[("h", &h.to_string()), ("j", &(h / 24).to_string())],
        )
    } else {
        fill(&tr("{h} h"), &[("h", &h.to_string())])
    }
}

fn zone_type(value: ZoneType) -> String {
    match value {
        ZoneType::Cache => tr("cache"),
        ZoneType::Primary => tr("primary"),
        ZoneType::Secondary => tr("secondary"),
        ZoneType::Stub => tr("stub"),
        ZoneType::Forwarder => tr("forwarder"),
        ZoneType::SecondaryCache => tr("secondary cache"),
    }
}

fn dynamic_update(value: DynamicUpdate) -> String {
    match value {
        DynamicUpdate::None => tr_ctx("feminine", "none"),
        DynamicUpdate::NonSecure => tr("nonsecure and secure"),
        DynamicUpdate::Secure => tr("secure only"),
    }
}

fn known<T: Copy>(value: Option<Known<T>>, name: fn(T) -> String) -> String {
    match value {
        None => tr("not specified (server default)"),
        Some(Known::Known(v)) => name(v),
        Some(Known::Other(v)) => fill(&tr("unknown value ({v})"), &[("v", &v.to_string())]),
    }
}

/// Settings of the zone (`dNSProperty`): (label, value); « not specified » if absent
/// (`lignes_reglages`).
pub fn settings_lines(settings: &ZoneSettings) -> Vec<(String, String)> {
    let mut lines = vec![
        (tr("Zone type"), known(settings.zone_type, zone_type)),
        (
            tr("Dynamic updates"),
            known(settings.dynamic_update, dynamic_update),
        ),
    ];
    match settings.aging {
        None => lines.push((tr("Aging"), tr("not specified (server default)"))),
        Some(on) => {
            let mut parts = vec![if on { tr("enabled") } else { tr("disabled") }];
            if let Some(h) = settings.no_refresh_interval {
                parts.push(fill(&tr("no-refresh {d}"), &[("d", &hours(h))]));
            }
            if let Some(h) = settings.refresh_interval {
                parts.push(fill(&tr("refresh {d}"), &[("d", &hours(h))]));
            }
            lines.push((tr("Aging"), parts.join(", ")));
        }
    }
    if !settings.others.is_empty() {
        let mut names: Vec<String> = settings.others.iter().map(|p| p.name()).collect();
        names.sort();
        names.dedup();
        lines.push((tr("Other settings"), names.join(", ")));
    }
    if settings.unreadable > 0 {
        lines.push((tr("Unreadable settings"), settings.unreadable.to_string()));
    }
    lines
}

/// The settings on one line, for the header of the table of the root of a zone
/// (`resume_reglages`).
pub fn settings_summary(settings: &ZoneSettings) -> String {
    if *settings == ZoneSettings::default() {
        return tr("Zone settings missing from the directory: those of the DNS server apply");
    }
    settings_lines(settings)
        .into_iter()
        .take(3)
        .map(|(name, value)| setting_line(&name, &value))
        .collect::<Vec<_>>()
        .join(" · ")
}

/// « name: value », in the tooltip of the settings.
pub fn setting_line(name: &str, value: &str) -> String {
    fill(&tr("{nom}: {valeur}"), &[("nom", name), ("valeur", value)])
}

// --- Writes --------------------------------------------------------------------------------

fn field(f: Field) -> String {
    match f {
        Field::Priority => tr("Priority"),
        Field::Weight => tr("Weight"),
        Field::Port => tr("Port"),
        Field::Ttl => tr("TTL"),
    }
}

/// The sentence of a refused DNS request (`ErreurDns.message`).
pub fn dns_error(error: &DnsError) -> String {
    match error {
        DnsError::EmptyName => tr("Empty name."),
        DnsError::NameTooLong { name } => fill(
            &tr("Name longer than 253 characters: “{nom}”."),
            &[("nom", name)],
        ),
        DnsError::EmptyLabel { name } => fill(
            &tr("Empty label (two consecutive dots) in “{nom}”."),
            &[("nom", name)],
        ),
        DnsError::WildcardFirstOnly => tr("“*” is only allowed at the start of a record name."),
        DnsError::InvalidLabel { label } => fill(
            &tr(
                "“{etiquette}” is not a valid DNS label: unaccented letters, digits, hyphens (not at either end) and underscores, 63 characters at most.",
            ),
            &[("etiquette", label)],
        ),
        DnsError::EmptyNameUseAt => tr("Empty name: type “@” for the zone itself."),
        DnsError::NotInZone { name, zone } => fill(
            &tr("“{nom}” is not in the {zone} zone."),
            &[("nom", name), ("zone", zone)],
        ),
        DnsError::EmptyText => tr("Empty text."),
        DnsError::QuotedTextExpected { rest } => fill(
            &tr("Quoted text expected, found “{reste}”."),
            &[("reste", rest)],
        ),
        DnsError::MissingQuote => tr("Missing closing quote."),
        DnsError::StringTooLong => {
            tr("String longer than 255 bytes: split it into several strings.")
        }
        DnsError::OutOfRange {
            field: f,
            value,
            max,
        } => fill(
            &tr("{nom}: {valeur} out of range (0 to {max})."),
            &[
                ("nom", &field(*f)),
                ("valeur", &value.to_string()),
                ("max", &max.to_string()),
            ],
        ),
        DnsError::TypeNotWritten { rtype } => fill(
            &tr("Type {type}: the tool only writes A, AAAA, CNAME, PTR, MX, SRV and TXT."),
            &[("type", rtype)],
        ),
        DnsError::Ipv4Expected => tr("IPv4 address expected."),
        DnsError::Ipv6Expected => tr("IPv6 address expected."),
        DnsError::TargetExpected => tr("Target name expected."),
        DnsError::MxExpected => tr("Priority and mail server expected."),
        DnsError::SrvExpected => tr("Priority, weight, port and target expected."),
        DnsError::TextExpected => tr("Text expected."),
        DnsError::InvalidInput { text, .. } => {
            fill(&tr("Invalid input: “{texte}”."), &[("texte", text)])
        }
        DnsError::InvalidAddress { text } => {
            fill(&tr("Invalid IP address: “{a}”."), &[("a", text)])
        }
        DnsError::UnreadableNode { name } => fill(
            &tr(
                "The name {nom} cannot be read with this account: its records cannot be modified without read permission.",
            ),
            &[("nom", name)],
        ),
        DnsError::NoRootNode { zone, dc } => fill(
            &tr("The {zone} zone has no @ node on {dc}."),
            &[("zone", zone), ("dc", dc)],
        ),
        DnsError::BadSoa { zone } => fill(
            &tr("The SOA of the {zone} zone is missing, duplicated or unreadable."),
            &[("zone", zone)],
        ),
        DnsError::NoVersion { .. } => tr("The server does not report the object's version."),
        DnsError::RecordGone { name } => fill(
            &tr(
                "The record is no longer on {nom} (modified or deleted in the meantime): refresh the window.",
            ),
            &[("nom", name)],
        ),
        DnsError::NotModifiable { rtype } => fill(
            &tr(
                "This record ({type}) cannot be modified by the tool: unsupported type, unreadable data or unknown rank.",
            ),
            &[("type", rtype)],
        ),
        DnsError::AlreadyThere { name, rtype } => fill(
            &tr("{nom} already has this record ({type})."),
            &[("nom", name), ("type", rtype)],
        ),
        DnsError::CnameNotAlone { name, types } => fill(
            &tr(
                "A CNAME must be alone on its name: {nom} already has {types}. Remove them first, or choose another name.",
            ),
            &[("nom", name), ("types", types)],
        ),
        DnsError::IsAlias { name } => fill(
            &tr(
                "{nom} is an alias (CNAME): it cannot hold anything else. Add the record to the target name, or remove the CNAME first.",
            ),
            &[("nom", name)],
        ),
        DnsError::NoChange => tr("No change: same data and TTL."),
        DnsError::NoRequest => tr("no DNS request"),
        DnsError::WrittenAndPurged { name } => fill(
            &tr("{nom} cannot be both written and purged."),
            &[("nom", name)],
        ),
        DnsError::NoLongerExists { name } => {
            fill(&tr("{nom} no longer exists: refresh."), &[("nom", name)])
        }
        DnsError::NoLongerTombstone { name } => fill(
            &tr(
                "{nom} is no longer a tombstone (brought back into service in the meantime): refresh.",
            ),
            &[("nom", name)],
        ),
        DnsError::UnexpectedRootOperation { .. } => {
            tr("Unexpected operation on the @ node of the zone.")
        }
        DnsError::Change(text) => crate::codec_texts::codec_message(text),
    }
}

/// Technical detail of a refused DNS request (the parser's message), empty otherwise.
pub fn dns_error_detail(error: &DnsError) -> String {
    match error {
        DnsError::InvalidInput { detail, .. } => detail.clone(),
        DnsError::UnexpectedRootOperation { dn } => dn.clone(),
        _ => String::new(),
    }
}

/// What will be proposed, one sentence per request (`_decrire`).
pub fn describe_requests(requests: &[Request]) -> String {
    let mut lines = Vec::new();
    for r in requests {
        let (verb, zone, name, rtype, data, ttl) = match r {
            Request::Add {
                zone,
                name,
                rtype,
                data,
                ttl,
            } => (tr("Add"), zone, name, rtype, data, ttl),
            Request::Modify {
                zone,
                name,
                rtype,
                data,
                ttl,
                ..
            } => (tr("Replace with"), zone, name, rtype, data, ttl),
            _ => continue,
        };
        let record = Record::new(*rtype, data.clone());
        lines.push(fill(
            &tr("{verbe}: {nom} {type} {donnees}, TTL {ttl} s"),
            &[
                ("verbe", &verb),
                ("nom", &fqdn(&zone.name, name)),
                ("type", &record.type_name()),
                ("donnees", &record.data_text().unwrap_or_default()),
                ("ttl", &ttl.to_string()),
            ],
        ));
    }
    lines.join("\n")
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use annuaire_codecs::dns_property::ZoneProperty;
    use annuaire_core::dns::node_dn;

    const ZONES: &str = "CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=test";

    fn txt(text: &str) -> Vec<u8> {
        Record::new(dns_record::TXT, RecordData::Txt(vec![text.into()]))
            .encode()
            .unwrap()
    }

    fn a(address: &str) -> Vec<u8> {
        let mut r = Record::new(dns_record::A, RecordData::Address(address.parse().unwrap()));
        r.ttl = 900;
        r.encode().unwrap()
    }

    fn node(name: &str, values: Vec<Vec<u8>>, tombstone: bool) -> Node {
        Node {
            dn: node_dn(&format!("DC=lab.test,{ZONES}"), name),
            name: name.into(),
            zone: "lab.test".into(),
            values,
            tombstone,
            modified: None,
            unreadable: false,
        }
    }

    const NAMES: [&str; 9] = [
        "dc1",
        "DC2",
        "DomainDnsZones",
        "_ldap._tcp.DomainDnsZones",
        "_ldap._tcp",
        "_kerberos._tcp",
        "_ldap._tcp.Default-First-Site-Name._sites",
        "_ldap._tcp.dc._msdcs",
        "intranet",
    ];

    fn marked_zone() -> Vec<Node> {
        let mut nodes: Vec<Node> = NAMES.iter().map(|n| node(n, vec![txt(n)], false)).collect();
        let mut soa = Record::new(
            dns_record::SOA,
            RecordData::Soa {
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
                primary_server: "dc1.lab.test".into(),
                responsible: "h.lab.test".into(),
            },
        );
        soa.ttl = 3600;
        let ns = Record::new(dns_record::NS, RecordData::Name("dc1.lab.test".into()));
        nodes.push(node(
            ROOT,
            vec![
                soa.encode().unwrap(),
                ns.encode().unwrap(),
                a("192.168.1.27"),
                txt("@"),
            ],
            false,
        ));
        nodes.push(node("tombe", vec![a("192.0.2.1")], true));
        nodes
    }

    fn all(b: &Branch) -> Vec<&Branch> {
        let mut out = vec![b];
        for c in &b.children {
            out.extend(all(c));
        }
        out
    }

    #[test]
    fn each_name_shows_only_its_records() {
        let zone = marked_zone();
        let t = tree("lab.test", &zone, false);
        let mut seen = Vec::new();
        for b in all(&t) {
            let lines = record_lines(b);
            let marks: Vec<String> = lines
                .iter()
                .filter(|l| l.rtype == "TXT")
                .map(|l| l.data.clone())
                .collect();
            let Some(n) = &b.node else {
                assert!(lines.is_empty() && !b.children.is_empty(), "{}", b.fqdn());
                continue;
            };
            assert_eq!(marks, [format!("\"{}\"", n.name)], "{}", b.fqdn());
            seen.push(n.name.clone());
        }
        seen.sort();
        let mut expected: Vec<String> = NAMES.iter().map(|n| (*n).to_owned()).collect();
        expected.push(ROOT.into());
        expected.sort();
        assert_eq!(seen, expected); // tombstone hidden by default
        assert!(t.is_root() && t.relative() == "@" && t.fqdn() == "lab.test");
        let lines = record_lines(&t);
        assert_eq!(
            lines.iter().map(|l| l.rtype.as_str()).collect::<Vec<_>>(),
            ["SOA", "NS", "A", "TXT"]
        );
        let ddz = t
            .children
            .iter()
            .find(|b| b.name() == "DomainDnsZones")
            .unwrap();
        assert_eq!(
            all(ddz)[1..]
                .iter()
                .map(|b| b.relative())
                .collect::<Vec<_>>(),
            ["_tcp.DomainDnsZones", "_ldap._tcp.DomainDnsZones"]
        );
        assert_eq!(
            branch_summary(ddz),
            "1 record at this name; 2 names below, in the tree, not counted here"
        );
        assert!(
            tree("lab.test", &zone, true)
                .children
                .iter()
                .any(|b| b.name() == "tombe" && b.icon() == TOMBSTONE_ICON)
        );
    }

    #[test]
    fn order_and_case() {
        let nodes = vec![
            node("10", vec![a("192.0.2.1")], false),
            node("9", vec![a("192.0.2.1")], false),
            node("b", vec![a("192.0.2.1")], false),
            node("É", vec![a("192.0.2.1")], false),
            node("a", vec![a("192.0.2.1")], false),
            node("x.dc2", vec![a("192.0.2.1")], false),
            node("DC2", vec![a("192.0.2.1")], false),
        ];
        let t = tree("z", &nodes, false);
        assert_eq!(
            t.children.iter().map(|b| b.name()).collect::<Vec<_>>(),
            ["9", "10", "a", "b", "DC2", "É"]
        );
        let dc2 = &t.children[4];
        assert!(dc2.node.is_some() && dc2.children.len() == 1);
        assert_eq!(dc2.icon(), FOLDER_ICON);
    }

    #[test]
    fn lines() {
        let mut srv = Record::new(
            dns_record::SRV,
            RecordData::Srv {
                priority: 0,
                weight: 100,
                port: 389,
                target: "dc1.lab.test".into(),
            },
        );
        srv.ttl = 900;
        let l = record_line(&srv, &srv.encode().unwrap());
        assert_eq!(
            (
                l.rtype.as_str(),
                l.data.as_str(),
                l.ttl.as_str(),
                l.timestamp.as_str(),
                l.remark.as_str()
            ),
            (
                "SRV",
                "0 100 389 dc1.lab.test",
                "900 s (15 min)",
                "static",
                ""
            )
        );
        assert!(l.modifiable);
        assert_eq!(duration_text(3600), "3600 s (1 h)");
        assert_eq!(duration_text(86400), "86400 s (1 d)");
        assert_eq!(duration_text(1200), "1200 s (20 min)");
        assert_eq!(duration_text(7), "7 s");
        let mut glue = Record::new(dns_record::NS, RecordData::Name("dc1.lab.test".into()));
        glue.rank = 0x82;
        assert!(record_line(&glue, &[]).remark.contains("delegation"));
        let mut cache = Record::new(
            dns_record::A,
            RecordData::Address("1.2.3.4".parse().unwrap()),
        );
        cache.rank = 0x08;
        assert!(
            record_line(&cache, &[])
                .remark
                .contains("outside the zone (ROOT_HINT)")
        );
        let n = node("x", vec![txt("x"), vec![1, 2]], false);
        let b = tree("lab.test", std::slice::from_ref(&n), false);
        assert!(branch_summary(&b.children[0]).contains("1 unreadable value(s)"));
        let mut odd = Record::new(
            dns_record::A,
            RecordData::Address("192.0.2.9".parse().unwrap()),
        );
        odd.rank = 0x13;
        let v = odd.encode().unwrap();
        assert!(!record_line(&odd, &v).modifiable);
    }

    #[test]
    fn zone_settings() {
        let integer = |id, value| {
            ZoneProperty::integer(id, value, None)
                .unwrap()
                .encode()
                .unwrap()
        };
        use annuaire_codecs::dns_property as p;
        let values = [
            integer(p::TYPE, 1),
            integer(p::ALLOW_UPDATE, 2),
            integer(p::AGING_STATE, 0),
            integer(p::NOREFRESH_INTERVAL, 168),
            integer(p::REFRESH_INTERVAL, 168),
            ZoneProperty::new(p::SECURE_TIME, vec![0; 8])
                .encode()
                .unwrap(),
        ];
        let settings = ZoneSettings::from_values(values.iter().map(Vec::as_slice));
        let lines: HashMap<String, String> = settings_lines(&settings).into_iter().collect();
        assert_eq!(lines["Zone type"], "primary");
        assert_eq!(lines["Dynamic updates"], "secure only");
        assert_eq!(
            lines["Aging"],
            "disabled, no-refresh 168 h (7 d), refresh 168 h (7 d)"
        );
        assert_eq!(lines["Other settings"], "SECURE_TIME");
        assert!(settings_summary(&settings).starts_with("Zone type: primary · "));
        assert!(settings_summary(&ZoneSettings::default()).starts_with("Zone settings missing"));
    }

    fn dated(n: Node, minute: i64) -> Node {
        let base = UtcTime::from_civil(annuaire_codecs::time::Civil {
            year: 2026,
            month: 10,
            day: 14,
            hour: 6,
            minute: 0,
            second: 0,
            fraction: 0,
        })
        .unwrap();
        Node {
            modified: base.add_seconds(minute * 60),
            ..n
        }
    }

    fn at(minute: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000 + minute * 60)
    }

    #[test]
    fn corrected_by_the_nodes_read_again() {
        let old = dated(node("web", vec![a("192.0.2.1")], false), 0);
        let again = dated(node("web", vec![a("192.0.2.2")], false), 5);
        let new = dated(node("neuf", vec![a("192.0.2.3")], false), 5);
        let other = dated(node("autre", vec![a("192.0.2.4")], false), 0);
        let gone = dated(node("retire", vec![a("192.0.2.5")], false), 0);
        let written = vec![
            Written {
                dn: again.dn.clone(),
                node: Some(again.clone()),
                read_at: at(5),
            },
            Written {
                dn: new.dn.clone(),
                node: Some(new.clone()),
                read_at: at(5),
            },
            Written {
                dn: gone.dn.clone(),
                node: None,
                read_at: at(5),
            },
        ];
        let out = correct(&[old.clone(), other, gone], &written, at(6));
        assert_eq!(
            out.iter().map(|n| n.name.as_str()).collect::<Vec<_>>(),
            ["web", "autre", "neuf"]
        );
        assert_eq!(out[0], again);
        let caught_up = dated(node("web", vec![a("192.0.2.2")], false), 5);
        assert_eq!(
            correct(std::slice::from_ref(&caught_up), &written[..1], at(6))[0],
            caught_up
        );
        assert_eq!(
            correct(std::slice::from_ref(&old), &written[..1], at(40))[0],
            old
        );
        // In the window, the nodes read again replace those shown, without condition.
        let deleted = dated(node("web", vec![a("192.0.2.1")], true), 5);
        let back = dated(node("web", vec![a("192.0.2.1")], false), 5);
        let w = Written {
            dn: back.dn.clone(),
            node: Some(back.clone()),
            read_at: at(5),
        };
        assert_eq!(
            replace(std::slice::from_ref(&deleted), std::slice::from_ref(&w)),
            [back]
        );
        let w = Written { node: None, ..w };
        assert!(replace(&[deleted], &[w]).is_empty());
    }
}

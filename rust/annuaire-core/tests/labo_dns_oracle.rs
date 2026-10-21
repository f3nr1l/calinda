// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The DNS of the core against the DNS tools of the DCs of LAB.TEST (port of
//! `test_dns_labo.py`, `test_sante_dns_labo.py` and of what `labo_dns` did not take from
//! `test_dns_ecriture_labo.py`, ADR 0020).
//!
//! - `dns_read_as_samba_tool`: for `lab.test`, `_msdcs.lab.test` and `1.168.192.in-addr.arpa`,
//!   the names read by LDAP give, name by name, what `samba-tool dns query <zone> <name> ALL`
//!   gives on dc1 (walked recursively): the same names, intermediate ones included, the same
//!   number of names below each, the same records (type, data, rank, serial, TTL) of each name
//!   only. The anomalies sown by `peupler.py` are read as the other records; a tombstone stays
//!   a tombstone.
//! - `dns_health_sown`: the anomalies sown by `labo/peupler.py` are all found, and only them
//!   (plus those of the lab documented one by one); the rules of the DCs find nothing else.
//! - `dns_health_fixes`: defects of trial (`essai-j35-*`, the PTR of a free address of
//!   192.168.1.240-254) found and fixed one at a time, each preview checked; a rollback that
//!   leaves the SOA incremented.
//! - `dns_types_as_samba_tool`: the seven types written by the core (`essai-j34-<type>`)
//!   compared byte for byte with what `samba-tool dns add/update` writes (`essai-j34-st-<type>`),
//!   up to the serial, each carrying the serial of the SOA of its write, seen by `dig` on dc1
//!   and dc2 and by `samba-tool dns query`; the deletion of the last record (a tombstone, unlike
//!   samba-tool), then the name back in service; the undo of a modification that gives back the
//!   bytes; an ordinary account (`gaelle.lambert`, a process of its own) that writes without
//!   incrementing the SOA, then sees a node whose DACL denies it the reading: unreadable,
//!   without records, not writable.
//!
//! LAB.TEST only. Only names of trial are written, all removed at the end, even after a
//! failure, and their absence checked on dc1 and dc2 (`ldbsearch`, `samba-tool`, `dig`). See
//! `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use annuaire_codecs::dns_property::{DynamicUpdate, Known, ZoneType};
use annuaire_codecs::dns_record::{self, Record, RecordData};
use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::time;
use annuaire_core::Connection;
use annuaire_core::changes::{self, Changeset, Issue, Operation};
use annuaire_core::dns::{self, Node, Partition, Zone};
use annuaire_core::dns_health::{self, Rule, Settings};
use annuaire_core::dns_write::{self as w, DnsError, PrepareError, Request};
use annuaire_core::messages::English;
use annuaire_core::search::{SD_DACL, sd_flags_control};
use annuaire_core::session::{Modification, Scope};
use annuaire_core::source::{self, DirectSource};
use serde_json::{Value as Json, json};

use labo::{Lab, Result, Trial, check, debug, entries, samba_only};

const DC1: &str = "dc1.lab.test";
const ZONE: &str = "lab.test";
const ZONE_REVERSE: &str = "1.168.192.in-addr.arpa";
const ADDRESSES: [(&str, &str); 2] = [("dc1", "192.168.1.27"), ("dc2", "192.168.1.28")];
const ORDINARY: &str = "gaelle.lambert";

// --- Common --------------------------------------------------------------------------------------

fn zones(connection: &Connection) -> Result<HashMap<String, Zone>> {
    Ok(dns::zones(connection)
        .map_err(debug)?
        .into_iter()
        .map(|z| (z.name.clone(), z))
        .collect())
}

/// The node read on the PDC; None if absent.
fn node(connection: &Connection, zone: &Zone, name: &str) -> Result<Option<Node>> {
    let read = dns::reread_nodes(connection, &[dns::node_dn(&zone.dn, name)]).map_err(debug)?;
    Ok(read.into_iter().next().and_then(|(_, n)| n))
}

/// The values of a node and `dNSTombstoned` ([] and None if absent).
fn values(
    connection: &Connection,
    zone: &Zone,
    name: &str,
) -> Result<(Vec<Vec<u8>>, Option<String>)> {
    let entry = labo::entry(
        connection,
        &dns::node_dn(&zone.dn, name),
        &["dnsRecord", "dNSTombstoned"],
        None,
    )?;
    Ok(match entry {
        None => (Vec::new(), None),
        Some(e) => (
            e.values("dnsRecord").to_vec(),
            e.values("dNSTombstoned")
                .first()
                .map(|v| String::from_utf8_lossy(v).into_owned()),
        ),
    })
}

/// (serial of the data, serial of the header) of the SOA, read by LDAP on the PDC.
fn soa(connection: &Connection, zone: &Zone) -> Result<(u32, u32)> {
    let read = node(connection, zone, dns::ROOT)?.ok_or("@")?;
    read.records()
        .into_iter()
        .find_map(|r| match r.data {
            RecordData::Soa { serial, .. } => Some((serial, r.serial)),
            _ => None,
        })
        .ok_or_else(|| "no SOA".into())
}

fn without_serial(value: &[u8]) -> Vec<u8> {
    let mut v = value.to_vec();
    for b in v.iter_mut().skip(8).take(4) {
        *b = 0;
    }
    v
}

fn add(zone: &Zone, name: &str, rtype: u16, text: &str) -> Result<Request> {
    Ok(Request::Add {
        zone: zone.clone(),
        name: name.into(),
        rtype,
        data: w::read_input(rtype, text).map_err(debug)?,
        ttl: w::DEFAULT_TTL,
    })
}

/// The requests built on the PDC and applied, with a new attempt on a conflict on the SOA.
fn write(trial: &Trial, requests: Vec<Request>) -> Result<(Changeset, changes::Report)> {
    let cs = w::build(&trial.connection, requests.clone(), Arc::new(English)).map_err(debug)?;
    let outcome = trial.outcome(&cs, None, Some(w::rebuild(requests, Arc::new(English))))?;
    if outcome.report.issue != Issue::Applied {
        return Err(format!(
            "not applied: {:?} {:?}",
            outcome.report.error, outcome.problems
        )
        .into());
    }
    Ok((cs, outcome.report))
}

/// (status, answers) of `dig` against a DC, without recursion.
fn dig(dc: &str, name: &str, rtype: &str) -> Result<(String, Vec<String>)> {
    let address = ADDRESSES
        .iter()
        .find(|(d, _)| *d == dc)
        .map(|(_, a)| *a)
        .ok_or("DC")?;
    let out = Command::new("dig")
        .args([
            "+noall",
            "+comments",
            "+answer",
            "+norecurse",
            "+time=3",
            "+tries=2",
            &format!("@{address}"),
            name,
            rtype,
        ])
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut status = "?".to_owned();
    let mut answers = Vec::new();
    for line in text.lines() {
        if let Some((_, rest)) = line.split_once("status:") {
            status = rest.split(',').next().unwrap_or_default().trim().to_owned();
        } else if !line.is_empty() && !line.starts_with(';') {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 5 && parts[3] == rtype {
                answers.push(parts[4..].join(" "));
            }
        }
    }
    answers.sort();
    Ok((status, answers))
}

fn dig_serial(dc: &str, zone: &str) -> Result<u32> {
    let (_, answers) = dig(dc, zone, "SOA")?;
    Ok(answers
        .first()
        .and_then(|a| a.split_whitespace().nth(2))
        .ok_or("SOA")?
        .parse()?)
}

/// Waits until `dig` against `dc` gives these values for each (name, type).
fn wait_dig(dc: &str, wanted: &BTreeMap<(String, String), Vec<String>>, limit: u64) -> Result<f64> {
    labo::wait(
        Duration::from_secs(limit),
        &format!("{dc}: {wanted:?}"),
        || {
            for ((name, rtype), values) in wanted {
                let mut values = values.clone();
                values.sort();
                if dig(dc, name, rtype)?.1 != values {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    )
}

/// Record lines of `samba-tool dns query <zone> <name> ALL` (empty: absent), on a DC.
fn samba_tool_query(dc: &str, names: &[(String, String)]) -> Result<BTreeMap<String, Vec<String>>> {
    let mut script = String::new();
    for (zone, name) in names {
        script.push_str(&format!(
            "echo '== {name}'\nsudo samba-tool dns query 127.0.0.1 {} {} ALL -P 2>&1 || true\n",
            labo::quote(zone),
            labo::quote(name)
        ));
    }
    let types = ["A", "AAAA", "CNAME", "PTR", "SRV", "MX", "TXT", "NS", "SOA"];
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut key = String::new();
    for line in labo::ssh(dc, &script)?.lines() {
        if let Some(name) = line.strip_prefix("== ") {
            key = name.to_owned();
            out.insert(key.clone(), Vec::new());
        } else if types.contains(&line.trim().split(':').next().unwrap_or_default()) {
            out.entry(key.clone())
                .or_default()
                .push(line.trim().to_owned());
        }
    }
    Ok(out)
}

/// `MX: x.lab.test. (10) (flags=f0, …)` → `10 x.lab.test.` (the form of dig).
fn as_dig(line: &str) -> String {
    let (rtype, rest) = line.split_once(": ").unwrap_or((line, ""));
    let value = rest.rsplit_once(" (flags=").map_or(rest, |(v, _)| v);
    match rtype {
        "AAAA" => value
            .parse::<IpAddr>()
            .map_or_else(|_| value.to_owned(), |a| a.to_string()),
        "CNAME" | "PTR" | "NS" => format!("{}.", value.trim_end_matches('.')),
        "MX" => {
            let (target, preference) = value.rsplit_once(" (").unwrap_or((value, ""));
            format!(
                "{} {}.",
                preference.trim_end_matches(')'),
                target.trim_end_matches('.')
            )
        }
        "SRV" => {
            let (target, numbers) = value.split_once(" (").unwrap_or((value, ""));
            let n: Vec<&str> = numbers
                .trim_end_matches(')')
                .split(',')
                .map(str::trim)
                .collect();
            format!(
                "{} {} {} {}.",
                n.get(1).unwrap_or(&""),
                n.get(2).unwrap_or(&""),
                n.first().unwrap_or(&""),
                target.trim_end_matches('.')
            )
        }
        "TXT" => value.replace("\",\"", "\" \""),
        _ => value.to_owned(),
    }
}

/// dig on dc1 at once, dc2 after the replication, samba-tool on both.
fn everywhere(wanted: &BTreeMap<(String, String), Vec<String>>) -> Result<()> {
    wait_dig("dc1", wanted, 10)?;
    let seconds = wait_dig("dc2", wanted, 120)?;
    println!("  seen by dig on dc2 after {seconds:.1} s");
    for (dc, _) in ADDRESSES {
        let names: Vec<(String, String)> = wanted
            .keys()
            .map(|(fqdn, _)| {
                let (name, zone) = fqdn.split_once('.').unwrap_or((fqdn, ""));
                (zone.to_owned(), name.to_owned())
            })
            .collect();
        let read = samba_tool_query(dc, &names)?;
        for ((fqdn, rtype), values) in wanted {
            let name = fqdn.split_once('.').map_or(fqdn.as_str(), |(n, _)| n);
            let mut seen: Vec<String> = read
                .get(name)
                .into_iter()
                .flatten()
                .filter(|l| l.starts_with(&format!("{rtype}:")))
                .map(|l| as_dig(l))
                .collect();
            seen.sort();
            let mut values = values.clone();
            values.sort();
            check(
                seen == values,
                &format!("samba-tool on {dc}: {fqdn} {rtype}"),
            )?;
        }
    }
    Ok(())
}

/// Deletes the nodes `prefix*` of both zones on the PDC (as `samba-tool dns delete`), and the
/// node `extra` of the reverse zone if every live record of it is ours; their names.
fn delete_nodes(
    connection: &Connection,
    zones: &HashMap<String, Zone>,
    prefix: &str,
    extra: Option<&str>,
) -> Result<Vec<String>> {
    let mut dns_list = Vec::new();
    for zone_name in [ZONE, ZONE_REVERSE] {
        let zone = &zones[zone_name];
        let mut filter = format!("(name={prefix}*)");
        if let Some(extra) = extra {
            filter = format!("(|{filter}(name={extra}))");
        }
        for e in entries(
            connection,
            &zone.dn,
            Scope::OneLevel,
            &filter,
            &["dnsRecord"],
        )? {
            let live: Vec<&Vec<u8>> = e
                .values("dnsRecord")
                .iter()
                .filter(|v| v.get(2..4) != Some(&[0, 0][..]))
                .collect();
            let is_extra = extra.is_some_and(|x| e.dn.starts_with(&format!("DC={x},")));
            if is_extra
                && !live
                    .iter()
                    .all(|v| v.windows(prefix.len()).any(|w| w == prefix.as_bytes()))
            {
                continue; // not ours: left alone
            }
            dns_list.push(e.dn);
        }
    }
    let to_delete = dns_list.clone();
    connection
        .run(false, move |link| {
            for dn in &to_delete {
                let id = link.session.delete(dn, Vec::new())?;
                link.session.result(id, Some(link.timeout))?;
            }
            Ok(())
        })
        .map_err(debug)?;
    Ok(dns_list)
}

/// Nothing of the trial left on dc1 and dc2: `ldbsearch`, `samba-tool`, `dig`.
fn nothing_left(lab: &Lab, prefix: &str, names: &[&str], extra: Option<&str>) -> Result<()> {
    let base = format!("DC=DomainDnsZones,{}", lab.base);
    let mut filter = format!("(name={prefix}*)");
    if let Some(extra) = extra {
        filter = format!("(|{filter}(name={extra}))");
    }
    let filter = format!("(&(objectClass=dnsNode){filter})");
    for (dc, _) in ADDRESSES {
        labo::wait(
            Duration::from_secs(120),
            &format!("nothing left on {dc}"),
            || {
                let left: Vec<String> = labo::ldbsearch(dc, &base, "sub", &filter, &["dn"])?
                    .iter()
                    .filter_map(|r| labo::ldif_text(r, "dn"))
                    .filter(|d| d.contains(prefix) || d.contains(ZONE_REVERSE))
                    .collect();
                Ok(left.is_empty())
            },
        )?;
        let query: Vec<(String, String)> = names
            .iter()
            .flat_map(|n| {
                [
                    (ZONE.to_owned(), (*n).to_owned()),
                    (ZONE_REVERSE.to_owned(), (*n).to_owned()),
                ]
            })
            .collect();
        let read = samba_tool_query(dc, &query)?;
        check(
            read.values().all(Vec::is_empty),
            &format!("{dc}: samba-tool finds nothing"),
        )?;
        for n in names {
            let (status, _) = dig(dc, &format!("{n}.{ZONE}"), "ANY")?;
            check(status == "NXDOMAIN", &format!("{dc}: {n} NXDOMAIN"))?;
        }
        if let Some(extra) = extra {
            check(
                dig(dc, &format!("{extra}.{ZONE_REVERSE}"), "PTR")?
                    .1
                    .is_empty(),
                &format!("{dc}: no PTR {extra}"),
            )?;
        }
        let line = labo::showrepl(dc)?;
        check(line.contains("ALL GOOD"), &format!("{dc}: {line}"))?;
    }
    Ok(())
}

/// A free address of 192.168.1.240-254: no node of that name in the reverse zone (tombstone
/// included) and no A of lab.test on it; its name in the reverse zone.
fn free_address(
    connection: &Connection,
    zones: &HashMap<String, Zone>,
) -> Result<(String, String)> {
    let taken: BTreeSet<String> = entries(
        connection,
        &zones[ZONE_REVERSE].dn,
        Scope::OneLevel,
        "(objectClass=*)",
        &["1.1"],
    )?
    .iter()
    .filter_map(|e| {
        annuaire_core::dn::split(&e.dn)
            .ok()?
            .into_iter()
            .next()
            .map(|c| c.value.to_lowercase())
    })
    .collect();
    let mut used = BTreeSet::new();
    for e in entries(
        connection,
        &zones[ZONE].dn,
        Scope::OneLevel,
        dns::NODES_FILTER,
        &["dnsRecord"],
    )? {
        for v in e.values("dnsRecord") {
            if let Ok(Record {
                data: RecordData::Address(a),
                ..
            }) = Record::decode(v)
            {
                used.insert(a.to_string());
            }
        }
    }
    (240..=254)
        .map(|k| (format!("192.168.1.{k}"), k.to_string()))
        .find(|(address, name)| !taken.contains(name) && !used.contains(address))
        .ok_or_else(|| "no free address in 192.168.1.240-254".into())
}

// --- Reading against samba-tool -----------------------------------------------------------------

/// Run on dc1 (`python3 -`, as root): the zone walked by samba-tool, name by name. Each block
/// `Name=X, Records=n, Children=m` belongs to its full name; the first block of a query is the
/// name asked itself (its Children is 0 there: the number comes from the block of the parent).
const WALK: &str = r#"
import json, re, subprocess, sys
zone = sys.argv[1]
names, errors, to_see = {}, [], ["@"]
block = re.compile(r"^  Name=(.*), Records=(\d+), Children=(\d+)$")
while to_see:
    name = to_see.pop()
    out = subprocess.run(["samba-tool", "dns", "query", "127.0.0.1", zone, name, "ALL", "-P"],
                         capture_output=True, text=True)
    if out.returncode:
        errors.append([name, out.stderr.strip()[-200:]])
        continue
    current = None
    for line in out.stdout.splitlines():
        m = block.match(line)
        if m:
            below, children = m.group(1), int(m.group(3))
            full = name if not below else (below if name == "@" else below + "." + name)
            current = names.setdefault(full, {"children": None, "records": []})
            current["records"] = []
            if below:
                current["children"] = children
                if children:
                    to_see.append(full)
            continue
        if line.startswith("    ") and current is not None:
            current["records"].append(line.strip())
print(json.dumps({"names": names, "errors": errors}))
"#;

type Shown = (String, String, u8, u32, u32);

/// A record line of `samba-tool dns query`, in a comparable form.
fn from_samba_tool(line: &str) -> Result<Shown> {
    let (rtype, rest) = line.split_once(": ").ok_or("line")?;
    let (data, tail) = rest.rsplit_once(" (flags=").ok_or("flags")?;
    let tail = tail.trim_end_matches(')');
    let mut flags = 0u8;
    let (mut serial, mut ttl) = (0u32, 0u32);
    for part in tail.split(", ") {
        if let Some(v) = part.strip_prefix("serial=") {
            serial = v.parse()?;
        } else if let Some(v) = part.strip_prefix("ttl=") {
            ttl = v.parse()?;
        } else {
            flags = u8::try_from(u32::from_str_radix(part, 16)? & 0xFF)?;
        }
    }
    let trim = |t: &str| t.trim_end_matches('.').to_owned();
    let data = match rtype {
        "A" | "AAAA" => data.parse::<IpAddr>()?.to_string(),
        "NS" | "CNAME" | "PTR" => trim(data),
        "MX" => {
            let (target, preference) = data.rsplit_once(" (").ok_or("MX")?;
            format!("{} {}", preference.trim_end_matches(')'), trim(target))
        }
        "SRV" => {
            let (target, numbers) = data.split_once(" (").ok_or("SRV")?;
            let n: Vec<&str> = numbers.trim_end_matches(')').split(", ").collect();
            format!("{} {} {} {}", n[1], n[2], n[0], trim(target))
        }
        "SOA" => data
            .split(", ")
            .map(|p| match p.split_once('=') {
                Some((k @ ("ns" | "email"), v)) => format!("{k}={}", v.trim_end_matches('.')),
                _ => p.to_owned(),
            })
            .collect::<Vec<_>>()
            .join(", "),
        _ => data.to_owned(),
    };
    Ok((rtype.to_owned(), data, flags, serial, ttl))
}

/// The same record read by the core.
fn from_core(r: &Record) -> Result<Shown> {
    let data = match &r.data {
        RecordData::Soa {
            serial,
            refresh,
            retry,
            expire,
            minimum,
            primary_server,
            responsible,
        } => format!(
            "serial={serial}, refresh={refresh}, retry={retry}, expire={expire}, minttl={minimum}, ns={primary_server}, email={responsible}"
        ),
        RecordData::Txt(strings) => strings
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(","),
        _ => r.data_text()?,
    };
    Ok((r.type_name(), data, r.rank, r.serial, r.ttl))
}

/// Names of a zone as samba-tool shows them: the names of the nodes in service and the names
/// between them and the zone; for each, the number of names directly below and its records.
fn tree(nodes: &[Node]) -> BTreeMap<String, (usize, Vec<Record>)> {
    let mut all: BTreeMap<String, Vec<Record>> = BTreeMap::new();
    all.insert("@".into(), Vec::new());
    for n in nodes.iter().filter(|n| !n.tombstone) {
        let name = n.name.to_lowercase();
        all.insert(name.clone(), n.records());
        let labels: Vec<&str> = name.split('.').collect();
        for k in 1..labels.len() {
            all.entry(labels[k..].join(".")).or_default();
        }
    }
    if let Some(root) = nodes.iter().find(|n| n.is_root()) {
        all.insert("@".into(), root.records());
    }
    let names: Vec<String> = all.keys().cloned().collect();
    all.into_iter()
        .map(|(name, records)| {
            let children = names
                .iter()
                .filter(|other| {
                    *other != "@"
                        && **other != name
                        && match name.as_str() {
                            "@" => !other.contains('.'),
                            _ => other
                                .strip_suffix(&format!(".{name}"))
                                .is_some_and(|label| !label.contains('.')),
                        }
                })
                .count();
            (name, (children, records))
        })
        .collect()
}

fn read_nodes(source: &DirectSource, zone: &Zone) -> Result<Vec<Node>> {
    let flux = source.dns_nodes(zone, labo::quiet());
    let mut out = Vec::new();
    while let Some(page) = flux.next_page() {
        out.extend(
            page.map_err(debug)?
                .iter()
                .map(|e| dns::node_from_entry(e, &zone.name)),
        );
    }
    Ok(out)
}

#[test]
#[ignore = "lab"]
fn dns_read_as_samba_tool() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let mut profile = lab.profile(false);
    profile.preferred_dc = Some(DC1.into());
    let source =
        DirectSource::with_connection(profile.clone(), source::connection_to(&profile, Some(DC1)));
    source.open().map_err(debug)?;
    let zones: HashMap<String, Zone> = source
        .dns_zones()
        .map_err(debug)?
        .into_iter()
        .map(|z| (z.name.clone(), z))
        .collect();
    println!("1. the zones of the three places");
    check(
        [ZONE, ZONE_REVERSE].iter().all(|z| {
            zones
                .get(*z)
                .is_some_and(|z| z.partition == Partition::Domain)
        }) && zones
            .get("_msdcs.lab.test")
            .is_some_and(|z| z.partition == Partition::Forest),
        "domain and forest partitions",
    )?;
    // The legacy place: the root hints of Samba.
    let legacy = source.dns_zones().map_err(debug)?;
    check(
        legacy
            .iter()
            .any(|z| z.partition == Partition::Legacy && z.root_hints()),
        "root hints in the legacy place",
    )?;
    let settings = &zones[ZONE].settings;
    check(
        settings.zone_type == Some(Known::Known(ZoneType::Primary))
            && settings.dynamic_update == Some(Known::Known(DynamicUpdate::Secure))
            && settings.aging == Some(false),
        "settings of lab.test (primary, secure updates, no aging)",
    )?;
    check(
        zones["_msdcs.lab.test"].settings.zone_type.is_none(),
        "_msdcs: no dNSProperty",
    )?;

    println!("2. name by name, as samba-tool");
    for zone_name in [ZONE, "_msdcs.lab.test", ZONE_REVERSE] {
        let zone = &zones[zone_name];
        let t = Instant::now();
        let nodes = read_nodes(&source, zone)?;
        let read = t.elapsed().as_secs_f64();
        let core = tree(&nodes);
        let t = Instant::now();
        let oracle: Json = serde_json::from_str(&labo::ssh_python("dc1", WALK, &[zone_name])?)?;
        check(oracle["errors"] == json!([]), "samba-tool without error")?;
        let wanted: BTreeMap<String, &Json> = oracle["names"]
            .as_object()
            .ok_or("names")?
            .iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        let mut outside = 0;
        let mut differences = Vec::new();
        for (name, (children, records)) in &core {
            let Some(theirs) = wanted.get(name) else {
                differences.push(format!("{name}: not shown by samba-tool"));
                continue;
            };
            let mut mine: Vec<Shown> = Vec::new();
            for r in records {
                if r.rank == dns_record::RANK_ZONE {
                    mine.push(from_core(r)?);
                } else {
                    outside += 1;
                }
            }
            mine.sort();
            let mut samba: Vec<Shown> = theirs["records"]
                .as_array()
                .ok_or("records")?
                .iter()
                .map(|l| from_samba_tool(l.as_str().unwrap_or_default()))
                .collect::<Result<_>>()?;
            samba.sort();
            if mine != samba {
                differences.push(format!("{name}: {mine:?} / {samba:?}"));
            }
            if let Some(n) = theirs["children"].as_u64()
                && usize::try_from(n)? != *children
            {
                differences.push(format!("{name}: {children} names below / {n}"));
            }
        }
        let missing: Vec<&String> = wanted.keys().filter(|k| !core.contains_key(*k)).collect();
        println!(
            "  {zone_name}: {} names, read in {read:.2} s, samba-tool in {:.1} s, {outside} records out of rank ZONE, {} tombstones",
            core.len(),
            t.elapsed().as_secs_f64(),
            nodes.iter().filter(|n| n.tombstone).count()
        );
        for d in differences.iter().take(5) {
            println!("    {d}");
        }
        check(
            differences.is_empty() && missing.is_empty(),
            &format!("{zone_name} as samba-tool"),
        )?;
        // The root: its own records, none of those of the names below.
        check(
            core["@"]
                .1
                .iter()
                .all(|r| ["SOA", "NS", "A", "AAAA", "MX", "TXT"].contains(&r.type_name().as_str())),
            "the root, its own records",
        )?;
    }

    println!("3. the anomalies sown, read as the others");
    let nodes = read_nodes(&source, &zones[ZONE])?;
    let by_name: HashMap<String, &Node> =
        nodes.iter().map(|n| (n.name.to_lowercase(), n)).collect();
    let texts = |n: &Node| -> Vec<String> {
        n.records()
            .iter()
            .filter_map(|r| r.data_text().ok())
            .collect()
    };
    check(
        by_name.get("intranet").is_some_and(|n| {
            n.records()
                .iter()
                .map(|r| (r.type_name(), r.data_text().unwrap_or_default()))
                .collect::<Vec<_>>()
                == [("CNAME".to_owned(), "srv-intranet-old.lab.test".to_owned())]
        }),
        "intranet: CNAME to an absent host",
    )?;
    let reverse = read_nodes(&source, &zones[ZONE_REVERSE])?;
    let reverse: HashMap<String, &Node> = reverse.iter().map(|n| (n.name.clone(), n)).collect();
    check(
        reverse
            .get("200")
            .is_some_and(|n| texts(n) == ["ancien-srv01.lab.test"])
            && reverse
                .get("27")
                .is_some_and(|n| texts(n) == ["dc1.lab.test"]),
        "PTR to an absent name, PTR of dc1",
    )?;
    check(
        by_name.get("vecteur-tombe").is_some_and(|n| n.tombstone),
        "the tombstone of J0.8, a tombstone",
    )?;
    source.close();
    Ok(())
}

// --- DNS health ---------------------------------------------------------------------------------

type Key = (String, String, String, String, String);

/// The constants of `labo/peupler.py`, read without importing it (it imports Samba).
fn constants() -> Result<Json> {
    let script = "import ast, json, sys\n\
        tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())\n\
        out = {}\n\
        for n in tree.body:\n\
        \x20   if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name):\n\
        \x20       try: out[n.targets[0].id] = ast.literal_eval(n.value)\n\
        \x20       except ValueError: pass\n\
        print(json.dumps(out, default=str))\n";
    let path = labo::repository().join("labo/peupler.py");
    let out = Command::new("python3")
        .args(["-I", "-c", script])
        .arg(path)
        .output()?;
    check(out.status.success(), "constants of peupler.py")?;
    Ok(serde_json::from_slice(&out.stdout)?)
}

/// What `peupler.py` sows, rule by rule (`creer_ordinateurs`, `creer_dns`).
fn sown() -> Result<BTreeSet<Key>> {
    let k = constants()?;
    check(
        k["ZONE"] == ZONE && k["ZONE_INVERSE"] == ZONE_REVERSE,
        "zones of peupler.py",
    )?;
    let sites = k["SITES"].as_array().ok_or("SITES")?;
    let key = |a: &str, b: &str, c: &str, d: &str, e: &str| -> Key {
        (
            a.into(),
            b.into(),
            c.to_lowercase(),
            d.into(),
            e.to_lowercase(),
        )
    };
    let mut out = BTreeSet::new();
    // Computers removed: dynamic A, and PTR for the first 15 (192.168.1.150-164).
    for n in 0..40usize {
        let code = sites[n % sites.len()][0].as_str().ok_or("site")?;
        let name = format!("{code}-PC9{n:03}").to_lowercase();
        let address = if n < 15 {
            format!("192.168.1.{}", 150 + n)
        } else {
            format!("10.{}.250.{n}", n % sites.len() + 1)
        };
        out.insert(key("hote-disparu", ZONE, &name, "A", &address));
        if n < 15 {
            out.insert(key(
                "hote-disparu",
                ZONE_REVERSE,
                &(150 + n).to_string(),
                "PTR",
                &format!("{name}.{ZONE}"),
            ));
        }
    }
    for n in 0..10 {
        out.insert(key(
            "ptr-sans-nom",
            ZONE_REVERSE,
            &(200 + n).to_string(),
            "PTR",
            &format!("ancien-srv{:02}.{ZONE}", n + 1),
        ));
    }
    for srv in k["SRV_ORPHELINS"].as_array().ok_or("SRV")? {
        let (name, target, port) = (
            srv[0].as_str().unwrap_or_default(),
            srv[1].as_str().unwrap_or_default(),
            srv[2].as_u64().unwrap_or(0),
        );
        // The DC locator (under `_sites`) to a vanished DC; the rest, an absent target.
        let rule = if name.starts_with("_ldap._tcp") || name.starts_with("_kerberos._tcp") {
            "dc-disparu"
        } else {
            "cible-absente"
        };
        out.insert(key(
            rule,
            ZONE,
            name,
            "SRV",
            &format!("0 100 {port} {target}"),
        ));
    }
    for cname in k["CNAME_ORPHELINS"].as_array().ok_or("CNAME")? {
        out.insert(key(
            "cible-absente",
            ZONE,
            cname[0].as_str().unwrap_or_default(),
            "CNAME",
            cname[1].as_str().unwrap_or_default(),
        ));
    }
    check(out.len() == 40 + 15 + 10 + 3 + 2, "70 records sown")?;
    Ok(out)
}

/// Real anomalies of the lab that do not come from `peupler.py`, each one justified.
fn real(state: &dns_health::DnsState, now: time::UtcTime) -> Result<BTreeSet<Key>> {
    let mut out: BTreeSet<Key> = [
        // Vector of J0.8 left in the zone: an MX to mail.lab.test, which does not exist.
        (
            "cible-absente",
            ZONE,
            "vecteur-mx",
            "MX",
            "10 mail.lab.test",
        ),
        // dc2 joined the domain on 2026-10-13 without a PTR in the reverse zone.
        ("sans-ptr", ZONE, "dc2", "A", "192.168.1.28"),
    ]
    .iter()
    .map(|(a, b, c, d, e)| {
        (
            (*a).into(),
            (*b).into(),
            (*c).into(),
            (*d).into(),
            (*e).into(),
        )
    })
    .collect();
    // The tombstone of the vector of J0.8 (2026-10-13) gets old after 14 days.
    let zone = state.zones.iter().find(|z| z.name == ZONE).ok_or("zone")?;
    for n in state.nodes.get(&zone.dn).into_iter().flatten() {
        if n.name == "vecteur-tombe" && n.tombstone {
            for r in n.records() {
                if let RecordData::Tombstone(nt) = r.data
                    && let Some(date) = time::nttime_to_utc(i64::try_from(nt)?)?
                    && now.seconds_since(date) > dns_health::DAYS_TOMBSTONE * 86_400
                {
                    out.insert((
                        "tombstone-ancien".into(),
                        ZONE.into(),
                        "vecteur-tombe".into(),
                        String::new(),
                        String::new(),
                    ));
                }
            }
        }
    }
    Ok(out)
}

fn keys(anomalies: &[dns_health::Anomaly]) -> BTreeSet<Key> {
    let mut out = BTreeSet::new();
    for a in anomalies {
        for t in &a.targets {
            let record = t.record();
            out.insert((
                a.rule.value().to_owned(),
                t.zone.name.to_lowercase(),
                t.name.to_lowercase(),
                record.as_ref().map(Record::type_name).unwrap_or_default(),
                record
                    .and_then(|r| r.data_text().ok())
                    .unwrap_or_default()
                    .to_lowercase(),
            ));
        }
    }
    out
}

/// Creation of the node of a sown server: the ages of the records are relative to it.
fn population(connection: &Connection) -> Result<time::UtcTime> {
    let zones = zones(connection)?;
    let entry = labo::entry(
        connection,
        &dns::node_dn(&zones[ZONE].dn, "par-srv01"),
        &["whenCreated"],
        None,
    )?
    .ok_or("par-srv01")?;
    Ok(time::decode_generalized_time(&labo::text(
        &entry,
        "whenCreated",
    ))?)
}

/// The sown computers have an A refreshed less than 180 days before the population: the
/// threshold follows the time elapsed since, so that their natural ageing does not count.
fn diagnose(
    connection: &Connection,
    populated: time::UtcTime,
) -> Result<(dns_health::DnsState, dns_health::Diagnosis)> {
    let t = Instant::now();
    let state = dns_health::read_state(connection).map_err(debug)?;
    let now = labo_now()?;
    let days = dns_health::DAYS_NOT_REFRESHED + now.seconds_since(populated) / 86_400 + 1;
    let diagnosis = dns_health::diagnose(
        &state,
        Settings {
            days,
            ..Settings::default()
        },
        Some(now),
    );
    println!(
        "  read and diagnosed in {:.2} s (threshold {days} days)",
        t.elapsed().as_secs_f64()
    );
    Ok((state, diagnosis))
}

fn labo_now() -> Result<time::UtcTime> {
    let seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok(time::nttime_to_utc(time::unix_to_nttime(seconds)?)?.ok_or("now")?)
}

#[test]
#[ignore = "lab"]
fn dns_health_sown() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let connection = source::connection_to(&lab.profile(false), None);
    let populated = population(&connection)?;
    let (state, diagnosis) = diagnose(&connection, populated)?;
    let wanted = sown()?;
    let documented = real(&state, diagnosis.now)?;
    let found = keys(&diagnosis.anomalies);
    let mut by_rule: BTreeMap<&str, usize> = BTreeMap::new();
    for a in &diagnosis.anomalies {
        *by_rule.entry(a.rule.value()).or_default() += 1;
    }
    println!(
        "  {} anomalies on {}: {by_rule:?}",
        diagnosis.anomalies.len(),
        state.dc
    );
    let missing: Vec<&Key> = wanted.difference(&found).collect();
    check(
        missing.is_empty(),
        &format!("every anomaly sown found {missing:?}"),
    )?;
    let extra: BTreeSet<Key> = found.difference(&wanted).cloned().collect();
    check(
        extra == documented,
        &format!("and only them, plus those documented {extra:?}"),
    )?;
    check(diagnosis.remarks.is_empty(), "no remark")?;
    check(
        by_rule.get("hote-disparu") == Some(&40),
        "one anomaly per computer removed, its PTR with it",
    )?;

    // Both DCs of the lab are clean: NS, A of the root, _msdcs, locator.
    let of_dc: Vec<String> = diagnosis
        .anomalies
        .iter()
        .filter(|a| {
            matches!(
                a.rule,
                Rule::NsOutsideDc | Rule::AOutsideDc | Rule::MissingDc
            )
        })
        .map(|a| format!("{:?}", a.title))
        .collect();
    check(
        of_dc.is_empty(),
        &format!("the rules of the DCs find nothing {of_dc:?}"),
    )?;
    let removed: Vec<&dns_health::Anomaly> = diagnosis
        .anomalies
        .iter()
        .filter(|a| a.rule == Rule::RemovedDc)
        .collect();
    let names: BTreeSet<String> = removed
        .iter()
        .filter_map(|a| a.targets.first())
        .map(|t| t.name.to_lowercase())
        .collect();
    check(
        names
            == [
                "_kerberos._tcp.lyon._sites".to_owned(),
                "_ldap._tcp.lyon._sites".to_owned(),
            ]
            .into(),
        "the locator of the vanished DC of Lyon",
    )?;
    check(
        removed.iter().all(|a| matches!(&a.explanation, dns_health::Explanation::SrvNotDc { missing_site: Some(s), .. } if s.eq_ignore_ascii_case("lyon"))),
        "explained by the missing site « lyon »",
    )?;
    connection.join();
    Ok(())
}

const J35: &str = "essai-j35";

/// The preview only aims at the nodes of trial, the PTR of trial and, on `@`, the SOA alone.
fn controlled(changeset: &Changeset, ptr: &str) -> Result<()> {
    for op in &changeset.operations {
        let (name, zone) = dns::node_parts(op.dn()).ok_or("node")?;
        if (name.starts_with(&format!("{J35}-")) && zone == ZONE)
            || (name == ptr && zone == ZONE_REVERSE)
        {
            continue;
        }
        let Operation::Modify { changes, .. } = op else {
            return Err(format!("FAILED: preview aims at {}", op.dn()).into());
        };
        check(name == "@", "only the SOA on @")?;
        for c in changes {
            check(
                c.attribute.eq_ignore_ascii_case("dnsRecord")
                    && c.removed
                        .iter()
                        .chain(&c.added)
                        .all(|v| v.get(2) == Some(&6)),
                "the SOA alone",
            )?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn fixes(trial: &Trial, lab: &Lab, zones: &HashMap<String, Zone>, ptr: &str) -> Result<()> {
    let (forward, reverse) = (&zones[ZONE], &zones[ZONE_REVERSE]);
    let populated = population(&trial.connection)?;
    println!("1. defects of trial");
    let requests = vec![
        Request::Add {
            zone: forward.clone(),
            name: format!("{J35}-cname"),
            rtype: dns_record::CNAME,
            data: RecordData::Name(format!("{J35}-absent.lab.test")),
            ttl: w::DEFAULT_TTL,
        },
        Request::Add {
            zone: reverse.clone(),
            name: ptr.into(),
            rtype: dns_record::PTR,
            data: RecordData::Name(format!("{J35}-hote.lab.test")),
            ttl: w::DEFAULT_TTL,
        },
    ];
    let cs = w::build(&trial.connection, requests.clone(), Arc::new(English)).map_err(debug)?;
    controlled(&cs, ptr)?;
    let outcome = trial.outcome(&cs, None, Some(w::rebuild(requests, Arc::new(English))))?;
    check(
        outcome.report.issue == Issue::Applied,
        "CNAME and PTR orphans written",
    )?;
    // A vanished machine (dynamic A, as a computer), a node deleted 30 days ago.
    let now = labo_now()?;
    let hours = |days: i64| -> Result<u32> {
        let date = now.add_seconds(-days * 86_400).ok_or("date")?;
        Ok(u32::try_from(dns_record::utc_to_hours(date))?)
    };
    let mut dynamic = Record::new(dns_record::A, RecordData::Address("192.0.2.235".parse()?));
    dynamic.ttl = 1200;
    dynamic.timestamp = hours(400)?;
    let thirty = time::utc_to_nttime(now.add_seconds(-30 * 86_400).ok_or("date")?)?;
    let laid = Changeset {
        operations: vec![
            Operation::add(
                &dns::node_dn(&forward.dn, &format!("{J35}-disparu")),
                vec![
                    (
                        "objectClass".into(),
                        vec![b"top".to_vec(), b"dnsNode".to_vec()],
                    ),
                    ("dnsRecord".into(), vec![dynamic.encode()?]),
                ],
            )
            .map_err(debug)?,
            Operation::add(
                &dns::node_dn(&forward.dn, &format!("{J35}-tombe")),
                vec![
                    (
                        "objectClass".into(),
                        vec![b"top".to_vec(), b"dnsNode".to_vec()],
                    ),
                    (
                        "dnsRecord".into(),
                        vec![w::tombstone_value(1, Some(u64::try_from(thirty)?))],
                    ),
                    ("dNSTombstoned".into(), vec![b"TRUE".to_vec()]),
                ],
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    };
    trial.apply(&laid)?;

    let wanted: BTreeSet<(String, Rule)> = [
        (format!("{J35}-cname"), Rule::MissingTarget),
        (ptr.to_owned(), Rule::PtrWithoutName),
        (format!("{J35}-disparu"), Rule::VanishedHost),
        (format!("{J35}-tombe"), Rule::OldTombstone),
    ]
    .into();
    let reading = source::connection_to(&lab.profile(false), None);
    let mut last = None;
    let seconds = labo::wait(Duration::from_secs(120), "defects found", || {
        let (state, diagnosis) = diagnose(&reading, populated)?;
        let ours: Vec<dns_health::Anomaly> = diagnosis
            .anomalies
            .iter()
            .filter(|a| {
                a.targets.first().is_some_and(|t| {
                    t.name.starts_with(J35) || (t.name == ptr && t.zone.name == ZONE_REVERSE)
                })
            })
            .cloned()
            .collect();
        let seen: BTreeSet<(String, Rule)> = ours
            .iter()
            .filter_map(|a| Some((a.targets.first()?.name.clone(), a.rule)))
            .collect();
        let done = seen == wanted;
        last = Some((state, diagnosis, ours));
        Ok(done)
    })?;
    println!("  found after {seconds:.1} s");
    let (state, diagnosis, ours) = last.ok_or("diagnosis")?;
    let others: BTreeSet<Key> = keys(&diagnosis.anomalies)
        .difference(&keys(&ours))
        .cloned()
        .collect();
    let mut expected = sown()?;
    expected.extend(real(&state, diagnosis.now)?);
    check(
        others == expected,
        "the rest: the anomalies sown and documented",
    )?;

    println!("2. one fix at a time, preview checked");
    let before = soa(&trial.connection, forward)?.0;
    let mut sorted = ours.clone();
    sorted.sort_by_key(|a| a.rule.value());
    for anomaly in &sorted {
        let fix = anomaly.fix.as_ref().ok_or("a fix")?;
        let requests = dns_health::requests([anomaly]);
        let cs = w::build(&trial.connection, requests.clone(), Arc::new(English)).map_err(debug)?;
        controlled(&cs, ptr)?;
        let outcome = trial.outcome(&cs, None, Some(w::rebuild(requests, Arc::new(English))))?;
        check(
            outcome.report.issue == Issue::Applied,
            &format!(
                "{}: {:?} ({} op.)",
                anomaly.rule.value(),
                fix.label,
                cs.operations.len()
            ),
        )?;
    }
    // Deletions of a CNAME and an A in lab.test (one SOA each), the purge does not touch it.
    check(
        soa(&trial.connection, forward)?.0 == before.wrapping_add(2),
        "SOA of lab.test +2",
    )?;
    let t = Instant::now();
    for (dc, _) in ADDRESSES {
        labo::wait(
            Duration::from_secs(120),
            &format!("fixes seen on {dc}"),
            || {
                Ok(dig(dc, &format!("{J35}-cname.{ZONE}"), "CNAME")?
                    .1
                    .is_empty()
                    && dig(dc, &format!("{J35}-disparu.{ZONE}"), "A")?.1.is_empty()
                    && dig(dc, &format!("{ptr}.{ZONE_REVERSE}"), "PTR")?
                        .1
                        .is_empty()
                    && labo::ldbsearch(
                        dc,
                        &format!("DC=DomainDnsZones,{}", lab.base),
                        "sub",
                        &format!("(name={J35}-tombe)"),
                        &["dn"],
                    )?
                    .is_empty())
            },
        )?;
    }
    println!("  seen everywhere after {:.1} s", t.elapsed().as_secs_f64());
    let (_, diagnosis) = diagnose(&trial.connection, populated)?;
    check(
        !diagnosis.anomalies.iter().any(|a| {
            a.targets
                .first()
                .is_some_and(|t| t.name.starts_with(J35) || t.name == ptr)
        }),
        "no defect of trial left",
    )?;
    check(
        sown()?.is_subset(&keys(&diagnosis.anomalies)),
        "the sown ones intact",
    )?;
    reading.join();

    println!("3. a rollback that leaves the SOA incremented");
    let cs = w::build(
        &trial.connection,
        vec![add(
            forward,
            &format!("{J35}-retour"),
            dns_record::A,
            "192.0.2.236",
        )?],
        Arc::new(English),
    )
    .map_err(debug)?;
    let mut operations = cs.operations.clone();
    operations.push(
        Operation::add(
            &dns::node_dn(&forward.dn, &format!("{J35}-refus")),
            vec![
                (
                    "objectClass".into(),
                    vec![b"top".to_vec(), b"dnsNode".to_vec()],
                ),
                ("dNSTombstoned".into(), vec![b"PEUT-ETRE".to_vec()]),
            ],
        )
        .map_err(debug)?,
    );
    let doomed = Changeset {
        operations,
        remarks: cs.remarks,
    };
    controlled(&doomed, "-")?;
    let before = soa(&trial.connection, forward)?.0;
    check(
        dig_serial("dc1", ZONE)? == before,
        "dig gives the same serial",
    )?;
    let outcome = trial.outcome(&doomed, None, None)?;
    println!(
        "  {:?}: {:?}",
        outcome.report.issue,
        outcome.report.error.as_ref().map(|e| &e.message)
    );
    check(
        outcome.report.issue == Issue::Cancelled && outcome.report.remaining_indices().is_empty(),
        "refused by the server, rolled back whole",
    )?;
    // +1 at the write, +1 at the rollback: never back.
    check(
        soa(&trial.connection, forward)?.0 == before.wrapping_add(2),
        "SOA +2",
    )?;
    check(
        dig_serial("dc1", ZONE)? == before.wrapping_add(2),
        "dig: SOA +2",
    )?;
    check(
        dig("dc1", &format!("{J35}-retour.{ZONE}"), "A")? == ("NXDOMAIN".into(), Vec::new()),
        "the name gone",
    )?;
    check(
        node(&trial.connection, forward, &format!("{J35}-retour"))?.is_none(),
        "the node removed",
    )
}

#[test]
#[ignore = "lab"]
fn dns_health_fixes() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("sante-dns")?;
    let trial = Trial::new(&lab, &scratch)?;
    let zones = zones(&trial.connection)?;
    let (address, ptr) = free_address(&trial.connection, &zones)?;
    println!("PTR of trial: {address}");
    delete_nodes(&trial.connection, &zones, J35, Some(&ptr))?;
    let done = fixes(&trial, &lab, &zones, &ptr);
    println!("4. cleaning");
    let names = [
        "essai-j35-cname",
        "essai-j35-disparu",
        "essai-j35-tombe",
        "essai-j35-retour",
        "essai-j35-refus",
    ];
    let cleaned = delete_nodes(&trial.connection, &zones, J35, Some(&ptr))
        .and_then(|_| nothing_left(&lab, J35, &names, Some(&ptr)));
    trial.connection.join();
    done.and(cleaned)
}

// --- The seven types against samba-tool ----------------------------------------------------------

const J34: &str = "essai-j34";

/// type → (zone, first value, value changed), in the form of the core.
fn cases() -> Vec<(&'static str, u16, &'static str, String, String)> {
    let target = |n: u8| format!("{J34}-cible-{n}.lab.test");
    vec![
        (
            "A",
            dns_record::A,
            ZONE,
            "192.0.2.10".into(),
            "192.0.2.11".into(),
        ),
        (
            "AAAA",
            dns_record::AAAA,
            ZONE,
            "2001:db8::10".into(),
            "2001:db8::11".into(),
        ),
        ("CNAME", dns_record::CNAME, ZONE, target(1), target(2)),
        (
            "PTR",
            dns_record::PTR,
            ZONE_REVERSE,
            format!("{J34}-hote-1.lab.test"),
            format!("{J34}-hote-2.lab.test"),
        ),
        (
            "SRV",
            dns_record::SRV,
            ZONE,
            format!("0 100 389 {}", target(1)),
            format!("0 100 636 {}", target(1)),
        ),
        (
            "MX",
            dns_record::MX,
            ZONE,
            format!("10 {J34}-mx-1.lab.test"),
            format!("20 {J34}-mx-1.lab.test"),
        ),
        (
            "TXT",
            dns_record::TXT,
            ZONE,
            "\"essai j34\" \"deux\"".into(),
            "\"essai j34\" \"trois\"".into(),
        ),
    ]
}

fn ours(rtype: &str) -> String {
    format!("{J34}-{}", rtype.to_lowercase())
}

fn theirs(rtype: &str) -> String {
    format!("{J34}-st-{}", rtype.to_lowercase())
}

/// Arguments of data of `samba-tool dns add/update`.
fn for_samba_tool(rtype: &str, text: &str) -> Vec<String> {
    let pieces: Vec<&str> = text.split_whitespace().collect();
    match rtype {
        "MX" => vec![format!("{} {}", pieces[1], pieces[0])],
        "SRV" => vec![format!(
            "{} {} {} {}",
            pieces[3], pieces[2], pieces[0], pieces[1]
        )],
        _ => vec![text.to_owned()],
    }
}

/// The value as `dig` shows it.
fn for_dig(rtype: &str, text: &str) -> String {
    match rtype {
        "CNAME" | "PTR" | "MX" | "SRV" => format!("{text}."),
        _ => text.to_owned(),
    }
}

fn samba_tool(operations: &[Vec<String>]) -> Result<()> {
    let mut script = String::new();
    for op in operations {
        let mut args = vec![op[0].clone(), "127.0.0.1".into()];
        args.extend(op[1..].iter().cloned());
        let quoted: Vec<String> = args.iter().map(|a| labo::quote(a)).collect();
        script.push_str(&format!(
            "sudo samba-tool dns {} -P 2>&1 | sed 's/^/R /'\n",
            quoted.join(" ")
        ));
    }
    let out = labo::ssh("dc1", &script)?;
    check(
        !out.contains("ERROR"),
        &format!("samba-tool: {} operation(s) done", out.lines().count()),
    )
}

#[allow(clippy::too_many_lines)]
fn seven_types(trial: &Trial, zones: &HashMap<String, Zone>) -> Result<()> {
    println!("1. the seven types, as samba-tool writes them");
    for (phase, rank) in [("addition", 1), ("modification", 2)] {
        let mut operations = Vec::new();
        for (name, rtype, zone_name, v1, v2) in cases() {
            let zone = &zones[zone_name];
            let before = soa(&trial.connection, zone)?.0;
            check(
                dig_serial("dc1", zone_name)? == before,
                "dig: the same serial",
            )?;
            let request = if rank == 1 {
                operations.push(
                    [
                        vec!["add".into(), zone_name.into(), theirs(name), name.into()],
                        for_samba_tool(name, &v1),
                    ]
                    .concat(),
                );
                add(zone, &ours(name), rtype, &v1)?
            } else {
                let old = values(&trial.connection, zone, &ours(name))?
                    .0
                    .into_iter()
                    .next()
                    .ok_or("value")?;
                operations.push(
                    [
                        vec!["update".into(), zone_name.into(), theirs(name), name.into()],
                        for_samba_tool(name, &v1),
                        for_samba_tool(name, &v2),
                    ]
                    .concat(),
                );
                Request::Modify {
                    zone: zone.clone(),
                    name: ours(name),
                    old,
                    rtype,
                    data: w::read_input(rtype, &v2).map_err(debug)?,
                    ttl: w::DEFAULT_TTL,
                }
            };
            write(trial, vec![request])?;
            // SOA: +1, data and header; the record carries this new serial.
            let after = before.wrapping_add(1);
            check(
                soa(&trial.connection, zone)? == (after, after),
                &format!("{phase} {name}: SOA +1"),
            )?;
            check(dig_serial("dc1", zone_name)? == after, "dig: SOA +1")?;
            let (written, _) = values(&trial.connection, zone, &ours(name))?;
            check(
                written.len() == 1 && Record::decode(&written[0])?.serial == after,
                "the record carries the serial of its SOA",
            )?;
        }
        samba_tool(&operations)?;
        let mut wanted = BTreeMap::new();
        for (name, _, zone_name, v1, v2) in cases() {
            let zone = &zones[zone_name];
            let text = if rank == 1 { &v1 } else { &v2 };
            let (mine, _) = values(&trial.connection, zone, &ours(name))?;
            let (reference, _) = values(&trial.connection, zone, &theirs(name))?;
            check(
                mine.len() == 1
                    && reference.len() == 1
                    && without_serial(&mine[0]) == without_serial(&reference[0]),
                &format!("{phase} {name}: byte for byte as samba-tool, up to the serial"),
            )?;
            for n in [ours(name), theirs(name)] {
                wanted.insert(
                    (format!("{n}.{zone_name}"), name.to_owned()),
                    vec![for_dig(name, text)],
                );
            }
        }
        everywhere(&wanted)?;
    }

    println!("2. deletion: a tombstone, then back in service");
    let mut deleted = BTreeMap::new();
    for (name, _, zone_name, _, _) in cases() {
        let zone = &zones[zone_name];
        let before = soa(&trial.connection, zone)?.0;
        let value = values(&trial.connection, zone, &ours(name))?
            .0
            .into_iter()
            .next()
            .ok_or("value")?;
        write(
            trial,
            vec![Request::Delete {
                zone: zone.clone(),
                name: ours(name),
                value,
            }],
        )?;
        let (left, tombstoned) = values(&trial.connection, zone, &ours(name))?;
        let record = Record::decode(left.first().ok_or("tombstone")?)?;
        check(
            left.len() == 1
                && tombstoned.as_deref() == Some("TRUE")
                && record.rtype == dns_record::TOMBSTONE
                && record.rank == 0
                && record.ttl == 0
                && record.serial == before.wrapping_add(1)
                && soa(&trial.connection, zone)?.0 == before.wrapping_add(1),
            &format!("{name}: tombstone, serial of the SOA"),
        )?;
        deleted.insert(
            (format!("{}.{zone_name}", ours(name)), name.to_owned()),
            Vec::new(),
        );
    }
    // A name in tombstone: NXDOMAIN for dig, nothing for samba-tool, which hides tombstones.
    for (fqdn, rtype) in deleted.keys() {
        check(
            dig("dc1", fqdn, rtype)?.0 == "NXDOMAIN",
            &format!("{fqdn}: NXDOMAIN"),
        )?;
    }
    wait_dig("dc2", &deleted, 120)?;
    for (dc, _) in ADDRESSES {
        let names: Vec<(String, String)> = cases()
            .iter()
            .map(|(n, _, z, _, _)| ((*z).to_owned(), ours(n)))
            .collect();
        check(
            samba_tool_query(dc, &names)?.values().all(Vec::is_empty),
            &format!("{dc}: samba-tool shows nothing"),
        )?;
    }
    let forward = &zones[ZONE];
    write(
        trial,
        vec![add(forward, &ours("A"), dns_record::A, "192.0.2.12")?],
    )?;
    samba_tool(&[vec![
        "add".into(),
        ZONE.into(),
        format!("{J34}-st-recree"),
        "A".into(),
        "192.0.2.12".into(),
    ]])?;
    let (mine, tombstoned) = values(&trial.connection, forward, &ours("A"))?;
    let (reference, _) = values(&trial.connection, forward, &format!("{J34}-st-recree"))?;
    check(
        tombstoned.as_deref() == Some("FALSE")
            && mine.len() == 1
            && without_serial(&mine[0]) == without_serial(reference.first().ok_or("reference")?),
        "back in service, as a new A of samba-tool",
    )?;
    everywhere(
        &[(
            (format!("{}.{ZONE}", ours("A")), "A".to_owned()),
            vec!["192.0.2.12".to_owned()],
        )]
        .into(),
    )?;

    println!("3. the undo of a modification gives back the bytes");
    let name = format!("{J34}-annule");
    write(trial, vec![add(forward, &name, dns_record::TXT, "avant")?])?;
    let origin = values(&trial.connection, forward, &name)?.0;
    let (_, report) = write(
        trial,
        vec![Request::Modify {
            zone: forward.clone(),
            name: name.clone(),
            old: origin.first().cloned().ok_or("value")?,
            rtype: dns_record::TXT,
            data: w::read_input(dns_record::TXT, "après").map_err(debug)?,
            ttl: 60,
        }],
    )?;
    let serial = soa(&trial.connection, forward)?.0;
    let inverse = trial.inverse(&report)?;
    let refreshed = w::refresh_soa(&trial.connection, inverse, Arc::new(English)).map_err(debug)?;
    let undone = trial.outcome(&refreshed, Some(report.id.clone()), None)?;
    check(undone.report.issue == Issue::Applied, "undone")?;
    check(
        values(&trial.connection, forward, &name)?.0 == origin,
        "bytes of origin, serial included",
    )?;
    check(
        soa(&trial.connection, forward)?.0 == serial.wrapping_add(1),
        "SOA +1 again",
    )
}

/// Run under the ordinary account: `write` (an A written through the core) or `unreadable`
/// (the names of lab.test read by the source, and a write tried on the unreadable one).
#[test]
#[ignore = "lab"]
fn dns_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let asked: Json = serde_json::from_str(&input)?;
    let lab = labo::lab();
    let name = asked["name"].as_str().ok_or("name")?.to_owned();
    let (connection, profile) = lab.pdc();
    let zone = zones(&connection)?.remove(ZONE).ok_or("zone")?;
    if asked["mode"] == "write" {
        let scratch = labo::Scratch::new("dns-enfant")?;
        let requests = vec![add(&zone, &name, dns_record::A, "192.0.2.40")?];
        let cs = w::build(&connection, requests.clone(), Arc::new(English)).map_err(debug)?;
        let outcome = annuaire_core::writer::apply(
            &connection,
            &profile,
            &cs,
            scratch.journal(),
            Arc::new(labo::Texts),
            None,
            Some(w::rebuild(requests, Arc::new(English))),
        )
        .map_err(debug)?;
        println!(
            "RESULT {}",
            json!({"issue": outcome.report.issue.name(), "user": outcome.report.user,
                   "operations": cs.operations.len(), "remarks": cs.remarks})
        );
    } else {
        let mut on_dc1 = lab.profile(false);
        on_dc1.preferred_dc = Some(DC1.into());
        let source = DirectSource::with_connection(
            on_dc1.clone(),
            source::connection_to(&on_dc1, Some(DC1)),
        );
        source.open().map_err(debug)?;
        let nodes = read_nodes(&source, &zone)?;
        source.close();
        // What the filter of J3.3 (objectClass=dnsNode) gave: the node was not there.
        let old: BTreeSet<String> = entries(
            &connection,
            &zone.dn,
            Scope::OneLevel,
            dns::NODES_FILTER,
            &["name"],
        )?
        .iter()
        .filter_map(|e| dns::node_parts(&e.dn).map(|(n, _)| n.to_lowercase()))
        .collect();
        let refusal = match w::build(
            &connection,
            vec![add(&zone, &name, dns_record::A, "192.0.2.51")?],
            Arc::new(English),
        ) {
            Err(PrepareError::Dns(DnsError::UnreadableNode { name })) => Some(name),
            Err(e) => Some(format!("other error {e:?}")),
            Ok(_) => None,
        };
        let mut names: Vec<String> = nodes.iter().map(|n| n.name.to_lowercase()).collect();
        names.sort();
        let unreadable: Vec<String> = nodes
            .iter()
            .filter(|n| n.unreadable)
            .map(|n| n.name.to_lowercase())
            .collect();
        let target = nodes.iter().find(|n| n.name.eq_ignore_ascii_case(&name));
        println!(
            "RESULT {}",
            json!({"names": names, "unreadable": unreadable, "refusal": refusal,
                   "records": target.map(|n| n.values.len()), "old_filter": old.contains(&name)})
        );
    }
    connection.join();
    Ok(())
}

fn as_ordinary(lab: &Lab, kdc: &labo::Kdc, mode: &str, name: &str) -> Result<Json> {
    let principal = format!("{ORDINARY}@{}", lab.realm());
    let refused = kdc.kinit_into(
        &principal,
        &labo::lab_password(labo::SEED, ORDINARY)?,
        "ordinaire",
    );
    check(refused.is_none(), "ticket of the ordinary account")?;
    let result = labo::child(
        "dns_child",
        &kdc.env("ordinaire"),
        &json!({"mode": mode, "name": name}).to_string(),
    );
    kdc.destroy("ordinaire");
    Ok(serde_json::from_str(&result?)?)
}

fn ordinary(
    trial: &Trial,
    lab: &Lab,
    zones: &HashMap<String, Zone>,
    kdc: &labo::Kdc,
) -> Result<()> {
    println!("4. an ordinary account writes without incrementing the SOA");
    let forward = &zones[ZONE];
    let name = format!("{J34}-ordinaire");
    let before = soa(&trial.connection, forward)?.0;
    let seen = as_ordinary(lab, kdc, "write", &name)?;
    println!("  {seen}");
    check(
        seen["issue"] == "applique" && seen["user"].as_str().is_some_and(|u| u.contains(ORDINARY)),
        "applied, by the account",
    )?;
    check(
        seen["operations"] == 1,
        "the creation of the node alone, no SOA",
    )?;
    check(
        seen["remarks"].as_array().is_some_and(|r| {
            r.iter().any(|m| {
                m.as_str()
                    .is_some_and(|m| m.contains("without incrementing"))
            })
        }),
        "remark: without increment",
    )?;
    check(
        soa(&trial.connection, forward)?.0 == before,
        "SOA unchanged",
    )?;
    let (value, _) = values(&trial.connection, forward, &name)?;
    check(
        Record::decode(value.first().ok_or("value")?)?.serial == before,
        "the record carries the present serial",
    )?;
    everywhere(
        &[(
            (format!("{name}.{ZONE}"), "A".to_owned()),
            vec!["192.0.2.40".to_owned()],
        )]
        .into(),
    )?;

    println!("5. a node the ordinary account cannot read");
    let name = format!("{J34}-illisible");
    write(
        trial,
        vec![add(forward, &name, dns_record::A, "192.0.2.50")?],
    )?;
    let dn = dns::node_dn(&forward.dn, &name);
    let account = entries(
        &trial.connection,
        &trial.base,
        Scope::Subtree,
        &format!("(sAMAccountName={ORDINARY})"),
        &["1.1"],
    )?
    .into_iter()
    .next()
    .ok_or("account")?
    .dn;
    let sid = trial.sid(&account)?;
    let entry = labo::entry(
        &trial.connection,
        &dn,
        &["nTSecurityDescriptor"],
        Some(SD_DACL),
    )?
    .ok_or("node")?;
    let mut descriptor =
        SecurityDescriptor::decode(entry.values("nTSecurityDescriptor").first().ok_or("SD")?)?;
    let refusal = Ace::simple(sd::ACCESS_DENIED, sd::ADS_RIGHT_DS_READ_PROP, &sid, 0)?;
    if let Some(dacl) = descriptor.dacl.as_mut() {
        dacl.aces.insert(0, refusal);
    }
    let value = descriptor.encode()?;
    let target = dn.clone();
    trial
        .connection
        .run(false, move |link| {
            let id = link.session.modify(
                &target,
                vec![Modification::Replace(
                    "nTSecurityDescriptor".into(),
                    vec![value.clone()],
                )],
                vec![sd_flags_control(SD_DACL)],
            )?;
            link.session.result(id, Some(link.timeout)).map(|_| ())
        })
        .map_err(debug)?;
    let seen = as_ordinary(lab, kdc, "unreadable", &name)?;
    let admin: Vec<String> = {
        let mut v: Vec<String> = entries(
            &trial.connection,
            &forward.dn,
            Scope::OneLevel,
            dns::NAMES_FILTER,
            &["name"],
        )?
        .iter()
        .filter_map(|e| dns::node_parts(&e.dn).map(|(n, _)| n.to_lowercase()))
        .collect();
        v.sort();
        v
    };
    println!(
        "  unreadable {}, refusal {}, records {}, old filter {}",
        seen["unreadable"], seen["refusal"], seen["records"], seen["old_filter"]
    );
    check(
        seen["names"] == json!(admin),
        "the same names as the administrator sees",
    )?;
    check(
        seen["unreadable"]
            .as_array()
            .is_some_and(|u| u.iter().any(|n| n == name.as_str())),
        "the node marked unreadable",
    )?;
    check(seen["records"] == 0, "without records")?;
    check(
        seen["refusal"]
            .as_str()
            .is_some_and(|r| r.split('.').next() == Some(name.as_str())),
        "a write refused before anything (unreadable node)",
    )?;
    check(
        seen["old_filter"] == false,
        "the filter of J3.3 hid it silently",
    )?;
    // The administrator reads it (the DACL only aims at the ordinary account).
    check(
        !values(&trial.connection, forward, &name)?.0.is_empty(),
        "the administrator reads it",
    )
}

#[test]
#[ignore = "lab"]
fn dns_types_as_samba_tool() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("dns-types")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, DC1)?;
    let zones = zones(&trial.connection)?;
    delete_nodes(&trial.connection, &zones, J34, None)?;
    let done = seven_types(&trial, &zones).and_then(|()| ordinary(&trial, &lab, &zones, &kdc));
    println!("6. cleaning");
    let mut names: Vec<String> = cases()
        .iter()
        .flat_map(|(n, ..)| [ours(n), theirs(n)])
        .collect();
    names.extend([
        format!("{J34}-st-recree"),
        format!("{J34}-annule"),
        format!("{J34}-ordinaire"),
        format!("{J34}-illisible"),
    ]);
    let names: Vec<&str> = names.iter().map(String::as_str).collect();
    let cleaned = delete_nodes(&trial.connection, &zones, J34, None)
        .and_then(|removed| {
            check(
                !removed.is_empty(),
                &format!("{} nodes removed", removed.len()),
            )
        })
        .and_then(|()| nothing_left(&lab, J34, &names, None));
    trial.connection.join();
    done.and(cleaned)
}

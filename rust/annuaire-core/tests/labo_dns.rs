// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS writes of the core against the lab (R4.7, port of `test_dns_ecriture_labo.py`, ADR
//! 0020): A with its PTR on two zones, conflict on the SOA settled by a new attempt, automatic
//! rollback that raises the SOA again, undo with the SOA read again (created names put in
//! tombstone), purge of the tombstones, then the DNS health read and diagnosed. Only names
//! `essai-r47*` and a free address of 192.168.1.240-254 are written; everything is removed at
//! the end, each SOA only went up.
//!
//! `dns_cleanup` removes what the interface trials left: the names `essai-r47*` (records, then
//! the tombstone purged) and the PTR of 192.168.1.240-254 that point to them or are tombstones.
//! See `labo/mod.rs` to run them.

mod labo;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use annuaire_codecs::dns_record::{self, Record, RecordData};
use annuaire_core::Connection;
use annuaire_core::changes::{self, ErrorRecord, Issue, Operation};
use annuaire_core::dns::{self, Zone};
use annuaire_core::dns_health::{self, Settings};
use annuaire_core::dns_write::{self as w, Request};
use annuaire_core::error::LdapError;
use annuaire_core::journal::Journal;
use annuaire_core::messages::{Catalog, English, Msg};
use annuaire_core::profile::Profile;
use annuaire_core::writer::{self, WriteCatalog, WriteMsg};

#[derive(Debug)]
struct Texts;

impl Catalog for Texts {
    fn text(&self, msg: &Msg) -> String {
        English.text(msg)
    }
}

impl WriteCatalog for Texts {
    fn write_text(&self, msg: &WriteMsg) -> String {
        format!("{msg:?}")
    }
    fn ldap_error(&self, error: &LdapError, _dc: &str) -> ErrorRecord {
        ErrorRecord {
            class: "ErreurLDAP".into(),
            message: error.to_string(),
            detail: String::new(),
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn serial(connection: &Connection, zone: &Zone) -> Result<u32> {
    let dn_root = dns::node_dn(&zone.dn, dns::ROOT);
    let read = dns::reread_nodes(connection, &[dn_root]).map_err(|e| format!("{e:?}"))?;
    let node = read.into_iter().next().and_then(|(_, n)| n).ok_or("no @")?;
    node.records()
        .into_iter()
        .find_map(|r| match r.data {
            RecordData::Soa { serial, .. } => Some(serial),
            _ => None,
        })
        .ok_or_else(|| "no SOA".into())
}

fn values(connection: &Connection, zone: &Zone, name: &str) -> Result<Option<dns::Node>> {
    let read = dns::reread_nodes(connection, &[dns::node_dn(&zone.dn, name)])
        .map_err(|e| format!("{e:?}"))?;
    Ok(read.into_iter().next().and_then(|(_, n)| n))
}

fn build(connection: &Connection, requests: &[Request]) -> Result<changes::Changeset> {
    w::build(connection, requests.to_vec(), Arc::new(English)).map_err(|e| format!("{e:?}").into())
}

fn apply(
    connection: &Connection,
    profile: &Profile,
    journal: &Arc<Journal>,
    changeset: &changes::Changeset,
    retry: Option<writer::Retry>,
    resumes: Option<String>,
) -> Result<writer::Outcome> {
    let t = Instant::now();
    let outcome = writer::apply(
        connection,
        profile,
        changeset,
        journal.clone(),
        Arc::new(Texts),
        resumes,
        retry,
    )
    .map_err(|e| format!("{e:?}"))?;
    println!(
        "  applied: {:?} in {:.2} s ({} operation(s))",
        outcome.report.issue,
        t.elapsed().as_secs_f64(),
        outcome.report.changeset.operations.len()
    );
    Ok(outcome)
}

fn add(zone: &Zone, name: &str, rtype: u16, text: &str) -> Result<Request> {
    Ok(Request::Add {
        zone: zone.clone(),
        name: name.into(),
        rtype,
        data: w::read_input(rtype, text).map_err(|e| format!("{e:?}"))?,
        ttl: w::DEFAULT_TTL,
    })
}

fn check(condition: bool, what: &str) -> Result<()> {
    if condition {
        println!("  ok: {what}");
        Ok(())
    } else {
        Err(format!("FAILED: {what}").into())
    }
}

#[test]
#[ignore = "lab"]
fn dns_cleanup() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("dns-nettoyage")?;
    let (connection, profile) = lab.pdc();
    clean(&connection, &profile, &scratch.journal())
}

#[test]
#[ignore = "lab"]
#[allow(clippy::too_many_lines)]
fn dns_writes() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let lab = labo::lab();
    let scratch = labo::Scratch::new("dns")?;
    let journal = scratch.journal();
    let domain = lab.domain.clone();
    // An object whose description is single-valued.
    let other = format!("CN=Guest,CN=Users,{}", lab.base);
    let (connection, profile) = lab.pdc();
    let t = Instant::now();
    let zones = dns::zones(&connection).map_err(|e| format!("{e:?}"))?;
    println!(
        "{} zones in {:.2} s",
        zones.len(),
        t.elapsed().as_secs_f64()
    );
    let forward = zones
        .iter()
        .find(|z| z.name.eq_ignore_ascii_case(&domain))
        .cloned()
        .ok_or("forward zone")?;

    // A free address of 192.168.1.240-254 in the most precise reverse zone.
    let mut chosen = None;
    for last in 240..=254u8 {
        let address: IpAddr = format!("192.168.1.{last}").parse()?;
        let Some((zone, name)) = w::reverse_zone(&zones, address) else {
            continue;
        };
        if values(&connection, &zone, &name)?.is_none() {
            chosen = Some((address, zone, name));
            break;
        }
    }
    let (address, reverse, ptr_name) = chosen.ok_or("no free address")?;
    println!("address {address}, PTR {ptr_name} in {}", reverse.name);
    let (f0, r0) = (
        serial(&connection, &forward)?,
        serial(&connection, &reverse)?,
    );
    println!("SOA {} = {f0}, {} = {r0}", forward.name, reverse.name);

    println!("1. A and PTR on two zones");
    let requests = vec![
        add(&forward, "essai-r47", dns_record::A, &address.to_string())?,
        add(
            &reverse,
            &ptr_name,
            dns_record::PTR,
            &format!("essai-r47.{}", forward.name),
        )?,
    ];
    let t = Instant::now();
    let first = build(&connection, &requests)?;
    println!("  built in {:.2} s", t.elapsed().as_secs_f64());
    let outcome = apply(
        &connection,
        &profile,
        &journal,
        &first,
        Some(w::rebuild(requests.clone(), Arc::new(English))),
        None,
    )?;
    check(outcome.report.issue == Issue::Applied, "applied")?;
    let first_report = outcome.report.clone();
    check(
        serial(&connection, &forward)? == f0.wrapping_add(1)
            && serial(&connection, &reverse)? == r0.wrapping_add(1),
        "SOA +1 in both zones",
    )?;

    println!("2. Conflict on the SOA");
    let late = vec![add(&forward, "essai-r47b", dns_record::TXT, "essai R4.7")?];
    let stale = build(&connection, &late)?;
    let meanwhile = vec![add(
        &forward,
        "essai-r47c",
        dns_record::TXT,
        "autre écrivain",
    )?];
    let m = build(&connection, &meanwhile)?;
    apply(&connection, &profile, &journal, &m, None, None)?;
    let refused = apply(&connection, &profile, &journal, &stale, None, None)?;
    check(
        refused.report.issue == Issue::Refused,
        "refused without retry",
    )?;
    let before = serial(&connection, &forward)?;
    let retried = apply(
        &connection,
        &profile,
        &journal,
        &stale,
        Some(w::rebuild(late.clone(), Arc::new(English))),
        None,
    )?;
    check(retried.report.issue == Issue::Applied, "applied with retry")?;
    check(
        serial(&connection, &forward)? == before.wrapping_add(1),
        "SOA +1",
    )?;

    println!("3. Automatic rollback: the SOA goes up again");
    let mut doomed = build(
        &connection,
        &[add(
            &forward,
            "essai-r47d",
            dns_record::A,
            &address.to_string(),
        )?],
    )?;
    let version = writer::read_version(&connection, &other).map_err(|e| format!("{e:?}"))?;
    // Two values of a single-valued attribute: refused by the server, not by the check.
    doomed.operations.push(Operation::modify(
        &other,
        vec![changes::Change::new(
            "description",
            Vec::new(),
            vec![b"essai-r47 un".to_vec(), b"essai-r47 deux".to_vec()],
        )?],
        version,
    )?);
    let before = serial(&connection, &forward)?;
    let rolled = apply(&connection, &profile, &journal, &doomed, None, None)?;
    check(rolled.report.issue == Issue::Cancelled, "cancelled")?;
    check(
        rolled
            .report
            .rollback
            .as_ref()
            .is_some_and(|r| r.remarks.iter().any(|m| m.contains("incremented again"))),
        "remark of the rollback",
    )?;
    check(
        serial(&connection, &forward)? == before.wrapping_add(2),
        "SOA +2",
    )?;
    check(
        values(&connection, &forward, "essai-r47d")?.is_none(),
        "node created removed",
    )?;

    println!("4. Undo of step 1: exact records, SOA read again, created names in tombstone");
    let reports = writer::read_journal(&journal);
    let inverse = changes::inverse(&first_report, &reports, &English)?;
    let (f1, r1) = (
        serial(&connection, &forward)?,
        serial(&connection, &reverse)?,
    );
    let refreshed = w::refresh_soa(&connection, inverse.clone(), Arc::new(English))
        .map_err(|e| format!("{e:?}"))?;
    for remark in &refreshed.remarks {
        println!("  remark: {remark}");
    }
    let undone = apply(
        &connection,
        &profile,
        &journal,
        &refreshed,
        Some(w::soa_up_to_date(inverse, Arc::new(English))),
        Some(first_report.id.clone()),
    )?;
    check(undone.report.issue == Issue::Applied, "undo applied")?;
    check(
        serial(&connection, &forward)? == f1.wrapping_add(1)
            && serial(&connection, &reverse)? == r1.wrapping_add(1),
        "SOA +1 again, never lowered",
    )?;
    let node = values(&connection, &forward, "essai-r47")?.ok_or("essai-r47 gone")?;
    check(node.tombstone, "essai-r47 in tombstone, not deleted")?;

    println!("5. Cleaning: records removed, tombstones purged");
    for name in ["essai-r47b", "essai-r47c"] {
        if let Some(n) = values(&connection, &forward, name)? {
            let requests: Vec<Request> = n
                .values
                .iter()
                .filter(|v| Record::decode(v).is_ok_and(|r| r.rtype != dns_record::TOMBSTONE))
                .map(|v| Request::Delete {
                    zone: forward.clone(),
                    name: name.into(),
                    value: v.clone(),
                })
                .collect();
            if !requests.is_empty() {
                let cs = build(&connection, &requests)?;
                apply(
                    &connection,
                    &profile,
                    &journal,
                    &cs,
                    Some(w::rebuild(requests, Arc::new(English))),
                    None,
                )?;
            }
        }
    }
    let mut purges = Vec::new();
    for (zone, name) in [
        (&forward, "essai-r47"),
        (&forward, "essai-r47b"),
        (&forward, "essai-r47c"),
        (&reverse, ptr_name.as_str()),
    ] {
        if values(&connection, zone, name)?.is_some() {
            purges.push(Request::Purge {
                zone: zone.clone(),
                name: name.into(),
            });
        }
    }
    let cs = build(&connection, &purges)?;
    let purged = apply(&connection, &profile, &journal, &cs, None, None)?;
    check(purged.report.issue == Issue::Applied, "purged")?;
    for (zone, name) in [
        (&forward, "essai-r47"),
        (&forward, "essai-r47b"),
        (&forward, "essai-r47c"),
        (&forward, "essai-r47d"),
        (&reverse, ptr_name.as_str()),
    ] {
        check(
            values(&connection, zone, name)?.is_none(),
            &format!("{name} absent"),
        )?;
    }
    println!(
        "SOA {} = {}, {} = {}",
        forward.name,
        serial(&connection, &forward)?,
        reverse.name,
        serial(&connection, &reverse)?
    );

    println!("6. DNS health");
    let t = Instant::now();
    let state = dns_health::read_state(&connection).map_err(|e| format!("{e:?}"))?;
    let read = t.elapsed();
    let t = Instant::now();
    let diagnosis = dns_health::diagnose(&state, Settings::default(), None);
    println!(
        "  read in {:.2} s ({} names), diagnosed in {:.3} s: {} anomalies, {} zones",
        read.as_secs_f64(),
        diagnosis.nodes,
        t.elapsed().as_secs_f64(),
        diagnosis.anomalies.len(),
        diagnosis.zones
    );
    for a in &diagnosis.anomalies {
        // Same line as the Python diagnosis, for the comparison.
        println!(
            "anomaly|{}|{}|{}|{}|{}",
            a.rule.value(),
            a.severity as u8,
            a.targets
                .first()
                .map(|t| t.fqdn().to_lowercase())
                .unwrap_or_default(),
            a.targets.len(),
            a.fix.as_ref().map_or(0, |f| f.requests.len())
        );
    }
    connection.close();
    Ok(())
}

/// Records of the nodes deleted, then the tombstones purged: what the trials left.
fn clean(connection: &Connection, profile: &Profile, journal: &Arc<Journal>) -> Result<()> {
    let zones = dns::zones(connection).map_err(|e| format!("{e:?}"))?;
    let mut names: Vec<(Zone, String)> = Vec::new();
    for zone in zones.iter().filter(|z| !z.root_hints()) {
        let mut entries = Vec::new();
        annuaire_core::source::search_blocking(
            connection,
            annuaire_core::search::Search {
                base: zone.dn.clone(),
                scope: annuaire_core::session::Scope::OneLevel,
                filter: dns::NAMES_FILTER.into(),
                attributes: dns::NODE_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect(),
                page_size: annuaire_core::search::PAGE_SIZE,
                sd_flags: None,
                controls: Vec::new(),
            },
            &mut |page| {
                entries.extend(page);
                true
            },
        )
        .map_err(|e| format!("{e:?}"))?;
        for e in entries {
            let n = dns::node_from_entry(&e, &zone.name);
            let ours = n.name.to_lowercase().starts_with("essai-r47")
                || (zone.reverse()
                    && n.name.parse::<u8>().is_ok_and(|x| x >= 240)
                    && zone.name.starts_with("1.168.192")
                    && (n.tombstone
                        || n.records().iter().any(|r| {
                            matches!(&r.data, RecordData::Name(t) if t.starts_with("essai-r47"))
                        })));
            if ours {
                names.push((zone.clone(), n.name.clone()));
            }
        }
    }
    println!("{} names to clean", names.len());
    for (zone, name) in &names {
        let Some(node) = values(connection, zone, name)? else {
            continue;
        };
        let requests: Vec<Request> = node
            .values
            .iter()
            .filter(|v| Record::decode(v).is_ok_and(|r| r.rtype != dns_record::TOMBSTONE))
            .map(|v| Request::Delete {
                zone: zone.clone(),
                name: name.clone(),
                value: v.clone(),
            })
            .collect();
        if !requests.is_empty() {
            let cs = build(connection, &requests)?;
            apply(
                connection,
                profile,
                journal,
                &cs,
                Some(w::rebuild(requests, Arc::new(English))),
                None,
            )?;
        }
        let cs = build(
            connection,
            &[Request::Purge {
                zone: zone.clone(),
                name: name.clone(),
            }],
        )?;
        apply(connection, profile, journal, &cs, None, None)?;
        println!("  {}: purged", dns::fqdn(&zone.name, name));
    }
    for (zone, name) in &names {
        check(
            values(connection, zone, name)?.is_none(),
            &format!("{name} absent"),
        )?;
    }
    connection.close();
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Reading again after a write, on the DC that received it (J2.11, ADR 0009,
//! `annuaire.core.relecture`).
//!
//! A write goes to the DC of the writes (PDC emulator); the source of the readings may aim at
//! another DC, that only gets the change at the next replication: a few seconds in a site, up
//! to hours between sites. Reading there shows the state before.
//!
//! `touched(report)` says, without network, which objects an application touched: those it
//! created, changed, renamed or deleted, plus the members added to a group or removed (their
//! `memberOf` changed), and which objects changed their DN. `reread(connection, touched)`
//! reads them again on the DC of the connection, in bursts (several reads in flight at once:
//! 5,000 accounts in a reasonable time, without a `|` filter that Samba evaluates in more than
//! linear time). The result, a `Reread`, is what a source holds for the present state of these
//! objects until its DC of reading got them; it is also what the local copy takes.

use std::collections::{HashMap, HashSet};
use std::time::SystemTime;

use crate::changes::{Operation, Report, dn_key, parent_dn};
use crate::connection::{Connection, Failure};
use crate::session::Entry;
use crate::source::{Item, record_attributes};
use crate::writer::Burst;

/// Reads sent before waiting for the answers (`RAFALE`).
pub const BURST: usize = 100;

/// `changes::dn_key`, or the DN in lower case if it cannot be read (never an error here)
/// (`cle`).
pub fn key(dn_text: &str) -> String {
    dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

/// Key of the parent DN; empty for a DN that cannot be read (`cle_parent`).
pub fn parent_key(dn_text: &str) -> String {
    parent_dn(dn_text).map(|p| key(&p)).unwrap_or_default()
}

/// What an application touched, computed on the report (`Touches`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Touched {
    /// To read again, each once: DN before and after for a renamed object.
    pub dns: Vec<String>,
    /// Key of the DN before → DN after, for the objects renamed or moved.
    pub moved: HashMap<String, String>,
    /// Keys of the DN that appeared: objects created, or arrived by a move.
    pub appeared: HashSet<String>,
}

/// Operations maybe written, in order: the changeset then the rollback, doubtful ones
/// included (they may have been applied) (`_operations`).
fn operations(report: &Report) -> Vec<&Operation> {
    let mut ops: Vec<&Operation> = report.applied.iter().map(|a| &a.operation).collect();
    ops.extend(report.doubtful.as_ref().map(|a| &a.operation));
    ops.extend(report.rollback_applied.iter().map(|a| &a.operation));
    ops.extend(report.doubtful_rollback.as_ref().map(|a| &a.operation));
    ops
}

/// `objets_touches`.
pub fn touched(report: &Report) -> Touched {
    let mut dns: Vec<(String, String)> = Vec::new();
    let mut paths: Vec<(String, String)> = Vec::new(); // key of the DN of origin → present DN
    let mut created: HashSet<String> = HashSet::new();
    let mut note = |dn_text: &str| {
        let k = key(dn_text);
        if !dns.iter().any(|(known, _)| *known == k) {
            dns.push((k, dn_text.to_owned()));
        }
    };
    for op in operations(report) {
        if op.is_sysvol() {
            continue;
        }
        note(op.dn());
        match op {
            Operation::Add { dn, .. } => {
                created.insert(key(dn));
            }
            Operation::Modify { changes, .. } => {
                for change in changes
                    .iter()
                    .filter(|c| c.attribute.eq_ignore_ascii_case("member"))
                {
                    for value in change.removed.iter().chain(&change.added) {
                        note(&String::from_utf8_lossy(value));
                    }
                }
            }
            Operation::Rename { dn, .. } => {
                let Ok(new) = op.dn_after() else { continue };
                note(&new);
                let start = key(dn);
                let mut followed = false;
                for (_, present) in paths.iter_mut().filter(|(_, p)| key(p) == start) {
                    *present = new.clone();
                    followed = true;
                }
                if !followed {
                    paths.push((start, new));
                }
            }
            _ => {}
        }
    }
    let moved: HashMap<String, String> = paths
        .into_iter()
        .filter(|(origin, now)| key(now) != *origin)
        .collect();
    let mut appeared = created;
    appeared.extend(moved.values().map(|d| key(d)));
    Touched {
        dns: dns.into_iter().map(|(_, d)| d).collect(),
        moved,
        appeared,
    }
}

/// Objects touched by a write, read again on the DC that received it (`Relecture`).
#[derive(Debug, Clone)]
pub struct Reread {
    pub dc: String,
    /// Instant of the reading again.
    pub date: SystemTime,
    /// By key of DN: the object read again, or None if it does not exist (deleted, or moved:
    /// see `moved`).
    pub objects: HashMap<String, Option<Item>>,
    /// The entries read, for the local copy.
    pub entries: Vec<Entry>,
    /// DN read that no longer exist (deleted, or moved: see `moved`).
    pub absent: Vec<String>,
    pub moved: HashMap<String, String>,
    pub appeared: HashSet<String>,
    /// DN touched as written or read, in lower case: a DN that is not there (nor among the
    /// keys) was not touched, without the cost of a split (`concerne`).
    pub forms: HashSet<String>,
}

impl Reread {
    /// Quick test: false if `dn` was certainly not touched (`concerne`).
    pub fn concerns(&self, dn_text: &str) -> bool {
        let lower = dn_text.to_lowercase();
        self.forms.contains(&lower)
            || self.objects.contains_key(&lower)
            || self.moved.contains_key(&lower)
    }

    pub fn object(&self, dn_text: &str) -> Option<&Item> {
        self.objects.get(&key(dn_text)).and_then(Option::as_ref)
    }

    pub fn known(&self, dn_text: &str) -> bool {
        self.objects.contains_key(&key(dn_text))
    }

    /// New DN of an object renamed or moved; None otherwise.
    pub fn destination(&self, dn_text: &str) -> Option<&str> {
        self.moved.get(&key(dn_text)).map(String::as_str)
    }
}

/// What a reading again asks: the model (`record_attributes`) and the columns of the local
/// copy, without `member` (read by ranges, its links stay until the next delta).
pub fn reread_attributes() -> Vec<String> {
    #[allow(unused_mut)]
    let mut wanted: Vec<String> = record_attributes().into_iter().map(str::to_owned).collect();
    #[cfg(feature = "local-copy")]
    wanted.extend(crate::store::cache_attributes());
    let mut names: Vec<String> = Vec::new();
    for name in wanted {
        if !name.eq_ignore_ascii_case("member")
            && !names.iter().any(|n| n.eq_ignore_ascii_case(&name))
        {
            names.push(name);
        }
    }
    names
}

/// A DN read, and its entry if it exists.
type Found = (String, Option<Entry>);

/// Reads each DN (scope base) on the thread of the connection, by bursts of `BURST`; None if
/// it does not exist (`lire_en_rafale`).
fn read_in_bursts(
    connection: &Connection,
    dns: &[String],
) -> Result<(String, Vec<Found>), Failure> {
    let dns = dns.to_vec();
    let attributes = reread_attributes();
    connection.run(true, move |link| {
        let names: Vec<&str> = attributes.iter().map(String::as_str).collect();
        let mut read = Vec::with_capacity(dns.len());
        for batch in dns.chunks(BURST) {
            let mut burst = Burst::new();
            for dn_text in batch {
                burst.read(link, dn_text, &names, "(objectClass=*)", None)?;
            }
            let answers = burst.receive(link)?;
            for (dn_text, answer) in batch.iter().zip(answers) {
                let entry = answer.and_then(|entries| entries.into_iter().next());
                read.push((dn_text.clone(), entry));
            }
        }
        Ok((link.state.dc.clone(), read))
    })
}

/// Reads the objects touched again on the DC of `connection` (blocking) (`relire`).
pub fn reread(connection: &Connection, touched: &Touched) -> Result<Reread, Failure> {
    let date = SystemTime::now();
    let (dc, read) = read_in_bursts(connection, &touched.dns)?;
    let mut forms: HashSet<String> = touched.dns.iter().map(|d| d.to_lowercase()).collect();
    let mut objects = HashMap::new();
    let (mut entries, mut absent) = (Vec::new(), Vec::new());
    for (dn_text, entry) in read {
        let item = entry.as_ref().map(Item::from_entry);
        match entry {
            Some(entry) => {
                forms.insert(entry.dn.to_lowercase());
                entries.push(entry);
            }
            None => absent.push(dn_text.clone()),
        }
        objects.insert(key(&dn_text), item);
    }
    Ok(Reread {
        dc,
        date,
        objects,
        entries,
        absent,
        moved: touched.moved.clone(),
        appeared: touched.appeared.clone(),
        forms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changes::{Applied, Change, Changeset, Issue};
    use crate::dn::Component;

    fn report(operations: Vec<Operation>) -> Report {
        Report {
            id: "x".into(),
            timestamp: String::new(),
            domain: "lab.test".into(),
            dc: "dc1".into(),
            user: String::new(),
            changeset: Changeset::default(),
            applied: operations
                .into_iter()
                .map(|operation| Applied {
                    operation,
                    after: None,
                    before: None,
                })
                .collect(),
            issue: Issue::Applied,
            error: None,
            rollback: None,
            origins: Vec::new(),
            rollback_applied: Vec::new(),
            rollback_error: None,
            doubtful: None,
            doubtful_rollback: None,
            resumes: None,
            resumed_by: None,
        }
    }

    #[test]
    fn touched_objects() {
        let member = Change::new(
            "member",
            vec![b"CN=b,DC=x".to_vec()],
            vec![b"CN=c,DC=x".to_vec()],
        )
        .unwrap();
        let ops = vec![
            Operation::add("CN=n,OU=a,DC=x", vec![("cn".into(), vec![b"n".to_vec()])]).unwrap(),
            Operation::modify("CN=g,DC=x", vec![member], None).unwrap(),
            Operation::rename(
                "CN=u,OU=a,DC=x",
                Component::new("CN", "u"),
                Some("OU=b,DC=x".into()),
                None,
            )
            .unwrap(),
        ];
        let t = touched(&report(ops));
        assert_eq!(
            t.dns,
            [
                "CN=n,OU=a,DC=x",
                "CN=g,DC=x",
                "CN=b,DC=x",
                "CN=c,DC=x",
                "CN=u,OU=a,DC=x",
                "CN=u,OU=b,DC=x"
            ]
        );
        assert_eq!(
            t.moved.get("cn=u,ou=a,dc=x").map(String::as_str),
            Some("CN=u,OU=b,DC=x")
        );
        assert!(t.appeared.contains("cn=n,ou=a,dc=x") && t.appeared.contains("cn=u,ou=b,dc=x"));
        assert_eq!(parent_key("CN=u,OU=b,DC=x"), "ou=b,dc=x");
    }
}

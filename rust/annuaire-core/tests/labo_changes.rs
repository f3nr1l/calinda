// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Changesets applied then undone against the lab LAB.TEST (port of `test_changes_labo.py`,
//! J1.8 and J1.10, ADR 0020): read-only profile refused, add, modify, rename and move,
//! two operations on one object, members of a group, delete then recreate, conflict on a
//! concurrent modification, undo from the journal, missing target seen before any write,
//! failure in the middle of five objects and complete rollback.
//!
//! Everything happens under `OU=Essais-R5,OU=Labo,DC=lab,DC=test`, created at the start and
//! removed at the end, also after a failure (and at the start, if a run was interrupted). One
//! test function: the steps share the OU and the journal. See `labo/mod.rs` to run it.

mod labo;

use std::collections::BTreeMap;
use std::sync::Arc;

use annuaire_core::Connection;
use annuaire_core::changes::{self, Change, Changeset, Issue, Operation, Read, Report};
use annuaire_core::dn::{self, Component};
use annuaire_core::journal::Journal;
use annuaire_core::profile::Profile;
use annuaire_core::search::read_entry;
use annuaire_core::session::Scope;
use annuaire_core::source;
use annuaire_core::writer::{self, ApplyError, ProblemKind};

use labo::{Result, Scratch, Texts, check, debug, entries};

const BASE: &str = "DC=lab,DC=test";

struct Trial {
    connection: Connection,
    profile: Profile,
    journal: Arc<Journal>,
    trials: String,
    arrival: String,
    departure: String,
}

fn bytes(values: &[&str]) -> Vec<Vec<u8>> {
    values.iter().map(|v| v.as_bytes().to_vec()).collect()
}

fn attributes(pairs: &[(&str, &[&str])]) -> changes::AttributeMap {
    pairs
        .iter()
        .map(|(a, v)| ((*a).to_owned(), bytes(v)))
        .collect()
}

impl Trial {
    fn apply_raw(&self, changeset: &Changeset) -> Result<writer::Outcome> {
        writer::apply(
            &self.connection,
            &self.profile,
            changeset,
            self.journal.clone(),
            Arc::new(Texts),
            None,
            None,
        )
        .map_err(debug)
    }

    fn apply(&self, operations: Vec<Operation>) -> Result<Report> {
        let outcome = self.apply_raw(&Changeset {
            operations,
            remarks: Vec::new(),
        })?;
        if outcome.report.issue != Issue::Applied {
            return Err(format!(
                "not applied: {:?} {:?} {:?}",
                outcome.report.issue, outcome.report.error, outcome.problems
            )
            .into());
        }
        Ok(outcome.report)
    }

    fn inverse(&self, report: &Report) -> Result<Changeset> {
        changes::inverse(report, &writer::read_journal(&self.journal), &Texts).map_err(debug)
    }

    fn undo(&self, report: &Report) -> Result<Report> {
        let inverse = self.inverse(report)?;
        let outcome = self.apply_raw(&inverse)?;
        check(outcome.report.issue == Issue::Applied, "undone")?;
        Ok(outcome.report)
    }

    fn exists(&self, dn: &str) -> Result<bool> {
        Ok(self.read(dn, &["1.1"])?.is_some())
    }

    fn read(
        &self,
        dn: &str,
        attributes: &[&str],
    ) -> Result<Option<BTreeMap<String, Vec<Vec<u8>>>>> {
        let dn = dn.to_owned();
        let names: Vec<String> = attributes.iter().map(|&a| a.to_owned()).collect();
        let entry = self
            .connection
            .run(true, move |link| {
                read_entry(
                    &mut *link.session,
                    &dn,
                    &names,
                    "(objectClass=*)",
                    None,
                    None,
                )
            })
            .map_err(debug)?;
        Ok(entry.map(|e| {
            e.attributes
                .into_iter()
                .map(|(a, mut v)| {
                    v.sort();
                    (a.to_lowercase(), v)
                })
                .collect()
        }))
    }

    /// The object without the system attributes, `memberOf` included (back link).
    fn state(&self, dn: &str) -> Result<BTreeMap<String, Vec<Vec<u8>>>> {
        let mut state = self
            .read(dn, &["*", "memberOf"])?
            .ok_or_else(|| format!("{dn} absent"))?;
        state.retain(|a, _| a == "memberof" || !changes::SYSTEM.contains(&a.as_str()));
        Ok(state)
    }

    fn version(&self, dn: &str) -> Result<Read> {
        writer::read_version(&self.connection, dn)
            .map_err(debug)?
            .ok_or_else(|| format!("{dn} absent").into())
    }

    fn user(&self, cn: &str) -> Result<String> {
        let dn = format!("CN={cn},{}", self.arrival);
        let account: String = format!("r5-{}", cn.to_lowercase().replace(' ', ""))
            .chars()
            .take(20)
            .collect();
        self.apply(vec![
            Operation::add(
                &dn,
                attributes(&[
                    ("objectClass", &["user"]),
                    ("sAMAccountName", &[&account]),
                    ("userAccountControl", &["514"]),
                    ("description", &["créé par R5"]),
                    ("otherTelephone", &["01 02", "01 03"]),
                ]),
            )
            .map_err(debug)?,
        ])?;
        Ok(dn)
    }

    fn modification(&self, dn: &str, wanted: &[(&str, &[&str])]) -> Result<Operation> {
        writer::prepare_modification(&self.connection, dn, attributes(wanted))
            .map_err(debug)?
            .ok_or_else(|| "nothing to change".into())
    }

    /// Removes the OU of trial and its content in one changeset, leaves first.
    fn empty(&self) -> Result<()> {
        let mut dns: Vec<String> = entries(
            &self.connection,
            &self.trials,
            Scope::Subtree,
            "(objectClass=*)",
            &["1.1"],
        )?
        .into_iter()
        .map(|e| e.dn)
        .collect();
        dns.sort_by_key(|d| std::cmp::Reverse(dn::split(d).map_or(0, |c| c.len())));
        let operations = dns
            .iter()
            .map(|d| Operation::delete(d, None, Vec::new()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(debug)?;
        if !operations.is_empty() {
            self.apply(operations)?;
        }
        Ok(())
    }
}

#[test]
#[ignore = "lab"]
fn changesets() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let scratch = Scratch::new("changes")?;
    let mut profile = Profile::new("lab.test");
    profile.read_only = false;
    // The DC is fixed: the versions (uSNChanged) compare on the DC of reading only.
    profile.preferred_dc = Some("dc1.lab.test".into());
    let trials = format!("OU=Essais-R5,OU=Labo,{BASE}");
    let trial = Trial {
        connection: source::connection_to(&profile, Some("dc1.lab.test")),
        profile,
        journal: scratch.journal(),
        arrival: format!("OU=Arrivée,{trials}"),
        departure: format!("OU=Départ\\, à trier,{trials}"),
        trials,
    };
    if trial.exists(&trial.trials)? {
        trial.empty()?; // left by an interrupted run
    }
    let ou = |dn: &str| Operation::add(dn, attributes(&[("objectClass", &["organizationalUnit"])]));
    trial.apply(vec![
        Operation::add(
            &trial.trials,
            attributes(&[
                ("objectClass", &["organizationalUnit"]),
                ("description", &["R5, à retirer"]),
            ]),
        )
        .map_err(debug)?,
        ou(&trial.arrival).map_err(debug)?,
        ou(&trial.departure).map_err(debug)?,
    ])?;
    let result = steps(&trial, &scratch);
    let cleaned = trial
        .empty()
        .and_then(|()| check(!trial.exists(&trial.trials)?, "OU of trial removed"));
    trial.connection.join();
    result.and(cleaned)
}

fn steps(trial: &Trial, scratch: &Scratch) -> Result<()> {
    println!("read-only profile");
    let read_only = Profile::new("lab.test");
    let refused = writer::apply(
        &trial.connection,
        &read_only,
        &Changeset {
            operations: vec![Operation::delete(&trial.trials, None, Vec::new()).map_err(debug)?],
            remarks: Vec::new(),
        },
        trial.journal.clone(),
        Arc::new(Texts),
        None,
        None,
    );
    check(
        matches!(refused, Err(ApplyError::Record(ref r)) if r.class == "ErreurLectureSeule"),
        "refused before anything",
    )?;

    println!("add, then its inverse");
    let contact = format!("CN=Contact R5,{}", trial.arrival);
    let report = trial.apply(vec![
        Operation::add(
            &contact,
            attributes(&[("objectClass", &["contact"]), ("mail", &["c@lab.test"])]),
        )
        .map_err(debug)?,
    ])?;
    check(trial.exists(&contact)?, "contact created")?;
    trial.undo(&report)?;
    check(!trial.exists(&contact)?, "contact removed by the inverse")?;

    println!("modify, then its inverse");
    let dn = trial.user("Modif")?;
    let before = trial.state(&dn)?;
    let modify = trial.modification(
        &dn,
        &[
            ("description", &["modifié, « guillemets » et accents"]),
            ("otherTelephone", &["01 03", "01 04", "01 05"]), // multi-valued: −1, +2
            ("info", &["ajouté"]),
            ("userAccountControl", &["66050"]), // 514 | DONT_EXPIRE_PASSWORD
        ],
    )?;
    check(
        matches!(&modify, Operation::Modify { changes, .. } if changes.len() == 4),
        "four changes",
    )?;
    let report = trial.apply(vec![modify])?;
    let during = trial.state(&dn)?;
    check(
        during.get("othertelephone") == Some(&bytes(&["01 03", "01 04", "01 05"])),
        "multi-valued written",
    )?;
    check(
        during.get("useraccountcontrol") == Some(&bytes(&["66050"]))
            && during.get("info") == Some(&bytes(&["ajouté"])),
        "values written",
    )?;
    trial.undo(&report)?;
    check(trial.state(&dn)? == before, "object as before")?;

    println!("rename and move, then the inverse");
    let dn = trial.user("Renomme")?;
    let before = trial.state(&dn)?;
    let rename = Operation::rename(
        &dn,
        Component::new("CN", "Dupont, Jérôme"),
        Some(trial.departure.clone()),
        Some(trial.version(&dn)?),
    )
    .map_err(debug)?;
    let moved = rename.dn_after().map_err(debug)?;
    check(
        moved == format!("CN=Dupont\\, Jérôme,{}", trial.departure),
        "new DN escaped",
    )?;
    let report = trial.apply(vec![rename])?;
    check(
        trial.state(&moved)?.get("cn") == Some(&bytes(&["Dupont, Jérôme"])),
        "renamed",
    )?;
    check(!trial.exists(&dn)?, "old DN gone")?;
    trial.undo(&report)?;
    check(trial.state(&dn)? == before, "back as before")?;

    println!("two operations on one object, one reading");
    let dn = trial.user("Menage")?;
    let before = trial.state(&dn)?;
    let read = trial.version(&dn)?;
    let rdn = dn::split(&dn)
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("RDN")?;
    let report = trial.apply(vec![
        Operation::modify(
            &dn,
            vec![
                Change::new("description", bytes(&["créé par R5"]), bytes(&["parti"]))
                    .map_err(debug)?,
            ],
            Some(read.clone()),
        )
        .map_err(debug)?,
        Operation::rename(&dn, rdn, Some(trial.departure.clone()), Some(read)).map_err(debug)?,
    ])?;
    trial.undo(&report)?;
    check(trial.state(&dn)? == before, "both undone")?;

    println!("members of a group");
    let member = trial.user("Membre")?;
    let group = format!("CN=GG-R5,{}", trial.arrival);
    trial.apply(vec![
        Operation::add(
            &group,
            attributes(&[("objectClass", &["group"]), ("sAMAccountName", &["gg-r5"])]),
        )
        .map_err(debug)?,
    ])?;
    let before = trial.state(&group)?;
    let report = trial.apply(vec![
        Operation::modify(
            &group,
            vec![Change::new("member", Vec::new(), bytes(&[&member])).map_err(debug)?],
            Some(trial.version(&group)?),
        )
        .map_err(debug)?,
    ])?;
    check(
        trial.state(&member)?.get("memberof") == Some(&bytes(&[&group])),
        "memberOf of the member",
    )?;
    trial.undo(&report)?;
    check(trial.state(&group)? == before, "group as before")?;
    check(
        !trial.state(&member)?.contains_key("memberof"),
        "member out of the group",
    )?;

    println!("delete, then recreate");
    let member = trial.user("Supprime")?;
    let other = trial.user("Reste")?;
    let group = format!("CN=GG-R5-Supp,{}", trial.arrival);
    trial.apply(vec![
        Operation::add(
            &group,
            attributes(&[
                ("objectClass", &["group"]),
                ("sAMAccountName", &["gg-r5-supp"]),
                ("member", &[&member, &other]),
            ]),
        )
        .map_err(debug)?,
    ])?;
    let (member_before, group_before) = (trial.state(&member)?, trial.state(&group)?);
    let old_sid = trial.read(&member, &["objectSid"])?.ok_or("member")?;
    let report = trial.apply(vec![
        Operation::delete(&member, Some(trial.version(&member)?), Vec::new()).map_err(debug)?,
    ])?;
    check(
        report.applied.first().is_some_and(|a| a.before.is_some()),
        "complete state kept before the deletion",
    )?;
    check(!trial.exists(&member)?, "deleted")?;
    let inverse = trial.inverse(&report)?;
    check(
        inverse.remarks.iter().any(|r| r.contains("new object")),
        "remark: a new object",
    )?;
    trial.undo(&report)?;
    check(
        trial.state(&member)? == member_before,
        "recreated, memberOf included",
    )?;
    let new_sid = trial.read(&member, &["objectSid"])?.ok_or("member")?;
    check(
        old_sid.get("objectsid") != new_sid.get("objectsid"),
        "new objectSid",
    )?;
    let report = trial.apply(vec![
        Operation::delete(&group, Some(trial.version(&group)?), Vec::new()).map_err(debug)?,
    ])?;
    trial.undo(&report)?;
    check(
        trial.state(&group)? == group_before,
        "group back with its members",
    )?;

    println!("conflict on a concurrent modification");
    let dn = trial.user("Conflit")?;
    let mine = trial.modification(&dn, &[("description", &["la mienne"])])?;
    // Another administrator comes between the preview and the application.
    let theirs = trial.modification(&dn, &[("info", &["la sienne"])])?;
    trial.apply(vec![theirs])?;
    let outcome = trial.apply_raw(&Changeset {
        operations: vec![mine],
        remarks: Vec::new(),
    })?;
    check(outcome.report.issue == Issue::Refused, "refused")?;
    check(
        outcome.problems.iter().map(|p| p.kind).collect::<Vec<_>>() == [ProblemKind::Version],
        "a version problem",
    )?;
    check(outcome.report.applied.is_empty(), "nothing applied")?;
    check(
        trial.state(&dn)?.get("description") == Some(&bytes(&["créé par R5"])),
        "description unchanged",
    )?;
    let mine = trial.modification(&dn, &[("description", &["la mienne"])])?;
    trial.apply(vec![mine])?;

    println!("undo from the journal");
    let dn = trial.user("Journal")?;
    let before = trial.state(&dn)?;
    let report = trial.apply(vec![
        trial.modification(&dn, &[("description", &["depuis le journal"])])?,
    ])?;
    let read = writer::read_journal(&trial.journal)
        .into_iter()
        .find(|r| r.id == report.id)
        .ok_or("report in the journal")?;
    check(
        read.user.to_lowercase().ends_with("administrator") && read.dc == "dc1.lab.test",
        "user and DC journaled",
    )?;
    trial.undo(&read)?;
    check(trial.state(&dn)? == before, "undone from the journal")?;
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(scratch.path().join("changes.jsonl"))?
            .permissions()
            .mode();
        check(mode & 0o777 == 0o600, "journal readable by its owner only")?;
    }

    println!("move to a missing OU: seen before any write");
    let dn = trial.user("Cible")?;
    let before = trial.state(&dn)?;
    let read = trial.version(&dn)?;
    let rdn = dn::split(&dn)
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("RDN")?;
    let outcome = trial.apply_raw(&Changeset {
        operations: vec![
            Operation::modify(
                &dn,
                vec![Change::new("info", Vec::new(), bytes(&["partira"])).map_err(debug)?],
                Some(read.clone()),
            )
            .map_err(debug)?,
            Operation::rename(
                &dn,
                rdn,
                Some(format!("OU=Inexistante,{}", trial.trials)),
                Some(read.clone()),
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    check(outcome.report.issue == Issue::Refused, "refused")?;
    check(
        outcome
            .problems
            .iter()
            .map(|p| (p.index, p.kind))
            .collect::<Vec<_>>()
            == [(1, ProblemKind::Target)],
        "the target of the second operation",
    )?;
    check(
        trial.state(&dn)? == before && trial.version(&dn)? == read,
        "nothing written",
    )?;

    println!("failure in the middle of five objects: everything undone");
    let users = [
        "Cinq Un",
        "Cinq Deux",
        "Cinq Trois",
        "Cinq Quatre",
        "Cinq Cinq",
    ]
    .iter()
    .map(|cn| trial.user(cn))
    .collect::<Result<Vec<_>>>()?;
    let group = format!("CN=GG-Cinq,{}", trial.arrival);
    trial.apply(vec![
        Operation::add(
            &group,
            attributes(&[("objectClass", &["group"]), ("sAMAccountName", &["gg-5"])]),
        )
        .map_err(debug)?,
    ])?;
    let all: Vec<String> = users.iter().cloned().chain([group.clone()]).collect();
    let before = all
        .iter()
        .map(|dn| trial.state(dn))
        .collect::<Result<Vec<_>>>()?;
    let new = format!("CN=Contact Cinq,{}", trial.arrival);
    let [one, two, three, four, five] = users.as_slice() else {
        return Err("five users".into());
    };
    let operations = vec![
        Operation::add(&new, attributes(&[("objectClass", &["contact"])])).map_err(debug)?,
        Operation::modify(
            one,
            vec![
                Change::new("description", bytes(&["créé par R5"]), bytes(&["modifié"]))
                    .map_err(debug)?,
                Change::new("userAccountControl", bytes(&["514"]), bytes(&["66050"]))
                    .map_err(debug)?,
            ],
            Some(trial.version(one)?),
        )
        .map_err(debug)?,
        Operation::rename(
            two,
            Component::new("CN", "Cinq, Deux déplacé"),
            Some(trial.departure.clone()),
            Some(trial.version(two)?),
        )
        .map_err(debug)?,
        // A valid integer (the prior check can evaluate it), out of the bounds of the schema
        // (0 to 65535): invalidAttributeSyntax on writing.
        Operation::modify(
            three,
            vec![Change::new("countryCode", bytes(&["0"]), bytes(&["70000"])).map_err(debug)?],
            Some(trial.version(three)?),
        )
        .map_err(debug)?,
        Operation::modify(
            &group,
            vec![Change::new("member", Vec::new(), bytes(&[four, five])).map_err(debug)?],
            Some(trial.version(&group)?),
        )
        .map_err(debug)?,
    ];
    let outcome = trial.apply_raw(&Changeset {
        operations,
        remarks: Vec::new(),
    })?;
    check(outcome.report.issue == Issue::Cancelled, "cancelled")?;
    check(
        outcome.report.applied.len() == 3 && outcome.report.rollback_applied.len() == 3,
        "three applied, three undone",
    )?;
    check(!trial.exists(&new)?, "contact created removed")?;
    let after = all
        .iter()
        .map(|dn| trial.state(dn))
        .collect::<Result<Vec<_>>>()?;
    check(after == before, "the six objects as before")?;
    let read = writer::read_journal(&trial.journal)
        .into_iter()
        .find(|r| r.id == outcome.report.id)
        .ok_or("report in the journal")?;
    check(
        read.issue == Issue::Cancelled && read.remaining_indices().is_empty(),
        "journaled as cancelled, nothing left",
    )?;
    Ok(())
}

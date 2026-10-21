// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The model, the queries and the activity against both DCs of LAB.TEST, with `ldbsearch` on
//! the DCs for oracle (port of `test_modele_labo.py`, `test_recherche_labo.py`,
//! `test_activite_multi_dc_labo.py` and `test_coherence_labo.py`, ADR 0020).
//!
//! - `model_inactive_as_ldbsearch`: the survey of the activity (20 000 users, the computers)
//!   gives the inactive accounts for 30, 90, 180 and 365 days that the computation by hand on
//!   `sam.ldb` gives (`lastLogon` not being replicated, the most recent of both DCs); the states
//!   of the accounts (disabled, expired, change required) as the DC says.
//! - `model_objects_and_membership`: known objects of the model; recursive groups as the IN_CHAIN
//!   rule of the DC computes them, a chain of seven, a cycle.
//! - `model_queries`: the ready queries run by the source, each compared with the same
//!   computation made on every account by the model; conflicts; administrators.
//! - `model_activity_on_two_dcs`: two accounts of the lab log on crosswise on dc1 and dc2, the
//!   survey keeps the `lastLogon` of the right DC, from either; dc2 stopped for one survey,
//!   which says so without failing.
//! - `model_coherence`: the source reads on dc2, the writes go to dc1; right after a write, the
//!   source shows the state written, read again on dc1, then goes back to dc2 once the
//!   replication arrived; 1 000 accounts read again by bursts.
//!
//! LAB.TEST only. Read only, except `model_coherence` (under `OU=Essais-J2-coherence`) and the
//! logons of two accounts of the lab, whose passwords come from the seed of `peupler.py`.
//! The command line of the Python version (`inactifs`) has no Rust counterpart. See
//! `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use annuaire_codecs::time;
use annuaire_core::changes::{Change, Changeset, Operation};
use annuaire_core::membership;
use annuaire_core::model::{self, ActivitySource, Object};
use annuaire_core::profile::Profile;
use annuaire_core::queries::{self, Kind, Query, State};
use annuaire_core::reread;
use annuaire_core::search::{self, OID_IN_CHAIN, Value};
use annuaire_core::session::Scope;
use annuaire_core::source::{self, DirectSource, Item};
use annuaire_core::{Connection, actions};

use labo::{Lab, Ldif, Result, Trial, check, debug, entries, samba_only};

const DC1: &str = "dc1.lab.test";
const DC2: &str = "dc2.lab.test";

fn groups_ou(lab: &Lab) -> String {
    format!("OU=Sécurité,OU=Groupes,OU=Labo,{}", lab.base)
}

fn not_cancelled() -> bool {
    false
}

/// The instant of reference, to the second, as NTTIME.
fn reference() -> Result<i64> {
    let seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    Ok(time::unix_to_nttime(seconds)?)
}

const DAY: i64 = 86_400 * time::TICKS_PER_SECOND;

/// Records of `sam.ldb` of dc1, `lastLogon` replaced by the most recent of both DCs.
fn oracle(lab: &Lab, filter: &str) -> Result<Vec<Ldif>> {
    let attributes = [
        "objectGUID",
        "lastLogon",
        "lastLogonTimestamp",
        "pwdLastSet",
        "whenCreated",
        "userAccountControl",
        "accountExpires",
    ];
    let mut records = labo::ldbsearch("dc1", &lab.base, "sub", filter, &attributes)?;
    let mut latest: BTreeMap<String, i64> = BTreeMap::new();
    for dc in ["dc1", "dc2"] {
        for r in labo::ldbsearch(dc, &lab.base, "sub", filter, &["objectGUID", "lastLogon"])? {
            if let (Some(guid), Some(logon)) = (
                labo::ldif_text(&r, "objectGUID"),
                labo::ldif_text(&r, "lastLogon"),
            ) {
                let logon: i64 = logon.parse()?;
                let entry = latest.entry(guid).or_default();
                *entry = (*entry).max(logon);
            }
        }
    }
    for r in &mut records {
        let guid = labo::ldif_text(r, "objectGUID").unwrap_or_default();
        let value = latest.get(&guid).copied().unwrap_or(0);
        r.insert("lastlogon".into(), vec![value.to_string().into_bytes()]);
    }
    Ok(records)
}

fn number(r: &Ldif, attribute: &str) -> Option<i64> {
    labo::ldif_text(r, attribute).and_then(|t| t.parse().ok())
}

/// GUIDs of the inactive accounts by hand: max(lastLogon, lastLogonTimestamp[, pwdLastSet]) <
/// threshold, or, without any date, whenCreated < threshold.
fn inactive_by_hand(records: &[Ldif], threshold: i64, with_pwd: bool) -> Result<BTreeSet<String>> {
    let generalized = time::nttime_to_utc(threshold)?
        .map(time::encode_generalized_time)
        .ok_or("threshold")?;
    let mut out = BTreeSet::new();
    for r in records {
        let mut names = vec!["lastLogon", "lastLogonTimestamp"];
        if with_pwd {
            names.push("pwdLastSet");
        }
        let dates: Vec<i64> = names
            .iter()
            .filter_map(|n| number(r, n))
            .filter(|&d| d != 0 && d != time::NTTIME_NEVER)
            .collect();
        let inactive = match dates.iter().max() {
            Some(&latest) => latest < threshold,
            None => {
                let created = labo::ldif_text(r, "whenCreated").unwrap_or_default();
                created.get(..14).unwrap_or_default() < generalized.get(..14).unwrap_or_default()
            }
        };
        if inactive {
            out.insert(
                labo::ldif_text(r, "objectGUID")
                    .unwrap_or_default()
                    .to_lowercase(),
            );
        }
    }
    Ok(out)
}

fn guids(accounts: &[queries::Surveyed]) -> BTreeSet<String> {
    accounts
        .iter()
        .filter_map(|(o, _)| o.common().guid.map(|g| g.to_string().to_lowercase()))
        .collect()
}

fn source_on(lab: &Lab, dc: &str) -> DirectSource {
    let mut profile = Profile::new(lab.domain.clone());
    profile.preferred_dc = Some(dc.into());
    DirectSource::with_connection(profile.clone(), source::connection_to(&profile, Some(dc)))
}

#[test]
#[ignore = "lab"]
fn model_inactive_as_ldbsearch() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let now = reference()?;
    let source = DirectSource::new(lab.profile(false));
    for (kind, filter, with_pwd) in [
        ("users", queries::USERS, false),
        ("computers", queries::COMPUTERS, true),
    ] {
        let t = std::time::Instant::now();
        let survey = source.survey(filter, &not_cancelled).map_err(debug)?;
        let accounts = survey.accounts();
        println!(
            "{kind}: {} accounts surveyed in {:.1} s",
            accounts.len(),
            t.elapsed().as_secs_f64()
        );
        check(
            survey.failures.is_empty()
                && survey.dcs.iter().cloned().collect::<BTreeSet<_>>()
                    == [DC1.to_owned(), DC2.to_owned()].into(),
            "survey complete on both DCs",
        )?;
        let records = oracle(&lab, filter)?;
        let all: BTreeSet<String> = records
            .iter()
            .filter_map(|r| labo::ldif_text(r, "objectGUID"))
            .map(|g| g.to_lowercase())
            .collect();
        check(all == guids(&accounts), "the same accounts as sam.ldb")?;
        if kind == "users" {
            check(accounts.len() >= 20_000, "20 000 users at least")?;
        }
        for days in [30, 90, 180, 365] {
            let threshold = now - days * DAY;
            let core = guids(&queries::select_inactive(accounts.clone(), threshold));
            let hand = inactive_by_hand(&records, threshold, with_pwd)?;
            check(
                core == hand,
                &format!("{kind} inactive for {days} days: {}", hand.len()),
            )?;
        }
        if kind == "users" {
            let utc = time::nttime_to_utc(now)?.ok_or("now")?;
            let by_guid: BTreeMap<String, &Object> = accounts
                .iter()
                .filter_map(|(o, _)| Some((o.common().guid?.to_string().to_lowercase(), o)))
                .collect();
            let mut disabled = 0;
            let mut expired = 0;
            for r in &records {
                let guid = labo::ldif_text(r, "objectGUID")
                    .unwrap_or_default()
                    .to_lowercase();
                let account = by_guid
                    .get(&guid)
                    .and_then(|o| o.account())
                    .ok_or("account")?;
                let uac = number(r, "userAccountControl").unwrap_or(0);
                let expires = number(r, "accountExpires").unwrap_or(0);
                let states = (
                    account.active(),
                    account.expired(utc),
                    account.must_change_password(),
                );
                let wanted = (
                    uac & 2 == 0,
                    expires != 0 && expires != time::NTTIME_NEVER && expires <= now,
                    labo::ldif_text(r, "pwdLastSet").as_deref() == Some("0"),
                );
                if states != wanted {
                    return Err(format!("FAILED: states of {guid}: {states:?} / {wanted:?}").into());
                }
                disabled += usize::from(!account.active());
                expired += usize::from(account.expired(utc));
            }
            println!("  {disabled} disabled, {expired} expired");
            check(
                disabled >= 6_006 && expired > 0,
                "states of the accounts as the DC says",
            )?;
        }
    }
    source.close();
    Ok(())
}

// --- Objects and membership -------------------------------------------------------------------

fn object(connection: &Connection, dn: &str) -> Result<Object> {
    let entry = labo::entry(connection, dn, &model::attributes(), None)?.ok_or("object")?;
    model::object_from_entry(&entry).map_err(debug)
}

fn direct_member(connection: &Connection, lab: &Lab, group: &str) -> Result<String> {
    let filter = search::and(&[
        queries::USERS.to_owned(),
        search::eq(
            "memberOf",
            Value::Text(&format!("CN={group},{}", groups_ou(lab))),
        )?,
    ])?;
    Ok(
        entries(connection, &lab.base, Scope::Subtree, &filter, &["1.1"])?
            .into_iter()
            .next()
            .ok_or("a member")?
            .dn,
    )
}

/// Server-side oracle: the groups containing one of `dns` by the IN_CHAIN rule.
fn in_chain(connection: &Connection, lab: &Lab, dns: &[&str]) -> Result<BTreeSet<String>> {
    let rules: Vec<String> = dns
        .iter()
        .map(|d| search::rule("member", OID_IN_CHAIN, Value::Text(d)))
        .collect::<std::result::Result<_, _>>()?;
    let filter = search::and(&["(objectClass=group)".to_owned(), search::or(&rules)?])?;
    Ok(
        entries(connection, &lab.base, Scope::Subtree, &filter, &["1.1"])?
            .into_iter()
            .map(|e| e.dn.to_lowercase())
            .collect(),
    )
}

/// Member at any depth: one round trip, IN_CHAIN in scope base on the object.
fn is_member(connection: &Connection, dn: &str, group: &str) -> Result<bool> {
    let filter = search::rule("memberOf", OID_IN_CHAIN, Value::Text(group))?;
    Ok(!entries(connection, dn, Scope::Base, &filter, &["1.1"])?.is_empty())
}

#[test]
#[ignore = "lab"]
fn model_objects_and_membership() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let base = lab.base.clone();
    let connection = source::connection_to(&lab.profile(false), None);
    println!("1. known objects");
    let admin = object(&connection, &format!("CN=Administrator,CN=Users,{base}"))?;
    let account = admin.account().ok_or("account")?;
    check(
        matches!(admin, Object::User { .. })
            && account.active()
            && account.primary_group_id == Some(513)
            && account.sid.is_some()
            && account.primary_group_sid().is_some(),
        "Administrator",
    )?;
    for dn in [
        format!("CN=Builtin,{base}"),
        format!("CN=LostAndFound,{base}"),
        base.clone(),
    ] {
        check(
            matches!(object(&connection, &dn)?, Object::Container(_)),
            &format!("{dn}: container"),
        )?;
    }
    check(
        matches!(
            object(&connection, &format!("OU=Labo,{base}"))?,
            Object::Ou(_)
        ),
        "OU=Labo: OU",
    )?;
    // Samba gives the 5 000 members at once, without range (ADR 0001, finding 6).
    match object(
        &connection,
        &format!("CN=GU-Tous-Salariés,{}", groups_ou(&lab)),
    )? {
        Object::Group {
            members,
            members_partial,
            ..
        } => check(
            members.len() == 5_000 && !members_partial,
            "5 000 members at once",
        )?,
        _ => return Err("not a group".into()),
    }

    println!("2. recursive groups as IN_CHAIN");
    let domain_users = format!("CN=Domain Users,CN=Users,{base}");
    for group in ["GG-Projet-148", "GG-Projet-006"] {
        let dn = direct_member(&connection, &lab, group)?;
        let found = membership::groups_of(&connection, &dn, true).map_err(debug)?;
        check(
            found.primary.as_deref() == Some(domain_users.as_str()),
            "primary group",
        )?;
        let mut wanted = in_chain(&connection, &lab, &[&dn, &domain_users])?;
        wanted.insert(domain_users.to_lowercase());
        let core: BTreeSet<String> = found
            .recursive
            .iter()
            .flatten()
            .map(|g| g.to_lowercase())
            .collect();
        check(
            core == wanted,
            &format!("groups of a member of {group}: {}", core.len()),
        )?;
    }

    println!("3. a chain of seven");
    let dn = direct_member(&connection, &lab, "GG-Projet-006")?;
    let found = membership::groups_of(&connection, &dn, true).map_err(debug)?;
    let recursive: HashSet<String> = found.recursive.iter().flatten().cloned().collect();
    check(
        (0..7).all(|k| recursive.contains(&format!("CN=GG-Projet-{k:03},{}", groups_ou(&lab)))),
        "GG-Projet-000 to 006",
    )?;
    check(
        is_member(
            &connection,
            &dn,
            &format!("CN=GG-Projet-000,{}", groups_ou(&lab)),
        )? && !is_member(
            &connection,
            &dn,
            &format!("CN=GG-Projet-007,{}", groups_ou(&lab)),
        )?,
        "member of 000, not of 007",
    )?;

    println!("4. a cycle: 147 ⊃ 148 ⊃ 149 ⊃ 147");
    let g147 = format!("CN=GG-Projet-147,{}", groups_ou(&lab));
    let found = membership::groups_of(&connection, &g147, true).map_err(debug)?;
    let recursive = found.recursive.unwrap_or_default();
    let distinct: HashSet<&String> = recursive.iter().collect();
    check(
        [147, 148, 149]
            .iter()
            .all(|k| recursive.contains(&format!("CN=GG-Projet-{k},{}", groups_ou(&lab))))
            && distinct.len() == recursive.len(),
        "each group once",
    )?;
    check(
        in_chain(&connection, &lab, &[&g147])?.contains(&g147.to_lowercase())
            && is_member(&connection, &g147, &g147)?,
        "147 member of itself",
    )?;
    connection.join();
    Ok(())
}

// --- Queries ------------------------------------------------------------------------------------

fn dns_of(source: &DirectSource, filter: String) -> Result<BTreeSet<String>> {
    Ok(
        labo::items(&source.search_under(filter, None, labo::quiet()))?
            .iter()
            .map(|i| i.dn().to_owned())
            .collect(),
    )
}

#[test]
#[ignore = "lab"]
fn model_queries() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let source = source_on(&lab, DC1);
    let base = source.open().map_err(debug)?;
    let accounts: Vec<Object> = entries(
        source.connection(),
        &base,
        Scope::Subtree,
        &queries::accounts(),
        &model::attributes(),
    )?
    .iter()
    .filter_map(|e| model::object_from_entry(e).ok())
    .filter(|o| o.account().is_some())
    .collect();
    println!("{} accounts read for the model", accounts.len());
    let policy = source.policy().map_err(debug)?;
    let now = reference()?;
    let utc = time::nttime_to_utc(now)?.ok_or("now")?;
    let by = |keep: &dyn Fn(&model::Account) -> bool| -> BTreeSet<String> {
        accounts
            .iter()
            .filter(|o| o.account().is_some_and(keep))
            .map(|o| o.common().dn.clone())
            .collect()
    };
    let filter = |q: Query, kind: Kind| {
        q.filter(kind, State::All, Some((&policy, now)))
            .ok_or("filter")
    };
    check(
        dns_of(&source, filter(Query::Disabled, Kind::All)?)? == by(&|a| !a.active()),
        "disabled, as the model",
    )?;
    check(
        dns_of(&source, filter(Query::PasswordNeverExpires, Kind::All)?)?
            == by(&|a| a.password_never_expires()),
        "password never expires, as the model",
    )?;
    check(
        dns_of(&source, filter(Query::Locked, Kind::All)?)? == by(&|a| a.locked(&policy, utc)),
        "locked, as the model",
    )?;
    let all = labo::items(&source.search_under("(objectClass=*)".into(), None, labo::quiet()))?;
    let conflicts: BTreeSet<String> = all
        .iter()
        .filter(|i| labo::item_name(i).contains("\nCNF:"))
        .map(|i| i.dn().to_owned())
        .collect();
    // The population of the lab: 6 CNF objects.
    check(
        conflicts.len() >= 6,
        &format!("{} conflicts in the lab", conflicts.len()),
    )?;
    check(
        dns_of(&source, filter(Query::Conflicts, Kind::All)?)? == conflicts,
        "conflicts, as the names say",
    )?;
    check(
        dns_of(&source, filter(Query::Administrators, Kind::User)?)?
            .contains(&format!("CN=Administrator,CN=Users,{base}")),
        "administrators: Administrator",
    )?;
    source.close();
    Ok(())
}

// --- Activity on two DCs ---------------------------------------------------------------------

fn last_logon(lab: &Lab, sam: &str, dc: &str) -> Result<i64> {
    let read = labo::ldbsearch(
        dc,
        &lab.base,
        "sub",
        &format!("(sAMAccountName={sam})"),
        &["lastLogon"],
    )?;
    Ok(read
        .first()
        .and_then(|r| number(r, "lastLogon"))
        .unwrap_or(0))
}

fn filter_of(a: &str, b: &str) -> String {
    format!("(|(sAMAccountName={a})(sAMAccountName={b}))")
}

fn survey_from(lab: &Lab, principal: &str, a: &str, b: &str) -> Result<source::Survey> {
    let source = source_on(lab, principal);
    let survey = source
        .survey(&filter_of(a, b), &not_cancelled)
        .map_err(debug);
    source.close();
    survey
}

fn by_name(survey: &source::Survey) -> BTreeMap<String, model::LastActivity> {
    survey
        .accounts()
        .into_iter()
        .filter_map(|(o, a)| Some((o.account()?.sam_account_name.clone(), a)))
        .collect()
}

fn activity_trial(lab: &Lab) -> Result<()> {
    // Two enabled accounts of OU=Labo with a recent password (the seed gives it).
    let now = reference()?;
    let recent = now - 30 * DAY;
    let candidates = labo::ldbsearch(
        "dc1",
        &lab.base,
        "sub",
        &format!(
            "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))\
             (pwdLastSet>={recent})(|(accountExpires=0)(accountExpires>={recent})))"
        ),
        &["sAMAccountName"],
    )?;
    let mut names: Vec<String> = candidates
        .iter()
        .filter(|r| labo::ldif_text(r, "dn").is_some_and(|d| d.contains("OU=Labo,")))
        .filter_map(|r| labo::ldif_text(r, "sAMAccountName"))
        .collect();
    names.sort();
    let [a, b, ..] = names.as_slice() else {
        return Err("no account of trial with a recent password: populate the lab again".into());
    };
    println!("accounts: {a}, {b}");
    let (k1, k2) = (labo::Kdc::new(lab, DC1)?, labo::Kdc::new(lab, DC2)?);
    let logon = |kdc: &labo::Kdc, sam: &str| -> Result<()> {
        let refused = kdc.refusal(
            &format!("{sam}@{}", lab.realm()),
            &labo::lab_password(labo::SEED, sam)?,
        );
        check(refused.is_none(), &format!("{sam} logs on"))
    };
    logon(&k1, a)?;
    logon(&k2, b)?;
    std::thread::sleep(Duration::from_secs(2));
    logon(&k2, a)?;
    logon(&k1, b)?;
    check(
        last_logon(lab, a, "dc2")? > last_logon(lab, a, "dc1")? && last_logon(lab, a, "dc1")? > 0,
        &format!("{a}: lastLogon more recent on dc2"),
    )?;
    check(
        last_logon(lab, b, "dc1")? > last_logon(lab, b, "dc2")? && last_logon(lab, b, "dc2")? > 0,
        &format!("{b}: lastLogon more recent on dc1"),
    )?;
    for principal in [DC1, DC2] {
        let survey = survey_from(lab, principal, a, b)?;
        check(
            survey.failures.is_empty()
                && survey.dcs.first().map(String::as_str) == Some(principal)
                && survey.dcs.iter().cloned().collect::<BTreeSet<_>>()
                    == [DC1.to_owned(), DC2.to_owned()].into(),
            &format!("survey from {principal}, both DCs"),
        )?;
        let found = by_name(&survey);
        for (sam, dc, short) in [(a, DC2, "dc2"), (b, DC1, "dc1")] {
            let activity = found.get(sam.as_str()).ok_or("account")?;
            check(
                activity.source == Some(ActivitySource::LastLogon)
                    && activity.dc.as_deref() == Some(dc)
                    && activity.nttime == last_logon(lab, sam, short)?,
                &format!("{sam}: lastLogon of {dc}"),
            )?;
        }
    }

    println!("dc2 stopped for one survey");
    let a_on_dc2 = last_logon(lab, a, "dc2")?;
    labo::ssh("dc2", "sudo systemctl stop samba-ad-dc\n")?;
    let stopped = (|| -> Result<()> {
        let survey = survey_from(lab, DC1, a, b)?;
        check(
            survey.dcs == [DC1]
                && survey
                    .failures
                    .iter()
                    .map(|f| f.dc.as_str())
                    .collect::<Vec<_>>()
                    == [DC2],
            "dc2 reported, the survey done",
        )?;
        let found = by_name(&survey);
        // Without dc2, the most recent logon of `a` is missing: its first one, seen by dc1.
        let seen = found.get(a.as_str()).ok_or("a")?.nttime;
        check(
            last_logon(lab, a, "dc1")? <= seen && seen < a_on_dc2,
            &format!("{a}: the logon seen by dc1, not the last one"),
        )?;
        check(
            found.get(b.as_str()).ok_or("b")?.nttime == last_logon(lab, b, "dc1")?,
            &format!("{b}: lastLogon of dc1"),
        )
    })();
    labo::ssh("dc2", "sudo systemctl start samba-ad-dc\n")?;
    let seconds = labo::wait(Duration::from_secs(180), "LDAP of dc2 open", || {
        Ok(std::net::TcpStream::connect_timeout(
            &"192.168.1.28:389".parse()?,
            Duration::from_secs(2),
        )
        .is_ok())
    })?;
    println!("  dc2 answers again after {seconds:.0} s");
    stopped?;
    // lastLogon of `a` on dc2 kept while it was stopped (an earlier survey read it).
    check(
        last_logon(lab, a, "dc2")? > 0,
        "dc2 back with its lastLogon",
    )
}

#[test]
#[ignore = "lab"]
fn model_activity_on_two_dcs() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    activity_trial(&lab)
}

// --- Coherence after a write -------------------------------------------------------------------

fn names(source: &DirectSource, dn: &str) -> Result<BTreeMap<String, Item>> {
    Ok(labo::items(&source.contents(dn, false, labo::quiet()))?
        .into_iter()
        .map(|i| (labo::item_name(&i), i))
        .collect())
}

fn description(item: &Item) -> String {
    match item {
        Item::Object(o) => o.common().description.clone(),
        Item::Unreadable { .. } => String::new(),
    }
}

#[allow(clippy::too_many_lines)]
fn coherence_trial(trial: &Trial, lab: &Lab, essais: &str) -> Result<()> {
    let target = trial.fresh_ou(essais, "Cible")?;
    let (one, two) = (
        format!("CN=Coherence Un,{essais}"),
        format!("CN=Coherence Deux,{essais}"),
    );
    for (name, sam) in [
        ("Coherence Un", "coherence.un"),
        ("Coherence Deux", "coherence.deux"),
    ] {
        trial.apply(
            &actions::create_user(
                essais,
                &actions::NewUser {
                    full_name: name.into(),
                    identifier: sam.into(),
                    ..actions::NewUser::default()
                },
            )
            .map_err(debug)?,
        )?;
    }
    let dc2_only = source::connection_to(&lab.profile(false), Some(DC2));
    for dn in [&target, &one, &two] {
        labo::wait(Duration::from_secs(120), "replicated on dc2", || {
            Ok(labo::entry(&dc2_only, dn, &["1.1"], None)?.is_some())
        })?;
    }
    let source = source_on(lab, DC2);
    source.open().map_err(debug)?;
    check(
        source.connection().state().is_some_and(|s| s.dc == DC2),
        "the source reads on dc2",
    )?;
    check(
        names(&source, essais)?.contains_key("Coherence Deux"),
        "seen on dc2",
    )?;

    let read = trial.read(&[&one, &two])?;
    let [un, deux] = read.as_slice() else {
        return Err("accounts".into());
    };
    let text = format!(
        "écrit sur dc1 à {}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    );
    let mut operations = vec![
        Operation::modify(
            &one,
            vec![
                Change::new("description", Vec::new(), vec![text.clone().into_bytes()])
                    .map_err(debug)?,
            ],
            Some(un.read.clone()),
        )
        .map_err(debug)?,
    ];
    operations.extend(
        actions::move_to(std::slice::from_ref(deux), &target)
            .map_err(debug)?
            .operations,
    );
    let report = trial.apply(&Changeset {
        operations,
        remarks: Vec::new(),
    })?;
    check(report.dc == DC1, "written on dc1")?;
    let writes = Arc::new(source::pdc_connection(&trial.profile));
    let again = reread::reread(&writes, &reread::touched(&report)).map_err(debug)?;
    source.note_written(&again, writes.clone());
    // What dc2 knows at this instant (the replication takes 1 to 2 s): told.
    let on_dc2 = labo::entry(&dc2_only, &one, &["description"], None)?;
    let late = on_dc2.is_none_or(|e| labo::text(&e, "description") != text);
    println!(
        "  dc2 right after the write: {}",
        if late {
            "not replicated yet"
        } else {
            "up to date"
        }
    );

    // The sheet goes to the DC of the writes.
    let record = source.record(&one, &[]).map_err(debug)?.ok_or("record")?;
    check(
        description(&record.item) == text,
        "the sheet shows the state written",
    )?;
    check(
        again.dc == DC1
            && again.destination(&two) == Some(format!("CN=Coherence Deux,{target}").as_str()),
        "read again on dc1, the move known",
    )?;
    // Lists read on dc2, corrected: description up to date, Deux gone to Cible.
    let content = names(&source, essais)?;
    check(
        content.get("Coherence Un").map(description).as_deref() == Some(text.as_str())
            && !content.contains_key("Coherence Deux"),
        "the list of the OU corrected",
    )?;
    check(
        names(&source, &target)?.contains_key("Coherence Deux"),
        "the list of Cible corrected",
    )?;
    let found = labo::items(&source.search_under(
        "(sAMAccountName=coherence.*)".into(),
        None,
        labo::quiet(),
    ))?;
    let found: BTreeSet<String> = found.iter().map(|i| i.dn().to_owned()).collect();
    check(
        found == [one.clone(), format!("CN=Coherence Deux,{target}")].into(),
        "the search corrected",
    )?;

    // Once the replication arrived, the readings go back to dc2.
    labo::wait(Duration::from_secs(120), "move replicated on dc2", || {
        Ok(labo::entry(
            &dc2_only,
            &format!("CN=Coherence Deux,{target}"),
            &["1.1"],
            None,
        )?
        .is_some())
    })?;
    labo::wait(Duration::from_secs(30), "back on dc2", || {
        names(&source, essais)?;
        Ok(!source.read_elsewhere(&one))
    })?;
    println!("  back on dc2 for {one}");
    source.close();
    dc2_only.join();
    writes.close();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn model_coherence() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("coherence")?;
    let trial = Trial::new(&lab, &scratch)?;
    let essais = trial.fresh_ou(&format!("OU=Labo,{}", trial.base), "Essais-J2-coherence")?;
    let done = coherence_trial(&trial, &lab, &essais);
    let cleaned = trial.remove_tree(&essais);

    // 1 000 accounts of the domain read again one by one, by bursts (read only).
    let burst = (|| -> Result<()> {
        let mut dns: Vec<String> = entries(
            &trial.connection,
            &format!("OU=Labo,{}", trial.base),
            Scope::Subtree,
            "(objectCategory=person)",
            &["1.1"],
        )?
        .into_iter()
        .map(|e| e.dn)
        .collect();
        dns.truncate(1000);
        check(dns.len() == 1000, "1 000 accounts")?;
        let t = std::time::Instant::now();
        let read = reread::reread(
            &trial.connection,
            &reread::Touched {
                dns: dns.clone(),
                ..reread::Touched::default()
            },
        )
        .map_err(debug)?;
        println!(
            "  1 000 accounts read again by bursts in {:.2} s",
            t.elapsed().as_secs_f64()
        );
        check(
            dns.iter().all(|d| read.object(d).is_some()),
            "every one read",
        )
    })();
    trial.connection.join();
    done.and(cleaned).and(burst)
}

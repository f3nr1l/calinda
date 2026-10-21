// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The local copy against both DCs of LAB.TEST (port of `test_cache_labo.py` and
//! `test_graphe_labo.py`, ADR 0020).
//!
//! - `cache_copy` (JC.2), under `OU=Essais-JC2,OU=Labo`: second opening (the first page of the
//!   20 000 accounts from the copy in less than 200 ms), delta in less than 1 s after a change, a
//!   deletion and an OU renamed elsewhere; the same deletion seen under an ordinary account (list
//!   of the GUIDs, `Deleted Objects` invisible, in a process of its own with the ticket of
//!   `jc2-lecteur`); failover: `samba-ad-dc` stopped on dc2, the DC of the copy, complete
//!   synchronization on dc1 while the old copy stays readable and dated, dc2 started again and
//!   the replication checked; a change of the schema detected (the landmark brought below the
//!   last `uSNChanged` of the schema: the schema of the lab is not changed); searches served by
//!   the copy as the DC answers them; no write founded on the copy; a process killed in the
//!   middle of the writing of a real complete synchronization, the copy left as it was.
//! - `cache_graph` (JC.3), under `OU=Essais-JC3`: a cycle, a chain, a primary group of trial and
//!   an account of the lab; the copy made after these writes answers the administrators (in less
//!   than 100 ms), the recursive members and the groups containing an object as IN_CHAIN on dc1,
//!   and the « Member of » tab as the DC.
//!
//! Everything is removed at the end, even after a failure. The password of `jc2-lecteur` is drawn
//! at random, never shown, and goes to `kinit` on its standard input. See `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use annuaire_codecs::Sid;
use annuaire_codecs::time;
use annuaire_core::cache::{CacheSource, Source};
use annuaire_core::changes::{Change, Changeset, Operation};
use annuaire_core::profile::Profile;
use annuaire_core::queries::{self, Kind, Query, State};
use annuaire_core::search::{self, OID_IN_CHAIN, Value};
use annuaire_core::session::Scope;
use annuaire_core::source::{DirectSource, Item};
use annuaire_core::store::{Landmark, Store};
use annuaire_core::sync::{self, Phase, Reason};
use annuaire_core::{actions, source};
use serde_json::{Value as Json, json};

use labo::{Lab, Result, Trial, check, debug, entries, samba_only};

const DC1: &str = "dc1.lab.test";
const DC2: &str = "dc2.lab.test";
const READER: &str = "jc2-lecteur";

fn profile_on(lab: &Lab, dc: &str) -> Profile {
    let mut profile = Profile::new(lab.domain.clone());
    profile.preferred_dc = Some(dc.into());
    profile
}

fn names(pages: &annuaire_core::cache::Pages) -> Result<BTreeMap<String, Item>> {
    Ok(labo::items(&pages.flux)?
        .into_iter()
        .map(|i| (labo::item_name(&i), i))
        .collect())
}

fn description(item: Option<&Item>) -> String {
    match item {
        Some(Item::Object(o)) => o.common().description.clone(),
        _ => String::new(),
    }
}

fn dns(pages: &annuaire_core::cache::Pages) -> Result<BTreeSet<String>> {
    Ok(labo::items(&pages.flux)?
        .iter()
        .map(|i| i.dn().to_lowercase())
        .collect())
}

fn disabled_user(parent: &str, name: &str) -> Result<Changeset> {
    actions::create_user(
        parent,
        &actions::NewUser {
            full_name: name.into(),
            identifier: name.into(),
            ..actions::NewUser::default()
        },
    )
    .map_err(debug)
}

fn describe(trial: &Trial, dn: &str, text: &str) -> Result<()> {
    let object = trial
        .read_with(&[dn], &["description"])?
        .pop()
        .ok_or("object")?;
    let change = Change::new(
        "description",
        object.values("description"),
        vec![text.as_bytes().to_vec()],
    )
    .map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(dn, vec![change], Some(object.read.clone())).map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    Ok(())
}

fn seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// --- Child: the copy under an ordinary account, or a synchronization to be killed ---------------

/// Run in a process of its own: `reader` (a copy and its content, under the ticket of the
/// ordinary account), or `sync` (one synchronization, killed by the parent while it writes).
#[test]
#[ignore = "lab"]
fn cache_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let asked: Json = serde_json::from_str(&input)?;
    let lab = labo::lab();
    let profile = profile_on(&lab, DC1);
    let path = Path::new(asked["path"].as_str().ok_or("path")?);
    if asked["mode"] == "sync" {
        println!("synchronizing");
        labo::synchronize(&profile, path, false)?;
        println!("RESULT {}", json!({"killed": false}));
        return Ok(());
    }
    let target = asked["target"].as_str().ok_or("target")?;
    let (reason, steps, seconds) = labo::synchronize(&profile, path, true)?;
    let connection = source::connection_to(&profile, Some(DC1));
    let access = sync::deleted_access(&connection).map_err(debug)?;
    connection.join();
    let parent = target.split_once(',').ok_or("parent")?.1;
    let source = labo::cache_source(&profile, path)?;
    let present = labo::items(&source.contents(parent, false, labo::quiet()).flux)?
        .iter()
        .any(|i| i.dn().eq_ignore_ascii_case(target));
    source.close();
    let removed: Vec<String> = steps
        .iter()
        .filter_map(|p| p.changes.as_ref())
        .flat_map(|c| c.objects.values())
        .filter(|(_, after)| after.is_none())
        .filter_map(|(before, _)| before.clone())
        .map(|d| d.to_lowercase())
        .collect();
    println!(
        "RESULT {}",
        json!({"access": access, "present": present, "seconds": seconds,
               "complete": reason.is_some(), "removed": removed})
    );
    Ok(())
}

// --- JC.2 ---------------------------------------------------------------------------------------

fn second_opening(trial: &Trial, lab: &Lab, copy: &Path, essais: &str) -> Result<()> {
    println!("1. second opening and delta");
    let profile = profile_on(lab, DC1);
    let source = labo::cache_source(&profile, copy)?;
    let t = Instant::now();
    let pages = source.search_under(queries::USERS.into(), None, labo::quiet());
    let first = pages.flux.next_page().ok_or("a page")?.map_err(debug)?;
    let first_page = t.elapsed();
    pages.flux.cancel();
    println!(
        "  first page ({} accounts) in {:.0} ms",
        first.len(),
        first_page.as_secs_f64() * 1000.0
    );
    // The criterion (200 ms) holds for an optimized build; a debug build decodes some ten
    // times slower.
    let limit = if cfg!(debug_assertions) { 2000 } else { 200 };
    check(
        pages.copy_date.is_some()
            && first.len() >= 100
            && first_page < Duration::from_millis(limit),
        &format!("the first page from the copy in less than {limit} ms"),
    )?;
    let t = Instant::now();
    let all = labo::items(
        &source
            .search_under(queries::USERS.into(), None, labo::quiet())
            .flux,
    )?;
    println!(
        "  {} accounts read and decoded from the copy in {:.2} s",
        all.len(),
        t.elapsed().as_secs_f64()
    );
    check(all.len() > 20_000, "the 20 000 accounts")?;
    let (_, _, opening) = labo::synchronize(&profile, copy, false)?;
    println!("  first delta (opening): {opening:.2} s");

    let text = format!("modifié ailleurs {}", seconds());
    let (a, b) = (format!("CN=jc2-a,{essais}"), format!("CN=jc2-b,{essais}"));
    let below = format!("OU=Sous,{essais}");
    describe(trial, &a, &text)?;
    trial.apply(&actions::delete(&trial.read(&[&b])?).map_err(debug)?)?;
    trial.apply(&actions::rename(&trial.read_one(&below)?, "Sous2", None, None).map_err(debug)?)?;
    let (reason, steps, delta) = labo::synchronize(&profile, copy, false)?;
    println!("  delta after three changes made elsewhere: {delta:.2} s");
    check(reason.is_none() && delta < 1.0, "a delta, in less than 1 s")?;
    let changes = steps
        .iter()
        .filter(|p| p.phase == Phase::Applied)
        .find_map(|p| p.changes.clone())
        .ok_or("changes")?;
    check(!changes.complete, "not complete")?;
    let source = labo::cache_source(&profile, copy)?;
    let again = source
        .delta_reread(&changes)
        .ok_or("reading of the delta")?;
    let below2 = format!("OU=Sous2,{essais}");
    check(
        description(again.object(&a)) == text,
        "the description changed, read from the delta",
    )?;
    check(
        again.known(&b) && again.object(&b).is_none(),
        "the deletion known",
    )?;
    check(
        again.destination(&format!("CN=jc2-c,{below}"))
            == Some(format!("CN=jc2-c,{below2}").as_str()),
        "the descendant of the OU renamed",
    )?;
    let content = names(&source.contents(essais, false, labo::quiet()))?;
    check(
        description(content.get("jc2-a")) == text
            && !content.contains_key("jc2-b")
            && content.contains_key("Sous2"),
        "the content of the OU from the copy",
    )?;
    check(
        names(&source.contents(&below2, false, labo::quiet()))?
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            == ["jc2-c"],
        "the content of the OU renamed",
    )?;
    let direct =
        DirectSource::with_connection(profile.clone(), source::connection_to(&profile, Some(DC1)));
    direct.open().map_err(debug)?;
    let from_copy =
        dns(&source.search_under("(objectClass=*)".into(), Some(essais), labo::quiet()))?;
    let from_dc: BTreeSet<String> =
        labo::items(&direct.search_under("(objectClass=*)".into(), Some(essais), labo::quiet()))?
            .iter()
            .map(|i| i.dn().to_lowercase())
            .collect();
    check(from_copy == from_dc, "a search under the OU, as the DC")?;
    direct.close();
    source.close();
    // Put back for the next steps.
    trial.apply(&actions::rename(&trial.read_one(&below2)?, "Sous", None, None).map_err(debug)?)?;
    trial.apply(&disabled_user(essais, "jc2-b")?)?;
    Ok(())
}

fn ordinary_account(
    trial: &Trial,
    kdc: &labo::Kdc,
    scratch: &labo::Scratch,
    essais: &str,
) -> Result<()> {
    println!("2. the deletion under an ordinary account");
    let path = scratch.path().join("lecteur.sqlite");
    let target = format!("CN=jc2-b,{essais}");
    let child = || -> Result<Json> {
        let input = json!({"mode": "reader", "path": path.display().to_string(), "target": target})
            .to_string();
        Ok(serde_json::from_str(&labo::child(
            "cache_child",
            &kdc.env("lecteur"),
            &input,
        )?)?)
    };
    let first = child()?;
    println!("  complete copy: {first}");
    check(
        first["access"] == false && first["present"] == true && first["complete"] == true,
        "Deleted Objects invisible, the object in the copy",
    )?;
    trial.apply(&actions::delete(&trial.read(&[&target])?).map_err(debug)?)?;
    let second = child()?;
    println!("  delta and list of the GUIDs: {second}");
    // Only it: the objects whose objectGUID the account cannot read stay (the GUID of the
    // extended DN, as the lines of the copy).
    check(
        second["present"] == false && second["removed"] == json!([target.to_lowercase()]),
        "the deletion found by the GUIDs, and only it",
    )?;
    trial.apply(&disabled_user(essais, "jc2-b")?)?;
    Ok(())
}

fn samba_dc2(action: &str) -> Result<()> {
    labo::ssh("dc2", &format!("sudo systemctl {action} samba-ad-dc\n"))?;
    Ok(())
}

fn failover(trial: &Trial, lab: &Lab, scratch: &labo::Scratch, essais: &str) -> Result<()> {
    println!("3. failover: dc2 stopped");
    let path = scratch.path().join("bascule.sqlite");
    let on_dc2 = profile_on(lab, DC2);
    labo::synchronize(&on_dc2, &path, true)?;
    check(
        Store::open(&path)
            .map_err(debug)?
            .landmark()
            .is_some_and(|l| l.dc == DC2),
        "copy made on dc2",
    )?;
    samba_dc2("stop")?;
    let stopped = (|| -> Result<()> {
        let source = labo::cache_source(&on_dc2, &path)?;
        let pages = source.contents(essais, false, labo::quiet());
        check(
            pages.copy_date.is_some() && names(&pages)?.contains_key("jc2-a"),
            "the old copy readable, dated",
        )?;
        let t = Instant::now();
        let (reason, _, _) = labo::synchronize(&on_dc2, &path, true)?;
        println!(
            "  failover dc2 → dc1 in {:.1} s: {reason:?}",
            t.elapsed().as_secs_f64()
        );
        check(
            reason == Some(Reason::OtherDc),
            "complete synchronization: other DC",
        )?;
        check(
            Store::open(&path)
                .map_err(debug)?
                .landmark()
                .is_some_and(|l| l.dc == DC1),
            "the copy now on dc1",
        )?;
        check(
            names(&source.contents(essais, false, labo::quiet()))?.contains_key("jc2-a"),
            "readable after the failover",
        )?;
        source.close();
        Ok(())
    })();
    samba_dc2("start")?;
    stopped?;
    // dc2 answers again, and the replication goes both ways.
    let text = format!("après redémarrage {}", seconds());
    describe(trial, &format!("CN=jc2-a,{essais}"), &text)?;
    let dc2 = source::connection_to(&lab.profile(false), Some(DC2));
    let waited = labo::wait(
        Duration::from_secs(240),
        "change of dc1 arrived on dc2",
        || {
            Ok(
                labo::entry(&dc2, &format!("CN=jc2-a,{essais}"), &["description"], None)
                    .ok()
                    .flatten()
                    .is_some_and(|e| labo::text(&e, "description") == text),
            )
        },
    );
    dc2.join();
    println!("  replicated on dc2 after {:.0} s", waited?);
    Ok(())
}

fn landmark_of(path: &Path) -> Result<Landmark> {
    let base = rusqlite::Connection::open(path)?;
    let text: String = base.query_row("SELECT valeur FROM etat WHERE cle = 'repere'", [], |r| {
        r.get(0)
    })?;
    Landmark::from_json(&text).ok_or_else(|| "landmark".into())
}

fn set_landmark(path: &Path, landmark: &Landmark) -> Result<()> {
    let base = rusqlite::Connection::open(path)?;
    base.execute(
        "UPDATE etat SET valeur = ? WHERE cle = 'repere'",
        [landmark.to_json()],
    )?;
    Ok(())
}

fn schema_change(lab: &Lab, copy: &Path) -> Result<()> {
    println!("4. a change of the schema detected");
    let profile = profile_on(lab, DC1);
    let connection = source::connection_to(&profile, Some(DC1));
    let state = sync::read_dc_state(&connection).map_err(debug)?;
    let highest = entries(
        &connection,
        &state.schema,
        Scope::Subtree,
        "(objectClass=*)",
        &["uSNChanged"],
    )?
    .iter()
    .filter_map(|e| labo::text(e, "uSNChanged").parse::<i64>().ok())
    .max()
    .ok_or("uSNChanged")?;
    connection.join();
    let mut landmark = landmark_of(copy)?;
    check(landmark.dc == DC1, "copy of dc1")?;
    landmark.usn = highest - 1;
    set_landmark(copy, &landmark)?;
    let (reason, _, seconds) = labo::synchronize(&profile, copy, false)?;
    println!("  {reason:?} in {seconds:.1} s");
    check(
        reason == Some(Reason::Schema),
        "complete synchronization: schema",
    )
}

fn searches(lab: &Lab, copy: &Path) -> Result<()> {
    println!("5. searches served by the copy, as the DC");
    let profile = profile_on(lab, DC1);
    labo::synchronize(&profile, copy, false)?;
    let source = labo::cache_source(&profile, copy)?;
    let direct =
        DirectSource::with_connection(profile.clone(), source::connection_to(&profile, Some(DC1)));
    direct.open().map_err(debug)?;
    let policy = direct.policy().map_err(debug)?;
    let now = time::unix_to_nttime(i64::try_from(seconds())?)?;
    let filters = vec![
        queries::search_filter("dupont", Kind::All, State::All),
        queries::search_filter("mar", Kind::User, State::Enabled),
        queries::search_filter("", Kind::Group, State::All),
        queries::search_filter("", Kind::Computer, State::Disabled),
        queries::search_filter("", Kind::Ou, State::All),
        queries::disabled(),
        queries::password_never_expires(),
        queries::CONFLICTS.to_owned(),
        queries::without_replicated_logon(),
        queries::locked(&policy, now),
    ];
    for filter in filters {
        let t = Instant::now();
        let pages = source.search_under(filter.clone(), None, labo::quiet());
        let from_copy = dns(&pages)?;
        let copy_time = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let from_dc: BTreeSet<String> =
            labo::items(&direct.search_under(filter.clone(), None, labo::quiet()))?
                .iter()
                .map(|i| i.dn().to_lowercase())
                .collect();
        println!(
            "  {:6} objects, copy {copy_time:.2} s, DC {:.2} s: {}",
            from_dc.len(),
            t.elapsed().as_secs_f64(),
            filter.chars().take(70).collect::<String>()
        );
        check(
            pages.copy_date.is_some() && from_copy == from_dc,
            "same result as the DC",
        )?;
    }
    source.close();
    direct.close();
    Ok(())
}

fn no_write_from_the_copy(trial: &Trial, lab: &Lab, copy: &Path, essais: &str) -> Result<()> {
    println!("6. no write founded on the copy");
    let base = rusqlite::Connection::open(copy)?;
    base.execute("UPDATE objets SET uac = 512 WHERE sam = 'jc2-a'", [])?;
    drop(base);
    let source = labo::cache_source(&profile_on(lab, DC1), copy)?;
    let pages = source.contents(essais, false, labo::quiet());
    let read = names(&pages)?;
    let active = match read.get("jc2-a") {
        Some(Item::Object(o)) => o
            .account()
            .is_some_and(annuaire_core::model::Account::active),
        _ => false,
    };
    source.close();
    check(
        pages.copy_date.is_some() && active,
        "the copy says jc2-a enabled (value forced)",
    )?;
    let objects = trial.read(&[&format!("CN=jc2-a,{essais}")])?;
    check(
        actions::enable(&objects, false)
            .map_err(debug)?
            .operations
            .is_empty(),
        "read on the DC of the writes: already disabled",
    )?;
    let enabling = actions::enable(&objects, true).map_err(debug)?;
    check(
        matches!(enabling.operations.as_slice(), [Operation::Modify { changes, .. }]
            if changes.first().is_some_and(|c| c.removed == [b"514".to_vec()])),
        "the enabling starts from 514",
    )
}

/// Rows of the objects and state of the copy, as a fingerprint.
fn fingerprint(path: &Path) -> Result<(usize, u64)> {
    use std::hash::{Hash, Hasher};
    let base = rusqlite::Connection::open(path)?;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut statement =
        base.prepare("SELECT guid, dn, description, uac, usn FROM objets ORDER BY guid")?;
    let mut rows = statement.query([])?;
    let mut n = 0;
    while let Some(row) = rows.next()? {
        let guid: Vec<u8> = row.get(0)?;
        let dn: String = row.get(1)?;
        let description: Option<String> = row.get(2)?;
        let uac: Option<i64> = row.get(3)?;
        let usn: Option<i64> = row.get(4)?;
        (guid, dn, description, uac, usn).hash(&mut hasher);
        n += 1;
    }
    let mut statement = base.prepare("SELECT cle, valeur FROM etat ORDER BY cle")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let (k, v): (String, String) = (row.get(0)?, row.get(1)?);
        (k, v).hash(&mut hasher);
    }
    Ok((n, hasher.finish()))
}

fn killed_in_the_middle(lab: &Lab, copy: &Path, scratch: &labo::Scratch) -> Result<()> {
    println!("7. a process killed in the middle of a complete synchronization");
    let path = scratch.path().join("atomicite.sqlite");
    std::fs::copy(copy, &path)?;
    let mut landmark = landmark_of(&path)?;
    "ancien-dc.lab.test".clone_into(&mut landmark.dc);
    set_landmark(&path, &landmark)?;
    let before = fingerprint(&path)?;
    let wal = path.with_extension("sqlite-wal");
    let wal_size = || std::fs::metadata(&wal).map_or(0, |m| m.len());
    let start = wal_size();
    let mut child = Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "cache_child",
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("ANNUAIRE_LABO_ENFANT", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    {
        use std::io::Write as _;
        let mut stdin = child.stdin.take().ok_or("stdin")?;
        stdin.write_all(
            json!({"mode": "sync", "path": path.display().to_string()})
                .to_string()
                .as_bytes(),
        )?;
    }
    // The complete copy is written in one transaction: kill the child once it has written
    // 2 MB of it in the WAL.
    let t = Instant::now();
    let mut killed = false;
    while t.elapsed() < Duration::from_secs(300) {
        if child.try_wait()?.is_some() {
            break;
        }
        if wal_size() > start + 2_000_000 {
            child.kill()?;
            killed = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let status = child.wait()?;
    println!(
        "  child: {status}, WAL {} bytes, after {:.1} s",
        wal_size(),
        t.elapsed().as_secs_f64()
    );
    check(killed, "killed while it was writing")?;
    check(
        fingerprint(&path)? == before,
        "the copy read again is the state before",
    )?;
    let base = rusqlite::Connection::open(&path)?;
    let integrity: String = base.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    drop(base);
    check(integrity == "ok", "integrity_check")?;
    let (reason, _, seconds) = labo::synchronize(&profile_on(lab, DC1), &path, false)?;
    println!(
        "  resumed: {reason:?}, {seconds:.1} s, {} objects before",
        before.0
    );
    check(
        reason.is_some() && landmark_of(&path)?.dc == DC1,
        "the next synchronization makes the copy whole again",
    )
}

fn copy_trial(
    trial: &Trial,
    lab: &Lab,
    scratch: &labo::Scratch,
    essais: &str,
    kdc: &labo::Kdc,
) -> Result<()> {
    let below = trial.fresh_ou(essais, "Sous")?;
    for (name, parent) in [
        ("jc2-a", essais),
        ("jc2-b", essais),
        ("jc2-c", below.as_str()),
    ] {
        trial.apply(&disabled_user(parent, name)?)?;
    }
    trial.apply(
        &actions::create_group(
            essais,
            "jc2-g",
            "",
            annuaire_codecs::uac::Scope::Global,
            true,
            "",
        )
        .map_err(debug)?,
    )?;
    let secret = labo::password(28);
    trial.apply(
        &actions::create_user(
            essais,
            &actions::NewUser {
                full_name: READER.into(),
                identifier: READER.into(),
                password: Some(secret.clone()),
                enable: true,
                ..actions::NewUser::default()
            },
        )
        .map_err(debug)?,
    )?;
    let refused = kdc.kinit_into(&format!("{READER}@{}", lab.realm()), &secret, "lecteur");
    drop(secret);
    check(refused.is_none(), "ticket of the ordinary account")?;
    let copy = scratch.path().join("lab.test.sqlite");
    let (reason, _, seconds) = labo::synchronize(&profile_on(lab, DC1), &copy, true)?;
    println!(
        "first opening, complete copy: {seconds:.2} s, {} bytes",
        std::fs::metadata(&copy)?.len()
    );
    check(reason == Some(Reason::First), "complete copy")?;
    second_opening(trial, lab, &copy, essais)?;
    ordinary_account(trial, kdc, scratch, essais)?;
    failover(trial, lab, scratch, essais)?;
    schema_change(lab, &copy)?;
    searches(lab, &copy)?;
    no_write_from_the_copy(trial, lab, &copy, essais)?;
    killed_in_the_middle(lab, &copy, scratch)
}

#[test]
#[ignore = "lab"]
fn cache_copy() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("copie")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, DC1)?;
    let essais = trial.fresh_ou(&format!("OU=Labo,{}", trial.base), "Essais-JC2")?;
    let done = copy_trial(&trial, &lab, &scratch, &essais, &kdc);
    kdc.destroy("lecteur");
    let cleaned = trial.remove_tree(&essais);
    trial.connection.join();
    done.and(cleaned)
}

// --- JC.3: the graph of the groups ------------------------------------------------------------

fn member_of_lab(trial: &Trial) -> Result<String> {
    let filter = search::and(&[
        queries::accounts(),
        search::eq(
            "memberOf",
            Value::Text(&format!(
                "CN=GG-Projet-006,OU=Sécurité,OU=Groupes,OU=Labo,{}",
                trial.base
            )),
        )?,
    ])?;
    Ok(entries(
        &trial.connection,
        &trial.base,
        Scope::Subtree,
        &filter,
        &["1.1"],
    )?
    .into_iter()
    .next()
    .ok_or("a member of GG-Projet-006")?
    .dn)
}

fn add_member(trial: &Trial, group: &str, member: &str) -> Result<()> {
    let read = trial.read(&[group])?.pop().ok_or("group")?;
    let change =
        Change::new("member", Vec::new(), vec![member.as_bytes().to_vec()]).map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![Operation::modify(group, vec![change], Some(read.read)).map_err(debug)?],
        remarks: Vec::new(),
    })?;
    Ok(())
}

/// The OU of trial removed: the accounts first (a primary group is not deleted while an account
/// names it), then the rest.
fn remove_graph(trial: &Trial, essais: &str) -> Result<()> {
    if !trial.exists(essais)? {
        return Ok(());
    }
    let users: Vec<String> = entries(
        &trial.connection,
        essais,
        Scope::Subtree,
        "(objectClass=user)",
        &["1.1"],
    )?
    .into_iter()
    .map(|e| e.dn)
    .collect();
    for user in &users {
        trial.apply(&actions::delete(&trial.read(&[user])?).map_err(debug)?)?;
    }
    trial.remove_tree(essais)
}

fn compare(
    copy: &CacheSource,
    direct: &DirectSource,
    name: &str,
    filter: &str,
) -> Result<BTreeSet<String>> {
    let t = Instant::now();
    let pages = copy.search_under(filter.to_owned(), None, labo::quiet());
    let local = dns(&pages)?;
    let copy_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    let remote: BTreeSet<String> =
        labo::items(&direct.search_under(filter.to_owned(), None, labo::quiet()))?
            .iter()
            .map(|i| i.dn().to_lowercase())
            .collect();
    println!(
        "  {name}: {} objects, copy {copy_ms:.1} ms, IN_CHAIN on the DC {:.2} s",
        local.len(),
        t.elapsed().as_secs_f64()
    );
    check(
        pages.copy_date.is_some() && local == remote,
        &format!("{name}: the copy as the DC"),
    )?;
    Ok(local)
}

#[allow(clippy::too_many_lines)]
fn graph_trial(trial: &Trial, lab: &Lab, scratch: &labo::Scratch, essais: &str) -> Result<()> {
    let dn = |name: &str| format!("CN={name},{essais}");
    for name in ["jc3-a", "jc3-b", "jc3-c", "jc3-d"] {
        trial.apply(
            &actions::create_group(
                essais,
                name,
                "",
                annuaire_codecs::uac::Scope::Global,
                true,
                "",
            )
            .map_err(debug)?,
        )?;
    }
    for name in ["jc3-u", "jc3-v"] {
        trial.apply(&disabled_user(essais, name)?)?;
    }
    for (group, member) in [
        ("jc3-a", "jc3-b"),
        ("jc3-b", "jc3-c"),
        ("jc3-c", "jc3-a"), // cycle
        ("jc3-d", "jc3-a"),
        ("jc3-c", "jc3-u"),
        ("jc3-b", "jc3-v"),
    ] {
        add_member(trial, &dn(group), &dn(member))?;
    }
    let labo_member = member_of_lab(trial)?;
    add_member(trial, &dn("jc3-d"), &labo_member)?;
    // jc3-c becomes the primary group of jc3-u.
    let sid: Sid = trial.sid(&dn("jc3-c"))?;
    let u = trial
        .read_with(&[&dn("jc3-u")], &["primaryGroupID"])?
        .pop()
        .ok_or("jc3-u")?;
    let change = Change::new(
        "primaryGroupID",
        u.values("primaryGroupID"),
        vec![sid.rid().ok_or("RID")?.to_string().into_bytes()],
    )
    .map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(&u.dn, vec![change], Some(u.read.clone())).map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;

    let profile = profile_on(lab, DC1);
    let path = scratch.path().join("graphe.sqlite");
    let (reason, _, seconds) = labo::synchronize(&profile, &path, true)?;
    println!("complete copy made after the writes: {seconds:.2} s");
    check(reason.is_some(), "complete copy")?;
    let copy = labo::cache_source(&profile, &path)?;
    let direct =
        DirectSource::with_connection(profile.clone(), source::connection_to(&profile, Some(DC1)));
    check(
        direct.open().map_err(debug)? == lab.base,
        "direct reading on dc1",
    )?;

    println!("1. administrators");
    let administrator = format!("CN=Administrator,CN=Users,{}", lab.base);
    let domain_admins = format!("CN=Domain Admins,CN=Users,{}", lab.base);
    let all = compare(&copy, &direct, "administrators", &queries::administrators())?;
    check(
        all.contains(&administrator.to_lowercase()) && all.contains(&domain_admins.to_lowercase()),
        "Administrator and Domain Admins",
    )?;
    let users = Query::Administrators
        .filter(Kind::User, State::All, None)
        .ok_or("filter")?;
    compare(&copy, &direct, "administrators (users)", &users)?;
    let mut durations = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        dns(&copy.search_under(queries::administrators(), None, labo::quiet()))?;
        durations.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    println!("  five passes on the copy: {durations:.1?} ms");
    check(
        durations.iter().all(|&d| d < 100.0),
        "less than 100 ms (criterion JC)",
    )?;

    println!("2. recursive members");
    let in_chain =
        |attribute: &str, dn: &str| search::rule(attribute, OID_IN_CHAIN, Value::Text(dn));
    for (name, group) in [
        ("Domain Admins", domain_admins.clone()),
        (
            "GU-Tous-Salariés",
            format!(
                "CN=GU-Tous-Salariés,OU=Sécurité,OU=Groupes,OU=Labo,{}",
                lab.base
            ),
        ),
        ("jc3-a (cycle)", dn("jc3-a")),
        ("jc3-d", dn("jc3-d")),
    ] {
        let members = compare(
            &copy,
            &direct,
            &format!("members of {name}"),
            &in_chain("memberOf", &group)?,
        )?;
        if name.starts_with("GU-") {
            check(members.len() == 5000, "5 000 members")?;
        }
        if name.starts_with("jc3-a") {
            // a is a member of itself; u is there only by its primary group.
            check(
                members.contains(&dn("jc3-a").to_lowercase())
                    && members.contains(&dn("jc3-v").to_lowercase())
                    && !members.contains(&dn("jc3-u").to_lowercase()),
                "the cycle, not the primary group",
            )?;
        }
    }

    println!("3. groups containing an object");
    for (name, object) in [
        ("jc3-v", dn("jc3-v")),
        ("account of the lab", labo_member.clone()),
    ] {
        let filter = search::and(&[
            "(objectClass=group)".to_owned(),
            in_chain("member", &object)?,
        ])?;
        compare(
            &copy,
            &direct,
            &format!("groups containing {name}"),
            &filter,
        )?;
    }

    println!("4. « Member of »");
    let lower = |v: &[String]| v.iter().map(|x| x.to_lowercase()).collect::<BTreeSet<_>>();
    for object in [dn("jc3-u"), dn("jc3-a"), labo_member.clone(), administrator] {
        let t = Instant::now();
        let local = copy.groups(&object).map_err(debug)?;
        let copy_ms = t.elapsed().as_secs_f64() * 1000.0;
        let t = Instant::now();
        let remote = direct.groups(&object).map_err(debug)?;
        println!(
            "  {object}: {} groups, copy {copy_ms:.1} ms, DC {:.2} s",
            local.recursive.as_ref().map_or(0, Vec::len),
            t.elapsed().as_secs_f64()
        );
        check(
            lower(&local.direct) == lower(&remote.direct)
                && local.primary == remote.primary
                && local.recursive == remote.recursive,
            "the groups as the DC",
        )?;
    }
    let u = copy.groups(&dn("jc3-u")).map_err(debug)?;
    let recursive = u.recursive.clone().unwrap_or_default();
    check(
        u.primary.as_deref() == Some(dn("jc3-c").as_str())
            && !u.direct.contains(&dn("jc3-c"))
            && ["jc3-a", "jc3-b", "jc3-c", "jc3-d"]
                .iter()
                .all(|g| recursive.contains(&dn(g))),
        "jc3-u: primary group jc3-c, out of member",
    )?;
    copy.close();
    direct.close();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn cache_graph() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("graphe")?;
    let trial = Trial::new(&lab, &scratch)?;
    let essais = format!("OU=Essais-JC3,{}", trial.base);
    remove_graph(&trial, &essais)?;
    let essais = trial.fresh_ou(&trial.base, "Essais-JC3")?;
    let done = graph_trial(&trial, &lab, &scratch, &essais);
    let cleaned = remove_graph(&trial, &essais).and_then(|()| {
        let dc2 = source::connection_to(&lab.profile(false), Some(DC2));
        let gone = labo::wait(Duration::from_secs(120), "OU gone from dc2", || {
            Ok(labo::entry(&dc2, &essais, &["1.1"], None)?.is_none())
        });
        dc2.join();
        println!("  {essais} gone from dc2 after {:.1} s", gone?);
        Ok(())
    });
    trial.connection.join();
    done.and(cleaned)
}

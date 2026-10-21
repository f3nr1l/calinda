// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Writes on the accounts against the lab (port of `test_actions_labo.py`,
//! `test_attributs_labo.py` and `test_verrouillage_labo.py`, ADR 0020).
//!
//! - `accounts_actions` (LAB.TEST and WIN.TEST), under `OU=Essais-J2.6,OU=Labo`: a user
//!   enabled in one request, its password neither in the preview nor in the journal, and
//!   granted by the KDC of the PDC emulator; change required then reset, the inverse that leaves
//!   the secret alone; a group, three accounts disabled and enabled again, unlock with nothing
//!   to do, renaming and its undo; an OU protected against deletion (the deletion cancelled, the
//!   neighbour deleted); a move of two accounts, its undo, their deletion.
//! - `accounts_attributes` (LAB.TEST), under `OU=Essais-J4A`: the syntaxes of the real schema
//!   (what the editor of the application builds its lines on), then one `Modify` of several
//!   syntaxes as the sheet builds it (`writer::prepare_modification` for the single-valued
//!   attributes, the values removed and added for a multi-valued one), read again by
//!   `ldbsearch` in `sam.ldb` of dc1, then of dc2 after the replication; the undo brings it back
//!   on both. A multi-valued change leaves a value added elsewhere meanwhile. A value the DC
//!   refuses writes nothing.
//! - `accounts_lockout` (LAB.TEST): a lockout threshold set for the time of the trial
//!   (`samba-tool domain passwordsettings set`, and the values read before put back whatever
//!   happens), an account locked by wrong passwords asked of dc1 alone, seen by the query
//!   « locked » read on each DC (the replication of the lockout measured), unlocked by a
//!   changeset on the PDC emulator.
//!
//! The passwords are drawn at random, never shown, given to `kinit` on its standard input.
//! See `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::time;
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_core::changes::{self, Change, Changeset, Issue, Operation};
use annuaire_core::messages::{Catalog as _, English};
use annuaire_core::model::Object;
use annuaire_core::queries;
use annuaire_core::schema::{self, Syntax};
use annuaire_core::source::{self, DirectSource};
use annuaire_core::{actions, writer};

use labo::{Lab, Result, Trial, check, debug, samba_only};

fn user(
    full_name: &str,
    sam: &str,
    upn: &str,
    secret: Option<&str>,
    change: bool,
) -> actions::NewUser {
    actions::NewUser {
        full_name: full_name.into(),
        identifier: sam.into(),
        upn: upn.into(),
        password: secret.map(str::to_owned),
        change_at_next_logon: change,
        enable: secret.is_some(),
        ..actions::NewUser::default()
    }
}

fn values(object: &actions::ReadObject, attribute: &str) -> Vec<Vec<u8>> {
    object.values(attribute)
}

// --- Actions -------------------------------------------------------------------------------------

#[allow(clippy::too_many_lines)]
fn actions_trial(trial: &Trial, lab: &Lab, essais: &str, kdc: &labo::Kdc) -> Result<()> {
    let realm = lab.realm();
    println!("1. a user enabled in one request");
    let secret = labo::password(24);
    let cs = actions::create_user(
        essais,
        &actions::NewUser {
            given_name: "Alice".into(),
            surname: "Essai".into(),
            ..user(
                "Alice Essai",
                "alice.essai",
                &format!("alice.essai@{}", lab.domain),
                Some(&secret),
                false,
            )
        },
    )
    .map_err(debug)?;
    let preview = changes::preview(&cs, &English).map_err(debug)?;
    check(
        !preview.contains(&secret)
            && preview.contains(&English.text(&annuaire_core::messages::Msg::Masked)),
        "password masked in the preview",
    )?;
    let report = trial.apply(&cs)?;
    let alice = trial.read_one(&format!("CN=Alice Essai,{essais}"))?;
    check(
        values(&alice, "userAccountControl") == [b"512".to_vec()],
        "enabled (512)",
    )?;
    // The initial password is set (KDC of the PDC emulator, where the core wrote).
    check(
        kdc.granted(&format!("alice.essai@{realm}"), &secret),
        "ticket granted with the initial password",
    )?;
    let journal = std::fs::read_to_string(trial.journal_path())?;
    check(
        !journal.contains(&secret) && journal.contains("masque"),
        "neither the journal nor the report kept the password",
    )?;
    check(
        writer::read_journal(&trial.journal)
            .last()
            .is_some_and(|r| r.id == report.id),
        "report journaled",
    )?;

    println!("2. change required, then reset");
    let secret = labo::password(24);
    trial.apply(
        &actions::create_user(
            essais,
            &user("Bruno Essai", "bruno.essai", "", Some(&secret), true),
        )
        .map_err(debug)?,
    )?;
    let dn = format!("CN=Bruno Essai,{essais}");
    let bruno = trial.read_one(&dn)?;
    check(
        values(&bruno, "pwdLastSet") == [b"0".to_vec()]
            && values(&bruno, "userAccountControl") == [b"512".to_vec()],
        "change required at next logon",
    )?;
    let refusal = kdc.refusal(&format!("bruno.essai@{realm}"), &secret);
    check(
        refusal
            .as_deref()
            .is_some_and(|r| r.to_lowercase().contains("expired")),
        "kinit: password expired",
    )?;
    // The refused request touched the object on the PDC (uSNChanged): read again first.
    let bruno = trial.read_one(&dn)?;
    let new = labo::password(24);
    let reset = trial.apply(&actions::reset_password(&bruno, &new, false).map_err(debug)?)?;
    check(
        values(&trial.read_one(&dn)?, "pwdLastSet") != [b"0".to_vec()],
        "no longer to change",
    )?;
    // The inverse does not touch the secret; it puts back « change required ».
    let inverse = trial.inverse(&reset)?;
    check(
        inverse.remarks.iter().any(|r| r.contains("secret")),
        "remark: the secret is not restored",
    )?;
    trial.apply(&inverse)?;
    check(
        values(&trial.read_one(&dn)?, "pwdLastSet") == [b"0".to_vec()],
        "change required again",
    )?;
    trial.apply(&actions::reset_password(&trial.read_one(&dn)?, &new, false).map_err(debug)?)?;
    // After the preview only: a logon changes the version of the object. The KDC of the PDC
    // emulator: dc2 has the new password 2 to 5 s later only.
    check(
        kdc.granted(&format!("bruno.essai@{realm}"), &new),
        "ticket with the new password",
    )?;

    println!("3. group, enabling, unlocking, renaming");
    trial.apply(
        &actions::create_group(essais, "GG Essai", "", GroupScope::Global, true, "J2.6")
            .map_err(debug)?,
    )?;
    check(
        trial
            .read_one(&format!("CN=GG Essai,{essais}"))?
            .text("sAMAccountName")
            == "GG Essai",
        "group named after its name",
    )?;
    let mut accounts = Vec::new();
    for i in 0..3 {
        trial.apply(
            &actions::create_user(
                essais,
                &user(
                    &format!("Lot {i}"),
                    &format!("lot.{i}"),
                    "",
                    Some(&labo::password(24)),
                    true,
                ),
            )
            .map_err(debug)?,
        )?;
        accounts.push(format!("CN=Lot {i},{essais}"));
    }
    let names: Vec<&str> = accounts.iter().map(String::as_str).collect();
    let disabling = trial.apply(&actions::enable(&trial.read(&names)?, false).map_err(debug)?)?;
    check(
        disabling.changeset.operations.len() == 3,
        "three operations",
    )?;
    let uac = |trial: &Trial| -> Result<Vec<Vec<Vec<u8>>>> {
        Ok(trial
            .read(&names)?
            .iter()
            .map(|o| values(o, "userAccountControl"))
            .collect())
    };
    check(
        uac(trial)?.iter().all(|v| v == &[b"514".to_vec()]),
        "disabled (514)",
    )?;
    check(
        actions::enable(&trial.read(&names)?, false)
            .map_err(debug)?
            .operations
            .is_empty(),
        "already disabled: nothing to do",
    )?;
    trial.undo(&disabling)?;
    check(
        uac(trial)?.iter().all(|v| v == &[b"512".to_vec()]),
        "enabled again by the undo",
    )?;
    // Never locked: nothing to write (a real lockout is `accounts_lockout`).
    check(
        actions::unlock(&trial.read(&names[..1])?)
            .map_err(debug)?
            .operations
            .is_empty(),
        "unlock: nothing to do",
    )?;
    let lot = trial.read_one(names[1])?;
    let renaming = trial
        .apply(&actions::rename(&lot, "Lot Un", Some("Lot Un"), Some("lot.un")).map_err(debug)?)?;
    check(
        trial
            .read_one(&format!("CN=Lot Un,{essais}"))?
            .text("sAMAccountName")
            == "lot.un",
        "renamed, identifier too",
    )?;
    trial.undo(&renaming)?;
    check(
        trial.read_one(names[1])?.text("sAMAccountName") == "lot.1",
        "renaming undone",
    )?;

    println!("4. an OU protected against deletion");
    let protected = trial.fresh_ou(essais, "Protégée")?;
    let neighbour = trial.fresh_ou(essais, "Voisine")?;
    let read = trial.descriptors(&[&protected, essais])?;
    let [ou, parent] = read.as_slice() else {
        return Err("OU and parent".into());
    };
    let protection = actions::protect_ou(ou, parent).map_err(debug)?;
    check(protection.operations.len() == 2, "the OU and its parent")?;
    trial.apply(&protection)?;
    let read = trial.descriptors(&[&protected, essais])?;
    let [ou, parent] = read.as_slice() else {
        return Err("OU and parent".into());
    };
    check(
        actions::is_protected(ou).map_err(debug)?
            && actions::protect_ou(ou, parent)
                .map_err(debug)?
                .operations
                .is_empty(),
        "protected, nothing more to do",
    )?;
    let refused = trial.outcome(
        &actions::delete(&trial.read(&[&protected])?).map_err(debug)?,
        None,
        None,
    )?;
    check(
        refused.report.issue == Issue::Cancelled && trial.exists(&protected)?,
        "deletion cancelled by the DC",
    )?;
    // The neighbour stays deletable: the refusal on the parent only hinders the protected OU.
    trial.apply(&actions::delete(&trial.read(&[&neighbour])?).map_err(debug)?)?;
    trial.apply(&actions::unprotect_ou(ou).map_err(debug)?)?;
    check(
        !actions::is_protected(&trial.descriptors(&[&protected])?.pop().ok_or("OU")?)
            .map_err(debug)?,
        "protection removed",
    )?;

    println!("5. move in batch, undo, deletion");
    let target = trial.fresh_ou(essais, "Désactivés")?;
    let mut moved = Vec::new();
    for i in 0..2 {
        let name = format!("Dépl {i}");
        trial.apply(
            &actions::create_user(essais, &user(&name, &format!("depl.{i}"), "", None, false))
                .map_err(debug)?,
        )?;
        moved.push(format!("CN={name},{essais}"));
    }
    let names: Vec<&str> = moved.iter().map(String::as_str).collect();
    let moving = trial.apply(&actions::move_to(&trial.read(&names)?, &target).map_err(debug)?)?;
    let there: Vec<String> = (0..2).map(|i| format!("CN=Dépl {i},{target}")).collect();
    check(
        trial
            .read(&there.iter().map(String::as_str).collect::<Vec<_>>())?
            .len()
            == 2,
        "moved",
    )?;
    check(
        actions::move_to(&trial.read(&[essais])?, &target).is_err(),
        "a move under itself refused",
    )?;
    trial.undo(&moving)?;
    check(trial.read(&names)?.len() == 2, "back by the undo")?;
    trial.apply(&actions::delete(&trial.read(&names)?).map_err(debug)?)?;
    check(trial.read(&names)?.is_empty(), "deleted")
}

#[test]
#[ignore = "lab"]
fn accounts_actions() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("actions")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, &lab.pdc_name())?;
    let labo_ou = format!("OU=Labo,{}", trial.base);
    let essais = trial.fresh_ou(&labo_ou, "Essais-J2.6")?;
    let done = actions_trial(&trial, &lab, &essais, &kdc);
    let cleaned = trial.remove_tree(&essais);
    trial.connection.join();
    done.and(cleaned)
}

// --- Attributes ----------------------------------------------------------------------------------

const CHECKED: [&str; 8] = [
    "displayName",
    "otherTelephone",
    "userAccountControl",
    "accountExpires",
    "showInAdvancedViewOnly",
    "thumbnailPhoto",
    "manager",
    "msTSExpireDate",
];

type State = BTreeMap<String, Vec<Vec<u8>>>;

/// The attributes checked of the object, read in `sam.ldb` of a DC; values sorted.
fn state(dc: &str, dn: &str) -> Result<State> {
    let read = labo::ldbsearch(dc, dn, "base", "(objectClass=*)", &CHECKED)?;
    let record = read.into_iter().next().unwrap_or_default();
    Ok(CHECKED
        .iter()
        .map(|a| {
            let mut v = record.get(&a.to_lowercase()).cloned().unwrap_or_default();
            v.sort();
            (a.to_lowercase(), v)
        })
        .collect())
}

fn wait_state(dc: &str, dn: &str, wanted: &State) -> Result<f64> {
    labo::wait(Duration::from_secs(120), &format!("state on {dc}"), || {
        Ok(&state(dc, dn)? == wanted)
    })
}

/// The `Modify` of the sheet: the single-valued attributes read again on the DC as wanted,
/// a multi-valued one by the values removed and added; the version of the reading.
fn modify(
    trial: &Trial,
    dn: &str,
    wanted: changes::AttributeMap,
    explicit: Vec<Change>,
) -> Result<Changeset> {
    let (mut changes, mut read) =
        match writer::prepare_modification(&trial.connection, dn, wanted).map_err(debug)? {
            Some(Operation::Modify { changes, read, .. }) => (changes, read),
            _ => (Vec::new(), None),
        };
    if !explicit.is_empty() {
        changes.extend(explicit);
        if read.is_none() {
            read = writer::read_version(&trial.connection, dn).map_err(debug)?;
        }
    }
    Ok(Changeset {
        operations: vec![Operation::modify(dn, changes, read).map_err(debug)?],
        remarks: Vec::new(),
    })
}

/// Allowed for the class `user` (the line of an empty attribute is shown, editable).
fn allowed(schema: &schema::Schema, class: &str, attribute: &str) -> bool {
    schema.ancestry(class).iter().any(|c| {
        c.optional
            .iter()
            .chain(&c.mandatory)
            .any(|a| a.eq_ignore_ascii_case(attribute))
            || c.auxiliaries.iter().any(|aux| {
                schema.ancestry(aux).iter().any(|x| {
                    x.optional
                        .iter()
                        .chain(&x.mandatory)
                        .any(|a| a.eq_ignore_ascii_case(attribute))
                })
            })
    })
}

#[allow(clippy::too_many_lines)]
fn attributes_trial(trial: &Trial, essais: &str) -> Result<()> {
    let util = format!("CN=essai-j4a-util,{essais}");
    let chef = format!("CN=essai-j4a-chef,{essais}");
    for name in ["essai-j4a-util", "essai-j4a-chef"] {
        trial.apply(
            &actions::create_user(essais, &user(name, name, "", None, false)).map_err(debug)?,
        )?;
    }
    println!("1. the real schema");
    let schema = schema::read_schema(&trial.connection).map_err(debug)?;
    let entry = trial
        .entry(&util, &["*", "nTSecurityDescriptor"])?
        .ok_or("account")?;
    check(
        entry.values("unicodePwd").is_empty()
            && entry.values("supplementalCredentials").is_empty()
            && changes::is_sensitive("unicodePwd")
            && changes::is_sensitive("supplementalCredentials"),
        "no secret read, the secrets known as such",
    )?;
    for (name, syntax, editable) in [
        ("objectsid", Syntax::Sid, false),
        ("objectguid", Syntax::Octets, false),
        ("whencreated", Syntax::GeneralizedTime, false),
        ("memberof", Syntax::Dn, false),
        ("useraccountcontrol", Syntax::Integer, true),
        ("accountexpires", Syntax::LargeInteger, true),
        ("othertelephone", Syntax::Unicode, true),
        ("manager", Syntax::Dn, true),
        ("ntsecuritydescriptor", Syntax::Descriptor, false),
    ] {
        let d = schema.attribute(name).ok_or("attribute")?;
        // What the editor of the application builds on: a syntax it reads back, not written
        // by the DC alone, not computed, not a back link.
        let writable = schema::EDITABLE_SYNTAXES.contains(&d.syntax)
            && !d.system
            && !d.constructed
            && !d.back_link();
        check(
            d.syntax == syntax && writable == editable,
            &format!("{name}: {syntax:?}, editable {editable}"),
        )?;
    }
    let sid = schema.attribute("objectsid").ok_or("objectSid")?;
    check(
        schema::edit_text(sid, entry.values("objectSid").first().ok_or("objectSid")?)
            .starts_with("S-1-5-21-"),
        "objectSid as text",
    )?;
    check(
        changes::descriptor_text(
            entry.values("nTSecurityDescriptor").first().ok_or("SD")?,
            &English,
        )
        .map_err(debug)?
        .starts_with("O:"),
        "descriptor in SDDL",
    )?;
    let expires = labo::text(&entry, "accountExpires").parse::<i64>()?;
    check(
        expires == 0 || time::is_never(expires).unwrap_or(false),
        "accountExpires: never",
    )?;
    check(
        entry.values("otherTelephone").is_empty() && allowed(&schema, "user", "otherTelephone"),
        "otherTelephone empty, allowed by the class",
    )?;
    check(
        schema.attributes.values().any(|d| d.constructed),
        "constructed attributes, read only",
    )?;
    let sam = schema.attribute("samaccountname").ok_or("sAMAccountName")?;
    check(sam.upper.is_some(), "sAMAccountName bounded by the schema")?;
    check(
        integer::check_bounds(
            1 << 33,
            schema::width(schema.attribute("useraccountcontrol").ok_or("uac")?),
        )
        .is_err()
            && integer::check_bounds(1 << 33, Width::Bits64).is_ok(),
        "32 bits for userAccountControl",
    )?;

    println!("2. several syntaxes in one Modify, then undone");
    let before = [state("dc1", &util)?, state("dc2", &util)?];
    wait_state("dc2", &util, &before[0])?; // accounts of trial replicated before starting
    let uac: u32 = trial.read_one(&util)?.text("userAccountControl").parse()?;
    let end = time::utc_to_nttime(time::decode_generalized_time("20271231230000.0Z")?)?;
    let photo = vec![0xff, 0xd8, 0xff, 0xe0];
    let wanted: changes::AttributeMap = vec![
        (
            "displayName".into(),
            vec!["Essai J4A, éditeur".as_bytes().to_vec()],
        ),
        (
            "userAccountControl".into(),
            vec![(uac | 0x10000).to_string().into_bytes()],
        ),
        ("accountExpires".into(), vec![end.to_string().into_bytes()]),
        ("showInAdvancedViewOnly".into(), vec![b"TRUE".to_vec()]),
        ("thumbnailPhoto".into(), vec![photo.clone()]),
        ("manager".into(), vec![chef.clone().into_bytes()]),
        ("msTSExpireDate".into(), vec![b"20271231230000.0Z".to_vec()]),
    ];
    let phones = Change::new(
        "otherTelephone",
        Vec::new(),
        vec![b"01 02 03 04 05".to_vec(), b"+33 6 00 00 00 00".to_vec()],
    )
    .map_err(debug)?;
    let cs = modify(trial, &util, wanted, vec![phones])?;
    check(
        matches!(
            cs.operations.as_slice(),
            [Operation::Modify { read: Some(_), .. }]
        ),
        "one Modify, with the version read",
    )?;
    let report = trial.apply(&cs)?;
    let mut expected: State = BTreeMap::new();
    for (a, v) in [
        (
            "displayname",
            vec!["Essai J4A, éditeur".as_bytes().to_vec()],
        ),
        (
            "othertelephone",
            vec![b"+33 6 00 00 00 00".to_vec(), b"01 02 03 04 05".to_vec()],
        ),
        (
            "useraccountcontrol",
            vec![(uac | 0x10000).to_string().into_bytes()],
        ),
        ("accountexpires", vec![end.to_string().into_bytes()]),
        ("showinadvancedviewonly", vec![b"TRUE".to_vec()]),
        ("thumbnailphoto", vec![photo]),
        ("manager", vec![chef.into_bytes()]),
        ("mstsexpiredate", vec![b"20271231230000.0Z".to_vec()]),
    ] {
        expected.insert(a.to_owned(), v);
    }
    check(
        state("dc1", &util)? == expected,
        "sam.ldb of dc1 as written",
    )?;
    println!("  dc2 after {:.1} s", wait_state("dc2", &util, &expected)?);
    trial.undo(&report)?;
    check(state("dc1", &util)? == before[0], "undone on dc1")?;
    println!(
        "  undo on dc2 after {:.1} s",
        wait_state("dc2", &util, &before[0])?
    );

    println!("3. a multi-valued change leaves a value added elsewhere");
    trial.apply(&modify(
        trial,
        &util,
        Vec::new(),
        vec![
            Change::new(
                "otherTelephone",
                Vec::new(),
                vec![b"01".to_vec(), b"02".to_vec()],
            )
            .map_err(debug)?,
        ],
    )?)?;
    let first = trial
        .entry(&util, &["otherTelephone"])?
        .and_then(|e| e.values("otherTelephone").first().cloned())
        .ok_or("a telephone")?;
    // Another administrator adds a number between the display and the preview.
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(
                &util,
                vec![
                    Change::new("otherTelephone", Vec::new(), vec![b"07".to_vec()])
                        .map_err(debug)?,
                ],
                None,
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    let change = Change::new(
        "otherTelephone",
        vec![first.clone()],
        vec![b"09 99".to_vec()],
    )
    .map_err(debug)?;
    let cs = modify(trial, &util, Vec::new(), vec![change])?;
    let before = state("dc1", &util)?;
    let report = trial.apply(&cs)?;
    let mut left: Vec<Vec<u8>> = before["othertelephone"]
        .iter()
        .filter(|v| **v != first)
        .cloned()
        .collect();
    left.push(b"09 99".to_vec());
    left.sort();
    let after = state("dc1", &util)?;
    check(
        after["othertelephone"] == left && after["othertelephone"].contains(&b"07".to_vec()),
        "only these two values changed",
    )?;
    trial.undo(&report)?;
    check(state("dc1", &util)? == before, "the list exactly back")?;
    println!("  dc2 after {:.1} s", wait_state("dc2", &util, &before)?);

    println!("4. a value the DC refuses: nothing written");
    let before = trial.read_one(&util)?.values("pwdLastSet");
    let version = writer::read_version(&trial.connection, &util).map_err(debug)?;
    let refused = trial.outcome(
        &Changeset {
            operations: vec![
                Operation::modify(
                    &util,
                    vec![
                        Change::new("pwdLastSet", before.clone(), vec![b"123".to_vec()])
                            .map_err(debug)?,
                    ],
                    version,
                )
                .map_err(debug)?,
            ],
            remarks: Vec::new(),
        },
        None,
        None,
    )?;
    println!(
        "  {:?}: {:?}",
        refused.report.issue,
        refused.report.error.map(|e| e.message)
    );
    check(
        refused.report.issue != Issue::Applied
            && trial.read_one(&util)?.values("pwdLastSet") == before,
        "pwdLastSet: only 0 and -1, refused by the DC",
    )
}

#[test]
#[ignore = "lab"]
fn accounts_attributes() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("attributs")?;
    let trial = Trial::new(&lab, &scratch)?;
    let essais = trial.fresh_ou(&trial.base, "Essais-J4A")?;
    let done = attributes_trial(&trial, &essais);
    let cleaned = trial.remove_tree(&essais).and_then(|()| {
        for dc in ["dc1", "dc2"] {
            labo::wait(
                Duration::from_secs(120),
                &format!("nothing left on {dc}"),
                || Ok(labo::ldbsearch(dc, &essais, "base", "(objectClass=*)", &["dn"])?.is_empty()),
            )?;
            let line = labo::showrepl(dc)?;
            check(line.contains("ALL GOOD"), &format!("{dc}: {line}"))?;
        }
        Ok(())
    });
    trial.connection.join();
    done.and(cleaned)
}

// --- Lockout -------------------------------------------------------------------------------------

const LOCKED: &str = "verrou.essai";
const THRESHOLD: usize = 3;

const SETTINGS: [(&str, &str); 3] = [
    (
        "Account lockout threshold (attempts)",
        "--account-lockout-threshold",
    ),
    (
        "Account lockout duration (mins)",
        "--account-lockout-duration",
    ),
    (
        "Reset account lockout after (mins)",
        "--reset-account-lockout-after",
    ),
];

/// Threshold, duration and reset of the lockout, as `samba-tool` shows them.
fn policy() -> Result<Vec<String>> {
    let out = labo::ssh("dc1", "sudo samba-tool domain passwordsettings show\n")?;
    SETTINGS
        .iter()
        .map(|(label, _)| {
            out.lines()
                .find_map(|l| l.strip_prefix(&format!("{label}: ")))
                .map(|v| v.trim().to_owned())
                .ok_or_else(|| format!("{label} not shown by samba-tool").into())
        })
        .collect()
}

fn set_policy(values: &[String]) -> Result<()> {
    let options: Vec<String> = SETTINGS
        .iter()
        .zip(values)
        .map(|((_, option), v)| format!("{option}={v}"))
        .collect();
    labo::ssh(
        "dc1",
        &format!(
            "sudo samba-tool domain passwordsettings set {}\n",
            options.join(" ")
        ),
    )?;
    Ok(())
}

fn lockout_time(dc: &str, base: &str) -> Result<i64> {
    let read = labo::ldbsearch(
        dc,
        base,
        "sub",
        &format!("(sAMAccountName={LOCKED})"),
        &["lockoutTime"],
    )?;
    Ok(read
        .first()
        .and_then(|r| labo::ldif_text(r, "lockoutTime"))
        .and_then(|t| t.parse().ok())
        .unwrap_or(0))
}

fn now() -> Result<(i64, time::UtcTime)> {
    let seconds = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let nt = time::unix_to_nttime(seconds)?;
    Ok((nt, time::nttime_to_utc(nt)?.ok_or("now")?))
}

/// The query « locked » read on `dc` alone, by the source of the interface: policy read on
/// this DC, present instant; the verdict of the model on the account read there agrees.
fn locked_on(lab: &Lab, dc: &str, account: &str) -> Result<bool> {
    let profile = lab.profile(false);
    let source =
        DirectSource::with_connection(profile.clone(), source::connection_to(&profile, Some(dc)));
    check(
        source.open().map_err(debug)? == lab.base,
        &format!("source on {dc}"),
    )?;
    let policy = source.policy().map_err(debug)?;
    let (nt, utc) = now()?;
    let found: Vec<String> =
        labo::items(&source.search_under(queries::locked(&policy, nt), None, labo::quiet()))?
            .iter()
            .map(|i| i.dn().to_owned())
            .collect();
    let inside = found.iter().any(|d| d.eq_ignore_ascii_case(account));
    let record = source
        .record(account, &[])
        .map_err(debug)?
        .ok_or("record")?;
    let verdict = match &record.item {
        source::Item::Object(object) => match object.as_ref() {
            Object::User { account: a, .. } => a.locked(&policy, utc),
            _ => return Err("not a user".into()),
        },
        source::Item::Unreadable { .. } => return Err("unreadable".into()),
    };
    source.close();
    check(
        verdict == inside,
        &format!("{dc}: the model agrees with the query"),
    )?;
    Ok(inside)
}

fn lockout_trial(trial: &Trial, lab: &Lab, essais: &str, kdc: &labo::Kdc) -> Result<()> {
    let account = format!("CN=Verrou Essai,{essais}");
    let secret = labo::password(24);
    trial.apply(
        &actions::create_user(
            essais,
            &user(
                "Verrou Essai",
                LOCKED,
                &format!("{LOCKED}@{}", lab.domain),
                Some(&secret),
                false,
            ),
        )
        .map_err(debug)?,
    )?;
    let principal = format!("{LOCKED}@{}", lab.realm());
    check(kdc.granted(&principal, &secret), "the account works")?;
    check(!locked_on(lab, "dc1.lab.test", &account)?, "not locked")?;
    for _ in 0..THRESHOLD {
        check(
            !kdc.granted(&principal, &labo::password(24)),
            "wrong password refused",
        )?;
    }
    check(
        lockout_time("dc1", &trial.base)? > 0,
        "lockoutTime set on dc1",
    )?;
    check(
        !kdc.granted(&principal, &secret),
        "the right password no longer enough",
    )?;
    check(
        locked_on(lab, "dc1.lab.test", &account)?,
        "locked, read on dc1",
    )?;
    let seconds = labo::wait(Duration::from_secs(120), "lockout replicated", || {
        Ok(lockout_time("dc2", &trial.base)? > 0)
    })?;
    println!("  lockoutTime replicated on dc2 in {seconds:.1} s");
    check(
        locked_on(lab, "dc2.lab.test", &account)?,
        "locked, read on dc2",
    )?;

    let cs = actions::unlock(&trial.read(&[&account])?).map_err(debug)?;
    check(cs.operations.len() == 1, "one operation")?;
    trial.apply(&cs)?;
    check(lockout_time("dc1", &trial.base)? == 0, "unlocked on dc1")?;
    check(
        !locked_on(lab, "dc1.lab.test", &account)?,
        "no longer in the query on dc1",
    )?;
    let seconds = labo::wait(Duration::from_secs(120), "unlock replicated", || {
        Ok(lockout_time("dc2", &trial.base)? == 0)
    })?;
    println!("  unlock replicated on dc2 in {seconds:.1} s");
    check(
        !locked_on(lab, "dc2.lab.test", &account)?,
        "no longer in the query on dc2",
    )?;
    check(kdc.granted(&principal, &secret), "the account works again")?;
    check(
        actions::unlock(&trial.read(&[&account])?)
            .map_err(debug)?
            .operations
            .is_empty(),
        "nothing more to unlock",
    )
}

#[test]
#[ignore = "lab"]
fn accounts_lockout() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("verrou")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, &lab.pdc_name())?;
    let essais = trial.fresh_ou(&format!("OU=Labo,{}", trial.base), "Essais-J2-verrou")?;
    let before = policy()?;
    println!("policy read: {before:?}");
    let done = set_policy(&["3".into(), "30".into(), "30".into()])
        .and_then(|()| {
            check(
                policy()? == ["3", "30", "30"],
                "threshold set for the trial",
            )
        })
        .and_then(|()| lockout_trial(&trial, &lab, &essais, &kdc));
    // The values read before, put back whatever happened, and seen.
    let restored = set_policy(&before).and_then(|()| {
        let after = policy()?;
        println!("policy put back: {after:?}");
        check(after == before, "policy of the domain as before")
    });
    let cleaned = trial.remove_tree(&essais);
    trial.connection.join();
    done.and(restored).and(cleaned)
}

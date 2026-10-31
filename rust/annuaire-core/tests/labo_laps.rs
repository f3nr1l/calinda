// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Windows LAPS against the lab (J9.4, ADR 0025): the station of the lab (`ANNUAIRE-POSTE1`)
//! joined to the domain aimed at, under a LAPS policy that backs up its password in clear in
//! the directory (`labo/README.md`, « LAPS »).
//!
//! - the password read by Calinda is the one of `Get-LapsADPassword` (WIN.TEST) — compared by
//!   fingerprint, never shown — with its account and its expiration date;
//! - an ordinary account of the domain reads the computer: the expiration date is there, the
//!   password is not, said « refused »;
//! - « Expire now » (a journaled changeset, whose journal holds no password), then the policy
//!   processed by the station (`Invoke-LapsPolicyProcessing`): a new password, the one of
//!   `Get-LapsADPassword`, and a later expiration date;
//! - the inverse of « Expire now » gives the date of before (on a computer of the trial, under
//!   `OU=Essais-J94,OU=Labo`).
//!
//! `ANNUAIRE_LABO_LAPS_ORACLE=0` (LAB.TEST) skips the comparison with `Get-LapsADPassword`,
//! which needs a domain the RSAT of a Windows machine can reach.

#![allow(clippy::indexing_slicing)]

mod labo;

use annuaire_core::changes::{Change, Changeset, Operation};
use annuaire_core::computers::{self, NewComputer};
use annuaire_core::laps::{self, Schema, State};
use annuaire_core::{actions, writer};

use labo::{Kdc, Result, Trial, check, debug};

const STATION: &str = "ANNUAIRE-POSTE1";
const OU: &str = "Essais-J94";
const READER: &str = "j94.lecteur";

fn fingerprint(value: &str) -> Result<String> {
    let digest = openssl::sha::sha256(value.as_bytes());
    Ok(digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..12]
        .to_owned())
}

/// What `Get-LapsADPassword` gives (WIN.TEST, from the DC): account, fingerprint, expiration.
fn oracle() -> Result<std::collections::BTreeMap<String, String>> {
    let output = labo::poste(
        &format!(
            "$p = Get-LapsADPassword -Identity {STATION} -AsPlainText\n\
             $h = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash(\
             [Text.Encoding]::UTF8.GetBytes([string]$p.Password))).Replace('-','').ToLower().Substring(0,12)\n\
             \"ACCOUNT=$($p.Account)\"; \"FINGERPRINT=$h\"; \"SOURCE=$($p.Source)\"\n\
             \"EXPIRATION=$((Get-ADComputer {STATION} -Properties msLAPS-PasswordExpirationTime).'msLAPS-PasswordExpirationTime')\""
        ),
        &["--cible", "wdc"],
    )?;
    Ok(labo::lines(&output))
}

fn station(trial: &Trial) -> Result<String> {
    labo::entries(
        &trial.connection,
        &trial.base,
        annuaire_core::session::Scope::Subtree,
        &format!("(sAMAccountName={STATION}$)"),
        &["1.1"],
    )?
    .into_iter()
    .next()
    .map(|e| e.dn)
    .ok_or_else(|| format!("{STATION} is not in {}", trial.base).into())
}

/// (state, account, fingerprint, expiration) of Windows LAPS read by Calinda.
fn calinda(
    connection: &annuaire_core::Connection,
    dn: &str,
) -> Result<(State, String, String, i64)> {
    let reading = laps::read(connection, dn)
        .map_err(debug)?
        .ok_or("computer absent")?;
    let windows = reading
        .get(Schema::Windows)
        .ok_or("not managed by Windows LAPS")?;
    let print = match &windows.password {
        Some(p) => fingerprint(p.reveal())?,
        None => String::new(),
    };
    Ok((
        windows.state.clone(),
        windows.account.clone().unwrap_or_default(),
        print,
        windows.expiration.unwrap_or(0),
    ))
}

#[test]
#[ignore = "lab: needs the station joined and its LAPS policy"]
fn laps_in_clear() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j94")?;
    let trial = Trial::new(&lab, &scratch)?;
    let with_oracle = std::env::var("ANNUAIRE_LABO_LAPS_ORACLE").as_deref() != Ok("0");
    let dn = station(&trial)?;

    // Read by Calinda, compared with Get-LapsADPassword.
    let (state, account, before, expiration) = calinda(&trial.connection, &dn)?;
    check(
        state == State::Readable,
        &format!("password readable: {state:?}"),
    )?;
    println!("  {dn}: account {account}, fingerprint {before}, expiration {expiration}");
    if with_oracle {
        let expected = oracle()?;
        check(
            expected.get("FINGERPRINT") == Some(&before),
            &format!(
                "fingerprint of Get-LapsADPassword: {:?}",
                expected.get("FINGERPRINT")
            ),
        )?;
        check(
            expected.get("ACCOUNT") == Some(&account),
            "account of Get-LapsADPassword",
        )?;
        check(
            expected.get("EXPIRATION") == Some(&expiration.to_string()),
            "expiration of Get-ADComputer",
        )?;
        println!("  same password, account and expiration as Get-LapsADPassword");
    }

    // An ordinary account: the date, not the password.
    let parent = format!("OU=Labo,{}", trial.base);
    let ou = trial.fresh_ou(&parent, OU)?;
    let secret = labo::password(24);
    trial.apply(
        &actions::create_user(
            &ou,
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
    let kdc = Kdc::new(&lab, &trial.dc)?;
    let refused = kdc.kinit_into(&format!("{READER}@{}", lab.realm()), &secret, "lecteur");
    check(refused.is_none(), "ticket of the ordinary account")?;
    let result = labo::child("laps_child", &kdc.env("lecteur"), &dn)?;
    check(
        result.starts_with("Refused"),
        &format!("ordinary account: {result}"),
    )?;
    println!("  ordinary account: {result}");

    // Expire now, then the station processes its policy.
    let reading = laps::read(&trial.connection, &dn)
        .map_err(debug)?
        .ok_or("absent")?;
    let report =
        trial.apply(&laps::expire_now(&reading, Schema::Windows, laps::now()).map_err(debug)?)?;
    let journal = std::fs::read_to_string(trial.journal_path())?;
    check(journal.contains(laps::EXPIRATION), "expiration journaled")?;
    check(
        !journal.contains(&format!("\"{}\"", laps::PASSWORD)),
        "no password in the journal",
    )?;
    let processed = labo::poste(
        "Invoke-LapsPolicyProcessing; Start-Sleep 5\n\
         Get-WinEvent -LogName 'Microsoft-Windows-LAPS/Operational' -MaxEvents 8 | \
         ForEach-Object { \"EVT$($_.Id)=1\" }",
        &["--voie", "agent"],
    )?;
    println!(
        "  expired by Calinda ({}), policy processed by the station (events {:?})",
        report.id,
        labo::lines(&processed).keys().collect::<Vec<_>>()
    );
    let (state, _, after, new_expiration) = calinda(&trial.connection, &dn)?;
    check(state == State::Readable, "readable after the rotation")?;
    check(after != before, "a new password after « Expire now »")?;
    check(
        new_expiration > laps::now(),
        "expiration moved into the future",
    )?;
    if with_oracle {
        check(
            oracle()?.get("FINGERPRINT") == Some(&after),
            "new password: the one of Get-LapsADPassword",
        )?;
    }
    println!("  rotated: fingerprint {after}, expiration {new_expiration}");

    // The inverse of « Expire now », on a computer of the trial.
    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let created = trial.apply(
        &computers::create_computer(
            &ou,
            &NewComputer {
                name: "J94PC".into(),
                ..NewComputer::default()
            },
            &rule,
        )
        .map_err(debug)?,
    )?;
    let pc = created
        .changeset
        .operations
        .first()
        .map(|o| o.dn().to_owned())
        .ok_or("dn")?;
    let read = writer::read_version(&trial.connection, &pc)
        .map_err(debug)?
        .ok_or("absent")?;
    let date = b"134100000000000000".to_vec();
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(
                &pc,
                vec![Change::new(laps::EXPIRATION, Vec::new(), vec![date.clone()]).map_err(debug)?],
                Some(read),
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    let reading = laps::read(&trial.connection, &pc)
        .map_err(debug)?
        .ok_or("absent")?;
    check(
        reading.get(Schema::Windows).map(|m| &m.state) == Some(&State::Refused),
        "a date without a password: said refused",
    )?;
    let expired =
        trial.apply(&laps::expire_now(&reading, Schema::Windows, laps::now()).map_err(debug)?)?;
    trial.undo(&expired)?;
    let back = laps::read(&trial.connection, &pc)
        .map_err(debug)?
        .ok_or("absent")?;
    check(
        back.get(Schema::Windows).and_then(|m| m.expiration) == Some(134_100_000_000_000_000),
        "undo: the date of before",
    )?;
    println!("  undo of « Expire now »: the date of before");
    trial.remove_tree(&ou)?;
    Ok(())
}

/// Run by `laps_in_clear` under the ticket of the ordinary account: the state read.
#[test]
#[ignore = "lab"]
fn laps_child() -> Result<()> {
    let Some(dn) = labo::child_input() else {
        return Ok(());
    };
    let lab = labo::lab();
    let connection = annuaire_core::source::pdc_connection(&lab.profile(false));
    let reading = laps::read(&connection, dn.trim())
        .map_err(debug)?
        .ok_or("absent")?;
    let windows = reading.get(Schema::Windows).ok_or("no expiration read")?;
    println!(
        "RESULT {:?} (expiration read: {})",
        windows.state,
        windows.expiration.is_some()
    );
    Ok(())
}

/// The confidentiality of `msLAPS-Password` on both DCs, without a station: a value of the trial
/// written by the administrator on a computer of the trial, read back by Calinda, refused to an
/// ordinary account (the expiration date stays readable).
#[test]
#[ignore = "lab"]
fn laps_confidential() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j94c")?;
    let trial = Trial::new(&lab, &scratch)?;
    let parent = format!("OU=Labo,{}", trial.base);
    let ou = trial.fresh_ou(&parent, OU)?;
    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let created = trial.apply(
        &computers::create_computer(
            &ou,
            &NewComputer {
                name: "J94PC".into(),
                ..NewComputer::default()
            },
            &rule,
        )
        .map_err(debug)?,
    )?;
    let pc = created
        .changeset
        .operations
        .first()
        .map(|o| o.dn().to_owned())
        .ok_or("dn")?;
    // A value of the trial in the JSON of Windows LAPS, drawn at random, never shown.
    let value = labo::password(20);
    let json = format!(r#"{{"n":"Administrateur","t":"1dd4a3b2c1d0e0f","p":"{value}"}}"#);
    let read = writer::read_version(&trial.connection, &pc)
        .map_err(debug)?
        .ok_or("absent")?;
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(
                &pc,
                vec![
                    Change::new(laps::PASSWORD, Vec::new(), vec![json.into_bytes()])
                        .map_err(debug)?,
                    Change::new(
                        laps::EXPIRATION,
                        Vec::new(),
                        vec![b"134100000000000000".to_vec()],
                    )
                    .map_err(debug)?,
                ],
                Some(read),
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    let journal = std::fs::read_to_string(trial.journal_path())?;
    check(!journal.contains(&value), "the value never in the journal")?;
    let (state, account, print, _) = calinda(&trial.connection, &pc)?;
    check(
        state == State::Readable && account == "Administrateur" && print == fingerprint(&value)?,
        "read back by the administrator",
    )?;
    let secret = labo::password(24);
    trial.apply(
        &actions::create_user(
            &ou,
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
    let kdc = Kdc::new(&lab, &trial.dc)?;
    check(
        kdc.kinit_into(&format!("{READER}@{}", lab.realm()), &secret, "lecteur")
            .is_none(),
        "ticket of the ordinary account",
    )?;
    let result = labo::child("laps_child", &kdc.env("lecteur"), &pc)?;
    println!(
        "  {}: administrator reads it, ordinary account: {result}",
        lab.domain
    );
    check(
        result.starts_with("Refused (expiration read: true)"),
        "ordinary account refused",
    )?;
    trial.remove_tree(&ou)?;
    Ok(())
}

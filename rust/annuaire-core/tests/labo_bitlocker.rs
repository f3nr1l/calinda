// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! BitLocker recovery passwords against the lab (J9.5, ADR 0025): the station of the lab
//! (`ANNUAIRE-POSTE1`, TPM 2.0) has its system volume encrypted, and its recovery password
//! backed up in the domain it is joined to by `Backup-BitLockerKeyProtector`
//! (`labo/README.md`, « BitLocker »).
//!
//! - the recovery passwords read by Calinda under the computer are those of the station
//!   (`Get-BitLockerVolume`, from the station itself): same identifier, same password, compared
//!   by fingerprint, never shown;
//! - found again by the first eight characters of the identifier, as the Windows tool;
//! - an ordinary account reads the object but not the password: said refused.

#![allow(clippy::indexing_slicing)]

mod labo;

use annuaire_core::actions;
use annuaire_core::bitlocker;

use labo::{Kdc, Result, Trial, check, debug};

const STATION: &str = "ANNUAIRE-POSTE1";
const OU: &str = "Essais-J95";
const READER: &str = "j95.lecteur";

fn fingerprint(value: &str) -> String {
    openssl::sha::sha256(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()[..12]
        .to_owned()
}

#[test]
#[ignore = "lab: needs the station joined, its volume encrypted and the key backed up"]
fn recovery_passwords() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j95")?;
    let trial = Trial::new(&lab, &scratch)?;
    let station = labo::entries(
        &trial.connection,
        &trial.base,
        annuaire_core::session::Scope::Subtree,
        &format!("(sAMAccountName={STATION}$)"),
        &["1.1"],
    )?
    .into_iter()
    .next()
    .map(|e| e.dn)
    .ok_or("station absent")?;

    // What the station has: identifier and fingerprint of each recovery password.
    let output = labo::poste(
        "(Get-BitLockerVolume -MountPoint C:).KeyProtector | \
         Where-Object KeyProtectorType -eq 'RecoveryPassword' | ForEach-Object {\n\
         $h = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash(\
         [Text.Encoding]::UTF8.GetBytes($_.RecoveryPassword))).Replace('-','').ToLower().Substring(0,12)\n\
         \"KEY_$($_.KeyProtectorId.Trim('{}').ToUpper().Replace('-','_'))=$h\" }",
        &["--voie", "agent"],
    )?;
    let station_keys: Vec<(String, String)> = labo::lines(&output)
        .into_iter()
        .filter_map(|(k, v)| k.strip_prefix("KEY_").map(|id| (id.replace('_', "-"), v)))
        .collect();
    check(
        !station_keys.is_empty(),
        "a recovery password on the station",
    )?;

    // Read by Calinda under the computer.
    let found = bitlocker::under(&trial.connection, &station).map_err(debug)?;
    println!("  {} recovery object(s) under {station}", found.len());
    let mut matched = None;
    for (id, print) in &station_keys {
        let Some(recovery) = found.iter().find(|r| r.id.as_deref() == Some(id.as_str())) else {
            continue;
        };
        let password = recovery.password.as_ref().ok_or("password not read")?;
        check(
            fingerprint(password.reveal()) == *print,
            &format!("same recovery password for {id}"),
        )?;
        matched = Some(id.clone());
        println!(
            "  {id}: backed up {}, same password as the station",
            recovery.date
        );
    }
    let id = matched.ok_or("no key of the station found in the directory")?;

    // The search by the first eight characters.
    let prefix = bitlocker::prefix(&id).ok_or("prefix")?;
    let searched = bitlocker::search(&trial.connection, &trial.base, &prefix).map_err(debug)?;
    check(
        searched.iter().any(|r| {
            r.id.as_deref() == Some(id.as_str()) && r.computer.eq_ignore_ascii_case(&station)
        }),
        "found again by the first eight characters",
    )?;
    println!("  found by « {prefix} »: {} result(s)", searched.len());

    // An ordinary account.
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
    check(
        kdc.kinit_into(&format!("{READER}@{}", lab.realm()), &secret, "lecteur")
            .is_none(),
        "ticket of the ordinary account",
    )?;
    let result = labo::child("recovery_child", &kdc.env("lecteur"), &station)?;
    println!("  ordinary account: {result}");
    check(
        result.ends_with("read=0"),
        "ordinary account: no recovery password read",
    )?;
    trial.remove_tree(&ou)?;
    Ok(())
}

/// Run by `recovery_passwords` under the ticket of the ordinary account.
#[test]
#[ignore = "lab"]
fn recovery_child() -> Result<()> {
    let Some(dn) = labo::child_input() else {
        return Ok(());
    };
    let lab = labo::lab();
    let connection = annuaire_core::source::pdc_connection(&lab.profile(false));
    let found = bitlocker::under(&connection, dn.trim()).map_err(debug)?;
    let read = found.iter().filter(|r| r.password.is_some()).count();
    println!("RESULT seen={} read={read}", found.len());
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The GPOs of the core read again and changed by the GPMC, and applied by Windows (port of
//! `test_gpo_gpmc_labo.py`, `test_gpo_registre_labo.py` and of the parts of
//! `test_preferences_labo.py` with the Windows station, ADR 0020). On LAB.TEST, the GPMC is the
//! one of the Windows station joined to the lab (RSAT, `poste.py --domaine`, LAB\Administrator,
//! on the PDC emulator where the core writes too); with `ANNUAIRE_LABO_DOMAINE=win.test`, the
//! one of the Windows DC itself, and the SYSVOL is replicated by DFS-R.
//!
//! - `gpmc_gpo_of_the_core`: a GPO created and linked by the core, seen by `Get-GPO`,
//!   `IsAclConsistent()` and `Get-GPOReport`; the GPMC sets a value in it and links it; the core
//!   reads again versions and links, filters it (ACL of the folder, file of the GPMC included),
//!   the GPMC deems it consistent; the core deletes it and the GPMC no longer finds it.
//! - `gpmc_gpo_of_the_gpmc`: a GPO created by the GPMC, read, linked, filtered, backed up,
//!   deleted and restored by the core; the GPMC finds it again with its value, its filtering and
//!   consistent ACLs.
//! - `gpmc_registry`: both `Registry.pol` written by the core (each type, a value disabled, a
//!   key purged), read again value by value by the GPMC, changed by it, read again by the core
//!   without loss, then applied by Windows (the station and the session of its user on
//!   LAB.TEST, the DC itself on WIN.TEST) and removed by the deletion of the GPO.
//! - `gpmc_preferences`: four families of preferences with targeting written by the core and
//!   described by the GPMC; on LAB.TEST, applied by the station (drive, shortcut, targeted
//!   values); a GPO of the GPMC changed by the core without loss; every element turned into a
//!   deletion and removed by the station.
//!
//! After each one, on Samba: no GPO of trial left in `samba-tool gpo listall`, the ACLs of the
//! SYSVOL as `sysvolcheck` wants them (`labo/verifier_acl_gpo.py`); on Windows: `Get-GPO -All`
//! and the folder on the share. See `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use annuaire_codecs::extensions as ext;
use annuaire_codecs::registry_pol::{self as rp, Entry, RegValue};
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_core::actions;
use annuaire_core::gpo::{self, Inventory, Part};
use annuaire_core::gpo_backup;
use annuaire_core::gpo_content::{self as gc, Work};
use annuaire_core::gpo_preferences::{self as gp, Preferences};
use annuaire_core::gpo_write::{self as w, GpoError};
use annuaire_core::gpp::{self, Common, EditableFilter, Element, Family, Filter, Target};
use annuaire_core::session::Scope;
use annuaire_core::xml::Node;
use serde_json::Value as Json;

use labo::{Lab, Result, Trial, catalog, check, debug, entries, lines};

fn gpo_error(e: GpoError) -> Box<dyn std::error::Error> {
    format!("{e:?}").into()
}

// --- PowerShell -----------------------------------------------------------------------------

/// Bytes at most per call of `poste.py --domaine` when a script is cut line by line (beyond
/// about 700, a call stayed blocked, 2026-10-14).
const CALL_SIZE: usize = 450;

/// The GroupPolicy module as an administrator of the domain, on the PDC emulator; the lines
/// `KEY=value`. `cut`: the script sent by packets of whole lines (each line stands alone).
fn gpmc(lab: &Lab, script: &str, cut: bool) -> Result<BTreeMap<String, String>> {
    let header = "$ErrorActionPreference='Stop'\n";
    let mut options: Vec<&str> = lab.gpmc_target().to_vec();
    options.push("--domaine");
    if !cut {
        return Ok(lines(&labo::poste(&format!("{header}{script}"), &options)?));
    }
    let mut packets: Vec<String> = Vec::new();
    for line in script.lines().map(str::trim).filter(|l| !l.is_empty()) {
        match packets.last_mut() {
            Some(last) if last.len() + line.len() < CALL_SIZE => {
                last.push_str(line);
                last.push('\n');
            }
            _ => packets.push(format!("{header}{line}\n")),
        }
    }
    let mut seen = BTreeMap::new();
    for packet in packets {
        seen.extend(lines(&labo::poste(&packet, &options)?));
    }
    Ok(seen)
}

/// PowerShell on the Windows machine of the domain (the station, or the DC), as its local
/// administrator (SYSTEM) or with `options` (`--session`).
fn station(lab: &Lab, script: &str, options: &[&str]) -> Result<String> {
    let mut all: Vec<&str> = lab.gpmc_target().to_vec();
    all.extend(options);
    labo::poste(script, &all)
}

fn yes(seen: &BTreeMap<String, String>, key: &str, value: &str) -> bool {
    seen.get(key).map(String::as_str) == Some(value)
}

// --- Oracles of the SYSVOL -------------------------------------------------------------------

/// Deviations of the ACLs of the SYSVOL from the check of `sysvolcheck`, read on dc1; none
/// against Windows (the GPMC judges by `IsAclConsistent()`).
fn acl(lab: &Lab, guids: &[&str]) -> Result<BTreeMap<String, Vec<String>>> {
    if lab.windows() {
        return Ok(guids
            .iter()
            .map(|g| ((*g).to_owned(), Vec::new()))
            .collect());
    }
    let script = std::fs::read_to_string(labo::repository().join("labo/verifier_acl_gpo.py"))?;
    let out = labo::ssh_python("dc1", &script, guids)?;
    let read: Json = serde_json::from_str(&out)?;
    Ok(read
        .as_object()
        .ok_or("JSON")?
        .iter()
        .map(|(g, errors)| {
            let errors = errors
                .as_array()
                .map(|e| {
                    e.iter()
                        .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            (g.clone(), errors)
        })
        .collect())
}

fn acl_clean(lab: &Lab, guid: &str) -> Result<bool> {
    Ok(acl(lab, &[guid])?.get(guid).is_some_and(Vec::is_empty))
}

/// The GPOs of trial (`displayName` starting with `prefix`), their DNs.
fn trial_gpos(trial: &Trial, prefix: &str) -> Result<Vec<String>> {
    Ok(entries(
        &trial.connection,
        &w::gpo_container(&trial.base),
        Scope::OneLevel,
        &format!("(&(objectClass=groupPolicyContainer)(displayName={prefix}*))"),
        &["1.1"],
    )?
    .into_iter()
    .map(|e| e.dn)
    .collect())
}

fn delete_gpo(trial: &Trial, dn: &str) -> Result<()> {
    trial.apply(&w::prepare_deletion(&trial.connection, dn, catalog()).map_err(gpo_error)?)?;
    Ok(())
}

/// The GPOs of trial deleted, and `ou` with what it holds.
fn clean(trial: &Trial, prefix: &str, ou: Option<&str>) -> Result<()> {
    for dn in trial_gpos(trial, prefix)? {
        delete_gpo(trial, &dn)?;
    }
    if let Some(ou) = ou {
        trial.remove_tree(ou)?;
    }
    Ok(())
}

/// Nothing of the trial is left: on Windows, neither GPO nor folder; on Samba, no GPO of
/// trial in `samba-tool gpo listall`, and the ACLs of the SYSVOL told.
fn final_check(trial: &Trial, lab: &Lab, prefix: &str, guids: &[&str]) -> Result<()> {
    check(
        trial_gpos(trial, prefix)?.is_empty(),
        "no GPO of trial left",
    )?;
    if lab.windows() {
        for guid in guids {
            let seen = gpmc(
                lab,
                &format!(
                    "\"GPO=\" + @(Get-GPO -All | ? {{ $_.DisplayName -like '{prefix}*' }}).Count\n\
                     \"DOSSIER=\" + (Test-Path '\\\\{0}\\SYSVOL\\{0}\\Policies\\{guid}')\n",
                    lab.domain
                ),
                true,
            )?;
            check(
                yes(&seen, "GPO", "0") && yes(&seen, "DOSSIER", "False"),
                "GPMC: neither GPO nor folder",
            )?;
        }
        return Ok(());
    }
    let listall = labo::ssh("dc1", "sudo samba-tool gpo listall 2>&1\n")?;
    check(
        !listall.contains(prefix) && guids.iter().all(|g| !listall.contains(g)),
        "samba-tool gpo listall: no GPO of trial",
    )?;
    let wrong: Vec<String> = acl(lab, &[])?
        .into_iter()
        .filter(|(_, e)| !e.is_empty())
        .map(|(g, _)| g)
        .collect();
    println!("  GPOs whose ACL sysvolcheck refuses (the lab's own): {wrong:?}");
    Ok(())
}

fn inventory(trial: &Trial) -> Result<Inventory> {
    Ok(Inventory {
        directory: gpo::read_directory(&trial.connection).map_err(debug)?,
        sysvol: gpo::read_pdc_sysvol(&trial.connection).map_err(debug)?,
        others: Vec::new(),
    })
}

fn gpo_of(trial: &Trial, guid: &str) -> Result<(gpo::Gpo, usize)> {
    let inventory = inventory(trial)?;
    let gpo = inventory
        .directory
        .gpos
        .get(guid)
        .cloned()
        .ok_or("GPO in the directory")?;
    Ok((gpo, inventory.deviations(guid).len()))
}

fn link(trial: &Trial, container: &str, dn: &str) -> Result<()> {
    match w::prepare_links(&trial.connection, container, w::link_gpo(dn, 0)) {
        Ok(cs) => trial.apply(&cs).map(|_| ()),
        Err(GpoError::AlreadyLinked) => Ok(()),
        Err(e) => Err(gpo_error(e)),
    }
}

fn create(trial: &Trial, name: &str) -> Result<(String, String)> {
    let cs = w::prepare_creation(&trial.connection, name, None, catalog()).map_err(gpo_error)?;
    trial.apply(&cs)?;
    let dn = cs.operations.first().ok_or("creation")?.dn().to_owned();
    let guid = w::guid_of(&dn);
    Ok((dn, guid))
}

// --- 1 and 2: GPO of the core, GPO of the GPMC -----------------------------------------------------

const J5E: &str = "Essai J5E";
const J5E_KEY: &str = "HKLM\\Software\\Policies\\AnnuaireEssai";

/// The OU of trial, an OU below and the group of the filtering.
fn j5e_setup(trial: &Trial) -> Result<(String, String, String)> {
    clean(trial, J5E, Some(&format!("OU=Essais-J5E,{}", trial.base)))?;
    let essais = trial.fresh_ou(&trial.base, "Essais-J5E")?;
    let below = trial.fresh_ou(&essais, "Sous")?;
    trial.apply(
        &actions::create_group(&essais, "GS-J5E-Filtrage", "", GroupScope::Global, true, "")
            .map_err(debug)?,
    )?;
    Ok((
        essais.clone(),
        below,
        format!("CN=GS-J5E-Filtrage,{essais}"),
    ))
}

#[allow(clippy::too_many_lines)]
fn gpo_of_the_core(trial: &Trial, lab: &Lab) -> Result<()> {
    let (essais, below, group) = j5e_setup(trial)?;
    let (dn, guid) = create(trial, "Essai J5E pour la GPMC")?;
    link(trial, &essais, &dn)?;

    let t = Instant::now();
    let seen = gpmc(
        lab,
        &format!(
            "$g = Get-GPO -Guid '{guid}'; \"NOM=\" + $g.DisplayName; \"ETAT=\" + $g.GpoStatus; \"ACL=\" + $g.IsAclConsistent()\n\
             [xml]$r = Get-GPOReport -Guid '{guid}' -ReportType Xml; \"RAPPORT=\" + $r.GPO.Name; \"LIEN_RAPPORT=\" + ((@($r.GPO.LinksTo) | % {{ $_.SOMPath }}) -join ',')\n\
             Set-GPRegistryValue -Guid '{guid}' -Key '{J5E_KEY}' -ValueName 'J5E' -Type String -Value 'gpmc' | Out-Null\n\
             $g = Get-GPO -Guid '{guid}'; \"VERSIONS=\" + $g.Computer.DSVersion + \"/\" + $g.Computer.SysvolVersion\n\
             if (-not ((Get-GPInheritance -Target '{below}').GpoLinks | ? {{ $_.GpoId -eq '{guid}' }})) {{ New-GPLink -Guid '{guid}' -Target '{below}' | Out-Null }}\n\
             \"LIENS=\" + (((Get-GPInheritance -Target '{below}').GpoLinks | % {{ $_.DisplayName }}) -join ',')\n"
        ),
        true,
    )?;
    println!("  GPMC ({:.0} s): {seen:?}", t.elapsed().as_secs_f64());
    check(
        yes(&seen, "NOM", "Essai J5E pour la GPMC")
            && yes(&seen, "RAPPORT", "Essai J5E pour la GPMC"),
        "Get-GPO and Get-GPOReport find it",
    )?;
    check(
        yes(&seen, "ETAT", "AllSettingsEnabled"),
        "both parts enabled",
    )?;
    check(yes(&seen, "ACL", "True"), "IsAclConsistent()")?;
    check(
        seen.get("LIEN_RAPPORT")
            .is_some_and(|l| l.contains(&format!("{}/Essais-J5E", lab.domain))),
        "the link of the core in the report",
    )?;
    let (dsv, svv) = seen
        .get("VERSIONS")
        .and_then(|v| v.split_once('/'))
        .ok_or("versions")?;
    let version: i64 = dsv.parse()?;
    // 1, or more if a packet was replayed.
    check(dsv == svv && version >= 1, "versions of the GPMC equal")?;
    check(
        yes(&seen, "LIENS", "Essai J5E pour la GPMC"),
        "linked by the GPMC",
    )?;

    // The core reads again what the GPMC wrote.
    let (gpo, deviations) = gpo_of(trial, &guid)?;
    check(
        gpo.versions().computer == version && gpo.versions().user == 0 && deviations == 0,
        "versions read again, directory = GPT.INI",
    )?;
    check(
        gpo.computer_extensions
            .to_uppercase()
            .contains(ext::REGISTRY),
        "the Registry extension of the GPMC",
    )?;
    let gplink = trial.entry(&below, &["gPLink"])?.ok_or("Sous")?;
    check(
        labo::text(&gplink, "gPLink").to_uppercase().contains(&guid),
        "the link of the GPMC read",
    )?;
    // The Registry.pol of the GPMC inherited an ACL sysvolcheck refuses.
    println!(
        "  ACL after the GPMC: {} deviation(s) from sysvolcheck",
        acl(lab, &[&guid])?.get(&guid).map_or(0, Vec::len)
    );
    // The core filters: object and folder, file of the GPMC included.
    let sid = trial.sid(&group)?;
    trial.apply(
        &w::prepare_filtering(&trial.connection, &dn, vec![sid], Vec::new(), catalog())
            .map_err(gpo_error)?,
    )?;
    check(
        acl_clean(lab, &guid)?,
        "ACLs of the folder as sysvolcheck wants",
    )?;
    let after = gpmc(
        lab,
        &format!(
            "\"ACL=\" + (Get-GPO -Guid '{guid}').IsAclConsistent()\n\
             \"PERM=\" + (((Get-GPPermission -Guid '{guid}' -All | ? {{ $_.Permission -eq 'GpoApply' }} | % {{ $_.Trustee.Name }}) -join ','))\n\
             \"VALEUR=\" + (Get-GPRegistryValue -Guid '{guid}' -Key '{J5E_KEY}' -ValueName 'J5E').Value\n"
        ),
        true,
    )?;
    println!("  GPMC after the filtering: {after:?}");
    check(
        yes(&after, "ACL", "True") && yes(&after, "VALEUR", "gpmc"),
        "consistent, value kept",
    )?;
    let permissions = after.get("PERM").cloned().unwrap_or_default();
    check(
        permissions.contains("GS-J5E-Filtrage")
            && permissions
                .split(',')
                .any(|p| p == "Authenticated Users" || p == "Utilisateurs authentifiés"),
        "filtering seen by the GPMC",
    )?;

    // The core deletes: the GPMC no longer finds it.
    delete_gpo(trial, &dn)?;
    let end = gpmc(
        lab,
        &format!(
            "\"TROUVEE=\" + [bool](Get-GPO -Guid '{guid}' -ErrorAction SilentlyContinue)\n\
             \"LIENS=\" + (((Get-GPInheritance -Target '{below}').GpoLinks | % {{ $_.DisplayName }}) -join ',')\n"
        ),
        true,
    )?;
    check(
        yes(&end, "TROUVEE", "False") && yes(&end, "LIENS", ""),
        "deleted, links included",
    )?;
    final_check(trial, lab, J5E, &[&guid])
}

#[allow(clippy::too_many_lines)]
fn gpo_of_the_gpmc(trial: &Trial, lab: &Lab, scratch: &labo::Scratch) -> Result<()> {
    let (essais, _below, group) = j5e_setup(trial)?;
    let made = gpmc(
        lab,
        "$g = Get-GPO -Name 'Essai J5E par la GPMC' -ErrorAction SilentlyContinue; if (-not $g) { $g = New-GPO -Name 'Essai J5E par la GPMC' }; \"GUID=\" + $g.Id\n",
        true,
    )?;
    let guid = format!("{{{}}}", made.get("GUID").ok_or("GUID")?.to_uppercase());
    let dn = w::gpo_dn(&trial.base, &guid);
    gpmc(
        lab,
        &format!(
            "Set-GPRegistryValue -Guid '{guid}' -Key '{J5E_KEY}' -ValueName 'J5E' -Type String -Value 'gpmc2' | Out-Null\n"
        ),
        true,
    )?;
    println!(
        "  ACL of a GPO of the GPMC: {} deviation(s) from sysvolcheck",
        acl(lab, &[&guid])?.get(&guid).map_or(0, Vec::len)
    );
    let (gpo, deviations) = gpo_of(trial, &guid)?;
    check(
        gpo.name == "Essai J5E par la GPMC" && deviations == 0 && gpo.versions().computer >= 1,
        "read by the core",
    )?;
    link(trial, &essais, &dn)?;
    let sid = trial.sid(&group)?;
    trial.apply(
        &w::prepare_filtering(&trial.connection, &dn, vec![sid], Vec::new(), catalog())
            .map_err(gpo_error)?,
    )?;
    check(
        acl_clean(lab, &guid)?,
        "ACLs as sysvolcheck wants after the filtering",
    )?;

    let folder = scratch.path().join("sauvegardes");
    std::fs::create_dir_all(&folder)?;
    let archive = gpo_backup::back_up(&trial.connection, &dn, &folder).map_err(gpo_error)?;
    let saved = gpo_backup::read_archive(&archive).map_err(debug)?;
    check(
        saved
            .elements
            .iter()
            .any(|e| e.path.to_lowercase() == "machine\\registry.pol"),
        "backed up with the file of the GPMC",
    )?;
    delete_gpo(trial, &dn)?;
    let absent = gpmc(
        lab,
        &format!("\"TROUVEE=\" + [bool](Get-GPO -Guid '{guid}' -ErrorAction SilentlyContinue)\n"),
        true,
    )?;
    check(yes(&absent, "TROUVEE", "False"), "deleted for the GPMC")?;
    trial.apply(
        &gpo_backup::prepare_restoration(&trial.connection, &saved, false, None, catalog())
            .map_err(gpo_error)?,
    )?;
    check(
        acl_clean(lab, &guid)?,
        "ACLs as sysvolcheck wants after the restoration",
    )?;
    link(trial, &essais, &dn)?;
    let back = gpmc(
        lab,
        &format!(
            "$g = Get-GPO -Guid '{guid}'; \"NOM=\" + $g.DisplayName; \"ACL=\" + $g.IsAclConsistent()\n\
             \"VALEUR=\" + (Get-GPRegistryValue -Guid '{guid}' -Key '{J5E_KEY}' -ValueName 'J5E').Value\n\
             \"PERM=\" + (((Get-GPPermission -Guid '{guid}' -All | ? {{ $_.Permission -eq 'GpoApply' }} | % {{ $_.Trustee.Name }}) -join ','))\n\
             \"LIENS=\" + (((Get-GPInheritance -Target '{essais}').GpoLinks | % {{ $_.DisplayName }}) -join ',')\n"
        ),
        true,
    )?;
    println!("  GPMC after the restoration: {back:?}");
    check(
        yes(&back, "NOM", "Essai J5E par la GPMC") && yes(&back, "ACL", "True"),
        "restored, consistent",
    )?;
    check(
        yes(&back, "VALEUR", "gpmc2")
            && back
                .get("PERM")
                .is_some_and(|p| p.contains("GS-J5E-Filtrage")),
        "its value and its filtering",
    )?;
    check(yes(&back, "LIENS", "Essai J5E par la GPMC"), "its link")?;
    delete_gpo(trial, &dn)?;
    let end = gpmc(
        lab,
        &format!("\"TROUVEE=\" + [bool](Get-GPO -Guid '{guid}' -ErrorAction SilentlyContinue)\n"),
        true,
    )?;
    check(yes(&end, "TROUVEE", "False"), "deleted again")?;
    final_check(trial, lab, J5E, &[&guid])
}

#[test]
#[ignore = "lab"]
fn gpmc_gpo_of_the_core() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("gpmc-1")?;
    let trial = Trial::new(&lab, &scratch)?;
    let done = gpo_of_the_core(&trial, &lab);
    let cleaned = clean(&trial, J5E, Some(&format!("OU=Essais-J5E,{}", trial.base)));
    trial.connection.join();
    done.and(cleaned)
}

#[test]
#[ignore = "lab"]
fn gpmc_gpo_of_the_gpmc() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("gpmc-2")?;
    let trial = Trial::new(&lab, &scratch)?;
    let done = gpo_of_the_gpmc(&trial, &lab, &scratch);
    let cleaned = clean(&trial, J5E, Some(&format!("OU=Essais-J5E,{}", trial.base)));
    trial.connection.join();
    done.and(cleaned)
}

// --- 3: Registry.pol, the GPMC, Windows ----------------------------------------------------------

const J7P: &str = "Essai J7P registre";
const J7P_KEY: &str = "Software\\Policies\\AnnuaireJ7P";

const GPUPDATE_COMPUTER: &str =
    "cmd /c \"echo n| gpupdate /target:computer /force /wait:120\" | Out-Null";
/// Run in `--session` (the only context where gpupdate processes the user).
const GPUPDATE_USER: &str = "cmd /c \"echo n| gpupdate /target:user /force /wait:120\" | Out-Null";
/// The account of the session opened on the station (`creer-poste.sh session`).
const SESSION: &str = "LAB\\herve.humbert2";

/// In SYSTEM: `gpresult /x` of a part, on one line `XML=`.
fn gpresult_script(computer: bool) -> String {
    let (scope, file) = if computer {
        (
            "/scope computer".to_owned(),
            "C:\\Windows\\Temp\\gpresult-ordinateur.xml",
        )
    } else {
        (
            format!("/user {SESSION} /scope user"),
            "C:\\Windows\\Temp\\gpresult-utilisateur.xml",
        )
    };
    format!(
        "gpresult {scope} /x {file} /f | Out-Null\n\
         'XML=' + ((Get-Content -Raw -Encoding Unicode {file}) -replace \"`r?`n\", ' ')\n\
         Remove-Item {file}\n"
    )
}

/// The GPOs of `gpresult /x` (`ComputerResults` or `UserResults`): name → IsValid,
/// FilterAllowed, AccessDenied.
fn gpresult_gpos(xml: &str, computer: bool) -> Result<BTreeMap<String, [String; 3]>> {
    let start = xml.find("?>").map_or(0, |i| i + 2);
    let text = xml.get(start..).unwrap_or_default();
    let document = roxmltree::Document::parse(text)?;
    let part = if computer {
        "ComputerResults"
    } else {
        "UserResults"
    };
    let block = document
        .root_element()
        .children()
        .find(|n| n.tag_name().name() == part)
        .ok_or("results")?;
    let child_text = |n: roxmltree::Node<'_, '_>, tag: &str| {
        n.children()
            .find(|c| c.tag_name().name() == tag)
            .and_then(|c| c.text())
            .unwrap_or_default()
            .to_owned()
    };
    Ok(block
        .children()
        .filter(|n| n.tag_name().name() == "GPO")
        .map(|n| {
            (
                child_text(n, "Name"),
                [
                    child_text(n, "IsValid"),
                    child_text(n, "FilterAllowed"),
                    child_text(n, "AccessDenied"),
                ],
            )
        })
        .collect())
}

/// In SYSTEM: values of `HKCU\<key>` of the user of the session, read in `HKEY_USERS\<SID>`.
fn user_registry_script(key: &str, names: &[&str]) -> String {
    let list: Vec<String> = names.iter().map(|n| format!("'{n}'")).collect();
    format!(
        "$sid = (New-Object Security.Principal.NTAccount('{SESSION}')).Translate([Security.Principal.SecurityIdentifier]).Value\n\
         $k = \"Registry::HKEY_USERS\\$sid\\{key}\"; 'U_EXISTE=' + (Test-Path $k)\n\
         if (Test-Path $k) {{ $p = Get-ItemProperty $k; foreach ($n in @({})) {{ 'U_' + $n.ToUpper() + '=' + \"$($p.$n)\" }} }}\n",
        list.join(",")
    )
}

/// The SYSVOL of dc1 copied on dc2, where the station reads it (LAB.TEST only).
fn copy_sysvol(lab: &Lab) -> Result<()> {
    if lab.windows() {
        Ok(())
    } else {
        labo::copy_sysvol()
    }
}

fn utf16z(text: &str) -> Result<Vec<u8>> {
    Ok(rp::encode_value(rp::REG_SZ, &RegValue::Text(text.into()))?)
}

fn value(name: &str, rtype: u32, data: &RegValue) -> Result<Entry> {
    Ok(Entry {
        key: J7P_KEY.into(),
        value_name: name.into(),
        rtype,
        data: rp::encode_value(rtype, data)?,
    })
}

fn machine_entries() -> Result<Vec<Entry>> {
    Ok(vec![
        value(
            "Texte",
            rp::REG_SZ,
            &RegValue::Text("Été à Paris, 20 °C".into()),
        )?,
        value(
            "Chemin",
            rp::REG_EXPAND_SZ,
            &RegValue::Text("%SystemRoot%\\Temp".into()),
        )?,
        value("Entier", rp::REG_DWORD, &RegValue::Integer(42))?,
        value(
            "Grand",
            rp::REG_QWORD,
            &RegValue::Integer(81_985_529_216_486_895),
        )?,
        value(
            "Liste",
            rp::REG_MULTI_SZ,
            &RegValue::Texts(vec!["un".into(), "deux".into(), "été".into()]),
        )?,
        value(
            "Octets",
            rp::REG_BINARY,
            &RegValue::Bytes(vec![0, 1, 0x7f, 0x80, 0xff]),
        )?,
    ])
}

/// What the GPMC says of each value: Type|Value|PolicyState.
const GPMC_MACHINE: [(&str, &str); 7] = [
    ("Texte", "String|Été à Paris, 20 °C|Set"),
    ("Chemin", "ExpandString|%SystemRoot%\\Temp|Set"),
    ("Entier", "DWord|42|Set"),
    ("Grand", "QWord|81985529216486895|Set"),
    ("Liste", "MultiString|un deux été|Set"),
    ("Octets", "Binary|0 1 127 128 255|Set"),
    ("Ancienne", "|  |Delete"),
];

fn registry(trial: &Trial, dn: &str, part: Part) -> Result<Vec<Entry>> {
    let read = gc::read_files(
        &trial.connection,
        dn,
        vec![(part, vec![gc::REGISTRY_POL.into()])],
    )
    .map_err(gpo_error)?
    .into_iter()
    .next()
    .ok_or("nothing read")?;
    gc::registry(&read).map_err(gpo_error)
}

fn write_registry(
    trial: &Trial,
    dn: &str,
    part: Part,
    change: Arc<dyn Fn(Vec<Entry>) -> Vec<Entry> + Send + Sync>,
) -> Result<()> {
    let work: Work = Arc::new(move |read| gc::modify_registry(read, change.as_ref()));
    let t = Instant::now();
    let cs = gc::prepare_contents(
        &trial.connection,
        dn,
        vec![(part, vec![gc::REGISTRY_POL.into()], work)],
        true,
        catalog(),
    )
    .map_err(gpo_error)?;
    println!("  preview in {:.2} s", t.elapsed().as_secs_f64());
    trial.apply(&cs)?;
    Ok(())
}

fn read_gpmc_registry(lab: &Lab, guid: &str) -> Result<BTreeMap<String, String>> {
    let mut script = vec![format!("$k = 'HKLM\\{J7P_KEY}'")];
    for (name, _) in GPMC_MACHINE {
        let upper = name.to_uppercase();
        script.push(format!(
            "$v = Get-GPRegistryValue -Guid '{guid}' -Key $k -ValueName '{name}' -ErrorAction SilentlyContinue; \
             if ($v) {{ 'M_{upper}=' + $v.Type + '|' + \"$($v.Value)\" + '|' + $v.PolicyState }} else {{ 'M_{upper}=absente' }}"
        ));
    }
    script.push(format!(
        "foreach ($n in 'ParGPMC','Apres') {{ $v = Get-GPRegistryValue -Guid '{guid}' -Key $k -ValueName $n -ErrorAction SilentlyContinue; \
         if ($v) {{ 'M_' + $n.ToUpper() + '=' + $v.Type + '|' + \"$($v.Value)\" + '|' + $v.PolicyState }} }}"
    ));
    script.push(format!(
        "Get-GPRegistryValue -Guid '{guid}' -Key 'HKCU\\{J7P_KEY}' | % {{ 'U_' + $_.ValueName.ToUpper() + '=' + $_.Type + '|' + \"$($_.Value)\" + '|' + $_.PolicyState }}"
    ));
    script.push(format!(
        "$p = Get-GPRegistryValue -Guid '{guid}' -Key 'HKLM\\{J7P_KEY}\\Purge' -ErrorAction SilentlyContinue; 'PURGE=' + (@($p) | % {{ \"$($_.ValueName)|$($_.PolicyState)\" }})"
    ));
    script.push(format!(
        "[xml]$r = Get-GPOReport -Guid '{guid}' -ReportType Xml; \
         'RAPPORT_O=' + $r.GPO.Computer.VersionDirectory + '/' + $r.GPO.Computer.VersionSysvol; \
         'RAPPORT_U=' + $r.GPO.User.VersionDirectory + '/' + $r.GPO.User.VersionSysvol; \
         'RAPPORT_EXT=' + ((@($r.GPO.Computer.ExtensionData) + @($r.GPO.User.ExtensionData) | % {{ $_.Name }}) -join ',')"
    ));
    script.push(format!(
        "$g = Get-GPO -Guid '{guid}'; 'GPO=' + $g.Computer.DSVersion + '/' + $g.Computer.SysvolVersion + '/' + $g.User.DSVersion + '/' + $g.User.SysvolVersion + '/' + $g.IsAclConsistent()"
    ));
    let t = Instant::now();
    let seen = gpmc(lab, &script.join("\n"), false)?;
    println!("  GPMC read in {:.0} s", t.elapsed().as_secs_f64());
    Ok(seen)
}

#[allow(clippy::too_many_lines)]
fn registry_trial(trial: &Trial, lab: &Lab) -> Result<()> {
    let essais = trial.fresh_ou(&trial.base, "Essais-J7P")?;
    let (dn, guid) = create(trial, J7P)?;
    link(trial, &essais, &dn)?;

    println!("1. both parts written by the core");
    let entries_machine = machine_entries()?;
    write_registry(
        trial,
        &dn,
        Part::Computer,
        Arc::new(move |mut entries| {
            for e in &entries_machine {
                entries = rp::set(&entries, e.clone());
            }
            let entries = rp::disable(&entries, J7P_KEY, "Ancienne");
            rp::delete_values(&entries, &format!("{J7P_KEY}\\Purge"))
        }),
    )?;
    let user = [
        value("Texte", rp::REG_SZ, &RegValue::Text("utilisateur".into()))?,
        value("Ecran", rp::REG_DWORD, &RegValue::Integer(600))?,
    ];
    write_registry(
        trial,
        &dn,
        Part::User,
        Arc::new(move |mut entries| {
            entries.extend(user.iter().cloned());
            entries
        }),
    )?;
    let (gpo, deviations) = gpo_of(trial, &guid)?;
    check(
        deviations == 0 && gpo.versions().computer == 1 && gpo.versions().user == 1,
        "versions 1/1, directory = GPT.INI",
    )?;
    check(
        gpo.computer_extensions == format!("[{}{}]", ext::REGISTRY, ext::REGISTRY_TOOL_MACHINE)
            && gpo.user_extensions == format!("[{}{}]", ext::REGISTRY, ext::REGISTRY_TOOL_USER),
        "extensions of the GPMC",
    )?;
    let written_machine = registry(trial, &dn, Part::Computer)?;

    println!("2. the GPMC reads each value, without deviation of version");
    let seen = read_gpmc_registry(lab, &guid)?;
    println!("  {seen:?}");
    for (name, wanted) in GPMC_MACHINE {
        let got = seen
            .get(&format!("M_{}", name.to_uppercase()))
            .cloned()
            .unwrap_or_default();
        let state = |t: &str| t.rsplit('|').next().unwrap_or_default().to_owned();
        let same = if wanted.starts_with('|') {
            state(&got) == state(wanted)
        } else {
            got == wanted
        };
        check(same, &format!("GPMC: {name} = {got}"))?;
    }
    check(
        yes(&seen, "U_TEXTE", "String|utilisateur|Set") && yes(&seen, "U_ECRAN", "DWord|600|Set"),
        "GPMC: user part",
    )?;
    check(
        yes(&seen, "RAPPORT_O", "1/1") && yes(&seen, "RAPPORT_U", "1/1"),
        "report without deviation",
    )?;
    check(
        seen.get("RAPPORT_EXT")
            .is_some_and(|e| e.contains("Registry")),
        "Registry extension in the report",
    )?;
    check(
        yes(&seen, "GPO", "1/1/1/1/True"),
        "Get-GPO: versions and ACL",
    )?;

    let seen = gpmc(
        lab,
        &format!(
            "Set-GPRegistryValue -Guid '{guid}' -Key 'HKLM\\{J7P_KEY}' -ValueName 'ParGPMC' -Type DWord -Value 7 | Out-Null\n\
             Set-GPRegistryValue -Guid '{guid}' -Key 'HKLM\\{J7P_KEY}' -ValueName 'Entier' -Type DWord -Value 43 | Out-Null\n\
             $g = Get-GPO -Guid '{guid}'; 'GPO=' + $g.Computer.DSVersion + '/' + $g.Computer.SysvolVersion\n"
        ),
        false,
    )?;
    check(
        yes(&seen, "GPO", "3/3"),
        "the GPMC sets one value and changes one",
    )?;

    println!("3. the core reads again: nothing lost");
    let mut read = registry(trial, &dn, Part::Computer)?;
    let mut wanted: Vec<Entry> = written_machine
        .iter()
        .map(|e| {
            if e.value_name == "Entier" {
                value("Entier", rp::REG_DWORD, &RegValue::Integer(43))
            } else {
                Ok(e.clone())
            }
        })
        .collect::<Result<_>>()?;
    wanted.push(value("ParGPMC", rp::REG_DWORD, &RegValue::Integer(7))?);
    println!(
        "  order after the GPMC: {:?}",
        read.iter()
            .map(|e| e.value_name.clone())
            .collect::<Vec<_>>()
    );
    let key = |e: &Entry| format!("{e:?}");
    read.sort_by_key(key);
    wanted.sort_by_key(key);
    check(
        read == wanted,
        "the entries of the core intact, those of the GPMC there",
    )?;
    let (gpo, deviations) = gpo_of(trial, &guid)?;
    check(deviations == 0 && gpo.versions().computer == 3, "version 3")?;
    write_registry(
        trial,
        &dn,
        Part::Computer,
        Arc::new(|entries| {
            let entries = rp::set(
                &entries,
                Entry {
                    key: J7P_KEY.into(),
                    value_name: "Apres".into(),
                    rtype: rp::REG_SZ,
                    data: utf16z("annuaire").unwrap_or_default(),
                },
            );
            rp::remove(&entries, J7P_KEY, Some("Octets"))
        }),
    )?;
    let seen = read_gpmc_registry(lab, &guid)?;
    check(
        yes(&seen, "M_ENTIER", "DWord|43|Set") && yes(&seen, "M_PARGPMC", "DWord|7|Set"),
        "GPMC: its own values",
    )?;
    check(
        yes(&seen, "M_APRES", "String|annuaire|Set") && yes(&seen, "M_OCTETS", "absente"),
        "GPMC: one added, one removed by the core",
    )?;
    check(
        yes(&seen, "M_TEXTE", GPMC_MACHINE[0].1) && yes(&seen, "M_LISTE", GPMC_MACHINE[4].1),
        "GPMC: the rest as written",
    )?;
    check(
        yes(&seen, "RAPPORT_O", "4/4") && seen.get("GPO").is_some_and(|g| g.ends_with("/True")),
        "version 4, ACL consistent",
    )?;

    println!("4. applied by Windows");
    applied(trial, lab, &dn)?;
    check(trial_gpos(trial, J7P)?.is_empty(), "GPO of trial deleted")?;
    trial.remove_tree(&essais)
}

#[allow(clippy::too_many_lines)]
fn applied(trial: &Trial, lab: &Lab, dn: &str) -> Result<()> {
    let base = &trial.base;
    let containers = if lab.windows() {
        vec![format!("OU=Domain Controllers,{base}")]
    } else {
        vec![
            format!("OU=Ordinateurs,OU=Direction,OU=Nantes,OU=Labo,{base}"),
            format!("OU=Utilisateurs,OU=Direction,OU=Nantes,OU=Labo,{base}"),
        ]
    };
    for container in &containers {
        link(trial, container, dn)?;
    }
    copy_sysvol(lab)?;
    let read_hklm = format!(
        "$k = 'HKLM:\\{J7P_KEY}'; 'EXISTE=' + (Test-Path $k)\n\
         if (Test-Path $k) {{ $p = Get-ItemProperty $k; foreach ($n in 'Texte','Chemin','Entier','Grand','Liste','Octets','Ancienne','ParGPMC','Apres') {{ \
         'R_' + $n.ToUpper() + '=' + \"$($p.$n)\" }}\n\
         $i = Get-Item $k; 'R_CHEMIN=' + $i.GetValue('Chemin', $null, 'DoNotExpandEnvironmentNames') + '|' + $i.GetValueKind('Chemin') }}\n"
    );
    let t = Instant::now();
    let seen = lines(&station(
        lab,
        &format!(
            "New-Item -Force 'HKLM:\\{J7P_KEY}' | Out-Null; Set-ItemProperty 'HKLM:\\{J7P_KEY}' -Name Ancienne -Value 1\n\
             {GPUPDATE_COMPUTER}\n{read_hklm}{}",
            gpresult_script(true)
        ),
        &[],
    )?);
    println!(
        "  gpupdate of the computer in {:.0} s: {:?}",
        t.elapsed().as_secs_f64(),
        seen.iter()
            .filter(|(k, _)| *k != "XML")
            .collect::<BTreeMap<_, _>>()
    );
    check(yes(&seen, "EXISTE", "True"), "the key on the machine")?;
    check(
        yes(&seen, "R_TEXTE", "Été à Paris, 20 °C")
            && yes(&seen, "R_CHEMIN", "%SystemRoot%\\Temp|ExpandString"),
        "texts, expandable kept",
    )?;
    check(
        yes(&seen, "R_ENTIER", "43") && yes(&seen, "R_GRAND", "81985529216486895"),
        "integers",
    )?;
    check(
        yes(&seen, "R_LISTE", "un deux été") && yes(&seen, "R_OCTETS", ""),
        "list, bytes removed",
    )?;
    check(
        yes(&seen, "R_PARGPMC", "7") && yes(&seen, "R_APRES", "annuaire"),
        "values of the GPMC and of the core",
    )?;
    check(
        yes(&seen, "R_ANCIENNE", ""),
        "the value disabled (**del.) disappeared",
    )?;
    let gpos = gpresult_gpos(seen.get("XML").ok_or("gpresult")?, true)?;
    println!("  gpresult: {:?}", gpos.get(J7P));
    check(
        gpos.get(J7P)
            .is_some_and(|g| g == &["true", "true", "false"]),
        "applied according to gpresult",
    )?;

    if !lab.windows() {
        // gpupdate in the session (bounded); registry and gpresult read in SYSTEM.
        station(lab, GPUPDATE_USER, &["--session"])?;
        let seen = lines(&station(
            lab,
            &format!(
                "{}{}",
                user_registry_script(J7P_KEY, &["Texte", "Ecran"]),
                gpresult_script(false)
            ),
            &[],
        )?);
        check(
            yes(&seen, "U_TEXTE", "utilisateur") && yes(&seen, "U_ECRAN", "600"),
            "user part applied in the session",
        )?;
        let gpos = gpresult_gpos(seen.get("XML").ok_or("gpresult")?, false)?;
        println!("  gpresult (user): {:?}", gpos.get(J7P));
        check(
            gpos.get(J7P)
                .is_some_and(|g| g[1] == "true" && g[2] == "false"),
            "allowed for the user",
        )?;
    }

    // The GPO deleted by the core (links included): the keys disappear.
    delete_gpo(trial, dn)?;
    copy_sysvol(lab)?;
    let seen = lines(&station(
        lab,
        &format!("{GPUPDATE_COMPUTER}\n{read_hklm}"),
        &[],
    )?);
    check(
        yes(&seen, "EXISTE", "False") || seen.get("R_TEXTE").is_none_or(String::is_empty),
        "values removed from the machine",
    )?;
    station(
        lab,
        &format!("Remove-Item -Force -Recurse 'HKLM:\\{J7P_KEY}' -ErrorAction SilentlyContinue"),
        &[],
    )?;
    if !lab.windows() {
        station(lab, GPUPDATE_USER, &["--session"])?;
        let seen = lines(&station(lab, &user_registry_script(J7P_KEY, &[]), &[])?);
        check(yes(&seen, "U_EXISTE", "False"), "removed from the session")?;
    }
    Ok(())
}

#[test]
#[ignore = "lab"]
fn gpmc_registry() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("gpmc-registre")?;
    let trial = Trial::new(&lab, &scratch)?;
    clean(&trial, J7P, Some(&format!("OU=Essais-J7P,{}", trial.base)))?;
    let done = registry_trial(&trial, &lab);
    let cleaned = clean(&trial, J7P, Some(&format!("OU=Essais-J7P,{}", trial.base)))
        .and_then(|()| copy_sysvol(&lab));
    trial.connection.join();
    done.and(cleaned)
}

// --- 4: preferences ------------------------------------------------------------------------------

const J7F: &str = "Essai J7F";
const J7F_NAME: &str = "Essai J7F préférences";
const J7F_GPMC: &str = "Essai J7F GPMC";
const SHARE: &str = "essai-j7f";
const J7F_KEY: &str = "Software\\Essai J7F";
const STATION: &str = "ANNUAIRE-POSTE1";

fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

fn group_filter(name: &str, sid: &str) -> EditableFilter {
    EditableFilter::new(
        Target::Group,
        &[
            ("bool", "AND"),
            ("not", "0"),
            ("name", name),
            ("sid", sid),
            ("userContext", "1"),
        ],
    )
}

fn computer_filter(name: &str) -> Filter {
    Filter::Editable(EditableFilter::new(
        Target::Computer,
        &[
            ("bool", "AND"),
            ("not", "0"),
            ("type", "NETBIOS"),
            ("name", name),
        ],
    ))
}

fn new_element(
    family: Family,
    name: &str,
    properties: &[(&str, &str)],
    filters: &[Filter],
    children: &[Node],
) -> Element {
    gpp::new_element(
        family,
        name,
        name,
        &owned(properties),
        &Common::default(),
        filters,
        &w::new_guid(),
        gpp::now(),
        children,
    )
}

/// A registry element as the form makes it: value (REG_SZ, REG_DWORD in decimal, REG_MULTI_SZ
/// one line a value), or the key itself (`name` empty).
fn registry_element(
    hive: &str,
    name: &str,
    rtype: &str,
    data: &str,
    action: &str,
    filters: &[Filter],
) -> Result<Element> {
    let (shown, rtype) = if name.is_empty() {
        (J7F_KEY, "REG_SZ")
    } else {
        (name, rtype)
    };
    let (value, values): (String, Vec<String>) = if action == "D" || name.is_empty() {
        (String::new(), Vec::new())
    } else {
        match rtype {
            "REG_DWORD" => (format!("{:08X}", data.parse::<u32>()?), Vec::new()),
            "REG_MULTI_SZ" => {
                let lines: Vec<String> = data.split('\n').map(str::to_owned).collect();
                (lines.join(" "), lines)
            }
            _ => (data.to_owned(), Vec::new()),
        }
    };
    let mut children = Vec::new();
    if !values.is_empty() {
        let mut container = Node::new("Values");
        for v in values {
            let mut child = Node::new("Value");
            child.text = v;
            container.children.push(child);
        }
        children.push(container);
    }
    let decimal = if rtype == "REG_DWORD" || rtype == "REG_QWORD" {
        "1"
    } else {
        "0"
    };
    Ok(new_element(
        Family::Registry,
        shown,
        &[
            ("action", action),
            ("displayDecimal", decimal),
            ("default", "0"),
            ("hive", hive),
            ("key", J7F_KEY),
            ("name", name),
            ("type", rtype),
            ("value", &value),
        ],
        filters,
        &children,
    ))
}

fn say(remarks: &[gp::Remark]) -> Vec<String> {
    remarks.iter().map(|x| format!("{x:?}")).collect()
}

fn write_preferences(
    trial: &Trial,
    dn: &str,
    part: Part,
    family: Family,
    operations: Vec<gp::Operation>,
) -> Result<()> {
    let work: Work = Arc::new(move |read| gp::change(read, family, &operations, &say));
    let t = Instant::now();
    let cs = gc::prepare_contents(
        &trial.connection,
        dn,
        vec![(part, vec![family.path()], work)],
        true,
        catalog(),
    )
    .map_err(gpo_error)?;
    trial.apply(&cs)?;
    println!("  {family:?} written in {:.1} s", t.elapsed().as_secs_f64());
    Ok(())
}

fn read_preferences(trial: &Trial, dn: &str, part: Part) -> Result<Preferences> {
    let read = gc::read_files(&trial.connection, dn, vec![(part, gp::paths())])
        .map_err(gpo_error)?
        .into_iter()
        .next()
        .ok_or("nothing read")?;
    gp::from_read(&read).map_err(gpo_error)
}

/// A group the account of the session is a member of, and one it is not a member of.
fn groups(trial: &Trial, lab: &Lab, netbios: &str) -> Result<(EditableFilter, EditableFilter)> {
    if lab.windows() {
        let sid = trial.sid(&trial.base)?;
        return Ok((
            group_filter(&format!("{netbios}\\Domain Users"), &format!("{sid}-513")),
            group_filter(&format!("{netbios}\\Domain Guests"), &format!("{sid}-514")),
        ));
    }
    let sid_of = |sam: &str| -> Result<String> {
        let found = entries(
            &trial.connection,
            &trial.base,
            Scope::Subtree,
            &format!("(sAMAccountName={sam})"),
            &["1.1"],
        )?;
        Ok(trial.sid(&found.first().ok_or("group")?.dn)?.to_string())
    };
    Ok((
        group_filter(
            &format!("{netbios}\\GG-Nantes-Direction"),
            &sid_of("GG-Nantes-Direction")?,
        ),
        group_filter(
            &format!("{netbios}\\GG-Paris-Direction"),
            &sid_of("GG-Paris-Direction")?,
        ),
    ))
}

fn parent_of(trial: &Trial, sam: &str) -> Result<String> {
    let found = entries(
        &trial.connection,
        &trial.base,
        Scope::Subtree,
        &format!("(sAMAccountName={sam})"),
        &["1.1"],
    )?;
    let dn = found.first().ok_or("account")?.dn.clone();
    Ok(dn.split_once(',').ok_or("parent")?.1.to_owned())
}

const GPUPDATE_BOUNDED: &str = "$p = Start-Process cmd -ArgumentList '/c echo n| gpupdate /target:@CIBLE@ /force /wait:120' \
-WindowStyle Hidden -PassThru; if (-not $p.WaitForExit(240000)) { $p.Kill(); 'GPUPDATE=delai' } else { 'GPUPDATE=fini' }";

const USER_PS: &str = "$sid = (New-Object Security.Principal.NTAccount('LAB', 'herve.humbert2')).Translate([Security.Principal.SecurityIdentifier]).Value\n\
$hku = \"Registry::HKEY_USERS\\$sid\"\n\
$bureau = 'C:\\Users\\herve.humbert2\\Desktop\\Essai J7F.lnk'\n";

/// Refreshes the user policy of the open session (`Invoke-GPUpdate`, which starts it in the
/// session without holding it), waits for `condition` (3 minutes at most) and reads `reading`;
/// as local administrator.
fn session_user(condition: &str, reading: &str) -> Result<BTreeMap<String, String>> {
    let script = format!(
        "{USER_PS}Invoke-GPUpdate -Target User -Force -RandomDelayInMinutes 0 | Out-Null\n\
         $fin = (Get-Date).AddMinutes(3); while ((Get-Date) -lt $fin -and -not ({condition})) {{ Start-Sleep 5 }}\n\
         'ATTENTE=' + [bool]({condition})\n{reading}\n\
         gpresult /user LAB\\herve.humbert2 /scope user /x $env:TEMP\\j7f.xml /f | Out-Null\n\
         $x = [xml](Get-Content -Raw $env:TEMP\\j7f.xml)\n\
         'GPO_UTILISATEUR=' + (($x.Rsop.UserResults.GPO | % {{ $_.Name }}) -join ',')\n\
         'EXTENSIONS=' + (($x.Rsop.UserResults.ExtensionData | % {{ $_.Name.'#text' }}) -join ',')"
    );
    Ok(lines(&labo::poste(&script, &[])?))
}

fn gpupdate(part: &str) -> Result<()> {
    let options: &[&str] = if part == "user" { &["--session"] } else { &[] };
    let seen = lines(&labo::poste(
        &GPUPDATE_BOUNDED.replace("@CIBLE@", part),
        options,
    )?);
    println!("  gpupdate {part}: {:?}", seen.get("GPUPDATE"));
    Ok(())
}

/// The share of trial on dc1 (smb.conf backed up), LAB.TEST only.
fn share(lab: &Lab, on: bool) -> Result<()> {
    if lab.windows() {
        return Ok(());
    }
    let script = if on {
        "sudo cp -n /etc/samba/smb.conf /root/smb.conf.avant-j7f && sudo mkdir -p /srv/essai-j7f \
         && sudo chmod 1777 /srv/essai-j7f && echo essai | sudo tee /srv/essai-j7f/lisez-moi.txt >/dev/null \
         && (grep -q '^\\[essai-j7f\\]' /etc/samba/smb.conf || printf '\\n[essai-j7f]\\n\\tpath = /srv/essai-j7f\\n\\tread only = no\\n' \
         | sudo tee -a /etc/samba/smb.conf >/dev/null) && sudo smbcontrol all reload-config\n"
    } else {
        "if sudo test -f /root/smb.conf.avant-j7f; then sudo cp /root/smb.conf.avant-j7f /etc/samba/smb.conf \
         && sudo rm /root/smb.conf.avant-j7f && sudo smbcontrol all reload-config; fi; sudo rm -rf /srv/essai-j7f\n"
    };
    labo::ssh("dc1", script)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn preferences_written(
    trial: &Trial,
    lab: &Lab,
    dn: &str,
    guid: &str,
    yes_group: &EditableFilter,
    no_group: &EditableFilter,
) -> Result<()> {
    println!("1. four families written by the core, read by the GPMC");
    let pdc = lab.pdc_name();
    let (oui, non) = (
        Filter::Editable(yes_group.clone()),
        Filter::Editable(no_group.clone()),
    );
    let (u, m) = (Part::User, Part::Computer);
    let unc = format!("\\\\{pdc}\\{SHARE}");
    write_preferences(
        trial,
        dn,
        u,
        Family::Drives,
        vec![gp::Operation::Add(new_element(
            Family::Drives,
            "X:",
            &[
                ("action", "R"),
                ("thisDrive", "NOCHANGE"),
                ("allDrives", "NOCHANGE"),
                ("userName", ""),
                ("path", &unc),
                ("label", "Essai J7F"),
                ("persistent", "1"),
                ("useLetter", "1"),
                ("letter", "X"),
            ],
            std::slice::from_ref(&oui),
            &[],
        ))],
    )?;
    let absent = format!("\\\\{pdc}\\essai-j7f-absente");
    write_preferences(
        trial,
        dn,
        u,
        Family::Printers,
        vec![gp::Operation::Add(new_element(
            Family::Printers,
            "essai-j7f-absente",
            &[
                ("action", "D"),
                ("comment", ""),
                ("path", &absent),
                ("location", ""),
                ("default", "0"),
                ("skipLocal", "0"),
                ("deleteAll", "0"),
                ("persistent", "0"),
                ("deleteMaps", "0"),
                ("port", ""),
            ],
            std::slice::from_ref(&non),
            &[],
        ))],
    )?;
    write_preferences(
        trial,
        dn,
        u,
        Family::Shortcuts,
        vec![gp::Operation::Add(new_element(
            Family::Shortcuts,
            "Essai J7F",
            &[
                ("pidl", ""),
                ("targetType", "FILESYSTEM"),
                ("action", "U"),
                ("comment", ""),
                ("shortcutKey", "0"),
                ("startIn", ""),
                ("arguments", ""),
                ("iconIndex", "0"),
                ("targetPath", "%WINDIR%\\notepad.exe"),
                ("iconPath", ""),
                ("window", ""),
                ("shortcutPath", "%DesktopDir%\\Essai J7F"),
            ],
            &[],
            &[],
        ))],
    )?;
    let negation = Filter::Editable(yes_group.with(&[("not", "1")]));
    let hkcu = "HKEY_CURRENT_USER";
    write_preferences(
        trial,
        dn,
        u,
        Family::Registry,
        vec![
            gp::Operation::Add(registry_element(
                hkcu,
                "Cible",
                "REG_SZ",
                "oui",
                "U",
                std::slice::from_ref(&oui),
            )?),
            gp::Operation::Add(registry_element(
                hkcu,
                "Exclu",
                "REG_DWORD",
                "1",
                "U",
                std::slice::from_ref(&non),
            )?),
            gp::Operation::Add(registry_element(
                hkcu,
                "Negation",
                "REG_SZ",
                "non",
                "U",
                &[negation],
            )?),
            gp::Operation::Add(registry_element(
                hkcu,
                "Liste",
                "REG_MULTI_SZ",
                "a\nb",
                "U",
                &[],
            )?),
        ],
    )?;
    let hklm = "HKEY_LOCAL_MACHINE";
    write_preferences(
        trial,
        dn,
        m,
        Family::Registry,
        vec![
            gp::Operation::Add(registry_element(
                hklm,
                "Machine",
                "REG_SZ",
                "Machine",
                "U",
                &[computer_filter(STATION)],
            )?),
            gp::Operation::Add(registry_element(
                hklm,
                "AutreMachine",
                "REG_SZ",
                "AutreMachine",
                "U",
                &[computer_filter("AUTRE-POSTE")],
            )?),
        ],
    )?;

    // The core reads again what it wrote, versions and extensions included.
    let read_u = read_preferences(trial, dn, u)?;
    let read_m = read_preferences(trial, dn, m)?;
    let counts: Vec<(Family, usize)> = read_u
        .files
        .iter()
        .map(|f| (f.family, f.elements().len()))
        .collect();
    check(
        counts
            == [
                (Family::Drives, 1),
                (Family::Printers, 1),
                (Family::Shortcuts, 1),
                (Family::Registry, 4),
            ],
        &format!("elements read again {counts:?}"),
    )?;
    check(
        Family::ALL.iter().all(|f| read_u.declared(*f)),
        "the four extensions declared (user)",
    )?;
    check(
        read_m.declared(Family::Registry) && !read_m.declared(Family::Shortcuts),
        "computer: registry only",
    )?;
    let (gpo, deviations) = gpo_of(trial, guid)?;
    check(
        gpo.versions().user == 4 && gpo.versions().computer == 1 && deviations == 0,
        "versions 4/1, directory = GPT.INI",
    )?;

    let t = Instant::now();
    let seen = gpmc(
        lab,
        &format!(
            "$g = Get-GPO -Guid '{guid}'; \"ACL=\" + $g.IsAclConsistent(); \"VU=\" + $g.User.DSVersion + \"/\" + $g.User.SysvolVersion; \"VM=\" + $g.Computer.DSVersion + \"/\" + $g.Computer.SysvolVersion\n\
             [xml]$r = Get-GPOReport -Guid '{guid}' -ReportType Xml\n\
             foreach ($p in 'Computer','User') {{ foreach ($x in $r.GPO.$p.ExtensionData) {{ (\"EXT_\" + $p.ToUpper() + \"_\" + ($x.Name -replace '[^A-Za-z]','').ToUpper()) + \"=\" + $x.Extension.OuterXml.Length }} }}\n\
             \"LETTRE=\" + ($r.GPO.User.ExtensionData | ? Name -eq 'Drive Maps').Extension.DriveMapSettings.Drive.Properties.letter\n\
             \"FILTRE=\" + ($r.GPO.User.ExtensionData | ? Name -eq 'Drive Maps').Extension.DriveMapSettings.Drive.Filters.FilterGroup.name\n\
             \"REGISTRE=\" + ((($r.GPO.User.ExtensionData | ? Name -eq 'Windows Registry').Extension.RegistrySettings.Registry | % {{ $_.Properties.name }}) -join ',')\n"
        ),
        false,
    )?;
    println!(
        "  GPMC report ({:.0} s): {seen:?}",
        t.elapsed().as_secs_f64()
    );
    check(
        yes(&seen, "ACL", "True") && yes(&seen, "VU", "4/4") && yes(&seen, "VM", "1/1"),
        "consistent, versions equal",
    )?;
    for e in [
        "EXT_USER_DRIVEMAPS",
        "EXT_USER_PRINTERS",
        "EXT_USER_SHORTCUTS",
        "EXT_USER_WINDOWSREGISTRY",
        "EXT_COMPUTER_WINDOWSREGISTRY",
    ] {
        check(
            seen.get(e).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0) > 0,
            &format!("{e} described"),
        )?;
    }
    let member = if lab.windows() {
        "Domain Users"
    } else {
        "GG-Nantes-Direction"
    };
    check(
        yes(&seen, "LETTRE", "X") && seen.get("FILTRE").is_some_and(|f| f.ends_with(member)),
        "drive and its targeting",
    )?;
    check(
        yes(&seen, "REGISTRE", "Cible,Exclu,Negation,Liste"),
        "registry elements in order",
    )
}

fn preferences_applied(lab: &Lab) -> Result<()> {
    println!("2. applied by the station");
    copy_sysvol(lab)?;
    let t = Instant::now();
    gpupdate("computer")?;
    let machine = lines(&labo::poste(
        &format!(
            "$k = Get-ItemProperty 'HKLM:\\{J7F_KEY}' -ErrorAction SilentlyContinue\n\
             'MACHINE=' + $k.Machine; 'AUTRE=' + $k.AutreMachine"
        ),
        &[],
    )?);
    let session = session_user(
        &format!("(Get-ItemProperty \"$hku\\{J7F_KEY}\" -ErrorAction SilentlyContinue).Cible"),
        &format!(
            "'NETUSE=' + (Get-ItemProperty \"$hku\\Network\\X\" -ErrorAction SilentlyContinue).RemotePath\n\
             'RACCOURCI=' + (Test-Path $bureau)\n\
             $k = Get-ItemProperty \"$hku\\{J7F_KEY}\" -ErrorAction SilentlyContinue\n\
             'CIBLE=' + $k.Cible; 'EXCLU=' + $k.Exclu; 'NEGATION=' + $k.Negation; 'LISTE=' + ($k.Liste -join '|')"
        ),
    )?;
    println!(
        "  {:.0} s: {machine:?} {session:?}",
        t.elapsed().as_secs_f64()
    );
    check(
        yes(&machine, "MACHINE", "Machine") && yes(&machine, "AUTRE", ""),
        "computer: the targeted value only",
    )?;
    check(yes(&session, "ATTENTE", "True"), "the session received it")?;
    check(
        session
            .get("NETUSE")
            .is_some_and(|n| n.eq_ignore_ascii_case(&format!("\\\\{}\\{SHARE}", lab.pdc_name()))),
        "drive X: mapped",
    )?;
    check(
        yes(&session, "RACCOURCI", "True"),
        "shortcut on the desktop",
    )?;
    check(
        yes(&session, "CIBLE", "oui") && yes(&session, "LISTE", "a|b"),
        "targeted values present",
    )?;
    check(
        yes(&session, "EXCLU", "") && yes(&session, "NEGATION", ""),
        "values of the negative targeting absent",
    )
}

fn preferences_of_the_gpmc(trial: &Trial, lab: &Lab, yes_group: &EditableFilter) -> Result<()> {
    println!("3. preferences of the GPMC changed by the core without loss");
    let made = gpmc(
        lab,
        &format!(
            "$g = New-GPO -Name '{J7F_GPMC}'; \"GUID=\" + $g.Id\n\
             Set-GPPrefRegistryValue -Guid $g.Id -Context User -Action Update -Key 'HKCU\\{J7F_KEY}' -ValueName 'Garde' -Value 'gpmc' -Type String | Out-Null\n\
             Set-GPPrefRegistryValue -Guid $g.Id -Context User -Action Replace -Key 'HKCU\\{J7F_KEY}' -ValueName 'Change' -Value 5 -Type DWord | Out-Null\n"
        ),
        false,
    )?;
    let guid = format!("{{{}}}", made.get("GUID").ok_or("GUID")?.to_uppercase());
    let dn = w::gpo_dn(&trial.base, &guid);
    let before = read_preferences(trial, &dn, Part::User)?;
    let file = before.file(Family::Registry).ok_or("registry")?;
    let content = file.content.clone().ok_or("content")?;
    let elements = file.elements();
    let [keep, change] = elements.as_slice() else {
        return Err(format!("{} elements of the GPMC", elements.len()).into());
    };
    check(
        change.property("value").as_deref() == Some("00000005"),
        "DWORD of the GPMC read (5)",
    )?;
    let properties: Vec<(String, String)> = change
        .properties()
        .into_iter()
        .map(|(k, v)| {
            if k == "value" {
                (k, "00000009".to_owned())
            } else {
                (k, v)
            }
        })
        .collect();
    let changed = gpp::modify_element(
        change,
        change.name(),
        change.status(),
        &properties,
        &change.common(),
        &[Filter::Editable(yes_group.clone())],
        gpp::now(),
        Some(&[]),
    );
    let added = registry_element("HKEY_CURRENT_USER", "Ajout", "REG_SZ", "outil", "U", &[])?;
    let (keep_raw, keep_value) = (
        keep.raw.clone().ok_or("raw bytes of the element")?,
        keep.property("value").unwrap_or_default(),
    );
    write_preferences(
        trial,
        &dn,
        Part::User,
        Family::Registry,
        vec![
            gp::Operation::Replace {
                uid: change.uid().to_owned(),
                element: changed,
            },
            gp::Operation::Add(added),
        ],
    )?;
    let after = read_preferences(trial, &dn, Part::User)?;
    let after = after
        .file(Family::Registry)
        .and_then(|f| f.content.clone())
        .ok_or("content after")?;
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    check(
        contains(&after, &keep_raw),
        "the element of the GPMC, byte for byte",
    )?;
    let head = content
        .windows(10)
        .position(|w| w == b"<Registry ")
        .ok_or("<Registry")?;
    check(
        after.starts_with(&content[..head]),
        "the header of the GPMC kept",
    )?;
    let seen = gpmc(
        lab,
        &format!(
            "[xml]$r = Get-GPOReport -Guid '{guid}' -ReportType Xml\n\
             foreach ($x in $r.GPO.User.ExtensionData.Extension.RegistrySettings.Registry) {{ \"V_\" + $x.Properties.name.ToUpper() + \"=\" + $x.Properties.value + \";\" + $x.Properties.action }}\n\
             \"FILTRE=\" + (($r.GPO.User.ExtensionData.Extension.RegistrySettings.Registry | ? {{ $_.Properties.name -eq 'Change' }}).Filters.FilterGroup.name)\n\
             \"VERSION=\" + (Get-GPO -Guid '{guid}').User.DSVersion + \"/\" + (Get-GPO -Guid '{guid}').User.SysvolVersion\n"
        ),
        false,
    )?;
    println!("  GPMC reads again: {seen:?}");
    // The report rather than Get-GPPrefRegistryValue: on Windows Server 2025, the
    // GroupPolicy module loses the last character of a string when writing and reading.
    check(
        yes(&seen, "V_GARDE", &format!("{keep_value};U")),
        "the element of the GPMC unchanged",
    )?;
    check(yes(&seen, "V_CHANGE", "00000009;R"), "the element changed")?;
    check(yes(&seen, "V_AJOUT", "outil;U"), "the element added")?;
    let member = if lab.windows() {
        "Domain Users"
    } else {
        "GG-Nantes-Direction"
    };
    check(
        seen.get("FILTRE").is_some_and(|f| f.ends_with(member)),
        "the targeting added",
    )?;
    let (a, s) = seen
        .get("VERSION")
        .and_then(|v| v.split_once('/'))
        .ok_or("version")?;
    check(a == s, "versions equal")
}

fn preferences_removed(trial: &Trial, lab: &Lab, dn: &str) -> Result<()> {
    println!("4. every element turned into a deletion");
    for part in [Part::Computer, Part::User] {
        let read = read_preferences(trial, dn, part)?;
        for file in &read.files {
            let mut operations = Vec::new();
            for e in file.elements() {
                let registry = file.family == Family::Registry;
                let properties: Vec<(String, String)> = e
                    .properties()
                    .into_iter()
                    .map(|(k, v)| match k.as_str() {
                        "action" => (k, "D".to_owned()),
                        "value" if registry => (k, String::new()),
                        _ => (k, v),
                    })
                    .collect();
                let element = gpp::modify_element(
                    e,
                    e.name(),
                    e.status(),
                    &properties,
                    &e.common(),
                    &[],
                    gpp::now(),
                    registry.then_some(&[][..]),
                );
                operations.push(gp::Operation::Replace {
                    uid: e.uid().to_owned(),
                    element,
                });
            }
            if !operations.is_empty() {
                write_preferences(trial, dn, part, file.family, operations)?;
            }
        }
        // The key itself, that the values deleted leave empty.
        let hive = if part == Part::Computer {
            "HKEY_LOCAL_MACHINE"
        } else {
            "HKEY_CURRENT_USER"
        };
        write_preferences(
            trial,
            dn,
            part,
            Family::Registry,
            vec![gp::Operation::Add(registry_element(
                hive,
                "",
                "REG_SZ",
                "",
                "D",
                &[],
            )?)],
        )?;
    }
    if lab.windows() {
        return Ok(());
    }
    copy_sysvol(lab)?;
    gpupdate("computer")?;
    let machine = lines(&labo::poste(
        &format!("'CLE=' + (Test-Path 'HKLM:\\{J7F_KEY}')"),
        &[],
    )?);
    let session = session_user(
        &format!(
            "-not (Test-Path \"$hku\\{J7F_KEY}\") -and -not (Test-Path $bureau) -and -not (Test-Path \"$hku\\Network\\X\")"
        ),
        &format!(
            "'NETUSE=' + (Test-Path \"$hku\\Network\\X\")\n'RACCOURCI=' + (Test-Path $bureau)\n\
             'CLE=' + (Test-Path \"$hku\\{J7F_KEY}\")"
        ),
    )?;
    println!("  after the removal: {session:?} {machine:?}");
    check(
        ["ATTENTE", "NETUSE", "RACCOURCI", "CLE"]
            .iter()
            .zip(["True", "False", "False", "False"])
            .all(|(k, v)| yes(&session, k, v)),
        "the station removed drive, shortcut and key",
    )?;
    check(
        yes(&machine, "CLE", "False"),
        "the key of the computer removed",
    )
}

fn preferences_trial(trial: &Trial, lab: &Lab) -> Result<()> {
    let netbios = gp::netbios_name(&trial.connection).map_err(debug)?;
    println!("NetBIOS name: {netbios}");
    let (dn, guid) = create(trial, J7F_NAME)?;
    if !lab.windows() {
        for sam in ["herve.humbert2", &format!("{STATION}$")] {
            link(trial, &parent_of(trial, sam)?, &dn)?;
        }
    }
    let (oui, non) = groups(trial, lab, &netbios)?;
    preferences_written(trial, lab, &dn, &guid, &oui, &non)?;
    if !lab.windows() {
        preferences_applied(lab)?;
    }
    preferences_of_the_gpmc(trial, lab, &oui)?;
    preferences_removed(trial, lab, &dn)
}

#[test]
#[ignore = "lab"]
fn gpmc_preferences() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("gpmc-preferences")?;
    let trial = Trial::new(&lab, &scratch)?;
    clean(&trial, J7F, None)?;
    let done = share(&lab, true).and_then(|()| preferences_trial(&trial, &lab));
    println!("5. cleaning");
    let cleaned = clean(&trial, J7F, None)
        .and_then(|()| check(trial_gpos(&trial, J7F)?.is_empty(), "no GPO of trial left"))
        .and_then(|()| copy_sysvol(&lab))
        .and_then(|()| share(&lab, false));
    trial.connection.join();
    done.and(cleaned)
}

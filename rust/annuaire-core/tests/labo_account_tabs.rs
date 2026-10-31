// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The account tabs of the sheet against the lab (J9.3, ADR 0024), on LAB.TEST and WIN.TEST,
//! under `OU=Essais-J93,OU=Labo`. Every write is a changeset of the common path, built as the
//! sheet builds it (`writer::prepare_modification`, the values removed and added of a
//! multi-valued attribute, `actions::protect`), and its effect is checked where it counts:
//!
//! - **logon hours**: no hour allowed, `kinit` and `smbclient` (NTLM) refused; the current
//!   local hour allowed from a local grid (offset of the machine of the trial), the bit of the
//!   current UTC hour checked independently, granted; every hour but the current one, refused;
//!   the undo brings the attribute back absent;
//! - **workstations**: `userWorkstations` set, `smbclient` granted under the name listed and
//!   refused under another; what `kinit` does said;
//! - **delegation**: S4U by `kvno -I … -P` from the service account: refused without
//!   delegation; granted in constrained delegation with protocol transition; refused « Kerberos
//!   only » (the evidence ticket of S4U2Self is not forwardable); unconstrained: the ticket of
//!   the service has `ok-as-delegate`; resource-based (RBCD descriptor on the target, written
//!   by the SDDL codec), granted, then refused once emptied;
//! - **SPN**: the owner found on the global catalog, the duplicate refused or not by the DC
//!   (said);
//! - **protection**: the deletion of a protected account refused, permitted once the
//!   protection is removed; a protection set by the domain's own tool (`Set-ADObject
//!   -ProtectedFromAccidentalDeletion` on WIN.TEST, `samba-tool dsacl set` on LAB.TEST) read;
//! - on WIN.TEST, every value compared with `Get-ADUser -Properties`, and the RBCD descriptor
//!   written by `Set-ADUser -PrincipalsAllowedToDelegateToAccount` compared with Calinda's.
//!
//! Passwords drawn at random, never shown, given to `kinit` on its standard input and to
//! `smbclient` by a file of the scratch folder (mode 600). See `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use annuaire_codecs::logon_hours::{self, LogonHours};
use annuaire_codecs::uac::UserAccountControl;
use annuaire_core::account_tabs::{self as tabs, Delegation};
use annuaire_core::changes::{Change, Changeset, Issue, Operation, Report, Values};
use annuaire_core::{actions, writer};

use labo::{Lab, Result, Trial, check, debug};

const USER: &str = "j93-user";
const SERVICE: &str = "j93-svc";
const TARGET: &str = "j93-cible";
const STATION: &str = "J93POSTE";

struct Accounts {
    user: String,
    service: String,
    target: String,
    user_secret: String,
    service_secret: String,
}

fn changeset(operation: Operation) -> Changeset {
    Changeset {
        operations: vec![operation],
        remarks: Vec::new(),
    }
}

/// The attributes given these values, as the sheet writes its inputs (one `Modify`, read
/// again on the PDC); None if nothing changes.
fn set(trial: &Trial, dn: &str, wanted: Vec<(&str, Values)>) -> Result<Option<Report>> {
    let wanted = wanted.into_iter().map(|(a, v)| (a.to_owned(), v)).collect();
    match writer::prepare_modification(&trial.connection, dn, wanted).map_err(debug)? {
        Some(operation) => Ok(Some(trial.apply(&changeset(operation))?)),
        None => Ok(None),
    }
}

/// Values removed and added of a multi-valued attribute, as the sheet writes a list.
fn change(
    trial: &Trial,
    dn: &str,
    attribute: &str,
    removed: Values,
    added: Values,
) -> Result<Report> {
    let read = writer::read_version(&trial.connection, dn)
        .map_err(debug)?
        .ok_or("object absent")?;
    trial.apply(&changeset(
        Operation::modify(
            dn,
            vec![Change::new(attribute, removed, added).map_err(debug)?],
            Some(read),
        )
        .map_err(debug)?,
    ))
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

fn uac(trial: &Trial, dn: &str) -> Result<u32> {
    let object = trial.read_one(dn)?;
    let value: i64 = object.text("userAccountControl").trim().parse()?;
    Ok((value & 0xFFFF_FFFF) as u32)
}

/// The delegation of the service account as the tab writes it: flags of `userAccountControl`
/// and list of the services, in one `Modify`.
fn delegate(trial: &Trial, dn: &str, choice: Delegation, services: &[&str]) -> Result<()> {
    let flags = choice.uac(uac(trial, dn)?);
    let services: Values = if choice.keeps_services() {
        services.iter().map(|s| bytes(s)).collect()
    } else {
        Vec::new()
    };
    set(
        trial,
        dn,
        vec![
            (
                "userAccountControl",
                vec![bytes(&UserAccountControl(flags).encode().to_string())],
            ),
            (tabs::DELEGATE_TO, services),
        ],
    )?;
    check(
        Delegation::of(uac(trial, dn)?, services_of(trial, dn)?.len()) == choice,
        &format!("delegation read back as {choice:?}"),
    )
}

fn services_of(trial: &Trial, dn: &str) -> Result<Vec<String>> {
    Ok(trial
        .read_with(&[dn], &[tabs::DELEGATE_TO])?
        .first()
        .map(|o| {
            o.values(tabs::DELEGATE_TO)
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect()
        })
        .unwrap_or_default())
}

fn netbios(lab: &Lab) -> String {
    lab.domain
        .split('.')
        .next()
        .unwrap_or_default()
        .to_uppercase()
}

/// `smbclient` to the NETLOGON share of the PDC, NTLM, under the station name `station`:
/// None if granted, else the status the server gave.
fn smb(
    lab: &Lab,
    scratch: &labo::Scratch,
    account: &str,
    secret: &str,
    station: &str,
) -> Result<Option<String>> {
    let file = scratch.path().join("smb-auth");
    std::fs::write(
        &file,
        format!(
            "username = {account}\npassword = {secret}\ndomain = {}\n",
            netbios(lab)
        ),
    )?;
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
    let result = labo::run(
        Command::new("smbclient")
            .arg(format!("//{}/NETLOGON", lab.pdc_name()))
            .arg("-A")
            .arg(&file)
            .args(["--use-kerberos=off", "-n", station, "-c", "ls"]),
        b"",
    );
    std::fs::remove_file(&file)?;
    Ok(result.err().map(|e| {
        let text = e.to_string();
        text.split_whitespace()
            .find(|w| w.starts_with("NT_STATUS_"))
            .map_or(text.clone(), str::to_owned)
    }))
}

/// `kvno` in the cache of the service account: S4U2Self for the user then, with `-P`,
/// S4U2Proxy to `target`. None if granted, else the message.
fn s4u(kdc: &labo::Kdc, user: &str, target: &str) -> Option<String> {
    let mut command = Command::new("kvno");
    command.args(["-I", user, "-P", target]);
    for (key, value) in kdc.env("svc") {
        command.env(key, value);
    }
    labo::run(&mut command, b"").err().map(|e| {
        e.to_string()
            .lines()
            .filter(|l| l.contains("kvno") || l.contains("KDC") || l.contains("while"))
            .collect::<Vec<_>>()
            .join(" ")
    })
}

/// A fresh ticket of the service account in the cache `svc`, forwardable (`kinit -f`): the
/// KDC makes the evidence ticket of S4U2Self forwardable only from a forwardable TGT.
fn service_ticket(kdc: &labo::Kdc, lab: &Lab, accounts: &Accounts) -> Result<()> {
    kdc.destroy("svc");
    let mut kinit = Command::new("kinit");
    kinit.args(["-f", &format!("{SERVICE}@{}", lab.realm())]);
    for (key, value) in kdc.env("svc") {
        kinit.env(key, value);
    }
    let granted = labo::run(
        &mut kinit,
        format!("{}\n", accounts.service_secret).as_bytes(),
    );
    check(granted.is_ok(), "ticket of the service account")
}

/// Hour of the UTC week now (0: Sunday 00:00 UTC), and the next one.
fn utc_hour_now() -> (usize, usize) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let days = seconds / 86_400;
    // 1970-01-01 was a Thursday (4).
    let weekday = (days + 4) % 7;
    let hour = (weekday * 24 + (seconds % 86_400) / 3600) as usize;
    (hour, (hour + 1) % logon_hours::HOURS)
}

/// Offset of the local time of this machine, in hours (`date +%z`).
fn local_offset() -> Result<i32> {
    let text = labo::run(Command::new("date").arg("+%z"), b"")?;
    let text = text.trim();
    let sign: i64 = if text.starts_with('-') { -1 } else { 1 };
    let digits = text.trim_start_matches(['+', '-']);
    let hours: i64 = digits.get(..2).unwrap_or("0").parse()?;
    let minutes: i64 = digits.get(2..4).unwrap_or("0").parse()?;
    Ok(logon_hours::offset_hours(
        sign * (hours * 3600 + minutes * 60),
    ))
}

fn wdc(script: &str) -> Result<String> {
    labo::poste(script, &["--cible", "wdc"])
}

/// `Get-ADUser -Properties` of an account, as `KEY=value` lines.
fn windows_account(sam: &str) -> Result<std::collections::BTreeMap<String, String>> {
    let script = format!(
        "$u = Get-ADUser -Identity '{sam}' -Properties logonHours,LogonWorkstations,\
TrustedForDelegation,TrustedToAuthForDelegation,'msDS-AllowedToDelegateTo',\
ServicePrincipalNames,ProtectedFromAccidentalDeletion,PrincipalsAllowedToDelegateToAccount\n\
\"HOURS=$(if ($u.logonHours) {{ [BitConverter]::ToString($u.logonHours) }})\"\n\
\"STATIONS=$($u.LogonWorkstations)\"\n\
\"T4D=$($u.TrustedForDelegation)\"\n\
\"T2A=$($u.TrustedToAuthForDelegation)\"\n\
\"SERVICES=$(($u.'msDS-AllowedToDelegateTo' | Sort-Object) -join ',')\"\n\
\"SPNS=$(($u.ServicePrincipalNames | Sort-Object) -join ',')\"\n\
\"PROTECTED=$($u.ProtectedFromAccidentalDeletion)\"\n\
\"RBCD=$(($u.PrincipalsAllowedToDelegateToAccount | Sort-Object) -join ';')\"\n"
    );
    Ok(labo::lines(&wdc(&script)?))
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join("-")
}

#[test]
#[ignore = "lab"]
fn account_tabs() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("onglets-compte")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, &lab.pdc_name())?;
    let labo_ou = format!("OU=Labo,{}", trial.base);
    let ou = trial.fresh_ou(&labo_ou, "Essais-J93")?;
    let result = run(&lab, &trial, &kdc, &scratch, &ou);
    for cache in ["svc", "user", "essai"] {
        kdc.destroy(cache);
    }
    let removed = trial.remove_tree(&ou);
    trial.connection.join();
    result?;
    removed
}

fn create(trial: &Trial, ou: &str, sam: &str, spn: Option<&str>) -> Result<(String, String)> {
    let secret = labo::password(28);
    trial.apply(
        &actions::create_user(
            ou,
            &actions::NewUser {
                full_name: sam.into(),
                identifier: sam.into(),
                password: Some(secret.clone()),
                enable: true,
                ..actions::NewUser::default()
            },
        )
        .map_err(debug)?,
    )?;
    let dn = format!("CN={sam},{ou}");
    if let Some(spn) = spn {
        change(trial, &dn, tabs::SPN, Vec::new(), vec![bytes(spn)])?;
    }
    Ok((dn, secret))
}

#[allow(clippy::too_many_lines)]
fn run(lab: &Lab, trial: &Trial, kdc: &labo::Kdc, scratch: &labo::Scratch, ou: &str) -> Result<()> {
    let realm = lab.realm();
    let host = |name: &str| format!("{name}.{}", lab.domain);
    let target_spn = format!("cifs/{}", host(TARGET));
    let service_spn = format!("HTTP/{}", host(SERVICE));

    println!("1. three accounts: a user, a service account, a target service");
    let (user, user_secret) = create(trial, ou, USER, None)?;
    let (service, service_secret) = create(trial, ou, SERVICE, Some(&service_spn))?;
    let (target, _) = create(trial, ou, TARGET, Some(&target_spn))?;
    let accounts = Accounts {
        user,
        service,
        target,
        user_secret,
        service_secret,
    };
    let principal = format!("{USER}@{realm}");
    check(
        kdc.granted(&principal, &accounts.user_secret),
        "the user gets a ticket",
    )?;
    check(
        smb(lab, scratch, USER, &accounts.user_secret, "AUTRE")?.is_none(),
        "the user connects by NTLM",
    )?;

    hours(lab, trial, kdc, scratch, &accounts, &principal)?;
    workstations(lab, trial, kdc, scratch, &accounts, &principal)?;
    delegation(lab, trial, kdc, &accounts, &target_spn, &service_spn)?;
    spns(trial, &accounts, &service_spn)?;
    protection(lab, trial, &accounts, ou)
}

fn hours(
    lab: &Lab,
    trial: &Trial,
    kdc: &labo::Kdc,
    scratch: &labo::Scratch,
    accounts: &Accounts,
    principal: &str,
) -> Result<()> {
    println!("2. logon hours");
    let dn = &accounts.user;
    let report = set(
        trial,
        dn,
        vec![(tabs::LOGON_HOURS, vec![LogonHours::none().encode()])],
    )?
    .ok_or("logonHours unchanged")?;
    let refused = kdc.refusal(principal, &accounts.user_secret);
    println!("  kinit outside of the hours: {refused:?}");
    check(refused.is_some(), "no hour allowed: kinit refused")?;
    let status = smb(lab, scratch, USER, &accounts.user_secret, "AUTRE")?;
    println!("  smbclient outside of the hours: {status:?}");
    check(
        status.as_deref() == Some("NT_STATUS_INVALID_LOGON_HOURS"),
        "no hour allowed: NTLM refused (NT_STATUS_INVALID_LOGON_HOURS)",
    )?;
    // The inverse of the write brings the attribute back absent.
    let undo = trial.undo(&report)?;
    check(undo.issue == Issue::Applied, "undo of the write")?;
    let read = trial.read_with(&[dn], &[tabs::LOGON_HOURS])?;
    check(
        read.first()
            .is_some_and(|o| o.values(tabs::LOGON_HOURS).is_empty()),
        "logonHours absent again after the undo",
    )?;
    check(
        kdc.granted(principal, &accounts.user_secret),
        "attribute absent: every hour allowed",
    )?;

    // The grid in local time, as the tab shows it: the current local hour and the next.
    let offset = local_offset()?;
    let (now, next) = utc_hour_now();
    let local = |utc: usize| {
        let h = (i64::try_from(utc).unwrap_or(0) + i64::from(offset)).rem_euclid(168);
        let h = usize::try_from(h).unwrap_or(0);
        (h / 24, h % 24)
    };
    let mut grid = [[false; 24]; 7];
    for utc in [now, next] {
        let (day, hour) = local(utc);
        grid[day][hour] = true;
    }
    let allowed = LogonHours::from_local_grid(&grid, offset);
    check(
        allowed.0[now] && allowed.0[next] && allowed.allowed() == 2,
        &format!("local grid (UTC{offset:+}) gives the bits of the UTC hours {now} and {next}"),
    )?;
    set(trial, dn, vec![(tabs::LOGON_HOURS, vec![allowed.encode()])])?;
    check(
        kdc.granted(principal, &accounts.user_secret),
        "the current hour allowed: kinit granted",
    )?;
    check(
        smb(lab, scratch, USER, &accounts.user_secret, "AUTRE")?.is_none(),
        "the current hour allowed: NTLM granted",
    )?;
    let mut others = LogonHours::default();
    others.0[now] = false;
    others.0[next] = false;
    set(trial, dn, vec![(tabs::LOGON_HOURS, vec![others.encode()])])?;
    check(
        kdc.refusal(principal, &accounts.user_secret).is_some(),
        "every hour but the current one: kinit refused",
    )?;
    if lab.windows() {
        let seen = windows_account(USER)?;
        check(
            seen.get("HOURS").map(String::as_str) == Some(hex(&others.encode()).as_str()),
            "Get-ADUser reads the same 21 bytes",
        )?;
    }
    set(trial, dn, vec![(tabs::LOGON_HOURS, Vec::new())])?;
    check(
        kdc.granted(principal, &accounts.user_secret),
        "attribute emptied: every hour allowed",
    )
}

fn workstations(
    lab: &Lab,
    trial: &Trial,
    kdc: &labo::Kdc,
    scratch: &labo::Scratch,
    accounts: &Accounts,
    principal: &str,
) -> Result<()> {
    println!("3. logon workstations");
    let dn = &accounts.user;
    set(
        trial,
        dn,
        vec![(
            tabs::WORKSTATIONS,
            vec![bytes(&format!("{STATION},J93AUTRE"))],
        )],
    )?;
    let listed = smb(lab, scratch, USER, &accounts.user_secret, STATION)?;
    check(listed.is_none(), "NTLM granted from a station of the list")?;
    let other = smb(lab, scratch, USER, &accounts.user_secret, "AUTRE")?;
    println!("  smbclient from another station: {other:?}");
    check(
        other.as_deref() == Some("NT_STATUS_INVALID_WORKSTATION"),
        "NTLM refused from another station (NT_STATUS_INVALID_WORKSTATION)",
    )?;
    let kinit = kdc.refusal(principal, &accounts.user_secret);
    println!("  kinit without address, list set: {kinit:?}");
    if lab.windows() {
        let seen = windows_account(USER)?;
        check(
            seen.get("STATIONS").map(String::as_str) == Some("J93POSTE,J93AUTRE"),
            "Get-ADUser reads LogonWorkstations",
        )?;
    }
    set(trial, dn, vec![(tabs::WORKSTATIONS, Vec::new())])?;
    check(
        smb(lab, scratch, USER, &accounts.user_secret, "AUTRE")?.is_none(),
        "list emptied: NTLM granted from any station",
    )
}

fn delegation(
    lab: &Lab,
    trial: &Trial,
    kdc: &labo::Kdc,
    accounts: &Accounts,
    target_spn: &str,
    service_spn: &str,
) -> Result<()> {
    println!("4. delegation");
    let service = &accounts.service;
    service_ticket(kdc, lab, accounts)?;
    let refused = s4u(kdc, USER, target_spn);
    println!("  S4U without delegation: {refused:?}");
    check(refused.is_some(), "no delegation: S4U2Proxy refused")?;

    delegate(
        trial,
        service,
        Delegation::Constrained { any_protocol: true },
        &[target_spn],
    )?;
    service_ticket(kdc, lab, accounts)?;
    let granted = s4u(kdc, USER, target_spn);
    check(
        granted.is_none(),
        &format!(
            "constrained with protocol transition: S4U2Self and S4U2Proxy granted ({granted:?})"
        ),
    )?;
    if lab.windows() {
        let seen = windows_account(SERVICE)?;
        check(
            seen.get("T2A").map(String::as_str) == Some("True")
                && seen.get("T4D").map(String::as_str) == Some("False")
                && seen.get("SERVICES").map(String::as_str) == Some(target_spn),
            "Get-ADUser: TrustedToAuthForDelegation and msDS-AllowedToDelegateTo",
        )?;
    }

    delegate(
        trial,
        service,
        Delegation::Constrained {
            any_protocol: false,
        },
        &[target_spn],
    )?;
    service_ticket(kdc, lab, accounts)?;
    let kerberos_only = s4u(kdc, USER, target_spn);
    println!("  S4U « Kerberos only »: {kerberos_only:?}");
    check(
        kerberos_only.is_some(),
        "constrained « Kerberos only »: S4U2Proxy refused from a protocol transition",
    )?;

    delegate(trial, service, Delegation::Unconstrained, &[])?;
    check(
        services_of(trial, service)?.is_empty(),
        "unconstrained: the list of services emptied",
    )?;
    kdc.destroy("user");
    check(
        kdc.kinit_into(
            &format!("{USER}@{}", lab.realm()),
            &accounts.user_secret,
            "user",
        )
        .is_none(),
        "ticket of the user",
    )?;
    let mut kvno = Command::new("kvno");
    kvno.arg(service_spn);
    let mut klist = Command::new("klist");
    klist.arg("-f");
    for (key, value) in kdc.env("user") {
        kvno.env(&key, &value);
        klist.env(key, value);
    }
    labo::run(&mut kvno, b"")?;
    let listed = labo::run(&mut klist, b"")?;
    let flags = listed
        .split(service_spn)
        .nth(1)
        .and_then(|rest| rest.split("Flags: ").nth(1))
        .and_then(|f| f.split_whitespace().next())
        .unwrap_or_default()
        .to_owned();
    check(
        flags.contains('O'),
        &format!("unconstrained: the ticket of the service is ok-as-delegate (flags {flags})"),
    )?;
    if lab.windows() {
        let seen = windows_account(SERVICE)?;
        check(
            seen.get("T4D").map(String::as_str) == Some("True"),
            "Get-ADUser: TrustedForDelegation",
        )?;
    }

    println!("5. resource-based constrained delegation");
    delegate(trial, service, Delegation::None, &[])?;
    let service_sid = trial.sid(service)?;
    let present = trial
        .read_with(&[&accounts.target], &[tabs::RBCD])?
        .first()
        .map(|o| o.values(tabs::RBCD))
        .unwrap_or_default();
    let value = tabs::rbcd_value(&present, &[service_sid]).map_err(debug)?;
    let writable = tabs::rbcd_writable(&trial.connection, &accounts.target).map_err(debug)?;
    check(
        writable == lab.windows(),
        &format!("allowedAttributesEffective: RBCD writable {writable}"),
    )?;
    if !lab.windows() {
        return samba_rbcd(trial, kdc, lab, accounts, target_spn, &value);
    }
    let report =
        set(trial, &accounts.target, vec![(tabs::RBCD, value.clone())])?.ok_or("RBCD unchanged")?;
    let read = trial
        .read_with(&[&accounts.target], &[tabs::RBCD])?
        .first()
        .map(|o| o.values(tabs::RBCD))
        .unwrap_or_default();
    check(
        tabs::rbcd_sids(&read).map_err(debug)? == vec![service_sid],
        &format!(
            "descriptor read back: {}",
            tabs::rbcd_sddl(&read).map_err(debug)?.unwrap_or_default()
        ),
    )?;
    service_ticket(kdc, lab, accounts)?;
    let granted = s4u(kdc, USER, target_spn);
    check(
        granted.is_none(),
        &format!("RBCD: S4U2Proxy granted without delegation on the service account ({granted:?})"),
    )?;
    if lab.windows() {
        let seen = windows_account(TARGET)?;
        check(
            seen.get("RBCD").is_some_and(|r| r.contains(SERVICE)),
            "Get-ADUser: PrincipalsAllowedToDelegateToAccount",
        )?;
    }
    // Emptied by the inverse of the write, refused again.
    let undo = trial.undo(&report)?;
    check(undo.issue == Issue::Applied, "undo of the RBCD write")?;
    let read = trial
        .read_with(&[&accounts.target], &[tabs::RBCD])?
        .first()
        .map(|o| o.values(tabs::RBCD))
        .unwrap_or_default();
    check(read.is_empty(), "RBCD attribute absent after the undo")?;
    service_ticket(kdc, lab, accounts)?;
    check(
        s4u(kdc, USER, target_spn).is_some(),
        "RBCD emptied: S4U2Proxy refused",
    )?;
    if lab.windows() {
        // The descriptor Windows writes, compared with Calinda's.
        wdc(&format!(
            "Set-ADUser -Identity '{TARGET}' -PrincipalsAllowedToDelegateToAccount (Get-ADUser -Identity '{SERVICE}')\n"
        ))?;
        let windows = trial
            .read_with(&[&accounts.target], &[tabs::RBCD])?
            .first()
            .map(|o| o.values(tabs::RBCD))
            .unwrap_or_default();
        let (theirs, ours) = (
            tabs::rbcd_sddl(&windows).map_err(debug)?,
            tabs::rbcd_sddl(&value).map_err(debug)?,
        );
        println!("  Windows: {theirs:?}");
        check(
            theirs == ours,
            "the descriptor written by Windows, in SDDL, is Calinda's",
        )?;
        check(
            tabs::rbcd_sids(&windows).map_err(debug)? == vec![service_sid],
            "and read by Calinda as the service account",
        )?;
        set(trial, &accounts.target, vec![(tabs::RBCD, Vec::new())])?;
    }
    Ok(())
}

/// Samba 4.22 declares the attribute `systemOnly` in its schema (Windows does not): the DC
/// refuses the write over LDAP, and only `samba-tool delegation add-principal`, on the DC's
/// own database, writes it. The descriptor Samba writes is read, and works.
fn samba_rbcd(
    trial: &Trial,
    kdc: &labo::Kdc,
    lab: &Lab,
    accounts: &Accounts,
    target_spn: &str,
    value: &Values,
) -> Result<()> {
    let schema = labo::entries(
        &trial.connection,
        &format!("CN=Schema,CN=Configuration,{}", trial.base),
        annuaire_core::session::Scope::OneLevel,
        &format!("(lDAPDisplayName={})", tabs::RBCD),
        &["systemOnly"],
    )?;
    check(
        schema
            .first()
            .is_some_and(|e| labo::text(e, "systemOnly") == "TRUE"),
        "Samba's schema: systemOnly TRUE",
    )?;
    let operation = writer::prepare_modification(
        &trial.connection,
        &accounts.target,
        vec![(tabs::RBCD.to_owned(), value.clone())],
    )
    .map_err(debug)?
    .ok_or("RBCD unchanged")?;
    let outcome = trial.outcome(&changeset(operation), None, None)?;
    let message = outcome
        .report
        .error
        .as_ref()
        .map(|e| e.message.clone())
        .unwrap_or_default();
    println!(
        "  written over LDAP: {:?} {message} {:?}",
        outcome.report.issue, outcome.problems
    );
    // Refused by the prior verification: Samba does not quote a systemOnly attribute in
    // allowedAttributesEffective (written anyway, the DC answers « can only be modified as
    // system »).
    check(
        outcome.report.issue == Issue::Refused && !outcome.problems.is_empty(),
        "Calinda's write refused before writing (attribute systemOnly, not writable)",
    )?;
    let tool = |verb: &str| {
        labo::ssh(
            "dc1",
            &format!("sudo samba-tool delegation {verb} {TARGET} {SERVICE} >/dev/null\n"),
        )
    };
    tool("add-principal")?;
    let read = trial
        .read_with(&[&accounts.target], &[tabs::RBCD])?
        .first()
        .map(|o| o.values(tabs::RBCD))
        .unwrap_or_default();
    println!(
        "  Samba: {}",
        tabs::rbcd_sddl(&read).map_err(debug)?.unwrap_or_default()
    );
    check(
        tabs::rbcd_sids(&read).map_err(debug)? == vec![trial.sid(&accounts.service)?],
        "the descriptor written by samba-tool read as the service account",
    )?;
    service_ticket(kdc, lab, accounts)?;
    let granted = s4u(kdc, USER, target_spn);
    println!("  RBCD, evidence not forwardable: {granted:?}");
    delegate(
        trial,
        &accounts.service,
        Delegation::Constrained { any_protocol: true },
        &[],
    )?;
    service_ticket(kdc, lab, accounts)?;
    let forwardable = s4u(kdc, USER, target_spn);
    println!("  RBCD, protocol transition allowed: {forwardable:?}");
    delegate(trial, &accounts.service, Delegation::None, &[])?;
    // Samba 4.22 grants the resource-based delegation only from a forwardable evidence
    // ticket (protocol transition allowed on the service account); Windows also from a
    // non-forwardable one (MS-SFU 3.2.5.2.2).
    check(
        forwardable.is_none(),
        "RBCD with protocol transition: S4U2Proxy granted",
    )?;
    tool("del-principal")?;
    service_ticket(kdc, lab, accounts)?;
    check(
        s4u(kdc, USER, target_spn).is_some(),
        "RBCD emptied: S4U2Proxy refused",
    )
}

fn spns(trial: &Trial, accounts: &Accounts, service_spn: &str) -> Result<()> {
    println!("6. service principal names");
    let owners = tabs::spn_owners(&trial.connection, service_spn, &accounts.user).map_err(debug)?;
    check(
        owners
            .iter()
            .any(|o| o.eq_ignore_ascii_case(&accounts.service)),
        &format!("global catalog: {service_spn} belongs to {SERVICE}"),
    )?;
    let upper = service_spn.to_uppercase();
    check(
        tabs::spn_owners(&trial.connection, &upper, &accounts.service)
            .map_err(debug)?
            .is_empty(),
        "the account itself is left out, the case does not count",
    )?;
    let read = writer::read_version(&trial.connection, &accounts.user)
        .map_err(debug)?
        .ok_or("user absent")?;
    let duplicate = changeset(
        Operation::modify(
            &accounts.user,
            vec![Change::new(tabs::SPN, Vec::new(), vec![bytes(service_spn)]).map_err(debug)?],
            Some(read),
        )
        .map_err(debug)?,
    );
    let outcome = trial.outcome(&duplicate, None, None)?;
    println!(
        "  duplicate written directly: {:?} {:?}",
        outcome.report.issue,
        outcome.report.error.as_ref().map(|e| &e.message)
    );
    if outcome.report.issue == Issue::Applied {
        change(
            trial,
            &accounts.user,
            tabs::SPN,
            vec![bytes(service_spn)],
            Vec::new(),
        )?;
    }
    Ok(())
}

fn protection(lab: &Lab, trial: &Trial, accounts: &Accounts, ou: &str) -> Result<()> {
    println!("7. protection against accidental deletion");
    let dn = &accounts.user;
    let read = trial.descriptors(&[dn, ou])?;
    let [object, parent] = read.as_slice() else {
        return Err("descriptors".into());
    };
    let protect = actions::protect(object, parent).map_err(debug)?;
    check(
        protect.operations.len() == 2,
        "deny on the account and deny of deleting children on its OU",
    )?;
    trial.apply(&protect)?;
    check(
        tabs::read_protection(&trial.connection, dn).map_err(debug)? == Some(true),
        "read back as protected",
    )?;
    if lab.windows() {
        check(
            windows_account(USER)?.get("PROTECTED").map(String::as_str) == Some("True"),
            "Get-ADUser: ProtectedFromAccidentalDeletion",
        )?;
    }
    let delete = actions::delete(&[trial.read_one(dn)?]).map_err(debug)?;
    let outcome = trial.outcome(&delete, None, None)?;
    println!(
        "  deletion: {:?} {:?}",
        outcome.report.issue,
        outcome.report.error.as_ref().map(|e| &e.message)
    );
    check(
        outcome.report.issue != Issue::Applied && trial.exists(dn)?,
        "the deletion of the protected account refused",
    )?;
    let object = trial.descriptors(&[dn])?.pop().ok_or("descriptor")?;
    trial.apply(&actions::unprotect(&object).map_err(debug)?)?;
    check(
        tabs::read_protection(&trial.connection, dn).map_err(debug)? == Some(false),
        "unticked: read back as not protected",
    )?;
    trial.apply(&actions::delete(&[trial.read_one(dn)?]).map_err(debug)?)?;
    check(!trial.exists(dn)?, "then the deletion permitted")?;

    // A protection set by the domain's own tool, read as such.
    let target = &accounts.target;
    if lab.windows() {
        wdc(&format!(
            "Set-ADObject -Identity '{target}' -ProtectedFromAccidentalDeletion $true\n"
        ))?;
    } else {
        labo::ssh(
            "dc1",
            &format!(
                "sudo samba-tool dsacl set -H /var/lib/samba/private/sam.ldb --objectdn={} --sddl='(D;;SDDT;;;WD)' >/dev/null\n",
                labo::quote(target)
            ),
        )?;
    }
    check(
        tabs::read_protection(&trial.connection, target).map_err(debug)? == Some(true),
        "a protection set by the domain's tool is read",
    )?;
    let object = trial.descriptors(&[target])?.pop().ok_or("descriptor")?;
    trial.apply(&actions::unprotect(&object).map_err(debug)?)?;
    check(
        tabs::read_protection(&trial.connection, target).map_err(debug)? == Some(false),
        "and removed by Calinda",
    )?;
    if lab.windows() {
        let seen = labo::lines(&wdc(&format!(
            "\"PROTECTED=$((Get-ADObject -Identity '{target}' -Properties ProtectedFromAccidentalDeletion).ProtectedFromAccidentalDeletion)\"\n"
        ))?);
        check(
            seen.get("PROTECTED").map(String::as_str) == Some("False"),
            "Get-ADObject: no longer protected",
        )?;
    }
    Ok(())
}

// --- Trial of the interface -------------------------------------------------------------------

const UI_OU: &str = "Essais-J93-UI";

/// `ANNUAIRE_LABO_ONGLETS`: `preparer` (OU `Essais-J93-UI` under `OU=Labo`: `j93-ui-user`,
/// `j93-ui-svc` with `HTTP/j93-ui-svc.<domain>`, `j93-ui-cible` with
/// `cifs/j93-ui-cible.<domain>`), `verifier` (what `tests/interface/essais-onglets.txt`
/// wrote through the sheet, read back), `nettoyer` (all removed).
#[test]
#[ignore = "lab"]
fn account_tabs_interface() -> Result<()> {
    let Ok(what) = std::env::var("ANNUAIRE_LABO_ONGLETS") else {
        return Ok(());
    };
    let lab = labo::lab();
    let scratch = labo::Scratch::new("onglets-interface")?;
    let trial = Trial::new(&lab, &scratch)?;
    let labo_ou = format!("OU=Labo,{}", trial.base);
    let ou = format!("OU={UI_OU},{labo_ou}");
    let host = |name: &str| format!("{name}.{}", lab.domain);
    let result = match what.as_str() {
        "preparer" => {
            let ou = trial.fresh_ou(&labo_ou, UI_OU)?;
            for (name, spn) in [
                ("j93-ui-user", None),
                ("j93-ui-svc", Some(format!("HTTP/{}", host("j93-ui-svc")))),
                (
                    "j93-ui-cible",
                    Some(format!("cifs/{}", host("j93-ui-cible"))),
                ),
            ] {
                let (dn, _) = create(&trial, &ou, name, spn.as_deref())?;
                println!("PREPARED {dn}");
            }
            Ok(())
        }
        "verifier" => verify_interface(&lab, &trial, &ou),
        _ => trial.remove_tree(&ou),
    };
    trial.connection.join();
    result
}

fn verify_interface(lab: &Lab, trial: &Trial, ou: &str) -> Result<()> {
    let user = format!("CN=j93-ui-user,{ou}");
    let service = format!("CN=j93-ui-svc,{ou}");
    let target = format!("CN=j93-ui-cible,{ou}");
    let read = trial.read_with(&[&user], &[tabs::LOGON_HOURS, tabs::WORKSTATIONS])?;
    let user_read = read.first().ok_or("user")?;
    // Monday to Friday, 08:00 to 18:00 in the local time of the interface (this machine).
    let offset = local_offset()?;
    let mut grid = [[false; 24]; 7];
    for row in grid.iter_mut().skip(1).take(5) {
        for cell in row.iter_mut().skip(8).take(10) {
            *cell = true;
        }
    }
    let expected = LogonHours::from_local_grid(&grid, offset).encode();
    check(
        user_read.values(tabs::LOGON_HOURS) == vec![expected.clone()],
        &format!("logonHours written by the sheet: {}", hex(&expected)),
    )?;
    check(
        user_read.text(tabs::WORKSTATIONS) == "J93POSTE,J93AUTRE",
        "userWorkstations written as ADUC does (no space)",
    )?;
    check(
        tabs::read_protection(&trial.connection, &user).map_err(debug)? == Some(true),
        "user protected against deletion",
    )?;
    let parent = trial.descriptors(&[ou])?.pop().ok_or("OU")?;
    let parent_sd = annuaire_codecs::sd::SecurityDescriptor::decode(
        parent.values(actions::SD).first().ok_or("descriptor")?,
    )
    .map_err(debug)?;
    check(
        actions::parent_protected(&parent_sd),
        "deny of deleting children on the OU",
    )?;
    let delegation = Delegation::of(uac(trial, &service)?, services_of(trial, &service)?.len());
    check(
        delegation == Delegation::Constrained { any_protocol: true },
        "service: constrained delegation, any protocol",
    )?;
    let target_spn = format!("cifs/j93-ui-cible.{}", lab.domain);
    check(
        services_of(trial, &service)? == vec![target_spn],
        "service: msDS-AllowedToDelegateTo chosen",
    )?;
    let spns = trial
        .read_with(&[&service], &[tabs::SPN])?
        .first()
        .map(|o| o.values(tabs::SPN))
        .unwrap_or_default();
    check(
        spns.contains(&bytes(&format!("HTTP/j93-ui-autre.{}", lab.domain))),
        "service: the SPN added",
    )?;
    let user_spns = trial
        .read_with(&[&user], &[tabs::SPN])?
        .first()
        .map(|o| o.values(tabs::SPN))
        .unwrap_or_default();
    check(
        user_spns.is_empty(),
        "the duplicate SPN was not written on the user",
    )?;
    if lab.windows() {
        let rbcd = trial
            .read_with(&[&target], &[tabs::RBCD])?
            .first()
            .map(|o| o.values(tabs::RBCD))
            .unwrap_or_default();
        check(
            tabs::rbcd_sids(&rbcd).map_err(debug)? == vec![trial.sid(&service)?],
            "target: RBCD written by the sheet",
        )?;
        let seen = windows_account("j93-ui-svc")?;
        check(
            seen.get("T2A").map(String::as_str) == Some("True"),
            "Get-ADUser of the service: TrustedToAuthForDelegation",
        )?;
        let seen = windows_account("j93-ui-user")?;
        check(
            seen.get("PROTECTED").map(String::as_str) == Some("True")
                && seen.get("HOURS").map(String::as_str) == Some(hex(&expected).as_str()),
            "Get-ADUser of the user: protected, logon hours",
        )?;
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Computer accounts and contacts against the lab (J9.2, ADR 0024), on LAB.TEST and WIN.TEST,
//! under `OU=Essais-J92,OU=Labo`. Every write is a changeset of the common path:
//!
//! - the rule of the DC read (`computers::read_rule`): Samba accepts the default password of a
//!   computer whatever the policy, Windows Server 2025 holds it to the complexity;
//! - a computer « pre-Windows 2000 »: where the DC accepts it, `userAccountControl` 4128,
//!   `sAMAccountName` `NAME$`, a ticket granted to `NAME$` with the name in lower case; where it
//!   does not, refused before any write (and the DC's own refusal checked by a direct write);
//! - a computer without the option: 4128, the default password refused (random, unknown);
//! - « Reset Account »: the name in lower case granted again, or a random password where the
//!   DC would refuse it;
//! - the ACEs of the joiner on the account, read back from the DC and found by
//!   `computers::joiners`;
//! - a contact, read back by the oracle of the domain (`ldbsearch` on dc1, `Get-ADObject` on
//!   wdc1).
//!
//! The real join of the station of the lab to an account created here is a separate procedure
//! (`labo/README.md`, « Jonction à un compte précréé »). Passwords never shown: given to `kinit`
//! on its standard input.

#![allow(clippy::indexing_slicing)]

mod labo;

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_core::actions;
use annuaire_core::computers::{self, NewComputer, NewContact};

use labo::{Kdc, Lab, Result, Trial, check, debug};

const OU: &str = "Essais-J92";
const GROUP: &str = "J92-Jonction";
const PRE_2000: &str = "J92PC1";
const RANDOM: &str = "J92PC2";
const CONTACT: &str = "Jeanne Dupré-J92";

fn uac(trial: &Trial, dn: &str) -> Result<i64> {
    Ok(trial
        .read_one(dn)?
        .text("userAccountControl")
        .trim()
        .parse()?)
}

#[test]
#[ignore = "lab: needs the DCs of the lab and an administrator ticket"]
fn computers_and_contacts() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j92")?;
    let trial = Trial::new(&lab, &scratch)?;
    let parent = format!("OU=Labo,{}", trial.base);
    let ou = trial.fresh_ou(&parent, OU)?;
    let kdc = Kdc::new(&lab, &trial.dc)?;
    let realm = lab.realm();

    // The delegated group (empty: the join itself is a separate procedure).
    trial.apply(
        &actions::create_group(
            &ou,
            GROUP,
            GROUP,
            annuaire_codecs::uac::Scope::Global,
            true,
            "",
        )
        .map_err(debug)?,
    )?;
    let group_sid = trial.sid(&format!("CN={GROUP},{ou}"))?;

    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let principal = |name: &str| format!("{name}$@{realm}");
    let created = |name: &str, pre_windows_2000: bool| -> Result<String> {
        let report = trial.apply(
            &computers::create_computer(
                &ou,
                &NewComputer {
                    name: name.into(),
                    pre_windows_2000,
                    ..NewComputer::default()
                },
                &rule,
            )
            .map_err(debug)?,
        )?;
        report
            .changeset
            .operations
            .first()
            .map(|o| o.dn().to_owned())
            .ok_or_else(|| "no dn".into())
    };
    println!(
        "  rule of {}: samba {}, complexity {}, {} characters at least; default of {PRE_2000} accepted: {}",
        trial.dc,
        rule.samba,
        rule.complex,
        rule.min_length,
        rule.accepts_default(PRE_2000)
    );
    check(rule.samba == !lab.windows(), "vendor of the DC")?;

    // Pre-Windows 2000: the name in lower case is the password, where the DC accepts it.
    let pc1 = if rule.accepts_default(PRE_2000) {
        let pc1 = created(PRE_2000, true)?;
        check(
            kdc.granted(&principal(PRE_2000), &computers::default_password(PRE_2000)),
            "pre-Windows 2000: ticket with the name in lower case",
        )?;
        println!("  {PRE_2000}: pre-Windows 2000, ticket granted with the default password");
        pc1
    } else {
        check(
            matches!(
                computers::create_computer(
                    &ou,
                    &NewComputer {
                        name: PRE_2000.into(),
                        pre_windows_2000: true,
                        ..NewComputer::default()
                    },
                    &rule,
                ),
                Err(actions::ActionError::DefaultPasswordRefused(_))
            ),
            "pre-Windows 2000 refused before any write",
        )?;
        let pc1 = created(PRE_2000, false)?;
        // The DC's own refusal, by a direct write of the default password.
        let object = trial.read_one(&pc1)?;
        let direct = annuaire_core::changes::Changeset {
            operations: vec![
                annuaire_core::changes::Operation::modify(
                    &pc1,
                    vec![
                        annuaire_core::changes::Change::new(
                            "unicodePwd",
                            Vec::new(),
                            vec![
                                actions::encode_password(&computers::default_password(PRE_2000))
                                    .map_err(debug)?,
                            ],
                        )
                        .map_err(debug)?,
                    ],
                    Some(object.read.clone()),
                )
                .map_err(debug)?,
            ],
            remarks: Vec::new(),
        };
        let outcome = trial.outcome(&direct, None, None)?;
        check(
            outcome.report.issue != annuaire_core::changes::Issue::Applied,
            "the DC refuses the default password itself",
        )?;
        println!(
            "  {PRE_2000}: pre-Windows 2000 refused before the write; the DC refuses the default password ({:?})",
            outcome
                .report
                .error
                .map(|e| e.message.lines().next().unwrap_or_default().to_owned())
        );
        pc1
    };
    check(
        uac(&trial, &pc1)? == i64::from(computers::COMPUTER_UAC),
        "userAccountControl 4128",
    )?;
    check(
        trial.read_one(&pc1)?.text("sAMAccountName") == format!("{PRE_2000}$"),
        "sAMAccountName NAME$",
    )?;

    // Without the option: random, the default password refused.
    let pc2 = created(RANDOM, false)?;
    let refused = kdc.refusal(&principal(RANDOM), &computers::default_password(RANDOM));
    check(refused.is_some(), "random password: default refused")?;
    println!("  {RANDOM}: 4128, default password refused");

    // Reset Account: the default password again, or a random one.
    let object = trial.read_one(&pc2)?;
    let (reset, default) = computers::reset_computer(&object, &rule).map_err(debug)?;
    trial.apply(&reset)?;
    check(
        default == rule.accepts_default(RANDOM),
        "reset: default password when the DC accepts it",
    )?;
    check(
        kdc.granted(&principal(RANDOM), &computers::default_password(RANDOM)) == default,
        "reset: ticket with the name in lower case only if it was set",
    )?;
    println!(
        "  {RANDOM}: reset, default password {}",
        if default {
            "set and granted"
        } else {
            "refused by the rule, random set"
        }
    );

    // The joiner: four ACEs on the object, read back.
    let read = trial.descriptors(&[pc1.as_str()])?;
    let object = read.first().ok_or("descriptor")?;
    trial.apply(&computers::allow_join(object, &group_sid).map_err(debug)?)?;
    let raw = trial.descriptor(&pc1)?;
    let descriptor = SecurityDescriptor::decode(&raw).map_err(debug)?;
    check(
        computers::joiners(&descriptor).contains(&group_sid),
        "joiner found in the descriptor read back",
    )?;
    let again = trial.descriptors(&[pc1.as_str()])?;
    check(
        computers::allow_join(again.first().ok_or("descriptor")?, &group_sid)
            .map_err(debug)?
            .operations
            .is_empty(),
        "joiner already there: nothing to write",
    )?;
    println!("  {PRE_2000}: four ACEs of the joiner written and read back");

    // A contact, read by the oracle of the domain.
    trial.apply(
        &computers::create_contact(
            &ou,
            &NewContact {
                full_name: CONTACT.into(),
                given_name: "Jeanne".into(),
                surname: "Dupré".into(),
                display_name: CONTACT.into(),
                mail: "jeanne.dupre@example.org".into(),
                telephone: "+596 596 00 00 00".into(),
                street: "1 rue de la Liberté".into(),
                postal_code: "97200".into(),
                city: "Fort-de-France".into(),
                ..NewContact::default()
            },
        )
        .map_err(debug)?,
    )?;
    let contact_dn = format!("CN={CONTACT},{ou}");
    let oracle = if lab.windows() {
        labo::poste(
            &format!(
                "$o = Get-ADObject -Identity '{contact_dn}' -Properties telephoneNumber,l,postalCode,mail\n\
                 \"CLASS=$($o.ObjectClass)\"; \"PHONE=$($o.telephoneNumber)\"; \"CITY=$($o.l)\"; \
                 \"ZIP=$($o.postalCode)\"; \"MAIL=$($o.mail)\""
            ),
            &["--cible", "wdc"],
        )?
    } else {
        labo::ssh(
            "dc1",
            &format!(
                "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -b {} -s base \
                 objectClass telephoneNumber l postalCode mail | \
                 sed -n 's/^objectClass: contact$/CLASS=contact/p; s/^telephoneNumber: /PHONE=/p; \
                 s/^l:: .*/CITY=b64/p; s/^l: /CITY=/p; s/^postalCode: /ZIP=/p; s/^mail: /MAIL=/p'\n",
                labo::quote(&contact_dn)
            ),
        )?
    };
    let lines = labo::lines(&oracle);
    check(
        lines.get("CLASS").is_some_and(|c| c == "contact"),
        &format!("contact class read by the oracle: {oracle}"),
    )?;
    check(
        lines.get("PHONE").map(String::as_str) == Some("+596 596 00 00 00")
            && lines.get("ZIP").map(String::as_str) == Some("97200")
            && lines.get("MAIL").map(String::as_str) == Some("jeanne.dupre@example.org"),
        &format!("contact attributes read by the oracle: {oracle}"),
    )?;
    println!("  contact read by the oracle of {}", lab.domain);

    trial.remove_tree(&ou)?;
    Ok(())
}

// --- The real join of the station of the lab ----------------------------------------------------

const JOIN_OU: &str = "Jonction-J92";
const JOIN_GROUP: &str = "J92-Joindre";
const JOIN_USER: &str = "j92.joindre";
/// The station of the lab (VM 125), its NetBIOS name.
const STATION: &str = "ANNUAIRE-POSTE1";

/// Where the account of the station is created: `ANNUAIRE_LABO_JONCTION_OU`, otherwise the OU of
/// the LAPS trial on WIN.TEST, and the place the station had on LAB.TEST.
fn station_parent(lab: &Lab, base: &str) -> String {
    std::env::var("ANNUAIRE_LABO_JONCTION_OU").unwrap_or_else(|_| {
        if lab.windows() {
            format!("OU=LAPS-Essai,OU=Labo,{base}")
        } else {
            format!("OU=Ordinateurs,OU=Direction,OU=Nantes,OU=Labo,{base}")
        }
    })
}

/// The DNS servers of the station in the domain aimed at.
fn station_dns(lab: &Lab) -> &'static str {
    if lab.windows() {
        "'192.168.1.210'"
    } else {
        "'192.168.1.27','192.168.1.28'"
    }
}

/// Waits until the station answers by its guest agent, after a restart.
fn station_back(what: &str) -> Result<()> {
    std::thread::sleep(std::time::Duration::from_secs(60));
    labo::wait(std::time::Duration::from_secs(900), what, || {
        Ok(labo::poste("'UP=1'", &["--voie", "agent"])
            .map(|o| o.contains("UP=1"))
            .unwrap_or(false))
    })?;
    Ok(())
}

/// The station of the lab joined to an account created by Calinda for a delegated group, by an
/// ordinary member of that group (`ANNUAIRE_LABO_JONCTION=1`; moves the station of domain:
/// see `labo/README.md`, « Jonction à un compte précréé »).
#[test]
#[ignore = "lab: moves the station of the lab to the domain aimed at"]
fn join_precreated() -> Result<()> {
    if std::env::var("ANNUAIRE_LABO_JONCTION").as_deref() != Ok("1") {
        println!("  ANNUAIRE_LABO_JONCTION=1 not set: skipped");
        return Ok(());
    }
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j92-jonction")?;
    let trial = Trial::new(&lab, &scratch)?;
    let labo_ou = format!("OU=Labo,{}", trial.base);
    let ou = format!("OU={JOIN_OU},{labo_ou}");
    if !trial.exists(&ou)? {
        trial.apply(
            &actions::create_ou(&labo_ou, JOIN_OU, "J9.2 : jonction déléguée").map_err(debug)?,
        )?;
    }
    // The delegated group and its ordinary member, password drawn again at each run.
    let group = format!("CN={JOIN_GROUP},{ou}");
    if !trial.exists(&group)? {
        trial.apply(
            &actions::create_group(
                &ou,
                JOIN_GROUP,
                JOIN_GROUP,
                annuaire_codecs::uac::Scope::Global,
                true,
                "",
            )
            .map_err(debug)?,
        )?;
    }
    let user = format!("CN={JOIN_USER},{ou}");
    let secret = labo::password(24);
    if trial.exists(&user)? {
        trial.apply(
            &actions::reset_password(&trial.read_one(&user)?, &secret, false).map_err(debug)?,
        )?;
    } else {
        trial.apply(
            &actions::create_user(
                &ou,
                &actions::NewUser {
                    full_name: JOIN_USER.into(),
                    identifier: JOIN_USER.into(),
                    password: Some(secret.clone()),
                    enable: true,
                    ..actions::NewUser::default()
                },
            )
            .map_err(debug)?,
        )?;
    }
    let members = trial.read_with(&[group.as_str()], &["member"])?;
    if !members.first().is_some_and(|g| {
        g.values("member")
            .iter()
            .any(|m| m.eq_ignore_ascii_case(user.as_bytes()))
    }) {
        let read = annuaire_core::writer::read_version(&trial.connection, &group)
            .map_err(debug)?
            .ok_or("group absent")?;
        trial.apply(&annuaire_core::changes::Changeset {
            operations: vec![
                annuaire_core::changes::Operation::modify(
                    &group,
                    vec![
                        annuaire_core::changes::Change::new(
                            "member",
                            Vec::new(),
                            vec![user.as_bytes().to_vec()],
                        )
                        .map_err(debug)?,
                    ],
                    Some(read),
                )
                .map_err(debug)?,
            ],
            remarks: Vec::new(),
        })?;
    }
    let group_sid = trial.sid(&group)?;

    // The old account of the station in this domain goes; Calinda creates it again.
    let old = labo::entries(
        &trial.connection,
        &trial.base,
        annuaire_core::session::Scope::Subtree,
        &format!("(sAMAccountName={STATION}$)"),
        &["1.1"],
    )?;
    for entry in &old {
        trial.remove_tree(&entry.dn)?;
        println!("  old account removed: {}", entry.dn);
    }
    let parent = station_parent(&lab, &trial.base);
    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let report = trial.apply(
        &computers::create_computer(
            &parent,
            &NewComputer {
                name: STATION.into(),
                ..NewComputer::default()
            },
            &rule,
        )
        .map_err(debug)?,
    )?;
    let account = report
        .changeset
        .operations
        .first()
        .map(|o| o.dn().to_owned())
        .ok_or("no dn")?;
    let read = trial.descriptors(&[account.as_str()])?;
    trial.apply(
        &computers::allow_join(read.first().ok_or("descriptor")?, &group_sid).map_err(debug)?,
    )?;
    let created = trial.read_with(&[account.as_str()], &["pwdLastSet", "userAccountControl"])?;
    let pwd_before = created
        .first()
        .map(|o| o.text("pwdLastSet"))
        .unwrap_or_default();
    println!("  {account}: created by Calinda, {JOIN_GROUP} allowed to join it");

    // The station leaves its domain locally (the account it leaves is not touched).
    let left = labo::poste(
        "$r = (Get-CimInstance Win32_ComputerSystem | Invoke-CimMethod -MethodName UnjoinDomainOrWorkgroup -Arguments @{FUnjoinOptions = [uint32]0}).ReturnValue\n\
         \"UNJOIN=$r\"\n\
         $w = (Get-CimInstance Win32_ComputerSystem | Invoke-CimMethod -MethodName JoinDomainOrWorkgroup -Arguments @{Name = 'LABO'}).ReturnValue\n\
         \"WORKGROUP=$w\"\n\
         shutdown /r /t 15 /c 'J9.2'",
        &["--voie", "agent"],
    )?;
    let lines = labo::lines(&left);
    check(
        lines.get("WORKGROUP").map(String::as_str) == Some("0"),
        &format!("station in a workgroup: {left}"),
    )?;
    println!(
        "  station out of its domain (unjoin {})",
        lines.get("UNJOIN").cloned().unwrap_or_default()
    );
    station_back("station back in its workgroup")?;

    // DNS of the domain, then the join under the ordinary member of the group.
    let joined = labo::poste_secret(
        &format!(
            "$a = Get-NetAdapter | Where-Object Status -eq 'Up' | Select-Object -First 1\n\
             Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ServerAddresses {}\n\
             Clear-DnsClientCache\n\
             $c = New-Object PSCredential('{}\\{JOIN_USER}', (ConvertTo-SecureString '@MDP@' -AsPlainText -Force))\n\
             try {{ Add-Computer -DomainName {} -Credential $c -Force -ErrorAction Stop; 'JOIN=ok' }} \
             catch {{ \"JOIN=$($_.Exception.Message)\" }}",
            station_dns(&lab),
            lab.domain
                .split('.')
                .next()
                .unwrap_or_default()
                .to_uppercase(),
            lab.domain
        ),
        &secret,
        &["--voie", "agent"],
    )?;
    let lines = labo::lines(&joined);
    check(
        lines.get("JOIN").map(String::as_str) == Some("ok"),
        &format!(
            "join by {JOIN_USER}: {}",
            lines.get("JOIN").cloned().unwrap_or_default()
        ),
    )?;
    println!("  Add-Computer by {JOIN_USER} (member of {JOIN_GROUP} only): accepted");
    labo::poste("shutdown /r /t 15 /c 'J9.2'", &["--voie", "agent"])?;
    station_back("station back in the domain")?;

    // What the join wrote on the account, and the secure channel of the station.
    let after = trial.read_with(
        &[account.as_str()],
        &[
            "pwdLastSet",
            "userAccountControl",
            "dNSHostName",
            "servicePrincipalName",
        ],
    )?;
    let after = after.first().ok_or("account gone")?;
    let host = format!("{}.{}", STATION.to_lowercase(), lab.domain);
    // The join keeps PASSWD_NOTREQD on an account made before it (4128, measured on both
    // domains): it sets the password, the DNS name and the SPNs only.
    let flags: i64 = after.text("userAccountControl").trim().parse()?;
    check(
        flags & 0x1000 != 0 && flags & 0x2 == 0,
        "workstation trust account, enabled, after the join",
    )?;
    println!("  userAccountControl after the join: {flags}");
    check(
        after.text("pwdLastSet") != pwd_before,
        "password set by the station",
    )?;
    check(
        after.text("dNSHostName").eq_ignore_ascii_case(&host),
        "dNSHostName written by the station",
    )?;
    check(
        after
            .values("servicePrincipalName")
            .iter()
            .any(|v| String::from_utf8_lossy(v).eq_ignore_ascii_case(&format!("HOST/{host}"))),
        "SPN written by the station",
    )?;
    let channel = labo::lines(&labo::poste(
        "\"CHANNEL=$(Test-ComputerSecureChannel)\"; \"DOMAIN=$((Get-CimInstance Win32_ComputerSystem).Domain)\"",
        &["--voie", "agent"],
    )?);
    check(
        channel.get("CHANNEL").map(String::as_str) == Some("True"),
        &format!("secure channel of the station: {channel:?}"),
    )?;
    println!(
        "  joined to {}: password, dNSHostName and SPN written, secure channel {}",
        channel.get("DOMAIN").cloned().unwrap_or_default(),
        channel.get("CHANNEL").cloned().unwrap_or_default()
    );
    Ok(())
}

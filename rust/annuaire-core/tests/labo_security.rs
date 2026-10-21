// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Security descriptors against the lab (port of `test_securite_labo.py` and of the
//! conditional ACEs of `test_pso_ace_labo.py`, ADR 0020).
//!
//! - `security_sddl_as_samba_tool`: on 200 varied objects (users, groups, computers, OUs,
//!   system containers, configuration and schema, GPOs, DNS nodes, objects protected by
//!   AdminSDHolder), the SDDL of the core, read by LDAP with SD flags 15, is the output of
//!   `samba-tool dsacl get` on dc1, character for character.
//! - `security_nomenclature`: the GUIDs of the delegation templates are those of the schema, a
//!   GUID that names three things is told apart by the mask of the ACE.
//! - `security_reading`: whole reading (SACL, ancestors, names), origin of each inherited ACE.
//! - `security_delegation`: under `OU=Essais-J4`, a group of trial receives three delegations on
//!   `OU=Cible`; a member account, in a process of its own with its own ticket, resets a
//!   password, changes the members of a group and creates a computer in `OU=Cible`, and fails
//!   in `OU=Hors`. Delegation removed: the same account fails everywhere and the descriptor of
//!   the OU is back byte for byte. Undo by the journaled inverse, optimistic guard. Nothing left
//!   on dc1 nor dc2 (`ldbsearch`), replication `ALL GOOD`.
//! - `security_conditional_aces` (LAB.TEST and WIN.TEST): on an account of `OU=Essais-FB`, the
//!   core adds `(XA;;WP;;;AU;(Member_of {SID(<group>)}))` and, typed with `SID(DA)`, a second one
//!   written with the full SID; read again as the native tool reads them (`samba-tool dsacl
//!   get`, or the Win32 form and `Get-Acl` on Windows); a member of the group writes the
//!   description of the target, an account outside of it cannot (each in a process of its own);
//!   removal: original descriptor byte for byte.
//!
//! The passwords of the accounts of trial are drawn at random, never shown, and go to `kinit`
//! and to the child by their standard input. See `labo/mod.rs`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::time::{Duration, Instant};

use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_codecs::{Sid, sddl};
use annuaire_core::changes::{Change, Changeset, Issue, Operation};
use annuaire_core::error::code;
use annuaire_core::schema;
use annuaire_core::search::{SD_SACL, SD_WITHOUT_SACL};
use annuaire_core::security::{self, Kind, Template};
use annuaire_core::session::{Modification, Scope};
use annuaire_core::{actions, writer};
use serde_json::{Value as Json, json};

use labo::{Lab, Result, Trial, check, debug, entries, samba_only};

// --- Child: what an account of trial does, with its own ticket ----------------------------------

/// One LDAP write, in the child: « permis », « refusé », or the error.
fn attempt(
    connection: &annuaire_core::Connection,
    write: impl FnMut(&mut annuaire_core::Link) -> std::result::Result<(), annuaire_core::LdapError>
    + Send
    + 'static,
) -> String {
    match connection.run(false, write) {
        Ok(()) => "permis".into(),
        Err(annuaire_core::connection::Failure::Ldap { error, .. })
            if error.code == code::INSUFFICIENT_ACCESS =>
        {
            "refusé".into()
        }
        Err(e) => format!("erreur {e:?}").chars().take(160).collect(),
    }
}

/// Run by the trials in a process of its own, under the ticket of an account of trial: the
/// tasks given on its standard input (passwords included), the result of each one.
#[test]
#[ignore = "lab"]
fn security_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let asked: Json = serde_json::from_str(&input)?;
    let lab = labo::lab();
    let (connection, _) = lab.pdc();
    let mut results = BTreeMap::new();
    for task in asked["tasks"].as_array().ok_or("tasks")? {
        let name = task["name"].as_str().ok_or("name")?.to_owned();
        let dn = task["dn"].as_str().ok_or("dn")?.to_owned();
        let outcome = match task["kind"].as_str().ok_or("kind")? {
            "password" => {
                let secret = asked["secrets"][task["secret"].as_str().ok_or("secret")?]
                    .as_str()
                    .ok_or("secret")?;
                let mut changes = vec![Modification::Replace(
                    "unicodePwd".into(),
                    vec![actions::encode_password(secret).map_err(debug)?],
                )];
                if task["change"] == true {
                    changes.push(Modification::Replace(
                        "pwdLastSet".into(),
                        vec![b"0".to_vec()],
                    ));
                }
                attempt(&connection, move |link| {
                    let id = link.session.modify(&dn, changes.clone(), Vec::new())?;
                    link.session.result(id, Some(link.timeout)).map(|_| ())
                })
            }
            "member" => {
                let member = task["member"].as_str().ok_or("member")?.as_bytes().to_vec();
                attempt(&connection, move |link| {
                    let change = Modification::Add("member".into(), vec![member.clone()]);
                    let id = link.session.modify(&dn, vec![change], Vec::new())?;
                    link.session.result(id, Some(link.timeout)).map(|_| ())
                })
            }
            "computer" => {
                let sam = task["sam"].as_str().ok_or("sam")?.as_bytes().to_vec();
                attempt(&connection, move |link| {
                    let attributes = vec![
                        (
                            "objectClass".to_owned(),
                            ["top", "person", "organizationalPerson", "user", "computer"]
                                .iter()
                                .map(|c| c.as_bytes().to_vec())
                                .collect(),
                        ),
                        ("sAMAccountName".to_owned(), vec![sam.clone()]),
                        ("userAccountControl".to_owned(), vec![b"4096".to_vec()]),
                    ];
                    let id = link.session.add(&dn, attributes, Vec::new())?;
                    link.session.result(id, Some(link.timeout)).map(|_| ())
                })
            }
            "description" => {
                let value = task["value"].as_str().ok_or("value")?.as_bytes().to_vec();
                attempt(&connection, move |link| {
                    let change = Modification::Replace("description".into(), vec![value.clone()]);
                    let id = link.session.modify(&dn, vec![change], Vec::new())?;
                    link.session.result(id, Some(link.timeout)).map(|_| ())
                })
            }
            "security" => match security::read_security(&connection, &dn) {
                Ok(Some(read)) => format!(
                    "lu sacl={} dacl={}",
                    read.sacl_read,
                    read.descriptor.dacl.map_or(0, |d| d.aces.len())
                ),
                Ok(None) => "absent".into(),
                Err(e) => format!("erreur {e:?}").chars().take(160).collect(),
            },
            other => format!("tâche inconnue {other}"),
        };
        results.insert(name, outcome);
    }
    connection.join();
    println!("RESULT {}", serde_json::to_string(&results)?);
    Ok(())
}

/// A ticket for `principal` in the cache `cache` of `kdc`, asked again for 30 s (an account
/// just created).
fn ticket(kdc: &labo::Kdc, principal: &str, secret: &str, cache: &str) -> Result<()> {
    let mut last = None;
    for _ in 0..15 {
        match kdc.kinit_into(principal, secret, cache) {
            None => return Ok(()),
            Some(refusal) => last = Some(refusal),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(format!("no ticket for {principal}: {}", last.unwrap_or_default()).into())
}

/// The tasks done by `account` in a child, with its ticket asked of the PDC.
fn as_account(
    lab: &Lab,
    kdc: &labo::Kdc,
    account: &str,
    secret: &str,
    tasks: &Json,
    secrets: &Json,
) -> Result<BTreeMap<String, String>> {
    let cache = format!("cc-{account}");
    ticket(kdc, &format!("{account}@{}", lab.realm()), secret, &cache)?;
    let input = json!({"tasks": tasks, "secrets": secrets}).to_string();
    let result = labo::child("security_child", &kdc.env(&cache), &input);
    kdc.destroy(&cache);
    Ok(serde_json::from_str(&result?)?)
}

fn user(parent: &str, name: &str, sam: &str, domain: &str, secret: &str) -> Result<Changeset> {
    actions::create_user(
        parent,
        &actions::NewUser {
            full_name: name.into(),
            identifier: sam.into(),
            upn: format!("{sam}@{domain}"),
            password: Some(secret.into()),
            change_at_next_logon: false,
            enable: true,
            ..actions::NewUser::default()
        },
    )
    .map_err(debug)
}

fn add_member(trial: &Trial, group: &str, member: &str) -> Result<()> {
    let change =
        Change::new("member", Vec::new(), vec![member.as_bytes().to_vec()]).map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![Operation::modify(group, vec![change], None).map_err(debug)?],
        remarks: Vec::new(),
    })?;
    Ok(())
}

fn group(trial: &Trial, parent: &str, name: &str) -> Result<String> {
    trial.apply(
        &actions::create_group(parent, name, "", GroupScope::Global, true, "").map_err(debug)?,
    )?;
    Ok(format!("CN={name},{parent}"))
}

// --- 1. SDDL as samba-tool --------------------------------------------------------------------

fn sorted_dns(
    trial: &annuaire_core::Connection,
    base: &str,
    filter: &str,
    scope: Scope,
) -> Result<Vec<String>> {
    let mut dns: Vec<String> = entries(trial, base, scope, filter, &["1.1"])?
        .into_iter()
        .map(|e| e.dn)
        .collect();
    dns.sort_by_key(|d| d.to_lowercase());
    Ok(dns)
}

fn at_steps(dns: &[String], n: usize) -> Vec<String> {
    if dns.len() <= n {
        return dns.to_vec();
    }
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    let step = dns.len() as f64 / n as f64;
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    (0..n)
        .map(|i| dns[(i as f64 * step) as usize].clone())
        .collect()
}

/// 200 objects chosen reproducibly (sorted DNs, taken at regular steps), by category.
fn sample(
    connection: &annuaire_core::Connection,
    base: &str,
) -> Result<Vec<(String, Vec<String>)>> {
    let root = connection
        .run(true, |link| Ok(link.state.root_dse.clone()))
        .map_err(debug)?;
    let (config, schema) = (
        root.configuration_naming_context,
        root.schema_naming_context,
    );
    let system: Vec<String> = [
        base.to_owned(),
        format!("CN=System,{base}"),
        format!("CN=AdminSDHolder,CN=System,{base}"),
        format!("CN=Users,{base}"),
        format!("CN=Computers,{base}"),
        format!("CN=Builtin,{base}"),
        format!("CN=ForeignSecurityPrincipals,{base}"),
        format!("OU=Domain Controllers,{base}"),
        format!("CN=Policies,CN=System,{base}"),
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{base}"),
        format!("CN=Infrastructure,{base}"),
        format!("CN=LostAndFound,{base}"),
        format!("CN=Program Data,{base}"),
        config.clone(),
        format!("CN=Partitions,{config}"),
        format!("CN=Sites,{config}"),
        format!("CN=Extended-Rights,{config}"),
        format!("CN=User-Force-Change-Password,CN=Extended-Rights,{config}"),
        schema.clone(),
        format!("CN=User,{schema}"),
        format!("CN=Computer,{schema}"),
        format!("CN=Pwd-Last-Set,{schema}"),
    ]
    .into();
    let labo = format!("OU=Labo,{base}");
    let categories: Vec<(&str, Vec<String>, usize)> = vec![
        ("system", system.clone(), system.len()),
        (
            "protected (adminCount)",
            sorted_dns(connection, base, "(adminCount=1)", Scope::Subtree)?,
            15,
        ),
        (
            "GPO",
            sorted_dns(
                connection,
                &format!("CN=Policies,CN=System,{base}"),
                "(objectClass=groupPolicyContainer)",
                Scope::Subtree,
            )?,
            10,
        ),
        (
            "Builtin groups",
            sorted_dns(
                connection,
                &format!("CN=Builtin,{base}"),
                "(objectClass=group)",
                Scope::OneLevel,
            )?,
            8,
        ),
        (
            "OU",
            sorted_dns(
                connection,
                base,
                "(objectClass=organizationalUnit)",
                Scope::Subtree,
            )?,
            30,
        ),
        (
            "computers",
            sorted_dns(connection, base, "(objectClass=computer)", Scope::Subtree)?,
            30,
        ),
        (
            "groups",
            sorted_dns(connection, &labo, "(objectClass=group)", Scope::Subtree)?,
            25,
        ),
        (
            "DNS nodes",
            sorted_dns(
                connection,
                &format!("DC=lab.test,CN=MicrosoftDNS,DC=DomainDnsZones,{base}"),
                "(objectClass=dnsNode)",
                Scope::Subtree,
            )?,
            10,
        ),
    ];
    let mut seen: HashSet<String> = HashSet::new();
    let mut chosen = Vec::new();
    let mut take = |name: &str, dns: Vec<String>, n: usize, seen: &mut HashSet<String>| {
        let left: Vec<String> = dns
            .into_iter()
            .filter(|d| !seen.contains(&d.to_lowercase()))
            .collect();
        let picked = at_steps(&left, n);
        seen.extend(picked.iter().map(|d| d.to_lowercase()));
        chosen.push((name.to_owned(), picked));
    };
    for (name, dns, n) in categories {
        take(name, dns, n, &mut seen);
    }
    let users = sorted_dns(
        connection,
        &labo,
        "(&(objectClass=user)(!(objectClass=computer)))",
        Scope::Subtree,
    )?;
    let n = 200 - seen.len();
    take("users", users, n, &mut seen);
    Ok(chosen)
}

/// SDDL of `samba-tool dsacl get` on dc1 for each DN (read in sam.ldb, as root).
fn samba_tool_dsacl(dns: &[String]) -> Result<BTreeMap<String, String>> {
    let script = format!(
        "sudo sh -c 'while IFS= read -r dn; do printf \"@@@ %s\\n\" \"$dn\"; \
         samba-tool dsacl get -H /var/lib/samba/private/sam.ldb --objectdn=\"$dn\" 2>&1; done' <<'FIN'\n{}\nFIN\n",
        dns.join("\n")
    );
    let output = labo::ssh("dc1", &script)?;
    let mut results: BTreeMap<String, String> = BTreeMap::new();
    let mut current: Option<String> = None;
    for line in output.lines() {
        if let Some(dn) = line.strip_prefix("@@@ ") {
            current = Some(dn.to_owned());
            results.insert(dn.to_owned(), String::new());
        } else if let Some(dn) = &current
            && !line.starts_with("descriptor for ")
        {
            results.entry(dn.clone()).or_default().push_str(line.trim());
        }
    }
    Ok(results)
}

#[test]
#[ignore = "lab"]
fn security_sddl_as_samba_tool() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let (connection, _) = lab.pdc();
    let domain = {
        let e = labo::entry(&connection, &lab.base, &["objectSid"], None)?.ok_or("domain")?;
        Sid::decode(e.values("objectSid").first().ok_or("objectSid")?)?
    };
    let chosen = sample(&connection, &lab.base)?;
    let dns: Vec<String> = chosen.iter().flat_map(|(_, d)| d.clone()).collect();
    let distinct: HashSet<String> = dns.iter().map(|d| d.to_lowercase()).collect();
    check(
        dns.len() == 200 && distinct.len() == 200,
        "200 distinct objects",
    )?;
    let t = Instant::now();
    let mut core = BTreeMap::new();
    for dn in &dns {
        let entry = labo::entry(
            &connection,
            dn,
            &[actions::SD],
            Some(SD_WITHOUT_SACL | SD_SACL),
        )?
        .ok_or("object")?;
        let raw = entry.values(actions::SD).first().ok_or("SD")?;
        core.insert(
            dn.clone(),
            sddl::sd_to_sddl(&SecurityDescriptor::decode(raw)?, Some(&domain))?,
        );
    }
    println!("  core: {:.2} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let oracle = samba_tool_dsacl(&dns)?;
    println!("  samba-tool: {:.2} s", t.elapsed().as_secs_f64());
    let different: Vec<&String> = dns
        .iter()
        .filter(|d| core.get(*d) != oracle.get(*d))
        .collect();
    for dn in different.iter().take(3) {
        println!(
            "  {dn}\n    core   {:?}\n    oracle {:?}",
            core.get(*dn),
            oracle.get(*dn)
        );
    }
    let counts: Vec<(String, usize)> = chosen.iter().map(|(n, d)| (n.clone(), d.len())).collect();
    println!(
        "  {counts:?}; with SACL {}, object ACEs {}, protected {}",
        core.values().filter(|v| v.contains("S:")).count(),
        core.values()
            .filter(|v| v.contains("(OA;") || v.contains("(OD;"))
            .count(),
        core.values()
            .filter(|v| v.split_once("D:").is_some_and(|(_, d)| d.starts_with('P')))
            .count()
    );
    check(
        different.is_empty(),
        "SDDL identical to samba-tool dsacl get on 200 objects",
    )?;
    connection.join();
    Ok(())
}

// --- 2 and 3. Nomenclature and reading ---------------------------------------------------------------

fn nomenclature(connection: &annuaire_core::Connection) -> Result<security::Nomenclature> {
    let schema = schema::read_schema(connection).map_err(debug)?;
    let complements = security::read_complements(connection).map_err(debug)?;
    Ok(security::nomenclature_from(&schema, &complements))
}

#[test]
#[ignore = "lab"]
fn security_nomenclature() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let (connection, _) = lab.pdc();
    let t = Instant::now();
    let n = nomenclature(&connection)?;
    println!(
        "  read in {:.2} s: {} GUIDs, {} classes",
        t.elapsed().as_secs_f64(),
        n.guids.len(),
        n.classes.len()
    );
    for (guid, name, kind) in [
        (security::class_user(), "user", Kind::Class),
        (security::class_group(), "group", Kind::Class),
        (security::class_computer(), "computer", Kind::Class),
        (security::class_ou(), "organizationalUnit", Kind::Class),
        (
            security::class_inetorgperson(),
            "inetOrgPerson",
            Kind::Class,
        ),
        (
            security::attribute_pwdlastset(),
            "pwdLastSet",
            Kind::Attribute,
        ),
        (security::attribute_member(), "member", Kind::Attribute),
    ] {
        let found = n.name(Some(&guid), 0);
        check(
            found.is_some_and(|f| f.name == name && f.kind == kind),
            &format!("{guid} is {name}"),
        )?;
    }
    for (guid, cn, kind, mask) in [
        (
            security::right_reset_password(),
            "User-Force-Change-Password",
            Kind::ExtendedRight,
            sd::ADS_RIGHT_DS_CONTROL_ACCESS,
        ),
        (
            security::write_dns_name(),
            "Validated-DNS-Host-Name",
            Kind::ValidatedWrite,
            sd::ADS_RIGHT_DS_SELF,
        ),
        (
            security::write_spn(),
            "Validated-SPN",
            Kind::ValidatedWrite,
            sd::ADS_RIGHT_DS_SELF,
        ),
        (
            security::set_account_restrictions(),
            "User-Account-Restrictions",
            Kind::PropertySet,
            sd::ADS_RIGHT_DS_READ_PROP,
        ),
    ] {
        let found = n.name(Some(&guid), mask);
        check(
            found.is_some_and(|f| f.cn == cn && f.kind == kind),
            &format!("{guid} is {cn}"),
        )?;
    }
    check(
        n.defaults.get("user").is_some_and(|d| d.starts_with("D:")),
        "default descriptor of user",
    )?;
    // One GUID for the validated write « DNS host name », the property set of the same name
    // and the attribute dNSHostName: the mask of the ACE decides.
    let names: BTreeSet<(String, String)> = n
        .guids
        .get(&security::write_dns_name())
        .into_iter()
        .flatten()
        .map(|g| {
            let shown = if g.cn.is_empty() {
                g.name.clone()
            } else {
                g.cn.clone()
            };
            (format!("{:?}", g.kind), shown)
        })
        .collect();
    let wanted: BTreeSet<(String, String)> = [
        ("ValidatedWrite", "Validated-DNS-Host-Name"),
        ("PropertySet", "DNS-Host-Name-Attributes"),
        ("Attribute", "dNSHostName"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    check(names == wanted, "three names for the GUID of dNSHostName")?;
    check(
        n.name(
            Some(&security::write_dns_name()),
            sd::ADS_RIGHT_DS_WRITE_PROP,
        )
        .is_some_and(|g| g.kind == Kind::PropertySet),
        "WP: the property set",
    )?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn security_reading() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let (connection, _) = lab.pdc();
    let n = nomenclature(&connection)?;
    let dn = format!("OU=Paris,OU=Labo,{}", lab.base);
    let mut durations = Vec::new();
    let mut read = None;
    for _ in 0..5 {
        let t = Instant::now();
        read = security::read_security(&connection, &dn).map_err(debug)?;
        durations.push(t.elapsed().as_secs_f64());
    }
    durations.sort_by(f64::total_cmp);
    println!("  median reading: {:.3} s", durations[2]);
    let read = read.ok_or("OU=Paris")?;
    check(
        read.sacl_read && read.descriptor.sacl.is_some(),
        "SACL read (administrator)",
    )?;
    check(
        read.ancestors
            .iter()
            .map(|a| a.dn.clone())
            .collect::<Vec<_>>()
            == [format!("OU=Labo,{}", lab.base), lab.base.clone()],
        "ancestors up to the root",
    )?;
    let dacl = read.descriptor.dacl.clone().ok_or("DACL")?;
    let inherited: Vec<&Ace> = dacl.aces.iter().filter(|a| a.is_inherited()).collect();
    check(
        !inherited.is_empty()
            && inherited
                .iter()
                .all(|a| security::origin(a, &read.ancestors).is_some()),
        "origin of each inherited ACE found",
    )?;
    let defaults = security::default_aces(&n, &read.classes);
    let explicit: Vec<&Ace> = dacl.aces.iter().filter(|a| !a.is_inherited()).collect();
    check(
        !explicit.is_empty() && explicit.iter().all(|a| security::is_default(a, &defaults)),
        "explicit ACEs: those of the default descriptor",
    )?;
    check(
        read.names.values().any(|s| s.name == "Domain Admins"),
        "SIDs named",
    )?;
    connection.join();
    Ok(())
}

// --- 4. Delegation tried by a delegated account --------------------------------------------------

const DELEGATE: &str = "j4.delegue";

/// The same acts inside the target and outside of it; `n` tells the computers apart.
fn tasks(n: u32, essais: &str, secrets: &mut serde_json::Map<String, Json>) -> Json {
    let mut list = Vec::new();
    for (suffix, title) in [("cible", "Cible"), ("hors", "Hors")] {
        let ou = format!("OU={title},{essais}");
        let letter = &title[..1];
        list.extend([
            json!({"name": format!("changement_exige_{suffix}"), "kind": "password", "change": true,
                   "dn": format!("CN=J4 {title},{ou}"), "secret": format!("exige_{suffix}")}),
            json!({"name": format!("mot_de_passe_{suffix}"), "kind": "password",
                   "dn": format!("CN=J4 {title},{ou}"), "secret": format!("nouveau_{suffix}")}),
            json!({"name": format!("membre_{suffix}"), "kind": "member",
                   "dn": format!("CN=GS-J4-{title},{ou}"), "member": format!("CN=J4 Delegue,{essais}")}),
            json!({"name": format!("ordinateur_{suffix}"), "kind": "computer",
                   "dn": format!("CN=J4PC{n}{letter},{ou}"), "sam": format!("J4PC{n}{letter}$")}),
        ]);
        secrets.insert(
            format!("nouveau_{suffix}"),
            Json::String(labo::password(24)),
        );
        secrets.insert(format!("exige_{suffix}"), Json::String(labo::password(24)));
    }
    Json::Array(list)
}

fn all(results: &BTreeMap<String, String>, value: &str) -> bool {
    !results.is_empty() && results.values().all(|v| v == value)
}

#[allow(clippy::too_many_lines)]
fn delegation(trial: &Trial, lab: &Lab, kdc: &labo::Kdc) -> Result<()> {
    let base = &trial.base;
    let essais = trial.fresh_ou(base, "Essais-J4")?;
    let target = trial.fresh_ou(&essais, "Cible")?;
    let outside = trial.fresh_ou(&essais, "Hors")?;
    let delegated = group(trial, &essais, "GS-J4-Support")?;
    let delegate_secret = labo::password(24);
    trial.apply(&user(
        &essais,
        "J4 Delegue",
        DELEGATE,
        &lab.domain,
        &delegate_secret,
    )?)?;
    add_member(trial, &delegated, &format!("CN=J4 Delegue,{essais}"))?;
    let mut originals = BTreeMap::new();
    for (ou, suffix, title) in [(&target, "cible", "Cible"), (&outside, "hors", "Hors")] {
        let secret = labo::password(24);
        trial.apply(&user(
            ou,
            &format!("J4 {title}"),
            &format!("j4.{suffix}"),
            &lab.domain,
            &secret,
        )?)?;
        originals.insert(suffix, secret);
        group(trial, ou, &format!("GS-J4-{title}"))?;
    }
    let sid = trial.sid(&delegated)?;
    let templates = [
        Template::ResetPasswords,
        Template::GroupMembers,
        Template::JoinComputers,
    ];
    let origin = trial.descriptor(&target)?;

    println!("1. without delegation: everything refused");
    let mut secrets = serde_json::Map::new();
    let list = tasks(1, &essais, &mut secrets);
    let without = as_account(
        lab,
        kdc,
        DELEGATE,
        &delegate_secret,
        &list,
        &Json::Object(secrets),
    )?;
    println!("  {without:?}");
    check(
        all(&without, "refusé"),
        "refused, in the target as elsewhere",
    )?;
    // An ordinary account reads the descriptor without the SACL (second reading, SD flags 7).
    let reading = as_account(
        lab,
        kdc,
        DELEGATE,
        &delegate_secret,
        &json!([{"name": "securite", "kind": "security", "dn": target}]),
        &json!({}),
    )?;
    println!("  {reading:?}");
    check(
        reading
            .get("securite")
            .is_some_and(|r| r.starts_with("lu sacl=false dacl=")),
        "an ordinary account reads the descriptor without the SACL",
    )?;

    println!("2. delegation: one changeset");
    let t = Instant::now();
    let before = trial.descriptors(&[&target])?.pop().ok_or("Cible")?;
    let report = trial.apply(&actions::delegate(&before, &sid, &templates).map_err(debug)?)?;
    println!("  applied in {:.2} s", t.elapsed().as_secs_f64());
    let after = SecurityDescriptor::decode(&trial.descriptor(&target)?)?;
    let wanted = actions::template_aces(&templates, &sid);
    let present: HashSet<&Ace> = after
        .dacl
        .as_ref()
        .map(|d| d.aces.iter().collect())
        .unwrap_or_default();
    check(
        wanted.iter().all(|a| present.contains(a)),
        "the ACEs of the templates written",
    )?;
    let found: HashSet<Template> = security::delegations(&after)
        .into_iter()
        .filter(|d| d.sid == sid)
        .map(|d| d.template)
        .collect();
    check(
        found == templates.into_iter().collect(),
        "the three delegations recognised",
    )?;
    for ace in &wanted {
        println!("  {}", sddl::ace_to_sddl(ace, None)?);
    }

    println!("3. with delegation: allowed in the target only");
    let mut secrets = serde_json::Map::new();
    let list = tasks(2, &essais, &mut secrets);
    let new_target = secrets["nouveau_cible"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let with = as_account(
        lab,
        kdc,
        DELEGATE,
        &delegate_secret,
        &list,
        &Json::Object(secrets),
    )?;
    println!("  {with:?}");
    let expected: BTreeMap<String, String> = [
        ("mot_de_passe_cible", "permis"),
        ("changement_exige_cible", "permis"),
        ("membre_cible", "permis"),
        ("ordinateur_cible", "permis"),
        ("mot_de_passe_hors", "refusé"),
        ("changement_exige_hors", "refusé"),
        ("membre_hors", "refusé"),
        ("ordinateur_hors", "refusé"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    check(with == expected, "the delegated rights, and only them")?;
    // The last password set by the delegate opens a session, not the old one (KDC of dc1,
    // where the delegate wrote).
    let realm = lab.realm();
    check(
        kdc.granted(&format!("j4.cible@{realm}"), &new_target),
        "the new password works",
    )?;
    check(
        !kdc.granted(&format!("j4.cible@{realm}"), &originals["cible"]),
        "the old one no longer",
    )?;
    check(
        kdc.granted(&format!("j4.hors@{realm}"), &originals["hors"]),
        "outside: unchanged",
    )?;
    let members = trial
        .entry(&format!("CN=GS-J4-Cible,{target}"), &["member"])?
        .ok_or("group")?;
    check(
        members.values("member") == [format!("CN=J4 Delegue,{essais}").into_bytes()],
        "member added by the delegate",
    )?;
    let pc = trial
        .entry(&format!("CN=J4PC2C,{target}"), &["sAMAccountName"])?
        .ok_or("computer")?;
    check(
        labo::text(&pc, "sAMAccountName") == "J4PC2C$",
        "computer created by the delegate",
    )?;

    println!("4. delegation removed: descriptor back byte for byte");
    let current = trial.descriptors(&[&target])?.pop().ok_or("Cible")?;
    trial.apply(&actions::remove_aces(&current, &wanted).map_err(debug)?)?;
    check(trial.descriptor(&target)? == origin, "descriptor of origin")?;
    let mut secrets = serde_json::Map::new();
    let list = tasks(3, &essais, &mut secrets);
    let removed = as_account(
        lab,
        kdc,
        DELEGATE,
        &delegate_secret,
        &list,
        &Json::Object(secrets),
    )?;
    println!("  {removed:?}");
    check(all(&removed, "refusé"), "refused everywhere again")?;
    check(
        writer::read_journal(&trial.journal)
            .last()
            .is_some_and(|r| r.issue == Issue::Applied)
            && report.issue == Issue::Applied,
        "journaled",
    )?;

    println!("5. undo and optimistic guard");
    let template = [Template::ReadUsers];
    let before = trial.descriptors(&[&target])?.pop().ok_or("Cible")?;
    let delegated_report =
        trial.apply(&actions::delegate(&before, &sid, &template).map_err(debug)?)?;
    trial.undo(&delegated_report)?;
    check(
        trial.descriptor(&target)? == origin,
        "the journaled inverse puts it back exactly",
    )?;
    let stale = trial.descriptors(&[&target])?.pop().ok_or("Cible")?;
    let change = Change::new(
        "description",
        Vec::new(),
        vec![b"modifiee entre-temps".to_vec()],
    )
    .map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![Operation::modify(&target, vec![change], None).map_err(debug)?],
        remarks: Vec::new(),
    })?;
    let refused = trial.outcome(
        &actions::delegate(&stale, &sid, &template).map_err(debug)?,
        None,
        None,
    )?;
    check(
        refused.report.issue == Issue::Refused,
        "changed meanwhile: refused",
    )?;
    check(trial.descriptor(&target)? == origin, "nothing written")
}

fn nothing_left_on_the_dcs(lab: &Lab) -> Result<()> {
    for dc in ["dc1", "dc2"] {
        let seconds = labo::wait(
            Duration::from_secs(120),
            &format!("nothing left on {dc}"),
            || {
                Ok(labo::ldbsearch(
                    dc,
                    &lab.base,
                    "sub",
                    "(|(ou=Essais-J4)(sAMAccountName=j4.*)(sAMAccountName=J4PC*)(cn=GS-J4-*))",
                    &["dn"],
                )?
                .is_empty())
            },
        )?;
        println!("  {dc}: nothing left after {seconds:.1} s");
        let line = labo::showrepl(dc)?;
        check(line.contains("ALL GOOD"), &format!("{dc}: {line}"))?;
    }
    Ok(())
}

#[test]
#[ignore = "lab"]
fn security_delegation() -> Result<()> {
    let lab = labo::lab();
    if !samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("securite")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, &lab.pdc_name())?;
    let essais = format!("OU=Essais-J4,{}", trial.base);
    let done = delegation(&trial, &lab, &kdc);
    println!("6. cleaning");
    let cleaned = trial
        .remove_tree(&essais)
        .and_then(|()| nothing_left_on_the_dcs(&lab));
    trial.connection.join();
    done.and(cleaned)
}

// --- 5. Conditional ACEs ------------------------------------------------------------------------

const MEMBER: &str = "fb.membre";
const OTHER: &str = "fb.autre";

/// The DACL of `dn` as the native tool reads it: `samba-tool dsacl get`, or the Win32 and .NET
/// (`Get-Acl`) forms of Windows.
fn native_sddl(lab: &Lab, dn: &str) -> Result<BTreeMap<String, String>> {
    if !lab.windows() {
        let out = labo::ssh(
            "dc1",
            &format!(
                "sudo samba-tool dsacl get -H /var/lib/samba/private/sam.ldb --objectdn={}\n",
                labo::quote(dn)
            ),
        )?;
        let text: String = out
            .lines()
            .filter(|l| !l.starts_with("descriptor for "))
            .map(str::trim)
            .collect();
        return Ok([("samba".to_owned(), text)].into());
    }
    // Bytes as stored (DirectorySearcher): `Get-ADObject` gives a .NET object that puts the
    // ACEs back in canonical order, as `Get-Acl` (ADR 0011 § 5).
    let script = format!(
        "$ErrorActionPreference='Stop'\n\
         $s = New-Object DirectoryServices.DirectorySearcher; $s.SearchRoot = New-Object DirectoryServices.DirectoryEntry('LDAP://{dn}'); $s.SearchScope = 'Base'; $s.SecurityMasks = 'Dacl'; $null = $s.PropertiesToLoad.Add('ntsecuritydescriptor'); $o = [byte[]]$s.FindOne().Properties['ntsecuritydescriptor'][0]; 'WIN32=' + (New-Object Security.AccessControl.RawSecurityDescriptor($o, 0)).GetSddlForm('Access')\n\
         Import-Module ActiveDirectory; 'GETACL=' + (Get-Acl -Path ('AD:' + '{dn}')).GetSecurityDescriptorSddlForm('Access')\n"
    );
    let seen = labo::lines(&labo::poste(&script, &["--cible", "wdc", "--domaine"])?);
    Ok([
        (
            "win32".to_owned(),
            seen.get("WIN32").cloned().ok_or("WIN32")?,
        ),
        (
            "getacl".to_owned(),
            seen.get("GETACL").cloned().ok_or("GETACL")?,
        ),
    ]
    .into())
}

fn write_description(
    lab: &Lab,
    kdc: &labo::Kdc,
    account: &str,
    secret: &str,
    target: &str,
    value: &str,
) -> Result<String> {
    let tasks =
        json!([{"name": "description", "kind": "description", "dn": target, "value": value}]);
    let result = as_account(lab, kdc, account, secret, &tasks, &json!({}))?;
    Ok(result.get("description").cloned().unwrap_or_default())
}

#[allow(clippy::too_many_lines)]
fn conditional(trial: &Trial, lab: &Lab, kdc: &labo::Kdc) -> Result<()> {
    let essais = trial.fresh_ou(&trial.base, "Essais-FB")?;
    let fb_group = group(trial, &essais, "GS-FB-Essai")?;
    let mut secrets = BTreeMap::new();
    for (sam, name) in [
        (MEMBER, "FB Membre"),
        (OTHER, "FB Autre"),
        ("fb.cible", "FB Cible"),
    ] {
        let secret = labo::password(20);
        trial.apply(&user(&essais, name, sam, &lab.domain, &secret)?)?;
        secrets.insert(sam, secret);
    }
    add_member(trial, &fb_group, &format!("CN=FB Membre,{essais}"))?;
    let target = format!("CN=FB Cible,{essais}");
    let n = nomenclature(&trial.connection)?;
    let domain = n.domain_sid.ok_or("SID of the domain")?;
    let group_sid = trial.sid(&fb_group)?;
    let origin = trial.descriptor(&target)?;

    println!("1. before: neither writes the description of the target");
    for account in [MEMBER, OTHER] {
        let seen = write_description(lab, kdc, account, &secrets[account], &target, "avant")?;
        check(seen == "refusé", &format!("{account}: {seen}"))?;
    }

    println!("2. two conditional ACEs typed in SDDL");
    let typed = sddl::ace_from_sddl(
        &format!("(XA;;WP;;;AU;(Member_of {{SID({group_sid})}}))"),
        Some(&domain),
        false,
    )?;
    let typed_da =
        sddl::ace_from_sddl("(XA;;RP;;;AU;(Member_of {SID(DA)}))", Some(&domain), false)?;
    let (text, text_da) = (
        sddl::ace_to_sddl(&typed, Some(&domain))?,
        sddl::ace_to_sddl(&typed_da, Some(&domain))?,
    );
    println!("  {text}\n  {text_da}");
    check(
        text_da.contains(&format!("SID({domain}-512)")),
        "SID(DA) written as a full SID",
    )?;
    check(
        security::is_conditional(typed.ace_type) && security::is_conditional(typed_da.ace_type),
        "conditional entries",
    )?;
    let object = trial.descriptors(&[&target])?.pop().ok_or("target")?;
    trial.apply(&actions::add_aces(&object, &[typed.clone(), typed_da.clone()]).map_err(debug)?)?;
    let written = SecurityDescriptor::decode(&trial.descriptor(&target)?)?;
    let dacl = written.dacl.clone().ok_or("DACL")?;
    check(
        dacl.aces.contains(&typed) && dacl.aces.contains(&typed_da),
        "both in the DACL",
    )?;

    println!("3. read again by the native tool");
    let only_dacl = SecurityDescriptor {
        owner: None,
        group: None,
        sacl: None,
        ..written.clone()
    };
    let core = sddl::sd_to_sddl(&only_dacl, Some(&domain))?;
    let native = native_sddl(lab, &target)?;
    println!(
        "  core: {} characters; native: {:?}",
        core.len(),
        native.iter().map(|(k, v)| (k, v.len())).collect::<Vec<_>>()
    );
    if lab.windows() {
        for form in ["win32", "getacl"] {
            let read = sddl::sd_from_sddl(&native[form], Some(&domain), false)?;
            let aces = read.dacl.map(|d| d.aces).unwrap_or_default();
            check(
                aces.contains(&typed) && aces.contains(&typed_da),
                &format!("{form}: both ACEs read again"),
            )?;
        }
        let read = sddl::sd_from_sddl(&native["win32"], Some(&domain), false)?;
        // The Win32 form keeps the order and the detail of the ACEs.
        check(read.dacl == written.dacl, "Win32 form: the same DACL")?;
    } else {
        let samba = &native["samba"];
        let tail = core.split_once("D:").map(|(_, d)| d).unwrap_or_default();
        check(
            samba.ends_with(tail) || samba.contains(tail),
            "samba-tool: the same DACL",
        )?;
        check(
            samba.contains(&text) && samba.contains(&text_da),
            "samba-tool: the same conditions",
        )?;
    }

    println!("4. effect: the member writes, the other one cannot");
    for (account, wanted) in [(MEMBER, "permis"), (OTHER, "refusé")] {
        let seen = write_description(
            lab,
            kdc,
            account,
            &secrets[account],
            &target,
            &format!("par {account}"),
        )?;
        check(seen == wanted, &format!("{account}: {seen}"))?;
    }
    let read = trial.entry(&target, &["description"])?.ok_or("target")?;
    check(
        read.values("description") == [format!("par {MEMBER}").into_bytes()],
        "description written by the member",
    )?;

    println!("5. removal: descriptor of origin byte for byte");
    let object = trial.descriptors(&[&target])?.pop().ok_or("target")?;
    trial.apply(&actions::remove_aces(&object, &[typed, typed_da]).map_err(debug)?)?;
    check(trial.descriptor(&target)? == origin, "descriptor of origin")?;
    let seen = write_description(lab, kdc, MEMBER, &secrets[MEMBER], &target, "après")?;
    check(seen == "refusé", "the right gone")
}

#[test]
#[ignore = "lab"]
fn security_conditional_aces() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("ace")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, &lab.pdc_name())?;
    let essais = format!("OU=Essais-FB,{}", trial.base);
    let done = conditional(&trial, &lab, &kdc);
    let cleaned = trial.remove_tree(&essais);
    trial.connection.join();
    done.and(cleaned)
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Cross-validation against the Windows Server 2025 DC of the lab, `wdc1.win.test` (port of
//! `test_windows_labo.py`, ADR 0020): sealed bind and TLS with the enterprise CA, search and
//! ranges of `member`, membership with a cycle, schema, SDDL compared with Windows' own forms,
//! delegation compared with the Windows wizard (`dsacls`), local copy under an administrator
//! and under an ordinary account, DNS (integrated zones, a record written by the core and served
//! by the Windows DNS server, health), SYSVOL replicated by DFS-R. Writes under `OU=Essais-W`,
//! created at the start and removed at the end, even after a failure.
//!
//! Played only with `ANNUAIRE_LABO_DOMAINE=win.test` and the ticket of an administrator of
//! WIN.TEST; skipped otherwise. PowerShell on the DC by `labo/poste.py --cible wdc` (see
//! `labo/mod.rs`). The accounts of `labo/peupler-windows.ps1` have HMAC(seed, identifier) as
//! password.

// serde_json's indexing gives `Null` for what is missing: it does not panic.
#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use annuaire_codecs::dns_record;
use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::{Sid, sddl};
use annuaire_core::cache::Source as _;
use annuaire_core::changes::{self, Issue};
use annuaire_core::dns::{self, Partition};
use annuaire_core::dns_health::{self, Rule, Settings};
use annuaire_core::dns_write::{self as dw, Request};
use annuaire_core::messages::English;
use annuaire_core::profile::{Mode, Profile};
use annuaire_core::queries::{self, Kind, State};
use annuaire_core::schema::{self, Syntax};
use annuaire_core::search::{
    self, OID_IN_CHAIN, OID_PAGES, OID_SD_FLAGS, SD_SACL, SD_WITHOUT_SACL, Value,
};
use annuaire_core::security::{self, Template};
use annuaire_core::session::Scope;
use annuaire_core::{actions, membership, source};
use serde_json::{Value as Json, json};

use labo::{Lab, Result, Trial, check, debug, entries, poste};

const DC: &str = "wdc1.win.test";
const DC_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 210);

/// The domain WIN.TEST, or None (and said) when another one is aimed at.
fn windows() -> Option<Lab> {
    let lab = labo::lab();
    if lab.windows() {
        Some(lab)
    } else {
        println!("  WIN.TEST only (ANNUAIRE_LABO_DOMAINE=win.test): skipped");
        None
    }
}

fn labo_ou(lab: &Lab) -> String {
    format!("OU=Labo,{}", lab.base)
}

fn groups_ou(lab: &Lab) -> String {
    format!("OU=Groupes,{}", labo_ou(lab))
}

/// Where `peupler-windows.ps1` delegated the reset of passwords with `dsacls`, as the wizard.
fn delegated_ou(lab: &Lab) -> String {
    format!("OU=Utilisateurs,OU=Support,OU=Nantes,{}", labo_ou(lab))
}

fn trials_ou(lab: &Lab) -> String {
    format!("OU=Essais-W,{}", lab.base)
}

/// PowerShell on the DC, as WIN\Administrateur (`--domaine`) or as local administrator.
fn powershell(script: &str, domain: bool) -> Result<BTreeMap<String, String>> {
    let mut options = vec!["--cible", "wdc"];
    if domain {
        options.push("--domaine");
    }
    Ok(labo::lines(&poste(script, &options)?))
}

fn dns_of(entries: &[annuaire_core::session::Entry]) -> BTreeSet<String> {
    entries.iter().map(|e| e.dn.to_lowercase()).collect()
}

fn domain_sid(trial_or: &annuaire_core::Connection, base: &str) -> Result<Sid> {
    let entry = labo::entry(trial_or, base, &["objectSid"], None)?.ok_or("domain")?;
    Ok(Sid::decode(
        entry.values("objectSid").first().ok_or("objectSid")?,
    )?)
}

// --- Bind, TLS, reading ---------------------------------------------------------------------

#[test]
#[ignore = "lab"]
#[allow(clippy::too_many_lines)]
fn windows_reading() -> Result<()> {
    let Some(lab) = windows() else {
        return Ok(());
    };
    let (connection, _) = lab.pdc();
    println!("1. sealed bind and RootDSE");
    let state = connection
        .run(true, |link| Ok((*link.state).clone()))
        .map_err(debug)?;
    check(
        state.dc == DC && state.ssf >= 128 && state.encrypted() && !state.tls,
        &format!("sealed bind on {} (SSF {})", state.dc, state.ssf),
    )?;
    let root = &state.root_dse;
    check(
        root.default_naming_context == lab.base && root.dns_host_name == DC,
        "naming context and DNS name",
    )?;
    check(
        root.domain_functionality == 7,
        "functional level 2016, as LAB.TEST",
    )?;
    check(
        root.supported_controls.iter().any(|c| c == OID_PAGES)
            && root.supported_controls.iter().any(|c| c == OID_SD_FLAGS),
        "paged results and SD flags supported",
    )?;

    println!("2. TLS with the enterprise CA read in the directory");
    let scratch = labo::Scratch::new("windows-ca")?;
    let base = format!(
        "CN=Certification Authorities,CN=Public Key Services,CN=Services,{}",
        root.configuration_naming_context
    );
    let cas = entries(
        &connection,
        &base,
        Scope::Subtree,
        "(objectClass=certificationAuthority)",
        &["cACertificate"],
    )?;
    let [ca] = cas.as_slice() else {
        return Err(format!("{} CA in the directory", cas.len()).into());
    };
    let der = ca.values("cACertificate").first().ok_or("cACertificate")?;
    let encoded = changes::base64_encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    let pem_path = scratch.path().join("ca-win-test.pem");
    std::fs::write(&pem_path, pem)?;
    for mode in [Mode::Ldaps, Mode::StartTls] {
        let mut profile = Profile::new(lab.domain.clone());
        profile.mode = mode;
        profile.ca = Some(pem_path.clone());
        let tls = source::connection_to(&profile, None);
        let state = tls
            .run(true, |link| Ok((*link.state).clone()))
            .map_err(debug)?;
        check(
            state.tls && state.encrypted() && state.dc == DC,
            &format!("{mode:?} with the enterprise CA"),
        )?;
        tls.join();
    }

    println!("3. search, accents and ranges");
    let users = queries::search_filter("", Kind::User, State::All);
    let all = entries(
        &connection,
        &labo_ou(&lab),
        Scope::Subtree,
        &users,
        &["1.1"],
    )?;
    check(
        all.len() == 200,
        &format!("{} users under OU=Labo", all.len()),
    )?;
    let disabled = queries::search_filter("", Kind::User, State::Disabled);
    let n = entries(
        &connection,
        &labo_ou(&lab),
        Scope::Subtree,
        &disabled,
        &["1.1"],
    )?
    .len();
    println!("  {n} disabled");
    let accent = queries::search_filter("Gaëlle", Kind::All, State::All);
    let found = entries(
        &connection,
        &labo_ou(&lab),
        Scope::Subtree,
        &accent,
        &["givenName"],
    )?;
    check(
        !found.is_empty() && found.iter().all(|e| labo::text(e, "givenName") == "Gaëlle"),
        "search with an accent",
    )?;
    let group = format!("CN=GG-Nantes-Support,{}", groups_ou(&lab));
    let by_10 = {
        let group = group.clone();
        connection
            .run(true, move |link| {
                search::read_ranges(
                    link.session.as_mut(),
                    &group,
                    "member",
                    10,
                    Some(link.timeout),
                )
                .map_err(|e| match e {
                    search::RangesError::Ldap(e) => e,
                    search::RangesError::Range(e) => annuaire_core::LdapError::new(
                        annuaire_core::error::code::DECODING_ERROR,
                        e.to_string(),
                    ),
                })
            })
            .map_err(debug)?
    };
    let whole = labo::entry(&connection, &group, &["member"], None)?.ok_or("group")?;
    let mut a = by_10.clone();
    let mut b = whole.values("member").to_vec();
    a.sort();
    b.sort();
    check(
        a == b && a.len() == 25,
        "25 members by explicit windows of 10, as whole",
    )?;

    println!("4. membership with a cycle");
    let project1 = format!("CN=GG-Projet-1,{}", groups_ou(&lab));
    let filter = search::rule("memberOf", OID_IN_CHAIN, Value::Text(&project1))?;
    let members = dns_of(&entries(
        &connection,
        &lab.base,
        Scope::Subtree,
        &filter,
        &["1.1"],
    )?);
    let projects: BTreeSet<String> = [1, 2, 3, 4]
        .iter()
        .map(|i| format!("CN=GG-Projet-{i},{}", groups_ou(&lab)).to_lowercase())
        .collect();
    // The cycle (Projet-4 member of Projet-1) brings the group of departure back: Windows
    // counts it among its own members by nesting.
    check(
        projects.is_subset(&members) && members.len() == 4 + 3,
        "members of GG-Projet-1 by IN_CHAIN, itself included",
    )?;
    let support = entries(
        &connection,
        &delegated_ou(&lab),
        Scope::Subtree,
        "(objectClass=user)",
        &["1.1"],
    )?
    .into_iter()
    .next()
    .ok_or("an account of the support")?
    .dn;
    let groups = membership::groups_of(&connection, &support, true).map_err(debug)?;
    let names: BTreeSet<String> = groups
        .recursive
        .iter()
        .flatten()
        .map(|g| source::name_from_dn(g))
        .collect();
    println!("  groups of {support}: {names:?}");
    check(
        [
            "GG-Nantes-Support",
            "GG-Nantes",
            "GG-Tous",
            "GG-Helpdesk",
            "Utilisateurs du domaine",
        ]
        .iter()
        .all(|n| names.contains(*n))
            && groups.primary.is_some(),
        "recursive groups and primary group",
    )?;

    println!("5. schema and nomenclature");
    let schema = schema::read_schema(&connection).map_err(debug)?;
    let unknown: Vec<&String> = schema
        .attributes
        .iter()
        .filter(|(_, d)| d.syntax == Syntax::Unknown)
        .map(|(n, _)| n)
        .collect();
    println!("  {} attributes", schema.attributes.len());
    check(
        unknown.is_empty(),
        &format!("no unknown syntax {unknown:?}"),
    )?;
    check(
        schema
            .attributes
            .contains_key("msds-allowedtoactonbehalfofotheridentity"),
        "schema 2012 or later",
    )?;
    let complements = security::read_complements(&connection).map_err(debug)?;
    let nomenclature = security::nomenclature_from(&schema, &complements);
    let name = nomenclature.name(
        Some(&security::right_reset_password()),
        sd::ADS_RIGHT_DS_CONTROL_ACCESS,
    );
    check(
        name.is_some_and(|n| n.cn == "User-Force-Change-Password"),
        "the reset of passwords named",
    )?;
    check(
        nomenclature
            .defaults
            .get("user")
            .is_some_and(|d| d.starts_with("D:")),
        "default descriptor of user",
    )?;

    println!("6. integrated zones");
    let zones = dns::zones(&connection).map_err(debug)?;
    let seen: HashSet<(String, Partition)> = zones
        .iter()
        .map(|z| (z.name.clone(), z.partition))
        .collect();
    for (zone, partition) in [
        ("win.test", Partition::Domain),
        ("1.168.192.in-addr.arpa", Partition::Domain),
        ("_msdcs.win.test", Partition::Forest),
        ("RootDNSServers", Partition::Domain),
        // Windows keeps the place of 2000 too.
        ("RootDNSServers", Partition::Legacy),
    ] {
        check(
            seen.contains(&(zone.to_owned(), partition)),
            &format!("zone {zone} in {}", partition.value()),
        )?;
    }

    println!("7. DNS health");
    let state = dns_health::read_state(&connection).map_err(debug)?;
    let diagnosis = dns_health::diagnose(&state, Settings::default(), None);
    for a in &diagnosis.anomalies {
        println!("  {} {:?}", a.rule.value(), a.title);
    }
    // peupler-windows.ps1 sets six A pc-nan-sup-N for four computers: the two without an
    // account are the only anomalies.
    check(
        diagnosis.anomalies.len() == 2
            && diagnosis.anomalies.iter().all(|a| {
                a.rule == Rule::VanishedHost
                    && a.targets.iter().any(|t| {
                        let name = t.name.to_lowercase();
                        name == "pc-nan-sup-5" || name == "pc-nan-sup-6"
                    })
            }),
        "the two A without account, and only them",
    )?;
    check(
        state
            .controllers
            .iter()
            .map(|c| c.name.as_str())
            .collect::<Vec<_>>()
            == [DC],
        "one DC",
    )?;

    println!("8. SYSVOL replicated by DFS-R");
    let dfsr = powershell(
        r#"
"MIGRATION=" + ((dfsrmig /getmigrationstate) -join ' ')
"PARTAGE=" + [bool](Get-SmbShare -Name SYSVOL -ErrorAction SilentlyContinue)
$e = Get-WinEvent -FilterHashtable @{LogName='DFS Replication'; Id=4602,4604} -MaxEvents 1 -ErrorAction SilentlyContinue
"INITIALISE=" + [bool]$e
"SYSVOLREADY=" + (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysvolReady
"#,
        false,
    )?;
    println!("  {dfsr:?}");
    check(
        dfsr.get("PARTAGE").map(String::as_str) == Some("True")
            && dfsr.get("SYSVOLREADY").map(String::as_str) == Some("1")
            && dfsr.get("INITIALISE").map(String::as_str) == Some("True"),
        "SYSVOL shared, ready, DFS-R initialised",
    )?;
    connection.join();
    Ok(())
}

// --- SDDL against Windows ---------------------------------------------------------------------

/// Families of the sample: base, filter, share.
fn families(base: &str) -> Vec<(&'static str, String, &'static str, usize)> {
    vec![
        (
            "utilisateurs",
            base.to_owned(),
            "(&(objectCategory=person)(objectClass=user))",
            7,
        ),
        ("groupes", base.to_owned(), "(objectClass=group)", 4),
        ("ordinateurs", base.to_owned(), "(objectClass=computer)", 2),
        ("ou", base.to_owned(), "(objectClass=organizationalUnit)", 3),
        ("adminCount", base.to_owned(), "(adminCount=1)", 2),
        ("conteneurs", base.to_owned(), "(objectClass=container)", 2),
        (
            "gpo",
            format!("CN=Policies,CN=System,{base}"),
            "(objectClass=groupPolicyContainer)",
            1,
        ),
        (
            "dns",
            format!("DC=DomainDnsZones,{base}"),
            "(objectClass=dnsNode)",
            2,
        ),
        (
            "dns-foret",
            format!("DC=ForestDnsZones,{base}"),
            "(objectClass=dnsNode)",
            1,
        ),
        (
            "configuration",
            format!("CN=Configuration,{base}"),
            "(objectClass=*)",
            2,
        ),
        (
            "schema",
            format!("CN=Schema,CN=Configuration,{base}"),
            "(objectClass=*)",
            2,
        ),
    ]
}

/// About 30 objects: the root, the delegated OU, then a few of each family, taken at regular
/// steps among the sorted DNs (reproducible).
fn sample(connection: &annuaire_core::Connection, lab: &Lab) -> Result<Vec<String>> {
    let mut taken = vec![lab.base.clone(), delegated_ou(lab)];
    for (_, base, filter, n) in families(&lab.base) {
        let mut dns: Vec<String> = entries(connection, &base, Scope::Subtree, filter, &["1.1"])?
            .into_iter()
            .map(|e| e.dn)
            .filter(|d| !taken.contains(d))
            .collect();
        dns.sort();
        let step = (dns.len() / n.max(1)).max(1);
        taken.extend(dns.into_iter().step_by(step).take(n));
    }
    Ok(taken)
}

const READ_ON_WINDOWS: &str = r#"
$ErrorActionPreference = 'Stop'
$dns = '@DNS@' | ConvertFrom-Json
$sortie = foreach ($dn in $dns) {
    $s = New-Object DirectoryServices.DirectorySearcher
    $s.SearchRoot = New-Object DirectoryServices.DirectoryEntry("LDAP://$($dn.Replace('/', '\/'))")
    $s.SearchScope = 'Base'
    $s.SecurityMasks = 'Owner,Group,Dacl,Sacl'
    $s.PropertiesToLoad.Add('ntsecuritydescriptor') | Out-Null
    $octets = [byte[]]$s.FindOne().Properties['ntsecuritydescriptor'][0]
    $brut = New-Object Security.AccessControl.RawSecurityDescriptor($octets, 0)
    [pscustomobject]@{ dn = $dn; octets = [Convert]::ToBase64String($octets); win32 = $brut.GetSddlForm('All') }
}
'JSON=' + (ConvertTo-Json -Compress -Depth 4 @($sortie))
"#;

/// The descriptors read on the DC (bytes, Win32 SDDL), by DN.
fn read_on_windows(dns: &[String]) -> Result<BTreeMap<String, (Vec<u8>, String)>> {
    // PowerShell takes the typographic quotes for quotes too: each one doubled.
    let list = serde_json::to_string(dns)?
        .replace('\'', "''")
        .replace('\u{2019}', "\u{2019}\u{2019}")
        .replace('\u{2018}', "\u{2018}\u{2018}");
    let script = READ_ON_WINDOWS.replace("@DNS@", &list);
    let read = powershell(&script, true)?;
    let objects: Json = serde_json::from_str(read.get("JSON").ok_or("no JSON")?)?;
    let mut out = BTreeMap::new();
    for o in objects.as_array().ok_or("objects")? {
        let dn = o["dn"].as_str().ok_or("dn")?.to_owned();
        let bytes = changes::base64_decode(o["octets"].as_str().ok_or("octets")?).map_err(debug)?;
        out.insert(dn, (bytes, o["win32"].as_str().ok_or("win32")?.to_owned()));
    }
    Ok(out)
}

/// The descriptors read by the core (SD flags 15).
fn read_by_core(
    connection: &annuaire_core::Connection,
    dns: &[String],
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut out = BTreeMap::new();
    for dn in dns {
        let entry = labo::entry(
            connection,
            dn,
            &[actions::SD],
            Some(SD_WITHOUT_SACL | SD_SACL),
        )?
        .ok_or("object")?;
        out.insert(
            dn.clone(),
            entry.values(actions::SD).first().ok_or("SD")?.clone(),
        );
    }
    Ok(out)
}

/// The ACEs of each ACL (`D`, `S`), fields split; headers under `X-header`, owner and group
/// under `O` and `G`.
fn sections(text: &str) -> BTreeMap<String, Vec<Vec<String>>> {
    let mut out = BTreeMap::new();
    let mut starts: Vec<usize> = text
        .char_indices()
        .filter(|&(i, c)| {
            "OGDS".contains(c)
                && text.get(i + 1..i + 2) == Some(":")
                && text[..i].chars().filter(|&c| c == '(').count()
                    == text[..i].chars().filter(|&c| c == ')').count()
        })
        .map(|(i, _)| i)
        .collect();
    starts.push(text.len());
    for pair in starts.windows(2) {
        let part = &text[pair[0]..pair[1]];
        let key = &part[..1];
        let body = &part[2..];
        if key == "D" || key == "S" {
            let header = body.split('(').next().unwrap_or_default().to_owned();
            out.insert(format!("{key}-header"), vec![vec![header]]);
            let mut aces = Vec::new();
            let mut depth = 0;
            let mut current = String::new();
            for c in body.chars() {
                match c {
                    '(' => {
                        if depth > 0 {
                            current.push(c);
                        }
                        depth += 1;
                    }
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            aces.push(current.split(';').map(str::to_owned).collect());
                            current.clear();
                        } else {
                            current.push(c);
                        }
                    }
                    _ if depth > 0 => current.push(c),
                    _ => {}
                }
            }
            out.insert(key.to_owned(), aces);
        } else {
            out.insert(key.to_owned(), vec![vec![body.to_owned()]]);
        }
    }
    out
}

/// (field, form of the core, form of Windows) for each field that differs.
fn differences(core: &str, windows: &str) -> Vec<(String, String, String)> {
    let (a, b) = (sections(core), sections(windows));
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    let fields = ["type", "flags", "rights", "guid", "inherited guid", "sid"];
    let mut out = Vec::new();
    for key in keys {
        let (x, y) = (
            a.get(key).cloned().unwrap_or_default(),
            b.get(key).cloned().unwrap_or_default(),
        );
        if key == "O" || key == "G" || key.ends_with("header") {
            if x != y {
                let flat =
                    |v: &[Vec<String>]| v.iter().map(|f| f.join(";")).collect::<Vec<_>>().join(";");
                out.push((key.clone(), flat(&x), flat(&y)));
            }
            continue;
        }
        if x.len() != y.len() {
            out.push((
                format!("{key}: number"),
                x.len().to_string(),
                y.len().to_string(),
            ));
            continue;
        }
        for (u, v) in x.iter().zip(&y) {
            for (i, field) in fields.iter().enumerate() {
                if let (Some(p), Some(q)) = (u.get(i), v.get(i))
                    && p != q
                {
                    out.push((format!("{key}: {field}"), p.clone(), q.clone()));
                }
            }
        }
    }
    out
}

#[test]
#[ignore = "lab"]
fn windows_sddl() -> Result<()> {
    let Some(lab) = windows() else {
        return Ok(());
    };
    let (connection, _) = lab.pdc();
    let domain = domain_sid(&connection, &lab.base)?;
    let objects = sample(&connection, &lab)?;
    println!("{} objects", objects.len());
    let mut core = read_by_core(&connection, &objects)?;
    let mut windows = read_on_windows(&objects)?;
    // An object rewritten by the DC between the two readings is read again: only the
    // agreement at one instant counts.
    let moved: Vec<String> = objects
        .iter()
        .filter(|d| windows.get(*d).map(|w| &w.0) != core.get(*d))
        .cloned()
        .collect();
    if !moved.is_empty() {
        println!("  read again: {moved:?}");
        core.extend(read_by_core(&connection, &moved)?);
        windows.extend(read_on_windows(&moved)?);
    }
    let abbreviated = [
        ("EA", 519),
        ("SA", 518),
        ("RO", 498),
        ("EK", 527),
        ("CN", 522),
    ];
    let domain_text = sddl::sid_to_sddl(&domain, None);
    let mut forms: BTreeMap<String, usize> = BTreeMap::new();
    for dn in &objects {
        let (bytes, win32) = windows.get(dn).ok_or("read on Windows")?;
        let mine = core.get(dn).ok_or("read by the core")?;
        check(bytes == mine, &format!("same bytes: {dn}"))?;
        let text = sddl::sd_to_sddl(&SecurityDescriptor::decode(mine)?, Some(&domain))?;
        let reread = sddl::sd_from_sddl(win32, Some(&domain), false)?;
        check(
            sddl::sd_to_sddl(&reread, Some(&domain))? == text,
            &format!("same meaning: {dn}"),
        )?;
        for (field, x, y) in differences(&text, win32) {
            // The only difference of form allowed: the SIDs Windows does not abbreviate.
            let allowed = (field.ends_with("sid") || field == "O" || field == "G")
                && abbreviated
                    .iter()
                    .any(|(abbr, rid)| x == *abbr && y == format!("{domain_text}-{rid}"));
            if !allowed {
                return Err(format!("FAILED: form of {dn}: {field} {x} / {y}").into());
            }
            *forms.entry(x).or_default() += 1;
        }
    }
    println!("  SIDs written whole by Windows: {forms:?}");
    connection.join();
    Ok(())
}

// --- Writes -------------------------------------------------------------------------------------

/// The ACEs of `sid` written on the object, not inherited.
fn explicit(descriptor: &[u8], sid: &Sid) -> Result<HashSet<Ace>> {
    let sd = SecurityDescriptor::decode(descriptor)?;
    Ok(sd
        .dacl
        .map(|d| d.aces)
        .unwrap_or_default()
        .into_iter()
        .filter(|a| !a.is_inherited() && a.sid().as_ref() == Some(sid))
        .collect())
}

fn delegation(trial: &Trial, lab: &Lab, essais: &str) -> Result<()> {
    println!("1. delegation as the Windows wizard");
    let helpdesk = trial.sid(&format!("CN=GG-Helpdesk,{}", groups_ou(lab)))?;
    let ou = trial.descriptors(&[essais])?.pop().ok_or("OU")?;
    let report = trial
        .apply(&actions::delegate(&ou, &helpdesk, &[Template::ResetPasswords]).map_err(debug)?)?;
    let mine = explicit(&trial.descriptor(essais)?, &helpdesk)?;
    let witness_raw = trial.descriptor(&delegated_ou(lab))?;
    let witness = explicit(&witness_raw, &helpdesk)?;
    let wanted: HashSet<Ace> = Template::ResetPasswords
        .aces(&helpdesk)
        .into_iter()
        .collect();
    // The same ACEs as those set by dsacls as the wizard (peupler-windows.ps1).
    check(
        mine == witness && mine == wanted,
        "same ACEs as the delegation of the wizard",
    )?;
    let seen = powershell(
        &format!(
            "$a = (dsacls.exe '{essais}') -match 'GG-Helpdesk'\n\
             $b = (dsacls.exe '{}') -match 'GG-Helpdesk'\n\
             \"OUTIL=\" + ($a -join ' | ')\n\"ASSISTANT=\" + ($b -join ' | ')\n",
            delegated_ou(lab)
        ),
        true,
    )?;
    println!("  dsacls: {seen:?}");
    check(
        seen.get("OUTIL").is_some_and(|o| !o.is_empty())
            && seen.get("OUTIL") == seen.get("ASSISTANT"),
        "dsacls reads the same delegation on both",
    )?;
    let found = security::delegations(&SecurityDescriptor::decode(&witness_raw)?);
    check(
        found.iter().map(|f| f.template).collect::<Vec<_>>() == [Template::ResetPasswords],
        "the delegation of the wizard recognised",
    )?;
    trial.undo(&report)?;
    check(
        explicit(&trial.descriptor(essais)?, &helpdesk)?.is_empty(),
        "delegation removed by the inverse",
    )
}

/// What a copy of the domain gives: complete or not, the names under `OU=Essais-W`, the
/// number of users.
fn copy_of(profile: &Profile, path: &std::path::Path, essais: &str) -> Result<Json> {
    let (reason, _, seconds) = labo::synchronize(profile, path, true)?;
    let source = labo::cache_source(profile, path)?;
    let pages = source.contents(essais, false, labo::quiet());
    let served = pages.copy_date.is_some();
    let mut names: Vec<String> = labo::items(&pages.flux)?
        .iter()
        .map(labo::item_name)
        .collect();
    names.sort();
    let users = labo::items(
        &source
            .search_under("(objectClass=user)".into(), None, labo::quiet())
            .flux,
    )?
    .len();
    source.close();
    Ok(json!({
        "complete": reason.is_some(), "served": served, "names": names,
        "users": users, "seconds": seconds,
    }))
}

/// Run by [`windows_writes`] under an ordinary account: the copy at the path given.
#[test]
#[ignore = "lab"]
fn windows_copy_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let asked: Json = serde_json::from_str(&input)?;
    let mut profile = Profile::new("win.test".to_owned());
    profile.preferred_dc = Some(DC.into());
    let copy = copy_of(
        &profile,
        std::path::Path::new(asked["path"].as_str().ok_or("path")?),
        asked["essais"].as_str().ok_or("essais")?,
    )?;
    println!("RESULT {copy}");
    Ok(())
}

fn local_copy(trial: &Trial, lab: &Lab, essais: &str, scratch: &labo::Scratch) -> Result<()> {
    println!("2. local copy, administrator and ordinary account");
    for name in ["copie-a", "copie-b"] {
        trial.apply(
            &actions::create_user(
                essais,
                &actions::NewUser {
                    full_name: name.into(),
                    identifier: name.replace('-', "."),
                    ..actions::NewUser::default()
                },
            )
            .map_err(debug)?,
        )?;
    }
    let mut profile = Profile::new(lab.domain.clone());
    profile.preferred_dc = Some(DC.into());
    let admin = scratch.path().join("admin.sqlite");
    let ordinary = scratch.path().join("ordinaire.sqlite");
    // The ordinary account: its ticket in a cache of its own, for the child alone.
    let kdc = labo::Kdc::new(lab, DC)?;
    let sam = "gaelle.chateau";
    let refused = kdc.kinit_into(
        &format!("{sam}@{}", lab.realm()),
        &labo::lab_password(labo::SEED, sam)?,
        "ordinaire",
    );
    check(refused.is_none(), "ticket of an ordinary account")?;
    let child = |path: &std::path::Path| -> Result<Json> {
        let input = json!({"path": path.display().to_string(), "essais": essais}).to_string();
        Ok(serde_json::from_str(&labo::child(
            "windows_copy_child",
            &kdc.env("ordinaire"),
            &input,
        )?)?)
    };
    let first = [copy_of(&profile, &admin, essais)?, child(&ordinary)?];
    println!("  complete: {first:?}");
    for x in &first {
        check(
            x["complete"] == true
                && x["served"] == true
                && x["names"] == json!(["copie-a", "copie-b"]),
            "complete copy, served by the copy",
        )?;
    }
    check(
        first[0]["users"] == first[1]["users"] && first[0]["users"].as_u64().unwrap_or(0) >= 240,
        "same users for both accounts",
    )?;
    // Changes made elsewhere: a deletion, a renaming.
    let b = trial.read_one(&format!("CN=copie-b,{essais}"))?;
    trial.apply(&actions::delete(&[b]).map_err(debug)?)?;
    let a = trial.read_one(&format!("CN=copie-a,{essais}"))?;
    trial.apply(&actions::rename(&a, "copie-a2", None, None).map_err(debug)?)?;
    let deltas = [copy_of(&profile, &admin, essais)?, child(&ordinary)?];
    println!("  delta: {deltas:?}");
    kdc.destroy("ordinaire");
    for x in &deltas {
        check(
            x["complete"] == false && x["names"] == json!(["copie-a2"]),
            "delta: renamed and deleted (uSNChanged, Show deleted, or the GUIDs)",
        )?;
    }
    Ok(())
}

/// The A addresses served by the DNS server of the DC (a UDP query, no cache).
fn served(name: &str) -> Result<Vec<Ipv4Addr>> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;
    let id = u16::try_from(std::process::id() & 0xffff).unwrap_or(1);
    let mut question = Vec::new();
    for label in name.split('.') {
        question.push(u8::try_from(label.len())?);
        question.extend(label.as_bytes());
    }
    question.push(0);
    let mut query = id.to_be_bytes().to_vec();
    query.extend([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend(&question);
    query.extend([0, 1, 0, 1]);
    socket.send_to(&query, (DC_ADDRESS, 53))?;
    let mut answer = [0u8; 4096];
    let n = socket.recv(&mut answer)?;
    let answer = answer.get(..n).ok_or("answer")?;
    let count = u16::from_be_bytes([answer[6], answer[7]]);
    let mut position = 12 + question.len() + 4;
    let mut addresses = Vec::new();
    for _ in 0..count {
        position += if answer[position] & 0xC0 == 0xC0 {
            2
        } else {
            question.len()
        };
        let rtype = u16::from_be_bytes([answer[position], answer[position + 1]]);
        let length = usize::from(u16::from_be_bytes([
            answer[position + 8],
            answer[position + 9],
        ]));
        let data = &answer[position + 10..position + 10 + length];
        if rtype == 1 && length == 4 {
            addresses.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        position += 10 + length;
    }
    Ok(addresses)
}

fn dns_write(trial: &Trial, lab: &Lab) -> Result<()> {
    println!("3. a record written by the core, served by the Windows DNS server");
    let zones = dns::zones(&trial.connection).map_err(debug)?;
    let zone = zones
        .iter()
        .find(|z| z.name.eq_ignore_ascii_case(&lab.domain))
        .ok_or("zone")?
        .clone();
    let name = format!("essai-w-{}", std::process::id());
    let address = Ipv4Addr::new(192, 0, 2, 77);
    let requests = vec![Request::Add {
        zone: zone.clone(),
        name: name.clone(),
        rtype: dns_record::A,
        data: dw::read_input(dns_record::A, &address.to_string()).map_err(debug)?,
        ttl: dw::DEFAULT_TTL,
    }];
    let built = dw::build(&trial.connection, requests.clone(), Arc::new(English)).map_err(debug)?;
    let outcome = trial.outcome(&built, None, Some(dw::rebuild(requests, Arc::new(English))))?;
    check(outcome.report.issue == Issue::Applied, "record written")?;
    // The Windows DNS server reads the directory by periodic polling: the record written by
    // LDAP is not served at once (Samba serves it at once).
    let fqdn = format!("{name}.{}", lab.domain);
    let seconds = labo::wait(Duration::from_secs(420), "record served", || {
        Ok(served(&fqdn)? == [address])
    })?;
    println!("  served after {seconds:.1} s");
    let seen = powershell(
        &format!(
            "$r = Get-DnsServerResourceRecord -ZoneName {} -Name {name} -RRType A\n\
             \"ADRESSE=\" + $r.RecordData.IPv4Address\n\"TTL=\" + $r.TimeToLive.TotalSeconds\n",
            lab.domain
        ),
        true,
    )?;
    check(
        seen.get("ADRESSE").map(String::as_str) == Some("192.0.2.77"),
        "Get-DnsServerResourceRecord reads it",
    )?;
    // Undo, by the path of the interface (SOA read again): the node created goes into
    // tombstone instead of being deleted; a deleted dnsNode would stay served by the Windows
    // DNS server (seen: more than 5 min, until the service restarts).
    let inverse = trial.inverse(&outcome.report)?;
    let refreshed =
        dw::refresh_soa(&trial.connection, inverse.clone(), Arc::new(English)).map_err(debug)?;
    let undone = trial.outcome(
        &refreshed,
        Some(outcome.report.id.clone()),
        Some(dw::soa_up_to_date(inverse, Arc::new(English))),
    )?;
    check(undone.report.issue == Issue::Applied, "undone")?;
    let seconds = labo::wait(Duration::from_secs(420), "record no longer served", || {
        Ok(served(&fqdn)?.is_empty())
    })?;
    println!("  gone after {seconds:.1} s");
    let node = labo::entry(
        &trial.connection,
        &dns::node_dn(&zone.dn, &name),
        &["dNSTombstoned"],
        None,
    )?
    .ok_or("node")?;
    check(
        node.values("dNSTombstoned") == [b"TRUE".to_vec()],
        "node in tombstone",
    )
}

/// The nodes `essai-w-*` of the zone, in tombstone, purged (what a trial leaves).
fn purge_dns(trial: &Trial, lab: &Lab) -> Result<()> {
    let zones = dns::zones(&trial.connection).map_err(debug)?;
    let Some(zone) = zones
        .iter()
        .find(|z| z.name.eq_ignore_ascii_case(&lab.domain))
    else {
        return Ok(());
    };
    for e in entries(
        &trial.connection,
        &zone.dn,
        Scope::OneLevel,
        "(name=essai-w-*)",
        &dns::NODE_ATTRIBUTES,
    )? {
        let node = dns::node_from_entry(&e, &zone.name);
        let live: Vec<Request> = node
            .values
            .iter()
            .filter(|v| {
                dns_record::Record::decode(v).is_ok_and(|r| r.rtype != dns_record::TOMBSTONE)
            })
            .map(|v| Request::Delete {
                zone: zone.clone(),
                name: node.name.clone(),
                value: v.clone(),
            })
            .collect();
        if !live.is_empty() {
            let cs =
                dw::build(&trial.connection, live.clone(), Arc::new(English)).map_err(debug)?;
            trial.outcome(&cs, None, Some(dw::rebuild(live, Arc::new(English))))?;
        }
        let purge = vec![Request::Purge {
            zone: zone.clone(),
            name: node.name.clone(),
        }];
        trial.apply(&dw::build(&trial.connection, purge, Arc::new(English)).map_err(debug)?)?;
        println!("  {} purged", node.name);
    }
    Ok(())
}

#[test]
#[ignore = "lab"]
fn windows_writes() -> Result<()> {
    let Some(lab) = windows() else {
        return Ok(());
    };
    let scratch = labo::Scratch::new("windows")?;
    let trial = Trial::new(&lab, &scratch)?;
    purge_dns(&trial, &lab)?;
    let essais = trial.fresh_ou(&lab.base, "Essais-W")?;
    let done = delegation(&trial, &lab, &essais)
        .and_then(|()| local_copy(&trial, &lab, &essais, &scratch))
        .and_then(|()| dns_write(&trial, &lab));
    println!("4. cleaning");
    let cleaned = trial
        .remove_tree(&trials_ou(&lab))
        .and_then(|()| purge_dns(&trial, &lab));
    trial.connection.join();
    done.and(cleaned)
}

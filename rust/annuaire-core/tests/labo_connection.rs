// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Connection and reading against the lab LAB.TEST (port of `test_connexion_labo.py`, J1.1 to
//! J1.3, ADR 0020): discovery of the DCs, sealed bind and RootDSE, paged search of the 20 000
//! users, one level, ranges of a group of 5 000 members, SD flags, an absent object and an
//! escaped value, the TLS modes on dc1 (with `ANNUAIRE_LABO_CA`, the CA of dc1: each Samba DC
//! has its own), no ticket.
//! Read only. See `labo/mod.rs` to run them.

mod labo;

use std::collections::HashSet;

use annuaire_core::connection::{ConnectFailure, Failure};
use annuaire_core::error::{Category, categorize};
use annuaire_core::profile::{Mode, Profile};
use annuaire_core::search::{
    self, OID_PAGES, OID_SD_FLAGS, PAGE_SIZE, SD_WITHOUT_SACL, Value, read_entry, read_ranges,
};
use annuaire_core::session::Scope;
use annuaire_core::source;
use annuaire_core::srv::{self, ResolvConf, SrvError};

use labo::{Result, check, debug, entries, pages};

const DOMAIN: &str = "lab.test";
const BASE: &str = "DC=lab,DC=test";

fn dcs() -> HashSet<String> {
    ["dc1.lab.test", "dc2.lab.test"]
        .into_iter()
        .map(String::from)
        .collect()
}

fn users_filter() -> Result<String> {
    Ok(search::and(&[
        search::eq("objectCategory", Value::Text("person"))?,
        search::eq("objectClass", Value::Text("user"))?,
    ])?)
}

fn connection() -> annuaire_core::Connection {
    source::connection_to(&Profile::new(DOMAIN), None)
}

#[test]
#[ignore = "lab"]
fn srv_records() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let conf = ResolvConf::system();
    let found: HashSet<String> = srv::find_dcs(&conf, DOMAIN)
        .map_err(debug)?
        .into_iter()
        .map(|r| r.target)
        .collect();
    check(found == dcs(), "both DCs found")?;
    let pdc = srv::find_pdc(&conf, DOMAIN).map_err(debug)?;
    check(
        pdc.is_some_and(|r| r.target == "dc1.lab.test"),
        "PDC emulator: the first DC",
    )?;
    check(
        matches!(
            srv::find_dcs(&conf, "nexiste.invalid"),
            Err(SrvError::NotFound { .. })
        ),
        "unknown domain: not found",
    )
}

#[test]
#[ignore = "lab"]
fn sealed_bind() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let connection = connection();
    let state = connection
        .run(true, |link| Ok(link.state.clone()))
        .map_err(debug)?;
    check(dcs().contains(&state.dc), "a DC of the domain")?;
    check(
        state.ssf >= 56 && state.encrypted() && !state.tls,
        "sealed, without TLS",
    )?;
    let dse = &state.root_dse;
    check(dse.default_naming_context == BASE, "default naming context")?;
    check(
        dse.configuration_naming_context == format!("CN=Configuration,{BASE}"),
        "configuration",
    )?;
    check(
        dse.schema_naming_context == format!("CN=Schema,CN=Configuration,{BASE}"),
        "schema",
    )?;
    check(dse.dns_host_name == state.dc, "host name")?;
    check(
        [OID_PAGES, OID_SD_FLAGS]
            .iter()
            .all(|oid| dse.supported_controls.iter().any(|c| c == oid)),
        "paging and SD flags controls",
    )?;
    check(dse.domain_functionality == 7, "functional level 2016")?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn users_flux() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let connection = connection();
    let pages = pages(
        &connection,
        BASE,
        Scope::Subtree,
        &users_filter()?,
        &["sAMAccountName"],
    )?;
    let largest = pages.iter().map(Vec::len).max().unwrap_or(0);
    let total: usize = pages.iter().map(Vec::len).sum();
    println!("  {total} users in {} pages", pages.len());
    check(
        i32::try_from(largest).is_ok_and(|n| n == PAGE_SIZE),
        "full pages",
    )?;
    check(total >= 20_000, "at least 20 000 users")?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn one_level() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let connection = connection();
    let lab = entries(
        &connection,
        &format!("OU=Labo,{BASE}"),
        Scope::OneLevel,
        "(objectClass=*)",
        &["1.1"],
    )?;
    check(
        lab.iter()
            .any(|e| e.dn == format!("OU=Départs,OU=Labo,{BASE}")),
        "OU=Départs under OU=Labo",
    )?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn member_ranges() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let connection = connection();
    let filter = search::and(&[
        search::eq("objectClass", Value::Text("group"))?,
        search::eq("cn", Value::Text("GU-Tous-Salariés"))?,
    ])?;
    let found = entries(&connection, BASE, Scope::Subtree, &filter, &["1.1"])?;
    check(found.len() == 1, "the large group")?;
    let dn = found.first().map(|e| e.dn.clone()).unwrap_or_default();
    let members = connection
        .run(true, move |link| {
            Ok(read_ranges(&mut *link.session, &dn, "member", 1500, None))
        })
        .map_err(debug)?
        .map_err(debug)?;
    let distinct: HashSet<&Vec<u8>> = members.iter().collect();
    check(
        members.len() == 5000 && distinct.len() == 5000,
        "5 000 distinct members",
    )?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn sd_flags() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let connection = connection();
    let dn = format!("CN=Administrator,CN=Users,{BASE}");
    let entry = connection
        .run(true, move |link| {
            read_entry(
                &mut *link.session,
                &dn,
                &["nTSecurityDescriptor".into()],
                "(objectClass=*)",
                Some(SD_WITHOUT_SACL),
                None,
            )
        })
        .map_err(debug)?
        .ok_or("Administrator")?;
    let sd = entry
        .values("nTSecurityDescriptor")
        .first()
        .cloned()
        .unwrap_or_default();
    let offset = |i: usize| {
        sd.get(i..i + 4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_le_bytes)
    };
    let (owner, group, sacl, dacl) = (offset(4), offset(8), offset(12), offset(16));
    check(
        owner != 0 && group != 0 && dacl != 0 && sacl == 0,
        "owner, group and DACL, no SACL",
    )?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn absent_and_escaped() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let connection = connection();
    let dn = format!("CN=absent-j1,{BASE}");
    let absent = connection
        .run(true, move |link| {
            read_entry(
                &mut *link.session,
                &dn,
                &["cn".into()],
                "(objectClass=*)",
                None,
                None,
            )
        })
        .map_err(debug)?;
    check(absent.is_none(), "absent object: none")?;
    // A value that would break an unescaped filter simply finds nothing.
    let trap = search::eq("sAMAccountName", Value::Text("*)(sAMAccountName=*"))?;
    let found = entries(&connection, BASE, Scope::Subtree, &trap, &["1.1"])?;
    check(found.is_empty(), "escaped value: nothing")?;
    connection.join();
    Ok(())
}

#[test]
#[ignore = "lab"]
fn tls_modes() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let Ok(ca) = std::env::var("ANNUAIRE_LABO_CA") else {
        println!("  ANNUAIRE_LABO_CA not set: skipped");
        return Ok(());
    };
    for mode in [Mode::Ldaps, Mode::StartTls] {
        let mut profile = Profile::new(DOMAIN);
        profile.mode = mode;
        profile.ca = Some(ca.clone().into());
        let connection = source::connection_to(&profile, Some("dc1.lab.test"));
        let state = connection
            .run(true, |link| Ok(link.state.clone()))
            .map_err(debug)?;
        check(
            state.tls && state.ssf == 0 && state.encrypted(),
            &format!("{mode:?}: TLS, no SASL layer"),
        )?;
        connection.join();
    }
    Ok(())
}

/// Run by [`without_ticket`] in a process of its own, with an empty credential cache.
#[test]
#[ignore = "lab"]
fn without_ticket_child() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    if std::env::var_os("ANNUAIRE_LABO_SANS_TICKET").is_none() {
        return Ok(());
    }
    let connection = connection();
    let failure = connection
        .run(true, |link| Ok(link.state.dc.clone()))
        .err()
        .ok_or("bound without a ticket")?;
    let category = match &failure {
        Failure::Connect(ConnectFailure::Bind { error, .. }) => Some(categorize(error)),
        Failure::Connect(ConnectFailure::NoDc { failures, .. }) => {
            failures.first().map(|(_, e)| categorize(e))
        }
        _ => None,
    };
    println!("  {failure:?}");
    check(category == Some(Category::Ticket), "no ticket: get one")
}

#[test]
#[ignore = "lab"]
fn without_ticket() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("sans-ticket")?;
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "without_ticket_child",
            "--nocapture",
        ])
        .env("ANNUAIRE_LABO_SANS_TICKET", "1")
        .env(
            "KRB5CCNAME",
            format!("FILE:{}", scratch.path().join("vide").display()),
        )
        .output()?;
    print!("{}", String::from_utf8_lossy(&output.stdout));
    check(output.status.success(), "the child saw the missing ticket")
}

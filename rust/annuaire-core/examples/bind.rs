// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Feasibility check of ADR 0016: GSSAPI bind (sealed on port 389, or over LDAPS / StartTLS
//! with the domain CA), `whoami`, then a paged search of every `user` object.
//!
//! ```text
//! KRB5CCNAME=FILE:… cargo run --release --example bind -- dc1.lab.test LAB.TEST DC=lab,DC=test
//! KRB5CCNAME=FILE:… cargo run --release --example bind -- dc1.lab.test LAB.TEST DC=lab,DC=test \
//!     ldaps ca.pem
//! ```
//!
//! The Kerberos service name is `ldap/<dc>@<REALM>`: with no realm, the default realm of
//! the host would be used.

use std::error::Error;
use std::time::Instant;

use ldap3::adapters::{Adapter, EntriesOnly, PagedResults};
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dc, realm, base, rest @ ..] = args.as_slice() else {
        return Err("usage: bind DC REALM BASE [sealed|ldaps|starttls [CA.pem]]".into());
    };
    let mode = rest.first().map_or("sealed", String::as_str);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(dc, realm, base, mode, rest.get(1)))
}

async fn run(
    dc: &str,
    realm: &str,
    base: &str,
    mode: &str,
    ca: Option<&String>,
) -> Result<(), Box<dyn Error>> {
    let start = Instant::now();
    let mut settings = LdapConnSettings::new();
    if let Some(ca) = ca {
        let pem = std::fs::read(ca)?;
        let connector = native_tls::TlsConnector::builder()
            .disable_built_in_roots(true)
            .add_root_certificate(native_tls::Certificate::from_pem(&pem)?)
            .build()?;
        settings = settings.set_connector(connector);
    }
    let url = match mode {
        "ldaps" => format!("ldaps://{dc}:636"),
        "starttls" => {
            settings = settings.set_starttls(true);
            format!("ldap://{dc}:389")
        }
        _ => format!("ldap://{dc}:389"),
    };
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url).await?;
    ldap3::drive!(conn);
    let bind = ldap.sasl_gssapi_bind(&format!("{dc}@{realm}")).await?;
    println!("bind: rc {} in {:?}", bind.rc, start.elapsed());
    let whoami = ldap.extended(ldap3::exop::WhoAmI).await?.0;
    let identity = String::from_utf8_lossy(&whoami.val.unwrap_or_default()).into_owned();
    println!("whoami: {identity}");

    let start = Instant::now();
    let adapters: Vec<Box<dyn Adapter<_, _>>> = vec![
        Box::new(EntriesOnly::new()),
        Box::new(PagedResults::new(1000)),
    ];
    let mut stream = ldap
        .streaming_search_with(
            adapters,
            base,
            Scope::Subtree,
            "(objectClass=user)",
            vec!["sAMAccountName", "objectSid", "userAccountControl"],
        )
        .await?;
    let mut count = 0usize;
    let mut first = None;
    while let Some(entry) = stream.next().await? {
        if first.is_none() {
            first = Some(start.elapsed());
            println!("first entry: {}", SearchEntry::construct(entry).dn);
        }
        count += 1;
    }
    let result = stream.finish().await;
    println!(
        "search: rc {}, {count} entries, first after {:?}, all after {:?}",
        result.rc,
        first.unwrap_or_default(),
        start.elapsed()
    );
    ldap.unbind().await?;
    Ok(())
}

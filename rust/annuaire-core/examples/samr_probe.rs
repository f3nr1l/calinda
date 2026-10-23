// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Probe of `samr` against a server (ADR 0023 § 6): its domains, then the local groups that
//! hold one of the SIDs given (the account domain first, then `Builtin`).
//!
//!     KRB5CCNAME=FILE:… cargo run --example samr_probe -- fs1.lab.test S-1-5-21-…-1104 …
//!         [--sign-only | --vectors]
//!
//! `--vectors` prints instead, one JSON object per line, the request and response stubs of
//! each call (`SamrConnect5`, `SamrEnumerateDomainsInSamServer`, `SamrLookupDomainInSamServer`,
//! `SamrOpenDomain`, `SamrGetAliasMembership` once with the SIDs given and once with each SID
//! alone, `SamrCloseHandle`), for `tests/vecteurs/samr.json`.

use std::time::{Duration, Instant};

use annuaire_codecs::Sid;
use annuaire_core::rpc::Rpc;
use annuaire_core::samr::{self, Samr, opnum};
use annuaire_core::smb::Options;
use annuaire_core::smb::pipe::Pipe;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut server = None;
    let mut sids = Vec::new();
    let mut flag = None;
    for arg in std::env::args().skip(1) {
        if arg.starts_with("--") {
            flag = Some(arg);
        } else if server.is_none() {
            server = Some(arg);
        } else {
            sids.push(arg.parse::<Sid>()?);
        }
    }
    let server = server.ok_or("server")?;
    let options = Options {
        encrypt: flag.as_deref() != Some("--sign-only"),
        timeout: Duration::from_secs(30),
        ..Options::default()
    };
    if flag.as_deref() == Some("--vectors") {
        return vectors(&server, &options, &sids);
    }
    let start = Instant::now();
    let mut service = Samr::open(&server, &options)?;
    println!("connected in {:?}", start.elapsed());
    for name in service.domains()? {
        println!("domain {name}: {}", service.lookup_domain(&name)?);
    }
    let t = Instant::now();
    let groups = service.local_groups(&sids)?;
    println!("{} local groups in {:?}", groups.len(), t.elapsed());
    for g in groups {
        println!("- {g}");
    }
    service.close();
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn line(server: &str, opnum: u16, extra: &str, request: &[u8], response: &[u8]) {
    println!(
        "{{\"serveur\": \"{server}\", \"opnum\": {opnum}{extra}, \"requete\": \"{}\", \"reponse\": \"{}\"}}",
        hex(request),
        hex(response)
    );
}

fn vectors(
    server: &str,
    options: &Options,
    sids: &[Sid],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rpc = Rpc::bind(Pipe::open(server, "samr", options)?, samr::INTERFACE)?;
    let request = samr::connect5_request(&format!("\\\\{server}"), samr::SERVER_ACCESS);
    let response = rpc.call(opnum::CONNECT5, &request)?;
    line(server, opnum::CONNECT5, "", &request, &response);
    let handle = samr::parse_connect5(&response)?;

    let request = samr::enumerate_domains_request(&handle, 0);
    let response = rpc.call(opnum::ENUMERATE_DOMAINS, &request)?;
    line(server, opnum::ENUMERATE_DOMAINS, "", &request, &response);
    let (_, names, _) = samr::parse_enumerate_domains(&response)?;

    let mut domains = vec![samr::builtin()];
    for name in names.iter().filter(|n| !n.eq_ignore_ascii_case("Builtin")) {
        let request = samr::lookup_domain_request(&handle, name);
        let response = rpc.call(opnum::LOOKUP_DOMAIN, &request)?;
        line(
            server,
            opnum::LOOKUP_DOMAIN,
            &format!(", \"domaine\": \"{name}\""),
            &request,
            &response,
        );
        domains.push(samr::parse_lookup_domain(&response)?);
    }

    let quoted = |list: &[Sid]| {
        list.iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    for domain in &domains {
        let request = samr::open_domain_request(&handle, domain, samr::DOMAIN_ACCESS);
        let response = rpc.call(opnum::OPEN_DOMAIN, &request)?;
        line(
            server,
            opnum::OPEN_DOMAIN,
            &format!(", \"sid\": \"{domain}\""),
            &request,
            &response,
        );
        let domain_handle = samr::parse_handle(&response, "SamrOpenDomain")?;
        let mut asked: Vec<Vec<Sid>> = vec![sids.to_vec()];
        asked.extend(sids.iter().map(|s| vec![*s]));
        for list in asked {
            let request = samr::alias_membership_request(&domain_handle, &list);
            let response = rpc.call(opnum::GET_ALIAS_MEMBERSHIP, &request)?;
            line(
                server,
                opnum::GET_ALIAS_MEMBERSHIP,
                &format!(
                    ", \"domaine_sid\": \"{domain}\", \"sids\": [{}]",
                    quoted(&list)
                ),
                &request,
                &response,
            );
        }
        let request = samr::close_request(&domain_handle);
        let response = rpc.call(opnum::CLOSE_HANDLE, &request)?;
        line(server, opnum::CLOSE_HANDLE, "", &request, &response);
    }
    let request = samr::close_request(&handle);
    let response = rpc.call(opnum::CLOSE_HANDLE, &request)?;
    line(server, opnum::CLOSE_HANDLE, "", &request, &response);
    rpc.into_transport().close();
    Ok(())
}

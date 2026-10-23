// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Probe of `srvsvc` against a file server (ADR 0023 § 1): the shares at level 502 (or 1),
//! then each disk share read again at levels 502 and 1005, descriptors in SDDL.
//!
//!     KRB5CCNAME=FILE:… cargo run --example shares_probe -- fs1.lab.test [--sign-only | --vectors]
//!
//! `--vectors` prints instead, one JSON object per line, the request and response stubs of
//! `NetrShareEnum` (levels 1 and 502) and `NetrShareGetInfo` (502 and 1005) of each disk share,
//! for `tests/vecteurs/srvsvc.json`.

use std::time::{Duration, Instant};

use annuaire_codecs::{sd::SecurityDescriptor, sddl};
use annuaire_core::rpc::Rpc;
use annuaire_core::smb::Options;
use annuaire_core::smb::pipe::Pipe;
use annuaire_core::srvsvc::{self, Srvsvc};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let server = args.next().ok_or("server")?;
    let flag = args.next();
    let options = Options {
        encrypt: flag.as_deref() != Some("--sign-only"),
        timeout: Duration::from_secs(30),
        ..Options::default()
    };
    if flag.as_deref() == Some("--vectors") {
        return vectors(&server, &options);
    }
    let start = Instant::now();
    let mut service = Srvsvc::open(&server, &options)?;
    println!("bound in {:?}", start.elapsed());
    let t = Instant::now();
    let shares = service.shares()?;
    println!("{} shares in {:?}", shares.len(), t.elapsed());
    for share in &shares {
        println!(
            "- {} type 0x{:08X} level {} uses {}/{} path {:?} remark {:?}",
            share.name,
            share.kind,
            share.level,
            share.current_uses,
            share.max_uses,
            share.path,
            share.remark
        );
        if let Some(d) = &share.descriptor {
            println!("  sddl {}", sddl(d));
        }
        if share.is_disk() {
            let again = service.share(&share.name)?;
            println!(
                "  get 502: same {}; flags 1005: {:?}",
                again == *share,
                service.share_flags(&share.name)
            );
        }
    }
    service.close();
    Ok(())
}

fn sddl(descriptor: &[u8]) -> String {
    match SecurityDescriptor::decode(descriptor).map(|d| sddl::sd_to_sddl(&d, None)) {
        Ok(Ok(text)) => text,
        other => format!("(undecodable: {other:?})"),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn vectors(server: &str, options: &Options) -> Result<(), Box<dyn std::error::Error>> {
    let mut rpc = Rpc::bind(Pipe::open(server, "srvsvc", options)?, srvsvc::INTERFACE)?;
    let unc = format!("\\\\{server}");
    let mut names = Vec::new();
    for level in [1, 502] {
        let request = srvsvc::enum_request(&unc, level);
        let response = rpc.call(15, &request)?;
        if level == 502 {
            names = srvsvc::parse_enum(&response)?
                .into_iter()
                .filter(|s| s.is_disk())
                .map(|s| s.name)
                .collect();
        }
        println!(
            "{{\"serveur\": \"{server}\", \"opnum\": 15, \"niveau\": {level}, \"requete\": \"{}\", \"reponse\": \"{}\"}}",
            hex(&request),
            hex(&response)
        );
    }
    for name in names {
        for level in [502, 1005] {
            let request = srvsvc::get_request(&unc, &name, level);
            let response = rpc.call(16, &request)?;
            println!(
                "{{\"serveur\": \"{server}\", \"opnum\": 16, \"niveau\": {level}, \"partage\": \"{name}\", \"requete\": \"{}\", \"reponse\": \"{}\"}}",
                hex(&request),
                hex(&response)
            );
        }
    }
    rpc.into_transport().close();
    Ok(())
}

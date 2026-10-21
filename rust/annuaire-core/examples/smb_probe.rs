// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Probe of the SMB client against a DC (ADR 0017): Kerberos session on the credential
//! cache, the `Policies` folder listed and a file read with its descriptor, each in one
//! compound request.
//!
//!     KRB5CCNAME=FILE:… cargo run --example smb_probe -- dc1.lab.test lab.test [--sign-only | --smb2]

#![allow(clippy::indexing_slicing)] // a probe: a missing response may panic

use std::time::{Duration, Instant};

use annuaire_core::smb::msg::{self, Create, RELATED_FILE_ID};
use annuaire_core::smb::{Client, Kerberos, Options};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let server = args.next().ok_or("server")?;
    let domain = args.next().ok_or("domain")?;
    let flag = args.next();
    let options = Options {
        encrypt: flag.as_deref() != Some("--sign-only"),
        smb2: flag.as_deref() == Some("--smb2"),
        timeout: Duration::from_secs(30),
        ..Options::default()
    };
    let start = Instant::now();
    let mut auth = Kerberos::new(&server, &domain)?;
    let mut client = Client::connect(&server, "SYSVOL", &options, &mut auth)?;
    println!(
        "session in {:?}: {:?}, {} credits",
        start.elapsed(),
        client.negotiated(),
        client.credits()
    );
    let policies = format!("{domain}\\Policies");
    let gpt = format!("{policies}\\{{31B2F340-016D-11D2-945F-00C04FB984F9}}\\GPT.INI");
    let t = Instant::now();
    let listing = vec![
        msg::create(&Create {
            path: &policies,
            access: 0x0000_0001 | 0x0000_0080,
            share: 7,
            disposition: 1,
            options: 1,
            ..Create::default()
        }),
        msg::query_directory(&RELATED_FILE_ID, 0, "*", 65536),
        msg::close(&RELATED_FILE_ID),
    ];
    let reading = vec![
        msg::create(&Create {
            path: &gpt,
            access: 0x0000_0001 | 0x0000_0080 | 0x0002_0000,
            share: 7,
            disposition: 1,
            options: 0x40,
            ..Create::default()
        }),
        msg::read(&RELATED_FILE_ID, 0, 65536),
        msg::query_info(&RELATED_FILE_ID, msg::INFO_SECURITY, 0, 7, 65536),
        msg::close(&RELATED_FILE_ID),
    ];
    let missing = vec![
        msg::create(&Create {
            path: "nowhere\\to\\be\\found",
            access: 0x80,
            share: 7,
            disposition: 1,
            ..Create::default()
        }),
        msg::close(&RELATED_FILE_ID),
    ];
    let results = client.exchange(&[listing, reading, missing])?;
    println!(
        "3 compounds in {:?}, {} round trip(s)",
        t.elapsed(),
        client.round_trips
    );
    let entries = msg::parse_directory(&msg::parse_output(&results[0][1].ok()?.msg, "QD")?)?;
    let names: Vec<_> = entries.iter().map(|e| e.name.as_str()).collect();
    println!("{policies}: {} entries: {names:?}", entries.len());
    let content = msg::parse_read(&results[1][1].ok()?.msg)?;
    println!("GPT.INI: {:?}", String::from_utf8_lossy(&content));
    let sd = msg::parse_output(&results[1][2].ok()?.msg, "QI")?;
    println!(
        "descriptor: {} bytes, control 0x{:02X}{:02X}",
        sd.len(),
        sd[3],
        sd[2]
    );
    println!(
        "missing: 0x{:08X}, then 0x{:08X}",
        results[2][0].status(),
        results[2][1].status()
    );
    client.close();
    println!("total {:?}", start.elapsed());
    Ok(())
}

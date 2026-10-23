// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The registry configuration of a Samba server through `winreg` (ADR 0023 § 9):
//!
//!     KRB5CCNAME=FILE:… cargo run --example winreg_probe -- fs1.lab.test [--vectors]
//!
//! Lists the sections under `HKLM\Software\Samba\smbconf` and the values of each, with the
//! time taken. `--vectors` prints instead, one JSON object per line, the request and response
//! stubs of each call (`OpenLocalMachine`, `BaseRegOpenKey`, `BaseRegEnumKey`,
//! `BaseRegEnumValue`, `BaseRegQueryValue`, and on a trial key of its own, made then deleted,
//! `BaseRegCreateKey`, `BaseRegSetValue`, `BaseRegDeleteValue`, `BaseRegDeleteKey`,
//! `BaseRegCloseKey`), for `tests/vecteurs/winreg.json`.

use std::time::{Duration, Instant};

use annuaire_core::rpc::Rpc;
use annuaire_core::smb::Options;
use annuaire_core::smb::pipe::Pipe;
use annuaire_core::winreg::{self, MAXIMUM_ALLOWED, SmbConf, Value, opnum};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let server = args.next().ok_or("server")?;
    let options = Options {
        timeout: Duration::from_secs(30),
        ..Options::default()
    };
    if args.next().as_deref() == Some("--vectors") {
        return vectors(&server, &options);
    }
    let start = Instant::now();
    let mut conf = SmbConf::open(&server, &options)?;
    println!("opened in {:?}", start.elapsed());
    let t = Instant::now();
    let sections = conf.sections()?;
    println!("{} sections in {:?}", sections.len(), t.elapsed());
    for section in sections {
        let t = Instant::now();
        match conf.values(&section) {
            Ok(values) => {
                println!("[{section}] ({:?})", t.elapsed());
                for (name, text) in values.unwrap_or_default() {
                    println!("    {name} = {text}");
                }
            }
            Err(e) => println!("[{section}] {e}"),
        }
    }
    conf.close();
    Ok(())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// One call, printed as a line of JSON; returns the response stub.
fn call(
    rpc: &mut Rpc<Pipe>,
    server: &str,
    op: u16,
    what: &str,
    request: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let response = rpc.call(op, &request)?;
    println!(
        "{{\"serveur\": \"{server}\", \"opnum\": {op}, \"appel\": \"{what}\", \"requete\": \"{}\", \"reponse\": \"{}\"}}",
        hex(&request),
        hex(&response)
    );
    Ok(response)
}

fn vectors(server: &str, options: &Options) -> Result<(), Box<dyn std::error::Error>> {
    let mut rpc = Rpc::bind(Pipe::open(server, "winreg", options)?, winreg::INTERFACE)?;
    let s = server;
    let r = call(
        &mut rpc,
        s,
        opnum::OPEN_LOCAL_MACHINE,
        "OpenLocalMachine",
        winreg::open_local_machine_request(MAXIMUM_ALLOWED),
    )?;
    let hklm = winreg::parse_handle(&r, "OpenLocalMachine")?;
    let r = call(
        &mut rpc,
        s,
        opnum::OPEN_KEY,
        "BaseRegOpenKey",
        winreg::open_key_request(&hklm, winreg::SMBCONF, MAXIMUM_ALLOWED),
    )?;
    let root = winreg::parse_handle(&r, "BaseRegOpenKey")?;
    // A key that does not exist: ERROR_FILE_NOT_FOUND.
    call(
        &mut rpc,
        s,
        opnum::OPEN_KEY,
        "BaseRegOpenKey",
        winreg::open_key_request(&root, "Calinda-absent", MAXIMUM_ALLOWED),
    )?;
    let mut sections = Vec::new();
    for index in 0.. {
        let r = call(
            &mut rpc,
            s,
            opnum::ENUM_KEY,
            "BaseRegEnumKey",
            winreg::enum_key_request(&root, index),
        )?;
        match winreg::parse_enum_key(&r)? {
            Some(name) => sections.push(name),
            None => break,
        }
    }
    for section in &sections {
        let r = call(
            &mut rpc,
            s,
            opnum::OPEN_KEY,
            "BaseRegOpenKey",
            winreg::open_key_request(&root, section, MAXIMUM_ALLOWED),
        )?;
        let key = winreg::parse_handle(&r, "BaseRegOpenKey")?;
        for index in 0.. {
            let r = call(
                &mut rpc,
                s,
                opnum::ENUM_VALUE,
                "BaseRegEnumValue",
                winreg::enum_value_request(&key, index, 0x2000),
            )?;
            if winreg::parse_enum_value(&r)?.is_none() {
                break;
            }
        }
        for name in ["path", "calinda-absent"] {
            call(
                &mut rpc,
                s,
                opnum::QUERY_VALUE,
                "BaseRegQueryValue",
                winreg::query_value_request(&key, name, 0x2000),
            )?;
        }
        call(
            &mut rpc,
            s,
            opnum::CLOSE_KEY,
            "BaseRegCloseKey",
            winreg::handle_request(&key),
        )?;
    }
    // Writes on a trial key of its own, deleted at the end.
    let trial = format!("Essai-Vecteurs-{}", std::process::id());
    let r = call(
        &mut rpc,
        s,
        opnum::CREATE_KEY,
        "BaseRegCreateKey",
        winreg::create_key_request(&root, &trial, MAXIMUM_ALLOWED),
    )?;
    let (key, _) = winreg::parse_create_key(&r)?;
    let written = (|| -> Result<(), Box<dyn std::error::Error>> {
        for (name, text) in [
            ("comment", "Vecteur d’essai, accentué"),
            ("csc policy", "manual"),
        ] {
            call(
                &mut rpc,
                s,
                opnum::SET_VALUE,
                "BaseRegSetValue",
                winreg::set_value_request(&key, name, &Value::sz(text)),
            )?;
        }
        call(
            &mut rpc,
            s,
            opnum::DELETE_VALUE,
            "BaseRegDeleteValue",
            winreg::name_request(&key, "csc policy"),
        )?;
        Ok(())
    })();
    call(
        &mut rpc,
        s,
        opnum::CLOSE_KEY,
        "BaseRegCloseKey",
        winreg::handle_request(&key),
    )?;
    call(
        &mut rpc,
        s,
        opnum::DELETE_KEY,
        "BaseRegDeleteKey",
        winreg::name_request(&root, &trial),
    )?;
    written?;
    for key in [root, hklm] {
        rpc.call(opnum::CLOSE_KEY, &winreg::handle_request(&key))?;
    }
    rpc.into_transport().close();
    Ok(())
}

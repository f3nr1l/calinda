// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Probe of what a file server lets an account do with the owner and the SACL of an element
//! (ADR 0023 § 5, J8.7), with the ticket of `KRB5CCNAME`: `read [sacl]` prints the descriptor;
//! `owner SID [backup]` writes the owner (with `FILE_OPEN_FOR_BACKUP_INTENT` if `backup`);
//! `sacl 'S:…' [backup]` writes the SACL. The NTSTATUS of a refusal is printed, not hidden.
//!
//!     KRB5CCNAME=FILE:… cargo run --example security_probe -- fs1.lab.test Commun 'dossier' owner S-1-5-32-544 backup

use std::time::Duration;

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sddl;
use annuaire_core::sysvol::{
    BACKUP_INTENT, INFO_OGD, INFO_OWNER, INFO_SACL, Protection, Session, SysvolError,
};

fn status(e: &SysvolError) -> String {
    e.ntstatus()
        .map_or_else(|| e.to_string(), |s| format!("0x{s:08X}"))
}

fn read(session: &mut Session, path: &str, info: u32) -> String {
    match session.descriptors(&[path.to_owned()], info) {
        Ok(mut r) => match r.pop() {
            Some(Ok(bytes)) => SecurityDescriptor::decode(&bytes)
                .ok()
                .and_then(|d| sddl::sd_to_sddl(&d, None).ok())
                .unwrap_or_else(|| "(undecodable)".into()),
            Some(Err(s)) => format!("refused 0x{s:08X}"),
            None => "no answer".into(),
        },
        Err(e) => format!("error {}", status(&e)),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [server, share, path, command, rest @ ..] = args.as_slice() else {
        return Err("server share path read|owner|sacl [value] [backup]".into());
    };
    let backup = rest.iter().any(|a| a == "backup");
    let options = if backup { BACKUP_INTENT } else { 0 };
    let mut session = Session::open_share(
        server,
        share,
        Protection::Encrypted,
        Duration::from_secs(30),
    )?;
    match command.as_str() {
        "read" => {
            let sacl = rest.iter().any(|a| a == "sacl");
            let info = if sacl { INFO_OGD | INFO_SACL } else { INFO_OGD };
            println!("READ {}", read(&mut session, path, info));
        }
        "owner" | "sacl" => {
            let value = rest.first().ok_or("value")?;
            let (text, info) = if command == "owner" {
                (format!("O:{value}"), INFO_OWNER)
            } else {
                (value.clone(), INFO_SACL)
            };
            let d = sddl::sd_from_sddl(&text, None, false)?;
            let written = session.set_descriptor_with(path, &d.encode()?, info, options);
            println!(
                "WRITE {}",
                written.map_or_else(|e| format!("refused {}", status(&e)), |()| "ok".into())
            );
            println!("READ {}", read(&mut session, path, info | INFO_OGD));
        }
        other => return Err(format!("unknown command {other}").into()),
    }
    session.close();
    Ok(())
}

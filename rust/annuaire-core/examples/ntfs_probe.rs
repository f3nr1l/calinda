// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Probe of the NTFS descriptors of a share (ADR 0023 § 5): the descriptor of a path in SDDL;
//! with a DACL in SDDL, that DACL written as Calinda writes it (`ntfs::written`), then read
//! back; with `--names`, the SIDs of the descriptor named by the server (`lsarpc`).
//!
//!     KRB5CCNAME=FILE:… cargo run --example ntfs_probe -- fs1.lab.test Commun 'dossier' ['PAI(A;OICI;FA;;;BA)'] [--names]

use std::time::Duration;

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sddl;
use annuaire_core::ntfs;
use annuaire_core::sysvol::{INFO_DACL, INFO_OGD, Protection, Session};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [server, share, path, rest @ ..] = args.as_slice() else {
        return Err("server share path [dacl] [--names]".into());
    };
    let names = rest.iter().any(|a| a == "--names");
    let dacl = rest.iter().find(|a| *a != "--names");
    let mut session = Session::open_share(
        server,
        share,
        Protection::Encrypted,
        Duration::from_secs(30),
    )?;
    let read = |session: &mut Session| -> Result<SecurityDescriptor, Box<dyn std::error::Error>> {
        let bytes = session
            .descriptors(std::slice::from_ref(path), INFO_OGD)?
            .into_iter()
            .next()
            .ok_or("no answer")?
            .map_err(|s| format!("NTSTATUS 0x{s:08X}"))?;
        Ok(SecurityDescriptor::decode(&bytes)?)
    };
    let before = read(&mut session)?;
    println!("read     {}", sddl::sd_to_sddl(&before, None)?);
    if let Some(text) = dacl {
        let protected = text.starts_with('P');
        let parsed = sddl::sd_from_sddl(&format!("D:{text}"), None, false)?;
        let wanted = ntfs::written(&before, ntfs::dacl_of(&parsed), protected);
        println!("written  {}", sddl::sd_to_sddl(&wanted, None)?);
        session.set_descriptor(path, &wanted.encode()?, INFO_DACL)?;
        let after = read(&mut session)?;
        println!("read     {}", sddl::sd_to_sddl(&after, None)?);
        println!(
            "same permissions: {}",
            ntfs::same_permissions(&after, &wanted)
        );
    }
    session.close();
    if names {
        let sids: Vec<_> = before
            .owner
            .iter()
            .chain(before.group.iter())
            .copied()
            .chain(ntfs::dacl_of(&before).iter().filter_map(|a| a.sid()))
            .collect();
        let options = Protection::Encrypted.options(Duration::from_secs(30));
        for (sid, name) in annuaire_core::lsarpc::name_sids(server, &sids, &options)? {
            println!("{sid} = {name}");
        }
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The SYSVOL of a DC limited to SMB 2.1, with signing only (ADR 0021). LAB.TEST only: dc2 is
//! set to `server max protocol = SMB2_10` for the time of the trial (its `smb.conf` saved
//! before, put back after and Samba restarted both times, even after a failure; a copy left
//! by an interrupted trial is put back first). Then:
//!
//! - before and after: dc1 and dc2 negotiate SMB 3.1.1, encrypted, with or without the option;
//! - option on: dc2 negotiates SMB 2.1, signed only (HMAC-SHA256); the GPT.INI of the Default
//!   Domain Policy read as the disk of dc2 holds it; the SYSVOL inventory read through a
//!   connection whose profile has the option (the propagation of the profile to the SYSVOL
//!   sessions); a folder and a file written, seen on the disk of dc2, then removed;
//! - option off: the session refused (`Smb2Only`), and the inventory of the same profile says
//!   so.
//!
//! The SYSVOL of a Samba DC is not replicated: what is written on dc2 stays there, and is
//! removed before the end. See `labo/mod.rs` to run it.

mod labo;

use std::time::Duration;

use annuaire_core::gpo::{self, SysvolReadError};
use annuaire_core::smb::ErrorKind;
use annuaire_core::smb::msg::{dialect, signing};
use annuaire_core::source;
use annuaire_core::sysvol::{self, Protection, Session, SysvolError};

use labo::{Lab, Result, check, debug};

const CONF: &str = "/etc/samba/smb.conf";
const SAVED: &str = "/etc/samba/smb.conf.annuaire-smb2";
const DEFAULT_POLICY: &str = "{31B2F340-016D-11D2-945F-00C04FB984F9}";
const DELAY: Duration = Duration::from_secs(30);

fn open(dc: &str, protection: Protection) -> sysvol::Result<Session> {
    Session::open(dc, protection, DELAY)
}

/// Dialect and encryption of a session opened and closed at once.
fn negotiated(dc: &str, protection: Protection) -> Result<(u16, bool)> {
    let session = open(dc, protection).map_err(debug)?;
    let n = session.negotiated();
    session.close();
    Ok((n.dialect, n.encrypted))
}

/// dc1 and dc2 as they are outside the trial: SMB 3.1.1, encrypted, with or without the
/// option.
fn smb3_everywhere(lab: &Lab) -> Result<()> {
    for dc in [lab.pdc_name(), lab.other_dc.clone()] {
        for protection in [Protection::Encrypted, Protection::AllowSmb2] {
            check(
                negotiated(&dc, protection)? == (dialect::SMB311, true),
                &format!("{dc}, {protection:?}: SMB 3.1.1 encrypted"),
            )?;
        }
    }
    Ok(())
}

/// Samba of dc2 restarted, until a session of `protection` opens (3 min at most).
fn restart_dc2(lab: &Lab, script: &str, protection: Protection) -> Result<()> {
    labo::ssh("dc2", script)?;
    let seconds = labo::wait(Duration::from_secs(180), "SYSVOL of dc2 open", || {
        Ok(open(&lab.other_dc, protection).map(Session::close).is_ok())
    })?;
    println!("  dc2 answers after {seconds:.0} s");
    Ok(())
}

/// dc2 limited to SMB 2.1: the configuration saved (a copy left by an interrupted trial put
/// back first), the line added to `[global]`.
fn limit_dc2(lab: &Lab) -> Result<()> {
    restart_dc2(
        lab,
        &format!(
            "set -e\n\
             if sudo test -e {SAVED}; then sudo cp -p {SAVED} {CONF}; fi\n\
             sudo cp -p {CONF} {SAVED}\n\
             sudo sed -i '/^\\[global\\]/a\\\tserver max protocol = SMB2_10' {CONF}\n\
             sudo testparm -s --parameter-name='server max protocol' 2>/dev/null\n\
             sudo systemctl restart samba-ad-dc\n"
        ),
        Protection::AllowSmb2,
    )
}

/// The configuration of dc2 put back, Samba restarted, SMB 3 back.
fn restore_dc2(lab: &Lab) -> Result<()> {
    restart_dc2(
        lab,
        &format!(
            "set -e\n\
             if sudo test -e {SAVED}; then sudo cp -p {SAVED} {CONF}; sudo rm -f {SAVED}; fi\n\
             sudo systemctl restart samba-ad-dc\n"
        ),
        Protection::Encrypted,
    )
}

/// Content of a file of the SYSVOL of dc2 read on its disk (a folder: empty); `None`: absent.
fn on_disk(lab: &Lab, path: &str) -> Result<Option<String>> {
    let out = labo::ssh(
        "dc2",
        &format!(
            "f={}\n\
             if sudo test -e \"$f\"; then echo present; sudo cat \"$f\" 2>/dev/null || true; \
             else echo absent; fi\n",
            labo::quote(&format!("/var/lib/samba/sysvol/{}/{path}", lab.domain))
        ),
    )?;
    match out.split_once('\n') {
        Some(("present", content)) => Ok(Some(content.to_owned())),
        Some(("absent", _)) => Ok(None),
        _ => Err(format!("unexpected answer of dc2: {out}").into()),
    }
}

/// With the option: SMB 2.1 signed, a read, the inventory through a profile, a write undone.
fn signed_only(lab: &Lab) -> Result<()> {
    let dc2 = lab.other_dc.as_str();
    let mut session = open(dc2, Protection::AllowSmb2).map_err(debug)?;
    let n = session.negotiated();
    check(
        (n.dialect, n.encrypted, n.signing) == (dialect::SMB210, false, signing::HMAC_SHA256),
        "dc2: SMB 2.1, not encrypted, signed with HMAC-SHA256",
    )?;
    let gpt = format!("{}\\Policies\\{DEFAULT_POLICY}\\GPT.INI", lab.domain);
    let read = session.read(&[gpt]).map_err(debug)?;
    let disk = on_disk(lab, &format!("Policies/{DEFAULT_POLICY}/GPT.INI"))?;
    check(
        read.first()
            .cloned()
            .flatten()
            .map(|c| String::from_utf8_lossy(&c).into_owned())
            == disk,
        "GPT.INI of the Default Domain Policy as on the disk of dc2",
    )?;

    // A folder and a file, written and removed; one left by an interrupted trial goes first.
    let folder = format!("{}\\annuaire-smb2", lab.domain);
    let file = format!("{folder}\\essai.txt");
    let states = session
        .states(&[(file.clone(), Some(false)), (folder.clone(), Some(true))])
        .map_err(debug)?;
    if states.first().is_some_and(|s| s.nature.is_some()) {
        session.erase(&file, false, &[]).map_err(debug)?;
    }
    if states.get(1).is_some_and(|s| s.nature.is_some()) {
        session.erase(&folder, true, &[]).map_err(debug)?;
    }
    let content = b"SMB 2.1, signing only\r\n";
    let written = (|| -> Result<()> {
        let (state, _) = session
            .create(&folder, true, b"", None, &[])
            .map_err(debug)?;
        check(state.nature == Some(true), "folder created")?;
        let (state, _) = session
            .create(&file, false, content, None, &[])
            .map_err(debug)?;
        check(
            state.content.as_deref() == Some(&content[..]),
            "file written, read back in the same compound",
        )?;
        check(
            on_disk(lab, "annuaire-smb2/essai.txt")?.as_deref()
                == Some(std::str::from_utf8(content)?),
            "the file on the disk of dc2",
        )
    })();
    let (state, _) = session.erase(&file, false, &[]).map_err(debug)?;
    let (folder_state, _) = session.erase(&folder, true, &[]).map_err(debug)?;
    session.close();
    written?;
    check(
        state.nature.is_none() && folder_state.nature.is_none(),
        "file and folder removed",
    )?;
    check(
        on_disk(lab, "annuaire-smb2")?.is_none(),
        "nothing left on the disk of dc2",
    )?;

    // The profile option carried to the SYSVOL sessions of a connection.
    let mut profile = lab.profile(false);
    profile.write_dc = Some(lab.other_dc.clone());
    profile.smb2_signing = true;
    let sysvol_dc = gpo::read_pdc_sysvol(&source::pdc_connection(&profile)).map_err(debug)?;
    check(
        sysvol_dc.dc == lab.other_dc
            && sysvol_dc.error.is_none()
            && sysvol_dc.folders.contains_key(DEFAULT_POLICY),
        "inventory of the SYSVOL of dc2 through a profile with the option",
    )
}

/// Without the option: refused, the option named by the kind of the error.
fn refused(lab: &Lab) -> Result<()> {
    let dc2 = lab.other_dc.as_str();
    let kind = |e: &SysvolError| match e {
        SysvolError::Session(e) => Some(e.kind.clone()),
        _ => None,
    };
    let error = open(dc2, Protection::Encrypted).err();
    println!("  refusal: {error:?}");
    check(
        error.as_ref().and_then(kind) == Some(ErrorKind::Smb2Only),
        "dc2 in SMB 2.1 refused without the option (Smb2Only)",
    )?;
    let mut profile = lab.profile(false);
    profile.write_dc = Some(lab.other_dc.clone());
    let sysvol_dc = gpo::read_pdc_sysvol(&source::pdc_connection(&profile)).map_err(debug)?;
    check(
        matches!(
            &sysvol_dc.error,
            Some(SysvolReadError::Sysvol(e)) if kind(e) == Some(ErrorKind::Smb2Only)
        ),
        "inventory through a profile without the option: refused (Smb2Only)",
    )
}

#[test]
#[ignore = "lab"]
fn smb2_signing_only() -> Result<()> {
    let lab = labo::lab();
    if !labo::samba_only(&lab) {
        return Ok(());
    }
    println!("1. SMB 3.1.1 before the trial");
    smb3_everywhere(&lab)?;
    println!("2. dc2 limited to SMB 2.1");
    let trial = limit_dc2(&lab).and_then(|()| {
        println!("3. option on");
        signed_only(&lab)?;
        println!("4. option off");
        refused(&lab)
    });
    println!("5. dc2 put back");
    let restored = restore_dc2(&lab);
    trial?;
    restored?;
    smb3_everywhere(&lab)
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Shares of a file server by changesets (ADR 0023 § 3 and 4, J8.2, J8.3, J8.6), against the
//! server itself as oracle: `fs1.lab.test` (Samba member: `net conf`, `sharesec` by ssh) or,
//! with `ANNUAIRE_LABO_DOMAINE=win.test`, `wdc1.win.test` (`Get-SmbShare` by `labo/poste.py`).
//!
//! The list read by Calinda is compared with the oracle; then a trial share is created on a
//! folder made beforehand, its permissions changed (an ordinary account of the domain refused,
//! then let in, then refused again by the undo), its options changed, the guard tried on a
//! share changed behind the preview, the share deleted (the folder stays) and recreated by
//! the undo. The share and its folder are removed at the end, even after a failure.
//!
//! On fs1 (J8.7, ADR 0023 § 9), the options and the limit go to the registry key of the share
//! (`net conf showshare`), with their effect: the share hidden from an ordinary account by
//! `access based share enum`, a connection refused beyond the limit; their undo puts the key
//! back as it was, and so does the undo of a deletion. Then, smb.conf saved aside and its share
//! commands removed for the time of the step (put back even after a failure, and at the start
//! of the next run if one was interrupted), a share is created, changed, deleted and each
//! undone by `winreg` alone. `shares_registry_on_dc` tries a creation on dc1 (a Samba DC that
//! does not read its shares from the registry): refused, and the registry of Samba as before.
//!
//! ```text
//! KRB5CCNAME=FILE:… cargo test -p annuaire-core --test labo_shares -- --ignored --nocapture --test-threads 1
//! ```

mod labo;

use std::collections::BTreeSet;
use std::process::Command;
use std::time::{Duration, Instant};

use annuaire_codecs::Sid;
use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sddl;
use annuaire_core::changes::{Changeset, Issue, Operation, ShareSpec};
use annuaire_core::share_write::{Shares, read_share};
use annuaire_core::smb::Options;
use annuaire_core::srvsvc::{Share, Srvsvc, flags};
use annuaire_core::sysvol::{Protection, Session};
use annuaire_core::writer::ProblemKind;
use labo::{Lab, Result, Trial, check, debug};

const NAME: &str = "Essai-Calinda";

/// The file server of the domain aimed at, and where the folder of the trial share lives.
#[derive(Debug)]
struct Server {
    host: String,
    windows: bool,
    /// The folder as the server names it to `srvsvc`.
    path: String,
    /// The KDC and an ordinary account made by `labo/peupler.py` (or its Windows twin).
    kdc: String,
    ordinary: &'static str,
}

fn server(lab: &Lab) -> Server {
    if lab.windows() {
        Server {
            host: "wdc1.win.test".into(),
            windows: true,
            path: format!("C:\\Partages\\{NAME}"),
            kdc: "wdc1.win.test".into(),
            ordinary: "gaelle.chateau",
        }
    } else {
        // Out of /srv/partages (mode 770): Samba enters the folder as the account at the
        // tree connect, the share permissions alone must decide.
        Server {
            host: "fs1.lab.test".into(),
            windows: false,
            path: "C:\\srv\\essai-calinda".into(),
            kdc: "dc1.lab.test".into(),
            ordinary: "gaelle.lambert",
        }
    }
}

// --- Oracles --------------------------------------------------------------------------------

/// A bash script on fs1, by `ANNUAIRE_LABO_FS1` (an ssh command to which `bash -s` is added;
/// default `ssh -o BatchMode=yes labadmin@fs1.lab.test`).
fn fs1(script: &str) -> Result<String> {
    let command = std::env::var("ANNUAIRE_LABO_FS1")
        .unwrap_or_else(|_| "ssh -o BatchMode=yes labadmin@fs1.lab.test".into());
    labo::run(
        Command::new("sh")
            .arg("-c")
            .arg(format!("{command} 'bash -s'")),
        script.as_bytes(),
    )
}

fn wdc(script: &str) -> Result<String> {
    labo::poste(script, &["--cible", "wdc"])
}

/// One permission of a share, as both sides can say it: SID, allowed, level.
type Permission = (String, bool, String);

/// Full, Change, Read, or the mask in hex.
fn level(mask: u32) -> String {
    if mask & 0x001F_01FF == 0x001F_01FF || mask & 0x1000_0000 != 0 {
        "FULL".into()
    } else if mask & 0x0013_01BF == 0x0013_01BF {
        "CHANGE".into()
    } else if mask & 0x0012_00A9 == 0x0012_00A9 {
        "READ".into()
    } else {
        format!("0x{mask:x}")
    }
}

/// The permissions of a descriptor; none: Everyone, Full control (what both servers apply).
fn permissions(descriptor: Option<&[u8]>) -> Result<BTreeSet<Permission>> {
    let Some(bytes) = descriptor else {
        return Ok([("S-1-1-0".to_owned(), true, "FULL".to_owned())].into());
    };
    let sd = SecurityDescriptor::decode(bytes).map_err(debug)?;
    let mut out = BTreeSet::new();
    for ace in sd.dacl.map(|a| a.aces).unwrap_or_default() {
        let sid = ace.sid().ok_or("ACE without SID")?;
        out.insert((sid.to_string(), !ace.is_deny(), level(ace.mask())));
    }
    Ok(out)
}

/// A share as the oracle tells it (values trimmed by `labo::lines`).
#[derive(Debug, Default)]
struct Told {
    path: String,
    comment: String,
    permissions: BTreeSet<Permission>,
    /// Access-based enumeration, caching mode, connection limit: `Get-SmbShare` on Windows,
    /// the parameters of the registry key on Samba (empty when absent).
    abe: String,
    caching: String,
    limit: String,
    /// Samba: `net conf showshare` as it prints it.
    conf: String,
}

/// Every share name the server has (lower case): registry shares of Samba (`net conf`),
/// `Get-SmbShare` on Windows (special shares too).
fn oracle_names(server: &Server) -> Result<BTreeSet<String>> {
    let text = if server.windows {
        let out = wdc("'NAMES=' + ((Get-SmbShare | ForEach-Object { $_.Name }) -join '|')")?;
        labo::lines(&out)
            .remove("NAMES")
            .unwrap_or_default()
            .replace('|', "\n")
    } else {
        fs1("sudo net conf listshares\n")?
    };
    Ok(text
        .lines()
        .map(|l| l.trim().to_lowercase())
        .filter(|l| !l.is_empty())
        .collect())
}

/// `sharesec --view`: `ACL:S-1-1-0:ALLOWED/0x0/FULL`; an empty list or none at all is the
/// open descriptor.
fn samba_permissions(view: &str) -> BTreeSet<Permission> {
    view.lines()
        .filter_map(|l| l.strip_prefix("ACL:"))
        .filter_map(|acl| {
            let (sid, rest) = acl.split_once(':')?;
            let mut parts = rest.split('/');
            let kind = parts.next()?;
            let _flags = parts.next()?;
            let right = parts.next()?;
            let right = match right.strip_prefix("0x") {
                Some(hex) => level(u32::from_str_radix(hex, 16).ok()?),
                None => right.to_owned(),
            };
            Some((sid.to_owned(), kind == "ALLOWED", right))
        })
        .collect()
}

fn oracle_share(server: &Server, name: &str, domain: Option<&Sid>) -> Result<Option<Told>> {
    if server.windows {
        let out = wdc(&format!(
            "$s = Get-SmbShare -Name '{name}' -ErrorAction SilentlyContinue\n\
             if (-not $s) {{ 'ABSENT=1' }} else {{\n\
             'PATH=' + $s.Path\n'DESC=' + $s.Description\n'SDDL=' + $s.SecurityDescriptor\n\
             'ABE=' + $s.FolderEnumerationMode\n'CACHE=' + $s.CachingMode\n\
             'LIMIT=' + $s.ConcurrentUserLimit }}\n"
        ))?;
        let lines = labo::lines(&out);
        if lines.contains_key("ABSENT") {
            return Ok(None);
        }
        let get = |k: &str| lines.get(k).cloned().unwrap_or_default();
        let sddl_text = get("SDDL");
        let permissions = if sddl_text.is_empty() {
            permissions(None)?
        } else {
            let sd = sddl::sd_from_sddl(&sddl_text, domain, false).map_err(debug)?;
            permissions(Some(&sd.encode().map_err(debug)?))?
        };
        return Ok(Some(Told {
            path: get("PATH"),
            comment: get("DESC"),
            permissions,
            abe: get("ABE"),
            caching: get("CACHE"),
            limit: get("LIMIT"),
            conf: String::new(),
        }));
    }
    let quoted = labo::quote(name);
    let out = fs1(&format!(
        "if ! sudo net conf showshare {quoted} >/tmp/calinda-share 2>/dev/null; then echo ABSENT=1; exit 0; fi\n\
         cat /tmp/calinda-share; echo ---; sudo sharesec {quoted} --view\n"
    ))?;
    if out.contains("ABSENT=1") {
        return Ok(None);
    }
    let (conf, view) = out.split_once("---").unwrap_or((&out, ""));
    let param = |key: &str| {
        conf.lines()
            .filter_map(|l| l.trim().split_once(" = "))
            .find(|(k, _)| k.trim() == key)
            .map(|(_, v)| v.trim().to_owned())
            .unwrap_or_default()
    };
    let mut perms = samba_permissions(view);
    if perms.is_empty() {
        perms = permissions(None)?;
    }
    Ok(Some(Told {
        path: param("path"),
        comment: param("comment"),
        permissions: perms,
        abe: param("access based share enum"),
        caching: param("csc policy"),
        limit: param("max connections"),
        conf: conf.trim().to_owned(),
    }))
}

/// Paths compared as Samba gives them through srvsvc (`C:\srv\x` for `/srv/x`).
fn same_path(calinda: &str, oracle: &str) -> bool {
    let norm = |p: &str| {
        let p = p.strip_prefix("C:").unwrap_or(p);
        p.replace('\\', "/").trim_end_matches('/').to_lowercase()
    };
    norm(calinda) == norm(oracle)
}

// --- What an ordinary account gets -------------------------------------------------------------

/// Run as the ordinary account: the tree connect on the share, then its root listed.
#[test]
#[ignore = "lab"]
fn shares_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let (host, share) = input.trim().split_once(' ').ok_or("host share")?;
    match Session::open_share(host, share, Protection::Encrypted, Duration::from_secs(30)) {
        // Windows lets the tree connect through and refuses at the opening of the root.
        Ok(mut session) => {
            match session.list("") {
                Ok(names) => println!("RESULT accepted, {} names at the root", names.len()),
                Err(e) => println!("RESULT refused at the root: {e}"),
            }
            session.close();
        }
        Err(e) => println!("RESULT refused at the tree connect: {e}"),
    }
    Ok(())
}

/// Does the ordinary account get in the share? Its ticket in a cache of its own.
fn ordinary_gets_in(lab: &Lab, server: &Server, kdc: &labo::Kdc) -> Result<bool> {
    let refused = kdc.kinit_into(
        &format!("{}@{}", server.ordinary, lab.realm()),
        &labo::lab_password(labo::SEED, server.ordinary)?,
        "ordinaire",
    );
    check(refused.is_none(), "ticket of the ordinary account")?;
    let result = labo::child(
        "shares_child",
        &kdc.env("ordinaire"),
        &format!("{} {NAME}", server.host),
    );
    kdc.destroy("ordinaire");
    let result = result?;
    println!("  {}: {result}", server.ordinary);
    Ok(result.starts_with("accepted"))
}

/// Run as the ordinary account: the share names `srvsvc` gives it.
#[test]
#[ignore = "lab"]
fn shares_list_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let mut service = Srvsvc::open(input.trim(), &options()).map_err(debug)?;
    let names: Vec<String> = service
        .names()
        .map_err(debug)?
        .into_iter()
        .map(|s| s.name)
        .collect();
    service.close();
    println!("RESULT {}", names.join("|"));
    Ok(())
}

/// Does the ordinary account see `name` in the list of the shares?
fn ordinary_sees(lab: &Lab, server: &Server, kdc: &labo::Kdc, name: &str) -> Result<bool> {
    let refused = kdc.kinit_into(
        &format!("{}@{}", server.ordinary, lab.realm()),
        &labo::lab_password(labo::SEED, server.ordinary)?,
        "ordinaire",
    );
    check(refused.is_none(), "ticket of the ordinary account")?;
    let result = labo::child("shares_list_child", &kdc.env("ordinaire"), &server.host);
    kdc.destroy("ordinaire");
    let listed = result?;
    Ok(listed.split('|').any(|n| n.eq_ignore_ascii_case(name)))
}

// --- The trial ----------------------------------------------------------------------------------

fn options() -> Options {
    Protection::Encrypted.options(Duration::from_secs(30))
}

fn service(server: &Server) -> Result<Srvsvc> {
    Srvsvc::open(&server.host, &options()).map_err(debug)
}

/// The share as Calinda reads it now.
fn current(server: &Server) -> Result<ShareSpec> {
    current_of(server, NAME)?.ok_or_else(|| format!("{NAME} absent").into())
}

fn current_of(server: &Server, name: &str) -> Result<Option<ShareSpec>> {
    let mut shares = Shares::new(Protection::Encrypted);
    let spec = read_share(&mut shares, &server.host, name).map_err(debug)?;
    shares.close();
    Ok(spec)
}

fn changeset(op: Operation) -> Changeset {
    Changeset {
        operations: vec![op],
        remarks: Vec::new(),
    }
}

fn descriptor(text: &str) -> Result<Vec<u8>> {
    sddl::sd_from_sddl(text, None, false)
        .map_err(debug)?
        .encode()
        .map_err(debug)
}

/// The share as the oracle tells it, compared with what Calinda reads.
fn agree(server: &Server, domain: &Sid, what: &str) -> Result<Told> {
    let told = oracle_share(server, NAME, Some(domain))?
        .ok_or(format!("{NAME} absent from the oracle"))?;
    let read = current(server)?;
    check(
        same_path(&read.path, &told.path),
        &format!("{what}: path {} = {}", read.path, told.path),
    )?;
    check(
        read.remark.trim() == told.comment,
        &format!("{what}: comment {:?}", told.comment),
    )?;
    check(
        permissions(read.descriptor.as_deref())? == told.permissions,
        &format!("{what}: permissions {:?}", told.permissions),
    )?;
    Ok(told)
}

fn make_folder(server: &Server) -> Result<()> {
    if server.windows {
        wdc(&format!(
            "New-Item -ItemType Directory -Force '{}' | Out-Null\n",
            server.path
        ))?;
    } else {
        fs1("sudo mkdir -p /srv/essai-calinda && sudo chmod 0777 /srv/essai-calinda\n")?;
    }
    Ok(())
}

fn folder_exists(server: &Server) -> Result<bool> {
    let out = if server.windows {
        wdc(&format!("'EXISTS=' + (Test-Path '{}')\n", server.path))?
    } else {
        fs1("test -d /srv/essai-calinda && echo EXISTS=True || echo EXISTS=False\n")?
    };
    Ok(labo::lines(&out).get("EXISTS").map(String::as_str) == Some("True"))
}

/// The share and its folder removed, whatever the trial left.
fn clean(server: &Server) -> Result<()> {
    if let Ok(mut s) = service(server) {
        let _ = s.delete(NAME);
        s.close();
    }
    if !server.windows {
        // The share of the step without share commands, if a run stopped before its end.
        fs1(&format!(
            "for s in $(sudo net conf listshares | grep '^{REGISTRY_PREFIX}'); do sudo net conf delshare \"$s\"; done\n"
        ))?;
    }
    if server.windows {
        wdc(&format!(
            "Remove-SmbShare -Name '{NAME}' -Force -ErrorAction SilentlyContinue\n\
             Remove-Item -Recurse -Force '{}' -ErrorAction SilentlyContinue\n",
            server.path
        ))?;
    } else {
        fs1(&format!(
            "sudo net conf delshare {} 2>/dev/null; sudo rm -rf /srv/essai-calinda\n",
            labo::quote(NAME)
        ))?;
    }
    Ok(())
}

#[test]
#[ignore = "lab"]
fn shares_by_changesets() -> Result<()> {
    if labo::child_input().is_some() {
        return Ok(());
    }
    let lab = labo::lab();
    let server = server(&lab);
    println!("file server {}", server.host);
    let conf = if server.windows {
        None
    } else {
        // A run interrupted during step 10 left smb.conf without its share commands.
        let (sha, restored) = restore_smb_conf()?;
        if restored {
            println!("smb.conf of fs1 put back: an earlier run was interrupted");
        }
        Some(sha)
    };
    enumeration(&server)?;
    clean(&server)?;
    make_folder(&server)?;
    let result = trial(&lab, &server);
    let cleaned = clean(&server);
    result?;
    cleaned?;
    check(
        oracle_share(&server, NAME, None)?.is_none() && !folder_exists(&server)?,
        "share and folder removed",
    )?;
    if let Some(before) = conf {
        check(
            restore_smb_conf()?.0 == before,
            "smb.conf of fs1 as it was (sha256)",
        )?;
    }
    Ok(())
}

/// 1. The list of Calinda and the one of the oracle.
fn enumeration(server: &Server) -> Result<()> {
    println!("1. list compared with the oracle");
    let t = Instant::now();
    let mut s = service(server)?;
    let bound = t.elapsed();
    let t = Instant::now();
    let shares: Vec<Share> = s.shares().map_err(debug)?;
    let listed = t.elapsed();
    s.close();
    println!(
        "  bound in {:.0} ms, {} shares listed in {:.1} ms",
        bound.as_secs_f64() * 1000.0,
        shares.len(),
        listed.as_secs_f64() * 1000.0
    );
    let ours: BTreeSet<String> = shares
        .iter()
        .filter(|s| server.windows || (s.is_disk() && !s.is_special()))
        .map(|s| s.name.to_lowercase())
        .collect();
    let theirs = oracle_names(server)?;
    // A trial interrupted earlier may have left its share: it is cleaned after this.
    let ours: BTreeSet<String> = ours
        .into_iter()
        .filter(|n| n != &NAME.to_lowercase())
        .collect();
    let theirs: BTreeSet<String> = theirs
        .into_iter()
        .filter(|n| n != &NAME.to_lowercase())
        .collect();
    check(ours == theirs, &format!("same names: {ours:?}"))?;
    let mut compared = 0;
    for share in shares.iter().filter(|s| s.is_disk() && !s.is_special()) {
        if share.name.eq_ignore_ascii_case(NAME) {
            continue;
        }
        let told = oracle_share(server, &share.name, None)?.ok_or("absent from the oracle")?;
        let ours = permissions(share.descriptor.as_deref())?;
        if !same_path(&share.path, &told.path)
            || share.remark.trim() != told.comment
            || ours != told.permissions
        {
            println!(
                "  Calinda: {:?} {:?} {ours:?}\n  oracle: {:?} {:?} {:?}",
                share.path, share.remark, told.path, told.comment, told.permissions
            );
        }
        check(
            same_path(&share.path, &told.path)
                && share.remark.trim() == told.comment
                && permissions(share.descriptor.as_deref())? == told.permissions,
            &format!(
                "{}: path, comment and permissions as the oracle",
                share.name
            ),
        )?;
        compared += 1;
    }
    println!("  {compared} disk shares compared field by field");
    // Samba announces itself a Unix server, Windows does not (J8.7).
    let mut shares = Shares::new(Protection::Encrypted);
    let samba = shares.samba(&server.host).map_err(debug)?;
    shares.close();
    check(
        samba == !server.windows,
        "Samba told apart by its server type",
    )?;
    Ok(())
}

fn trial(lab: &Lab, server: &Server) -> Result<()> {
    let scratch = labo::Scratch::new("partages")?;
    let trial = Trial::new(lab, &scratch)?;
    let sid = trial.sid(&trial.base)?;
    let domain = sid.to_string();
    let admins = format!("{domain}-512");
    let users = format!("{domain}-513");
    let kdc = labo::Kdc::new(lab, &server.kdc)?;

    println!("2. creation by a changeset");
    let wanted = ShareSpec {
        name: NAME.into(),
        path: server.path.clone(),
        remark: "Essai de Calinda".into(),
        max_uses: u32::MAX,
        descriptor: None,
        flags: 0,
        registry: None,
    };
    let t = Instant::now();
    let report = trial.apply(&changeset(Operation::add_share(&server.host, wanted)))?;
    println!("  applied in {:.2} s", t.elapsed().as_secs_f64());
    check(report.dc == server.host, "the report names the file server")?;
    agree(server, &sid, "created")?;
    check(
        ordinary_gets_in(lab, server, &kdc)?,
        "no descriptor: the ordinary account gets in",
    )?;

    println!("3. permissions: administrators only, and a new comment");
    let before = current(server)?;
    let mut after = before.clone();
    after.remark = "Essai de Calinda, administrateurs".into();
    after.descriptor = Some(descriptor(&format!(
        "O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;{admins})"
    ))?);
    trial.apply(&changeset(Operation::change_share(
        &server.host,
        before,
        after,
    )))?;
    agree(server, &sid, "administrators only")?;
    check(
        !ordinary_gets_in(lab, server, &kdc)?,
        "the ordinary account is refused",
    )?;

    println!("4. Domain Users: Read");
    let before = current(server)?;
    let mut after = before.clone();
    after.descriptor = Some(descriptor(&format!(
        "O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;{admins})(A;;0x1200a9;;;{users})"
    ))?);
    let read_report = trial.apply(&changeset(Operation::change_share(
        &server.host,
        before,
        after,
    )))?;
    let told = agree(server, &sid, "Domain Users: Read")?;
    check(
        told.permissions
            .contains(&(users.clone(), true, "READ".into())),
        "the oracle shows Domain Users: Read",
    )?;
    check(
        ordinary_gets_in(lab, server, &kdc)?,
        "the ordinary account gets in",
    )?;

    println!("5. undo of 4 by its journaled inverse");
    trial.undo(&read_report)?;
    agree(server, &sid, "undone")?;
    check(
        !ordinary_gets_in(lab, server, &kdc)?,
        "the ordinary account is refused again",
    )?;

    println!("6. guard: a share changed behind the preview");
    let stale = current(server)?;
    if server.windows {
        wdc(&format!(
            "Set-SmbShare -Name '{NAME}' -Description 'changé ailleurs' -Force\n"
        ))?;
    } else {
        fs1(&format!(
            "sudo net conf setparm {} comment 'changé ailleurs'\n",
            labo::quote(NAME)
        ))?;
    }
    // Samba's srvsvc gives a share changed through `net conf` as it was until an enumeration,
    // which `read_share` makes: the change is seen at once.
    let seen = labo::wait(
        Duration::from_secs(120),
        "the change seen by srvsvc",
        || Ok(current(server)?.remark == "changé ailleurs"),
    )?;
    println!("  change seen by srvsvc after {seen:.1} s");
    let mut after = stale.clone();
    after.remark = "jamais écrit".into();
    let outcome = trial.outcome(
        &changeset(Operation::change_share(&server.host, stale, after)),
        None,
        None,
    )?;
    println!("  {:?} {:?}", outcome.report.issue, outcome.problems);
    check(
        outcome.report.issue != Issue::Applied
            && outcome
                .problems
                .iter()
                .any(|p| p.kind == ProblemKind::Version),
        "not written, the change is seen",
    )?;
    check(
        oracle_share(server, NAME, Some(&sid))?.is_some_and(|t| t.comment == "changé ailleurs"),
        "the comment of elsewhere stays",
    )?;

    println!("7. options and connection limit");
    let before = current(server)?;
    let mut after = before.clone();
    after.flags =
        (before.flags & !flags::CSC_MASK) | flags::CSC_NONE | flags::ACCESS_BASED_DIRECTORY_ENUM;
    after.max_uses = 5;
    let outcome = trial.outcome(
        &changeset(Operation::change_share(&server.host, before, after)),
        None,
        None,
    )?;
    let error = outcome.report.error.as_ref().map(|e| e.message.clone());
    println!("  {:?} {:?}", outcome.report.issue, error);
    if server.windows {
        check(outcome.report.issue == Issue::Applied, "applied")?;
        let told = agree(server, &sid, "options")?;
        check(
            told.abe == "AccessBased" && told.caching == "None" && told.limit == "5",
            &format!("Get-SmbShare: {} {} {}", told.abe, told.caching, told.limit),
        )?;
    } else {
        // J8.7: written to the key of the share, no longer kept by Samba.
        check(outcome.report.issue == Issue::Applied, "applied")?;
        let told = agree(server, &sid, "options")?;
        check(
            told.abe == "yes" && told.caching == "disable" && told.limit == "5",
            &format!(
                "net conf showshare: {} {} {}",
                told.abe, told.caching, told.limit
            ),
        )?;
        let read = current(server)?;
        check(
            read.max_uses == 5
                && read.flags & (flags::CSC_MASK | flags::ACCESS_BASED_DIRECTORY_ENUM)
                    == flags::CSC_NONE | flags::ACCESS_BASED_DIRECTORY_ENUM,
            "read again by Calinda through winreg",
        )?;
        // The share permissions are the administrators' since step 5: hidden from the
        // ordinary account by « access based share enum ».
        check(
            !ordinary_sees(lab, server, &kdc, NAME)?,
            "access based share enum: the ordinary account does not see the share",
        )?;
        println!("7b. undo of the options: the key as it was");
        trial.undo(&outcome.report)?;
        let told = agree(server, &sid, "options undone")?;
        check(
            told.abe.is_empty() && told.caching.is_empty() && told.limit.is_empty(),
            &format!("parameters removed:\n{}", told.conf),
        )?;
        check(
            ordinary_sees(lab, server, &kdc, NAME)?,
            "the ordinary account sees the share again",
        )?;
    }

    println!("8. deletion: the folder stays");
    let present = current(server)?;
    let key = oracle_share(server, NAME, Some(&sid))?.map(|t| t.conf);
    let deleted = trial.apply(&changeset(Operation::delete_share(
        &server.host,
        present.clone(),
    )))?;
    check(
        oracle_share(server, NAME, Some(&sid))?.is_none(),
        "share deleted",
    )?;
    check(folder_exists(server)?, "folder kept")?;

    println!("9. undo of the deletion: the share is back with its permissions");
    trial.undo(&deleted)?;
    let told = agree(server, &sid, "recreated")?;
    check(
        told.permissions == permissions(present.descriptor.as_deref())?,
        "same permissions as before the deletion",
    )?;
    let again = current(server)?;
    check(
        again.remark == present.remark && again.flags == present.flags,
        "same comment and options",
    )?;
    if !server.windows {
        // The same values; their order is the one of the server's « add share command »
        // (`net conf addshare`), the values it does not write put back after.
        check(
            key.as_deref().map(sorted_lines) == Some(sorted_lines(&told.conf)),
            &format!("the registry key as before the deletion:\n{}", told.conf),
        )?;
        without_commands(lab, server, &trial, &sid, &kdc)?;
    }
    Ok(())
}

// --- fs1 without its share commands (J8.7) ---------------------------------------------------

/// Where smb.conf waits while its share commands are removed.
const SAVED: &str = "/etc/samba/smb.conf.calinda-essai";
/// The shares of step 10 begin with it (and the pid of the trial).
const REGISTRY_PREFIX: &str = "Essai-Winreg-";

/// Samba reloaded: smbd and the others, and the worker of `samba-dcerpcd` that serves
/// `srvsvc` stopped (`rpcd_classic`, started again at the next call): it keeps the
/// configuration it was started with, `smbcontrol` does not reach it.
const RELOAD: &str = "sudo smbcontrol all reload-config >/dev/null; \
                      sudo pkill -f '^/usr/libexec/samba/rpcd_classic'; true";

/// smb.conf put back if a copy waits, Samba reloaded; its sha256, and whether it was put back.
fn restore_smb_conf() -> Result<(String, bool)> {
    let out = fs1(&format!(
        "if sudo test -f {SAVED}; then sudo cp -p {SAVED} /etc/samba/smb.conf && sudo rm -f {SAVED} \
         && {{ {RELOAD}; }} && echo RESTORED=1; fi\n\
         echo SHA=$(sudo sha256sum /etc/samba/smb.conf | cut -c1-64)\n"
    ))?;
    let lines = labo::lines(&out);
    let sha = lines.get("SHA").cloned().ok_or("sha256 of smb.conf")?;
    Ok((sha, lines.contains_key("RESTORED")))
}

/// smb.conf without the share commands while it lives; put back when it is dropped, even
/// after a failure.
struct WithoutCommands;

impl WithoutCommands {
    fn new() -> Result<Self> {
        restore_smb_conf()?;
        let out = fs1(&format!(
            "sudo cp -p /etc/samba/smb.conf {SAVED} && sudo sed -i '/share command/d' /etc/samba/smb.conf \
             && {{ {RELOAD}; }} && echo LEFT=$(sudo testparm -s 2>/dev/null | grep -c 'share command')\n"
        ))?;
        let guard = Self;
        check(
            labo::lines(&out).get("LEFT").map(String::as_str) == Some("0"),
            "share commands removed from smb.conf",
        )?;
        Ok(guard)
    }
}

impl Drop for WithoutCommands {
    fn drop(&mut self) {
        match restore_smb_conf() {
            Ok((_, true)) => println!("  smb.conf of fs1 put back, Samba reloaded"),
            Ok((_, false)) => eprintln!("smb.conf of fs1: no copy to put back"),
            Err(e) => eprintln!("smb.conf of fs1 NOT put back: {e}"),
        }
    }
}

fn sorted_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    lines.sort();
    lines
}

/// `net conf showshare` of `name`, `None` if absent.
fn showshare(name: &str) -> Result<Option<String>> {
    Ok(oracle_share(
        &Server {
            host: "fs1.lab.test".into(),
            windows: false,
            path: String::new(),
            kdc: String::new(),
            ordinary: "",
        },
        name,
        None,
    )?
    .map(|t| t.conf))
}

/// 10. Creation, change, deletion and their undo by `winreg` alone.
fn without_commands(
    lab: &Lab,
    server: &Server,
    trial: &Trial,
    sid: &Sid,
    kdc: &labo::Kdc,
) -> Result<()> {
    println!("10. fs1 without its share commands");
    let name = format!("{REGISTRY_PREFIX}{}", std::process::id());
    let _guard = WithoutCommands::new()?;
    let mut service = service(server)?;
    let refused = service.add(&Share {
        name: name.clone(),
        kind: 0,
        path: server.path.clone(),
        max_uses: u32::MAX,
        level: 502,
        ..Share::default()
    });
    service.close();
    println!("  NetrShareAdd: {refused:?}");
    check(
        matches!(
            refused,
            Err(annuaire_core::srvsvc::Error::Refused { code: 5, .. })
        ),
        "srvsvc refuses the creation",
    )?;

    println!("10a. creation with options");
    let wanted = ShareSpec {
        name: name.clone(),
        path: server.path.clone(),
        remark: "Essai winreg".into(),
        max_uses: 2,
        descriptor: None,
        flags: flags::CSC_AUTO | flags::ACCESS_BASED_DIRECTORY_ENUM,
        registry: None,
    };
    let t = Instant::now();
    let created = trial.apply(&changeset(Operation::add_share(&server.host, wanted)))?;
    println!("  applied in {:.2} s", t.elapsed().as_secs_f64());
    let made = showshare(&name)?.ok_or("no key")?;
    let expected = format!(
        "[{name}]\n\tpath = /srv/essai-calinda\n\tcomment = Essai winreg\n\tguest ok = no\n\
         \tread only = no\n\tmax connections = 2\n\tcsc policy = documents\n\
         \taccess based share enum = yes"
    );
    check(made == expected, &format!("net conf showshare:\n{made}"))?;
    // Served at once: listed, and open to the administrator.
    let t = Instant::now();
    check(current_of(server, &name)?.is_some(), "listed by srvsvc")?;
    let mut session = Session::open_share(
        &server.host,
        &name,
        Protection::Encrypted,
        Duration::from_secs(30),
    )
    .map_err(debug)?;
    session.list("").map_err(debug)?;
    println!(
        "  listed and connected {:.0} ms after the write",
        t.elapsed().as_secs_f64() * 1000.0
    );

    println!("10b. change: comment, limit 1, no caching");
    let before = current_of(server, &name)?.ok_or("absent")?;
    let mut after = before.clone();
    after.remark = "Essai winreg, modifié".into();
    after.max_uses = 1;
    after.flags = (before.flags & !flags::CSC_MASK) | flags::CSC_NONE;
    let changed = trial.apply(&changeset(Operation::change_share(
        &server.host,
        before,
        after,
    )))?;
    let now = showshare(&name)?.unwrap_or_default();
    check(
        now.contains("comment = Essai winreg, modifié")
            && now.contains("max connections = 1")
            && now.contains("csc policy = disable"),
        &format!("net conf showshare:\n{now}"),
    )?;
    // The administrator's session holds the one connection allowed.
    let second = Session::open_share(
        &server.host,
        &name,
        Protection::Encrypted,
        Duration::from_secs(30),
    );
    println!("  second connection: {:?}", second.as_ref().err());
    check(
        second.is_err(),
        "the connection beyond the limit is refused",
    )?;
    if let Ok(s) = second {
        s.close();
    }
    session.close();

    println!("10c. permissions to the administrators: hidden from the ordinary account");
    check(
        ordinary_sees(lab, server, kdc, &name)?,
        "seen while the share is open to all",
    )?;
    let before = current_of(server, &name)?.ok_or("absent")?;
    let mut after = before.clone();
    after.descriptor = Some(descriptor(&format!(
        "O:BAG:BAD:(A;;FA;;;BA)(A;;FA;;;{sid}-512)"
    ))?);
    let closed = trial.apply(&changeset(Operation::change_share(
        &server.host,
        before,
        after,
    )))?;
    check(
        !ordinary_sees(lab, server, kdc, &name)?,
        "access based share enum: not seen",
    )?;

    println!("10d. Ctrl+Z of the permissions and of the change");
    trial.undo(&closed)?;
    trial.undo(&changed)?;
    // Samba moves a value set again to the end of its key: the same values, not the same order.
    let undone = showshare(&name)?.unwrap_or_default();
    check(
        sorted_lines(&undone) == sorted_lines(&expected),
        &format!("the values as created:\n{undone}"),
    )?;

    println!("10e. deletion, then its Ctrl+Z");
    let present = current_of(server, &name)?.ok_or("absent")?;
    let key = showshare(&name)?;
    let deleted = trial.apply(&changeset(Operation::delete_share(&server.host, present)))?;
    check(
        showshare(&name)?.is_none() && current_of(server, &name)?.is_none(),
        "key and share gone",
    )?;
    check(folder_exists(server)?, "folder kept")?;
    trial.undo(&deleted)?;
    // Made again by Calinda, in the order read: the key exactly as it was.
    check(
        showshare(&name)? == key,
        "the key back as it was, in its order",
    )?;

    println!("10f. Ctrl+Z of the creation: the key removed");
    trial.undo(&created)?;
    check(
        showshare(&name)?.is_none() && current_of(server, &name)?.is_none(),
        "key and share gone",
    )?;
    // A key deleted leaves the descriptor of the share in `share_info.tdb` (`net conf
    // delshare` removes it): made again and deleted by `net conf`, nothing is left.
    let q = labo::quote(&name);
    let out = fs1(&format!(
        "sudo net conf addshare {q} /srv/essai-calinda >/dev/null && sudo net conf delshare {q}\n\
         echo LEFT=$(sudo tdbdump /var/lib/samba/share_info.tdb | grep -ci {q})\n"
    ))?;
    check(
        labo::lines(&out).get("LEFT").map(String::as_str) == Some("0"),
        "no descriptor left in share_info.tdb",
    )
}

// --- dc1: a Samba DC, shares of smb.conf only (J8.7) ------------------------------------------

/// The registry of Samba and its shares on dc1, as `net registry` and `net conf` list them.
fn dc_registry() -> Result<String> {
    labo::ssh(
        "dc1",
        "sudo net registry enumerate_recursive 'HKLM\\Software\\Samba'; echo ---; sudo net conf list\n",
    )
}

#[test]
#[ignore = "lab"]
fn shares_registry_on_dc() -> Result<()> {
    let lab = labo::lab();
    if lab.windows() {
        println!("Samba DC only");
        return Ok(());
    }
    let name = format!("{REGISTRY_PREFIX}{}", std::process::id());
    let folder = format!("/srv/essai-calinda-dc-{}", std::process::id());
    let before = dc_registry()?;
    labo::ssh("dc1", &format!("sudo mkdir -p {folder}\n"))?;
    let result = (|| -> Result<()> {
        let scratch = labo::Scratch::new("partages-dc")?;
        let trial = Trial::new(&lab, &scratch)?;
        let outcome = trial.outcome(
            &changeset(Operation::add_share(
                "dc1.lab.test",
                ShareSpec {
                    name: name.clone(),
                    path: format!("C:{}", folder.replace('/', "\\")),
                    remark: "Essai winreg".into(),
                    max_uses: u32::MAX,
                    descriptor: None,
                    flags: 0,
                    registry: None,
                },
            )),
            None,
            None,
        )?;
        let error = outcome.report.error.as_ref().map(|e| e.message.clone());
        println!("  {:?} {error:?}", outcome.report.issue);
        check(
            outcome.report.issue != Issue::Applied
                && error.is_some_and(|m| m.contains("ShareRegistryIgnored")),
            "not served by the DC, said",
        )
    })();
    let after = dc_registry();
    labo::ssh("dc1", &format!("sudo rmdir {folder}\n"))?;
    result?;
    let after = after?;
    check(
        before == after,
        &format!("registry of dc1 as before:\n{before}\n---\n{after}"),
    )?;
    println!(
        "  registry of dc1 unchanged ({} lines)",
        before.lines().count()
    );
    Ok(())
}

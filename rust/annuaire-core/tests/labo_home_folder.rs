// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The home folder of an account as ADUC makes it (ADR 0027), against `fs1.lab.test` (Samba
//! member, oracle `samba-tool ntacl get` by ssh) or, with `ANNUAIRE_LABO_DOMAINE=win.test`,
//! `wdc1.win.test` (`Get-Acl` by `labo/poste.py`).
//!
//! A trial share `Home-Calinda` is made on the server (its root: SYSTEM and Administrators in
//! full control for everything below, Authenticated Users reading the root only), and two
//! accounts in an OU of their own. The home folder of the first, written
//! `\\<NETBIOS>\Home-Calinda\%USERNAME%` with the drive `H:`, is planned as the sheet plans it
//! (`%username%` expanded, server found by its NetBIOS name), then written in one changeset
//! with the attributes: the oracle reads the explicit ACEs of ADUC before the inherited ones,
//! the account writes in its folder and the other account cannot list it. The undo is refused
//! while the folder holds the file of the account; the file removed, the undo deletes the
//! folder and puts the attributes back. An existing folder is left as it is; a missing parent
//! and a missing share are refused before anything is written. Share, folder and accounts are
//! removed at the end, even after a failure.
//!
//! ```text
//! KRB5CCNAME=FILE:… cargo test -p annuaire-core --test labo_home_folder -- --ignored --nocapture --test-threads 1
//! ```

mod labo;

use std::process::Command;
use std::time::Duration;

use annuaire_codecs::Sid;
use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sddl;
use annuaire_core::actions;
use annuaire_core::changes::{Changeset, Operation, ShareSpec};
use annuaire_core::home_folder::{self, Plan, PlanError, Refusal};
use annuaire_core::ntfs;
use annuaire_core::srvsvc::Srvsvc;
use annuaire_core::sysvol::{INFO_OGD, Protection, Session};
use annuaire_core::writer;
use labo::{Lab, Result, Trial, check, debug};

const SHARE: &str = "Home-Calinda";
const OWNER: &str = "hf-proprio";
const OTHER: &str = "hf-autre";
const NEW: &str = "hf-nouveau";
const FILE: &str = "essai.txt";
/// The DACL of the root of the share.
const ROOT: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a9;;;AU)";
const DELAY: Duration = Duration::from_secs(30);

/// The file server aimed at.
#[derive(Debug)]
struct Server {
    host: String,
    /// The name a UNC path gives it, resolved by the directory.
    netbios: &'static str,
    windows: bool,
    /// The folder of the share on the server, and as `srvsvc` names it.
    local: &'static str,
    path: &'static str,
    kdc: String,
}

fn server(lab: &Lab) -> Server {
    if lab.windows() {
        Server {
            host: "wdc1.win.test".into(),
            netbios: "WDC1",
            windows: true,
            local: "C:\\Partages\\Home-Calinda",
            path: "C:\\Partages\\Home-Calinda",
            kdc: "wdc1.win.test".into(),
        }
    } else {
        Server {
            host: "fs1.lab.test".into(),
            netbios: "FS1",
            windows: false,
            local: "/srv/home-calinda",
            path: "C:\\srv\\home-calinda",
            kdc: "dc1.lab.test".into(),
        }
    }
}

/// A bash script on fs1 (`ANNUAIRE_LABO_FS1`, as `labo_shares`).
fn fs1(script: &str) -> Result<String> {
    let command = std::env::var("ANNUAIRE_LABO_FS1")
        .unwrap_or_else(|_| "ssh -o BatchMode=yes labadmin@192.168.1.211".into());
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

/// The share and its folder removed, whatever an earlier run left.
fn clean(server: &Server) -> Result<()> {
    if let Ok(mut s) = Srvsvc::open(&server.host, &Protection::Encrypted.options(DELAY)) {
        let _ = s.delete(SHARE);
        s.close();
    }
    if server.windows {
        wdc(&format!(
            "Remove-SmbShare -Name '{SHARE}' -Force -ErrorAction SilentlyContinue\n\
             Remove-Item -Recurse -Force '{}' -ErrorAction SilentlyContinue\n",
            server.local
        ))?;
    } else {
        fs1(&format!(
            "sudo net conf delshare {SHARE} 2>/dev/null; sudo rm -rf {}\n",
            server.local
        ))?;
    }
    Ok(())
}

/// The folder of the trial share, its root permissions set by the server's own tool: SYSTEM
/// and Administrators in full control of everything, Authenticated Users reading the root
/// only (what a share of home folders usually has).
fn make_folder(server: &Server) -> Result<()> {
    if server.windows {
        wdc(&format!(
            "New-Item -ItemType Directory -Force '{0}' | Out-Null\n\
             $a = Get-Acl '{0}'\n\
             $a.SetSecurityDescriptorSddlForm('{ROOT}', 'Access')\n\
             Set-Acl -Path '{0}' -AclObject $a\n",
            server.local
        ))?;
    } else {
        fs1(&format!(
            "sudo install -d -m 0777 {0} && \
             sudo samba-tool ntacl set 'O:BAG:SY{ROOT}' {0} --use-s3fs\n",
            server.local
        ))?;
    }
    Ok(())
}

/// The share, made by Calinda as `labo_shares` makes it: no descriptor, everyone at the share
/// level (NTFS decides).
fn make_share(server: &Server, trial: &Trial) -> Result<()> {
    make_folder(server)?;
    let spec = ShareSpec {
        name: SHARE.into(),
        path: server.path.into(),
        remark: "Essai de Calinda".into(),
        max_uses: u32::MAX,
        descriptor: None,
        flags: 0,
        registry: None,
    };
    trial.apply(&changeset_of(Operation::add_share(&server.host, spec)))?;
    Ok(())
}

/// `GetNamedSecurityInfo` in SDDL, the ACEs in their order on the disk: `Get-Acl` gives them
/// sorted (its `CommonSecurityDescriptor` puts them in an order of its own).
const RAW_SDDL: &str = r#"Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class HfSddl {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint GetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint revision, uint info, out IntPtr text, out uint size);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  public static string Get(string path) {
    IntPtr sd; uint r = GetNamedSecurityInfoW(path, 1, 7u, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
    if (r != 0) throw new Exception("GetNamedSecurityInfo " + path + " " + r);
    IntPtr text; uint size; ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, 7u, out text, out size);
    string s = Marshal.PtrToStringUni(text); LocalFree(text); LocalFree(sd); return s;
  }
}
'@
"#;

/// The descriptor of a folder of the share, as the server itself tells it, in SDDL.
fn oracle_sddl(server: &Server, name: &str) -> Result<String> {
    let out = if server.windows {
        wdc(&format!(
            "{RAW_SDDL}'SDDL=' + [HfSddl]::Get('{}\\{name}')\n",
            server.local
        ))?
    } else {
        fs1(&format!(
            "echo SDDL=$(sudo samba-tool ntacl get --as-sddl --use-s3fs {}/{} 2>/dev/null)\n",
            server.local,
            labo::quote(name)
        ))?
    };
    labo::lines(&out)
        .get("SDDL")
        .cloned()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("no descriptor for {name}: {out}").into())
}

fn folder_exists(server: &Server, name: &str) -> Result<bool> {
    let out = if server.windows {
        wdc(&format!(
            "'EXISTS=' + (Test-Path '{}\\{name}')\n",
            server.local
        ))?
    } else {
        fs1(&format!(
            "test -d {}/{} && echo EXISTS=True || echo EXISTS=False\n",
            server.local,
            labo::quote(name)
        ))?
    };
    Ok(labo::lines(&out).get("EXISTS").map(String::as_str) == Some("True"))
}

fn session(server: &Server) -> Result<Session> {
    Session::open_share(&server.host, SHARE, Protection::Encrypted, DELAY).map_err(debug)
}

fn encoded(text: &str, domain: &Sid) -> Result<Vec<u8>> {
    sddl::sd_from_sddl(text, Some(domain), false)
        .map_err(debug)?
        .encode()
        .map_err(debug)
}

/// Run as an account of the trial: `write PATH` creates a file in its home folder, `list
/// PATH` lists a folder.
#[test]
#[ignore = "lab"]
fn home_folder_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let mut words = input.split_whitespace();
    let (Some(host), Some(verb), Some(path)) = (words.next(), words.next(), words.next()) else {
        return Err("host verb path".into());
    };
    let mut session =
        match Session::open_share(host, SHARE, Protection::Encrypted, Duration::from_secs(30)) {
            Ok(s) => s,
            Err(e) => {
                println!("RESULT refused at the tree connect: {e}");
                return Ok(());
            }
        };
    let result = if verb == "write" {
        session
            .write(path, b"Calinda\r\n", true)
            .map(|()| "accepted".to_owned())
    } else {
        session
            .list(path)
            .map(|names| format!("accepted, {} names", names.len()))
    };
    match result {
        Ok(text) => println!("RESULT {text}"),
        Err(e) => println!("RESULT refused: {e}"),
    }
    session.close();
    Ok(())
}

/// What `account` gets doing `verb` on `path`, with its own ticket.
fn as_account(
    server: &Server,
    kdc: &labo::Kdc,
    account: &str,
    verb: &str,
    path: &str,
) -> Result<bool> {
    let result = labo::child(
        "home_folder_child",
        &kdc.env(account),
        &format!("{} {verb} {path}", server.host),
    )?;
    println!("  {account} {verb} {path}: {result}");
    Ok(result.starts_with("accepted"))
}

#[test]
#[ignore = "lab"]
fn home_folder_as_aduc() -> Result<()> {
    if labo::child_input().is_some() {
        return Ok(());
    }
    let lab = labo::lab();
    let server = server(&lab);
    println!("file server {}", server.host);
    let scratch = labo::Scratch::new("dossier-personnel")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = labo::Kdc::new(&lab, &server.kdc)?;
    clean(&server)?;
    let ou = trial.fresh_ou(&trial.base, "Essais-Dossier")?;
    let result = make_share(&server, &trial).and_then(|()| run(&lab, &server, &trial, &kdc, &ou));
    kdc.destroy(OWNER);
    kdc.destroy(OTHER);
    let cleaned = clean(&server);
    let removed = trial.remove_tree(&ou);
    trial.connection.join();
    result?;
    cleaned?;
    removed?;
    check(!folder_exists(&server, "")?, "share folder removed")
}

fn run(lab: &Lab, server: &Server, trial: &Trial, kdc: &labo::Kdc, ou: &str) -> Result<()> {
    let domain = trial.sid(&trial.base)?;

    println!("1. two accounts");
    for name in [OWNER, OTHER] {
        let secret = labo::password(28);
        trial.apply(
            &actions::create_user(
                ou,
                &actions::NewUser {
                    full_name: name.into(),
                    identifier: name.into(),
                    password: Some(secret.clone()),
                    enable: true,
                    ..actions::NewUser::default()
                },
            )
            .map_err(debug)?,
        )?;
        let refused = kdc.kinit_into(&format!("{name}@{}", lab.realm()), &secret, name);
        check(refused.is_none(), &format!("ticket of {name}"))?;
    }
    let dn = format!("CN={OWNER},{ou}");

    println!("2. planned as the sheet plans it");
    let account = home_folder::read_account(&trial.connection, &dn)
        .map_err(debug)?
        .ok_or("account absent")?;
    check(account.sam == OWNER, "sAMAccountName read")?;
    let netbios = if server.windows { "WIN" } else { "LAB" };
    check(
        account.name == format!("{netbios}\\{OWNER}"),
        &format!("named by the NetBIOS name of the domain: {}", account.name),
    )?;
    let written = format!("\\\\{}\\{SHARE}\\%USERNAME%", server.netbios);
    let directory = home_folder::expand_username(&written, &account.sam);
    check(
        directory == format!("\\\\{}\\{SHARE}\\{OWNER}", server.netbios),
        &format!("%USERNAME% expanded: {directory}"),
    )?;
    let Some(Plan::Create(op)) =
        home_folder::plan(&trial.connection, &account, &directory).map_err(debug)?
    else {
        return Err("the folder is not planned for creation".into());
    };
    check(
        op.server() == Some(server.host.as_str()),
        &format!("{} found as {}", server.netbios, server.host),
    )?;
    let modify = writer::prepare_modification(
        &trial.connection,
        &dn,
        vec![
            ("homeDrive".into(), vec![b"H:".to_vec()]),
            ("homeDirectory".into(), vec![directory.clone().into_bytes()]),
        ],
    )
    .map_err(debug)?
    .ok_or("nothing to change")?;
    let changeset = Changeset {
        operations: vec![modify, *op],
        remarks: Vec::new(),
    };

    println!("3. attributes and folder in one changeset");
    let report = trial.apply(&changeset)?;
    check(report.dc == trial.dc, "the report names the DC")?;
    let entry = trial
        .entry(&dn, &["homeDrive", "homeDirectory"])?
        .ok_or("account absent")?;
    check(
        labo::text(&entry, "homeDirectory") == directory && labo::text(&entry, "homeDrive") == "H:",
        "homeDrive and homeDirectory written, expanded",
    )?;
    let told = oracle_sddl(server, OWNER)?;
    println!("  oracle: {told}");
    let told = SecurityDescriptor::decode(&encoded(&told, &domain)?).map_err(debug)?;
    let expected =
        SecurityDescriptor::decode(&home_folder::descriptor(&account.sid)).map_err(debug)?;
    let explicit = ntfs::explicit_aces(&told);
    let wanted = ntfs::explicit_aces(&expected);
    check(
        explicit.len() == wanted.len()
            && explicit
                .iter()
                .zip(&wanted)
                .all(|(a, b)| ntfs::same_ace(a, b)),
        "explicit ACEs of ADUC: account and Administrators, folder and inherit-only",
    )?;
    let inherited = ntfs::inherited_of(&told);
    let authenticated = Sid::new(5, &[11]).map_err(debug)?;
    check(
        !ntfs::is_protected(&told)
            && inherited.len() >= 2
            && inherited.iter().all(|a| a.sid() != Some(authenticated)),
        &format!(
            "inheritance on, {} entries inherited from the root (its root-only entry not)",
            inherited.len()
        ),
    )?;
    let ace_order = ntfs::is_canonical(&ntfs::dacl_of(&told));
    check(ace_order, "canonical order")?;
    let mut files = session(server)?;
    let read = files
        .read_descriptors(&[OWNER.to_owned()], INFO_OGD)
        .map_err(debug)?
        .into_iter()
        .next()
        .flatten()
        .ok_or("not read by Calinda")?;
    files.close();
    check(
        ntfs::same_permissions(&SecurityDescriptor::decode(&read).map_err(debug)?, &told),
        "Calinda reads what the server tells",
    )?;

    println!("4. what the accounts can do");
    let inside = format!("{OWNER}\\{FILE}");
    check(
        as_account(server, kdc, OWNER, "write", &inside)?,
        "the account writes in its home folder",
    )?;
    check(
        !as_account(server, kdc, OTHER, "list", OWNER)?,
        "the other account cannot list it",
    )?;

    println!("5. an existing folder is left as it is");
    let again = home_folder::plan(&trial.connection, &account, &directory).map_err(debug)?;
    check(
        matches!(again, Some(Plan::Exists { .. })),
        "planned as existing: no operation",
    )?;
    let refused = trial.outcome(
        &changeset_of(changeset.operations.get(1).cloned().ok_or("no folder")?),
        None,
        None,
    )?;
    check(
        refused
            .problems
            .iter()
            .any(|p| p.kind == writer::ProblemKind::Exists),
        "a creation proposed again is refused by the prior verification",
    )?;

    println!("6. a missing parent, a missing share");
    let deeper = format!("\\\\{}\\{SHARE}\\absent\\{OWNER}", server.netbios);
    check(
        matches!(
            home_folder::plan(&trial.connection, &account, &deeper),
            Err(PlanError::Refused {
                refusal: Refusal::ParentMissing { .. },
                ..
            })
        ),
        "missing parent refused",
    )?;
    let elsewhere = format!("\\\\{}\\Pas-De-Partage\\{OWNER}", server.netbios);
    check(
        matches!(
            home_folder::plan(&trial.connection, &account, &elsewhere),
            Err(PlanError::Refused {
                refusal: Refusal::ShareMissing,
                ..
            })
        ),
        "missing share refused, no share created",
    )?;

    println!("7. the undo keeps what the account wrote");
    let inverse = trial.inverse(&report)?;
    check(
        matches!(
            inverse.operations.first(),
            Some(Operation::DeleteShareFolder { .. })
        ),
        "inverse: the folder first, then the attributes",
    )?;
    let kept = trial.outcome(&inverse, Some(report.id.clone()), None)?;
    check(
        kept.problems
            .iter()
            .any(|p| p.kind == writer::ProblemKind::NotLeaf),
        "undo refused: the folder is not empty",
    )?;
    check(folder_exists(server, OWNER)?, "folder and file kept")?;
    let mut files = session(server)?;
    files.delete(&inside, false).map_err(debug)?;
    files.close();
    trial.undo(&report)?;
    check(!folder_exists(server, OWNER)?, "folder deleted by the undo")?;
    let entry = trial
        .entry(&dn, &["homeDrive", "homeDirectory"])?
        .ok_or("account absent")?;
    check(
        labo::text(&entry, "homeDirectory").is_empty()
            && labo::text(&entry, "homeDrive").is_empty(),
        "attributes put back",
    )?;
    created_with_its_folder(server, trial, ou, &domain)
}

/// An account created with its profile, as the dialog of creation makes it: its home folder in
/// the same changeset, its ACEs naming the SID the DC gives it.
fn created_with_its_folder(server: &Server, trial: &Trial, ou: &str, domain: &Sid) -> Result<()> {
    println!("8. an account created with its home folder");
    let user = actions::NewUser {
        full_name: NEW.into(),
        identifier: NEW.into(),
        home_drive: "H:".into(),
        home_directory: format!("\\\\{}\\{SHARE}\\%username%", server.netbios),
        profile_path: format!("\\\\{}\\{SHARE}\\Profils\\%USERNAME%", server.netbios),
        ..actions::NewUser::default()
    };
    let mut changeset = actions::create_user(ou, &user).map_err(debug)?;
    let dn = changeset
        .operations
        .first()
        .map(|o| o.dn().to_owned())
        .ok_or("no creation")?;
    let directory = format!("\\\\{}\\{SHARE}\\{NEW}", server.netbios);
    let Some(Plan::Create(op)) =
        home_folder::plan_new(&trial.connection, &dn, NEW, &directory).map_err(debug)?
    else {
        return Err("the folder of the new account is not planned".into());
    };
    check(
        matches!(&*op, Operation::CreateShareFolder { account_dn: Some(d), descriptor, .. }
            if *d == dn && descriptor.is_empty()),
        "its ACEs wait for the SID of the account",
    )?;
    changeset.operations.push(*op);
    let report = trial.apply(&changeset)?;
    let entry = trial
        .entry(&dn, &["homeDirectory", "profilePath"])?
        .ok_or("account absent")?;
    check(
        labo::text(&entry, "homeDirectory") == directory
            && labo::text(&entry, "profilePath").ends_with(&format!("\\Profils\\{NEW}")),
        "%username% expanded at the creation",
    )?;
    let sid = trial.sid(&dn)?;
    let told =
        SecurityDescriptor::decode(&encoded(&oracle_sddl(server, NEW)?, domain)?).map_err(debug)?;
    let wanted = SecurityDescriptor::decode(&home_folder::descriptor(&sid)).map_err(debug)?;
    let (explicit, wanted) = (ntfs::explicit_aces(&told), ntfs::explicit_aces(&wanted));
    check(
        explicit.len() == wanted.len()
            && explicit
                .iter()
                .zip(&wanted)
                .all(|(a, b)| ntfs::same_ace(a, b)),
        &format!("ACEs of ADUC for the SID given by the DC ({sid})"),
    )?;
    trial.undo(&report)?;
    check(
        !folder_exists(server, NEW)? && !trial.exists(&dn)?,
        "undone: folder deleted, then the account",
    )
}

fn changeset_of(op: Operation) -> Changeset {
    Changeset {
        operations: vec![op],
        remarks: Vec::new(),
    }
}

/// What the interface trial of ADR 0027 (`tests/interface/essais-dossier.txt`) needs, by
/// `ANNUAIRE_LABO_DOSSIER`: `preparer` (share, OU `Essais-Dossier-UI`, account `hf-ui-a` without
/// home folder, `hf-ui-b` whose home folder is written but missing), `verifier` (the folders
/// the trial made, as the server tells them), `nettoyer` (all removed).
#[test]
#[ignore = "lab"]
fn home_folder_interface() -> Result<()> {
    let Ok(what) = std::env::var("ANNUAIRE_LABO_DOSSIER") else {
        return Ok(());
    };
    let lab = labo::lab();
    let server = server(&lab);
    let scratch = labo::Scratch::new("dossier-interface")?;
    let trial = Trial::new(&lab, &scratch)?;
    let ou = format!("OU=Essais-Dossier-UI,{}", trial.base);
    let result = match what.as_str() {
        "preparer" => {
            clean(&server)?;
            trial.remove_tree(&ou)?;
            let ou = trial.fresh_ou(&trial.base, "Essais-Dossier-UI")?;
            make_share(&server, &trial)?;
            for (name, home) in [
                ("hf-ui-a", None),
                (
                    "hf-ui-b",
                    Some(format!("\\\\{}\\{SHARE}\\hf-ui-b", server.netbios)),
                ),
            ] {
                let mut changeset = actions::create_user(
                    &ou,
                    &actions::NewUser {
                        full_name: name.into(),
                        identifier: name.into(),
                        home_drive: if home.is_some() {
                            "H:".into()
                        } else {
                            String::new()
                        },
                        home_directory: home.unwrap_or_default(),
                        ..actions::NewUser::default()
                    },
                )
                .map_err(debug)?;
                changeset.remarks.clear();
                trial.apply(&changeset)?;
                println!("PREPARED CN={name},{ou}");
            }
            Ok(())
        }
        "verifier" => {
            let domain = trial.sid(&trial.base)?;
            for name in ["hf-ui-a", "hf-ui-b", "hf-ui-c"] {
                let dn = format!("CN={name},{ou}");
                let sid = trial.sid(&dn).ok();
                let told = folder_exists(&server, name)?
                    .then(|| oracle_sddl(&server, name))
                    .transpose()?;
                let aduc = match (&told, sid) {
                    (Some(t), Some(sid)) => {
                        let t = SecurityDescriptor::decode(&encoded(t, &domain)?).map_err(debug)?;
                        let w = SecurityDescriptor::decode(&home_folder::descriptor(&sid))
                            .map_err(debug)?;
                        let (a, b) = (ntfs::explicit_aces(&t), ntfs::explicit_aces(&w));
                        a.len() == b.len() && a.iter().zip(&b).all(|(x, y)| ntfs::same_ace(x, y))
                    }
                    _ => false,
                };
                let home = trial
                    .entry(&dn, &["homeDirectory"])?
                    .map(|e| labo::text(&e, "homeDirectory"))
                    .unwrap_or_default();
                println!(
                    "VERIFIED {name}: account {}, homeDirectory {home:?}, folder {}, ACEs of ADUC {aduc}",
                    trial.exists(&dn)?,
                    told.is_some()
                );
            }
            Ok(())
        }
        _ => {
            clean(&server)?;
            trial.remove_tree(&ou)
        }
    };
    trial.connection.join();
    result
}

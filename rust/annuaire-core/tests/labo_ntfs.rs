// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! NTFS permissions of a share and the propagation of their inheritance (J8.4, ADR 0023 § 5),
//! against the lab (ADR 0020): `fs1.lab.test` (Samba member, `acl_xattr`) or, with
//! `ANNUAIRE_LABO_DOMAINE=win.test`, `wdc1.win.test` (Windows Server 2025).
//!
//! On the server, a share of trial `J84-Essai-<n>` whose folder holds two twin trees made by a
//! script on the server itself, `calinda` and `jumeau`, of 3 085 elements each (12 folders of
//! 12 subfolders of 20 files, 4 files in each first-level folder, and a folder `protege`):
//!
//! 1. the same protected DACL is set on both roots (with `CREATOR OWNER`, generic rights, an
//!    ACE for files only); Calinda propagates it with « replace » under `calinda`, Windows does
//!    it under `jumeau` (`TreeResetNamedSecurityInfo`, what the « Replace all child object
//!    permissions » box of Explorer calls); every descendant is compared;
//! 2. `protege` gets a protected DACL of its own, in both trees, and one file of `calinda` a
//!    DACL the administrator may not change;
//! 3. Calinda changes the root of `calinda` (a denial, « Modify » for Domain Users, a right on
//!    subfolders one level down, `CREATOR GROUP` giving a principal already granted more, Read
//!    on files already covered) by a changeset of two operations (the root, then the
//!    propagation), through the writer and its journal; the file the administrator may not
//!    change is reported as refused, the others are written; the descriptor written is read
//!    back by the server's own tool (`smbcacls --sddl` on Samba, `icacls` on Windows); the
//!    same DACL is set on `jumeau` and Windows propagates it (`SetNamedSecurityInfo`); both
//!    trees compared again, `protege` untouched;
//! 4. what an ordinary account of the domain does with its ticket (`smbclient`): it writes a
//!    file deep in `calinda` after step 3, an account of the denied group does not;
//! 5. another change, its propagation stopped after the first batches (what is written is in
//!    the backup), then resumed by a second changeset; trees compared;
//! 6. both changesets undone from their backups (Ctrl+Z): `calinda` is again exactly as after
//!    step 3, and the ordinary account still writes, then after undoing step 3 it no longer
//!    does;
//! 7. a propagation cut by a stop of the application (J8.7): its intention journaled, the
//!    propagation run without the writer and stopped on the way, no report; the journal offers
//!    it to resume, the backup settles it as applied, the completion propagates again with a
//!    backup of its own and the tree is as Windows makes it; both undone, the tree is back.
//!
//! Windows propagates for the twin: on wdc1 itself (PowerShell over ssh,
//! `ANNUAIRE_LABO_SSH_WDC1`), on fs1 from the Windows workstation joined to LAB.TEST as
//! `LAB\Administrator` (`labo/poste.py --domaine`, `ANNUAIRE_LABO_POSTE`), on the UNC path of
//! the twin, as Explorer would. The rate of the propagation (elements per second) is measured
//! from the machine that runs the trial. Everything made is removed at the end, even after a
//! failure; share, folder and OU carry the number of the run, other trials may play on the same
//! server. The backups go to `$XDG_STATE_HOME/calinda/propagations`: run the trial with a
//! `XDG_STATE_HOME` of its own.
//!
//! With `ANNUAIRE_LABO_SMB2=1` (J8.7, fs1 only), the same trial runs with fs1 limited to SMB 2.1
//! (`server max protocol = SMB2_10` added to the `[global]` of its `smb.conf`, its shares being
//! in the registry; the file saved before and put back after, `smbd` restarted both times, even
//! after a failure, a copy left by an interrupted trial put back first) through a profile with
//! the option « Allow SMB 2 with signing only » (ADR 0021): the sessions of the trial and of the
//! writer negotiate SMB 2.1, signed with HMAC-SHA256, not encrypted, and so does the
//! workstation; at the end, a session and a propagation through a profile without the option
//! are refused (`Smb2Only`), nothing written. Then fs1 is put back, before the cleaning.
//!
//! `ntfs_volume`, with `ANNUAIRE_LABO_VOLUME=100000` (J8.7; skipped without it), does it at
//! scale: two twin trees of 100 111 elements (10 × 10 × 10 folders, 96 files in each of the
//! last ones, a folder of 3 000 files) made on the server, counted (`propagation::count`),
//! propagated with « replace » by the writer, changed and propagated again, stopped half way
//! and resumed, then undone (Ctrl+Z) to the tree as made; the rate, the memory of the process
//! (peak of `VmHWM`, set back before each step by `/proc/self/clear_refs`) and the size of each
//! backup are printed; Windows propagates the same root on the twin (« replace », the tree
//! holding no explicit entry by then) and every element is compared, the descriptors read by
//! batches. Run it alone (`-- --ignored ntfs_volume`): about ten minutes on fs1, most of it
//! Windows from the workstation.
//!
//! ```text
//! KRB5CCNAME=FILE:… XDG_STATE_HOME=… cargo test -p annuaire-core --test labo_ntfs -- --ignored --nocapture --test-threads 1
//! ```

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::BTreeMap;
use std::process::Command;
use std::time::{Duration, Instant};

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_codecs::{Sid, sddl};
use annuaire_core::actions;
use annuaire_core::changes::{self, Change, Changeset, Issue, Operation, Report, base64_encode};
use annuaire_core::ntfs;
use annuaire_core::propagation::{self, Progress};
use annuaire_core::smb::msg::{dialect, signing};
use annuaire_core::smb::{ErrorKind, Options};
use annuaire_core::srvsvc::{self, Share, Srvsvc};
use annuaire_core::sysvol::{self, INFO_DACL, INFO_OGD, Protection, Session, SysvolError};
use annuaire_core::writer;

use labo::{Lab, Result, Trial, check, debug};

/// The number of this run, in the names of what it makes on the servers (share, folder, OU):
/// other trials may run there at the same time, and the Windows workstation keeps a connection
/// to a share deleted then created again under the same name (`SetNamedSecurityInfo` then
/// answers 87).
fn run() -> u32 {
    std::process::id() % 100_000
}

/// `ANNUAIRE_LABO_SMB2`: the trial on fs1 limited to SMB 2.1, through a profile with the option
/// « Allow SMB 2 with signing only » (ADR 0021).
fn smb2() -> bool {
    std::env::var("ANNUAIRE_LABO_SMB2").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// The protection of the sessions of the trial: the profile option in SMB 2 mode.
fn protection() -> Protection {
    Protection::of_profile(smb2())
}
const DELAY: Duration = Duration::from_secs(60);
const OURS: &str = "calinda";
const TWIN: &str = "jumeau";
/// An element of `calinda` the administrator may read but not change (its DACL grants it
/// read only, and `OWNER RIGHTS` takes WRITE_DAC from its owner): the propagation must report
/// it and go on. Left out of the comparisons with the twin.
const LOCKED: &str = "d2\\s2\\f1.txt";
/// Elements of one tree, its root left out.
const ELEMENTS: usize = 12 + 12 * 4 + 12 * 12 + 12 * 12 * 20 + 2;

/// The server of the trial and the share it makes there.
#[derive(Debug)]
struct Server {
    name: String,
    share: String,
    /// The folder of the share, as the server names it.
    path: String,
    windows: bool,
    /// Elements of one tree, its root left out.
    elements: usize,
}

impl Server {
    fn of(lab: &Lab) -> Self {
        Self::named(lab, "J84-Essai", ELEMENTS)
    }

    /// `name` with the number of the run: the share, and its folder on the server.
    fn named(lab: &Lab, name: &str, elements: usize) -> Self {
        let share = format!("{name}-{}", run());
        if lab.windows() {
            Self {
                name: format!("wdc1.{}", lab.domain),
                path: format!("C:\\{share}"),
                share,
                windows: true,
                elements,
            }
        } else {
            Self {
                name: format!("fs1.{}", lab.domain),
                path: format!("/srv/{}", share.to_lowercase()),
                share,
                windows: false,
                elements,
            }
        }
    }

    /// A bash script as root on fs1 (`ANNUAIRE_LABO_SSH_FS1`, as `labo_effective_access`).
    fn bash(&self, script: &str) -> Result<String> {
        let command = std::env::var("ANNUAIRE_LABO_SSH_FS1")
            .unwrap_or_else(|_| "ssh -o BatchMode=yes labadmin@fs1.lab.test".into());
        labo::run(
            Command::new("sh")
                .arg("-c")
                .arg(format!("{command} 'sudo bash -s'")),
            script.as_bytes(),
        )
    }

    /// PowerShell on wdc1 by ssh (`ANNUAIRE_LABO_SSH_WDC1`, default
    /// `ssh -o BatchMode=yes labadmin@wdc1.win.test`): the script in `-EncodedCommand`, the
    /// standard input of OpenSSH for Windows losing what passes 4 KiB.
    fn powershell(&self, script: &str) -> Result<String> {
        let command = std::env::var("ANNUAIRE_LABO_SSH_WDC1")
            .unwrap_or_else(|_| "ssh -o BatchMode=yes labadmin@wdc1.win.test".into());
        let full = format!(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; \
$ErrorActionPreference='Stop'; {script}"
        );
        let utf16: Vec<u8> = full.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64_encode(&utf16);
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!(
                "{command} 'powershell -NoProfile -NonInteractive -EncodedCommand {encoded}'"
            ))
            .output()?;
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        // PowerShell writes its errors as CLIXML on the standard error.
        let errors = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() || errors.contains("S=\"Error\"") {
            return Err(format!("powershell: {text}\n{errors}").into());
        }
        Ok(text)
    }
}

fn options() -> Options {
    protection().options(DELAY)
}

fn session(server: &Server) -> Result<Session> {
    Session::open_share(&server.name, &server.share, protection(), DELAY).map_err(debug)
}

// --- Windows propagates -------------------------------------------------------------------------

/// The C# that sets a DACL as Explorer does: `SetNamedSecurityInfo` (inheritance propagated by
/// the client), or `TreeResetNamedSecurityInfo` without keeping the explicit entries (« Replace
/// all child object permissions »). The descriptor comes in base64, its DACL is taken as is.
const SETTER: &str = r#"Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class J84 {
  [DllImport("advapi32.dll")] static extern bool GetSecurityDescriptorDacl(byte[] sd, out bool present, out IntPtr dacl, out bool defaulted);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint TreeResetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, bool keep, IntPtr fn, int mode, IntPtr args);
  public static uint Set(string path, string b64, bool protect, bool reset) {
    byte[] sd = Convert.FromBase64String(b64);
    GCHandle pin = GCHandle.Alloc(sd, GCHandleType.Pinned);
    try {
      IntPtr start = pin.AddrOfPinnedObject();
      int offset = BitConverter.ToInt32(sd, 16);
      IntPtr dacl = offset == 0 ? IntPtr.Zero : new IntPtr(start.ToInt64() + offset);
      uint info = 4u | (protect ? 0x80000000u : 0x20000000u);
      return reset
        ? TreeResetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero, false, IntPtr.Zero, 0, IntPtr.Zero)
        : SetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, dacl, IntPtr.Zero);
    } finally { pin.Free(); }
  }
}
'@
"#;

/// Windows sets `descriptor`'s DACL on the root of the twin and propagates it.
fn windows_propagates(
    server: &Server,
    descriptor: &SecurityDescriptor,
    reset: bool,
) -> Result<f64> {
    let bytes = descriptor.encode().map_err(debug)?;
    let protect = ntfs::is_protected(descriptor);
    let target = if server.windows {
        format!("{}\\{TWIN}", server.path)
    } else {
        format!("\\\\{}\\{}\\{TWIN}", server.name, server.share)
    };
    // From the workstation, the dialect of its connection to fs1 (2.1 in SMB 2 mode).
    let dialect = if server.windows {
        String::new()
    } else {
        format!(
            "try {{ 'DIALECT=' + (Get-SmbConnection -ServerName '{}' -ErrorAction Stop | \
Select-Object -First 1).Dialect }} catch {{ 'DIALECT=?' }}\n",
            server.name
        )
    };
    let script = format!(
        "{SETTER}$w = [Diagnostics.Stopwatch]::StartNew()\n\
$r = [J84]::Set('{target}', '{}', ${protect}, ${reset})\n\
'RESULT=' + $r\n'SECONDS=' + $w.Elapsed.TotalSeconds.ToString([Globalization.CultureInfo]::InvariantCulture)\n{dialect}",
        base64_encode(&bytes)
    );
    let out = if server.windows {
        server.powershell(&script)?
    } else {
        labo::poste(&script, &["--domaine"])?
    };
    let lines = labo::lines(&out);
    check(
        lines.get("RESULT").map(String::as_str) == Some("0"),
        &format!(
            "Windows set the DACL of the twin ({out}; {} ; {})",
            text(descriptor),
            base64_encode(&bytes)
        ),
    )?;
    if let Some(dialect) = lines.get("DIALECT") {
        println!("  the workstation reaches {} in SMB {dialect}", server.name);
        if smb2() {
            check(dialect == "2.1", "the workstation in SMB 2.1 too")?;
        }
    }
    Ok(lines
        .get("SECONDS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0.0))
}

// --- Trees ---------------------------------------------------------------------------------------

/// The two trees, made on the server itself.
fn make_trees(server: &Server) -> Result<()> {
    if server.windows {
        server.powershell(&format!(
            "$d='{}'; if (Test-Path $d) {{ Remove-Item -Recurse -Force $d }}\n\
foreach ($t in '{OURS}','{TWIN}') {{ foreach ($i in 1..12) {{ $a=\"$d\\$t\\d$i\"; \
[void][IO.Directory]::CreateDirectory($a); foreach ($k in 1..4) {{ [IO.File]::WriteAllText(\"$a\\f$k.txt\",'x') }}; \
foreach ($j in 1..12) {{ $b=\"$a\\s$j\"; [void][IO.Directory]::CreateDirectory($b); \
foreach ($k in 1..20) {{ [IO.File]::WriteAllText(\"$b\\f$k.txt\",'x') }} }} }}; \
[void][IO.Directory]::CreateDirectory(\"$d\\$t\\protege\"); [IO.File]::WriteAllText(\"$d\\$t\\protege\\secret.txt\",'x') }}\n\
'OK'",
            server.path
        ))?;
    } else {
        // The administrator owns everything: with `acl_xattr:ignore system acls`, Samba lets
        // only the POSIX owner write the descriptor of an element without NT descriptor.
        server.bash(&format!(
            "set -e\nd={}\nrm -rf \"$d\"\ninstall -d -m 0777 \"$d\"\n\
for t in {OURS} {TWIN}; do\n for i in $(seq 1 12); do\n  a=\"$d/$t/d$i\"; mkdir -p \"$a\"\n\
  for k in 1 2 3 4; do echo x > \"$a/f$k.txt\"; done\n  for j in $(seq 1 12); do\n\
   b=\"$a/s$j\"; mkdir \"$b\"; for k in $(seq 1 20); do echo x > \"$b/f$k.txt\"; done\n  done\n done\n\
 mkdir \"$d/$t/protege\"; echo x > \"$d/$t/protege/secret.txt\"\ndone\n\
chown -R 'LAB\\administrator':'LAB\\domain users' \"$d\"\nchmod -R a+rwX \"$d\"\necho OK\n",
            server.path
        ))?;
    }
    Ok(())
}

/// Every descriptor under `root` (paths relative to it, the root as « »).
fn snapshot(session: &mut Session, root: &str) -> Result<BTreeMap<String, SecurityDescriptor>> {
    let tree = session
        .walk(&[root.to_owned()])
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("no tree")?;
    let mut paths = vec![root.to_owned()];
    paths.extend(tree.entries.iter().map(|e| sysvol::join(&[root, &e.path])));
    let read = session.descriptors(&paths, INFO_OGD).map_err(debug)?;
    let mut out = BTreeMap::new();
    for (path, r) in paths.iter().zip(read) {
        let bytes = r.map_err(|s| format!("{path}: 0x{s:08X}"))?;
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .trim_start_matches('\\')
            .to_lowercase();
        out.insert(relative, SecurityDescriptor::decode(&bytes).map_err(debug)?);
    }
    Ok(out)
}

fn text(d: &SecurityDescriptor) -> String {
    sddl::sd_to_sddl(d, None).unwrap_or_default()
}

/// The ACEs of `x` and `y` that differ, position by position, and the protection.
fn ace_diff(x: &SecurityDescriptor, y: &SecurityDescriptor) -> String {
    let ace = |a: Option<&annuaire_codecs::sd::Ace>| {
        a.and_then(|a| sddl::ace_to_sddl(a, None).ok())
            .unwrap_or_else(|| "-".into())
    };
    let (p, q) = (ntfs::dacl_of(x), ntfs::dacl_of(y));
    let mut out = Vec::new();
    for i in 0..p.len().max(q.len()) {
        let (a, b) = (p.get(i), q.get(i));
        let same = matches!((a, b), (Some(a), Some(b)) if ntfs::same_ace(a, b));
        if !same {
            out.push(format!("#{i} {} | {}", ace(a), ace(b)));
        }
    }
    if ntfs::is_protected(x) != ntfs::is_protected(y) {
        out.push("protection".into());
    }
    out.join(" ; ")
}

/// The paths whose permissions differ (at most a few shown), and their number.
fn differences(
    a: &BTreeMap<String, SecurityDescriptor>,
    b: &BTreeMap<String, SecurityDescriptor>,
    skip_root: bool,
) -> (usize, Vec<String>) {
    let mut n = 0;
    let mut shown = Vec::new();
    for (path, x) in a {
        if (skip_root && path.is_empty()) || path == LOCKED {
            continue;
        }
        let same = b.get(path).is_some_and(|y| ntfs::same_permissions(x, y));
        if !same {
            n += 1;
            if shown.len() < 4 {
                shown.push(format!(
                    "{path}: {}",
                    b.get(path).map_or("(absent)".into(), |y| ace_diff(x, y))
                ));
            }
        }
    }
    n += b.keys().filter(|k| !a.contains_key(*k)).count();
    (n, shown)
}

fn compare_trees(
    session: &mut Session,
    what: &str,
) -> Result<BTreeMap<String, SecurityDescriptor>> {
    let ours = snapshot(session, OURS)?;
    let twin = snapshot(session, TWIN)?;
    check(
        ours.len() == ELEMENTS + 1 && twin.len() == ELEMENTS + 1,
        &format!("{what}: {} and {} elements", ours.len(), twin.len()),
    )?;
    let (n, shown) = differences(&ours, &twin, true);
    for s in &shown {
        println!("    {s}");
    }
    check(
        n == 0,
        &format!("{what}: propagation of Calinda = propagation of Windows ({n} differences)"),
    )?;
    Ok(ours)
}

// --- Descriptors ---------------------------------------------------------------------------------

/// A DACL from SDDL, written as Calinda writes it (`ntfs::written`), on `origin`.
fn dacl(origin: &SecurityDescriptor, text: &str, protected: bool) -> Result<SecurityDescriptor> {
    let parsed = sddl::sd_from_sddl(&format!("D:{text}"), None, false).map_err(debug)?;
    Ok(ntfs::written(
        origin,
        ntfs::canonical(&ntfs::dacl_of(&parsed)),
        protected,
    ))
}

fn read_one(session: &mut Session, path: &str) -> Result<(Vec<u8>, SecurityDescriptor)> {
    let bytes = session
        .descriptors(&[path.to_owned()], INFO_OGD)
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("no answer")?
        .map_err(|s| format!("{path}: 0x{s:08X}"))?;
    let d = SecurityDescriptor::decode(&bytes).map_err(debug)?;
    Ok((bytes, d))
}

fn set(session: &mut Session, path: &str, d: &SecurityDescriptor) -> Result<()> {
    session
        .set_descriptor(path, &d.encode().map_err(debug)?, INFO_DACL)
        .map_err(debug)
}

/// The descriptor of `path` as the server's own tool reads it: `smbcacls --sddl` (Samba),
/// `icacls /save` (Windows, the DACL only); its aliases (`DU`…) resolved in `domain`.
fn told_by_server(server: &Server, path: &str, domain: &Sid) -> Result<SecurityDescriptor> {
    let text = if server.windows {
        // `icacls /save`, not `Get-Acl`: .NET puts the ACEs of the SDDL it gives in an order
        // of its own.
        let out = server.powershell(&format!(
            "$f = Join-Path $env:TEMP 'j84.acl'; icacls '{}\\{path}' /save $f /q | Out-Null; \
'SDDL=' + (Get-Content -Encoding Unicode $f)[1]; Remove-Item $f",
            server.path
        ))?;
        labo::lines(&out).remove("SDDL").ok_or("no SDDL")?
    } else {
        let output = Command::new("smbcacls")
            .args([
                "--use-kerberos=required",
                "--sddl",
                &format!("//{}/{}", server.name, server.share),
                path,
            ])
            .output()?;
        let out = String::from_utf8_lossy(&output.stdout).into_owned();
        out.lines()
            .find(|l| l.contains("D:"))
            .map(|l| l.trim().trim_start_matches("SDDL:").trim().to_owned())
            .ok_or_else(|| {
                format!(
                    "smbcacls: {out} {}",
                    String::from_utf8_lossy(&output.stderr)
                )
            })?
    };
    sddl::sd_from_sddl(&text, Some(domain), false).map_err(|e| format!("{text}: {e:?}").into())
}

// --- Accounts ------------------------------------------------------------------------------------

fn add_member(trial: &Trial, group: &str, member: &str) -> Result<()> {
    let change =
        Change::new("member", Vec::new(), vec![member.as_bytes().to_vec()]).map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![Operation::modify(group, vec![change], None).map_err(debug)?],
        remarks: Vec::new(),
    })?;
    Ok(())
}

fn user(trial: &Trial, lab: &Lab, ou: &str, name: &str, secret: &str) -> Result<String> {
    trial.apply(
        &actions::create_user(
            ou,
            &actions::NewUser {
                full_name: name.into(),
                identifier: name.into(),
                upn: format!("{name}@{}", lab.domain),
                password: Some(secret.into()),
                change_at_next_logon: false,
                enable: true,
                ..actions::NewUser::default()
            },
        )
        .map_err(debug)?,
    )?;
    Ok(format!("CN={name},{ou}"))
}

fn ticket(kdc: &labo::Kdc, principal: &str, secret: &str, cache: &str) -> Result<()> {
    let mut last = None;
    for _ in 0..15 {
        match kdc.kinit_into(principal, secret, cache) {
            None => return Ok(()),
            Some(refusal) => last = Some(refusal),
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    Err(format!("no ticket for {principal}: {}", last.unwrap_or_default()).into())
}

/// Can the account of `cache` write a file in `folder` of the share? (`smbclient put`)
fn writes(server: &Server, kdc: &labo::Kdc, cache: &str, folder: &str) -> Result<bool> {
    let sample = kdc.folder.path().join("j84.txt");
    std::fs::write(&sample, b"J8.4\n")?;
    let mut command = Command::new("smbclient");
    command.args([
        "--use-kerberos=required",
        &format!("//{}/{}", server.name, server.share),
        "-c",
        &format!(
            "put \"{}\" \"{folder}\\j84-ecrit.txt\"; rm \"{folder}\\j84-ecrit.txt\"",
            sample.display()
        ),
    ]);
    for (key, value) in kdc.env(cache) {
        command.env(key, value);
    }
    let output = command.output()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if text.contains("NT_STATUS_ACCESS_DENIED") {
        return Ok(false);
    }
    if output.status.success() && !text.contains("NT_STATUS_") {
        return Ok(true);
    }
    Err(format!("smbclient: {}", text.trim()).into())
}

// --- The trial -----------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Made {
    share: bool,
    folder: bool,
    backups: Vec<String>,
}

fn changeset(operations: Vec<Operation>) -> Changeset {
    Changeset {
        operations,
        remarks: Vec::new(),
    }
}

fn rate(p: &Progress, seconds: f64) -> String {
    format!(
        "{} examined, {} written, {} refused in {seconds:.2} s: {:.0} elements/s, {:.0} written/s",
        p.examined,
        p.written,
        p.refused,
        p.examined as f64 / seconds.max(1e-3),
        p.written as f64 / seconds.max(1e-3)
    )
}

/// The root of `calinda` changed and propagated by one changeset; its report, the control.
fn change_and_propagate(
    trial: &Trial,
    server: &Server,
    made: &mut Made,
    before: &[u8],
    after: &SecurityDescriptor,
    replace: bool,
    stop_after: Option<usize>,
) -> Result<(Report, Progress, f64, Vec<propagation::Refusal>)> {
    let id = propagation::new_id();
    made.backups.push(id.clone());
    let control = propagation::control(&id);
    let mut operations = Vec::new();
    let after_bytes = after.encode().map_err(debug)?;
    let present = SecurityDescriptor::decode(before).map_err(debug)?;
    if !ntfs::same_permissions(&present, after) {
        operations.push(Operation::set_file_descriptor(
            &server.name,
            &server.share,
            OURS,
            before.to_vec(),
            after_bytes,
        ));
    }
    operations.push(Operation::propagate_inheritance(
        &server.name,
        &server.share,
        OURS,
        replace,
        &id,
        server.elements,
    ));
    let watcher = stop_after.map(|n| {
        let control = control.clone();
        std::thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(3600);
            while Instant::now() < end {
                let p = control.progress();
                if p.examined >= n {
                    control.stop();
                    return;
                }
                if p.finished {
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    });
    let start = Instant::now();
    let report = trial.apply(&changeset(operations))?;
    let seconds = start.elapsed().as_secs_f64();
    if let Some(w) = watcher {
        let _ = w.join();
    }
    let progress = control.progress();
    let refusals = control.refusals();
    for r in refusals.iter().take(5) {
        println!("    refused {r:?}");
    }
    propagation::forget(&id);
    Ok((report, progress, seconds, refusals))
}

/// The share of the trial, on its folder, open to everyone (the NTFS permissions decide).
fn add_share(server: &Server, made: &mut Made, remark: &str) -> Result<()> {
    let mut service = Srvsvc::open(&server.name, &options()).map_err(debug)?;
    let added = service.add(&Share {
        name: server.share.clone(),
        kind: srvsvc::stype::DISKTREE,
        remark: remark.into(),
        max_uses: u32::MAX,
        path: server.path.clone(),
        descriptor: Some(
            sddl::sd_from_sddl("O:BAG:BAD:(A;;FA;;;WD)", None, false)
                .map_err(debug)?
                .encode()
                .map_err(debug)?,
        ),
        ..Share::default()
    });
    service.close();
    added.map_err(debug)?;
    made.share = true;
    Ok(())
}

fn cases(trial: &Trial, lab: &Lab, server: &Server, made: &mut Made) -> Result<()> {
    println!("1. trees, share, accounts");
    let start = Instant::now();
    made.folder = true;
    make_trees(server)?;
    println!(
        "  {} elements made on the server in {:.1} s",
        2 * (ELEMENTS + 1),
        start.elapsed().as_secs_f64()
    );
    add_share(server, made, "Essai J8.4")?;

    let n = run();
    let essais = trial.fresh_ou(&trial.base, &format!("Essais-J84-{}", run()))?;
    let refused_group = format!("GG-J84-Refus-{n}");
    trial.apply(
        &actions::create_group(&essais, &refused_group, "", GroupScope::Global, true, "")
            .map_err(debug)?,
    )?;
    let refused_dn = format!("CN={refused_group},{essais}");
    let readers_group = format!("GG-J84-Lecteurs-{n}");
    trial.apply(
        &actions::create_group(&essais, &readers_group, "", GroupScope::Global, true, "")
            .map_err(debug)?,
    )?;
    let readers_dn = format!("CN={readers_group},{essais}");
    let (plain, denied) = (format!("j84a.{n}"), format!("j84r.{n}"));
    let (plain_secret, denied_secret) = (labo::password(24), labo::password(24));
    let plain_dn = user(trial, lab, &essais, &plain, &plain_secret)?;
    let denied_dn = user(trial, lab, &essais, &denied, &denied_secret)?;
    add_member(trial, &refused_dn, &denied_dn)?;
    add_member(trial, &readers_dn, &plain_dn)?;
    let refused = trial.sid(&refused_dn)?;
    let readers = trial.sid(&readers_dn)?;
    let domain = trial.sid(&plain_dn)?.domain().map_err(debug)?;
    let domain_users = domain.with_rid(513).map_err(debug)?;

    let mut s = session(server)?;
    if smb2() {
        let n = s.negotiated();
        check(
            (n.dialect, n.encrypted, n.signing) == (dialect::SMB210, false, signing::HMAC_SHA256),
            "the share in SMB 2.1, not encrypted, signed with HMAC-SHA256",
        )?;
    }
    println!("2. the same root on both trees, propagated with « replace »");
    let (_, origin) = read_one(&mut s, OURS)?;
    let base = dacl(
        &origin,
        "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;GRGX;;;AU)(A;OI;FR;;;BU)",
        true,
    )?;
    let (before, _) = read_one(&mut s, OURS)?;
    let (report, progress, seconds, _) =
        change_and_propagate(trial, server, made, &before, &base, true, None)?;
    println!("  Calinda: {}", rate(&progress, seconds));
    check(
        report.changeset.operations.len() == 2,
        "one changeset of two operations",
    )?;
    check(
        progress.refused == 0 && progress.examined == ELEMENTS && progress.finished,
        &format!("every element examined ({progress:?})"),
    )?;
    // Windows is given the root as the server keeps it (Samba stores generic rights mapped):
    // both propagate from the same DACL.
    let (_, stored) = read_one(&mut s, OURS)?;
    set(&mut s, TWIN, &stored)?;
    let windows = windows_propagates(server, &stored, true)?;
    println!(
        "  Windows ({}): {windows:.2} s",
        if server.windows {
            "on the server"
        } else {
            "from the workstation"
        }
    );
    compare_trees(&mut s, "replace")?;

    println!("3. a protected folder of its own");
    let (_, p) = read_one(&mut s, &format!("{OURS}\\protege"))?;
    let own = dacl(&p, "(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)", true)?;
    set(&mut s, &format!("{OURS}\\protege"), &own)?;
    set(&mut s, &format!("{TWIN}\\protege"), &own)?;
    // Not protected: the propagation tries to write it, the server refuses.
    let locked_path = format!("{OURS}\\{LOCKED}");
    let (_, l) = read_one(&mut s, &locked_path)?;
    let locked = dacl(&l, "(A;;0x1200a9;;;BA)(A;;0x20000;;;OW)(A;;FA;;;SY)", false)?;
    set(&mut s, &locked_path, &locked)?;

    println!("4. a change of the root, propagated by the writer");
    let (before, root) = read_one(&mut s, OURS)?;
    let mut explicit = ntfs::explicit_aces(&root);
    let added = sddl::sd_from_sddl(
        &format!(
            "D:(D;OICI;0x116;;;{refused})(A;OICI;0x1301bf;;;{domain_users})(A;CINP;FR;;;{readers})(A;OICIIO;GR;;;CG)(A;OI;FR;;;{domain_users})"
        ),
        None,
        false,
    )
    .map_err(debug)?;
    explicit.extend(ntfs::dacl_of(&added));
    let changed = ntfs::composed(&root, &explicit, &[], true);
    check(
        ntfs::changes_children(&root, &changed),
        "the change reaches the children",
    )?;
    let (report_main, progress, seconds, refusals) =
        change_and_propagate(trial, server, made, &before, &changed, false, None)?;
    println!("  Calinda: {}", rate(&progress, seconds));
    check(
        progress.refused == 1 && progress.written > 3000,
        &format!("descendants written, one refused ({progress:?})"),
    )?;
    check(
        refusals.iter().any(|r| {
            r.path.eq_ignore_ascii_case(&locked_path)
                && r.reason == propagation::Reason::Refused(0xC000_0022)
        }),
        &format!("the locked element is reported as refused ({refusals:?})"),
    )?;
    let backup = propagation::backup_path(made.backups.last().ok_or("backup")?, None);
    let (header, saved) = propagation::read_backup(&backup).map_err(debug)?;
    check(
        // Saved before the write: the element refused is in it too.
        header.share == server.share && saved.len() == progress.written + progress.refused,
        &format!("backup {} holds {} elements", backup.display(), saved.len()),
    )?;
    // Read back by the server's own tool.
    let (_, written_root) = read_one(&mut s, OURS)?;
    for path in [OURS.to_owned(), format!("{OURS}\\d3\\s7\\f11.txt")] {
        let told = told_by_server(server, &path, &domain)?;
        let (_, ours) = read_one(&mut s, &path)?;
        println!("  {path}: {}", text(&told));
        check(
            ntfs::same_permissions(&told, &ours),
            &format!("{path} read back identical by the server's tool"),
        )?;
    }
    check(
        ntfs::same_permissions(&written_root, &changed),
        "the root is as written",
    )?;
    set(&mut s, TWIN, &written_root)?;
    let windows = windows_propagates(server, &written_root, false)?;
    println!("  Windows: {windows:.2} s");
    let after_main = compare_trees(&mut s, "change")?;
    check(
        after_main
            .get("protege")
            .is_some_and(|d| ntfs::same_permissions(d, &own)),
        "the protected folder is untouched",
    )?;

    println!("5. what ordinary accounts do with their ticket");
    let kdc = labo::Kdc::new(lab, &lab.pdc_name())?;
    ticket(
        &kdc,
        &format!("{plain}@{}", lab.realm()),
        &plain_secret,
        "cc-a",
    )?;
    ticket(
        &kdc,
        &format!("{denied}@{}", lab.realm()),
        &denied_secret,
        "cc-r",
    )?;
    let deep = format!("{OURS}\\d5\\s9");
    check(
        writes(server, &kdc, "cc-a", &deep)?,
        "Domain Users write deep after the propagation",
    )?;
    check(
        !writes(server, &kdc, "cc-r", &deep)?,
        "the denied group does not write",
    )?;

    println!("6. another change, stopped, then resumed");
    let (before, root) = read_one(&mut s, OURS)?;
    let mut explicit = ntfs::explicit_aces(&root);
    explicit.extend(ntfs::dacl_of(
        &sddl::sd_from_sddl(&format!("D:(A;OIIO;0x1200a9;;;{readers})"), None, false)
            .map_err(debug)?,
    ));
    let second = ntfs::composed(&root, &explicit, &[], true);
    let (report_stopped, progress, seconds, _) = change_and_propagate(
        trial,
        server,
        made,
        &before,
        &second,
        false,
        Some(propagation::BATCH * 2),
    )?;
    println!("  stopped: {}", rate(&progress, seconds));
    check(
        progress.stopped && progress.examined < ELEMENTS && progress.written > 0,
        &format!("stopped on the way ({progress:?})"),
    )?;
    let half = snapshot(&mut s, OURS)?;
    let stopped_saved = propagation::read_backup(&propagation::backup_path(
        made.backups.last().ok_or("backup")?,
        None,
    ))
    .map_err(debug)?
    .1;
    check(
        stopped_saved.len() >= progress.written,
        "what is written is saved",
    )?;
    let (before, _) = read_one(&mut s, OURS)?;
    let (report_resumed, progress, seconds, _) =
        change_and_propagate(trial, server, made, &before, &second, false, None)?;
    println!("  resumed: {}", rate(&progress, seconds));
    check(
        report_resumed.changeset.operations.len() == 1 && progress.finished && !progress.stopped,
        "the resumption is a propagation alone, to the end",
    )?;
    check(
        progress.written + stopped_saved.len() >= 2900,
        "the resumption writes what the stop left",
    )?;
    let (_, stored) = read_one(&mut s, OURS)?;
    set(&mut s, TWIN, &stored)?;
    windows_propagates(server, &stored, false)?;
    compare_trees(&mut s, "stopped and resumed")?;
    let (n, _) = differences(&half, &snapshot(&mut s, OURS)?, false);
    check(n > 0, "the stop had left the tree half done")?;

    println!("7. undone from the backups");
    let start = Instant::now();
    trial.undo(&report_resumed)?;
    trial.undo(&report_stopped)?;
    println!("  two undos in {:.2} s", start.elapsed().as_secs_f64());
    let back = snapshot(&mut s, OURS)?;
    let (n, shown) = differences(&after_main, &back, false);
    for line in &shown {
        println!("    {line}");
    }
    check(
        n == 0,
        &format!("the tree is as after step 4 ({n} differences)"),
    )?;
    check(
        writes(server, &kdc, "cc-a", &deep)?,
        "Domain Users still write",
    )?;
    trial.undo(&report_main)?;
    check(
        !writes(server, &kdc, "cc-a", &deep)?,
        "no longer after undoing step 4",
    )?;
    let (n, _) = differences(&after_main, &snapshot(&mut s, OURS)?, false);
    check(
        n > 3000,
        &format!("step 4 undone everywhere ({n} elements back)"),
    )?;
    kdc.destroy("cc-a");
    kdc.destroy("cc-r");
    cut_by_a_stop(trial, server, made, &mut s, &readers)?;
    s.close();
    Ok(())
}

/// Step 8: a propagation cut by a stop of the application, settled and completed as the
/// resuming at the opening of the domain does it (`history::propose_resume`).
fn cut_by_a_stop(
    trial: &Trial,
    server: &Server,
    made: &mut Made,
    s: &mut Session,
    readers: &Sid,
) -> Result<()> {
    println!("8. a propagation cut by a stop of the application");
    let start_tree = snapshot(s, OURS)?;
    let (before, root) = read_one(s, OURS)?;
    let mut explicit = ntfs::explicit_aces(&root);
    explicit.extend(ntfs::dacl_of(
        &sddl::sd_from_sddl(&format!("D:(A;OICI;0x1301bf;;;{readers})"), None, false)
            .map_err(debug)?,
    ));
    let third = ntfs::composed(&root, &explicit, &[], true);
    set(s, OURS, &third)?;
    let id = propagation::new_id();
    made.backups.push(id.clone());
    let changeset = changeset(vec![Operation::propagate_inheritance(
        &server.name,
        &server.share,
        OURS,
        false,
        &id,
        ELEMENTS,
    )]);
    // What the writer journals before its first request, then nothing more: the stop.
    let mut intention = serde_json::Map::new();
    for (key, value) in [
        ("version", serde_json::json!(changes::JOURNAL_VERSION)),
        (
            "id",
            serde_json::json!(format!("essai-{}", propagation::new_id())),
        ),
        ("etape", serde_json::json!("intention")),
        ("horodatage", serde_json::json!(writer::timestamp())),
        ("domaine", serde_json::json!(trial.profile.domain)),
        ("dc", serde_json::json!(trial.dc)),
        ("utilisateur", serde_json::json!("essai")),
        ("reprend", serde_json::Value::Null),
        (
            "changeset",
            changes::changeset_to_json(&changeset).map_err(debug)?,
        ),
    ] {
        intention.insert(key.into(), value);
    }
    trial.journal.write(&intention).map_err(debug)?;
    let control = propagation::control(&id);
    let watcher = {
        let control = control.clone();
        std::thread::spawn(move || {
            for _ in 0..6000 {
                if control.progress().examined >= propagation::BATCH * 2 {
                    control.stop();
                    return;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })
    };
    propagation::propagate(
        s,
        &propagation::Header {
            server: server.name.clone(),
            share: server.share.clone(),
            root: OURS.into(),
            replace: false,
            parts: propagation::Parts::default(),
        },
        &propagation::backup_path(&id, None),
        ELEMENTS,
        &control,
    )
    .map_err(debug)?;
    let _ = watcher.join();
    let cut = control.progress();
    propagation::forget(&id);
    check(
        cut.stopped && cut.written > 0 && cut.examined < ELEMENTS,
        &format!("cut on the way ({cut:?})"),
    )?;
    let start = Instant::now();
    let interrupted = writer::to_resume(&trial.journal)
        .into_iter()
        .find(|r| matches!(r.changeset.operations.first(), Some(Operation::PropagateInheritance { backup, .. }) if *backup == id))
        .ok_or("the cut propagation is not offered to resume")?;
    check(
        interrupted.doubtful.is_some() && interrupted.applied.is_empty(),
        "the cut propagation is doubtful",
    )?;
    let settled = writer::ascertain(&trial.connection, &interrupted).map_err(debug)?;
    check(
        settled.doubtful.is_none() && settled.applied.len() == 1,
        "settled from its backup: applied",
    )?;
    let completion = changes::completion(&interrupted, &settled).map_err(debug)?;
    let Some(Operation::PropagateInheritance { backup: again, .. }) = completion.operations.first()
    else {
        return Err("no propagation to complete".into());
    };
    check(
        completion.operations.len() == 1 && *again != id,
        "the completion propagates again, with a backup of its own",
    )?;
    println!(
        "  settled in {:.2} s, {} written before the cut",
        start.elapsed().as_secs_f64(),
        cut.written
    );
    made.backups.push(again.clone());
    let control = propagation::control(again);
    let start = Instant::now();
    let completed = trial
        .outcome(&completion, Some(interrupted.id.clone()), None)?
        .report;
    let progress = control.progress();
    propagation::forget(again);
    println!(
        "  completed: {}",
        rate(&progress, start.elapsed().as_secs_f64())
    );
    check(
        completed.issue == Issue::Applied && progress.finished && !progress.stopped,
        "the completion goes to the end",
    )?;
    check(
        progress.written > 0 && progress.written + cut.written >= 2900,
        "the completion writes what the cut left",
    )?;
    check(
        writer::to_resume(&trial.journal)
            .iter()
            .all(|r| r.id != interrupted.id),
        "no longer offered to resume",
    )?;
    let (_, stored) = read_one(s, OURS)?;
    set(s, TWIN, &stored)?;
    windows_propagates(server, &stored, false)?;
    compare_trees(s, "cut, then completed")?;
    trial.undo(&completed)?;
    trial.undo(&settled)?;
    set(
        s,
        OURS,
        &SecurityDescriptor::decode(&before).map_err(debug)?,
    )?;
    let (n, shown) = differences(&start_tree, &snapshot(s, OURS)?, false);
    for line in &shown {
        println!("    {line}");
    }
    check(
        n == 0,
        &format!("both undone: the tree is back ({n} differences)"),
    )?;
    Ok(())
}

// --- fs1 limited to SMB 2.1 ---------------------------------------------------------------------

const FS1_CONF: &str = "/etc/samba/smb.conf";
/// The configuration of fs1 while it is limited: put back after the trial, and before it if an
/// interrupted trial left it.
const FS1_SAVED: &str = "/etc/samba/smb.conf.annuaire-ntfs-smb2";

/// Dialect, encryption and signing of a session on the share `Commun` of fs1.
fn negotiated(server: &Server, protection: Protection) -> Result<(u16, bool, u16)> {
    let session = Session::open_share(&server.name, "Commun", protection, DELAY).map_err(debug)?;
    let n = session.negotiated();
    session.close();
    Ok((n.dialect, n.encrypted, n.signing))
}

/// Samba of fs1 restarted by `script`, until it answers with `protection` (3 min at most).
fn restart_fs1(server: &Server, script: &str, protection: Protection) -> Result<String> {
    let out = server.bash(script)?;
    let seconds = labo::wait(Duration::from_secs(180), "fs1 answers", || {
        Ok(negotiated(server, protection).is_ok())
    })?;
    println!("  fs1 answers after {seconds:.0} s");
    Ok(out)
}

/// fs1 limited to SMB 2.1: `smb.conf` saved (a copy left by an interrupted trial put back
/// first), the line added to `[global]`; its shares are in the registry, its globals in
/// `smb.conf`, which `testparm` confirms (a global of the registry would come over it).
fn limit_fs1(server: &Server) -> Result<()> {
    let out = restart_fs1(
        server,
        &format!(
            "set -e\n\
             if test -e {FS1_SAVED}; then cp -p {FS1_SAVED} {FS1_CONF}; fi\n\
             cp -p {FS1_CONF} {FS1_SAVED}\n\
             sed -i '/^\\[global\\]/a\\\tserver max protocol = SMB2_10' {FS1_CONF}\n\
             echo \"MAX=$(testparm -s --parameter-name='server max protocol' 2>/dev/null)\"\n\
             systemctl restart smbd\n"
        ),
        Protection::AllowSmb2,
    )?;
    // `testparm` says `SMB2` for `SMB2_10`.
    let max = labo::lines(&out).remove("MAX").unwrap_or_default();
    check(
        matches!(max.as_str(), "SMB2" | "SMB2_10"),
        &format!("fs1: server max protocol = SMB2_10 (testparm: {max})"),
    )?;
    check(
        negotiated(server, Protection::AllowSmb2)?
            == (dialect::SMB210, false, signing::HMAC_SHA256),
        "fs1: SMB 2.1, not encrypted, signed with HMAC-SHA256",
    )
}

/// The configuration of fs1 put back, Samba restarted, SMB 3.1.1 encrypted again.
fn restore_fs1(server: &Server) -> Result<()> {
    restart_fs1(
        server,
        &format!(
            "set -e\n\
             if test -e {FS1_SAVED}; then cp -p {FS1_SAVED} {FS1_CONF}; rm -f {FS1_SAVED}; fi\n\
             systemctl restart smbd\n"
        ),
        Protection::Encrypted,
    )?;
    let (dialect, encrypted, _) = negotiated(server, Protection::Encrypted)?;
    check(
        dialect == dialect::SMB311 && encrypted,
        "fs1 put back: SMB 3.1.1 encrypted",
    )
}

/// Without the option, fs1 limited to SMB 2.1 is refused: a session, and the writer (a
/// propagation through a profile without the option: nothing written).
fn refused_without_option(lab: &Lab, server: &Server) -> Result<()> {
    println!("9. without the option");
    let error =
        Session::open_share(&server.name, &server.share, Protection::Encrypted, DELAY).err();
    check(
        matches!(&error, Some(SysvolError::Session(e)) if e.kind == ErrorKind::Smb2Only),
        &format!("session refused without the option ({error:?})"),
    )?;
    let scratch = labo::Scratch::new("ntfs-sans-option")?;
    let trial = Trial::new(lab, &scratch)?;
    let id = propagation::new_id();
    let outcome = trial.outcome(
        &changeset(vec![Operation::propagate_inheritance(
            &server.name,
            &server.share,
            OURS,
            false,
            &id,
            ELEMENTS,
        )]),
        None,
        None,
    )?;
    let said = format!("{:?} {:?}", outcome.report.error, outcome.problems);
    println!("  writer: {:?} {said}", outcome.report.issue);
    let refused = outcome.report.issue != Issue::Applied && said.contains("Smb2Only");
    let unsaved = !propagation::backup_path(&id, None).exists();
    trial.connection.join();
    check(
        refused,
        "the propagation refused by the writer, for want of the option (Smb2Only)",
    )?;
    check(unsaved, "nothing written: no backup")
}

fn clean(trial: &Trial, server: &Server, made: &Made) -> Result<()> {
    let mut errors = Vec::new();
    if made.share {
        match Srvsvc::open(&server.name, &options()) {
            Ok(mut service) => {
                if let Err(e) = service.delete(&server.share) {
                    errors.push(format!("share: {e}"));
                }
                service.close();
            }
            Err(e) => errors.push(format!("srvsvc: {e}")),
        }
    }
    if made.folder {
        let removed = if server.windows {
            server.powershell(&format!(
                "if (Test-Path '{0}') {{ cmd /c rd /s /q '{0}' }}; 'OK'",
                server.path
            ))
        } else {
            server.bash(&format!("rm -rf {}\n", server.path))
        };
        if let Err(e) = removed {
            errors.push(format!("folder: {e}"));
        }
    }
    for id in &made.backups {
        let _ = std::fs::remove_file(propagation::backup_path(id, None));
    }
    if let Err(e) = trial.remove_tree(&format!("OU=Essais-J84-{},{}", run(), trial.base)) {
        errors.push(format!("OU: {e}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; ").into())
    }
}

#[test]
#[ignore = "lab"]
fn ntfs_propagation() -> Result<()> {
    let lab = labo::lab();
    if smb2() && !labo::samba_only(&lab) {
        return Ok(());
    }
    let server = Server::of(&lab);
    let scratch = labo::Scratch::new("ntfs")?;
    let mut profile = lab.profile(true);
    profile.smb2_signing = smb2();
    let trial = Trial::with_profile(&lab, &scratch, profile)?;
    let mut made = Made::default();
    let limited = if smb2() {
        println!("0. fs1 limited to SMB 2.1");
        limit_fs1(&server)
    } else {
        Ok(())
    };
    let done = limited
        .and_then(|()| cases(&trial, &lab, &server, &mut made))
        .and_then(|()| {
            if smb2() {
                refused_without_option(&lab, &server)
            } else {
                Ok(())
            }
        });
    if let Err(e) = &done {
        println!("FAILED: {e}");
    }
    // Put back as soon as possible: the limit hinders the other trials on fs1.
    let restored = if smb2() {
        println!("10. fs1 put back");
        restore_fs1(&server)
    } else {
        Ok(())
    };
    println!("11. cleaning");
    let cleaned = clean(&trial, &server, &made);
    trial.connection.join();
    done.and(restored).and(cleaned)
}

// --- Volume (J8.7) -------------------------------------------------------------------------------

/// `ANNUAIRE_LABO_VOLUME`: the elements of each tree of the trial of volume (100 000 when the
/// value is not a number of at least 10 000); absent, that trial is skipped.
fn volume() -> Option<usize> {
    let value = std::env::var("ANNUAIRE_LABO_VOLUME")
        .ok()
        .filter(|v| !v.is_empty() && v != "0")?;
    Some(
        value
            .parse()
            .ok()
            .filter(|n| *n >= 10_000)
            .unwrap_or(100_000),
    )
}

/// Files of the folder `grand`, whose listing takes several responses.
const LARGE: usize = 3000;

/// The shape of a tree of about `size` elements: 10 × 10 × 10 folders (1 110), the files of each
/// of the 1 000 last ones, and `grand`; its elements, root left out.
fn shape(size: usize) -> (usize, usize) {
    let per_leaf = size.saturating_sub(1110 + 1 + LARGE).div_ceil(1000).max(1);
    (per_leaf, 1110 + 1000 * per_leaf + 1 + LARGE)
}

/// The two trees of the trial of volume, made on the server itself.
fn make_volume(server: &Server, per_leaf: usize) -> Result<()> {
    if server.windows {
        server.powershell(&format!(
            "$d='{}'; if (Test-Path $d) {{ cmd /c rd /s /q $d }}\n\
foreach ($t in '{OURS}','{TWIN}') {{ $g=\"$d\\$t\\grand\"; [void][IO.Directory]::CreateDirectory($g); \
foreach ($f in 1..{LARGE}) {{ [IO.File]::Create(\"$g\\f$f.txt\").Dispose() }}; \
foreach ($i in 1..10) {{ foreach ($j in 1..10) {{ foreach ($k in 1..10) {{ $l=\"$d\\$t\\d$i\\s$j\\t$k\"; \
[void][IO.Directory]::CreateDirectory($l); foreach ($f in 1..{per_leaf}) {{ [IO.File]::Create(\"$l\\f$f.txt\").Dispose() }} }} }} }} }}\n\
'OK'",
            server.path
        ))?;
    } else {
        server.bash(&format!(
            "set -e\nd={}\nrm -rf \"$d\"\ninstall -d -m 0777 \"$d\"\n\
for t in {OURS} {TWIN}; do\n mkdir -p \"$d/$t/grand\"\n (cd \"$d/$t/grand\" && touch $(seq -f 'f%g.txt' 1 {LARGE}))\n\
 for i in $(seq 1 10); do for j in $(seq 1 10); do for k in $(seq 1 10); do\n\
  l=\"$d/$t/d$i/s$j/t$k\"; mkdir -p \"$l\"; (cd \"$l\" && touch $(seq -f 'f%g.txt' 1 {per_leaf}))\n\
 done; done; done\ndone\n\
chown -R 'LAB\\administrator':'LAB\\domain users' \"$d\"\nchmod -R a+rwX \"$d\"\necho OK\n",
            server.path
        ))?;
    }
    Ok(())
}

/// VmRSS and VmHWM of the process, in KiB.
fn memory() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let field = |name: &str| {
        status
            .lines()
            .find_map(|l| l.strip_prefix(name))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap_or(0)
    };
    (field("VmRSS:"), field("VmHWM:"))
}

/// The peak of the memory set back to what the process holds now (`clear_refs`, 5): the start
/// of a measure; its resident memory.
fn measure() -> u64 {
    let _ = std::fs::write("/proc/self/clear_refs", "5");
    memory().0
}

/// The peak of the memory since `measure`.
fn measured(what: &str, start: u64) {
    let (rss, hwm) = memory();
    let mib = |k: u64| k as f64 / 1024.0;
    println!(
        "  memory, {what}: {:.1} MiB before, peak {:.1} MiB (+{:.1} MiB), {:.1} MiB after",
        mib(start),
        mib(hwm),
        mib(hwm.saturating_sub(start)),
        mib(rss)
    );
}

/// Size of the backup of the last propagation, for `saved` elements.
fn backup_size(made: &Made, saved: usize) -> Result<()> {
    let id = made.backups.last().ok_or("backup")?;
    let bytes = std::fs::metadata(propagation::backup_path(id, None))?.len();
    println!(
        "  backup: {:.1} MiB for {saved} elements ({:.0} bytes each)",
        bytes as f64 / (1024.0 * 1024.0),
        bytes as f64 / saved.max(1) as f64
    );
    Ok(())
}

/// The paths of the tree under `root` (relative to the share), the root first.
fn all_paths(session: &mut Session, root: &str) -> Result<Vec<String>> {
    let tree = session
        .walk(&[root.to_owned()])
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("no tree")?;
    let mut paths = vec![root.to_owned()];
    paths.extend(tree.entries.iter().map(|e| sysvol::join(&[root, &e.path])));
    Ok(paths)
}

/// What the permissions of a descriptor are (its protection and ACEs), in a word.
fn fingerprint(d: &SecurityDescriptor) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ntfs::is_protected(d).hash(&mut h);
    for ace in &ntfs::dacl_of(d) {
        sddl::ace_to_sddl(ace, None)
            .unwrap_or_default()
            .hash(&mut h);
    }
    h.finish()
}

/// The fingerprint of each path, read by batches: a tree of 100 000 elements held in a few
/// MiB.
fn fingerprints(session: &mut Session, paths: &[String]) -> Result<Vec<u64>> {
    let mut out = Vec::with_capacity(paths.len());
    for chunk in paths.chunks(propagation::BATCH) {
        for (path, r) in chunk
            .iter()
            .zip(session.descriptors(chunk, INFO_OGD).map_err(debug)?)
        {
            let bytes = r.map_err(|s| format!("{path}: 0x{s:08X}"))?;
            out.push(fingerprint(
                &SecurityDescriptor::decode(&bytes).map_err(debug)?,
            ));
        }
    }
    Ok(out)
}

/// Every element of `calinda` compared with its twin, by batches; the root left out.
fn compare_with_twin(session: &mut Session, paths: &[String]) -> Result<usize> {
    let mut n = 0;
    let mut shown = 0;
    for chunk in paths
        .get(1..)
        .unwrap_or_default()
        .chunks(propagation::BATCH)
    {
        let twins: Vec<String> = chunk
            .iter()
            .map(|p| format!("{TWIN}{}", p.strip_prefix(OURS).unwrap_or(p)))
            .collect();
        let ours = session.descriptors(chunk, INFO_OGD).map_err(debug)?;
        let theirs = session.descriptors(&twins, INFO_OGD).map_err(debug)?;
        for ((path, a), b) in chunk.iter().zip(ours).zip(theirs) {
            let decode = |r: std::result::Result<Vec<u8>, u32>| {
                r.ok().and_then(|b| SecurityDescriptor::decode(&b).ok())
            };
            match (decode(a), decode(b)) {
                (Some(x), Some(y)) if ntfs::same_permissions(&x, &y) => {}
                (x, y) => {
                    n += 1;
                    if shown < 4 {
                        shown += 1;
                        let diff = match (&x, &y) {
                            (Some(x), Some(y)) => ace_diff(x, y),
                            _ => "unreadable".into(),
                        };
                        println!("    {path}: {diff}");
                    }
                }
            }
        }
    }
    Ok(n)
}

fn mismatches(a: &[u64], b: &[u64]) -> usize {
    a.iter().zip(b).filter(|(x, y)| x != y).count() + a.len().abs_diff(b.len())
}

fn volume_cases(trial: &Trial, server: &Server, per_leaf: usize, made: &mut Made) -> Result<()> {
    let elements = server.elements;
    println!("1. two trees of {elements} elements, share");
    let start = Instant::now();
    made.folder = true;
    make_volume(server, per_leaf)?;
    println!(
        "  {} elements made on the server in {:.1} s",
        2 * (elements + 1),
        start.elapsed().as_secs_f64()
    );
    add_share(server, made, "Essai J8.7, volume")?;
    let mut s = session(server)?;

    println!("2. counted before the propagation");
    let rss = measure();
    let start = Instant::now();
    let (folders, files) = propagation::count(&mut s, OURS).map_err(debug)?;
    let seconds = start.elapsed().as_secs_f64();
    measured("count", rss);
    println!(
        "  {folders} folders and {files} files counted in {seconds:.2} s ({:.0} elements/s)",
        (folders + files) as f64 / seconds.max(1e-3)
    );
    check(
        folders + files == elements,
        &format!("{elements} elements counted"),
    )?;

    println!("3. the tree as made, read");
    let start = Instant::now();
    let paths = all_paths(&mut s, OURS)?;
    let as_made = fingerprints(&mut s, &paths)?;
    println!(
        "  {} descriptors read in {:.1} s",
        paths.len(),
        start.elapsed().as_secs_f64()
    );
    check(paths.len() == elements + 1, "every element listed")?;

    println!("4. « replace » from the root");
    let (before, origin) = read_one(&mut s, OURS)?;
    let base = dacl(
        &origin,
        "(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)(A;OICI;GRGX;;;AU)(A;OI;FR;;;BU)",
        true,
    )?;
    let rss = measure();
    let (report_replace, progress, seconds, _) =
        change_and_propagate(trial, server, made, &before, &base, true, None)?;
    measured("propagation", rss);
    println!("  Calinda: {}", rate(&progress, seconds));
    check(
        progress.examined == elements && progress.refused == 0 && progress.finished,
        &format!("every element examined ({progress:?})"),
    )?;
    backup_size(made, progress.written)?;
    let replaced = fingerprints(&mut s, &paths)?;

    println!("5. a change of the root, stopped half way, then resumed");
    let (before, root) = read_one(&mut s, OURS)?;
    let mut explicit = ntfs::explicit_aces(&root);
    explicit.extend(ntfs::dacl_of(
        &sddl::sd_from_sddl(
            "D:(A;OICI;0x1301bf;;;BU)(A;CINP;FR;;;BG)(A;OICIIO;GR;;;CG)(A;OI;FR;;;NS)",
            None,
            false,
        )
        .map_err(debug)?,
    ));
    let changed = ntfs::composed(&root, &explicit, &[], true);
    let rss = measure();
    let (report_stopped, stopped, seconds, _) = change_and_propagate(
        trial,
        server,
        made,
        &before,
        &changed,
        false,
        Some(elements / 2),
    )?;
    measured("propagation stopped", rss);
    println!("  stopped: {}", rate(&stopped, seconds));
    check(
        stopped.stopped && stopped.examined < elements && stopped.written > 0,
        &format!("stopped half way ({stopped:?})"),
    )?;
    backup_size(made, stopped.written)?;
    let (before, _) = read_one(&mut s, OURS)?;
    let rss = measure();
    let (report_resumed, progress, seconds, _) =
        change_and_propagate(trial, server, made, &before, &changed, false, None)?;
    measured("resumption", rss);
    println!("  resumed: {}", rate(&progress, seconds));
    check(
        progress.finished && !progress.stopped && progress.refused == 0,
        "the resumption goes to the end",
    )?;
    check(
        progress.written + stopped.written == elements,
        "the resumption writes what the stop left, nothing else",
    )?;
    backup_size(made, progress.written)?;

    println!("6. Windows propagates the same root on the twin");
    let (_, stored) = read_one(&mut s, OURS)?;
    set(&mut s, TWIN, &stored)?;
    // Under the root, no explicit entry is left since step 4: « replace » gives what the
    // propagation of the change gives.
    let windows = windows_propagates(server, &stored, true)?;
    println!(
        "  Windows ({}): {windows:.1} s, {:.0} elements/s",
        if server.windows {
            "on the server"
        } else {
            "from the workstation"
        },
        elements as f64 / windows.max(1e-3)
    );
    let start = Instant::now();
    let n = compare_with_twin(&mut s, &paths)?;
    println!(
        "  {} elements compared in {:.1} s",
        elements,
        start.elapsed().as_secs_f64()
    );
    check(
        n == 0,
        &format!(
            "propagation of Calinda = propagation of Windows on every element ({n} differences)"
        ),
    )?;

    println!("7. undone (Ctrl+Z): the resumption, the stopped propagation, then « replace »");
    let rss = measure();
    let start = Instant::now();
    trial.undo(&report_resumed)?;
    let first = start.elapsed().as_secs_f64();
    let start = Instant::now();
    trial.undo(&report_stopped)?;
    let second = start.elapsed().as_secs_f64();
    measured("two undos", rss);
    println!(
        "  undone in {first:.1} s ({} elements) and {second:.1} s ({} elements)",
        progress.written, stopped.written
    );
    let n = mismatches(&replaced, &fingerprints(&mut s, &paths)?);
    check(
        n == 0,
        &format!("the tree is as after « replace » ({n} differences)"),
    )?;
    let rss = measure();
    let start = Instant::now();
    trial.undo(&report_replace)?;
    let third = start.elapsed().as_secs_f64();
    measured("undo of « replace »", rss);
    println!("  « replace » undone in {third:.1} s");
    let n = mismatches(&as_made, &fingerprints(&mut s, &paths)?);
    check(n == 0, &format!("the tree is as made ({n} differences)"))?;
    s.close();
    Ok(())
}

/// The propagation of a tree of 100 000 elements (`ANNUAIRE_LABO_VOLUME`): count, rate, memory
/// of the process, size of the backup, stop and resumption, undo, the result compared on every
/// element with Windows.
#[test]
#[ignore = "lab"]
fn ntfs_volume() -> Result<()> {
    let Some(size) = volume() else {
        println!("  ANNUAIRE_LABO_VOLUME not set: skipped");
        return Ok(());
    };
    let lab = labo::lab();
    let (per_leaf, elements) = shape(size);
    let server = Server::named(&lab, "J87-Volume", elements);
    let scratch = labo::Scratch::new("ntfs-volume")?;
    let trial = Trial::new(&lab, &scratch)?;
    let mut made = Made::default();
    let done = volume_cases(&trial, &server, per_leaf, &mut made);
    if let Err(e) = &done {
        println!("FAILED: {e}");
    }
    println!("8. cleaning");
    let cleaned = clean(&trial, &server, &made);
    trial.connection.join();
    done.and(cleaned)
}

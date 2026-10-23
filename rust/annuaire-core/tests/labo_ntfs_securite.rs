// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Owner and SACL of the files and folders of a share (J8.7, ADR 0023 § 5), against the lab
//! (ADR 0020): `fs1.lab.test` (Samba member, `acl_xattr`) or, with
//! `ANNUAIRE_LABO_DOMAINE=win.test`, `wdc1.win.test` (Windows Server 2025).
//!
//! 1. What the server lets an account do with the owner and the SACL over SMB, where the
//!    client sends no privilege: the administrator, an ordinary account, the same account
//!    granted a privilege for the trial (`net sam rights grant` on fs1, `LsaAddAccountRights`
//!    on wdc1, removed after), on elements whose DACL gives them nothing, with and without
//!    `FILE_OPEN_FOR_BACKUP_INTENT`. The matrix is printed and checked.
//! 2. Ownership (J8.7, lot 3): two twin trees of 59 elements, `calinda` and `jumeau`, with a
//!    protected folder and a file the administrator may not read; the root of `calinda` and
//!    everything under it given to an ordinary account by one changeset through the writer
//!    (the root, then the propagation of the owner), Windows doing the same on `jumeau`
//!    (`TreeSetNamedSecurityInfo`, on wdc1 itself, on fs1 from the workstation); owners and
//!    DACLs compared, the owner read back by the server's own tool (`samba-tool ntacl get`,
//!    `GetNamedSecurityInfo`); the refusals of an ordinary account and of one holding
//!    `SeTakeOwnershipPrivilege`, through the writer in a process of their own; Ctrl+Z.
//! 3. Auditing entries (J8.7, lot 4): a protected SACL set on `protege` by the server; the
//!    SACL of the root of `calinda` changed and propagated through the writer, Windows doing
//!    the same on `jumeau` (`SetNamedSecurityInfo`; on fs1, from the workstation, Samba
//!    refuses it, checked); DACLs and SACLs compared, read back by the server's tool; a DACL
//!    written alone, from a reading with and without the SACL; « replace all child object
//!    auditing entries » (`TreeResetNamedSecurityInfo`); the refusal of an ordinary account;
//!    four Ctrl+Z, the tree as before.
//!
//! A share of trial `J87S-<n>` on a folder made on the server; accounts in an OU of their own.
//! Everything made is removed at the end, even after a failure, the privileges granted too.
//!
//! ```text
//! KRB5CCNAME=FILE:… XDG_STATE_HOME=… cargo test -p annuaire-core --test labo_ntfs_securite -- --ignored --nocapture --test-threads 1
//! ```

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::{Sid, sddl};
use annuaire_core::actions;
use annuaire_core::changes::{self, Changeset, Operation};
use annuaire_core::propagation::{self, Parts};
use annuaire_core::smb::Options;
use annuaire_core::srvsvc::{self, Share, Srvsvc};
use annuaire_core::sysvol;
use annuaire_core::sysvol::{
    BACKUP_INTENT, INFO_OGD, INFO_OWNER, INFO_SACL, Protection, Session, SysvolError,
};
use serde_json::{Value as Json, json};

use labo::{Lab, Result, Trial, check, debug};

fn number() -> u32 {
    std::process::id() % 100_000
}

/// The share of this run (a child process is given the name of its parent).
fn share() -> &'static str {
    static NAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    NAME.get_or_init(|| {
        std::env::var("ANNUAIRE_LABO_PARTAGE").unwrap_or_else(|_| format!("J87S-{}", number()))
    })
}

const DELAY: Duration = Duration::from_secs(60);
const ADMINISTRATORS: &str = "S-1-5-32-544";

#[derive(Debug, Clone)]
struct Server {
    name: String,
    path: String,
    windows: bool,
}

impl Server {
    fn of(lab: &Lab) -> Self {
        if lab.windows() {
            Self {
                name: format!("wdc1.{}", lab.domain),
                path: format!("C:\\J87S-{}", number()),
                windows: true,
            }
        } else {
            Self {
                name: format!("fs1.{}", lab.domain),
                path: format!("/srv/j87s-{}", number()),
                windows: false,
            }
        }
    }

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

    /// PowerShell on wdc1 by ssh: the script copied by scp (it passes the length of a command
    /// line, and the standard input of OpenSSH for Windows loses what passes 4 KiB), run with
    /// `-File`, then removed (`ANNUAIRE_LABO_WDC1`, default `labadmin@wdc1.win.test`).
    fn powershell(&self, script: &str) -> Result<String> {
        let host =
            std::env::var("ANNUAIRE_LABO_WDC1").unwrap_or_else(|_| "labadmin@wdc1.win.test".into());
        let full = format!(
            "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ProgressPreference='SilentlyContinue'; \
$ErrorActionPreference='Stop'; {script}"
        );
        let name = format!("j87s-{}.ps1", number());
        let local = std::env::temp_dir().join(&name);
        // A BOM: Windows PowerShell reads a file without one in the code page of the system.
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend(full.as_bytes());
        std::fs::write(&local, bytes)?;
        let copied = Command::new("scp")
            .args(["-q", "-o", "BatchMode=yes"])
            .arg(&local)
            .arg(format!("{host}:{name}"))
            .status()?;
        let _ = std::fs::remove_file(&local);
        if !copied.success() {
            return Err("scp to wdc1".into());
        }
        let output = Command::new("ssh")
            .args(["-o", "BatchMode=yes", &host])
            .arg(format!(
                "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File {name} & del {name}"
            ))
            .output()?;
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let errors = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() || errors.contains("S=\"Error\"") || !errors.trim().is_empty() {
            return Err(format!("powershell: {text}\n{errors}").into());
        }
        Ok(text)
    }

    /// Folders `names` under the folder of the share, each with the descriptor `sddl` (owner,
    /// group, protected DACL), set on the server itself.
    fn make(&self, items: &[(String, String)]) -> Result<()> {
        if self.windows {
            let mut script = format!(
                "{LSA}$d='{}'; [void][IO.Directory]::CreateDirectory($d)\n",
                self.path
            );
            for (name, sddl) in items {
                script.push_str(&format!(
                    "[void][IO.Directory]::CreateDirectory(\"$d\\{name}\"); \
[J87S]::SetSddl(\"$d\\{name}\", '{sddl}')\n"
                ));
            }
            script.push_str("'OK'");
            self.powershell(&script)?;
        } else {
            let mut script = format!(
                "set -e\nd={}\ninstall -d -m 0777 \"$d\"\nchown 'LAB\\administrator':'LAB\\domain users' \"$d\"\n",
                self.path
            );
            for (name, sddl) in items {
                script.push_str(&format!(
                    "install -d -m 0777 \"$d/{name}\"\nsamba-tool ntacl set '{sddl}' \"$d/{name}\" --use-s3fs\n"
                ));
            }
            script.push_str("echo OK\n");
            self.bash(&script)?;
        }
        Ok(())
    }

    /// Grants (or removes) a privilege to an account of the domain on the server.
    fn privilege(&self, sam: &str, sid: &Sid, privilege: &str, grant: bool) -> Result<()> {
        if self.windows {
            self.powershell(&format!(
                "{LSA}[J87S]::Right('{sid}', '{privilege}', ${grant}); 'OK'"
            ))?;
        } else {
            let verb = if grant { "grant" } else { "revoke" };
            self.bash(&format!(
                "net sam rights {verb} 'LAB\\{sam}' {privilege} >/dev/null\necho OK\n"
            ))?;
        }
        Ok(())
    }

    fn remove(&self) -> Result<()> {
        if self.windows {
            self.powershell(&format!(
                "if (Test-Path '{0}') {{ Remove-Item -Recurse -Force '{0}' }}; 'OK'",
                self.path
            ))?;
        } else {
            self.bash(&format!("rm -rf '{}'\n", self.path))?;
        }
        Ok(())
    }
}

/// The C# of the trial on wdc1: a descriptor set from SDDL with the privileges of the
/// administrator (`SetFileSecurity`, owner included), a privilege granted to or removed from
/// an account (`LsaAddAccountRights`, `LsaRemoveAccountRights`).
const LSA: &str = r#"Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Security.Principal;
public static class J87S {
  [StructLayout(LayoutKind.Sequential)] struct LSA_UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  [StructLayout(LayoutKind.Sequential)] struct LSA_OBJECT_ATTRIBUTES { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
  [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref LSA_OBJECT_ATTRIBUTES attributes, uint access, out IntPtr handle);
  [DllImport("advapi32.dll")] static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, bool all, LSA_UNICODE_STRING[] rights, uint count);
  [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
  [DllImport("advapi32.dll")] static extern uint LsaNtStatusToWinError(uint status);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string sddl, uint revision, out IntPtr sd, out uint size);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool SetFileSecurityW(string name, uint info, IntPtr sd);
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool LookupPrivilegeValueW(string system, string name, out long luid);
  [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr token, bool disable, ref TOKEN_PRIVILEGES state, int length, IntPtr previous, IntPtr returned);
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [StructLayout(LayoutKind.Sequential, Pack=4)] struct TOKEN_PRIVILEGES { public int Count; public long Luid; public int Attributes; }
  static void Enable(string name) {
    IntPtr token; OpenProcessToken(GetCurrentProcess(), 0x28, out token);
    TOKEN_PRIVILEGES p = new TOKEN_PRIVILEGES(); p.Count = 1; p.Attributes = 2;
    LookupPrivilegeValueW(null, name, out p.Luid);
    AdjustTokenPrivileges(token, false, ref p, 0, IntPtr.Zero, IntPtr.Zero);
  }
  public static void SetSddl(string path, string sddl) {
    Enable("SeRestorePrivilege"); Enable("SeSecurityPrivilege"); Enable("SeTakeOwnershipPrivilege");
    IntPtr sd; uint size;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out sd, out size)) throw new Exception("sddl " + Marshal.GetLastWin32Error());
    uint info = 1u | 2u | 4u | (sddl.Contains("S:") ? 8u : 0u) | (sddl.Contains("D:P") ? 0x80000000u : 0u);
    // The owner first, alone (it opens an element whose DACL gives nothing), then the rest.
    SetFileSecurityW(path, 1u, sd);
    bool ok = SetFileSecurityW(path, info, sd); int error = Marshal.GetLastWin32Error(); LocalFree(sd);
    if (!ok) throw new Exception("SetFileSecurity " + path + " " + error);
  }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint GetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, out IntPtr sd);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(IntPtr sd, uint revision, uint info, out IntPtr text, out uint size);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint TreeSetNamedSecurityInfoW(string name, int type, uint info, byte[] owner, IntPtr group, IntPtr dacl, IntPtr sacl, uint action, IntPtr fn, int mode, IntPtr args);
  public static string GetSddl(string path, uint info) {
    Enable("SeSecurityPrivilege"); Enable("SeBackupPrivilege");
    IntPtr sd; uint r = GetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, out sd);
    if (r != 0) throw new Exception("GetNamedSecurityInfo " + path + " " + r);
    IntPtr text; uint size; ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1, info, out text, out size);
    string s = Marshal.PtrToStringUni(text); LocalFree(text); LocalFree(sd); return s;
  }
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint SetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)] static extern uint TreeResetNamedSecurityInfoW(string name, int type, uint info, IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl, bool keep, IntPtr fn, int mode, IntPtr args);
  public static uint SetSacl(string path, string b64, bool protect, bool reset) {
    Enable("SeSecurityPrivilege");
    byte[] sd = Convert.FromBase64String(b64);
    GCHandle pin = GCHandle.Alloc(sd, GCHandleType.Pinned);
    try {
      IntPtr start = pin.AddrOfPinnedObject();
      int offset = BitConverter.ToInt32(sd, 12);
      IntPtr sacl = offset == 0 ? IntPtr.Zero : new IntPtr(start.ToInt64() + offset);
      uint info = 8u | (protect ? 0x40000000u : 0x10000000u);
      return reset
        ? TreeResetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl, false, IntPtr.Zero, 1, IntPtr.Zero)
        : SetNamedSecurityInfoW(path, 1, info, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, sacl);
    } finally { pin.Free(); }
  }
  public static uint TreeOwner(string path, string sid) {
    Enable("SeRestorePrivilege"); Enable("SeTakeOwnershipPrivilege");
    SecurityIdentifier id = new SecurityIdentifier(sid); byte[] bytes = new byte[id.BinaryLength]; id.GetBinaryForm(bytes, 0);
    return TreeSetNamedSecurityInfoW(path, 1, 1u, bytes, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1u, IntPtr.Zero, 1, IntPtr.Zero);
  }
  public static void Right(string sid, string right, bool grant) {
    LSA_OBJECT_ATTRIBUTES a = new LSA_OBJECT_ATTRIBUTES(); IntPtr policy;
    uint s = LsaOpenPolicy(IntPtr.Zero, ref a, 0x00000811, out policy);
    if (s != 0) throw new Exception("LsaOpenPolicy " + LsaNtStatusToWinError(s));
    SecurityIdentifier id = new SecurityIdentifier(sid); byte[] bytes = new byte[id.BinaryLength]; id.GetBinaryForm(bytes, 0);
    LSA_UNICODE_STRING[] r = new LSA_UNICODE_STRING[1];
    r[0].Buffer = Marshal.StringToHGlobalUni(right); r[0].Length = (ushort)(right.Length * 2); r[0].MaximumLength = (ushort)(right.Length * 2 + 2);
    s = grant ? LsaAddAccountRights(policy, bytes, r, 1) : LsaRemoveAccountRights(policy, bytes, false, r, 1);
    Marshal.FreeHGlobal(r[0].Buffer); LsaClose(policy);
    if (s != 0 && grant) throw new Exception("LsaAddAccountRights " + LsaNtStatusToWinError(s));
  }
}
'@
"#;

/// The twin trees, made on the server: `d1`…`d3`, each with three files and three
/// subfolders of four files; `protege` (protected DACL) and its file; and in each tree
/// `d2\s2\f1.txt`, whose DACL gives the administrator nothing.
const OURS: &str = "calinda";
const TWIN: &str = "jumeau";
const LOCKED: &str = "d2\\s2\\f1.txt";
const ELEMENTS: usize = 3 + 3 * 3 + 3 * 3 + 3 * 3 * 4 + 2;

impl Server {
    fn make_trees(&self) -> Result<()> {
        if self.windows {
            self.powershell(&format!(
                "{LSA}$d='{}'\n\
foreach ($t in '{OURS}','{TWIN}') {{ foreach ($i in 1..3) {{ $a=\"$d\\$t\\d$i\"; \
[void][IO.Directory]::CreateDirectory($a); foreach ($k in 1..3) {{ [IO.File]::WriteAllText(\"$a\\f$k.txt\",'x') }}; \
foreach ($j in 1..3) {{ $b=\"$a\\s$j\"; [void][IO.Directory]::CreateDirectory($b); \
foreach ($k in 1..4) {{ [IO.File]::WriteAllText(\"$b\\f$k.txt\",'x') }} }} }}; \
[void][IO.Directory]::CreateDirectory(\"$d\\$t\\protege\"); [IO.File]::WriteAllText(\"$d\\$t\\protege\\secret.txt\",'x'); \
[J87S]::SetSddl(\"$d\\$t\\protege\", 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)'); \
[J87S]::SetSddl(\"$d\\$t\\{LOCKED}\", 'O:SYG:SYD:P(A;;FA;;;SY)') }}\n'OK'",
                self.path
            ))?;
        } else {
            self.bash(&format!(
                "set -e\nd={}\n\
for t in {OURS} {TWIN}; do\n for i in 1 2 3; do\n  a=\"$d/$t/d$i\"; mkdir -p \"$a\"\n\
  for k in 1 2 3; do echo x > \"$a/f$k.txt\"; done\n  for j in 1 2 3; do\n\
   b=\"$a/s$j\"; mkdir \"$b\"; for k in 1 2 3 4; do echo x > \"$b/f$k.txt\"; done\n  done\n done\n\
 mkdir \"$d/$t/protege\"; echo x > \"$d/$t/protege/secret.txt\"\ndone\n\
chown -R 'LAB\\administrator':'LAB\\domain users' \"$d/{OURS}\" \"$d/{TWIN}\"\nchmod -R a+rwX \"$d/{OURS}\" \"$d/{TWIN}\"\n\
for t in {OURS} {TWIN}; do\n\
 samba-tool ntacl set 'O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)' \"$d/$t/protege\" --use-s3fs\n\
 samba-tool ntacl set 'O:SYG:SYD:P(A;;FA;;;SY)' \"$d/$t/d2/s2/f1.txt\" --use-s3fs\ndone\necho OK\n",
                self.path
            ))?;
        }
        Ok(())
    }

    /// Windows replaces the owner of the twin and of everything under it, as « Replace owner
    /// on subcontainers and objects » does (`TreeSetNamedSecurityInfo`, `TREE_SEC_INFO_SET`):
    /// on wdc1 itself, on fs1 from the workstation joined to LAB.TEST.
    fn windows_owner(&self, owner: &Sid) -> Result<()> {
        let target = if self.windows {
            format!("{}\\{TWIN}", self.path)
        } else {
            format!("\\\\{}\\{}\\{TWIN}", self.name, share())
        };
        let script = format!("{LSA}'RESULT=' + [J87S]::TreeOwner('{target}', '{owner}')\n");
        let out = if self.windows {
            self.powershell(&script)?
        } else {
            labo::poste(&script, &["--domaine"])?
        };
        check(
            labo::lines(&out).get("RESULT").map(String::as_str) == Some("0"),
            &format!("Windows replaced the owner of the twin ({})", out.trim()),
        )
    }

    /// The descriptor of `path` (relative to the share) as the server tells it: `smbcacls
    /// --sddl` on Samba, `GetNamedSecurityInfo` on Windows; `info` as for `QUERY_INFO`.
    fn told(&self, path: &str, info: u32, domain: &Sid) -> Result<SecurityDescriptor> {
        let text = if self.windows {
            let out = self.powershell(&format!(
                "{LSA}'SDDL=' + [J87S]::GetSddl('{}\\{path}', {info})",
                self.path
            ))?;
            labo::lines(&out).remove("SDDL").ok_or("no SDDL")?
        } else {
            // As root, from the extended attribute: elements the administrator may not
            // read over SMB included.
            let out = self.bash(&format!(
                "samba-tool ntacl get --as-sddl --use-s3fs '{}/{}'\n",
                self.path,
                path.replace('\\', "/")
            ))?;
            out.lines()
                .find(|l| l.contains("O:") || l.contains("D:") || l.contains("S:"))
                .map(|l| l.trim().to_owned())
                .ok_or_else(|| format!("samba-tool: {out}"))?
        };
        sddl::sd_from_sddl(&text, Some(domain), false).map_err(|e| format!("{text}: {e:?}").into())
    }
}

/// Every descriptor under `root` (paths relative to it, the root as « »), with `info`; those
/// the account may not read left out.
fn snapshot(
    session: &mut Session,
    root: &str,
    info: u32,
) -> Result<BTreeMap<String, SecurityDescriptor>> {
    let tree = session
        .walk(&[root.to_owned()])
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("no tree")?;
    let mut paths = vec![root.to_owned()];
    paths.extend(tree.entries.iter().map(|e| sysvol::join(&[root, &e.path])));
    let read = session.descriptors(&paths, info).map_err(debug)?;
    let mut out = BTreeMap::new();
    for (path, r) in paths.iter().zip(read) {
        let Ok(bytes) = r else { continue };
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .trim_start_matches('\\')
            .to_lowercase();
        out.insert(relative, SecurityDescriptor::decode(&bytes).map_err(debug)?);
    }
    Ok(out)
}

/// The paths where `same` does not hold between `a` and `b`, and a few of them shown.
fn differences(
    a: &BTreeMap<String, SecurityDescriptor>,
    b: &BTreeMap<String, SecurityDescriptor>,
    same: impl Fn(&SecurityDescriptor, &SecurityDescriptor) -> bool,
) -> (usize, Vec<String>) {
    let mut n = b.keys().filter(|k| !a.contains_key(*k)).count();
    let mut shown = Vec::new();
    for (path, x) in a {
        if !b.get(path).is_some_and(|y| same(x, y)) {
            n += 1;
            if shown.len() < 4 {
                shown.push(format!(
                    "{path}: {} | {}",
                    text(x),
                    b.get(path).map_or("(absent)".into(), text)
                ));
            }
        }
    }
    (n, shown)
}

fn options() -> Options {
    Protection::Encrypted.options(DELAY)
}

fn text(d: &SecurityDescriptor) -> String {
    sddl::sd_to_sddl(d, None).unwrap_or_default()
}

fn status_of(e: &SysvolError) -> String {
    e.ntstatus()
        .map_or_else(|| format!("{e}"), |s| format!("0x{s:08X}"))
}

// --- What an account may do over SMB ------------------------------------------------------------

/// One try: on `path`, `what` (`owner` with the SID `value`, `sacl-read`, `sacl` with the SACL
/// `value`), with `FILE_OPEN_FOR_BACKUP_INTENT` or not. « ok », or the NTSTATUS of the refusal.
fn attempt(session: &mut Session, path: &str, what: &str, value: &str, backup: bool) -> String {
    let options = if backup { BACKUP_INTENT } else { 0 };
    let written = |session: &mut Session, sddl_text: &str, info: u32| -> String {
        let parsed = sddl::sd_from_sddl(sddl_text, None, false).map_err(|e| format!("{e:?}"));
        let d = match parsed.and_then(|d| d.encode().map_err(|e| format!("{e:?}"))) {
            Ok(d) => d,
            Err(e) => return e,
        };
        match session.set_descriptor_with(path, &d, info, options) {
            Ok(()) => "ok".into(),
            Err(e) => status_of(&e),
        }
    };
    match what {
        "owner" => written(session, &format!("O:{value}"), INFO_OWNER),
        "sacl" => written(session, value, INFO_SACL),
        "read" => match session.descriptors(&[path.to_owned()], INFO_OGD) {
            Ok(mut r) => match r.pop() {
                Some(Ok(_)) => "ok".into(),
                Some(Err(s)) => format!("0x{s:08X}"),
                None => "none".into(),
            },
            Err(e) => status_of(&e),
        },
        "sacl-read" => match session.descriptors(&[path.to_owned()], INFO_SACL) {
            Ok(mut r) => match r.pop() {
                Some(Ok(_)) => "ok".into(),
                Some(Err(s)) => format!("0x{s:08X}"),
                None => "none".into(),
            },
            Err(e) => status_of(&e),
        },
        other => format!("unknown {other}"),
    }
}

/// The tries of `tasks` (`[path, what, value, backup]`) in a session of the account of the
/// ticket of `KRB5CCNAME`; their results in the same order.
fn attempts(server: &str, tasks: &[Json]) -> Result<Vec<String>> {
    let mut session =
        Session::open_share(server, share(), Protection::Encrypted, DELAY).map_err(debug)?;
    let mut out = Vec::new();
    for t in tasks {
        out.push(attempt(
            &mut session,
            t[0].as_str().unwrap_or_default(),
            t[1].as_str().unwrap_or_default(),
            t[2].as_str().unwrap_or_default(),
            t[3].as_bool().unwrap_or(false),
        ));
    }
    session.close();
    Ok(out)
}

/// Run as another account (`labo::child`): the tries asked on its standard input.
#[test]
#[ignore = "lab"]
fn security_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let asked: Json = serde_json::from_str(&input)?;
    let tasks = asked["tasks"].as_array().ok_or("tasks")?;
    let results = attempts(asked["server"].as_str().ok_or("server")?, tasks)?;
    println!("RESULT {}", json!(results));
    Ok(())
}

/// Run as another account (`labo::child`): the changeset asked on its standard input, through
/// the writer; the message of its error, if any.
#[test]
#[ignore = "lab"]
fn writer_child() -> Result<()> {
    let Some(input) = labo::child_input() else {
        return Ok(());
    };
    let asked: Json = serde_json::from_str(&input)?;
    let operations = asked["operations"]
        .as_array()
        .ok_or("operations")?
        .iter()
        .map(changes::operation_from_json)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(debug)?;
    let lab = labo::lab();
    let scratch = labo::Scratch::new("ntfs-securite-enfant")?;
    let trial = Trial::new(&lab, &scratch)?;
    let outcome = trial.outcome(
        &Changeset {
            operations,
            remarks: Vec::new(),
        },
        None,
        None,
    )?;
    let error = outcome
        .report
        .error
        .as_ref()
        .map(|e| e.message.clone())
        .unwrap_or_default();
    println!("RESULT {}", json!(error));
    trial.connection.join();
    Ok(())
}

/// The changeset applied as the account of `cache`: the message of its error ("" if applied).
fn written_as(kdc: &labo::Kdc, cache: &str, operations: &[Operation]) -> Result<String> {
    let operations = operations
        .iter()
        .map(changes::operation_to_json)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(debug)?;
    let input = json!({ "operations": operations }).to_string();
    let mut env = kdc.env(cache);
    env.push(("ANNUAIRE_LABO_PARTAGE".into(), share().into()));
    let result = labo::child("writer_child", &env, &input)?;
    Ok(serde_json::from_str(&result)?)
}

fn as_account(
    kdc: &labo::Kdc,
    cache: &str,
    server: &Server,
    tasks: &[Json],
) -> Result<Vec<String>> {
    let input = json!({ "server": server.name, "tasks": tasks }).to_string();
    let mut env = kdc.env(cache);
    env.push(("ANNUAIRE_LABO_PARTAGE".into(), share().into()));
    let result = labo::child("security_child", &env, &input)?;
    Ok(serde_json::from_str(&result)?)
}

// --- Accounts ------------------------------------------------------------------------------------

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

// --- The trial -----------------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Made {
    share: bool,
    folder: bool,
    ou: Option<String>,
    /// Privileges granted: (sAMAccountName, SID, privilege).
    privileges: Vec<(String, Sid, String)>,
    backups: Vec<String>,
}

struct Accounts {
    plain: (String, Sid),
    granted: (String, Sid),
    kdc: labo::Kdc,
}

fn accounts(trial: &Trial, lab: &Lab, made: &mut Made) -> Result<Accounts> {
    let n = number();
    let ou = trial.fresh_ou(&trial.base, &format!("Essais-J87S-{n}"))?;
    made.ou = Some(ou.clone());
    let (plain, granted) = (format!("j87p.{n}"), format!("j87q.{n}"));
    let (plain_secret, granted_secret) = (labo::password(24), labo::password(24));
    let plain_dn = user(trial, lab, &ou, &plain, &plain_secret)?;
    let granted_dn = user(trial, lab, &ou, &granted, &granted_secret)?;
    let kdc = labo::Kdc::new(lab, &lab.pdc_name())?;
    ticket(
        &kdc,
        &format!("{plain}@{}", lab.realm()),
        &plain_secret,
        "cc-p",
    )?;
    ticket(
        &kdc,
        &format!("{granted}@{}", lab.realm()),
        &granted_secret,
        "cc-q",
    )?;
    Ok(Accounts {
        plain: (plain, trial.sid(&plain_dn)?),
        granted: (granted, trial.sid(&granted_dn)?),
        kdc,
    })
}

fn make_share(server: &Server, made: &mut Made) -> Result<()> {
    let mut service = Srvsvc::open(&server.name, &options()).map_err(debug)?;
    let added = service.add(&Share {
        name: share().into(),
        kind: srvsvc::stype::DISKTREE,
        remark: "Essai J8.7".into(),
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

/// The matrix of what each account may do on elements whose DACL gives it nothing (owner
/// SYSTEM, `(A;OICI;FA;;;SY)` only), with and without backup intent.
fn privileges(
    server: &Server,
    accounts: &Accounts,
    made: &mut Made,
) -> Result<BTreeMap<String, String>> {
    let closed = "O:SYG:SYD:P(A;OICI;FA;;;SY)";
    let open = "O:SYG:SYD:P(A;OICI;FA;;;WD)";
    let (plain_sid, granted_sid) = (accounts.plain.1.to_string(), accounts.granted.1.to_string());
    // (label, who, privilege granted, self SID, another SID)
    let rounds: [(&str, &str, &[&str], String, String); 6] = [
        (
            "admin",
            "admin",
            &[],
            ADMINISTRATORS.into(),
            plain_sid.clone(),
        ),
        (
            "ordinaire",
            "p",
            &[],
            plain_sid.clone(),
            granted_sid.clone(),
        ),
        (
            "SeTakeOwnership",
            "q",
            &["SeTakeOwnershipPrivilege"],
            granted_sid.clone(),
            plain_sid.clone(),
        ),
        (
            "SeRestore",
            "q",
            &["SeRestorePrivilege"],
            granted_sid.clone(),
            plain_sid.clone(),
        ),
        (
            "SeTakeOwnership+SeRestore",
            "q",
            &["SeTakeOwnershipPrivilege", "SeRestorePrivilege"],
            granted_sid.clone(),
            plain_sid.clone(),
        ),
        (
            "SeSecurity",
            "q",
            &["SeSecurityPrivilege"],
            granted_sid.clone(),
            plain_sid.clone(),
        ),
    ];
    let mut items = vec![("ouvert".to_owned(), open.to_owned())];
    for (label, ..) in &rounds {
        for target in ["soi", "BA", "autre"] {
            for backup in ["", "-b"] {
                items.push((format!("{label}-{target}{backup}"), closed.to_owned()));
            }
        }
    }
    made.folder = true;
    server.make(&items)?;
    let sacl = "S:(AU;OICISAFA;FA;;;WD)";
    let mut matrix = BTreeMap::new();
    for (label, who, privilege, own, other) in &rounds {
        let mut tasks = Vec::new();
        for (target, sid) in [
            ("soi", own.as_str()),
            ("BA", ADMINISTRATORS),
            ("autre", other.as_str()),
        ] {
            for backup in [false, true] {
                let path = format!("{label}-{target}{}", if backup { "-b" } else { "" });
                tasks.push(json!([path, "owner", sid, backup]));
            }
        }
        tasks.push(json!(["", "sacl-read", "", false]));
        tasks.push(json!(["ouvert", "read", "", false]));
        for backup in [false, true] {
            tasks.push(json!(["ouvert", "sacl-read", "", backup]));
            tasks.push(json!(["ouvert", "sacl", sacl, backup]));
        }
        for p in privilege.iter() {
            server.privilege(&accounts.granted.0, &accounts.granted.1, p, true)?;
            made.privileges.push((
                accounts.granted.0.clone(),
                accounts.granted.1,
                (*p).to_owned(),
            ));
        }
        let results = match *who {
            "admin" => attempts(&server.name, &tasks)?,
            "p" => as_account(&accounts.kdc, "cc-p", server, &tasks)?,
            _ => as_account(&accounts.kdc, "cc-q", server, &tasks)?,
        };
        for p in privilege.iter() {
            server.privilege(&accounts.granted.0, &accounts.granted.1, p, false)?;
            made.privileges.retain(|(_, _, q)| q != p);
        }
        for (task, result) in tasks.iter().zip(results) {
            let key = format!(
                "{label} {} {}{}",
                task[1].as_str().unwrap_or_default(),
                task[0].as_str().unwrap_or_default(),
                if task[3] == true { " +backup" } else { "" }
            );
            println!("  {key}: {result}");
            matrix.insert(key, result);
        }
    }
    Ok(matrix)
}

fn cases(trial: &Trial, lab: &Lab, server: &Server, made: &mut Made) -> Result<()> {
    println!("1. share, accounts");
    let accounts = accounts(trial, lab, made)?;
    // The folder of the share first (Windows wants it to exist).
    server.make(&[])?;
    made.folder = true;
    make_share(server, made)?;
    println!("2. what each account may do with the owner and the SACL");
    let matrix = privileges(server, &accounts, made)?;
    check_matrix(server, &matrix)?;
    let domain = accounts.plain.1.domain().map_err(debug)?;
    println!("3. ownership taken through the writer, below too, as Windows does it");
    owner(trial, server, &accounts, made, &domain)?;
    println!("6. auditing entries (SACL) propagated as Windows does it");
    audit(trial, server, &accounts, made, &domain)?;
    accounts.kdc.destroy("cc-p");
    accounts.kdc.destroy("cc-q");
    Ok(())
}

/// What the lab measured (ADR 0023 § 5), checked at each run: on both servers, the
/// administrator writes any owner and the SACL; an ordinary account may write neither
/// (`STATUS_ACCESS_DENIED`, `STATUS_PRIVILEGE_NOT_HELD`); `SeTakeOwnershipPrivilege` lets an
/// account take ownership, not give it (`STATUS_INVALID_OWNER`); `SeSecurityPrivilege` opens
/// the SACL. `FILE_OPEN_FOR_BACKUP_INTENT` changes nothing on Samba; on Windows it lets
/// `SeRestorePrivilege` open the element and give it any owner.
fn check_matrix(server: &Server, m: &BTreeMap<String, String>) -> Result<()> {
    let is = |key: &str, want: &str| m.get(key).is_some_and(|v| v == want);
    let all = |prefix: &str, want: &str| {
        m.iter()
            .filter(|(k, _)| k.starts_with(prefix))
            .all(|(_, v)| v == want)
    };
    check(
        all("admin ", "ok"),
        "the administrator writes any owner, reads and writes the SACL",
    )?;
    check(
        all("ordinaire owner", "0xC0000022") && all("ordinaire sacl", "0xC0000061"),
        "an ordinary account: owner refused (access denied), SACL refused (privilege not held)",
    )?;
    check(
        is("ordinaire read ouvert", "ok"),
        "an ordinary account reads owner, group and DACL: the SACL is asked only where it serves",
    )?;
    check(
        is("SeTakeOwnership owner SeTakeOwnership-soi", "ok")
            && is("SeTakeOwnership owner SeTakeOwnership-autre", "0xC000005A"),
        "SeTakeOwnershipPrivilege: takes ownership, does not give it (invalid owner)",
    )?;
    check(
        all("SeTakeOwnership+SeRestore owner", "ok"),
        "SeTakeOwnershipPrivilege and SeRestorePrivilege: any owner",
    )?;
    check(
        all("SeSecurity sacl", "ok") && all("SeSecurity owner", "0xC0000022"),
        "SeSecurityPrivilege: the SACL, not the owner",
    )?;
    // BUILTIN\Administrators as owner for an account that is not a member: Windows refuses,
    // Samba (which maps it to a group) lets it.
    let ba = if server.windows { "0xC000005A" } else { "ok" };
    check(
        is("SeTakeOwnership owner SeTakeOwnership-BA", ba),
        &format!("SeTakeOwnershipPrivilege, Administrators as owner: {ba}"),
    )?;
    if server.windows {
        check(
            is("SeRestore owner SeRestore-autre", "0xC0000022")
                && is("SeRestore owner SeRestore-autre-b +backup", "ok"),
            "Windows: SeRestorePrivilege opens the element with backup intent only",
        )?;
    } else {
        check(
            all("SeRestore owner", "0xC0000022"),
            "Samba: SeRestorePrivilege alone does not open the element, backup intent or not",
        )?;
    }
    Ok(())
}

fn owners(a: &SecurityDescriptor, b: &SecurityDescriptor) -> bool {
    a.owner == b.owner
}

/// The root of `calinda` and everything under it given to the ordinary account, by one
/// changeset (the root, then the propagation of the owner alone); Windows does the same on
/// `jumeau`; compared, read back by the server's tool, then undone.
fn owner(
    trial: &Trial,
    server: &Server,
    accounts: &Accounts,
    made: &mut Made,
    domain: &Sid,
) -> Result<()> {
    server.make_trees()?;
    let mut s =
        Session::open_share(&server.name, share(), Protection::Encrypted, DELAY).map_err(debug)?;
    let before = snapshot(&mut s, OURS, INFO_OGD)?;
    check(
        before.len() == ELEMENTS && !before.contains_key(LOCKED),
        &format!(
            "{} elements read in the tree, the locked file not",
            before.len()
        ),
    )?;
    let new_owner = accounts.plain.1;
    let root = s
        .descriptors(&[OURS.to_owned()], INFO_OGD)
        .map_err(debug)?
        .remove(0)
        .map_err(|st| format!("root: 0x{st:08X}"))?;
    let mut changed = SecurityDescriptor::decode(&root).map_err(debug)?;
    changed.owner = Some(new_owner);
    let id = propagation::new_id();
    made.backups.push(id.clone());
    let control = propagation::control(&id);
    let operations = vec![
        Operation::set_file_descriptor(
            &server.name,
            share(),
            OURS,
            root.clone(),
            changed.encode().map_err(debug)?,
        ),
        Operation::propagate_parts(
            &server.name,
            share(),
            OURS,
            false,
            Parts {
                dacl: false,
                sacl: None,
                owner: Some(new_owner),
            },
            &id,
            ELEMENTS,
        ),
    ];
    let start = std::time::Instant::now();
    let report = trial.apply(&Changeset {
        operations,
        remarks: Vec::new(),
    })?;
    let seconds = start.elapsed().as_secs_f64();
    let progress = control.progress();
    propagation::forget(&id);
    println!(
        "  Calinda: {} examined, {} written, {} refused in {seconds:.2} s",
        progress.examined, progress.written, progress.refused
    );
    check(
        progress.written == ELEMENTS && progress.refused == 0,
        "every descendant written, under the protected folder and the unreadable file too",
    )?;
    let (_, saved) =
        propagation::read_backup(&propagation::backup_path(&id, None)).map_err(debug)?;
    check(
        saved
            .iter()
            .any(|e| e.path.to_lowercase().ends_with(LOCKED) && e.before.is_empty()),
        "the unreadable file is saved without its « before »",
    )?;
    server.windows_owner(&new_owner)?;
    let ours = snapshot(&mut s, OURS, INFO_OGD)?;
    let twin = snapshot(&mut s, TWIN, INFO_OGD)?;
    let (n, shown) = differences(&ours, &twin, |a, b| {
        a.owner == b.owner && annuaire_core::ntfs::same_permissions(a, b)
    });
    for line in &shown {
        println!("    {line}");
    }
    check(
        n == 0,
        &format!("owner and DACL of Calinda = those of Windows ({n} differences)"),
    )?;
    check(
        ours.values().all(|d| d.owner == Some(new_owner)),
        "every element has the new owner",
    )?;
    let (n, _) = differences(&before, &ours, annuaire_core::ntfs::same_permissions);
    check(n == 0, "the DACLs did not change")?;
    for path in [OURS.to_owned(), format!("{OURS}\\{LOCKED}")] {
        let told = server.told(&path, INFO_OGD, domain)?;
        println!("  {path}: {}", text(&told));
        check(
            told.owner == Some(new_owner),
            &format!("{path}: the owner read back by the server's tool"),
        )?;
    }
    println!("4. refusals, as an ordinary account and with SeTakeOwnershipPrivilege");
    let target = format!("{OURS}\\d1");
    let present = s
        .descriptors(std::slice::from_ref(&target), INFO_OGD)
        .map_err(debug)?
        .remove(0)
        .map_err(|st| format!("d1: 0x{st:08X}"))?;
    let given = |owner: Sid| -> Result<Operation> {
        let mut d = SecurityDescriptor::decode(&present).map_err(debug)?;
        d.owner = Some(owner);
        Ok(Operation::set_file_descriptor(
            &server.name,
            share(),
            &target,
            present.clone(),
            d.encode().map_err(debug)?,
        ))
    };
    // The plain account owns d1 now: it gets WRITE_DAC and READ_CONTROL, not WRITE_OWNER.
    let refused = written_as(&accounts.kdc, "cc-q", &[given(accounts.granted.1)?])?;
    println!("  ordinary account: {refused}");
    check(
        refused.contains("OwnerRefused") && refused.contains("3221225506"),
        "an ordinary account is refused ownership, the refusal said as such",
    )?;
    server.privilege(
        &accounts.granted.0,
        &accounts.granted.1,
        "SeTakeOwnershipPrivilege",
        true,
    )?;
    made.privileges.push((
        accounts.granted.0.clone(),
        accounts.granted.1,
        "SeTakeOwnershipPrivilege".into(),
    ));
    let other = written_as(&accounts.kdc, "cc-q", &[given(administrator(domain)?)?])?;
    let own = written_as(&accounts.kdc, "cc-q", &[given(accounts.granted.1)?])?;
    server.privilege(
        &accounts.granted.0,
        &accounts.granted.1,
        "SeTakeOwnershipPrivilege",
        false,
    )?;
    made.privileges.clear();
    println!("  SeTakeOwnershipPrivilege, to another: {other}; to itself: {own:?}");
    check(
        other.contains("OwnerRefused") && other.contains("3221225562"),
        "giving ownership without SeRestorePrivilege: invalid owner, said as such",
    )?;
    check(
        own.is_empty(),
        "taking ownership with SeTakeOwnershipPrivilege",
    )?;
    println!("5. undone (Ctrl+Z)");
    // d1 back to the plain account, then the changeset of step 3 undone.
    let back = s
        .descriptors(std::slice::from_ref(&target), INFO_OGD)
        .map_err(debug)?
        .remove(0)
        .map_err(|st| format!("d1: 0x{st:08X}"))?;
    let mut d = SecurityDescriptor::decode(&back).map_err(debug)?;
    d.owner = Some(new_owner);
    trial.apply(&Changeset {
        operations: vec![Operation::set_file_descriptor(
            &server.name,
            share(),
            &target,
            back,
            d.encode().map_err(debug)?,
        )],
        remarks: Vec::new(),
    })?;
    let start = std::time::Instant::now();
    let control = propagation::control(&id);
    trial.undo(&report)?;
    println!("  undone in {:.2} s", start.elapsed().as_secs_f64());
    let refusals = control.refusals();
    propagation::forget(&id);
    check(
        refusals.len() == 1
            && refusals[0].path.to_lowercase().ends_with(LOCKED)
            && refusals[0].reason == propagation::Reason::NotSaved,
        &format!("only the unreadable file is left, reported ({refusals:?})"),
    )?;
    let after = snapshot(&mut s, OURS, INFO_OGD)?;
    let (n, shown) = differences(&before, &after, |a, b| {
        owners(a, b) && annuaire_core::ntfs::same_permissions(a, b)
    });
    for line in &shown {
        println!("    {line}");
    }
    check(n == 0, &format!("the tree is as before ({n} differences)"))?;
    s.close();
    Ok(())
}

/// Windows sets the SACL of `descriptor` on the root of the twin and propagates it
/// (`SetNamedSecurityInfo`), or replaces the SACL of every descendant
/// (`TreeResetNamedSecurityInfo`, « Replace all child object auditing entries »).
fn windows_audit(server: &Server, descriptor: &SecurityDescriptor, reset: bool) -> Result<()> {
    let bytes = descriptor.encode().map_err(debug)?;
    let protect = annuaire_core::ntfs::is_sacl_protected(descriptor);
    let target = if server.windows {
        format!("{}\\{TWIN}", server.path)
    } else {
        format!("\\\\{}\\{}\\{TWIN}", server.name, share())
    };
    let script = format!(
        "{LSA}'RESULT=' + [J87S]::SetSacl('{target}', '{}', ${protect}, ${reset})\n",
        annuaire_core::changes::base64_encode(&bytes)
    );
    let out = if server.windows {
        server.powershell(&script)?
    } else {
        labo::poste(&script, &["--domaine"])?
    };
    // From a Windows workstation, Samba refuses it: the client opens the element with
    // ACCESS_SYSTEM_SECURITY alone, which Samba refuses to an SMB 2 open (as smbtorture says
    // Windows does), and setting a SACL there asks WRITE_DAC too (ADR 0023 § 5).
    let want = if server.windows { "0" } else { "5" };
    check(
        labo::lines(&out).get("RESULT").map(String::as_str) == Some(want),
        &format!("Windows set the SACL of the twin: {want} ({})", out.trim()),
    )
}

/// The bits of the control that go with the SACL.
const SACL_CONTROL: u16 = annuaire_codecs::sd::SE_SACL_PRESENT
    | annuaire_codecs::sd::SE_SACL_PROTECTED
    | annuaire_codecs::sd::SE_SACL_AUTO_INHERITED;

fn same_both(a: &SecurityDescriptor, b: &SecurityDescriptor) -> bool {
    annuaire_core::ntfs::same_permissions(a, b) && annuaire_core::ntfs::same_audit(a, b)
}

/// Both trees compared on their DACL and SACL, the elements the administrator may not read
/// left out.
fn compare_audit(s: &mut Session, what: &str) -> Result<BTreeMap<String, SecurityDescriptor>> {
    let mut ours = snapshot(s, OURS, INFO_OGD | INFO_SACL)?;
    let mut twin = snapshot(s, TWIN, INFO_OGD | INFO_SACL)?;
    // The locked file: Calinda writes the SACL with the DACL (Samba keeps its control bits
    // only so), which asks WRITE_DAC; Windows, locally, writes it with ACCESS_SYSTEM_SECURITY
    // alone. Refused to Calinda, it is left out.
    let locked = (ours.remove(LOCKED), twin.remove(LOCKED));
    let (n, shown) = differences(&ours, &twin, same_both);
    if let (Some(d), _) = locked {
        ours.insert(LOCKED.to_owned(), d);
    }
    for line in &shown {
        println!("    {line}");
    }
    check(
        n == 0 && ours.len() == ELEMENTS + 1,
        &format!(
            "{what}: SACLs of Calinda = SACLs of Windows on {} elements ({n} differences)",
            ours.len()
        ),
    )?;
    Ok(ours)
}

/// One changeset of the writer on the root of `calinda`: its descriptor if it changes, then
/// the propagation of `parts`; the report and the progress.
fn audit_changeset(
    trial: &Trial,
    server: &Server,
    made: &mut Made,
    before: &[u8],
    after: Option<&SecurityDescriptor>,
    parts: Parts,
) -> Result<(changes::Report, propagation::Progress, f64)> {
    let id = propagation::new_id();
    made.backups.push(id.clone());
    let control = propagation::control(&id);
    let mut operations = Vec::new();
    if let Some(after) = after {
        operations.push(Operation::set_file_descriptor(
            &server.name,
            share(),
            OURS,
            before.to_vec(),
            after.encode().map_err(debug)?,
        ));
    }
    operations.push(Operation::propagate_parts(
        &server.name,
        share(),
        OURS,
        false,
        parts,
        &id,
        ELEMENTS,
    ));
    let start = std::time::Instant::now();
    let report = trial.apply(&Changeset {
        operations,
        remarks: Vec::new(),
    })?;
    let seconds = start.elapsed().as_secs_f64();
    let progress = control.progress();
    for r in control.refusals().iter().take(3) {
        println!("    refused {r:?}");
    }
    propagation::forget(&id);
    Ok((report, progress, seconds))
}

/// The root of `calinda`; read with its SACL, marked so, as the « Security » tab does.
fn read_root(s: &mut Session, info: u32) -> Result<(Vec<u8>, SecurityDescriptor)> {
    let bytes = s
        .descriptors(&[OURS.to_owned()], info)
        .map_err(debug)?
        .remove(0)
        .map_err(|st| format!("root: 0x{st:08X}"))?;
    let mut d = SecurityDescriptor::decode(&bytes).map_err(debug)?;
    if info & INFO_SACL == 0 {
        return Ok((bytes, d));
    }
    annuaire_core::ntfs::mark_sacl_read(&mut d);
    Ok((d.encode().map_err(debug)?, d))
}

/// The SACL of the root of `calinda` changed and propagated through the writer, Windows doing
/// the same on `jumeau`; read back by the server's tool; a DACL written alone leaves the
/// SACL; « replace »; the refusal of an ordinary account; Ctrl+Z.
fn audit(
    trial: &Trial,
    server: &Server,
    accounts: &Accounts,
    made: &mut Made,
    domain: &Sid,
) -> Result<()> {
    use annuaire_core::ntfs;
    let protected_sacl = "S:PAI(AU;OICISA;FA;;;BA)";
    let protege = format!("O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY){protected_sacl}");
    // The locked file now readable, not writable (`OWNER RIGHTS` leaves its owner READ_CONTROL
    // only): Windows, which reads every descendant, stops on one it cannot read.
    let locked = "O:BAG:SYD:P(A;;0x1200a9;;;BA)(A;;0x20000;;;OW)(A;;FA;;;SY)";
    for t in [OURS, TWIN] {
        if server.windows {
            server.powershell(&format!(
                "{LSA}[J87S]::SetSddl('{0}\\{t}\\protege', '{protege}'); \
[J87S]::SetSddl('{0}\\{t}\\{LOCKED}', '{locked}'); 'OK'",
                server.path
            ))?;
        } else {
            server.bash(&format!(
                "samba-tool ntacl set '{protege}' '{0}/{t}/protege' --use-s3fs\n\
samba-tool ntacl set '{locked}' '{0}/{t}/d2/s2/f1.txt' --use-s3fs\necho OK\n",
                server.path
            ))?;
        }
    }
    let mut s =
        Session::open_share(&server.name, share(), Protection::Encrypted, DELAY).map_err(debug)?;
    // The twin given back the owner of `calinda` (step 5 undid only `calinda`): `CREATOR
    // OWNER` gives the owner of each element.
    let (_, root) = read_root(&mut s, INFO_OGD)?;
    server.windows_owner(&root.owner.ok_or("owner")?)?;
    let before = snapshot(&mut s, OURS, INFO_OGD | INFO_SACL)?;
    let told = server.told(&format!("{OURS}\\protege"), INFO_OGD | INFO_SACL, domain)?;
    println!("  protege, set on the server: {}", text(&told));
    check(
        ntfs::is_sacl_protected(&told) && ntfs::sacl_of(&told).len() == 1,
        "a protected SACL set on the server is kept by it",
    )?;
    let (root_bytes, root) = read_root(&mut s, INFO_OGD | INFO_SACL)?;
    let added = sddl::sd_from_sddl(
        "S:(AU;OICISA;FA;;;WD)(AU;CIFA;0x116;;;AU)(AU;OICIIOSAFA;GA;;;CO)(AU;OINPSA;FR;;;BU)(AU;OICIFA;FA;;;WD)",
        None,
        false,
    )
    .map_err(debug)?;
    let changed = ntfs::with_sacl(&root, &ntfs::sacl_of(&added), &[], true);
    let (report_main, progress, seconds) = audit_changeset(
        trial,
        server,
        made,
        &root_bytes,
        Some(&changed),
        Parts {
            dacl: false,
            sacl: Some(false),
            owner: None,
        },
    )?;
    println!(
        "  Calinda: {} examined, {} written, {} refused in {seconds:.2} s",
        progress.examined, progress.written, progress.refused
    );
    check(
        progress.written == ELEMENTS - 3 && progress.refused == 1,
        "the auditing entries written below, not under the protected folder, the locked file refused",
    )?;
    let (_, stored) = read_root(&mut s, INFO_OGD | INFO_SACL)?;
    check(
        ntfs::same_audit(&stored, &changed),
        "the root is as written",
    )?;
    windows_audit(server, &stored, false)?;
    let after_main = if server.windows {
        compare_audit(&mut s, "change")?
    } else {
        snapshot(&mut s, OURS, INFO_OGD | INFO_SACL)?
    };
    check(
        after_main
            .get("protege")
            .is_some_and(|d| ntfs::is_sacl_protected(d) && ntfs::sacl_of(d).len() == 1),
        "the folder whose SACL is protected is untouched",
    )?;
    let (n, _) = differences(&before, &after_main, ntfs::same_permissions);
    check(n == 0, "the DACLs did not change")?;
    for path in [
        OURS.to_owned(),
        format!("{OURS}\\d1"),
        format!("{OURS}\\d3\\s2"),
        format!("{OURS}\\d3\\s2\\f4.txt"),
    ] {
        let told = server.told(&path, INFO_OGD | INFO_SACL, domain)?;
        let ours = after_main
            .get(
                path.strip_prefix(OURS)
                    .unwrap_or(&path)
                    .trim_start_matches('\\'),
            )
            .ok_or("missing")?;
        println!("  {path}: {}", text(&told));
        check(
            ntfs::same_audit(&told, ours),
            &format!("{path}: the SACL read back identical by the server's tool"),
        )?;
    }
    println!("7. a DACL written alone leaves the SACL");
    let ace = |text: &str| -> Result<annuaire_codecs::sd::Ace> {
        Ok(sddl::sd_from_sddl(&format!("D:{text}"), None, false)
            .map_err(debug)?
            .dacl
            .ok_or("dacl")?
            .aces
            .remove(0))
    };
    // As the « Security » tab of an account that reads the SACL: the descriptor sent
    // carries the SACL as read, only the DACL is written.
    let (with_bytes, with) = read_root(&mut s, INFO_OGD | INFO_SACL)?;
    let mut explicit = ntfs::explicit_aces(&with);
    explicit.push(ace("(A;;0x1200a9;;;AU)")?);
    let mut first = ntfs::composed(
        &with,
        &explicit,
        &ntfs::inherited_of(&with),
        ntfs::is_protected(&with),
    );
    first.sacl = with.sacl.clone();
    first.control |= with.control & SACL_CONTROL;
    let report_first = trial.apply(&Changeset {
        operations: vec![Operation::set_file_descriptor(
            &server.name,
            share(),
            OURS,
            with_bytes,
            first.encode().map_err(debug)?,
        )],
        remarks: Vec::new(),
    })?;
    let told = server.told(OURS, INFO_OGD | INFO_SACL, domain)?;
    check(
        ntfs::same_audit(&told, &changed) && ntfs::same_permissions(&told, &first),
        "the DACL written, the SACL as it was, protection included (server's tool)",
    )?;
    // As an account that may not read the SACL: the descriptor sent knows nothing of it.
    let (plain_bytes, plain) = read_root(&mut s, INFO_OGD)?;
    check(
        !ntfs::has_sacl(&plain),
        "read without the SACL, the root carries none",
    )?;
    let mut explicit = ntfs::explicit_aces(&plain);
    explicit.push(ace("(A;;0x1200a9;;;BU)")?);
    let dacl_only = ntfs::composed(
        &plain,
        &explicit,
        &ntfs::inherited_of(&plain),
        ntfs::is_protected(&plain),
    );
    let report_dacl = trial.apply(&Changeset {
        operations: vec![Operation::set_file_descriptor(
            &server.name,
            share(),
            OURS,
            plain_bytes,
            dacl_only.encode().map_err(debug)?,
        )],
        remarks: Vec::new(),
    })?;
    let told = server.told(OURS, INFO_OGD | INFO_SACL, domain)?;
    println!("  {}", text(&told));
    let entries = ntfs::sacl_of(&told) == ntfs::sacl_of(&changed)
        || ntfs::sacl_of(&told)
            .iter()
            .zip(ntfs::sacl_of(&changed).iter())
            .all(|(a, b)| ntfs::same_ace(a, b));
    if server.windows {
        check(
            entries && ntfs::same_audit(&told, &changed),
            "Windows: the SACL as it was, protection included",
        )?;
    } else {
        // `acl_xattr` takes the control bits of the descriptor sent with a DACL: those of the
        // SACL, unknown to the account, are lost; its entries are kept.
        check(
            entries && !ntfs::is_sacl_protected(&told),
            "Samba: the auditing entries kept, their protection lost (control bits of the DACL)",
        )?;
    }
    check(
        ntfs::same_permissions(&told, &dacl_only),
        "the DACL written (server's tool)",
    )?;
    // The same DACL on the twin, whose trees are compared again.
    s.set_descriptor(TWIN, &dacl_only.encode().map_err(debug)?, sysvol::INFO_DACL)
        .map_err(debug)?;
    println!("8. « replace all child object auditing entries »");
    let (root_bytes, _) = read_root(&mut s, INFO_OGD | INFO_SACL)?;
    let (report_replace, progress, _) = audit_changeset(
        trial,
        server,
        made,
        &root_bytes,
        None,
        Parts {
            dacl: false,
            sacl: Some(true),
            owner: None,
        },
    )?;
    println!(
        "  Calinda: {} examined, {} written",
        progress.examined, progress.written
    );
    let (_, stored) = read_root(&mut s, INFO_OGD | INFO_SACL)?;
    windows_audit(server, &stored, true)?;
    let replaced = if server.windows {
        compare_audit(&mut s, "replace")?
    } else {
        snapshot(&mut s, OURS, INFO_OGD | INFO_SACL)?
    };
    check(
        replaced
            .get("protege")
            .is_some_and(|d| !ntfs::is_sacl_protected(d) && ntfs::explicit_sacl(d).is_empty()),
        "the protected SACL replaced by the inherited entries",
    )?;
    println!("9. refused to an ordinary account, readable without the SACL");
    let mut audited = SecurityDescriptor::decode(&root_bytes).map_err(debug)?;
    audited = ntfs::with_sacl(&audited, &[], &ntfs::inherited_sacl(&audited), false);
    let refused = written_as(
        &accounts.kdc,
        "cc-p",
        &[Operation::set_file_descriptor(
            &server.name,
            share(),
            OURS,
            root_bytes.clone(),
            audited.encode().map_err(debug)?,
        )],
    )?;
    println!("  ordinary account: {refused}");
    check(
        refused.contains("AuditRefused") && refused.contains("3221225569"),
        "the SACL refused to an ordinary account, said with the privilege it asks",
    )?;
    println!("10. undone (Ctrl+Z)");
    let start = std::time::Instant::now();
    trial.undo(&report_replace)?;
    trial.undo(&report_dacl)?;
    trial.undo(&report_first)?;
    trial.undo(&report_main)?;
    println!("  four undos in {:.2} s", start.elapsed().as_secs_f64());
    let back = snapshot(&mut s, OURS, INFO_OGD | INFO_SACL)?;
    let (n, shown) = differences(&before, &back, same_both);
    for line in &shown {
        println!("    {line}");
    }
    check(
        n == 0,
        &format!("DACLs and SACLs as before ({n} differences)"),
    )?;
    s.close();
    Ok(())
}

/// The administrator of the domain: another account than the one writing.
fn administrator(domain: &Sid) -> Result<Sid> {
    domain.with_rid(500).map_err(debug)
}

fn clean(trial: &Trial, server: &Server, made: &Made) -> Result<()> {
    let mut errors = Vec::new();
    for (sam, sid, privilege) in &made.privileges {
        if let Err(e) = server.privilege(sam, sid, privilege, false) {
            errors.push(format!("privilege {privilege}: {e}"));
        }
    }
    if made.share {
        match Srvsvc::open(&server.name, &options()) {
            Ok(mut service) => {
                if let Err(e) = service.delete(share()) {
                    errors.push(format!("share: {e}"));
                }
                service.close();
            }
            Err(e) => errors.push(format!("srvsvc: {e}")),
        }
    }
    if made.folder
        && let Err(e) = server.remove()
    {
        errors.push(format!("folder: {e}"));
    }
    for id in &made.backups {
        let _ = std::fs::remove_file(annuaire_core::propagation::backup_path(id, None));
    }
    if let Some(ou) = &made.ou
        && let Err(e) = trial.remove_tree(ou)
    {
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
fn ntfs_owner_and_sacl() -> Result<()> {
    if labo::child_input().is_some() {
        return Ok(());
    }
    let lab = labo::lab();
    let server = Server::of(&lab);
    let scratch = labo::Scratch::new("ntfs-securite")?;
    let trial = Trial::new(&lab, &scratch)?;
    let mut made = Made::default();
    let done = cases(&trial, &lab, &server, &mut made);
    if let Err(e) = &done {
        println!("FAILED: {e}");
    }
    println!("11. cleaning");
    let cleaned = clean(&trial, &server, &made);
    trial.connection.join();
    done.and(cleaned)
}

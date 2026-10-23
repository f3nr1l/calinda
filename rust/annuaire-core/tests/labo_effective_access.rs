// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Effective access against the lab (J8.5, J8.7, ADR 0023 § 6, ADR 0020).
//!
//! `effective_access_cases`: on the file server of the domain aimed at (`fs1`, Samba member of
//! LAB.TEST; `wdc1`, the Windows DC of WIN.TEST), a share of trial `J85-Essai-<pid>` whose own
//! descriptor grants « Change » to Everyone and « Full control » to Administrators, created by
//! `srvsvc` (`NetrShareAdd`), and five folders whose descriptors the core writes:
//!
//! 1. `lecture`: read granted to a group that holds a group of the account (nesting, read in
//!    `tokenGroups`);
//! 2. `local`: change granted to a local group of the server, found by SAMR (on fs1, only
//!    there; on a DC, `tokenGroups` holds it too) (Samba: an alias of the account domain of fs1 that holds a group of the
//!    account; Windows: `Performance Log Users`, which holds a group of the account);
//! 3. `refus`: change granted to Domain Users, writing denied to a group of the account;
//! 4. `herite\sous`: change granted by an ACE inherited from `herite`;
//! 5. `proprietaire`: a folder the account created (it is the owner), whose DACL grants it
//!    nothing: READ_CONTROL and WRITE_DAC as owner, WRITE_DAC cut by the share;
//! 6. `local-imbrique` (Samba): change granted to an alias that holds the alias of `local`;
//!    Samba does not follow that nesting (nor does Windows allow it), the core neither;
//! 7. `builtin-dc` (Samba, J8.7): change granted to Backup Operators, which on the DCs holds a
//!    group of the account (`tokenGroups` gives it) and which fs1 does not have: no access;
//! 8. `builtin-fs1` (Samba, J8.7): change granted to Guests, which on fs1 only holds another
//!    group of the account: access, found by SAMR in the Builtin of fs1.
//!
//! The access the core computes for an ordinary account of trial is compared with what this
//! account does with its own ticket (`smbclient` and `smbcacls`, the Samba tools, not the core):
//! list the folder (READ_DATA), write a file in it (WRITE_DATA), read its descriptor
//! (READ_CONTROL) and, for two cases, write it (WRITE_DAC). Then the token of a group given in
//! place of the account.
//!
//! Last, Windows computes the same access (J8.7, `labo/acces_effectif_authz.ps1`):
//! `AuthzAccessCheck` for `MAXIMUM_ALLOWED`, as the « Effective Access » tab of Explorer, on
//! the descriptors Windows reads itself (the folder by `Get-Acl`; the share by `Get-SmbShare`
//! on wdc1, the descriptor read by the core for fs1), for each case and for the group; its
//! masks of the folder and of the share must be those of the core, and the groups of the
//! domain and local groups of its context those of the token of the core (how the context is
//! built: see [`authz_script`]). On wdc1 itself by ssh, for fs1 on the station joined to
//! LAB.TEST (`labo/poste.py --domaine`, `ANNUAIRE_LABO_POSTE`).
//!
//! The names of what is made end with the number of the process (other trials may use the
//! servers at the same time); everything is removed, even after a failure.
//!
//! The password of the account of trial is drawn at random, never shown, and goes to `kinit` on
//! its standard input. Its name and those of its groups change at each run (winbind on fs1
//! keeps a name with its SID for 5 min). With LAB.TEST, the trial reaches fs1 by `ssh`
//! (`ANNUAIRE_LABO_SSH_FS1`, see `Server::ssh`) for its local groups and the folder of the
//! share; with WIN.TEST (`ANNUAIRE_LABO_DOMAINE=win.test`), everything goes through the core
//! (`C$`, `srvsvc`).

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::time::{Duration, Instant};

use annuaire_codecs::sd::{self, SecurityDescriptor};
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_codecs::{Sid, sddl};
use annuaire_core::actions;
use annuaire_core::changes::{Change, Changeset, Operation};
use annuaire_core::effective_access::{self, Effective, LocalGroups, Source, Target, right};
use annuaire_core::samr::Samr;
use annuaire_core::smb::Options;
use annuaire_core::srvsvc::{self, Share, Srvsvc};
use annuaire_core::sysvol::{self, Protection, Session};

use labo::{Lab, Result, Trial, check, debug};

const DELAY: Duration = Duration::from_secs(30);
/// Read, change, full control (rights of files).
const READ: &str = "0x1200a9";
const CHANGE: &str = "0x1301bf";
/// Writing denied: WRITE_DATA, APPEND_DATA, WRITE_EA, WRITE_ATTRIBUTES.
const NO_WRITE: &str = "0x116";
const CASES: [&str; 8] = [
    "lecture",
    "local",
    "refus",
    "herite\\sous",
    "proprietaire",
    "local-imbrique",
    "builtin-dc",
    "builtin-fs1",
];
/// The cases of a Samba member only.
const MEMBER_ONLY: [&str; 3] = ["local-imbrique", "builtin-dc", "builtin-fs1"];
/// Backup Operators: an alias of the Builtin of the DCs that holds a group of the account, and
/// that fs1 does not have; Guests: an alias of the Builtin of fs1 that holds another one.
const BACKUP_OPERATORS: &str = "S-1-5-32-551";
const GUESTS: &str = "S-1-5-32-546";

/// The file server of the domain aimed at, and the names of this run.
#[derive(Debug)]
struct Server {
    name: String,
    /// Suffix of the names of this run (other trials may use the server at the same time).
    n: u32,
    /// The share of trial, `J85-Essai-<n>`.
    share: String,
    /// Folder of the share, as `NetrShareAdd` takes it.
    path: String,
    windows: bool,
}

impl Server {
    fn of(lab: &Lab) -> Self {
        let n = std::process::id() % 100_000;
        let share = format!("J85-Essai-{n}");
        if lab.windows() {
            Self {
                name: format!("wdc1.{}", lab.domain),
                n,
                path: format!("C:\\{share}"),
                share,
                windows: true,
            }
        } else {
            Self {
                name: format!("fs1.{}", lab.domain),
                n,
                path: format!("/srv/j85-essai-{n}"),
                share,
                windows: false,
            }
        }
    }

    /// A bash script as root on fs1. `ANNUAIRE_LABO_SSH_FS1` replaces the command that reaches
    /// it (default `ssh -o BatchMode=yes labadmin@fs1.lab.test`).
    fn ssh(&self, script: &str) -> Result<String> {
        let command = std::env::var("ANNUAIRE_LABO_SSH_FS1")
            .unwrap_or_else(|_| "ssh -o BatchMode=yes labadmin@fs1.lab.test".into());
        labo::run(
            Command::new("sh")
                .arg("-c")
                .arg(format!("{command} 'sudo bash -s'")),
            script.as_bytes(),
        )
    }
}

fn options() -> Options {
    Protection::Encrypted.options(DELAY)
}

/// A descriptor to write, from SDDL. `SE_DACL_AUTO_INHERIT_REQ` as `SetSecurityInfo` sets it:
/// without it, Windows and Samba drop `SE_DACL_AUTO_INHERITED` (`AI`), and the folders then
/// created under it get the inheritable ACEs of their parent without the `ID` flag.
fn descriptor(text: &str) -> Result<Vec<u8>> {
    let mut d = sddl::sd_from_sddl(text, None, false).map_err(debug)?;
    if d.control & sd::SE_DACL_AUTO_INHERITED != 0 {
        d.control |= sd::SE_DACL_AUTO_INHERIT_REQ;
    }
    d.encode().map_err(debug)
}

fn add_member(trial: &Trial, group: &str, member: &str) -> Result<()> {
    let change =
        Change::new("member", Vec::new(), vec![member.as_bytes().to_vec()]).map_err(debug)?;
    trial.apply(&Changeset {
        operations: vec![Operation::modify(group, vec![change], None).map_err(debug)?],
        remarks: Vec::new(),
    })?;
    Ok(())
}

fn group(trial: &Trial, parent: &str, name: &str, scope: GroupScope) -> Result<String> {
    trial.apply(&actions::create_group(parent, name, "", scope, true, "").map_err(debug)?)?;
    Ok(format!("CN={name},{parent}"))
}

/// DN of an object by its SID (`<SID=…>`).
fn dn_of(trial: &Trial, sid: &str) -> Result<String> {
    Ok(trial
        .entry(&format!("<SID={sid}>"), &["1.1"])?
        .ok_or_else(|| format!("{sid} absent"))?
        .dn)
}

/// A ticket for the account, asked again for 30 s (an account just created).
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

// --- What the account does, with the Samba tools ----------------------------------------------

/// A Samba tool run with the ticket of the account: `Ok(true)` if it did it, `Ok(false)` if
/// the server said `ACCESS_DENIED`, an error otherwise.
fn tool(kdc: &labo::Kdc, cache: &str, program: &str, args: &[&str]) -> Result<bool> {
    let mut command = Command::new(program);
    command.args(["--use-kerberos=required"]).args(args);
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
    Err(format!("{program} {args:?}: {}", text.trim()).into())
}

/// What the account could do on `path`: list, write a file, read and (if `dac`) write the
/// descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Seen {
    list: bool,
    write: bool,
    read_acl: bool,
    write_acl: Option<bool>,
}

fn observe(
    server: &Server,
    kdc: &labo::Kdc,
    cache: &str,
    path: &str,
    dac: Option<&str>,
) -> Result<Seen> {
    let unc = format!("//{}/{}", server.name, server.share);
    let sample = kdc.folder.path().join("j85.txt");
    std::fs::write(&sample, b"J8.5\n")?;
    let list = tool(
        kdc,
        cache,
        "smbclient",
        &[&unc, "-c", &format!("ls \"{path}\\*\"")],
    )?;
    let write = tool(
        kdc,
        cache,
        "smbclient",
        &[
            &unc,
            "-c",
            &format!("put \"{}\" \"{path}\\j85-ecrit.txt\"", sample.display()),
        ],
    )?;
    let read_acl = tool(kdc, cache, "smbcacls", &[&unc, path])?;
    let write_acl = match dac {
        Some(ace) => Some(tool(kdc, cache, "smbcacls", &[&unc, path, "-M", ace])?),
        None => None,
    };
    Ok(Seen {
        list,
        write,
        read_acl,
        write_acl,
    })
}

// --- The trial ----------------------------------------------------------------------------------

/// What was made, to be removed.
#[derive(Debug, Default)]
struct Made {
    share: bool,
    folder: bool,
    aliases: Vec<String>,
    /// A group of trial put in BUILTIN\Guests of fs1, by its SID.
    guest: Option<String>,
}

fn rights(mask: u32) -> String {
    let names = [
        (right::READ_DATA, "RD"),
        (right::WRITE_DATA, "WD"),
        (right::APPEND_DATA, "AD"),
        (right::READ_EA, "REA"),
        (right::WRITE_EA, "WEA"),
        (right::EXECUTE, "X"),
        (right::DELETE_CHILD, "DC"),
        (right::READ_ATTRIBUTES, "RA"),
        (right::WRITE_ATTRIBUTES, "WA"),
        (right::DELETE, "DE"),
        (right::READ_CONTROL, "RC"),
        (right::WRITE_DAC, "WDAC"),
        (right::WRITE_OWNER, "WO"),
        (right::SYNCHRONIZE, "S"),
    ];
    names
        .iter()
        .filter(|(b, _)| mask & b != 0)
        .map(|(_, n)| *n)
        .collect::<Vec<_>>()
        .join(" ")
}

fn source(e: &Effective, bit: u32) -> String {
    let Some(d) = e.folder.decision(bit) else {
        return "-".into();
    };
    let kind = if d.allowed { "allow" } else { "deny" };
    match d.source {
        Source::Ace(i) => {
            let ace = e
                .folder_descriptor
                .dacl
                .as_ref()
                .and_then(|a| a.aces.get(i));
            let text = ace
                .and_then(|a| sddl::ace_to_sddl(a, None).ok())
                .unwrap_or_default();
            format!("{kind} ACE {i} {text}")
        }
        Source::Owner => format!("{kind} owner"),
        Source::NoDacl => format!("{kind} no DACL"),
    }
}

fn cases(trial: &Trial, lab: &Lab, server: &Server, made: &mut Made) -> Result<()> {
    let kdc = labo::Kdc::new(lab, &lab.pdc_name())?;
    println!("1. accounts and groups");
    let essais = trial.fresh_ou(&trial.base, &format!("Essais-J85-{}", server.n))?;
    // Names of this run: Samba finds the account of a session by its name, through the cache
    // of winbind (5 min), and would give an account recreated under the same name its old SID.
    let n = server.n;
    let account = format!("j85.{n}");
    let secret = labo::password(24);
    trial.apply(
        &actions::create_user(
            &essais,
            &actions::NewUser {
                full_name: account.clone(),
                identifier: account.clone(),
                upn: format!("{account}@{}", lab.domain),
                password: Some(secret.clone()),
                change_at_next_logon: false,
                enable: true,
                ..actions::NewUser::default()
            },
        )
        .map_err(debug)?,
    )?;
    let user = format!("CN={account},{essais}");
    let readers = group(
        trial,
        &essais,
        &format!("GG-J85-Lecteurs-{n}"),
        GroupScope::Global,
    )?;
    let nested = group(
        trial,
        &essais,
        &format!("GG-J85-Imbrique-{n}"),
        GroupScope::Global,
    )?;
    let refused = group(
        trial,
        &essais,
        &format!("GG-J85-Refus-{n}"),
        GroupScope::Global,
    )?;
    add_member(trial, &readers, &user)?;
    add_member(trial, &nested, &readers)?;
    add_member(trial, &refused, &user)?;
    // Samba only: a group in Backup Operators of the DCs, another in Guests of fs1.
    let (backup_group, guest_group) = if server.windows {
        (String::new(), String::new())
    } else {
        let backup = group(
            trial,
            &essais,
            &format!("GG-J85-Sauvegarde-{n}"),
            GroupScope::Global,
        )?;
        let guest = group(
            trial,
            &essais,
            &format!("GG-J85-Invites-{n}"),
            GroupScope::Global,
        )?;
        add_member(trial, &backup, &user)?;
        add_member(trial, &guest, &user)?;
        add_member(trial, &dn_of(trial, BACKUP_OPERATORS)?, &backup)?;
        (backup, guest)
    };
    let sid = |dn: &str| trial.sid(dn).map(|s| s.to_string());
    let (user_sid, readers_sid, nested_sid, refused_sid) =
        (sid(&user)?, sid(&readers)?, sid(&nested)?, sid(&refused)?);
    let guest_sid = if guest_group.is_empty() {
        String::new()
    } else {
        sid(&guest_group)?
    };
    let _ = &backup_group;
    let domain_users = format!("{}-513", user_sid.rsplit_once('-').ok_or("user SID")?.0);

    println!("2. local group reached through SAMR only");
    let mut nested_local = String::new();
    let local = if server.windows {
        // A domain local group cannot join a group of Builtin (WILL_NOT_PERFORM): the
        // global group of the account joins it directly.
        add_member(trial, &dn_of(trial, "S-1-5-32-559")?, &readers)?;
        "S-1-5-32-559".to_owned()
    } else {
        // The administrator owns the folder of the share (with `acl_xattr:ignore system acls`,
        // Samba gives WRITE_DAC to the owner of a folder without NT descriptor only).
        made.aliases = vec![format!("J85-Local2-{n}"), format!("J85-Local-{n}")];
        made.guest = Some(guest_sid.clone());
        made.folder = true;
        // The member by its SID: winbind keeps the name of a group of an earlier trial with
        // its old SID.
        let out = server.ssh(&format!(
            "set -e\nnet sam createlocalgroup J85-Local-{n} >/dev/null\n\
net sam createlocalgroup J85-Local2-{n} >/dev/null\n\
net sam addmem J85-Local-{n} {readers_sid} >/dev/null\n\
net sam addmem J85-Local2-{n} 'FS1\\J85-Local-{n}' >/dev/null\n\
net sam addmem 'BUILTIN\\Guests' {guest_sid} >/dev/null\n\
net sam show 'FS1\\J85-Local-{n}' | sed -n 's/.* with SID //p'\n\
net sam show 'FS1\\J85-Local2-{n}' | sed -n 's/.* with SID //p'\n\
install -d -m 0777 -o 'LAB\\administrator' {}\n",
            server.path
        ))?;
        let mut sids = out.split_whitespace().map(str::to_owned);
        let local = sids.next().ok_or("SID of J85-Local")?;
        nested_local = sids.next().ok_or("SID of J85-Local2")?;
        local
    };
    local.parse::<Sid>().map_err(debug)?;
    println!("  local group {local}");

    println!("3. share and folders");
    if server.windows {
        let mut c =
            Session::open_share(&server.name, "C$", Protection::Encrypted, DELAY).map_err(debug)?;
        c.create_directory(&server.share).map_err(debug)?;
        c.close();
        made.folder = true;
    }
    let mut service = Srvsvc::open(&server.name, &options()).map_err(debug)?;
    let added = service.add(&Share {
        name: server.share.clone(),
        kind: srvsvc::stype::DISKTREE,
        remark: "Essai J8.5".into(),
        max_uses: u32::MAX,
        path: server.path.clone(),
        descriptor: Some(descriptor(&format!(
            "O:BAG:BAD:(A;;{CHANGE};;;WD)(A;;FA;;;BA)"
        ))?),
        ..Share::default()
    });
    service.close();
    added.map_err(debug)?;
    made.share = true;

    let mut session =
        Session::open_share(&server.name, &server.share, Protection::Encrypted, DELAY)
            .map_err(debug)?;
    let info = sysvol::INFO_OGD;
    let protected = |aces: &str| format!("O:BAG:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY){aces}");
    // The root: read and create folders for any account of the domain, this folder only.
    session
        .set_descriptor("", &descriptor(&protected("(A;;0x1200ad;;;AU)"))?, info)
        .map_err(debug)?;
    for (path, aces) in [
        ("lecture", format!("(A;OICI;{READ};;;{nested_sid})")),
        ("local", format!("(A;OICI;{CHANGE};;;{local})")),
        (
            "refus",
            format!("(D;OICI;{NO_WRITE};;;{refused_sid})(A;OICI;{CHANGE};;;{domain_users})"),
        ),
        ("herite", format!("(A;OICI;{CHANGE};;;{user_sid})")),
        (
            "local-imbrique",
            format!("(A;OICI;{CHANGE};;;{nested_local})"),
        ),
        (
            "builtin-dc",
            format!("(A;OICI;{CHANGE};;;{BACKUP_OPERATORS})"),
        ),
        ("builtin-fs1", format!("(A;OICI;{CHANGE};;;{GUESTS})")),
    ] {
        if server.windows && MEMBER_ONLY.contains(&path) {
            continue;
        }
        session.create_directory(path).map_err(debug)?;
        session
            .set_descriptor(path, &descriptor(&protected(&aces))?, info)
            .map_err(debug)?;
    }
    session.create_directory("herite\\sous").map_err(debug)?;

    // The account creates `proprietaire`, then only Administrators and SYSTEM keep a right.
    let cache = "cc-j85";
    ticket(&kdc, &format!("{account}@{}", lab.realm()), &secret, cache)?;
    let unc = format!("//{}/{}", server.name, server.share);
    check(
        tool(
            &kdc,
            cache,
            "smbclient",
            &[&unc, "-c", "mkdir proprietaire"],
        )?,
        "the account creates proprietaire",
    )?;
    let read = session
        .read_descriptors(&["proprietaire".to_owned()], info)
        .map_err(debug)?;
    let owned = SecurityDescriptor::decode(
        read.first()
            .and_then(Option::as_deref)
            .ok_or("proprietaire absent")?,
    )
    .map_err(debug)?;
    check(
        owned.owner.map(|o| o.to_string()) == Some(user_sid.clone()),
        &format!(
            "the account owns proprietaire (owner {:?})",
            owned.owner.map(|o| o.to_string())
        ),
    )?;
    session
        .set_descriptor(
            "proprietaire",
            &descriptor("D:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")?,
            sysvol::INFO_DACL,
        )
        .map_err(debug)?;
    session.close();

    println!("4. effective access computed, then what the account does");
    let mut failures = Vec::new();
    let mut compared = Vec::new();
    for path in CASES {
        if server.windows && MEMBER_ONLY.contains(&path) {
            continue;
        }
        let target = Target {
            server: server.name.clone(),
            share: server.share.clone(),
            path: path.into(),
        };
        let t = Instant::now();
        let e = effective_access::read(
            &trial.connection,
            &user,
            &target,
            Protection::Encrypted,
            DELAY,
        )
        .map_err(debug)?;
        println!("  {path}: read in {} ms", t.elapsed().as_millis());
        compared.push(Compared {
            name: path.into(),
            path: path.into(),
            effective: e.clone(),
        });
        let dac = matches!(path, "proprietaire" | "lecture")
            .then_some("ACL:S-1-5-32-544:ALLOWED/OI|CI/FULL");
        let seen = observe(server, &kdc, cache, path, dac)?;
        let computed = Seen {
            list: e.granted & right::READ_DATA != 0,
            write: e.granted & right::WRITE_DATA != 0,
            read_acl: e.granted & right::READ_CONTROL != 0,
            write_acl: dac.map(|_| e.granted & right::WRITE_DAC != 0),
        };
        println!("  {path}: granted {}", rights(e.granted));
        println!(
            "    {}",
            sddl::sd_to_sddl(&e.folder_descriptor, None).unwrap_or_default()
        );
        println!(
            "    folder {} ; share {}",
            rights(e.folder.granted),
            e.share
                .as_ref()
                .map_or("(no descriptor)".into(), |s| rights(s.granted))
        );
        for bit in [
            right::READ_DATA,
            right::WRITE_DATA,
            right::READ_CONTROL,
            right::WRITE_DAC,
        ] {
            println!("    {:5} {}", rights(bit), source(&e, bit));
        }
        if let LocalGroups::NotEvaluated(why) = &e.token.local_groups {
            println!("    local groups not evaluated: {why}");
        }
        println!("    computed {computed:?}\n    seen     {seen:?}");
        if computed != seen {
            failures.push(path);
        }
        if e.partial() {
            failures.push(path);
        }
        match path {
            "lecture" => check(
                e.token.contains(&nested_sid.parse().map_err(debug)?)
                    && !e.token.directory_groups.is_empty(),
                "lecture: the nested group comes from tokenGroups",
            )?,
            // On a DC, `tokenGroups` already holds the groups of Builtin: SAMR adds nothing.
            "local" => {
                let sid: Sid = local.parse().map_err(debug)?;
                let samr = matches!(&e.token.local_groups,
                    LocalGroups::Evaluated(l) if l.contains(&sid) != server.windows);
                let directory = e.token.directory_groups.contains(&sid);
                check(
                    samr && directory == server.windows,
                    &format!(
                        "local: the local group comes from SAMR on a member, from tokenGroups on a \
DC (tokenGroups: {directory})"
                    ),
                )?;
            }
            "refus" => check(
                e.folder
                    .decision(right::WRITE_DATA)
                    .is_some_and(|d| !d.allowed && d.source == Source::Ace(2)),
                "refus: WRITE_DATA denied by the ACE that denies it",
            )?,
            "builtin-dc" => {
                let alias: Sid = BACKUP_OPERATORS.parse().map_err(debug)?;
                let directory =
                    effective_access::read_token(&trial.connection, &user).map_err(debug)?;
                check(
                    directory.contains(&alias),
                    "builtin-dc: tokenGroups gives Backup Operators of the DCs",
                )?;
                check(
                    e.folder.granted & right::WRITE_DATA == 0 && !e.token.contains(&alias),
                    "builtin-dc: Backup Operators of the DCs left out on fs1",
                )?;
            }
            "builtin-fs1" => {
                let alias: Sid = GUESTS.parse().map_err(debug)?;
                check(
                    e.folder.granted & right::WRITE_DATA != 0
                        && matches!(&e.token.local_groups,
                            LocalGroups::Evaluated(l) if l.contains(&alias)),
                    "builtin-fs1: Guests of fs1 found by SAMR",
                )?;
            }
            "local-imbrique" => check(
                e.granted == 0 && !e.token.contains(&nested_local.parse().map_err(debug)?),
                "local-imbrique: an alias held by an alias is not in the token",
            )?,
            "herite\\sous" => check(
                matches!(e.folder.decision(right::WRITE_DATA).map(|d| d.source),
                    Some(Source::Ace(i)) if e.folder_descriptor.dacl.as_ref()
                        .and_then(|a| a.aces.get(i))
                        .is_some_and(|a| a.is_inherited()
                            && a.sid().map(|s| s.to_string()) == Some(user_sid.clone()))),
                "herite\\sous: WRITE_DATA granted by the ACE inherited from herite",
            )?,
            "proprietaire" => check(
                e.folder
                    .decision(right::READ_CONTROL)
                    .is_some_and(|d| d.allowed && d.source == Source::Owner)
                    && e.folder.granted & right::WRITE_DAC != 0
                    && e.limited_by_share() & right::WRITE_DAC != 0,
                "proprietaire: owner rights, WRITE_DAC cut by the share",
            )?,
            _ => {}
        }
    }
    kdc.destroy(cache);

    println!("5. a group in place of the account");
    let target = Target {
        server: server.name.clone(),
        share: server.share.clone(),
        path: "lecture".into(),
    };
    let e = effective_access::read(
        &trial.connection,
        &readers,
        &target,
        Protection::Encrypted,
        DELAY,
    )
    .map_err(debug)?;
    check(
        e.token.is_group
            && e.token
                .directory_groups
                .contains(&nested_sid.parse().map_err(debug)?),
        "GG-J85-Lecteurs: its parent group is in the token",
    )?;
    check(
        e.granted & right::READ_DATA != 0 && e.granted & right::WRITE_DATA == 0,
        "GG-J85-Lecteurs reads lecture and does not write",
    )?;
    compared.push(Compared {
        name: "groupe:lecture".into(),
        path: "lecture".into(),
        effective: e,
    });
    failures.dedup();
    check(
        failures.is_empty(),
        &format!("computed access is the access seen (differences: {failures:?})"),
    )?;

    println!("6. Windows computes the same access (AuthzAccessCheck)");
    let t = Instant::now();
    let output = windows_access(server, &compared)?;
    println!(
        "  {} cases in {:.1} s (whole call)",
        compared.len(),
        t.elapsed().as_secs_f64()
    );
    let differences = compare_with_windows(&compared, &output);
    check(
        differences.is_empty(),
        &format!("Windows computes the access the core computes (differences: {differences:?})"),
    )
}

// --- What Windows computes ----------------------------------------------------------------------

/// A case compared with Windows: what the core computed for a principal on a folder.
#[derive(Debug)]
struct Compared {
    name: String,
    path: String,
    effective: Effective,
}

/// SIDs as a PowerShell list: `@('S-1-…', …)`.
fn ps_list(sids: &[Sid]) -> String {
    let quoted: Vec<String> = sids.iter().map(|s| format!("'{s}'")).collect();
    format!("@({})", quoted.join(", "))
}

/// The cases (`$Cas`) followed by `labo/acces_effectif_authz.ps1`.
///
/// The context Windows builds (`AuthzInitializeContextFromSid`) holds the groups of the domain
/// and the local groups of the machine that computes. On wdc1, that machine is the server:
/// its context is taken as is. For fs1, it is the station joined to LAB.TEST, whose local
/// groups are not those of fs1 (Windows cannot ask a Samba server for them): they are replaced
/// by those of fs1 (`Alias`, see [`server_aliases`]), the groups of the domain staying those
/// of Windows. For a group given in place of an account, Windows looks for no group at all (its
/// context stays empty, without even Everyone): the context is then the token of the core
/// (`Groupes`), and only the evaluation of the descriptors is compared.
fn authz_script(server: &Server, compared: &[Compared]) -> Result<String> {
    let mut cases = Vec::new();
    for c in compared {
        let e = &c.effective;
        let (folder, share) = if server.windows {
            (format!("{}\\{}", server.path, c.path), server.share.clone())
        } else {
            let share = e
                .share_descriptor
                .as_ref()
                .ok_or("share without descriptor")?;
            (
                format!("\\\\{}\\{}\\{}", server.name, server.share, c.path),
                sddl::sd_to_sddl(share, None).map_err(debug)?,
            )
        };
        let token = if e.token.is_group {
            format!("; Groupes = {}", ps_list(&e.token.sids()[1..]))
        } else if server.windows {
            String::new()
        } else {
            format!("; Alias = {}", ps_list(&server_aliases(server, &e.token)?))
        };
        cases.push(format!(
            "  @{{ Nom = '{}'; Chemin = '{folder}'; Partage = '{share}'; Sid = '{}'{token} }}",
            c.name, e.token.principal
        ));
    }
    let body = std::fs::read_to_string(labo::repository().join("labo/acces_effectif_authz.ps1"))?;
    Ok(format!("$Cas = @(\n{}\n)\n{body}", cases.join(",\n")))
}

/// All the local groups of fs1 for a token, asked of fs1 by SAMR from its SIDs that are not
/// of `Builtin`. Not the local groups of the core's token: SAMR leaves out the aliases already
/// in the token, and `tokenGroups`, read on a DC, already holds the groups of `Builtin` of the
/// DCs (BUILTIN\Users through Domain Users), which a member server does not take from there.
fn server_aliases(server: &Server, token: &effective_access::Token) -> Result<Vec<Sid>> {
    let sids: Vec<Sid> = token
        .without_local()
        .into_iter()
        .filter(|s| !s.to_string().starts_with("S-1-5-32-"))
        .collect();
    let mut samr = Samr::open(&server.name, &options()).map_err(debug)?;
    let aliases = samr.local_groups(&sids);
    samr.close();
    aliases.map_err(debug)
}

/// What Windows computes for the cases: on wdc1 itself (PowerShell over ssh,
/// `ANNUAIRE_LABO_SSH_WDC1`), for fs1 on the station joined to LAB.TEST as
/// `LAB\Administrator` (`labo/poste.py --domaine`, `ANNUAIRE_LABO_POSTE`), which reads the
/// descriptors of the folders on their UNC path.
fn windows_access(server: &Server, compared: &[Compared]) -> Result<String> {
    let script = authz_script(server, compared)?;
    if !server.windows {
        return labo::poste(&script, &["--domaine"]);
    }
    // The command line of OpenSSH for Windows (cmd.exe, 8 KiB) is too short for the script in
    // `-EncodedCommand`, and its standard input loses what passes 4 KiB: the script goes by SMB
    // to the folder of the share, removed with it.
    let mut c =
        Session::open_share(&server.name, "C$", Protection::Encrypted, DELAY).map_err(debug)?;
    let mut bytes = b"\xef\xbb\xbf".to_vec();
    bytes.extend_from_slice(script.as_bytes());
    let written = c.write(&format!("{}\\authz.ps1", server.share), &bytes, true);
    c.close();
    written.map_err(debug)?;
    let command = std::env::var("ANNUAIRE_LABO_SSH_WDC1")
        .unwrap_or_else(|_| "ssh -o BatchMode=yes labadmin@wdc1.win.test".into());
    labo::run(
        Command::new("sh").arg("-c").arg(format!(
            "{command} 'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File \
{}\\authz.ps1'",
            server.path
        )),
        b"",
    )
}

/// A mask of the output of the script (`ntfs 0x…`), None for an error of the API.
fn mask(field: &str, label: &str) -> Option<u32> {
    let hex = field.strip_prefix(label)?.trim().strip_prefix("0x")?;
    u32::from_str_radix(hex, 16).ok()
}

/// The differences between the core and Windows, case by case: the masks of the folder and of
/// the share, then the groups of the two tokens that are groups of the domain or local groups
/// (`S-1-5-21-…`, `S-1-5-32-…`). The other identities (well-known SIDs of a logon, the
/// integrity label of the context) are printed, not counted: no ACE of the trial names them.
fn compare_with_windows(compared: &[Compared], output: &str) -> Vec<String> {
    let answers: BTreeMap<&str, Vec<&str>> = output
        .lines()
        .filter_map(|line| {
            let fields: Vec<&str> = line.trim().split(" | ").collect();
            (fields.len() == 5 && fields[1].starts_with("ntfs ")).then(|| (fields[0], fields))
        })
        .collect();
    let mut differences = Vec::new();
    for c in compared {
        let e = &c.effective;
        let Some(fields) = answers.get(c.name.as_str()) else {
            differences.push(format!("{}: no answer ({})", c.name, output.trim()));
            continue;
        };
        let core_share = e
            .share
            .as_ref()
            .map_or(effective_access::FILE_ALL_ACCESS, |s| s.granted);
        let (ntfs, share) = (mask(fields[1], "ntfs"), mask(fields[2], "partage"));
        println!(
            "  {}: Windows {} {} ({}) ; core ntfs {:#x} partage {:#x}",
            c.name, fields[1], fields[2], fields[4], e.folder.granted, core_share
        );
        if ntfs != Some(e.folder.granted) || share != Some(core_share) {
            differences.push(format!("{}: masks", c.name));
        }
        let windows: BTreeSet<String> = fields[3]
            .trim_start_matches("groupes")
            .trim()
            .split(',')
            .filter(|g| !g.is_empty())
            .map(str::to_owned)
            .collect();
        let core: BTreeSet<String> = e.token.sids()[1..]
            .iter()
            .map(ToString::to_string)
            .collect();
        let counted = |s: &&String| s.starts_with("S-1-5-21-") || s.starts_with("S-1-5-32-");
        let only_windows: Vec<&String> = windows.difference(&core).collect();
        let only_core: Vec<&String> = core.difference(&windows).collect();
        // Where a SID of the core comes from: the directory, SAMR, or a network logon.
        let origin = |s: &String| {
            let sid: Option<Sid> = s.parse().ok();
            let local = matches!(&e.token.local_groups,
                LocalGroups::Evaluated(l) if sid.is_some_and(|x| l.contains(&x)));
            if sid.is_some_and(|x| e.token.directory_groups.contains(&x)) {
                format!("{s} (directory)")
            } else if local {
                format!("{s} (SAMR)")
            } else {
                s.clone()
            }
        };
        let only_core_text: Vec<String> = only_core.iter().map(|s| origin(s)).collect();
        println!("    token: only Windows {only_windows:?}, only core {only_core_text:?}");
        if only_windows.iter().chain(&only_core).any(counted) {
            differences.push(format!("{}: groups of the token", c.name));
        }
    }
    differences
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
        if server.windows {
            match Session::open_share(&server.name, "C$", Protection::Encrypted, DELAY) {
                Ok(mut c) => {
                    if let Err(e) = remove(&mut c, &server.share) {
                        errors.push(format!("folder: {e}"));
                    }
                    c.close();
                }
                Err(e) => errors.push(format!("C$: {e}")),
            }
        } else if let Err(e) = server.ssh(&format!("rm -rf {}\n", server.path)) {
            errors.push(format!("folder: {e}"));
        }
    }
    if let Some(sid) = &made.guest {
        if let Err(e) = server.ssh(&format!("net sam delmem 'BUILTIN\\Guests' {sid}\n")) {
            errors.push(format!("Guests: {e}"));
        }
    }
    for alias in &made.aliases {
        if let Err(e) = server.ssh(&format!("net sam deletelocalgroup {alias}\n")) {
            errors.push(format!("alias {alias}: {e}"));
        }
    }
    if let Err(e) = trial.remove_tree(&format!("OU=Essais-J85-{},{}", server.n, trial.base)) {
        errors.push(format!("OU: {e}"));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; ").into())
    }
}

/// A folder and everything in it, children first.
fn remove(session: &mut Session, path: &str) -> sysvol::Result<()> {
    for child in session.list(path)? {
        match session.nature(&child)? {
            Some(true) => remove(session, &child)?,
            Some(false) => session.delete(&child, false)?,
            None => {}
        }
    }
    session.delete(path, true)
}

#[test]
#[ignore = "lab"]
fn effective_access_cases() -> Result<()> {
    let lab = labo::lab();
    let server = Server::of(&lab);
    let scratch = labo::Scratch::new("acces-effectif")?;
    let trial = Trial::new(&lab, &scratch)?;
    let mut made = Made::default();
    let done = cases(&trial, &lab, &server, &mut made);
    println!("7. cleaning");
    let cleaned = clean(&trial, &server, &made);
    trial.connection.join();
    done.and(cleaned)
}

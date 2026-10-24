// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Operations of a changeset on the shares of a file server: verification, writing,
//! ascertaining (ADR 0023 § 3 to 5).
//!
//! `writer` handles them as the SYSVOL operations, in the same order, with the same journal
//! and the same rollback; this module is their part. A share has no version: each operation
//! carries the state read for the preview, compared with the server in the prior verification
//! and again just before the write; after the write, the state is read back and compared with
//! the state wanted. A share is read with `srvsvc` (levels 502 and 1005), a file or folder
//! by an SMB session on its share.
//!
//! On a Samba server, a share whose key is in the registry configuration (`net conf`) is also
//! read and written by `winreg` (J8.7, ADR 0023 § 9): its connection limit and its options,
//! which `srvsvc` neither gives nor applies, and its creation, change and deletion when Samba
//! refuses them for want of its share commands.

use std::collections::HashMap;

use annuaire_codecs::sd::{self, Ace, Acl, SecurityDescriptor};

use crate::changes::{ErrorRecord, Operation, ShareSpec};
use crate::propagation::{self, Direction, Header};
use crate::smb::client::Options;
use crate::srvsvc::{self, Share, Srvsvc, werror};
use crate::sysvol::{
    self, BACKUP_INTENT, INFO_OGD, INFO_OWNER, INFO_SACL, Protection, Session, SysvolError,
};
use crate::sysvol_write::{DACL_BITS, DELAY, StepError, aces};
use crate::winreg::{self, SmbConf, Values};
use crate::writer::{ProblemKind, WriteCatalog, WriteMsg};

/// The connections of an application to file servers: one `srvsvc` per server, one SMB
/// session per share, the registry configuration of a Samba server, opened at the first need,
/// closed at the end.
#[derive(Debug)]
pub struct Shares {
    protection: Protection,
    services: HashMap<String, Srvsvc>,
    files: HashMap<(String, String), Session>,
    /// Per server: Samba or not, asked once.
    samba: HashMap<String, bool>,
    /// Per Samba server: its registry configuration, `None` if it cannot be opened.
    confs: HashMap<String, Option<SmbConf>>,
}

impl Default for Shares {
    fn default() -> Self {
        Self::new(Protection::Encrypted)
    }
}

impl Shares {
    pub fn new(protection: Protection) -> Self {
        Self {
            protection,
            services: HashMap::new(),
            files: HashMap::new(),
            samba: HashMap::new(),
            confs: HashMap::new(),
        }
    }

    /// Is `server` a Samba server? Samba announces itself a Unix server
    /// (`SV_TYPE_SERVER_UNIX` in `SERVER_INFO_101`), Windows never does.
    pub fn samba(&mut self, server: &str) -> srvsvc::Result<bool> {
        let key = server.to_lowercase();
        if let Some(samba) = self.samba.get(&key) {
            return Ok(*samba);
        }
        let kind = self.service(server)?.server_type()?;
        let samba = kind & srvsvc::sv_type::SERVER_UNIX != 0;
        self.samba.insert(key, samba);
        Ok(samba)
    }

    /// The registry configuration of a Samba server (`HKLM\Software\Samba\smbconf`), opened
    /// at the first need; `None` for Windows (never asked), or when the account cannot open it
    /// (Samba gives it only to `SeDiskOperatorPrivilege`).
    pub fn smbconf(&mut self, server: &str) -> srvsvc::Result<Option<&mut SmbConf>> {
        let key = server.to_lowercase();
        if !self.confs.contains_key(&key) {
            // A server that does not say its type is taken for Windows: nothing changes.
            let conf = if self.samba(server).unwrap_or(false) {
                SmbConf::open(server, &self.options()).ok()
            } else {
                None
            };
            self.confs.insert(key.clone(), conf);
        }
        Ok(self.confs.get_mut(&key).and_then(Option::as_mut))
    }

    pub fn options(&self) -> Options {
        self.protection.options(DELAY)
    }

    pub fn service(&mut self, server: &str) -> srvsvc::Result<&mut Srvsvc> {
        let key = server.to_lowercase();
        if !self.services.contains_key(&key) {
            let service = Srvsvc::open(server, &self.options())?;
            self.services.insert(key.clone(), service);
        }
        self.services
            .get_mut(&key)
            .ok_or_else(|| srvsvc::Error::Rpc(crate::rpc::RpcError::Protocol("no service".into())))
    }

    /// The session of `\\server\share`, opened at the first need, and again after an error
    /// of the session (J8.8): a write that timed out on a slow server leaves requests without
    /// their responses, the rollback that follows goes through a new session.
    pub fn files(&mut self, server: &str, share: &str) -> sysvol::Result<&mut Session> {
        let key = (server.to_lowercase(), share.to_lowercase());
        if self.files.get(&key).is_some_and(|s| !s.usable())
            && let Some(abandoned) = self.files.remove(&key)
        {
            abandoned.close();
        }
        if !self.files.contains_key(&key) {
            let session = Session::open_share(server, share, self.protection, DELAY)?;
            self.files.insert(key.clone(), session);
        }
        self.files.get_mut(&key).ok_or_else(|| {
            SysvolError::Session(crate::smb::SmbError::new(
                crate::smb::ErrorKind::Protocol,
                "no session",
            ))
        })
    }

    pub fn close(&mut self) {
        for (_, service) in self.services.drain() {
            service.close();
        }
        for (_, session) in self.files.drain() {
            session.close();
        }
        for conf in self.confs.drain().filter_map(|(_, c)| c) {
            conf.close();
        }
        self.samba.clear();
    }
}

impl Drop for Shares {
    fn drop(&mut self) {
        self.close();
    }
}

// --- States -----------------------------------------------------------------------------------

/// A share as the server gives it, in the form a changeset writes.
pub fn spec_of(share: &Share, flags: u32) -> ShareSpec {
    ShareSpec {
        name: share.name.clone(),
        path: share.path.clone(),
        remark: share.remark.clone(),
        max_uses: share.max_uses,
        descriptor: share.descriptor.clone(),
        flags,
        registry: None,
    }
}

/// `SHARE_INFO_502` written for a spec: a disk share.
pub fn share_of(spec: &ShareSpec) -> Share {
    Share {
        name: spec.name.clone(),
        kind: srvsvc::stype::DISKTREE,
        remark: spec.remark.clone(),
        max_uses: spec.max_uses,
        current_uses: 0,
        path: spec.path.clone(),
        descriptor: spec.descriptor.clone(),
        level: 502,
    }
}

/// Present state of a share (`None`: it does not exist): `srvsvc`, then on a Samba server the
/// values of its registry key if it has one.
pub fn read_share(
    shares: &mut Shares,
    server: &str,
    name: &str,
) -> srvsvc::Result<Option<ShareSpec>> {
    let service = shares.service(server)?;
    // Samba serves a share changed outside (`net conf`) as it was until an enumeration: the
    // guard would compare with a stale state. One more round trip, 1 to 2 ms.
    service.names()?;
    let mut spec = match service.share(name) {
        Ok(share) => {
            let flags = service.share_flags(name).unwrap_or(0);
            spec_of(&share, flags)
        }
        // Samba answers « invalid name » to a share it does not have.
        Err(srvsvc::Error::Refused {
            code: werror::NERR_NET_NAME_NOT_FOUND | werror::INVALID_NAME,
            ..
        }) => return Ok(None),
        Err(e) => return Err(e),
    };
    complete(shares, server, &mut spec)?;
    Ok(Some(spec))
}

/// The values of the registry key of a share of a Samba server, if it has one; nothing to do
/// for Windows, or for a share of smb.conf.
pub fn complete(shares: &mut Shares, server: &str, spec: &mut ShareSpec) -> srvsvc::Result<()> {
    if winreg::share_key(&spec.name).is_err() {
        return Ok(());
    }
    if let Some(conf) = shares.smbconf(server)? {
        if let Some(values) = conf.values(&spec.name)? {
            from_registry(spec, values);
        }
    }
    Ok(())
}

// --- The registry of Samba (J8.7, ADR 0023 § 9) ----------------------------------------------

/// The last value of `parameter` (Samba keeps the last one), whatever its case.
fn value_of<'a>(values: &'a Values, parameter: &str) -> Option<&'a str> {
    values
        .iter()
        .rev()
        .find(|(n, _)| n.eq_ignore_ascii_case(parameter))
        .map(|(_, v)| v.as_str())
}

fn boolean(text: &str) -> Option<bool> {
    match text.trim().to_lowercase().as_str() {
        "yes" | "true" | "1" | "on" => Some(true),
        "no" | "false" | "0" | "off" => Some(false),
        _ => None,
    }
}

/// `csc policy` and the offline caching of `SHARE_INFO_1005`.
const CSC: [(&str, u32); 4] = [
    ("manual", srvsvc::flags::CSC_MANUAL),
    ("documents", srvsvc::flags::CSC_AUTO),
    ("programs", srvsvc::flags::CSC_VDO),
    ("disable", srvsvc::flags::CSC_NONE),
];

fn csc_of(text: &str) -> Option<u32> {
    CSC.iter()
        .find(|(t, _)| t.eq_ignore_ascii_case(text.trim()))
        .map(|(_, f)| *f)
}

/// The path of the folder as Samba writes it: a drive letter dropped, `/` for `\` (what Samba
/// does with the path of `NetrShareAdd`).
pub fn samba_path(path: &str) -> String {
    let mut chars = path.chars();
    let rest = match (chars.next(), chars.next()) {
        (Some(d), Some(':')) if d.is_ascii_alphabetic() => chars.as_str(),
        _ => path,
    };
    rest.replace('\\', "/")
}

/// The limit and the options a share has by its registry values, absent ones at Samba's
/// default: `max connections` (0: none), `csc policy` (manual), `access based share enum`
/// (no). `srvsvc` never gives the last two, and gives a `csc policy` changed in the registry
/// as it was (seen on fs1: still `documents` after `programs` was written, new sessions too);
/// a value of the global section is not seen.
fn from_registry(spec: &mut ShareSpec, values: Values) {
    spec.max_uses = value_of(&values, "max connections")
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|n| *n != 0)
        .unwrap_or(u32::MAX);
    let csc = value_of(&values, "csc policy")
        .and_then(csc_of)
        .unwrap_or(srvsvc::flags::CSC_MANUAL);
    let abe = value_of(&values, "access based share enum").and_then(boolean) == Some(true);
    spec.flags &= !(srvsvc::flags::CSC_MASK | srvsvc::flags::ACCESS_BASED_DIRECTORY_ENUM);
    spec.flags |= csc;
    if abe {
        spec.flags |= srvsvc::flags::ACCESS_BASED_DIRECTORY_ENUM;
    }
    spec.registry = Some(values);
}

/// The parameters the fields of `spec` set, in the words of `net conf`, and the value that
/// means « unset » for those that have one.
fn typed(spec: &ShareSpec) -> [(&'static str, String, Option<&'static str>); 5] {
    let csc = CSC
        .iter()
        .find(|(_, f)| *f == spec.flags & srvsvc::flags::CSC_MASK)
        .map_or("manual", |(t, _)| t);
    let abe = spec.flags & srvsvc::flags::ACCESS_BASED_DIRECTORY_ENUM != 0;
    let max = if spec.max_uses == u32::MAX {
        0
    } else {
        spec.max_uses
    };
    [
        ("path", samba_path(&spec.path), None),
        ("comment", spec.remark.clone(), Some("")),
        ("max connections", max.to_string(), Some("0")),
        ("csc policy", csc.to_owned(), Some("manual")),
        (
            "access based share enum",
            if abe { "yes" } else { "no" }.to_owned(),
            Some("no"),
        ),
    ]
}

/// Two values of a parameter mean the same.
fn same_value(parameter: &str, a: &str, b: &str) -> bool {
    match parameter {
        "path" => same_path(a, b),
        "comment" => a == b,
        "max connections" => a.trim().parse::<u32>().ok() == b.trim().parse::<u32>().ok(),
        "csc policy" => csc_of(a).is_some() && csc_of(a) == csc_of(b),
        _ => boolean(a).is_some() && boolean(a) == boolean(b),
    }
}

/// What to write to the key of a share for the fields of `spec`, from its `current` values:
/// each parameter of `typed` set (`Some`) or removed (`None`), only those that change. The
/// values `spec` was read with (or the current ones) decide the form: a value that already
/// says what is wanted is kept as it is written, an absent one stays absent when the field is
/// at its default, so that the undo of a change puts back the key as it was.
fn registry_changes(spec: &ShareSpec, current: &Values) -> Vec<(String, Option<String>)> {
    let base = spec.registry.as_ref().unwrap_or(current);
    let mut changes = Vec::new();
    for (parameter, wanted, default) in typed(spec) {
        let target = match value_of(base, parameter) {
            Some(b) if same_value(parameter, b, &wanted) => Some(b.to_owned()),
            None if default.is_some_and(|d| same_value(parameter, d, &wanted)) => None,
            _ => Some(wanted),
        };
        if value_of(current, parameter) != target.as_deref() {
            changes.push((parameter.to_owned(), target));
        }
    }
    changes
}

/// The values of the key of a share created by Calinda: those it had (undo of a deletion),
/// or those of `net conf addshare` (path, comment, `guest ok`, `read only` as a Windows share
/// does: the share permissions decide), then the fields of `spec`.
fn creation_values(spec: &ShareSpec) -> Values {
    let mut values = spec.registry.clone().unwrap_or_else(|| {
        vec![
            ("path".into(), samba_path(&spec.path)),
            ("comment".into(), spec.remark.clone()),
            ("guest ok".into(), "no".into()),
            ("read only".into(), "no".into()),
        ]
    });
    let base = ShareSpec {
        registry: Some(values.clone()),
        ..spec.clone()
    };
    for (name, value) in registry_changes(&base, &values) {
        let at = values
            .iter()
            .position(|(n, _)| n.eq_ignore_ascii_case(&name));
        match (at, value) {
            (Some(i), Some(v)) => {
                if let Some(slot) = values.get_mut(i) {
                    slot.1 = v;
                }
            }
            (None, Some(v)) => values.push((name, v)),
            (Some(i), None) => {
                values.remove(i);
            }
            (None, None) => {}
        }
    }
    values
}

/// Paths are compared without case (Windows) and without the separator's form; the drive
/// letter Samba puts before its paths does not count against a path given without it.
fn same_path(a: &str, b: &str) -> bool {
    let norm = |p: &str| p.replace('/', "\\").trim_end_matches('\\').to_lowercase();
    let (x, y) = (norm(a), norm(b));
    let drive = |p: &str| p.as_bytes().get(1) == Some(&b':');
    if drive(&x) != drive(&y) {
        let strip = |p: &str| p.get(2..).filter(|_| drive(p)).unwrap_or(p).to_owned();
        return strip(&x) == strip(&y);
    }
    x == y
}

/// What a share without descriptor gives, on Windows as on Samba: Everyone, Full control.
/// Neither accepts an empty descriptor, so this one is written to go back to no descriptor.
pub fn open_descriptor() -> Vec<u8> {
    let Ok(ace) = Ace::simple(sd::ACCESS_ALLOWED, FILE_ALL_ACCESS, &sd::everyone(), 0) else {
        return Vec::new();
    };
    SecurityDescriptor {
        revision: 1,
        control: sd::SE_SELF_RELATIVE | sd::SE_DACL_PRESENT,
        owner: None,
        group: None,
        sacl: None,
        dacl: Some(Acl {
            revision: sd::ACL_REVISION,
            aces: vec![ace],
        }),
    }
    .encode()
    .unwrap_or_default()
}

const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// The descriptor a share has in effect: its own, or the open one.
fn effective(descriptor: Option<&[u8]>) -> Vec<u8> {
    descriptor.map_or_else(open_descriptor, <[u8]>::to_vec)
}

/// Same permissions on a share: same DACL, a missing descriptor taken as the open one; owner
/// and group compared only when both have them (Windows adds its own to a descriptor that
/// has none, and neither plays in the access to a share).
pub fn same_share_descriptor(a: Option<&[u8]>, b: Option<&[u8]>) -> bool {
    let (a, b) = (effective(a), effective(b));
    let (Ok(x), Ok(y)) = (
        SecurityDescriptor::decode(&a),
        SecurityDescriptor::decode(&b),
    ) else {
        return a == b;
    };
    let both = |p: &Option<annuaire_codecs::sid::Sid>, q: &Option<annuaire_codecs::sid::Sid>| {
        p.is_none() || q.is_none() || p == q
    };
    both(&x.owner, &y.owner)
        && both(&x.group, &y.group)
        && aces(&x) == aces(&y)
        && x.control & DACL_BITS == y.control & DACL_BITS
}

/// The fields `wanted` sets differently from `from` are as `wanted` in `present`, options and
/// connection limit aside (`options`). The flags are compared on the bits that change only:
/// a server keeps the others as it likes.
fn reached_but_options(present: &ShareSpec, from: &ShareSpec, wanted: &ShareSpec) -> bool {
    (same_path(&from.path, &wanted.path) || same_path(&present.path, &wanted.path))
        && (from.remark == wanted.remark || present.remark == wanted.remark)
        && (same_share_descriptor(from.descriptor.as_deref(), wanted.descriptor.as_deref())
            || same_share_descriptor(present.descriptor.as_deref(), wanted.descriptor.as_deref()))
}

fn options_reached(present: &ShareSpec, from: &ShareSpec, wanted: &ShareSpec) -> bool {
    let changed = from.flags ^ wanted.flags;
    (from.max_uses == wanted.max_uses || present.max_uses == wanted.max_uses)
        && (present.flags & changed == wanted.flags & changed)
}

fn reached(present: &ShareSpec, from: &ShareSpec, wanted: &ShareSpec) -> bool {
    reached_but_options(present, from, wanted) && options_reached(present, from, wanted)
}

/// The share is as the preview read it; its registry values too, those the fields do not say
/// (they are compared through the fields), when both sides have a key.
fn unchanged(present: &ShareSpec, expected: &ShareSpec) -> bool {
    let others = |values: &Values| -> Values {
        let typed = typed(expected);
        values
            .iter()
            .filter(|(n, _)| !typed.iter().any(|(t, _, _)| n.eq_ignore_ascii_case(t)))
            .cloned()
            .collect()
    };
    let registry = match (&present.registry, &expected.registry) {
        (Some(p), Some(e)) => others(p) == others(e),
        _ => true,
    };
    same_path(&present.path, &expected.path)
        && present.remark == expected.remark
        && present.max_uses == expected.max_uses
        && present.flags == expected.flags
        && same_share_descriptor(
            present.descriptor.as_deref(),
            expected.descriptor.as_deref(),
        )
        && registry
}

/// After a write the server accepted: Ok if the share read again is as wanted; else the
/// error that says what is not (Samba keeps the options and the limit of its configuration).
fn verify(
    present: Option<&ShareSpec>,
    from: &ShareSpec,
    wanted: &ShareSpec,
    unc: String,
    catalog: &dyn WriteCatalog,
) -> Result<(), StepError> {
    match present {
        Some(p) if reached(p, from, wanted) => Ok(()),
        // A share of smb.conf on Samba: its options are not written (J8.7: those of the
        // registry are).
        Some(p) if p.registry.is_none() && reached_but_options(p, from, wanted) => Err(not_seen(
            WriteMsg::ShareOptionsKept { unc },
            catalog,
            "options",
        )),
        _ => Err(not_seen(WriteMsg::ShareNotInState { unc }, catalog, "relu")),
    }
}

/// A descriptor of a file or folder read back is the one written: same owner and group (when
/// written), same permissions (`ntfs::same_permissions`: generic rights mapped by Samba,
/// `SE_DACL_AUTO_INHERIT_REQ` kept by neither server).
pub fn same_file_descriptor(read: Option<&[u8]>, written: Option<&[u8]>) -> bool {
    same_file_descriptor_with(read, written, false)
}

/// `same_file_descriptor`, the SACLs compared too if `sacl` (both read with it, J8.7: a
/// Windows server gives no `SE_SACL_PRESENT` for an element without auditing entries, so its
/// absence does not tell a SACL not read).
pub fn same_file_descriptor_with(read: Option<&[u8]>, written: Option<&[u8]>, sacl: bool) -> bool {
    let (Some(a), Some(b)) = (read, written) else {
        return read.is_none() && written.is_none();
    };
    let (Ok(x), Ok(y)) = (SecurityDescriptor::decode(a), SecurityDescriptor::decode(b)) else {
        return a == b;
    };
    let both = |p: &Option<annuaire_codecs::sid::Sid>, q: &Option<annuaire_codecs::sid::Sid>| {
        q.is_none() || p == q
    };
    let audit = !sacl || crate::ntfs::same_audit(&x, &y);
    both(&x.owner, &y.owner)
        && both(&x.group, &y.group)
        && crate::ntfs::same_permissions(&x, &y)
        && audit
}

/// The descriptor as it goes to the server: `SE_DACL_AUTO_INHERIT_REQ` with
/// `SE_DACL_AUTO_INHERITED`, as `SetSecurityInfo` sends it (ADR 0023 § 5); a descriptor read
/// from a server (the « before » an undo writes back) never has it.
fn with_inherit_request(descriptor: &[u8]) -> Vec<u8> {
    let Ok(mut d) = SecurityDescriptor::decode(descriptor) else {
        return descriptor.to_vec();
    };
    let before = d.control;
    if d.control & sd::SE_DACL_AUTO_INHERITED != 0 {
        d.control |= sd::SE_DACL_AUTO_INHERIT_REQ;
    }
    // The same for the SACL (J8.7).
    if d.control & sd::SE_SACL_AUTO_INHERITED != 0 {
        d.control |= sd::SE_SACL_AUTO_INHERIT_REQ;
    }
    if d.control == before {
        return descriptor.to_vec();
    }
    d.encode().unwrap_or_else(|_| descriptor.to_vec())
}

fn file_descriptor(
    shares: &mut Shares,
    server: &str,
    share: &str,
    path: &str,
) -> sysvol::Result<Option<Vec<u8>>> {
    file_descriptor_with(shares, server, share, path, INFO_OGD)
}

/// The descriptor of a file or folder with the parts `info` (the SACL only where it serves:
/// it asks `SeSecurityPrivilege`).
fn file_descriptor_with(
    shares: &mut Shares,
    server: &str,
    share: &str,
    path: &str,
    info: u32,
) -> sysvol::Result<Option<Vec<u8>>> {
    let session = shares.files(server, share)?;
    Ok(session
        .read_descriptors(&[path.to_owned()], info)?
        .into_iter()
        .next()
        .flatten())
}

/// The parts read to guard and read back a `SetFileDescriptor`: the SACL too if it is written.
fn guarded(before: &[u8], after: &[u8]) -> u32 {
    if crate::sysvol_write::information(before, after) & INFO_SACL != 0 {
        INFO_OGD | INFO_SACL
    } else {
        INFO_OGD
    }
}

// --- Prior verification -----------------------------------------------------------------------

/// What the prior verification finds for one operation; `Err` when the server cannot be read
/// (nothing is written).
pub(crate) fn check(
    shares: &mut Shares,
    op: &Operation,
    catalog: &dyn WriteCatalog,
) -> Result<Option<(ProblemKind, WriteMsg)>, ErrorRecord> {
    let unc = op.dn().to_owned();
    let server = op.server().unwrap_or_default().to_owned();
    let read = |shares: &mut Shares, name: &str| -> Result<Option<ShareSpec>, ErrorRecord> {
        read_share(shares, &server, name).map_err(|e| catalog.share_error(&e, &server))
    };
    Ok(match op {
        Operation::AddShare { share, .. } => {
            read(shares, &share.name)?.map(|_| (ProblemKind::Exists, WriteMsg::ShareExists { unc }))
        }
        Operation::ChangeShare { before, .. } => match read(shares, &before.name)? {
            None => Some((ProblemKind::Missing, WriteMsg::ShareMissing { unc })),
            Some(present) if !unchanged(&present, before) => {
                Some((ProblemKind::Version, WriteMsg::ShareChanged { unc }))
            }
            Some(_) => None,
        },
        Operation::DeleteShare { share, .. } => match read(shares, &share.name)? {
            None => Some((ProblemKind::Missing, WriteMsg::ShareMissing { unc })),
            Some(present) if !unchanged(&present, share) => {
                Some((ProblemKind::Version, WriteMsg::ShareChanged { unc }))
            }
            Some(_) => None,
        },
        Operation::SetFileDescriptor {
            share,
            path,
            before,
            after,
            ..
        } => match file_descriptor_with(shares, &server, share, path, guarded(before, after))
            .map_err(|e| audit_record(&e, &unc, &server, guarded(before, after), catalog))?
        {
            None => Some((
                ProblemKind::Missing,
                WriteMsg::SysvolNoLongerExists { path: unc },
            )),
            Some(present)
                if !same_file_descriptor_with(
                    Some(&present),
                    Some(before),
                    guarded(before, after) & INFO_SACL != 0,
                ) =>
            {
                Some((
                    ProblemKind::Version,
                    WriteMsg::SysvolPermissionsChanged { path: unc },
                ))
            }
            Some(_) => None,
        },
        Operation::PropagateInheritance {
            share,
            path,
            backup,
            direction,
            ..
        } => match direction {
            Direction::Compute => match file_descriptor(shares, &server, share, path)
                .map_err(|e| catalog.file_error(&e, &server))?
            {
                None => Some((
                    ProblemKind::Missing,
                    WriteMsg::SysvolNoLongerExists { path: unc },
                )),
                Some(_) => None,
            },
            Direction::Undo | Direction::Redo => backup_readable(&server, share, backup)
                .err()
                .map(|file| (ProblemKind::Missing, WriteMsg::BackupUnusable { file })),
        },
        _ => None,
    })
}

/// The backup `id` of a propagation on `\\server\share`, opened: its elements, read as they
/// are written back, and their number; the path of the file if it cannot be read or is the one
/// of another share.
fn backup_of(
    server: &str,
    share: &str,
    id: &str,
) -> Result<(propagation::Elements, usize), String> {
    let file = propagation::backup_path(id, None);
    let shown = file.display().to_string();
    match propagation::open_backup(&file) {
        Ok((header, elements))
            if header.server.eq_ignore_ascii_case(server)
                && header.share.eq_ignore_ascii_case(share) =>
        {
            let total = propagation::saved_count(&file).map_err(|_| shown.clone())?;
            Ok((elements, total))
        }
        _ => Err(shown),
    }
}

/// The backup `id` reads to its end (the prior verification of a rewrite): nothing is written
/// from a backup that would fail half way. Read line by line, none kept.
fn backup_readable(server: &str, share: &str, id: &str) -> Result<(), String> {
    let (mut elements, _) = backup_of(server, share, id)?;
    match elements.find_map(|e| e.err()) {
        Some(_) => Err(propagation::backup_path(id, None).display().to_string()),
        None => Ok(()),
    }
}

// --- Writing ----------------------------------------------------------------------------------

fn record(class: &str, message: String, detail: impl Into<String>) -> ErrorRecord {
    ErrorRecord {
        class: class.into(),
        message,
        detail: detail.into(),
    }
}

fn conflict(msg: WriteMsg, catalog: &dyn WriteCatalog, what: &str) -> StepError {
    StepError::Conflict(record("ErreurConflit", catalog.write_text(&msg), what))
}

fn not_seen(msg: WriteMsg, catalog: &dyn WriteCatalog, what: &str) -> StepError {
    StepError::Verification(record("ErreurVerification", catalog.write_text(&msg), what))
}

/// A refusal to write the owner, said with the privilege it asks (J8.7): the server answers
/// `STATUS_ACCESS_DENIED` to an account that may not take ownership, `STATUS_INVALID_OWNER`
/// to one that gives it to another account without `SeRestorePrivilege`.
fn owner_refused(
    error: SysvolError,
    unc: &str,
    server: &str,
    catalog: &dyn WriteCatalog,
) -> StepError {
    let Some(status) = error
        .ntstatus()
        .filter(|_| !matches!(error, SysvolError::Session(_)))
    else {
        return StepError::Other(catalog.file_error(&error, server));
    };
    StepError::Other(record(
        "ErreurSysvol",
        catalog.write_text(&WriteMsg::OwnerRefused {
            path: unc.to_owned(),
            status,
        }),
        format!("NTSTATUS 0x{status:08X}"),
    ))
}

/// A refusal of a read or write that involves the SACL, said with the privilege it asks
/// (`SeSecurityPrivilege`, J8.7); other errors as usual.
fn audit_refused(
    error: SysvolError,
    unc: &str,
    server: &str,
    info: u32,
    catalog: &dyn WriteCatalog,
) -> StepError {
    StepError::Other(audit_record(&error, unc, server, info, catalog))
}

fn audit_record(
    error: &SysvolError,
    unc: &str,
    server: &str,
    info: u32,
    catalog: &dyn WriteCatalog,
) -> ErrorRecord {
    match error.ntstatus() {
        Some(status @ (crate::smb::msg::status::ACCESS_DENIED | 0xC000_0061))
            if info & INFO_SACL != 0 && !matches!(error, SysvolError::Session(_)) =>
        {
            record(
                "ErreurSysvol",
                catalog.write_text(&WriteMsg::AuditRefused {
                    path: unc.to_owned(),
                    status,
                }),
                format!("NTSTATUS 0x{status:08X}"),
            )
        }
        _ => catalog.file_error(error, server),
    }
}

/// The registry configuration of `server` can be written (a Samba server whose registry the
/// account opens).
fn registry_open(shares: &mut Shares, server: &str) -> bool {
    matches!(shares.smbconf(server), Ok(Some(_)))
}

/// `f` on the registry configuration of `server`, which must be open.
fn with_conf<T>(
    shares: &mut Shares,
    server: &str,
    f: impl FnOnce(&mut SmbConf) -> winreg::Result<T>,
) -> srvsvc::Result<T> {
    match shares.smbconf(server)? {
        Some(conf) => f(conf),
        None => Err(srvsvc::Error::Refused {
            op: "winreg",
            code: winreg::werror::ACCESS_DENIED,
        }),
    }
}

/// The values of the key of a share; `None` without a key (or without registry).
fn registry_values(
    shares: &mut Shares,
    server: &str,
    name: &str,
) -> srvsvc::Result<Option<Values>> {
    if winreg::share_key(name).is_err() {
        return Ok(None);
    }
    match shares.smbconf(server)? {
        Some(conf) => conf.values(name),
        None => Ok(None),
    }
}

/// Removes the key Calinda made for a share that did not come to be (best effort: the error
/// reported is the one that stopped the creation).
fn drop_key(shares: &mut Shares, server: &str, name: &str) {
    let _ = with_conf(shares, server, |c| c.delete(name));
}

/// Guard, write and read back of one operation (`appliquer`).
pub(crate) fn apply(
    shares: &mut Shares,
    op: &Operation,
    catalog: &dyn WriteCatalog,
) -> Result<(), StepError> {
    let unc = op.dn().to_owned();
    let server = op.server().unwrap_or_default().to_owned();
    let share_error = |e: srvsvc::Error| StepError::Other(catalog.share_error(&e, &server));
    let file_error = |e: SysvolError| StepError::Other(catalog.file_error(&e, &server));
    match op {
        Operation::AddShare { share, .. } => {
            if read_share(shares, &server, &share.name)
                .map_err(share_error)?
                .is_some()
            {
                return Err(conflict(WriteMsg::ShareExists { unc }, catalog, "existe"));
            }
            let added = shares
                .service(&server)
                .and_then(|s| s.add(&share_of(share)));
            let by_registry = match added {
                Ok(()) => false,
                // Samba without « add share command »: the key made by Calinda (J8.7).
                Err(srvsvc::Error::Refused {
                    code: werror::ACCESS_DENIED,
                    ..
                }) if registry_open(shares, &server) => {
                    let values = creation_values(share);
                    with_conf(shares, &server, |c| c.create(&share.name, &values))
                        .map_err(share_error)?;
                    true
                }
                Err(e) => return Err(share_error(e)),
            };
            if by_registry {
                // A server that does not read its shares from the registry (a Samba DC as
                // provisioned, `registry shares` off) does not serve it: nothing is left.
                let served = read_share(shares, &server, &share.name);
                if !matches!(served, Ok(Some(_))) {
                    drop_key(shares, &server, &share.name);
                    return match served {
                        Err(e) => Err(share_error(e)),
                        _ => Err(not_seen(
                            WriteMsg::ShareRegistryIgnored { unc },
                            catalog,
                            "registre",
                        )),
                    };
                }
                // Samba keeps the descriptor of a share deleted by its key (`share_info.tdb`):
                // a share made again under the same name would get it. The one wanted (or the
                // open one) is written in any case.
                let sd = effective(share.descriptor.as_deref());
                let written = shares
                    .service(&server)
                    .and_then(|s| s.set_descriptor(&share.name, &sd));
                if let Err(e) = written {
                    drop_key(shares, &server, &share.name);
                    return Err(share_error(e));
                }
            }
            let current = registry_values(shares, &server, &share.name).map_err(share_error)?;
            match current {
                // The options (and, for an undo, the values the key had) go to the key.
                Some(current) if !by_registry => {
                    let written = match &share.registry {
                        Some(_) => {
                            let values = creation_values(share);
                            with_conf(shares, &server, |c| c.restore(&share.name, &values))
                        }
                        None => {
                            let changes = registry_changes(share, &current);
                            with_conf(shares, &server, |c| c.change(&share.name, &changes))
                        }
                    };
                    written.map_err(share_error)?;
                }
                Some(_) => {}
                None if share.flags != 0 => {
                    shares
                        .service(&server)
                        .and_then(|s| s.set_flags(&share.name, share.flags))
                        .map_err(share_error)?;
                }
                None => {}
            }
            let present = read_share(shares, &server, &share.name).map_err(share_error)?;
            let empty = ShareSpec {
                max_uses: u32::MAX,
                ..ShareSpec::default()
            };
            verify(present.as_ref(), &empty, share, unc, catalog)
        }
        Operation::ChangeShare { before, after, .. } => {
            let present = match read_share(shares, &server, &before.name).map_err(share_error)? {
                None => return Err(conflict(WriteMsg::ShareMissing { unc }, catalog, "absent")),
                Some(p) if !unchanged(&p, before) => {
                    return Err(conflict(WriteMsg::ShareChanged { unc }, catalog, "modifié"));
                }
                Some(p) => p,
            };
            let descriptor =
                !same_share_descriptor(before.descriptor.as_deref(), after.descriptor.as_deref());
            if let Some(current) = &present.registry {
                // A share of Samba's registry (J8.7): the descriptor by 1501 (Samba keeps it
                // apart), path and comment by 502 for the « change share command » of the
                // server, by the key if Samba refuses for want of it; the limit and the options
                // by the key, where `srvsvc` cannot put them.
                let service = shares.service(&server).map_err(share_error)?;
                if descriptor {
                    let sd = effective(after.descriptor.as_deref());
                    service
                        .set_descriptor(&after.name, &sd)
                        .map_err(share_error)?;
                }
                if !same_path(&before.path, &after.path) || before.remark != after.remark {
                    let mut whole = share_of(after);
                    whole.max_uses = present.max_uses;
                    whole.descriptor = Some(effective(after.descriptor.as_deref()));
                    match service.set_share(&whole) {
                        Ok(()) => {}
                        Err(srvsvc::Error::Refused {
                            code: werror::ACCESS_DENIED,
                            ..
                        }) => {}
                        Err(e) => return Err(share_error(e)),
                    }
                }
                let now = registry_values(shares, &server, &after.name)
                    .map_err(share_error)?
                    .unwrap_or_else(|| current.clone());
                let changes = registry_changes(after, &now);
                if !changes.is_empty() {
                    with_conf(shares, &server, |c| c.change(&after.name, &changes))
                        .map_err(share_error)?;
                }
            } else {
                let service = shares.service(&server).map_err(share_error)?;
                let others = !same_path(&before.path, &after.path)
                    || before.remark != after.remark
                    || before.max_uses != after.max_uses;
                if others || descriptor {
                    // Level 502 carries the whole share: Windows clears the comment of a share
                    // whose descriptor is set alone (1501). Samba, when path, comment or limit
                    // change (its « change share command »), leaves the descriptor of 502
                    // aside: with both to change, the descriptor goes first by 1501, then 502
                    // sets the rest (and the descriptor again, for Windows). A share goes back
                    // to no descriptor through the open one, the servers refusing an empty one.
                    let mut whole = share_of(after);
                    if descriptor {
                        let sd = effective(after.descriptor.as_deref());
                        if others {
                            service
                                .set_descriptor(&after.name, &sd)
                                .map_err(share_error)?;
                        }
                        whole.descriptor = Some(sd);
                    }
                    match service.set_share(&whole) {
                        // Samba without « change share command » still sets a descriptor alone.
                        Err(srvsvc::Error::Refused {
                            code: werror::ACCESS_DENIED,
                            ..
                        }) if !others => {
                            let sd = whole.descriptor.unwrap_or_default();
                            service
                                .set_descriptor(&after.name, &sd)
                                .map_err(share_error)?;
                        }
                        other => other.map_err(share_error)?,
                    }
                }
                if before.flags != after.flags {
                    service
                        .set_flags(&after.name, after.flags)
                        .map_err(share_error)?;
                }
            }
            let present = read_share(shares, &server, &after.name).map_err(share_error)?;
            verify(present.as_ref(), before, after, unc, catalog)
        }
        Operation::DeleteShare { share, .. } => {
            let present = match read_share(shares, &server, &share.name).map_err(share_error)? {
                None => return Err(conflict(WriteMsg::ShareMissing { unc }, catalog, "absent")),
                Some(p) if !unchanged(&p, share) => {
                    return Err(conflict(WriteMsg::ShareChanged { unc }, catalog, "modifié"));
                }
                Some(p) => p,
            };
            let deleted = shares.service(&server).and_then(|s| s.delete(&share.name));
            match deleted {
                Ok(()) => {}
                // Samba without « delete share command »: its key deleted (J8.7).
                Err(srvsvc::Error::Refused {
                    code: werror::ACCESS_DENIED,
                    ..
                }) if present.registry.is_some() && registry_open(shares, &server) => {
                    with_conf(shares, &server, |c| c.delete(&share.name)).map_err(share_error)?;
                }
                Err(e) => return Err(share_error(e)),
            }
            match read_share(shares, &server, &share.name).map_err(share_error)? {
                None => Ok(()),
                Some(_) => Err(not_seen(WriteMsg::ShareNotInState { unc }, catalog, "relu")),
            }
        }
        Operation::SetFileDescriptor {
            share,
            path,
            before,
            after,
            ..
        } => {
            let parts = guarded(before, after);
            let present = file_descriptor_with(shares, &server, share, path, parts)
                .map_err(|e| audit_refused(e, &unc, &server, parts, catalog))?;
            match present {
                None => {
                    return Err(conflict(
                        WriteMsg::SysvolNoLongerExists { path: unc },
                        catalog,
                        "absent",
                    ));
                }
                Some(p)
                    if !same_file_descriptor_with(
                        Some(&p),
                        Some(before),
                        parts & INFO_SACL != 0,
                    ) =>
                {
                    return Err(conflict(
                        WriteMsg::SysvolPermissionsChanged { path: unc },
                        catalog,
                        "descripteur",
                    ));
                }
                Some(_) => {}
            }
            let info = crate::sysvol_write::information(before, after);
            let written = with_inherit_request(after);
            // The owner goes first, on its own, with `FILE_OPEN_FOR_BACKUP_INTENT`: a Windows
            // server applies then the restore privilege of the account (ADR 0023 § 5); the
            // rest after, which the new owner may write even if the DACL gave it nothing.
            if info & INFO_OWNER != 0 {
                shares
                    .files(&server, share)
                    .and_then(|s| s.set_descriptor_with(path, &written, INFO_OWNER, BACKUP_INTENT))
                    .map_err(|e| owner_refused(e, &unc, &server, catalog))?;
            }
            // A SACL goes with the DACL (as it is): Samba keeps the control bits of a SACL
            // only when the DACL is written with it (ADR 0023 § 5).
            let mut rest = info & !INFO_OWNER;
            if rest & INFO_SACL != 0 {
                rest |= crate::sysvol::INFO_DACL;
            }
            if rest != 0 {
                shares
                    .files(&server, share)
                    .and_then(|s| s.set_descriptor(path, &written, rest))
                    .map_err(|e| audit_refused(e, &unc, &server, rest, catalog))?;
            }
            let again =
                file_descriptor_with(shares, &server, share, path, parts).map_err(file_error)?;
            if same_file_descriptor_with(again.as_deref(), Some(after), parts & INFO_SACL != 0) {
                Ok(())
            } else {
                Err(not_seen(
                    WriteMsg::FileNotInState { path: unc },
                    catalog,
                    "relu",
                ))
            }
        }
        Operation::PropagateInheritance {
            share,
            path,
            replace,
            parts,
            backup,
            direction,
            count,
            ..
        } => {
            let control = propagation::control(backup);
            let backup_error = |file: String, detail: String| {
                StepError::Other(record(
                    "ErreurSauvegarde",
                    catalog.write_text(&WriteMsg::BackupUnusable { file }),
                    detail,
                ))
            };
            let saved = match direction {
                Direction::Compute => None,
                Direction::Undo | Direction::Redo => Some(
                    backup_of(&server, share, backup)
                        .map_err(|file| backup_error(file, String::new()))?,
                ),
            };
            let session = shares.files(&server, share).map_err(file_error)?;
            let done = match saved {
                None => propagation::propagate(
                    session,
                    &Header {
                        server: server.clone(),
                        share: share.clone(),
                        root: path.clone(),
                        replace: *replace,
                        parts: parts.clone(),
                    },
                    &propagation::backup_path(backup, None),
                    *count,
                    &control,
                ),
                Some((elements, total)) => {
                    propagation::rewrite(session, elements, total, parts, *direction, &control)
                }
            };
            // A refused element is reported by the control, not as a failure of the
            // operation: what is written stays written, and saved.
            done.map_err(|e| match e {
                propagation::Error::Smb(e) => file_error(e),
                propagation::Error::Backup { path, detail } => {
                    backup_error(path.display().to_string(), detail)
                }
            })
        }
        _ => Err(StepError::Other(record(
            "ErreurAnnuaire",
            "opération sans partage".into(),
            "",
        ))),
    }
}

/// Did the operation take place? `None` when the server does not tell (`constater`).
pub fn ascertain(shares: &mut Shares, op: &Operation) -> Option<bool> {
    let server = op.server()?.to_owned();
    match op {
        Operation::AddShare { share, .. } => {
            let present = read_share(shares, &server, &share.name).ok()?;
            Some(present.is_some_and(|p| reached_but_options(&p, &ShareSpec::default(), share)))
        }
        Operation::DeleteShare { share, .. } => {
            let present = read_share(shares, &server, &share.name).ok()?;
            Some(present.is_none())
        }
        Operation::ChangeShare { before, after, .. } => {
            let present = read_share(shares, &server, &after.name).ok()??;
            if reached(&present, before, after) {
                Some(true)
            } else if unchanged(&present, before) {
                Some(false)
            } else {
                None
            }
        }
        Operation::SetFileDescriptor {
            share,
            path,
            before,
            after,
            ..
        } => {
            let present = file_descriptor(shares, &server, share, path).ok()??;
            if same_file_descriptor(Some(&present), Some(after)) {
                Some(true)
            } else if same_file_descriptor(Some(&present), Some(before)) {
                Some(false)
            } else {
                None
            }
        }
        // Cut by a stop of the application (ADR 0023 § 8). The backup is created before the
        // first write, each batch saved before it is written: a backup of this share means the
        // propagation started, and what it wrote is saved, so it counts as applied (as after
        // « Stop »); no backup, nothing was written.
        Operation::PropagateInheritance {
            share,
            backup,
            direction: Direction::Compute,
            ..
        } => {
            let file = propagation::backup_path(backup, None);
            match propagation::read_header(&file) {
                Ok(header)
                    if header.server.eq_ignore_ascii_case(&server)
                        && header.share.eq_ignore_ascii_case(share) =>
                {
                    Some(true)
                }
                Err(_) if !file.exists() => Some(false),
                _ => None,
            }
        }
        // A rewrite from the backup: done if one element at least is as it had to become.
        Operation::PropagateInheritance {
            share,
            backup,
            direction,
            parts,
            ..
        } => {
            let (elements, _) = backup_of(&server, share, backup).ok()?;
            let session = shares.files(&server, share).ok()?;
            propagation::rewritten(session, elements, parts, *direction).ok()?
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(path: &str, remark: &str, flags: u32) -> ShareSpec {
        ShareSpec {
            name: "Commun".into(),
            path: path.into(),
            remark: remark.into(),
            max_uses: u32::MAX,
            descriptor: None,
            flags,
            registry: None,
        }
    }

    #[test]
    fn paths_compare_as_windows_does() {
        assert!(same_path("C:\\Partages\\Commun", "c:\\partages\\commun\\"));
        assert!(same_path("C:\\srv\\partages", "C:/srv/partages"));
        assert!(!same_path("C:\\srv\\a", "C:\\srv\\b"));
    }

    #[test]
    fn reached_looks_at_what_changes_only() {
        let before = spec("C:\\a", "x", 0x1100);
        let after = spec("C:\\a", "y", 0x1100 | 0x800);
        // The server keeps 0x1000 as it likes, the comment and ABE are reached.
        assert!(reached(&spec("C:\\A", "y", 0x0900), &before, &after));
        assert!(!reached(&spec("C:\\a", "x", 0x0900), &before, &after));
        assert!(!reached(&spec("C:\\a", "y", 0x0100), &before, &after));
    }

    fn sd(text: &str) -> Vec<u8> {
        annuaire_codecs::sddl::sd_from_sddl(text, None, false)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn no_descriptor_is_everyone_full_control() {
        assert!(same_share_descriptor(None, Some(&sd("D:(A;;FA;;;WD)"))));
        assert!(same_share_descriptor(None, Some(&open_descriptor())));
        assert!(!same_share_descriptor(
            None,
            Some(&sd("D:(A;;0x1200a9;;;WD)"))
        ));
    }

    #[test]
    fn owner_and_group_added_by_windows_do_not_count() {
        let written = sd("D:(A;;FA;;;WD)");
        let read = sd("O:BAG:SYD:(A;;FA;;;WD)");
        assert!(same_share_descriptor(Some(&read), Some(&written)));
        assert!(!same_share_descriptor(
            Some(&sd("O:SYG:SYD:(A;;FA;;;WD)")),
            Some(&read)
        ));
    }

    #[test]
    fn options_kept_are_told_apart() {
        let before = spec("C:\\a", "x", 0);
        let mut after = spec("C:\\a", "y", 0x830);
        after.max_uses = 5;
        // Samba: comment written, options and limit of its configuration kept.
        let present = spec("C:\\a", "y", 0);
        assert!(reached_but_options(&present, &before, &after));
        assert!(!reached(&present, &before, &after));
    }

    #[test]
    fn file_descriptors_as_servers_keep_them() {
        // Written with AR and generic rights, read back without AR and mapped (Samba).
        let written = sd("O:BAG:SYD:PARAI(A;OICIIO;GA;;;CO)(A;OICI;GXGR;;;AU)");
        let read = sd("O:BAG:SYD:PAI(A;OICIIO;FA;;;CO)(A;OICI;0x1200a9;;;AU)");
        assert!(same_file_descriptor(Some(&read), Some(&written)));
        assert!(!same_file_descriptor(
            Some(&sd("O:SYG:SYD:PAI(A;OICIIO;FA;;;CO)(A;OICI;0x1200a9;;;AU)")),
            Some(&written)
        ));
        // A descriptor read goes back with the request of automatic inheritance.
        let again = SecurityDescriptor::decode(&with_inherit_request(&read)).unwrap();
        assert_ne!(again.control & sd::SE_DACL_AUTO_INHERIT_REQ, 0);
        let plain = sd("O:BAD:(A;;FA;;;WD)");
        assert_eq!(with_inherit_request(&plain), plain);
        // The SACL counts when both have one (J8.7), and asks its inheritance too.
        let audited = sd("O:BAG:SYD:PAI(A;OICI;FA;;;BA)S:AI(AU;OICISA;FA;;;WD)");
        let other = sd("O:BAG:SYD:PAI(A;OICI;FA;;;BA)S:AI(AU;OICIFA;FA;;;WD)");
        let without = sd("O:BAG:SYD:PAI(A;OICI;FA;;;BA)");
        assert!(!same_file_descriptor_with(
            Some(&audited),
            Some(&other),
            true
        ));
        assert!(same_file_descriptor(Some(&audited), Some(&other)));
        assert!(!same_file_descriptor_with(
            Some(&without),
            Some(&audited),
            true
        ));
        assert!(same_file_descriptor(Some(&without), Some(&audited)));
        let again = SecurityDescriptor::decode(&with_inherit_request(&audited)).unwrap();
        assert_ne!(again.control & sd::SE_SACL_AUTO_INHERIT_REQ, 0);
        // A DACL changed alone does not write the SACL; a SACL changed does.
        let dacl_only = sd("O:BAG:SYD:PAI(A;OICI;FA;;;SY)S:AI(AU;OICISA;FA;;;WD)");
        assert_eq!(guarded(&audited, &dacl_only), INFO_OGD);
        assert_eq!(
            crate::sysvol_write::information(&audited, &dacl_only),
            sysvol::INFO_DACL
        );
        assert_eq!(guarded(&audited, &other), INFO_OGD | INFO_SACL);
        assert_eq!(
            crate::sysvol_write::information(&audited, &other),
            sysvol::INFO_SACL
        );
    }

    fn values(pairs: &[(&str, &str)]) -> Values {
        pairs
            .iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn registry_values_say_limit_and_options() {
        let mut spec = spec("C:\\srv\\a", "x", srvsvc::flags::CSC_AUTO);
        from_registry(
            &mut spec,
            values(&[
                ("path", "/srv/a"),
                ("max connections", "25"),
                ("access based share enum", "Yes"),
            ]),
        );
        assert_eq!(spec.max_uses, 25);
        // No « csc policy »: Samba's default, whatever srvsvc gave.
        assert_eq!(
            spec.flags,
            srvsvc::flags::CSC_MANUAL | srvsvc::flags::ACCESS_BASED_DIRECTORY_ENUM
        );
        from_registry(
            &mut spec,
            values(&[("max connections", "0"), ("csc policy", "disable")]),
        );
        assert_eq!(spec.max_uses, u32::MAX);
        assert_eq!(spec.flags, srvsvc::flags::CSC_NONE);
    }

    #[test]
    fn registry_changes_write_what_changes_and_undo_puts_back() {
        let read = values(&[
            ("path", "/srv/a"),
            ("comment", "x"),
            ("guest ok", "no"),
            ("read only", "no"),
            ("vfs objects", "acl_xattr"),
        ]);
        let mut before = spec("C:\\srv\\a", "x", 0);
        from_registry(&mut before, read.clone());
        // Nothing changed, nothing written.
        assert!(registry_changes(&before, &read).is_empty());
        let mut after = before.clone();
        after.max_uses = 5;
        after.flags = srvsvc::flags::CSC_NONE | srvsvc::flags::ACCESS_BASED_DIRECTORY_ENUM;
        after.remark = "y".into();
        let changes = registry_changes(&after, &read);
        assert_eq!(
            changes,
            [
                ("comment".to_owned(), Some("y".to_owned())),
                ("max connections".to_owned(), Some("5".to_owned())),
                ("csc policy".to_owned(), Some("disable".to_owned())),
                ("access based share enum".to_owned(), Some("yes".to_owned())),
            ]
        );
        // Never a parameter outside the list.
        assert!(changes.iter().all(|(n, _)| winreg::allowed(n)));
        // The undo: the values absent before are removed, the comment put back.
        let mut now = read.clone();
        for (n, v) in &changes {
            match now.iter_mut().find(|(m, _)| m == n) {
                Some(slot) => slot.1 = v.clone().unwrap(),
                None => now.push((n.clone(), v.clone().unwrap())),
            }
        }
        let undo = registry_changes(&before, &now);
        assert_eq!(
            undo,
            [
                ("comment".to_owned(), Some("x".to_owned())),
                ("max connections".to_owned(), None),
                ("csc policy".to_owned(), None),
                ("access based share enum".to_owned(), None),
            ]
        );
        // A value already saying what is wanted keeps its form.
        let yes = values(&[("path", "/srv/a"), ("access based share enum", "True")]);
        let mut s = spec("C:\\srv\\a", "", srvsvc::flags::ACCESS_BASED_DIRECTORY_ENUM);
        s.registry = Some(yes.clone());
        assert!(registry_changes(&s, &yes).is_empty());
    }

    #[test]
    fn creation_values_as_net_conf_then_the_options() {
        let mut s = spec("C:\\srv\\essai", "Essai", srvsvc::flags::CSC_AUTO);
        s.max_uses = 3;
        assert_eq!(
            creation_values(&s),
            values(&[
                ("path", "/srv/essai"),
                ("comment", "Essai"),
                ("guest ok", "no"),
                ("read only", "no"),
                ("max connections", "3"),
                ("csc policy", "documents"),
            ])
        );
        // An undo of a deletion: the values the key had, in their order.
        let had = values(&[
            ("path", "/srv/essai"),
            ("vfs objects", "acl_xattr full_audit"),
            ("max connections", "3"),
            ("csc policy", "documents"),
        ]);
        s.registry = Some(had.clone());
        s.remark = String::new();
        assert_eq!(creation_values(&s), had);
    }

    #[test]
    fn samba_paths() {
        assert_eq!(samba_path("C:\\srv\\partages\\Été"), "/srv/partages/Été");
        assert_eq!(samba_path("/srv/x"), "/srv/x");
        assert!(same_path("/srv/x", "C:\\srv\\X"));
        assert!(!same_path("D:\\srv\\x", "C:\\srv\\x"));
    }

    #[test]
    fn unchanged_sees_the_other_registry_values() {
        let read = values(&[("path", "/srv/a"), ("vfs objects", "acl_xattr")]);
        let mut expected = spec("C:\\srv\\a", "x", 0);
        expected.registry = Some(read.clone());
        let mut present = expected.clone();
        // A parameter of the list goes through the fields.
        present.registry = Some(values(&[
            ("path", "/srv/a"),
            ("vfs objects", "acl_xattr"),
            ("comment", "x"),
        ]));
        assert!(unchanged(&present, &expected));
        present.registry = Some(values(&[("path", "/srv/a"), ("vfs objects", "")]));
        assert!(!unchanged(&present, &expected));
        // A side without key: the fields alone.
        present.registry = None;
        assert!(unchanged(&present, &expected));
    }

    #[test]
    fn unchanged_is_strict() {
        let read = spec("C:\\a", "x", 0);
        assert!(unchanged(&spec("c:\\A", "x", 0), &read));
        assert!(!unchanged(&spec("C:\\a", "x", 0x10), &read));
        assert!(!unchanged(&spec("C:\\a", "z", 0), &read));
    }
}

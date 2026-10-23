// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Messages of the core shown to the user (preview of a changeset, remarks of an inverse).
//!
//! The core never formats them itself: it names them ([`Msg`]) and a [`Catalog`] gives
//! the text. In R2 the Python module renders them with the French `msgid` of the Python
//! core through `gettext` (ADR 0016, § 6); [`English`] is the source text of the Rust
//! version, which becomes the `msgid` in R4.

/// A message and its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// Value of a secret attribute.
    Masked,
    /// A text value with its FILETIME date.
    QuotedWithDate {
        text: String,
        date: String,
    },
    Quoted {
        text: String,
    },
    /// Binary value: first bytes in hexadecimal, ellipsis if cut, size.
    Hex {
        bytes: String,
        more: String,
        n: usize,
    },
    /// FILETIME 0 or maximum.
    Never,
    Ttl {
        ttl: u32,
    },
    Serial {
        serial: u32,
    },
    Rank {
        rank: String,
    },
    Dynamic,
    Replace {
        attribute: String,
        before: String,
        after: String,
    },
    Removed {
        attribute: String,
        value: String,
    },
    Added {
        attribute: String,
        value: String,
    },
    Bytes {
        n: usize,
    },
    CreateFolder {
        path: String,
    },
    DeleteFolder {
        path: String,
    },
    CreateFile {
        path: String,
    },
    ReplaceFile {
        path: String,
    },
    DeleteFile {
        path: String,
    },
    SetPermissions {
        path: String,
    },
    AddShare {
        unc: String,
    },
    ChangeShare {
        unc: String,
    },
    DeleteShare {
        unc: String,
    },
    DeleteShareKeepsFolder,
    /// Inheritance propagated under a folder of a share (ADR 0023 § 5).
    Propagate {
        path: String,
    },
    PropagationCount {
        n: usize,
    },
    PropagationReplace,
    /// The owner of every descendant replaced (J8.7), alone or with the DACL.
    PropagateOwner {
        path: String,
    },
    PropagationOwner {
        owner: String,
    },
    /// The auditing entries of the descendants recomputed (J8.7).
    PropagateAudit {
        path: String,
    },
    PropagationAudit {
        replace: bool,
    },
    PropagationBackup {
        file: String,
    },
    /// Descriptors of a propagation written back (`undo`) or again.
    PropagationRewrite {
        path: String,
        undo: bool,
    },
    SharePath {
        path: String,
    },
    ShareRemark {
        remark: String,
    },
    ShareMaxUses {
        n: u32,
    },
    ShareFlags {
        flags: u32,
    },
    Create {
        dn: String,
    },
    NoVersionCheck,
    Modify {
        dn: String,
    },
    Rename {
        dn: String,
        new_dn: String,
    },
    Delete {
        dn: String,
    },
    DeleteIrreversible,
    NoChange,
    Remarks,
    SecretNotRestored {
        attribute: String,
    },
    PwdLastSetNow,
    RecreatedWithPermissions {
        dn: String,
    },
    RecreatedNew {
        dn: String,
    },
    SecretNotJournaled {
        attribute: String,
    },
    RecreatedDisabled {
        dn: String,
    },
    /// Beginning of a remark on the SOA of a zone (DNS, J3.4).
    DnsZone {
        zone: String,
    },
    DnsSerial {
        before: u32,
        after: u32,
    },
    DnsSoaNotWritable {
        serial: u32,
    },
    DnsBackInService {
        name: String,
    },
    DnsTombstoned {
        name: String,
    },
    DnsSoaNotRestored,
    DnsUndoCreation {
        name: String,
    },
    /// Remarks of the changesets of the group policies (`actions_gpo`, `sauvegarde_gpo`).
    GpoCreated {
        name: String,
        guid: String,
    },
    GpoAclReset {
        name: String,
        n: usize,
    },
    GpoNobodyApplies,
    GpoAuthenticatedUsersCannotRead,
    GpoDeleted {
        name: String,
        guid: String,
        links: usize,
        items: usize,
    },
    GpoFolderAbsent,
    GpoOrphansRemoved {
        list: String,
    },
    GpoOrphanDeleted {
        name: String,
        dc: String,
        items: usize,
    },
    GpoOrphanLinks {
        n: usize,
    },
    GpoCopy {
        name: String,
        old: String,
        guid: String,
    },
    GpoRecreated {
        name: String,
        guid: String,
        date: String,
    },
    GpoBackupLinks {
        links: String,
    },
    GpoRestored {
        name: String,
        date: String,
        version: i64,
        user: i64,
        computer: i64,
    },
    /// Remarks of a write of the content of a GPO (R4.9, `ecrire_contenus`).
    GpoContentVersion {
        part: crate::gpo::Part,
        name: String,
        before: i64,
        after: i64,
    },
    GpoPartDisabled {
        part: crate::gpo::Part,
    },
    GpoVersionsDiffered {
        directory: i64,
        sysvol: i64,
    },
    /// Remarks of the security settings (R4.9, `strategie_securite`).
    GpoSecurityNotAtRoot,
    GpoSecurityPdcApplies,
    GpoSecuritySamba,
    /// `keys`: the keys of `[System Access]` set aside (the interface names them).
    GpoSecurityPrior {
        names: String,
        keys: Vec<String>,
    },
}

fn part_name(part: crate::gpo::Part) -> &'static str {
    match part {
        crate::gpo::Part::Computer => "Computer Configuration",
        crate::gpo::Part::User => "User Configuration",
    }
}

fn versions_text(version: i64) -> String {
    let v = crate::gpo::versions(version);
    format!("user {}, computer {}", v.user, v.computer)
}

/// Gives the text of a message.
pub trait Catalog {
    fn text(&self, msg: &Msg) -> String;
}

/// The English source texts.
#[derive(Debug, Clone, Copy, Default)]
pub struct English;

impl Catalog for English {
    fn text(&self, msg: &Msg) -> String {
        match msg {
            Msg::Masked => "<hidden>".into(),
            Msg::QuotedWithDate { text, date } => format!("“{text}” ({date})"),
            Msg::Quoted { text } => format!("“{text}”"),
            Msg::Hex { bytes, more, n } => format!("0x{bytes}{more} ({n} bytes)"),
            Msg::Never => "never".into(),
            Msg::Ttl { ttl } => format!("TTL {ttl}"),
            Msg::Serial { serial } => format!("serial {serial}"),
            Msg::Rank { rank } => format!("rank {rank}"),
            Msg::Dynamic => "dynamic".into(),
            Msg::Replace {
                attribute,
                before,
                after,
            } => format!("{attribute}: {before} → {after}"),
            Msg::Removed { attribute, value } => format!("{attribute}: − {value}"),
            Msg::Added { attribute, value } => format!("{attribute}: + {value}"),
            Msg::Bytes { n } => format!("{n} bytes"),
            Msg::CreateFolder { path } => format!("Create the folder {path}"),
            Msg::DeleteFolder { path } => format!("Delete the folder {path}"),
            Msg::CreateFile { path } => format!("Create the file {path}"),
            Msg::ReplaceFile { path } => format!("Replace the file {path}"),
            Msg::DeleteFile { path } => format!("Delete the file {path}"),
            Msg::SetPermissions { path } => format!("Change the permissions of {path}"),
            Msg::AddShare { unc } => format!("Create the share {unc}"),
            Msg::ChangeShare { unc } => format!("Change the share {unc}"),
            Msg::DeleteShare { unc } => format!("Delete the share {unc}"),
            Msg::DeleteShareKeepsFolder => "The folder and its content stay on the server.".into(),
            Msg::Propagate { path } => format!("Propagate the inheritance under {path}"),
            Msg::PropagationCount { n } => format!("{n} elements under the folder examined"),
            Msg::PropagationReplace => {
                "The permissions of every descendant are replaced by the inherited ones.".into()
            }
            Msg::PropagateOwner { path } => format!("Replace the owner under {path}"),
            Msg::PropagationOwner { owner } => {
                format!("owner of every element under the folder: {owner}")
            }
            Msg::PropagateAudit { path } => {
                format!("Propagate the auditing entries under {path}")
            }
            Msg::PropagationAudit { replace: false } => {
                "auditing entries inherited computed again".into()
            }
            Msg::PropagationAudit { replace: true } => {
                "auditing entries of every descendant replaced by the inherited ones".into()
            }
            Msg::PropagationBackup { file } => format!("backup: {file}"),
            Msg::PropagationRewrite { path, undo: true } => {
                format!("Write back the permissions saved under {path}")
            }
            Msg::PropagationRewrite { path, undo: false } => {
                format!("Write again the permissions propagated under {path}")
            }
            Msg::SharePath { path } => format!("path: {path}"),
            Msg::ShareRemark { remark } => format!("comment: {remark}"),
            Msg::ShareMaxUses { n } => format!("at most {n} connections"),
            Msg::ShareFlags { flags } => format!("options: 0x{flags:08X}"),
            Msg::Create { dn } => format!("Create {dn}"),
            Msg::NoVersionCheck => "(no version check)".into(),
            Msg::Modify { dn } => format!("Modify {dn}"),
            Msg::Rename { dn, new_dn } => format!("Rename or move {dn} → {new_dn}"),
            Msg::Delete { dn } => format!("Delete {dn}"),
            Msg::DeleteIrreversible => "Not reversible as it is: undoing creates a new object \
(new objectGUID and objectSid, password and permissions not restored)."
                .into(),
            Msg::NoChange => "No change.".into(),
            Msg::Remarks => "Remarks:".into(),
            Msg::SecretNotRestored { attribute } => {
                format!("{attribute}: previous value unknown (secret), not restored.")
            }
            Msg::PwdLastSetNow => {
                "pwdLastSet: the previous date cannot be restored, it becomes “now”.".into()
            }
            Msg::RecreatedWithPermissions { dn } => format!(
                "{dn} will be recreated as a new object (new objectGUID), with its original \
permissions."
            ),
            Msg::RecreatedNew { dn } => format!(
                "{dn} will be recreated as a new object: new objectGUID and objectSid; the \
permissions that named the old SID, the security descriptor, the password and the primary group \
are not restored."
            ),
            Msg::SecretNotJournaled { attribute } => {
                format!("{attribute}: secret not journaled, not restored.")
            }
            Msg::RecreatedDisabled { dn } => {
                format!("{dn} will be recreated disabled: its password is lost.")
            }
            Msg::DnsZone { zone } => format!("Zone {zone}: "),
            Msg::DnsSerial { before, after } => format!(
                "serial number {before} → {after}. If it changes before the write (another \
write in the zone), the tool reads it again and starts over."
            ),
            Msg::DnsSoaNotWritable { serial } => format!(
                "your account cannot modify the SOA: the records are written without \
incrementing the serial number ({serial}). The DCs replicate the zone without using it; a \
conventional secondary server (zone transfer) will only see the change at an administrator's \
next write."
            ),
            Msg::DnsBackInService { name } => {
                format!("{name} was a tombstone: it is brought back into service.")
            }
            Msg::DnsTombstoned { name } => format!(
                "{name}: last record removed, the name becomes a tombstone (the object stays in \
the directory, as with the DNS server)."
            ),
            Msg::DnsSoaNotRestored => {
                "The SOA serial number is not restored: it is incremented again.".into()
            }
            Msg::DnsUndoCreation { name } => format!(
                "{name}: undoing its creation turns it into a tombstone instead of deleting the \
object, which the Windows DNS server would not see disappear."
            ),
            Msg::GpoCreated { name, guid } => format!(
                "GPO “{name}”: {guid}, not linked; link it afterwards to a domain or an OU."
            ),
            Msg::GpoAclReset { name, n } => format!(
                "Permissions of the “{name}” folder reset from those of the GPO, on {n} item(s), \
like samba-tool ntacl sysvolreset."
            ),
            Msg::GpoNobodyApplies => {
                "No account or group applies this GPO any more: it applies to nobody.".into()
            }
            Msg::GpoAuthenticatedUsersCannotRead => "Authenticated Users can no longer read the \
GPO: since MS16-072, computers read user GPOs under their own account, and a GPO they cannot \
read is not applied. Leave them at least Read (or give it to Domain Computers)."
                .into(),
            Msg::GpoDeleted {
                name,
                guid,
                links,
                items,
            } => format!("GPO “{name}” ({guid}): {links} link(s) removed, {items} SYSVOL item(s)."),
            Msg::GpoFolderAbsent => "The GPO folder is missing from this DC's SYSVOL.".into(),
            Msg::GpoOrphansRemoved { list } => format!(
                "SYSVOL folders without a GPO in the directory (interrupted creation or \
deletion): {list}. Undoing puts them back as they were."
            ),
            Msg::GpoOrphanDeleted { name, dc, items } => format!(
                "Folder without a GPO “{name}”: no Group Policy Object in the directory has this \
GUID (read again on {dc}). {items} item(s) deleted with their contents and permissions; undoing \
recreates them exactly."
            ),
            Msg::GpoOrphanLinks { n } => format!(
                "{n} container(s) keep a link to this GUID: they are not changed (link to a \
missing GPO)."
            ),
            Msg::GpoCopy { name, old, guid } => {
                format!("Copy of “{name}” ({old}) under a new GUID: {guid}.")
            }
            Msg::GpoRecreated { name, guid, date } => {
                format!("GPO “{name}” recreated under its GUID {guid}, from the backup of {date}.")
            }
            Msg::GpoBackupLinks { links } => {
                format!("Links at the time of the backup (not restored, like the GPMC): {links}.")
            }
            Msg::GpoRestored {
                name,
                date,
                version,
                user,
                computer,
            } => format!(
                "GPO “{name}” brought back to its backup of {date}; version raised to {version} \
(user {user}, computer {computer}) so that computers apply it again."
            ),
            Msg::GpoContentVersion {
                part,
                name,
                before,
                after,
            } => format!(
                "{} of “{name}”: version {before} → {after}, in the directory and GPT.INI.",
                part_name(*part)
            ),
            Msg::GpoPartDisabled { part } => format!(
                "The {} of this GPO is disabled: this setting will not apply as long as it stays so.",
                part_name(*part).to_lowercase()
            ),
            Msg::GpoSecurityNotAtRoot => "This GPO is not linked to the root of the domain: its \
password and lockout policy only holds for the local accounts of the computers where it applies, \
not for the accounts of the domain."
                .into(),
            Msg::GpoSecurityPdcApplies => "Linked to the root of the domain: the PDC emulator \
will carry the account policy over to the domain object at its next refresh of the security \
policy."
                .into(),
            Msg::GpoSecuritySamba => "Samba does not apply the account policy of a GPO itself: \
the domain object gets the same values, as samba-tool domain passwordsettings set would do."
                .into(),
            Msg::GpoSecurityPrior { names, keys } => format!(
                "Also defined by a GPO of higher precedence linked to the domain ({names}), these \
settings stay those of the domain object: {}.",
                keys.join(", ")
            ),
            Msg::GpoVersionsDiffered { directory, sysvol } => format!(
                "The versions of the directory ({}) and of GPT.INI ({}) differed: the highest \
was used, both are equal again.",
                versions_text(*directory),
                versions_text(*sysvol)
            ),
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the « Shares » window (ADR 0023): kinds and options of a share, permissions of a
//! share and of a file or folder in the words of Windows (« Read », « Change », « Full
//! control », « Modify », « Read & execute »…), what an ACE applies to. No widget here: the
//! window (`shares`) and the dialogs use these texts, the tests check them.

use std::collections::HashMap;

use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::sid::Sid;
use annuaire_core::security::SidName;
use annuaire_core::srvsvc::{Share, flags, stype};

use crate::i18n::{fill, tr, tr_ctx};
use crate::security_views::sid_name;

pub type Names = HashMap<Sid, SidName>;

// --- Access masks of files (MS-DTYP 2.4.3, MS-SMB2 2.2.13.1.1) -----------------------------------

pub const READ_DATA: u32 = 0x0000_0001;
pub const WRITE_DATA: u32 = 0x0000_0002;
pub const APPEND_DATA: u32 = 0x0000_0004;
pub const READ_EA: u32 = 0x0000_0008;
pub const WRITE_EA: u32 = 0x0000_0010;
pub const EXECUTE: u32 = 0x0000_0020;
pub const DELETE_CHILD: u32 = 0x0000_0040;
pub const READ_ATTRIBUTES: u32 = 0x0000_0080;
pub const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;

/// The basic permissions of the « Security » tab of Windows, from the strongest.
pub const FULL: u32 = 0x001F_01FF;
pub const MODIFY: u32 = 0x0013_01BF;
pub const READ_EXECUTE: u32 = 0x0012_00A9;
pub const READ: u32 = 0x0012_0089;
pub const WRITE: u32 = 0x0010_0116;

/// Permissions of a share: « Change » is Modify plus Delete child in Samba's form.
pub const SHARE_CHANGE: u32 = MODIFY;
pub const SHARE_READ: u32 = READ_EXECUTE;

const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;

/// Generic rights as file rights (MS-DTYP 2.4.3, the mapping of files).
pub fn file_mask(mask: u32) -> u32 {
    let mut out = mask & !(GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ);
    if mask & GENERIC_ALL != 0 {
        out |= FULL;
    }
    if mask & GENERIC_READ != 0 {
        out |= READ;
    }
    if mask & GENERIC_WRITE != 0 {
        out |= WRITE;
    }
    if mask & GENERIC_EXECUTE != 0 {
        out |= READ_ATTRIBUTES | EXECUTE | READ_CONTROL | SYNCHRONIZE;
    }
    out
}

/// The share permission a mask gives: Full control, Change, Read, or none of the three.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareLevel {
    Full,
    Change,
    Read,
    Special,
}

pub fn share_level(mask: u32) -> ShareLevel {
    let m = file_mask(mask);
    if m & FULL == FULL {
        ShareLevel::Full
    } else if m & SHARE_CHANGE == SHARE_CHANGE {
        ShareLevel::Change
    } else if m & SHARE_READ == SHARE_READ {
        ShareLevel::Read
    } else {
        ShareLevel::Special
    }
}

pub fn share_level_text(level: ShareLevel) -> String {
    match level {
        ShareLevel::Full => tr("Full control"),
        ShareLevel::Change => tr("Change"),
        // « Lire » in the « Share » tab of Windows, « Lecture » in the « Security » tab.
        ShareLevel::Read => tr_ctx("share permission", "Read"),
        ShareLevel::Special => tr("Special permissions"),
    }
}

/// The mask written for a share permission (the form of Windows).
pub fn share_level_mask(level: ShareLevel) -> u32 {
    match level {
        ShareLevel::Full => FULL,
        ShareLevel::Change => SHARE_CHANGE,
        ShareLevel::Read | ShareLevel::Special => SHARE_READ,
    }
}

/// The basic permission of a file mask, as the « Security » tab of Windows names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileLevel {
    Full,
    Modify,
    ReadExecute,
    Read,
    Write,
    Special,
}

pub const FILE_LEVELS: [FileLevel; 5] = [
    FileLevel::Full,
    FileLevel::Modify,
    FileLevel::ReadExecute,
    FileLevel::Read,
    FileLevel::Write,
];

pub fn file_level(mask: u32) -> FileLevel {
    let m = file_mask(mask);
    if m & FULL == FULL {
        FileLevel::Full
    } else if m & MODIFY == MODIFY {
        FileLevel::Modify
    } else if m == READ_EXECUTE || m & !SYNCHRONIZE == READ_EXECUTE & !SYNCHRONIZE {
        FileLevel::ReadExecute
    } else if m == READ || m & !SYNCHRONIZE == READ & !SYNCHRONIZE {
        FileLevel::Read
    } else if m == WRITE || m & !SYNCHRONIZE == WRITE & !SYNCHRONIZE {
        FileLevel::Write
    } else {
        FileLevel::Special
    }
}

pub fn file_level_text(level: FileLevel) -> String {
    match level {
        FileLevel::Full => tr("Full control"),
        FileLevel::Modify => tr("Modify"),
        FileLevel::ReadExecute => tr("Read & execute"),
        FileLevel::Read => tr("Read"),
        FileLevel::Write => tr("Write"),
        FileLevel::Special => tr("Special permissions"),
    }
}

pub fn file_level_mask(level: FileLevel) -> u32 {
    match level {
        FileLevel::Full => FULL,
        FileLevel::Modify => MODIFY,
        FileLevel::ReadExecute | FileLevel::Special => READ_EXECUTE,
        FileLevel::Read => READ,
        FileLevel::Write => WRITE,
    }
}

/// The fine rights of a mask, each named, for « Special permissions ».
pub fn fine_rights(mask: u32, folder: bool) -> Vec<String> {
    let m = file_mask(mask);
    let names: [(u32, String); 13] = [
        (
            READ_DATA,
            if folder {
                tr("List folder")
            } else {
                tr("Read data")
            },
        ),
        (
            WRITE_DATA,
            if folder {
                tr("Create files")
            } else {
                tr("Write data")
            },
        ),
        (
            APPEND_DATA,
            if folder {
                tr("Create folders")
            } else {
                tr("Append data")
            },
        ),
        (READ_EA, tr("Read extended attributes")),
        (WRITE_EA, tr("Write extended attributes")),
        (
            EXECUTE,
            if folder {
                tr("Traverse folder")
            } else {
                tr("Execute file")
            },
        ),
        (DELETE_CHILD, tr("Delete subfolders and files")),
        (READ_ATTRIBUTES, tr("Read attributes")),
        (WRITE_ATTRIBUTES, tr("Write attributes")),
        (DELETE, tr("Delete")),
        (READ_CONTROL, tr("Read permissions")),
        (WRITE_DAC, tr("Change permissions")),
        (WRITE_OWNER, tr("Take ownership")),
    ];
    names
        .into_iter()
        .filter(|(bit, _)| m & bit != 0)
        .map(|(_, name)| name)
        .collect()
}

// --- What an ACE applies to -------------------------------------------------------------------

const OI: u8 = sd::OBJECT_INHERIT_ACE;
const CI: u8 = sd::CONTAINER_INHERIT_ACE;
const NP: u8 = sd::NO_PROPAGATE_INHERIT_ACE;
const IO: u8 = sd::INHERIT_ONLY_ACE;

/// The choices of « Applies to » of Windows, for a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    ThisFolder,
    FolderSubfoldersFiles,
    FolderSubfolders,
    FolderFiles,
    SubfoldersFiles,
    Subfolders,
    Files,
}

pub const SCOPES: [Scope; 7] = [
    Scope::ThisFolder,
    Scope::FolderSubfoldersFiles,
    Scope::FolderSubfolders,
    Scope::FolderFiles,
    Scope::SubfoldersFiles,
    Scope::Subfolders,
    Scope::Files,
];

pub fn scope_of(flags: u8) -> Scope {
    match (flags & IO != 0, flags & CI != 0, flags & OI != 0) {
        (false, false, false) | (true, false, false) => Scope::ThisFolder,
        (false, true, true) => Scope::FolderSubfoldersFiles,
        (false, true, false) => Scope::FolderSubfolders,
        (false, false, true) => Scope::FolderFiles,
        (true, true, true) => Scope::SubfoldersFiles,
        (true, true, false) => Scope::Subfolders,
        (true, false, true) => Scope::Files,
    }
}

/// Inheritance flags of a scope (without `NP`, `ID` and the audit flags).
pub fn scope_flags(scope: Scope) -> u8 {
    match scope {
        Scope::ThisFolder => 0,
        Scope::FolderSubfoldersFiles => CI | OI,
        Scope::FolderSubfolders => CI,
        Scope::FolderFiles => OI,
        Scope::SubfoldersFiles => IO | CI | OI,
        Scope::Subfolders => IO | CI,
        Scope::Files => IO | OI,
    }
}

pub fn scope_text(scope: Scope) -> String {
    match scope {
        Scope::ThisFolder => tr("This folder only"),
        Scope::FolderSubfoldersFiles => tr("This folder, subfolders and files"),
        Scope::FolderSubfolders => tr("This folder and subfolders"),
        Scope::FolderFiles => tr("This folder and files"),
        Scope::SubfoldersFiles => tr("Subfolders and files only"),
        Scope::Subfolders => tr("Subfolders only"),
        Scope::Files => tr("Files only"),
    }
}

/// « Applies to » of an ACE: its scope on a folder, nothing on a file.
pub fn applies_to(ace: &Ace, folder: bool) -> String {
    if !folder {
        return String::new();
    }
    let mut text = scope_text(scope_of(ace.flags));
    if ace.flags & NP != 0 && ace.flags & (CI | OI) != 0 {
        text = fill(&tr("{portee} (one level)"), &[("portee", &text)]);
    }
    text
}

// --- Sentences --------------------------------------------------------------------------------

/// One permission of a share: « Everyone: Read », « Domain Users: denied Change ».
pub fn share_ace_sentence(ace: &Ace, names: Option<&Names>) -> String {
    let who = ace
        .sid()
        .map_or_else(|| tr("(unknown)"), |s| sid_name(&s, names));
    let level = share_level_text(share_level(ace.mask()));
    let key = if ace.is_deny() {
        tr("{qui}: denied {droit}")
    } else {
        tr("{qui}: {droit}")
    };
    fill(&key, &[("qui", &who), ("droit", &level)])
}

/// The permissions of a share in one line; a share without descriptor is open to all, on
/// Windows as on Samba.
pub fn share_permissions_summary(descriptor: Option<&[u8]>, names: Option<&Names>) -> String {
    let Some(bytes) = descriptor else {
        return tr("Everyone: Full control (no permissions set on the share)");
    };
    let Ok(d) = SecurityDescriptor::decode(bytes) else {
        return tr("Unreadable permissions");
    };
    let Some(dacl) = d.dacl.as_ref() else {
        return tr("Everyone: Full control (no list of permissions)");
    };
    if dacl.aces.is_empty() {
        return tr("Nobody (empty list of permissions)");
    }
    dacl.aces
        .iter()
        .filter(|a| a.is_readable())
        .map(|a| share_ace_sentence(a, names))
        .collect::<Vec<_>>()
        .join(" ; ")
}

/// One permission of a file or folder: who, allowed or denied, the basic permission, what it
/// applies to, inherited or not.
pub fn file_ace_sentence(ace: &Ace, folder: bool, names: Option<&Names>) -> String {
    let who = ace
        .sid()
        .map_or_else(|| tr("(unknown)"), |s| sid_name(&s, names));
    let level = file_level(ace.mask());
    let right = if level == FileLevel::Special {
        fill(
            &tr("special permissions ({droits})"),
            &[("droits", &fine_rights(ace.mask(), folder).join(", "))],
        )
    } else {
        file_level_text(level)
    };
    let key = if ace.is_deny() {
        tr("{qui}: denied {droit}")
    } else {
        tr("{qui}: {droit}")
    };
    let mut text = fill(&key, &[("qui", &who), ("droit", &right)]);
    let scope = applies_to(ace, folder);
    if !scope.is_empty() {
        text = format!("{text} — {scope}");
    }
    if ace.is_inherited() {
        text = fill(&tr("{texte} (inherited)"), &[("texte", &text)]);
    }
    text
}

// --- The « Security » tab of a file or folder (J8.4) ---------------------------------------------

/// The permission of an ACE in words: its basic permission, or « Special permissions » with
/// the fine rights.
pub fn file_right_text(mask: u32, folder: bool) -> String {
    let level = file_level(mask);
    if level == FileLevel::Special {
        fill(
            &tr("Special permissions: {droits}"),
            &[("droits", &fine_rights(mask, folder).join(", "))],
        )
    } else {
        file_level_text(level)
    }
}

/// What a row of the « Security » tab says under its principal: allowed or denied, the
/// permission, what it applies to (folders), and whether it is inherited and from where.
pub fn file_entry_subtitle(ace: &Ace, folder: bool, source: Option<&str>) -> String {
    let mut parts = vec![
        if ace.is_deny() {
            tr("Deny")
        } else {
            tr("Allow")
        },
        file_right_text(ace.mask(), folder),
    ];
    let scope = applies_to(ace, folder);
    if !scope.is_empty() {
        parts.push(scope);
    }
    parts.push(match (ace.is_inherited(), source) {
        (false, _) => tr("explicit"),
        (true, Some(from)) => fill(&tr("inherited from {source}"), &[("source", from)]),
        (true, None) => tr("inherited from above the share"),
    });
    parts.join(" · ")
}

/// The kind of an auditing entry (J8.7), as the « Auditing » tab of Windows: success,
/// failure, or both (« All »).
pub fn audit_type_text(flags: u8) -> String {
    let success = flags & sd::SUCCESSFUL_ACCESS_ACE != 0;
    let failure = flags & sd::FAILED_ACCESS_ACE != 0;
    match (success, failure) {
        (true, true) => tr("All (auditing)"),
        (false, true) => tr("Failure"),
        _ => tr("Success"),
    }
}

/// What an auditing entry says: its kind, the rights audited, where it applies, where it
/// comes from.
pub fn audit_entry_subtitle(ace: &Ace, folder: bool, source: Option<&str>) -> String {
    let mut parts = vec![
        audit_type_text(ace.flags),
        file_right_text(ace.mask(), folder),
    ];
    let scope = applies_to(ace, folder);
    if !scope.is_empty() {
        parts.push(scope);
    }
    parts.push(match (ace.is_inherited(), source) {
        (false, _) => tr("explicit"),
        (true, Some(from)) => fill(&tr("inherited from {source}"), &[("source", from)]),
        (true, None) => tr("inherited from above the share"),
    });
    parts.join(" · ")
}

/// The state of the inheritance of an element, in one sentence.
pub fn inheritance_text(protected: bool, root: bool) -> String {
    match (protected, root) {
        (true, _) => tr(
            "Inheritance is disabled: only the explicit entries apply, nothing comes from the parent folder.",
        ),
        (false, true) => tr(
            "The entries inherited from the folder above the share apply; it cannot be read from here.",
        ),
        (false, false) => tr("The entries inherited from the parent folder apply."),
    }
}

/// The entry Windows offers for a principal just added: allow « Read & execute », on this
/// folder, its subfolders and files.
pub fn new_entry(sid: &Sid, folder: bool) -> Option<Ace> {
    let flags = if folder {
        scope_flags(Scope::FolderSubfoldersFiles)
    } else {
        0
    };
    Ace::simple(sd::ACCESS_ALLOWED, READ_EXECUTE, sid, flags).ok()
}

/// An explicit entry built from the choices of the entry dialog.
pub fn entry_ace(deny: bool, mask: u32, scope: Scope, one_level: bool, sid: &Sid) -> Option<Ace> {
    let mut flags = scope_flags(scope);
    if one_level && flags & (CI | OI) != 0 {
        flags |= NP;
    }
    let kind = if deny {
        sd::ACCESS_DENIED
    } else {
        sd::ACCESS_ALLOWED
    };
    Ace::simple(kind, mask, sid, flags).ok()
}

/// The fine rights of the entry dialog, in the order of Windows.
pub const FINE_RIGHTS: [u32; 13] = [
    EXECUTE,
    READ_DATA,
    READ_ATTRIBUTES,
    READ_EA,
    WRITE_DATA,
    APPEND_DATA,
    WRITE_ATTRIBUTES,
    WRITE_EA,
    DELETE_CHILD,
    DELETE,
    READ_CONTROL,
    WRITE_DAC,
    WRITE_OWNER,
];

/// The name of one fine right (a single bit of `FINE_RIGHTS`).
pub fn fine_right_text(bit: u32, folder: bool) -> String {
    fine_rights(bit, folder)
        .into_iter()
        .next()
        .unwrap_or_default()
}

// --- Editing the permissions of a share -------------------------------------------------------

/// A group or account of the « Share » tab: the level allowed and the level denied (`None`:
/// none). `allow_mask` and `deny_mask` keep the masks read, written back as they were when
/// the level does not change (Samba's « Change » is not the one of Windows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareEntry {
    pub sid: Sid,
    pub allow: Option<ShareLevel>,
    pub deny: Option<ShareLevel>,
    allow_mask: u32,
    deny_mask: u32,
}

impl ShareEntry {
    pub fn new(sid: Sid, allow: Option<ShareLevel>) -> Self {
        Self {
            sid,
            allow,
            deny: None,
            allow_mask: allow.map_or(0, share_level_mask),
            deny_mask: 0,
        }
    }

    fn mask(level: Option<ShareLevel>, read: u32) -> u32 {
        match level {
            None => 0,
            Some(l) if read != 0 && share_level(read) == l => read,
            Some(l) => share_level_mask(l),
        }
    }
}

/// The groups and accounts of a share's descriptor, in the order of their first ACE; no
/// descriptor: Everyone, Full control. ACEs that are neither allowed nor denied simple ACEs
/// are left aside (`share_descriptor` keeps them).
pub fn share_entries(descriptor: Option<&[u8]>) -> Vec<ShareEntry> {
    let Some(bytes) = descriptor else {
        return vec![ShareEntry::new(sd::everyone(), Some(ShareLevel::Full))];
    };
    let Ok(d) = SecurityDescriptor::decode(bytes) else {
        return Vec::new();
    };
    let mut entries: Vec<ShareEntry> = Vec::new();
    for ace in d.dacl.iter().flat_map(|a| &a.aces) {
        let simple = matches!(ace.ace_type, sd::ACCESS_ALLOWED | sd::ACCESS_DENIED);
        let Some(sid) = ace.sid().filter(|_| simple) else {
            continue;
        };
        let index = match entries.iter().position(|e| e.sid == sid) {
            Some(i) => i,
            None => {
                entries.push(ShareEntry {
                    sid,
                    allow: None,
                    deny: None,
                    allow_mask: 0,
                    deny_mask: 0,
                });
                entries.len() - 1
            }
        };
        let Some(entry) = entries.get_mut(index) else {
            continue;
        };
        if ace.is_deny() {
            entry.deny_mask |= ace.mask();
            entry.deny = Some(share_level(entry.deny_mask));
        } else {
            entry.allow_mask |= ace.mask();
            entry.allow = Some(share_level(entry.allow_mask));
        }
    }
    entries
}

/// The descriptor written for `entries`: owner, group and control of `origin` kept, the denied
/// ACEs first, then the allowed ones (the canonical order), then the ACEs `share_entries`
/// left aside.
pub fn share_descriptor(origin: Option<&[u8]>, entries: &[ShareEntry]) -> Option<Vec<u8>> {
    let origin = origin.and_then(|b| SecurityDescriptor::decode(b).ok());
    let others: Vec<Ace> = origin
        .as_ref()
        .and_then(|d| d.dacl.as_ref())
        .map(|a| {
            a.aces
                .iter()
                .filter(|x| !matches!(x.ace_type, sd::ACCESS_ALLOWED | sd::ACCESS_DENIED))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let mut aces = Vec::new();
    for e in entries {
        let mask = ShareEntry::mask(e.deny, e.deny_mask);
        if mask != 0 {
            aces.push(Ace::simple(sd::ACCESS_DENIED, mask, &e.sid, 0).ok()?);
        }
    }
    for e in entries {
        let mask = ShareEntry::mask(e.allow, e.allow_mask);
        if mask != 0 {
            aces.push(Ace::simple(sd::ACCESS_ALLOWED, mask, &e.sid, 0).ok()?);
        }
    }
    aces.extend(others);
    let (owner, group, control) = origin.map_or((None, None, 0), |d| (d.owner, d.group, d.control));
    SecurityDescriptor {
        revision: 1,
        control: control | sd::SE_SELF_RELATIVE | sd::SE_DACL_PRESENT,
        owner,
        group,
        sacl: None,
        dacl: Some(sd::Acl {
            revision: sd::ACL_REVISION,
            aces,
        }),
    }
    .encode()
    .ok()
}

/// The levels offered in the « Allow » and « Deny » choices, after « None ».
pub const SHARE_LEVELS: [ShareLevel; 3] = [ShareLevel::Read, ShareLevel::Change, ShareLevel::Full];

// --- Shares -----------------------------------------------------------------------------------

pub fn kind_text(share: &Share) -> String {
    let base = match share.kind & stype::BASE {
        stype::DISKTREE => tr("Folder"),
        stype::PRINTQ => tr("Printer"),
        stype::DEVICE => tr("Device"),
        stype::IPC => tr("Interprocess communication"),
        _ => tr("Other"),
    };
    if share.is_special() {
        fill(&tr("{genre}, administrative"), &[("genre", &base)])
    } else {
        base
    }
}

/// The options of `SHARE_INFO_1005` in words.
pub fn flags_text(value: u32) -> String {
    let mut parts = vec![match value & flags::CSC_MASK {
        flags::CSC_MANUAL => tr("offline: files chosen by the user"),
        flags::CSC_AUTO => tr("offline: all files opened"),
        flags::CSC_VDO => tr("offline: all files opened, optimized for performance"),
        _ => tr("offline: none"),
    }];
    if value & flags::ACCESS_BASED_DIRECTORY_ENUM != 0 {
        parts.push(tr("access-based enumeration"));
    }
    if value & flags::ENCRYPT_DATA != 0 {
        parts.push(tr("encrypted access required"));
    }
    let known = flags::CSC_MASK | flags::ACCESS_BASED_DIRECTORY_ENUM | flags::ENCRYPT_DATA;
    if value & !known != 0 {
        parts.push(fill(
            &tr("other options 0x{valeur}"),
            &[("valeur", &format!("{:X}", value & !known))],
        ));
    }
    parts.join(", ")
}

/// Maximum connections: « no limit » or the number.
pub fn max_uses_text(n: u32) -> String {
    if n == u32::MAX {
        tr("no limit")
    } else {
        n.to_string()
    }
}

/// The share name Windows accepts: 1 to 80 characters, none of `"/\[]:|<>+=;,?*` nor a
/// control character.
pub fn share_name_problem(name: &str) -> Option<String> {
    let name = name.trim();
    if name.is_empty() {
        return Some(tr("The name is empty."));
    }
    if name.chars().count() > 80 {
        return Some(tr("The name is longer than 80 characters."));
    }
    if name
        .chars()
        .any(|c| c.is_control() || "\"/\\[]:|<>+=;,?*".contains(c))
    {
        return Some(tr("The name contains a character that Windows refuses."));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_levels_as_windows_and_samba_write_them() {
        assert_eq!(share_level(0x001F_01FF), ShareLevel::Full);
        assert_eq!(share_level(0x0013_01BF), ShareLevel::Change);
        assert_eq!(share_level(0x0013_01FF), ShareLevel::Change); // Samba's CHANGE
        assert_eq!(share_level(0x0012_00A9), ShareLevel::Read);
        assert_eq!(share_level(GENERIC_ALL), ShareLevel::Full);
        assert_eq!(share_level(0x0000_0001), ShareLevel::Special);
    }

    #[test]
    fn file_levels() {
        assert_eq!(file_level(FULL), FileLevel::Full);
        assert_eq!(file_level(MODIFY), FileLevel::Modify);
        assert_eq!(file_level(READ_EXECUTE), FileLevel::ReadExecute);
        assert_eq!(file_level(READ), FileLevel::Read);
        assert_eq!(file_level(WRITE), FileLevel::Write);
        assert_eq!(
            file_level(GENERIC_READ | GENERIC_EXECUTE),
            FileLevel::ReadExecute
        );
        assert_eq!(file_level(READ_DATA | DELETE), FileLevel::Special);
    }

    #[test]
    fn scopes_round_trip() {
        for scope in SCOPES {
            assert_eq!(scope_of(scope_flags(scope)), scope);
        }
        assert_eq!(
            scope_of(CI | OI | sd::INHERITED_ACE),
            Scope::FolderSubfoldersFiles
        );
    }

    fn sddl(text: &str) -> Vec<u8> {
        annuaire_codecs::sddl::sd_from_sddl(text, None, false)
            .unwrap()
            .encode()
            .unwrap()
    }

    fn sddl_of(bytes: &[u8]) -> String {
        annuaire_codecs::sddl::sd_to_sddl(&SecurityDescriptor::decode(bytes).unwrap(), None)
            .unwrap()
    }

    #[test]
    fn share_entries_and_back() {
        let read = sddl("O:BAG:BAD:(A;;0x1301ff;;;WD)(D;;0x1200a9;;;AN)(A;;FA;;;BA)");
        let mut entries = share_entries(Some(&read));
        assert_eq!(entries.len(), 3);
        assert_eq!(entries.first().unwrap().allow, Some(ShareLevel::Change));
        assert_eq!(entries.get(1).unwrap().deny, Some(ShareLevel::Read));
        // Unchanged: Samba's « Change » mask is kept; denied ACEs first.
        assert_eq!(
            sddl_of(&share_descriptor(Some(&read), &entries).unwrap()),
            "O:BAG:BAD:(D;;0x1200a9;;;AN)(A;;0x1301ff;;;WD)(A;;FA;;;BA)"
        );
        entries.first_mut().unwrap().allow = Some(ShareLevel::Read);
        entries.remove(1);
        assert_eq!(
            sddl_of(&share_descriptor(Some(&read), &entries).unwrap()),
            "O:BAG:BAD:(A;;0x1200a9;;;WD)(A;;FA;;;BA)"
        );
    }

    #[test]
    fn no_descriptor_is_everyone_full_control() {
        let entries = share_entries(None);
        assert_eq!(
            entries,
            vec![ShareEntry::new(sd::everyone(), Some(ShareLevel::Full))]
        );
        assert_eq!(
            sddl_of(&share_descriptor(None, &entries).unwrap()),
            "D:(A;;FA;;;WD)"
        );
        assert_eq!(sddl_of(&share_descriptor(None, &[]).unwrap()), "D:");
    }

    #[test]
    fn file_entries_in_words() {
        let ace = |t: &str| {
            annuaire_codecs::sddl::sd_from_sddl(&format!("D:{t}"), None, false)
                .unwrap()
                .dacl
                .unwrap()
                .aces
                .remove(0)
        };
        let a = ace("(A;OICIID;0x1301bf;;;AU)");
        let text = file_entry_subtitle(&a, true, Some("\\\\fs1\\Commun"));
        assert!(text.contains("Modify"), "{text}");
        assert!(text.contains("This folder, subfolders and files"), "{text}");
        assert!(text.contains("\\\\fs1\\Commun"), "{text}");
        let d = ace("(D;;0x50000;;;WD)");
        let text = file_entry_subtitle(&d, false, None);
        assert!(text.starts_with("Deny"), "{text}");
        assert!(text.contains("Special permissions"), "{text}");
        assert!(text.ends_with("explicit"), "{text}");
        let sid: Sid = "S-1-5-11".parse().unwrap();
        let built = entry_ace(false, MODIFY, Scope::SubfoldersFiles, true, &sid).unwrap();
        assert_eq!(built.flags, IO | CI | OI | NP);
        assert_eq!(new_entry(&sid, false).unwrap().flags, 0);
        assert_eq!(FINE_RIGHTS.iter().fold(0, |m, b| m | b) | SYNCHRONIZE, FULL);
    }

    #[test]
    fn share_names() {
        assert!(share_name_problem("Commun").is_none());
        assert!(share_name_problem("Été 2026$").is_none());
        assert!(share_name_problem("").is_some());
        assert!(share_name_problem("a/b").is_some());
        assert!(share_name_problem(&"x".repeat(81)).is_some());
    }
}

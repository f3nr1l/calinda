// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! NTFS permissions of the files and folders of a share (ADR 0023 § 5): the inheritance as
//! Windows computes it, the descriptor written as `SetSecurityInfo` writes it, and what the
//! « Security » tab needs to edit a DACL (canonical order, inheritance turned off or on, the
//! ancestor an inherited ACE comes from).
//!
//! Neither Windows nor Samba propagates a DACL written over SMB: `SetNamedSecurityInfo` does
//! it on the client, element by element. The rules are those of MS-DTYP 2.5.3.4.2
//! (`ComputeInheritedACLfromParent`) with the post-processing of
//! `CreatePrivateObjectSecurityEx`: an inheritable ACE of the parent gives a child folder an
//! ACE that applies to it (if `CI`) and one that passes on (unless `NP`), in one ACE when it
//! can; a child file gets the ACEs marked `OI`, without inheritance flags. `CREATOR OWNER` and
//! `CREATOR GROUP` become the owner and the group of the child, generic rights become file
//! rights, in the ACE that applies; the ACE that passes on keeps them, inherit-only.

use annuaire_codecs::sd::{self, Ace, Acl, SecurityDescriptor};
use annuaire_codecs::sid::Sid;

use crate::effective_access::map_generic;

const OI: u8 = sd::OBJECT_INHERIT_ACE;
const CI: u8 = sd::CONTAINER_INHERIT_ACE;
const NP: u8 = sd::NO_PROPAGATE_INHERIT_ACE;
const IO: u8 = sd::INHERIT_ONLY_ACE;
const ID: u8 = sd::INHERITED_ACE;
/// Audit flags, kept as they are (SACL only).
const AUDIT: u8 = sd::SUCCESSFUL_ACCESS_ACE | sd::FAILED_ACCESS_ACE;
const GENERIC: u32 = sd::GENERIC_ALL | sd::GENERIC_READ | sd::GENERIC_WRITE | sd::GENERIC_EXECUTE;

/// `CREATOR OWNER`, S-1-3-0.
pub fn creator_owner() -> Sid {
    Sid::new(3, &[0]).expect("S-1-3-0 is a valid SID")
}

/// `CREATOR GROUP`, S-1-3-1.
pub fn creator_group() -> Sid {
    Sid::new(3, &[1]).expect("S-1-3-1 is a valid SID")
}

/// An ACE that passes to children (`OI` or `CI`).
pub fn inheritable(ace: &Ace) -> bool {
    ace.flags & (OI | CI) != 0
}

/// The ACE as it applies to a child: `CREATOR OWNER` and `CREATOR GROUP` replaced by the owner
/// and the group of the child (when known), generic rights mapped to file rights. `None` when
/// nothing changes (or for an ACE whose layout is not a simple one: it is copied as it is).
fn applied(ace: &Ace, owner: Option<&Sid>, group: Option<&Sid>) -> Option<Ace> {
    let simple = matches!(
        ace.ace_type,
        sd::ACCESS_ALLOWED | sd::ACCESS_DENIED | sd::SYSTEM_AUDIT | sd::SYSTEM_ALARM
    );
    if !simple {
        return None;
    }
    let sid = ace.sid()?;
    let replaced = if sid == creator_owner() {
        owner.copied()
    } else if sid == creator_group() {
        group.copied()
    } else {
        None
    };
    let generic = ace.mask() & GENERIC != 0;
    if replaced.is_none() && !generic {
        return None;
    }
    Ace::simple(
        ace.ace_type,
        map_generic(ace.mask()),
        &replaced.unwrap_or(sid),
        ace.flags,
    )
    .ok()
}

/// Must an inheritable ACE be split in two, one that applies and one that passes on?
fn needs_split(ace: &Ace) -> bool {
    let creator = ace
        .sid()
        .is_some_and(|s| s == creator_owner() || s == creator_group());
    let simple = matches!(
        ace.ace_type,
        sd::ACCESS_ALLOWED | sd::ACCESS_DENIED | sd::SYSTEM_AUDIT | sd::SYSTEM_ALARM
    );
    simple && (creator || ace.mask() & GENERIC != 0)
}

fn with_flags(ace: &Ace, flags: u8) -> Ace {
    Ace {
        ace_type: ace.ace_type,
        flags,
        body: ace.body.clone(),
    }
}

/// The ACEs a child gets from the ACEs of its parent, in their order; `directory` for a
/// folder, `owner` and `group` of the child for `CREATOR OWNER` and `CREATOR GROUP`.
pub fn inherited_aces(
    parent: &[Ace],
    directory: bool,
    owner: Option<&Sid>,
    group: Option<&Sid>,
) -> Vec<Ace> {
    let mut out = Vec::new();
    for ace in parent.iter().filter(|a| inheritable(a)) {
        let audit = ace.flags & AUDIT;
        let (applies, passes) = if directory {
            (
                ace.flags & CI != 0,
                ace.flags & NP == 0 && ace.flags & (CI | OI) != 0,
            )
        } else {
            (ace.flags & OI != 0, false)
        };
        let effective = || {
            let ace = applied(ace, owner, group).unwrap_or_else(|| ace.clone());
            with_flags(&ace, ID | audit)
        };
        let passing = |io: u8| with_flags(ace, (ace.flags & (OI | CI)) | io | ID | audit);
        match (applies, passes) {
            (true, true) if !needs_split(ace) => add(&mut out, passing(0)),
            (true, true) => {
                add(&mut out, effective());
                add(&mut out, passing(IO));
            }
            (true, false) => add(&mut out, effective()),
            (false, true) => add(&mut out, passing(IO)),
            (false, false) => {}
        }
    }
    out
}

/// An inherited ACE is added as Windows adds it: left out when an ACE added before it already
/// gives as much to the same principal (same type, rights that hold its rights) wherever it
/// applies (to the child itself, to files, to folders, beyond one level). Seen on wdc1 and from
/// a workstation on fs1: `CREATOR OWNER` that becomes `BUILTIN\Administrators`, already
/// granted Full control; Read given by `CREATOR GROUP`, or to files only, to Domain Users
/// already granted Modify on everything.
fn add(out: &mut Vec<Ace>, ace: Ace) {
    let mask = map_generic(ace.mask());
    let covered = out.iter().any(|a| {
        let reaches = |flag: u8| ace.flags & flag == 0 || a.flags & flag != 0;
        a.ace_type == ace.ace_type
            && a.flags & AUDIT & ace.flags == ace.flags & AUDIT
            && a.sid().is_some()
            && a.sid() == ace.sid()
            && map_generic(a.mask()) & mask == mask
            && (ace.flags & IO != 0 || a.flags & IO == 0)
            && reaches(OI)
            && reaches(CI)
            && (ace.flags & (OI | CI) == 0 || ace.flags & NP != 0 || a.flags & NP == 0)
    });
    if !covered {
        out.push(ace);
    }
}

/// An explicit ACE added to `out`: joined to one of the same principal, type and flags (its
/// rights added), as the security editor of Windows does when an account already listed is
/// added again (J8.8); otherwise appended. Only ACEs of the simple layout (mask, SID, nothing
/// after) are joined; inherited ones are appended as they are.
pub fn merge_into(out: &mut Vec<Ace>, ace: Ace) {
    let joinable = |a: &Ace| {
        !a.is_inherited()
            && matches!(
                a.ace_type,
                sd::ACCESS_ALLOWED | sd::ACCESS_DENIED | sd::SYSTEM_AUDIT
            )
            && a.sid().is_some()
            && a.data().is_empty()
    };
    if joinable(&ace)
        && let Some(sid) = ace.sid()
        && let Some(same) = out.iter_mut().find(|a| {
            joinable(a)
                && a.ace_type == ace.ace_type
                && a.flags == ace.flags
                && a.sid() == Some(sid)
        })
        && let Ok(joined) = Ace::simple(ace.ace_type, same.mask() | ace.mask(), &sid, ace.flags)
    {
        *same = joined;
        return;
    }
    out.push(ace);
}

/// The explicit ACEs with those of the same principal, type and flags made one (`merge_into`):
/// what is written, as Windows writes it.
pub fn merged(aces: &[Ace]) -> Vec<Ace> {
    let mut out = Vec::with_capacity(aces.len());
    for ace in aces {
        merge_into(&mut out, ace.clone());
    }
    out
}

/// The DACL in the order of Windows: explicit denials, explicit allowances (each in their
/// order), then the inherited ACEs in their order.
pub fn canonical(aces: &[Ace]) -> Vec<Ace> {
    let explicit = aces.iter().filter(|a| !a.is_inherited());
    let mut out: Vec<Ace> = explicit.clone().filter(|a| a.is_deny()).cloned().collect();
    out.extend(explicit.filter(|a| !a.is_deny()).cloned());
    out.extend(aces.iter().filter(|a| a.is_inherited()).cloned());
    out
}

/// Is the DACL in canonical order? (Windows shows a warning otherwise.)
pub fn is_canonical(aces: &[Ace]) -> bool {
    canonical(aces) == aces
}

pub fn is_protected(descriptor: &SecurityDescriptor) -> bool {
    descriptor.control & sd::SE_DACL_PROTECTED != 0
}

fn dacl_aces(descriptor: &SecurityDescriptor) -> &[Ace] {
    descriptor.dacl.as_ref().map_or(&[], |a| a.aces.as_slice())
}

/// The ACEs of the DACL of a descriptor (none without a DACL).
pub fn dacl_of(descriptor: &SecurityDescriptor) -> Vec<Ace> {
    dacl_aces(descriptor).to_vec()
}

/// The explicit ACEs of a descriptor (not marked `ID`).
pub fn explicit_aces(descriptor: &SecurityDescriptor) -> Vec<Ace> {
    dacl_aces(descriptor)
        .iter()
        .filter(|a| !a.is_inherited())
        .cloned()
        .collect()
}

/// The inherited ACEs of a descriptor (marked `ID`).
pub fn inherited_of(descriptor: &SecurityDescriptor) -> Vec<Ace> {
    dacl_aces(descriptor)
        .iter()
        .filter(|a| a.is_inherited())
        .cloned()
        .collect()
}

/// The descriptor written for a DACL, as `SetSecurityInfo` writes it: DACL present,
/// automatically inherited, with `SE_DACL_AUTO_INHERIT_REQ` (without it, Windows and Samba
/// drop `AI` and the folders created afterwards get ACEs without `ID`, ADR 0023 § 5),
/// protected or not; owner and group of `origin`; no SACL (it is not written).
pub fn written(origin: &SecurityDescriptor, aces: Vec<Ace>, protected: bool) -> SecurityDescriptor {
    let mut control = sd::SE_SELF_RELATIVE
        | sd::SE_DACL_PRESENT
        | sd::SE_DACL_AUTO_INHERITED
        | sd::SE_DACL_AUTO_INHERIT_REQ;
    if protected {
        control |= sd::SE_DACL_PROTECTED;
    }
    let revision = origin
        .dacl
        .as_ref()
        .map_or(sd::ACL_REVISION, |a| a.revision.max(sd::ACL_REVISION));
    SecurityDescriptor {
        revision: sd::REVISION,
        control,
        owner: origin.owner,
        group: origin.group,
        sacl: None,
        dacl: Some(Acl { revision, aces }),
    }
}

/// The descriptor of an element whose explicit ACEs, inherited ACEs and protection are those
/// given: explicit ones merged (`merged`) in canonical order, then the inherited ones.
pub fn composed(
    origin: &SecurityDescriptor,
    explicit: &[Ace],
    inherited: &[Ace],
    protected: bool,
) -> SecurityDescriptor {
    let mut aces = canonical(&merged(explicit));
    aces.extend(inherited.iter().cloned());
    written(origin, aces, protected)
}

/// The descriptor of a child recomputed from its parent: unchanged if its DACL is protected
/// (unless `replace`); otherwise its explicit ACEs kept (none with `replace`, which also lifts
/// the protection) and its inherited ACEs recomputed.
pub fn recompute(
    child: &SecurityDescriptor,
    parent: &SecurityDescriptor,
    directory: bool,
    replace: bool,
) -> SecurityDescriptor {
    if is_protected(child) && !replace {
        return child.clone();
    }
    let explicit = if replace {
        Vec::new()
    } else {
        explicit_aces(child)
    };
    let inherited = inherited_aces(
        dacl_aces(parent),
        directory,
        child.owner.as_ref(),
        child.group.as_ref(),
    );
    let mut aces = explicit;
    aces.extend(inherited);
    written(child, aces, false)
}

/// The DACL of `a` gives what the one of `b` gives: same ACEs in the same order (`same_ace`),
/// same protection. Owner, group and the other control bits do not count (a Windows server
/// keeps `AI` as it computes it, neither keeps `SE_DACL_AUTO_INHERIT_REQ`).
pub fn same_permissions(a: &SecurityDescriptor, b: &SecurityDescriptor) -> bool {
    let (x, y) = (dacl_aces(a), dacl_aces(b));
    x.len() == y.len()
        && x.iter().zip(y).all(|(p, q)| same_ace(p, q))
        && is_protected(a) == is_protected(b)
}

/// Same ACE, generic rights taken as the file rights they stand for: Samba stores them mapped
/// (`GA` written, `FA` read back, even in an inherit-only ACE), Windows keeps them.
pub fn same_ace(a: &Ace, b: &Ace) -> bool {
    if a == b {
        return true;
    }
    let simple = matches!(
        a.ace_type,
        sd::ACCESS_ALLOWED | sd::ACCESS_DENIED | sd::SYSTEM_AUDIT
    );
    simple
        && a.ace_type == b.ace_type
        && a.flags == b.flags
        && a.sid().is_some()
        && a.sid() == b.sid()
        && map_generic(a.mask()) == map_generic(b.mask())
}

/// Does going from `before` to `after` change what the children of a folder inherit?
/// Computed on a child folder and a child file, the owner standing for itself.
pub fn changes_children(before: &SecurityDescriptor, after: &SecurityDescriptor) -> bool {
    [true, false].into_iter().any(|directory| {
        inherited_aces(dacl_aces(before), directory, None, None)
            != inherited_aces(dacl_aces(after), directory, None, None)
    })
}

/// Inheritance turned off, as Windows offers it: the inherited ACEs become explicit (`ID`
/// removed, each once), or are removed.
pub fn without_inheritance(descriptor: &SecurityDescriptor, convert: bool) -> SecurityDescriptor {
    let mut explicit = explicit_aces(descriptor);
    if convert {
        for ace in inherited_of(descriptor) {
            let ace = with_flags(&ace, ace.flags & !ID);
            if !explicit.contains(&ace) {
                explicit.push(ace);
            }
        }
    }
    composed(descriptor, &explicit, &[], true)
}

/// Inheritance turned on again: protection lifted, inherited ACEs recomputed from the parent
/// when it is known (the root of a share has no parent the client can read: its inherited
/// ACEs are kept).
pub fn with_inheritance(
    descriptor: &SecurityDescriptor,
    parent: Option<&SecurityDescriptor>,
    directory: bool,
) -> SecurityDescriptor {
    let inherited = match parent {
        Some(p) => inherited_aces(
            dacl_aces(p),
            directory,
            descriptor.owner.as_ref(),
            descriptor.group.as_ref(),
        ),
        None => inherited_of(descriptor),
    };
    composed(descriptor, &explicit_aces(descriptor), &inherited, false)
}

// --- The SACL (J8.7) ---------------------------------------------------------------------------

/// The ACEs of the SACL of a descriptor (none without a SACL, or one not read).
pub fn sacl_of(descriptor: &SecurityDescriptor) -> Vec<Ace> {
    descriptor
        .sacl
        .as_ref()
        .map_or_else(Vec::new, |a| a.aces.clone())
}

/// Was the SACL read with the descriptor (`SACL_SECURITY_INFORMATION`)? A server gives
/// `SE_SACL_PRESENT` then, even for an empty one.
pub fn has_sacl(descriptor: &SecurityDescriptor) -> bool {
    descriptor.control & sd::SE_SACL_PRESENT != 0 || descriptor.sacl.is_some()
}

/// A descriptor read with its SACL, marked so: a Windows server gives neither a SACL nor
/// `SE_SACL_PRESENT` for an element without auditing entries, which would not tell it from a
/// descriptor read without (the « before » of a write that must put back an empty SACL).
pub fn mark_sacl_read(descriptor: &mut SecurityDescriptor) {
    if descriptor.sacl.is_none() {
        descriptor.sacl = Some(Acl {
            revision: sd::ACL_REVISION,
            aces: Vec::new(),
        });
    }
    descriptor.control |= sd::SE_SACL_PRESENT;
}

pub fn is_sacl_protected(descriptor: &SecurityDescriptor) -> bool {
    descriptor.control & sd::SE_SACL_PROTECTED != 0
}

pub fn explicit_sacl(descriptor: &SecurityDescriptor) -> Vec<Ace> {
    sacl_of(descriptor)
        .into_iter()
        .filter(|a| !a.is_inherited())
        .collect()
}

pub fn inherited_sacl(descriptor: &SecurityDescriptor) -> Vec<Ace> {
    sacl_of(descriptor)
        .into_iter()
        .filter(Ace::is_inherited)
        .collect()
}

/// `descriptor` with this SACL, as `SetSecurityInfo` writes it: present, automatically
/// inherited, with `SE_SACL_AUTO_INHERIT_REQ`, protected or not; explicit entries first,
/// merged.
pub fn with_sacl(
    descriptor: &SecurityDescriptor,
    explicit: &[Ace],
    inherited: &[Ace],
    protected: bool,
) -> SecurityDescriptor {
    let mut out = descriptor.clone();
    let mut aces = canonical(&merged(explicit));
    aces.extend(inherited.iter().cloned());
    let revision = descriptor
        .sacl
        .as_ref()
        .map_or(sd::ACL_REVISION, |a| a.revision.max(sd::ACL_REVISION));
    out.sacl = Some(Acl { revision, aces });
    out.control &= !sd::SE_SACL_PROTECTED;
    out.control |= sd::SE_SACL_PRESENT | sd::SE_SACL_AUTO_INHERITED | sd::SE_SACL_AUTO_INHERIT_REQ;
    if protected {
        out.control |= sd::SE_SACL_PROTECTED;
    }
    out
}

/// The SACL of a child recomputed from its parent, as the DACL (`recompute`): unchanged if
/// protected (unless `replace`), explicit entries kept (none with `replace`), inherited ones
/// recomputed; the rest of the descriptor as it is.
pub fn recompute_sacl(
    child: &SecurityDescriptor,
    parent: &SecurityDescriptor,
    directory: bool,
    replace: bool,
) -> SecurityDescriptor {
    if is_sacl_protected(child) && !replace {
        return child.clone();
    }
    let explicit = if replace {
        Vec::new()
    } else {
        explicit_sacl(child)
    };
    let inherited = inherited_aces(
        &sacl_of(parent),
        directory,
        child.owner.as_ref(),
        child.group.as_ref(),
    );
    with_sacl(child, &explicit, &inherited, false)
}

/// The SACL of `a` audits what the one of `b` audits: same ACEs in the same order, same
/// protection.
pub fn same_audit(a: &SecurityDescriptor, b: &SecurityDescriptor) -> bool {
    let (x, y) = (sacl_of(a), sacl_of(b));
    x.len() == y.len()
        && x.iter().zip(&y).all(|(p, q)| same_ace(p, q))
        && is_sacl_protected(a) == is_sacl_protected(b)
}

/// Does going from `before` to `after` change the auditing entries the children inherit?
pub fn changes_children_audit(before: &SecurityDescriptor, after: &SecurityDescriptor) -> bool {
    [true, false].into_iter().any(|directory| {
        inherited_aces(&sacl_of(before), directory, None, None)
            != inherited_aces(&sacl_of(after), directory, None, None)
    })
}

/// Inheritance of the auditing entries turned off: the inherited ones converted, or removed.
pub fn sacl_without_inheritance(
    descriptor: &SecurityDescriptor,
    convert: bool,
) -> SecurityDescriptor {
    let mut explicit = explicit_sacl(descriptor);
    if convert {
        for ace in inherited_sacl(descriptor) {
            let ace = with_flags(&ace, ace.flags & !ID);
            if !explicit.contains(&ace) {
                explicit.push(ace);
            }
        }
    }
    with_sacl(descriptor, &explicit, &[], true)
}

/// Inheritance of the auditing entries turned on again, recomputed from the parent if known.
pub fn sacl_with_inheritance(
    descriptor: &SecurityDescriptor,
    parent: Option<&SecurityDescriptor>,
    directory: bool,
) -> SecurityDescriptor {
    let inherited = match parent {
        Some(p) => inherited_aces(
            &sacl_of(p),
            directory,
            descriptor.owner.as_ref(),
            descriptor.group.as_ref(),
        ),
        None => inherited_sacl(descriptor),
    };
    with_sacl(descriptor, &explicit_sacl(descriptor), &inherited, false)
}

/// Where an inherited auditing entry comes from (`inheritance_source` on the SACLs).
pub fn audit_source(ace: &Ace, ancestors: &[SecurityDescriptor]) -> Option<usize> {
    let sacls: Vec<SecurityDescriptor> = ancestors
        .iter()
        .map(|d| SecurityDescriptor {
            dacl: d.sacl.clone(),
            ..d.clone()
        })
        .collect();
    inheritance_source(ace, &sacls)
}

/// Could `source`, an ACE of an ancestor, have given `ace`? Same type, same principal (or
/// `CREATOR OWNER`, `CREATOR GROUP`), same rights once mapped.
fn gives(source: &Ace, ace: &Ace) -> bool {
    if source.ace_type != ace.ace_type
        || !inheritable(source)
        || source.flags & AUDIT != ace.flags & AUDIT
    {
        return false;
    }
    let (Some(a), Some(b)) = (source.sid(), ace.sid()) else {
        return source.body == ace.body;
    };
    let principal = a == b || a == creator_owner() || a == creator_group();
    principal && (source.mask() == ace.mask() || map_generic(source.mask()) == ace.mask())
}

/// Where an inherited ACE comes from, as Windows says it (`GetInheritanceSource`): the index,
/// in `ancestors` (the parent first, then up to the root of the share), of the nearest one
/// that holds it explicitly; `None` if no ancestor read does (it comes from above the share,
/// or was inherited before a change).
pub fn inheritance_source(ace: &Ace, ancestors: &[SecurityDescriptor]) -> Option<usize> {
    for (index, ancestor) in ancestors.iter().enumerate() {
        let found: Vec<&Ace> = dacl_aces(ancestor)
            .iter()
            .filter(|s| gives(s, ace))
            .collect();
        // Not found at this level: it cannot come from above either.
        if found.is_empty() {
            return None;
        }
        if found.iter().any(|s| !s.is_inherited()) {
            return Some(index);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use annuaire_codecs::sddl;

    const OWNER: &str = "S-1-5-21-1-2-3-1104";
    const GROUP: &str = "S-1-5-21-1-2-3-513";

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    fn sd_of(text: &str) -> SecurityDescriptor {
        sddl::sd_from_sddl(text, None, false).unwrap()
    }

    fn aces(text: &str) -> Vec<Ace> {
        sd_of(&format!("D:{text}")).dacl.unwrap().aces
    }

    fn text(aces: &[Ace]) -> String {
        aces.iter()
            .map(|a| sddl::ace_to_sddl(a, None).unwrap())
            .collect()
    }

    fn child(parent: &str, directory: bool) -> String {
        text(&inherited_aces(
            &aces(parent),
            directory,
            Some(&sid(OWNER)),
            Some(&sid(GROUP)),
        ))
    }

    #[test]
    fn container_and_object_inherit() {
        // « This folder, subfolders and files »: one ACE on a folder, kept inheritable.
        let p = "(A;OICI;0x1301bf;;;S-1-5-21-1-2-3-1105)";
        assert_eq!(child(p, true), "(A;OICIID;0x1301bf;;;S-1-5-21-1-2-3-1105)");
        assert_eq!(child(p, false), "(A;ID;0x1301bf;;;S-1-5-21-1-2-3-1105)");
    }

    #[test]
    fn container_inherit_only() {
        // « This folder and subfolders »: nothing for a file.
        let p = "(A;CI;0x1200a9;;;WD)";
        assert_eq!(child(p, true), "(A;CIID;0x1200a9;;;WD)");
        assert_eq!(child(p, false), "");
    }

    #[test]
    fn object_inherit_only() {
        // « This folder and files »: a folder passes it to its files, inherit-only.
        let p = "(A;OI;0x1200a9;;;WD)";
        assert_eq!(child(p, true), "(A;OIIOID;0x1200a9;;;WD)");
        assert_eq!(child(p, false), "(A;ID;0x1200a9;;;WD)");
    }

    #[test]
    fn inherit_only_on_the_parent() {
        // « Subfolders and files only »: the parent does not use it, the children do.
        let p = "(A;OICIIO;0x1301bf;;;AU)";
        assert_eq!(child(p, true), "(A;OICIID;0x1301bf;;;AU)");
        assert_eq!(child(p, false), "(A;ID;0x1301bf;;;AU)");
        // « Files only ».
        let p = "(A;OIIO;FR;;;AU)";
        assert_eq!(child(p, true), "(A;OIIOID;FR;;;AU)");
        assert_eq!(child(p, false), "(A;ID;FR;;;AU)");
    }

    #[test]
    fn no_propagate() {
        // One level only: the children get it as theirs, not their own children.
        let p = "(A;OICINP;0x1301bf;;;AU)";
        assert_eq!(child(p, true), "(A;ID;0x1301bf;;;AU)");
        assert_eq!(child(p, false), "(A;ID;0x1301bf;;;AU)");
        // Files only, one level: a subfolder gets nothing.
        let p = "(A;OINP;FR;;;AU)";
        assert_eq!(child(p, true), "");
        assert_eq!(child(p, false), "(A;ID;FR;;;AU)");
        let p = "(A;CINPIO;FR;;;AU)";
        assert_eq!(child(p, true), "(A;ID;FR;;;AU)");
        assert_eq!(child(p, false), "");
    }

    #[test]
    fn creator_owner_becomes_the_owner() {
        // As Windows: on a folder, the owner of the child with mapped rights, and CREATOR
        // OWNER kept inherit-only for the next level; on a file, the owner only.
        let p = "(A;OICIIO;GA;;;CO)";
        assert_eq!(
            child(p, true),
            format!("(A;ID;FA;;;{OWNER})(A;OICIIOID;GA;;;CO)")
        );
        assert_eq!(child(p, false), format!("(A;ID;FA;;;{OWNER})"));
        let p = "(A;OICI;0x1200a9;;;CG)";
        assert_eq!(
            child(p, true),
            format!("(A;ID;0x1200a9;;;{GROUP})(A;OICIIOID;0x1200a9;;;CG)")
        );
        // Without a known owner, CREATOR OWNER stays.
        let got = inherited_aces(&aces("(A;OI;FA;;;CO)"), false, None, None);
        assert_eq!(text(&got), "(A;ID;FA;;;CO)");
    }

    #[test]
    fn redundant_aces_are_left_out() {
        // As wdc1 does it: the owner is BUILTIN\Administrators, already granted Full control
        // by an ACE that applies to the child; CREATOR OWNER gives it nothing more.
        let p = "(A;OICI;FA;;;BA)(A;OICIIO;GA;;;CO)";
        let owner = sid("S-1-5-32-544");
        let got = |directory| text(&inherited_aces(&aces(p), directory, Some(&owner), None));
        assert_eq!(got(true), "(A;OICIID;FA;;;BA)(A;OICIIOID;GA;;;CO)");
        assert_eq!(got(false), "(A;ID;FA;;;BA)");
        // CREATOR GROUP gives Read to the group of the child, which already has Modify.
        let p = format!("(A;OICI;0x1301bf;;;{GROUP})(A;OICIIO;FR;;;CG)");
        assert_eq!(child(&p, false), format!("(A;ID;0x1301bf;;;{GROUP})"));
        // Read for files only, to a principal granted Modify on everything: nothing more.
        let p = format!("(A;OICI;0x1301bf;;;{GROUP})(A;OI;FR;;;{GROUP})");
        assert_eq!(child(&p, false), format!("(A;ID;0x1301bf;;;{GROUP})"));
        assert_eq!(child(&p, true), format!("(A;OICIID;0x1301bf;;;{GROUP})"));
        // Not covered: one level only does not hold what passes beyond, a denial does not
        // hold an allowance, Read does not hold Modify.
        let p = format!("(A;OICINP;0x1301bf;;;{GROUP})(A;CI;FR;;;{GROUP})");
        assert_eq!(
            child(&p, true),
            format!("(A;ID;0x1301bf;;;{GROUP})(A;CIID;FR;;;{GROUP})")
        );
        let p = format!("(D;OICI;FA;;;{GROUP})(A;OICI;FR;;;{GROUP})(A;OICI;0x1301bf;;;{GROUP})");
        assert_eq!(
            child(&p, false),
            format!("(D;ID;FA;;;{GROUP})(A;ID;FR;;;{GROUP})(A;ID;0x1301bf;;;{GROUP})")
        );
    }

    #[test]
    fn generic_rights_are_split_and_mapped() {
        // BUILTIN\Users:(OI)(CI)(GR,GE) as on the root of a Windows disk.
        let p = "(A;OICI;GRGX;;;BU)";
        assert_eq!(child(p, true), "(A;ID;0x1200a9;;;BU)(A;OICIIOID;GXGR;;;BU)");
        assert_eq!(child(p, false), "(A;ID;0x1200a9;;;BU)");
    }

    #[test]
    fn explicit_and_not_inheritable_aces_stay_behind() {
        let p = "(A;;FA;;;BA)(D;OICI;0x116;;;S-1-5-21-1-2-3-1106)(A;OICIID;FA;;;SY)";
        // Denials pass on in the parent's order, before what the parent inherited itself.
        assert_eq!(
            child(p, true),
            // 0x116 written by the codec with the letters of the directory rights.
            "(D;OICIID;DCLCRPCR;;;S-1-5-21-1-2-3-1106)(A;OICIID;FA;;;SY)"
        );
    }

    #[test]
    fn canonical_order() {
        let a = aces("(A;;FA;;;BA)(A;OICIID;FA;;;SY)(D;;0x116;;;AU)(D;ID;FR;;;WD)(A;;FR;;;BU)");
        let c = canonical(&a);
        assert_eq!(
            text(&c),
            "(D;;DCLCRPCR;;;AU)(A;;FA;;;BA)(A;;FR;;;BU)(A;OICIID;FA;;;SY)(D;ID;FR;;;WD)"
        );
        assert!(!is_canonical(&a));
        assert!(is_canonical(&c));
    }

    /// The DACL of the incident of J8.8: the same account added twice with the same flags.
    #[test]
    fn same_principal_and_flags_merged() {
        let user = "S-1-5-21-1-2-3-1106";
        let twice = aces(&format!(
            "(A;OICI;0x1f01ff;;;{user})(A;OICI;0x1f01ff;;;{user})(A;OICIID;FA;;;SY)"
        ));
        let origin = sd_of("O:BAG:SYD:AI");
        let explicit: Vec<Ace> = twice
            .iter()
            .filter(|a| !a.is_inherited())
            .cloned()
            .collect();
        let inherited: Vec<Ace> = twice.iter().filter(|a| a.is_inherited()).cloned().collect();
        let written = composed(&origin, &explicit, &inherited, false);
        assert_eq!(
            text(&dacl_of(&written)),
            format!("(A;OICI;FA;;;{user})(A;OICIID;FA;;;SY)")
        );
        // Added again with other rights: joined; with other flags, another type, or
        // inherited: kept apart.
        let mut out = aces(&format!("(A;OICI;FR;;;{user})"));
        merge_into(
            &mut out,
            aces(&format!("(A;OICI;0x116;;;{user})"))[0].clone(),
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mask(), 0x0012_0089 | 0x116);
        for other in [
            format!("(A;CI;FR;;;{user})"),
            format!("(D;OICI;FR;;;{user})"),
            format!("(A;OICIID;FR;;;{user})"),
            "(A;OICI;FR;;;BU)".to_owned(),
        ] {
            merge_into(&mut out, aces(&other)[0].clone());
        }
        assert_eq!(out.len(), 5);
        // The SACL the same way.
        let audit = sd_of(&format!("S:(AU;OICISA;FW;;;{user})(AU;OICISA;FR;;;{user})"))
            .sacl
            .unwrap()
            .aces;
        let with = with_sacl(&origin, &audit, &[], false);
        assert_eq!(sacl_of(&with).len(), 1);
        assert_eq!(sacl_of(&with)[0].mask(), 0x0012_0116 | 0x0012_0089);
    }

    #[test]
    fn recompute_keeps_explicit_and_protection() {
        let parent = sd_of("O:BAG:SYD:PAI(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;AU)");
        let child = sd_of(&format!(
            "O:{OWNER}G:{GROUP}D:AI(A;;FR;;;WD)(A;OICIID;FA;;;SY)"
        ));
        let new = recompute(&child, &parent, true, false);
        assert_eq!(
            sddl::sd_to_sddl(&new, None).unwrap(),
            format!(
                "O:{OWNER}G:{GROUP}D:ARAI(A;;FR;;;WD)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;AU)"
            )
        );
        // A protected child does not change.
        let protected = sd_of("O:BAG:SYD:PAI(A;;FA;;;WD)");
        assert_eq!(recompute(&protected, &parent, true, false), protected);
        // « Replace »: explicit ones removed, protection lifted.
        let new = recompute(&protected, &parent, false, true);
        assert_eq!(
            sddl::sd_to_sddl(&new, None).unwrap(),
            "O:BAG:SYD:ARAI(A;ID;FA;;;BA)(A;ID;0x1200a9;;;AU)"
        );
        assert!(!same_permissions(&new, &protected));
    }

    #[test]
    fn what_changes_children() {
        let before = sd_of("D:AI(A;OICI;FA;;;BA)");
        // A right for this folder only: nothing for the children.
        let after = sd_of("D:AI(A;;FR;;;AU)(A;OICI;FA;;;BA)");
        assert!(!changes_children(&before, &after));
        // Files only: the children change.
        let after = sd_of("D:AI(A;OIIO;FR;;;AU)(A;OICI;FA;;;BA)");
        assert!(changes_children(&before, &after));
        // Protection with inherited ACEs removed: what passes on changes.
        let before = sd_of("D:AI(A;OICIID;FA;;;BA)");
        let after = without_inheritance(&before, false);
        assert!(changes_children(&before, &after));
        // Converted: the same ACEs pass on, now explicit; children keep the same ones.
        let after = without_inheritance(&before, true);
        assert!(!changes_children(&before, &after));
        assert_eq!(
            sddl::sd_to_sddl(&after, None).unwrap(),
            "D:PARAI(A;OICI;FA;;;BA)"
        );
    }

    #[test]
    fn inheritance_turned_on_again() {
        let parent = sd_of("D:AI(A;OICI;FA;;;BA)(A;OI;FR;;;AU)");
        let folder = sd_of("D:PAI(A;;FR;;;WD)");
        let on = with_inheritance(&folder, Some(&parent), true);
        assert_eq!(
            sddl::sd_to_sddl(&on, None).unwrap(),
            "D:ARAI(A;;FR;;;WD)(A;OICIID;FA;;;BA)(A;OIIOID;FR;;;AU)"
        );
        let root = sd_of("D:PAI(A;;FR;;;WD)(A;OICIID;FA;;;SY)");
        assert_eq!(
            sddl::sd_to_sddl(&with_inheritance(&root, None, true), None).unwrap(),
            "D:ARAI(A;;FR;;;WD)(A;OICIID;FA;;;SY)"
        );
    }

    #[test]
    fn generic_rights_read_back_mapped() {
        // Samba stores GA as FA and GR|GX as 0x1200a9, inherit-only ACEs included.
        let written = sd_of("D:PAI(A;OICIIO;GA;;;CO)(A;OICI;GXGR;;;AU)");
        let read = sd_of("D:PAI(A;OICIIO;FA;;;CO)(A;OICI;0x1200a9;;;AU)");
        assert!(same_permissions(&written, &read));
        let other = sd_of("D:PAI(A;OICIIO;FA;;;CO)(A;OICI;FR;;;AU)");
        assert!(!same_permissions(&written, &other));
        assert!(!same_permissions(
            &written,
            &sd_of("D:AI(A;OICIIO;GA;;;CO)(A;OICI;GXGR;;;AU)")
        ));
    }

    #[test]
    fn written_asks_for_automatic_inheritance() {
        let d = written(&sd_of("O:BAD:(A;;FA;;;WD)"), aces("(A;;FA;;;WD)"), false);
        assert_eq!(
            d.control & (sd::SE_DACL_AUTO_INHERIT_REQ | sd::SE_DACL_AUTO_INHERITED),
            sd::SE_DACL_AUTO_INHERIT_REQ | sd::SE_DACL_AUTO_INHERITED
        );
        assert!(d.sacl.is_none());
        assert_eq!(d.owner, Some(sid("S-1-5-32-544")));
    }

    #[test]
    fn auditing_entries_inherit_as_permissions() {
        // Success on files and folders for Everyone, failure on folders for Authenticated
        // Users, one level only: as the DACL, the audit flags kept.
        let parent =
            sd_of("O:BAG:SYD:PAI(A;OICI;FA;;;BA)S:PAI(AU;OICISA;FA;;;WD)(AU;CINPFA;0x116;;;AU)");
        let child = sd_of(&format!(
            "O:{OWNER}G:{GROUP}D:AI(A;OICIID;FA;;;BA)S:AI(AU;SA;FR;;;BU)"
        ));
        let folder = recompute_sacl(&child, &parent, true, false);
        assert_eq!(
            sddl::sd_to_sddl(&folder, None).unwrap(),
            format!(
                "O:{OWNER}G:{GROUP}D:AI(A;OICIID;FA;;;BA)S:ARAI(AU;SA;FR;;;BU)(AU;OICIIDSA;FA;;;WD)(AU;IDFA;DCLCRPCR;;;AU)"
            )
        );
        // The DACL untouched; a file gets the OI entries only.
        assert!(same_permissions(&folder, &child));
        let file = recompute_sacl(&child, &parent, false, false);
        assert_eq!(text(&sacl_of(&file)), "(AU;SA;FR;;;BU)(AU;IDSA;FA;;;WD)");
        // A failure entry is not covered by a success entry of the same rights.
        let p = sd_of("S:(AU;OICISA;FA;;;WD)(AU;OICIFA;FA;;;WD)");
        assert_eq!(
            text(&inherited_aces(&sacl_of(&p), false, None, None)),
            "(AU;IDSA;FA;;;WD)(AU;IDFA;FA;;;WD)"
        );
        // Protected: unchanged, unless « replace ».
        let protected = sd_of("S:PAI(AU;SA;FR;;;BU)");
        assert_eq!(recompute_sacl(&protected, &parent, true, false), protected);
        let replaced = recompute_sacl(&protected, &parent, false, true);
        assert_eq!(text(&sacl_of(&replaced)), "(AU;IDSA;FA;;;WD)");
        assert!(!is_sacl_protected(&replaced) && !same_audit(&replaced, &protected));
        assert!(changes_children_audit(&protected, &parent));
        // Turned off then on again, and where an inherited entry comes from.
        let off = sacl_without_inheritance(&folder, true);
        assert!(is_sacl_protected(&off) && inherited_sacl(&off).is_empty());
        assert_eq!(explicit_sacl(&off).len(), 3);
        let on = sacl_with_inheritance(&off, Some(&parent), true);
        assert!(!is_sacl_protected(&on) && inherited_sacl(&on).len() == 2);
        let ace = &inherited_sacl(&folder)[0];
        assert_eq!(audit_source(ace, std::slice::from_ref(&parent)), Some(0));
        assert!(has_sacl(&folder) && !has_sacl(&sd_of("D:(A;;FA;;;WD)")));
    }

    #[test]
    fn source_of_an_inherited_ace() {
        // The root gives Authenticated Users; « a » inherits it and passes it to « a\b ».
        let root = sd_of("D:PAI(A;OICI;0x1301bf;;;AU)(A;OICI;FA;;;BA)");
        let a = sd_of("D:AI(A;OICI;FR;;;WD)(A;OICIID;0x1301bf;;;AU)(A;OICIID;FA;;;BA)");
        let ace = &aces("(A;OICIID;0x1301bf;;;AU)")[0];
        assert_eq!(inheritance_source(ace, &[a.clone(), root.clone()]), Some(1));
        let ace = &aces("(A;ID;FR;;;WD)")[0];
        assert_eq!(inheritance_source(ace, &[a.clone(), root.clone()]), Some(0));
        // CREATOR OWNER on the parent gives the owner.
        let parent = sd_of("D:(A;OICIIO;GA;;;CO)");
        let ace = &aces(&format!("(A;ID;FA;;;{OWNER})"))[0];
        assert_eq!(inheritance_source(ace, &[parent]), Some(0));
        // Inherited at the root itself: from above the share.
        let root = sd_of("D:AI(A;OICIID;FA;;;SY)");
        let ace = &aces("(A;OICIID;FA;;;SY)")[0];
        assert_eq!(inheritance_source(ace, &[root]), None);
        // Not found at all.
        let ace = &aces("(A;ID;FA;;;BG)")[0];
        assert_eq!(inheritance_source(ace, &[a]), None);
    }
}

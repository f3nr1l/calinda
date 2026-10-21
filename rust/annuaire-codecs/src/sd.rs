// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Self-relative security descriptor (MS-DTYP 2.4.6): bytes ⇄ structure.
//!
//! The descriptor is split into header (revision, control), owner, group, SACL and DACL,
//! and each ACE into type, flags and body. The body of every ACE is kept raw (re-encoded
//! as is, padding included): a descriptor read then encoded gives the same bytes, whatever
//! the types of its ACEs. Mask, SID and GUIDs are read from the body for simple ACEs,
//! object ACEs (object type and inherited object type GUIDs, MS-DTYP 2.4.4.3) and
//! callback ACEs (condition kept raw in `data`).
//!
//! Encoding follows the layout of AD and Samba: header, owner, group, SACL, DACL. Windows
//! stores the same parts as SACL, DACL, owner, group, so `encode(decode(x)) == x` only
//! holds for a descriptor written by Samba: compare descriptors structurally (`==`).
//!
//! Port of `annuaire/core/codecs/sd.py`.

use std::fmt;

use crate::guid::Guid;
use crate::read::le_u32;
use crate::sid::{Sid, SidError};

/// Why a descriptor or an ACE was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdError {
    /// Fewer than 20 bytes.
    TooShort,
    /// Revision other than 1, or `SE_SELF_RELATIVE` not set.
    NotSelfRelative,
    /// ACL header beyond the end of the descriptor.
    TruncatedAcl,
    /// ACL size beyond the end of the descriptor.
    AclTooLong,
    /// ACE header beyond the end of its ACL.
    TruncatedAce,
    /// ACE size below 8 bytes or beyond the end of its ACL.
    InvalidAceSize,
    /// Object ACE shorter than its mask and flags.
    TruncatedObjectAce,
    /// SID of the owner, the group or an ACE.
    Sid(SidError),
    /// `Ace::simple` with another type.
    NotSimpleType(u8),
    /// `Ace::object` with another type.
    NotObjectType(u8),
    /// The descriptor has no DACL.
    NoDacl,
    /// An ACE to add is inherited.
    InheritedAce,
    /// ACE or ACL beyond 65 535 bytes, or more than 65 535 ACEs.
    TooLong,
}

impl fmt::Display for SdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort => write!(f, "descriptor too short"),
            Self::NotSelfRelative => {
                write!(f, "descriptor not self-relative or of unknown revision")
            }
            Self::TruncatedAcl => write!(f, "truncated ACL"),
            Self::AclTooLong => write!(f, "ACL longer than the descriptor"),
            Self::TruncatedAce => write!(f, "truncated ACE"),
            Self::InvalidAceSize => write!(f, "invalid ACE size"),
            Self::TruncatedObjectAce => write!(f, "truncated object ACE"),
            Self::Sid(e) => e.fmt(f),
            Self::NotSimpleType(t) => write!(f, "not a simple ACE type: {t}"),
            Self::NotObjectType(t) => write!(f, "not an object ACE type: {t}"),
            Self::NoDacl => write!(f, "descriptor without DACL"),
            Self::InheritedAce => write!(f, "an added ACE must be explicit"),
            Self::TooLong => write!(f, "ACE or ACL too long"),
        }
    }
}

impl std::error::Error for SdError {}

impl From<SidError> for SdError {
    fn from(e: SidError) -> Self {
        Self::Sid(e)
    }
}

pub const REVISION: u8 = 1;
pub const ACL_REVISION: u8 = 2;
pub const ACL_REVISION_DS: u8 = 4;

// Control bits (MS-DTYP 2.4.6).
pub const SE_OWNER_DEFAULTED: u16 = 0x0001;
pub const SE_GROUP_DEFAULTED: u16 = 0x0002;
pub const SE_DACL_PRESENT: u16 = 0x0004;
pub const SE_DACL_DEFAULTED: u16 = 0x0008;
pub const SE_SACL_PRESENT: u16 = 0x0010;
pub const SE_SACL_DEFAULTED: u16 = 0x0020;
pub const SE_DACL_AUTO_INHERIT_REQ: u16 = 0x0100;
pub const SE_SACL_AUTO_INHERIT_REQ: u16 = 0x0200;
pub const SE_DACL_AUTO_INHERITED: u16 = 0x0400;
pub const SE_SACL_AUTO_INHERITED: u16 = 0x0800;
pub const SE_DACL_PROTECTED: u16 = 0x1000;
pub const SE_SACL_PROTECTED: u16 = 0x2000;
pub const SE_SELF_RELATIVE: u16 = 0x8000;

// ACE types (MS-DTYP 2.4.4.1).
pub const ACCESS_ALLOWED: u8 = 0;
pub const ACCESS_DENIED: u8 = 1;
pub const SYSTEM_AUDIT: u8 = 2;
pub const SYSTEM_ALARM: u8 = 3;
pub const ACCESS_ALLOWED_OBJECT: u8 = 5;
pub const ACCESS_DENIED_OBJECT: u8 = 6;
pub const SYSTEM_AUDIT_OBJECT: u8 = 7;
pub const SYSTEM_ALARM_OBJECT: u8 = 8;
pub const ACCESS_ALLOWED_CALLBACK: u8 = 9;
pub const ACCESS_DENIED_CALLBACK: u8 = 10;
pub const ACCESS_ALLOWED_CALLBACK_OBJECT: u8 = 11;
pub const ACCESS_DENIED_CALLBACK_OBJECT: u8 = 12;
pub const SYSTEM_AUDIT_CALLBACK: u8 = 13;
pub const SYSTEM_ALARM_CALLBACK: u8 = 14;
pub const SYSTEM_AUDIT_CALLBACK_OBJECT: u8 = 15;
pub const SYSTEM_ALARM_CALLBACK_OBJECT: u8 = 16;
pub const SYSTEM_MANDATORY_LABEL: u8 = 17;
pub const SYSTEM_RESOURCE_ATTRIBUTE: u8 = 18;
pub const SYSTEM_SCOPED_POLICY_ID: u8 = 19;

// ACE flags (MS-DTYP 2.4.4.1).
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
pub const NO_PROPAGATE_INHERIT_ACE: u8 = 0x04;
pub const INHERIT_ONLY_ACE: u8 = 0x08;
pub const INHERITED_ACE: u8 = 0x10;
pub const SUCCESSFUL_ACCESS_ACE: u8 = 0x40;
pub const FAILED_ACCESS_ACE: u8 = 0x80;

// Object ACE flags: which GUIDs follow the mask.
pub const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;
pub const ACE_INHERITED_OBJECT_TYPE_PRESENT: u32 = 0x2;

// Access rights (MS-ADTS 5.1.3.2; MS-DTYP 2.4.3).
pub const ADS_RIGHT_DS_CREATE_CHILD: u32 = 0x0000_0001;
pub const ADS_RIGHT_DS_DELETE_CHILD: u32 = 0x0000_0002;
pub const ADS_RIGHT_ACTRL_DS_LIST: u32 = 0x0000_0004;
pub const ADS_RIGHT_DS_SELF: u32 = 0x0000_0008;
pub const ADS_RIGHT_DS_READ_PROP: u32 = 0x0000_0010;
pub const ADS_RIGHT_DS_WRITE_PROP: u32 = 0x0000_0020;
pub const ADS_RIGHT_DS_DELETE_TREE: u32 = 0x0000_0040;
pub const ADS_RIGHT_DS_LIST_OBJECT: u32 = 0x0000_0080;
pub const ADS_RIGHT_DS_CONTROL_ACCESS: u32 = 0x0000_0100;
pub const DELETE: u32 = 0x0001_0000;
pub const READ_CONTROL: u32 = 0x0002_0000;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
pub const SYNCHRONIZE: u32 = 0x0010_0000;
pub const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_READ: u32 = 0x8000_0000;

/// `GENERIC_ALL` translated for a directory object: CCDCLCSWRPWPDTLOCRSDRCWDWO.
pub const DS_FULL_CONTROL: u32 = 0x000F_01FF;
pub const DS_READ: u32 =
    READ_CONTROL | ADS_RIGHT_ACTRL_DS_LIST | ADS_RIGHT_DS_READ_PROP | ADS_RIGHT_DS_LIST_OBJECT;
pub const DS_WRITE: u32 = READ_CONTROL | ADS_RIGHT_DS_SELF | ADS_RIGHT_DS_WRITE_PROP;
pub const DS_EXECUTE: u32 = READ_CONTROL | ADS_RIGHT_ACTRL_DS_LIST;

/// Generic rights replaced by the directory rights they stand for (MS-ADTS 5.1.3.3).
pub fn translate_generic(mut mask: u32) -> u32 {
    for (generic, specific) in [
        (GENERIC_ALL, DS_FULL_CONTROL),
        (GENERIC_READ, DS_READ),
        (GENERIC_WRITE, DS_WRITE),
        (GENERIC_EXECUTE, DS_EXECUTE),
    ] {
        if mask & generic != 0 {
            mask = (mask & !generic) | specific;
        }
    }
    mask
}

/// Everyone, S-1-1-0.
pub fn everyone() -> Sid {
    Sid::new(1, &[0]).expect("S-1-1-0 is a valid SID")
}

pub(crate) fn is_simple(t: u8) -> bool {
    t <= SYSTEM_ALARM
}

pub(crate) fn is_plain_object(t: u8) -> bool {
    (ACCESS_ALLOWED_OBJECT..=SYSTEM_ALARM_OBJECT).contains(&t)
}

/// Mask then SID, followed by data (condition, resource attribute).
fn is_other_simple(t: u8) -> bool {
    matches!(
        t,
        ACCESS_ALLOWED_CALLBACK
            | ACCESS_DENIED_CALLBACK
            | SYSTEM_AUDIT_CALLBACK
            | SYSTEM_ALARM_CALLBACK
            | SYSTEM_MANDATORY_LABEL
            | SYSTEM_RESOURCE_ATTRIBUTE
            | SYSTEM_SCOPED_POLICY_ID
    )
}

fn is_other_object(t: u8) -> bool {
    matches!(
        t,
        ACCESS_ALLOWED_CALLBACK_OBJECT
            | ACCESS_DENIED_CALLBACK_OBJECT
            | SYSTEM_AUDIT_CALLBACK_OBJECT
            | SYSTEM_ALARM_CALLBACK_OBJECT
    )
}

/// An ACE: type, flags and raw body.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    /// Everything after the ACE header (mask, optional GUIDs, SID, data…).
    pub body: Vec<u8>,
}

impl Ace {
    /// The access mask; 0 for a body shorter than four bytes (never read from a descriptor).
    pub fn mask(&self) -> u32 {
        le_u32(&self.body, 0).unwrap_or(0)
    }

    pub fn is_object(&self) -> bool {
        is_plain_object(self.ace_type) || is_other_object(self.ace_type)
    }

    /// The body has a known layout (mask, GUIDs, SID); otherwise only the raw body counts.
    pub fn is_readable(&self) -> bool {
        is_simple(self.ace_type) || self.is_object() || is_other_simple(self.ace_type)
    }

    fn presence(&self) -> u32 {
        if self.is_object() {
            le_u32(&self.body, 4).unwrap_or(0)
        } else {
            0
        }
    }

    fn sid_position(&self) -> usize {
        if !self.is_object() {
            return 4;
        }
        8 + 16 * (self.presence() & 3).count_ones() as usize
    }

    /// GUID of the object type (class, attribute, property set, extended right).
    pub fn object_type(&self) -> Option<Guid> {
        if self.presence() & ACE_OBJECT_TYPE_PRESENT != 0 {
            return Guid::read(&self.body, 8).ok().map(|(g, _)| g);
        }
        None
    }

    /// GUID of the class of objects the ACE applies to through inheritance.
    pub fn inherited_object_type(&self) -> Option<Guid> {
        let presence = self.presence();
        if presence & ACE_INHERITED_OBJECT_TYPE_PRESENT != 0 {
            let start = if presence & ACE_OBJECT_TYPE_PRESENT != 0 {
                24
            } else {
                8
            };
            return Guid::read(&self.body, start).ok().map(|(g, _)| g);
        }
        None
    }

    fn read_sid(&self) -> Result<Option<(Sid, usize)>, SidError> {
        if !self.is_readable() {
            return Ok(None);
        }
        Sid::read(&self.body, self.sid_position()).map(Some)
    }

    /// The SID of the ACE; `None` for a type of unknown layout (or a malformed body, which
    /// `SecurityDescriptor::decode` refuses).
    pub fn sid(&self) -> Option<Sid> {
        self.read_sid().ok().flatten().map(|(s, _)| s)
    }

    /// What follows the SID: condition of a callback ACE, or padding.
    pub fn data(&self) -> &[u8] {
        match self.read_sid() {
            Ok(Some((_, end))) => self.body.get(end..).unwrap_or_default(),
            _ => &[],
        }
    }

    pub fn is_inherited(&self) -> bool {
        self.flags & INHERITED_ACE != 0
    }

    pub fn is_deny(&self) -> bool {
        matches!(
            self.ace_type,
            ACCESS_DENIED
                | ACCESS_DENIED_OBJECT
                | ACCESS_DENIED_CALLBACK
                | ACCESS_DENIED_CALLBACK_OBJECT
        )
    }

    pub fn is_allow(&self) -> bool {
        matches!(
            self.ace_type,
            ACCESS_ALLOWED
                | ACCESS_ALLOWED_OBJECT
                | ACCESS_ALLOWED_CALLBACK
                | ACCESS_ALLOWED_CALLBACK_OBJECT
        )
    }

    /// A simple ACE (`A`, `D`, `AU`, `AL`).
    pub fn simple(ace_type: u8, mask: u32, sid: &Sid, flags: u8) -> Result<Self, SdError> {
        if !is_simple(ace_type) {
            return Err(SdError::NotSimpleType(ace_type));
        }
        let mut body = mask.to_le_bytes().to_vec();
        sid.write_to(&mut body);
        Ok(Self {
            ace_type,
            flags,
            body,
        })
    }

    /// An object ACE (`OA`, `OD`, `OU`, `OL`); an absent GUID is not written.
    pub fn object(
        ace_type: u8,
        mask: u32,
        sid: &Sid,
        flags: u8,
        object_type: Option<Guid>,
        inherited_object_type: Option<Guid>,
    ) -> Result<Self, SdError> {
        if !is_plain_object(ace_type) {
            return Err(SdError::NotObjectType(ace_type));
        }
        let mut body = object_body(mask, object_type, inherited_object_type);
        sid.write_to(&mut body);
        Ok(Self {
            ace_type,
            flags,
            body,
        })
    }
}

/// Mask, presence flags and the GUIDs that are present.
pub(crate) fn object_body(mask: u32, object: Option<Guid>, inherited: Option<Guid>) -> Vec<u8> {
    let presence = if object.is_some() {
        ACE_OBJECT_TYPE_PRESENT
    } else {
        0
    } | if inherited.is_some() {
        ACE_INHERITED_OBJECT_TYPE_PRESENT
    } else {
        0
    };
    let mut body = mask.to_le_bytes().to_vec();
    body.extend(presence.to_le_bytes());
    for g in [object, inherited].into_iter().flatten() {
        body.extend(g.as_bytes());
    }
    body
}

/// An access control list.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Acl {
    pub revision: u8,
    pub aces: Vec<Ace>,
}

/// A security descriptor. `==` compares the structure, whatever the layout of the bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecurityDescriptor {
    pub revision: u8,
    pub control: u16,
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub sacl: Option<Acl>,
    pub dacl: Option<Acl>,
}

fn read_acl(bytes: &[u8], position: usize) -> Result<Acl, SdError> {
    let header = bytes
        .get(position..position + 8)
        .ok_or(SdError::TruncatedAcl)?;
    let [revision, _, s0, s1, c0, c1, _, _] = header else {
        return Err(SdError::TruncatedAcl);
    };
    let size = usize::from(u16::from_le_bytes([*s0, *s1]));
    let count = u16::from_le_bytes([*c0, *c1]);
    let end = position + size;
    if end > bytes.len() {
        return Err(SdError::AclTooLong);
    }
    let mut aces = Vec::with_capacity(usize::from(count));
    let mut cursor = position + 8;
    for _ in 0..count {
        let header = bytes.get(cursor..cursor + 4).filter(|_| cursor + 4 <= end);
        let Some([ace_type, flags, z0, z1]) = header else {
            return Err(SdError::TruncatedAce);
        };
        let ace_size = usize::from(u16::from_le_bytes([*z0, *z1]));
        if ace_size < 8 || cursor + ace_size > end {
            return Err(SdError::InvalidAceSize);
        }
        let body = bytes
            .get(cursor + 4..cursor + ace_size)
            .ok_or(SdError::InvalidAceSize)?;
        let ace = Ace {
            ace_type: *ace_type,
            flags: *flags,
            body: body.to_vec(),
        };
        if ace.is_readable() {
            if ace.is_object() && ace.body.len() < 8 {
                return Err(SdError::TruncatedObjectAce);
            }
            ace.read_sid()?; // the SID must fit in the body
        }
        aces.push(ace);
        cursor += ace_size;
    }
    Ok(Acl {
        revision: *revision,
        aces,
    })
}

impl SecurityDescriptor {
    /// Self-relative descriptor → structure.
    pub fn decode(bytes: &[u8]) -> Result<Self, SdError> {
        let Some([revision, _, k0, k1, ..]) = bytes.get(..20) else {
            return Err(SdError::TooShort);
        };
        let control = u16::from_le_bytes([*k0, *k1]);
        let offset = |i: usize| le_u32(bytes, i).unwrap_or(0) as usize;
        let (o_owner, o_group, o_sacl, o_dacl) = (offset(4), offset(8), offset(12), offset(16));
        if *revision != REVISION || control & SE_SELF_RELATIVE == 0 {
            return Err(SdError::NotSelfRelative);
        }
        let sid = |position: usize| -> Result<Option<Sid>, SdError> {
            if position == 0 {
                return Ok(None);
            }
            Ok(Some(Sid::read(bytes, position)?.0))
        };
        let owner = sid(o_owner)?;
        let group = sid(o_group)?;
        let acl = |present: u16, position: usize| -> Result<Option<Acl>, SdError> {
            if control & present == 0 || position == 0 {
                return Ok(None);
            }
            read_acl(bytes, position).map(Some)
        };
        let sacl = acl(SE_SACL_PRESENT, o_sacl)?;
        let dacl = acl(SE_DACL_PRESENT, o_dacl)?;
        Ok(Self {
            revision: *revision,
            control,
            owner,
            group,
            sacl,
            dacl,
        })
    }

    /// Structure → self-relative descriptor (owner, group, SACL, DACL: Samba's layout).
    pub fn encode(&self) -> Result<Vec<u8>, SdError> {
        let parts = [
            self.owner.as_ref().map(Sid::encode).unwrap_or_default(),
            self.group.as_ref().map(Sid::encode).unwrap_or_default(),
            self.sacl
                .as_ref()
                .map(encode_acl)
                .transpose()?
                .unwrap_or_default(),
            self.dacl
                .as_ref()
                .map(encode_acl)
                .transpose()?
                .unwrap_or_default(),
        ];
        let mut out = Vec::with_capacity(20 + parts.iter().map(Vec::len).sum::<usize>());
        out.extend([self.revision, 0]);
        out.extend((self.control | SE_SELF_RELATIVE).to_le_bytes());
        let mut position = 20;
        for part in &parts {
            let offset = if part.is_empty() { 0 } else { position };
            out.extend(
                u32::try_from(offset)
                    .map_err(|_| SdError::TooLong)?
                    .to_le_bytes(),
            );
            position += part.len();
        }
        for part in parts {
            out.extend(part);
        }
        Ok(out)
    }

    /// Adds explicit ACEs to the DACL in canonical order (MS-DTYP 2.4.5): a deny first, an
    /// allow after the existing explicit ACEs and before the inherited ones. An ACE already
    /// present is not added twice.
    pub fn add_aces(&self, aces: &[Ace]) -> Result<Self, SdError> {
        let dacl = self.dacl.as_ref().ok_or(SdError::NoDacl)?;
        let mut current = dacl.aces.clone();
        for ace in aces {
            if ace.is_inherited() {
                return Err(SdError::InheritedAce);
            }
            if current.contains(ace) {
                continue;
            }
            let position = if ace.is_deny() {
                0
            } else {
                current.iter().filter(|a| !a.is_inherited()).count()
            };
            current.insert(position, ace.clone());
        }
        let mut revision = dacl.revision;
        if aces.iter().any(Ace::is_object) {
            revision = revision.max(ACL_REVISION_DS);
        }
        Ok(Self {
            dacl: Some(Acl {
                revision,
                aces: current,
            }),
            ..self.clone()
        })
    }

    /// Removes from the DACL the explicit ACEs equal to the given ones.
    pub fn remove_aces(&self, aces: &[Ace]) -> Self {
        let Some(dacl) = &self.dacl else {
            return self.clone();
        };
        let kept = dacl
            .aces
            .iter()
            .filter(|a| a.is_inherited() || !aces.contains(a))
            .cloned()
            .collect();
        Self {
            dacl: Some(Acl {
                revision: dacl.revision,
                aces: kept,
            }),
            ..self.clone()
        }
    }

    /// An explicit ACE denies "delete" and "delete subtree" to Everyone.
    pub fn is_protected(&self) -> bool {
        let Some(dacl) = &self.dacl else {
            return false;
        };
        let wanted = DELETE | ADS_RIGHT_DS_DELETE_TREE;
        let everyone = everyone();
        dacl.aces.iter().any(|a| {
            a.ace_type == ACCESS_DENIED
                && !a.is_inherited()
                && a.sid() == Some(everyone)
                && a.mask() & wanted == wanted
        })
    }

    /// Adds the deny ACE at the head of the DACL (canonical order: explicit denies first).
    pub fn protect(&self) -> Result<Self, SdError> {
        let dacl = self.dacl.as_ref().ok_or(SdError::NoDacl)?;
        if self.is_protected() {
            return Ok(self.clone());
        }
        let mut aces = vec![protection_ace()];
        aces.extend(dacl.aces.iter().cloned());
        Ok(Self {
            dacl: Some(Acl {
                revision: dacl.revision,
                aces,
            }),
            ..self.clone()
        })
    }

    /// Removes the explicit deny ACEs that only deny deletion to Everyone.
    pub fn unprotect(&self) -> Self {
        let Some(dacl) = &self.dacl else {
            return self.clone();
        };
        let wanted = DELETE | ADS_RIGHT_DS_DELETE_TREE;
        let everyone = everyone();
        let kept = dacl
            .aces
            .iter()
            .filter(|a| {
                !(a.ace_type == ACCESS_DENIED
                    && !a.is_inherited()
                    && a.sid() == Some(everyone)
                    && a.mask() & !wanted == 0)
            })
            .cloned()
            .collect();
        Self {
            dacl: Some(Acl {
                revision: dacl.revision,
                aces: kept,
            }),
            ..self.clone()
        }
    }
}

/// The ACE that protects an object from accidental deletion, as the Windows console does.
pub fn protection_ace() -> Ace {
    let mut body = (DELETE | ADS_RIGHT_DS_DELETE_TREE).to_le_bytes().to_vec();
    everyone().write_to(&mut body);
    Ace {
        ace_type: ACCESS_DENIED,
        flags: 0,
        body,
    }
}

fn encode_acl(acl: &Acl) -> Result<Vec<u8>, SdError> {
    let mut body = Vec::new();
    for a in &acl.aces {
        let size = u16::try_from(4 + a.body.len()).map_err(|_| SdError::TooLong)?;
        body.extend([a.ace_type, a.flags]);
        body.extend(size.to_le_bytes());
        body.extend(&a.body);
    }
    let size = u16::try_from(8 + body.len()).map_err(|_| SdError::TooLong)?;
    let count = u16::try_from(acl.aces.len()).map_err(|_| SdError::TooLong)?;
    let mut out = Vec::with_capacity(8 + body.len());
    out.extend([acl.revision, 0]);
    out.extend(size.to_le_bytes());
    out.extend(count.to_le_bytes());
    out.extend([0, 0]);
    out.extend(body);
    Ok(out)
}

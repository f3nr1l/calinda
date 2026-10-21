// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! SDDL (MS-DTYP 2.5.1) of a security descriptor, both ways.
//!
//! The form written is Samba 4.22's (`security.descriptor.as_sddl(domain SID)`, which
//! `samba-tool dsacl get` prints), recorded against the lab oracle:
//! - sections `O:`, `G:`, `D:`, `S:` in that order, an absent section omitted;
//! - ACL flags `P`, `AR`, `AI`; ACE flags `OI CI NP IO ID SA FA`;
//! - mask: `FA`, `FR`, `FW` or `FX` when it equals one of them exactly, otherwise the codes
//!   `CC DC LC SW RP WP DT LO CR SD RC WD WO GA GX GW GR` when they cover it entirely,
//!   otherwise lower-case hexadecimal without leading zeros (`0x1200a9`); empty for 0;
//! - SID abbreviated (`BA`, `DA`…) when an abbreviation exists; the domain-relative ones
//!   (`DA`, `DU`…) only when the domain SID is given;
//! - GUIDs in lower case; conditional ACEs (`XA`, `XD`, `ZA`, `XU`) and resource attribute
//!   ACEs (`RA`) with their condition in Samba's form ([`crate::condition`]), also read in
//!   Windows' form; mandatory label and central policy ACEs not represented
//!   (`Error::SddlUnrepresentable`): Samba does not write them either.
//!
//! Read back, every ACL has revision 4, as with Samba's `from_sddl`. Windows' form (full
//! SIDs for `RO`, `SA`, `EA`, `CN`, `EK`) is read as well.
//!
//! Port of the SDDL part of `annuaire/core/codecs/sd.py`.

use std::fmt;
use std::sync::OnceLock;

use crate::condition::{self, ConditionError};
use crate::guid::Guid;
use crate::pytext::{self, at, from, sub};
use crate::sd::*;
use crate::sid::Sid;

/// Why a text could not be read, or a descriptor written, in SDDL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SddlError {
    /// Malformed SDDL text (Python: `SddlInvalide`).
    Invalid(String),
    /// The descriptor holds what SDDL, in Samba's form, does not write (Python:
    /// `SddlNonRepresentable`).
    Unrepresentable(String),
    /// The descriptor read from the text cannot be built (ACE or ACL too long).
    Descriptor(SdError),
}

impl fmt::Display for SddlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(m) | Self::Unrepresentable(m) => f.write_str(m),
            Self::Descriptor(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for SddlError {}

impl From<SdError> for SddlError {
    fn from(e: SdError) -> Self {
        Self::Descriptor(e)
    }
}

type Result<T> = std::result::Result<T, SddlError>;

/// Well-known SID abbreviations, independent of the domain (Samba 4.22's table, recorded
/// against the oracle: every code is read and written back identically).
pub const ABBREVIATIONS: [(&str, &str); 49] = [
    ("AA", "S-1-5-32-579"),
    ("AC", "S-1-15-2-1"),
    ("AN", "S-1-5-7"),
    ("AO", "S-1-5-32-548"),
    ("AS", "S-1-18-1"),
    ("AU", "S-1-5-11"),
    ("BA", "S-1-5-32-544"),
    ("BG", "S-1-5-32-546"),
    ("BO", "S-1-5-32-551"),
    ("BU", "S-1-5-32-545"),
    ("CD", "S-1-5-32-574"),
    ("CG", "S-1-3-1"),
    ("CO", "S-1-3-0"),
    ("CY", "S-1-5-32-569"),
    ("ED", "S-1-5-9"),
    ("ER", "S-1-5-32-573"),
    ("ES", "S-1-5-32-576"),
    ("HA", "S-1-5-32-578"),
    ("HI", "S-1-16-12288"),
    ("IS", "S-1-5-32-568"),
    ("IU", "S-1-5-4"),
    ("LS", "S-1-5-19"),
    ("LU", "S-1-5-32-559"),
    ("LW", "S-1-16-4096"),
    ("ME", "S-1-16-8192"),
    ("MP", "S-1-16-8448"),
    ("MS", "S-1-5-32-577"),
    ("MU", "S-1-5-32-558"),
    ("NO", "S-1-5-32-556"),
    ("NS", "S-1-5-20"),
    ("NU", "S-1-5-2"),
    ("OW", "S-1-3-4"),
    ("PO", "S-1-5-32-550"),
    ("PS", "S-1-5-10"),
    ("PU", "S-1-5-32-547"),
    ("RA", "S-1-5-32-575"),
    ("RC", "S-1-5-12"),
    ("RD", "S-1-5-32-555"),
    ("RE", "S-1-5-32-552"),
    ("RM", "S-1-5-32-580"),
    ("RU", "S-1-5-32-554"),
    ("SI", "S-1-16-16384"),
    ("SO", "S-1-5-32-549"),
    ("SS", "S-1-18-2"),
    ("SU", "S-1-5-6"),
    ("SY", "S-1-5-18"),
    ("UD", "S-1-5-84-0-0-0-0-0"),
    ("WD", "S-1-1-0"),
    ("WR", "S-1-5-33"),
];

/// Domain-relative abbreviations (RID appended to the domain SID). `EA`, `SA`, `PA` and
/// `RO` name groups of the forest root domain; Samba relates them to the given domain.
pub const DOMAIN_ABBREVIATIONS: [(&str, u32); 17] = [
    ("AP", 525),
    ("CA", 517),
    ("CN", 522),
    ("DA", 512),
    ("DC", 515),
    ("DD", 516),
    ("DG", 514),
    ("DU", 513),
    ("EA", 519),
    ("EK", 527),
    ("KA", 526),
    ("LA", 500),
    ("LG", 501),
    ("PA", 520),
    ("RO", 498),
    ("RS", 553),
    ("SA", 518),
];

/// ACL flags, as control bits of the DACL; the SACL's are twice these.
const ACL_FLAGS: [(&str, u16); 3] = [
    ("P", SE_DACL_PROTECTED),
    ("AR", SE_DACL_AUTO_INHERIT_REQ),
    ("AI", SE_DACL_AUTO_INHERITED),
];

pub const ACE_FLAGS: [(&str, u8); 7] = [
    ("OI", OBJECT_INHERIT_ACE),
    ("CI", CONTAINER_INHERIT_ACE),
    ("NP", NO_PROPAGATE_INHERIT_ACE),
    ("IO", INHERIT_ONLY_ACE),
    ("ID", INHERITED_ACE),
    ("SA", SUCCESSFUL_ACCESS_ACE),
    ("FA", FAILED_ACCESS_ACE),
];

pub const ACE_TYPES: [(u8, &str); 8] = [
    (ACCESS_ALLOWED, "A"),
    (ACCESS_DENIED, "D"),
    (SYSTEM_AUDIT, "AU"),
    (SYSTEM_ALARM, "AL"),
    (ACCESS_ALLOWED_OBJECT, "OA"),
    (ACCESS_DENIED_OBJECT, "OD"),
    (SYSTEM_AUDIT_OBJECT, "OU"),
    (SYSTEM_ALARM_OBJECT, "OL"),
];

/// ACEs followed by a condition ([`crate::condition`]) or a resource attribute (`RA`).
pub const CONDITIONAL_TYPES: [(u8, &str); 5] = [
    (ACCESS_ALLOWED_CALLBACK, "XA"),
    (ACCESS_DENIED_CALLBACK, "XD"),
    (ACCESS_ALLOWED_CALLBACK_OBJECT, "ZA"),
    (SYSTEM_AUDIT_CALLBACK, "XU"),
    (SYSTEM_RESOURCE_ATTRIBUTE, "RA"),
];

/// Rights codes, in the order Samba writes them.
pub const RIGHTS: [(&str, u32); 17] = [
    ("CC", ADS_RIGHT_DS_CREATE_CHILD),
    ("DC", ADS_RIGHT_DS_DELETE_CHILD),
    ("LC", ADS_RIGHT_ACTRL_DS_LIST),
    ("SW", ADS_RIGHT_DS_SELF),
    ("RP", ADS_RIGHT_DS_READ_PROP),
    ("WP", ADS_RIGHT_DS_WRITE_PROP),
    ("DT", ADS_RIGHT_DS_DELETE_TREE),
    ("LO", ADS_RIGHT_DS_LIST_OBJECT),
    ("CR", ADS_RIGHT_DS_CONTROL_ACCESS),
    ("SD", DELETE),
    ("RC", READ_CONTROL),
    ("WD", WRITE_DAC),
    ("WO", WRITE_OWNER),
    ("GA", GENERIC_ALL),
    ("GX", GENERIC_EXECUTE),
    ("GW", GENERIC_WRITE),
    ("GR", GENERIC_READ),
];

/// File masks written as a single code when the mask equals one of them exactly.
pub const FILE_RIGHTS: [(&str, u32); 4] = [
    ("FA", 0x001F_01FF),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00A0),
];

/// Read-only codes (registry keys), accepted but never written.
const KEY_RIGHTS: [(&str, u32); 4] = [
    ("KA", 0x000F_003F),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    ("KX", 0x0002_0019),
];

/// Every bit that the rights codes name.
const ALL_RIGHTS: u32 = 0xF01FF | GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ;

fn sddl_invalid(m: String) -> SddlError {
    SddlError::Invalid(m)
}

/// The well-known SIDs of [`ABBREVIATIONS`], parsed once.
fn abbreviated() -> &'static [(&'static str, Sid)] {
    static TABLE: OnceLock<Vec<(&'static str, Sid)>> = OnceLock::new();
    TABLE.get_or_init(|| {
        ABBREVIATIONS
            .iter()
            .filter_map(|(code, text)| Some((*code, text.parse().ok()?)))
            .collect()
    })
}

/// SID in SDDL: its abbreviation when it has one, `S-1-…` otherwise.
pub fn sid_to_sddl(sid: &Sid, domain: Option<&Sid>) -> String {
    if let Some((code, _)) = abbreviated().iter().find(|(_, s)| s == sid) {
        return code.to_string();
    }
    let relative = match (domain, sid.sub_authorities().split_last()) {
        (Some(domain), Some((rid, head)))
            if sid.authority() == domain.authority() && head == domain.sub_authorities() =>
        {
            DOMAIN_ABBREVIATIONS.iter().find(|(_, r)| r == rid)
        }
        _ => None,
    };
    if let Some((code, _)) = relative {
        return code.to_string();
    }
    sid.to_string()
}

pub fn sid_from_sddl(text: &str, domain: Option<&Sid>) -> Result<Sid> {
    if let Some((_, sid)) = abbreviated().iter().find(|(c, _)| *c == text) {
        return Ok(*sid);
    }
    if let Some((_, rid)) = DOMAIN_ABBREVIATIONS.iter().find(|(c, _)| *c == text) {
        return domain
            .filter(|d| d.is_domain_sid())
            .and_then(|d| d.with_rid(*rid).ok())
            .ok_or_else(|| sddl_invalid(format!("abbreviation {text} without a domain SID")));
    }
    text.parse()
        .map_err(|_| sddl_invalid(format!("invalid SID: {text:?}")))
}

pub fn mask_to_sddl(mask: u32) -> String {
    if let Some((code, _)) = FILE_RIGHTS.iter().find(|(_, v)| *v == mask) {
        return code.to_string();
    }
    if mask & !ALL_RIGHTS != 0 {
        return format!("0x{mask:x}");
    }
    RIGHTS
        .iter()
        .filter(|(_, bit)| mask & bit != 0)
        .map(|(code, _)| *code)
        .collect()
}

pub fn mask_from_sddl(text: &str) -> Result<u32> {
    let chars = pytext::chars(text);
    mask_from_chars(&chars)
}

fn mask_from_chars(text: &[char]) -> Result<u32> {
    let shown = || pytext::string(text);
    if text.is_empty() {
        return Ok(0);
    }
    if pytext::head2_lower(text) == "0x" {
        // int(text, 16): the value modulo 2^32.
        return pytext::py_int(text, 16)
            .map(|v| v.mask64() as u32)
            .ok_or_else(|| sddl_invalid(format!("invalid mask: {:?}", shown())));
    }
    if text.iter().all(|c| c.is_ascii_digit()) {
        return pytext::py_int(text, 10)
            .map(|v| v.mask64() as u32)
            .ok_or_else(|| sddl_invalid(format!("invalid mask: {:?}", shown())));
    }
    if text.len() % 2 != 0 {
        return Err(sddl_invalid(format!("invalid mask: {:?}", shown())));
    }
    let mut mask = 0;
    for pair in text.chunks(2) {
        let code: String = pair.iter().collect();
        let bit = RIGHTS
            .iter()
            .chain(FILE_RIGHTS.iter())
            .chain(KEY_RIGHTS.iter())
            .find(|(c, _)| *c == code)
            .map(|(_, b)| *b)
            .ok_or_else(|| sddl_invalid(format!("unknown right: {code:?}")))?;
        mask |= bit;
    }
    Ok(mask)
}

fn flags_to_sddl<T>(flags: T, table: &[(&str, T)]) -> Result<String>
where
    T: Copy + std::ops::BitAnd<Output = T> + std::ops::BitOr<Output = T> + PartialEq + Default,
    T: std::ops::Not<Output = T> + std::fmt::LowerHex,
{
    let known = table.iter().fold(T::default(), |acc, (_, b)| acc | *b);
    if flags & !known != T::default() {
        return Err(SddlError::Unrepresentable(format!(
            "flags not representable: 0x{flags:x}"
        )));
    }
    Ok(table
        .iter()
        .filter(|(_, b)| flags & *b != T::default())
        .map(|(c, _)| *c)
        .collect())
}

fn flags_from_sddl<T>(text: &[char], table: &[(&str, T)]) -> Result<T>
where
    T: Copy + std::ops::BitOr<Output = T> + Default,
{
    let mut flags = T::default();
    let mut position = 0;
    while position < text.len() {
        let found = table
            .iter()
            .find(|(c, _)| pytext::starts_with(from(text, position), c));
        let Some((code, bit)) = found else {
            return Err(sddl_invalid(format!(
                "unknown flag in {:?}",
                pytext::string(text)
            )));
        };
        flags = flags | *bit;
        position += code.chars().count();
    }
    Ok(flags)
}

fn type_name(ace_type: u8) -> Option<&'static str> {
    ACE_TYPES
        .iter()
        .chain(CONDITIONAL_TYPES.iter())
        .find(|(t, _)| *t == ace_type)
        .map(|(_, n)| *n)
}

fn is_conditional(ace_type: u8) -> bool {
    CONDITIONAL_TYPES.iter().any(|(t, _)| *t == ace_type)
}

/// One ACE in parentheses; `Error::SddlUnrepresentable` outside the eight usual types and
/// the conditional and resource attribute ACEs ([`CONDITIONAL_TYPES`]).
pub fn ace_to_sddl(ace: &Ace, domain: Option<&Sid>) -> Result<String> {
    let name = type_name(ace.ace_type).ok_or_else(|| {
        SddlError::Unrepresentable(format!("ACE of type {}: no SDDL form", ace.ace_type))
    })?;
    let sid = ace
        .sid()
        .ok_or_else(|| SddlError::Invalid("ACE with a malformed SID".into()))?;
    let mut fields = vec![
        name.to_string(),
        flags_to_sddl(ace.flags, &ACE_FLAGS)?,
        mask_to_sddl(ace.mask()),
        ace.object_type().map(|g| g.to_string()).unwrap_or_default(),
        ace.inherited_object_type()
            .map(|g| g.to_string())
            .unwrap_or_default(),
        sid_to_sddl(&sid, domain),
    ];
    let unrepresentable = |e: ConditionError| {
        SddlError::Unrepresentable(format!("ACE of type {}: {e}", ace.ace_type))
    };
    if ace.ace_type == SYSTEM_RESOURCE_ATTRIBUTE {
        fields.push(condition::resource_attribute_to_sddl(ace.data()).map_err(unrepresentable)?);
    } else if is_conditional(ace.ace_type) {
        fields.push(condition::condition_to_sddl(ace.data()).map_err(unrepresentable)?);
    }
    Ok(format!("({})", fields.join(";")))
}

/// `text` split at `separator` outside parentheses and double quotes.
fn split_outside(text: &[char], separator: char) -> Vec<&[char]> {
    let mut pieces = Vec::new();
    let mut depth: i64 = 0;
    let mut quote = false;
    let mut start = 0;
    for (i, &c) in text.iter().enumerate() {
        if c == '"' {
            quote = !quote;
        } else if quote {
            continue;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
        } else if c == separator && depth == 0 {
            pieces.push(sub(text, start, i));
            start = i + 1;
        }
    }
    pieces.push(from(text, start));
    pieces
}

/// One ACE in parentheses, of one of the types of [`ACE_TYPES`] or [`CONDITIONAL_TYPES`]
/// (seventh field: the condition, or the resource attribute of an `RA`). `samba`: a
/// resource attribute stored as Samba 4.22 does ([`condition::encode_resource_attribute`]).
pub fn ace_from_sddl(text: &str, domain: Option<&Sid>, samba: bool) -> Result<Ace> {
    ace_from_chars(&pytext::chars(text), domain, samba)
}

fn ace_from_chars(text: &[char], domain: Option<&Sid>, samba: bool) -> Result<Ace> {
    let shown = || pytext::string(text);
    let body = pytext::strip(text);
    if body.first() != Some(&'(') || body.last() != Some(&')') || body.len() < 2 {
        return Err(sddl_invalid(format!("malformed ACE: {:?}", shown())));
    }
    let fields = split_outside(sub(body, 1, body.len() - 1), ';');
    let (f, condition_field) = match fields.as_slice() {
        [a, b, c, d, e, g] => ([*a, *b, *c, *d, *e, *g], None),
        [a, b, c, d, e, g, h] => ([*a, *b, *c, *d, *e, *g], Some(*h)),
        _ => return Err(sddl_invalid(format!("malformed ACE: {:?}", shown()))),
    };
    let [
        type_text,
        flags_text,
        mask_text,
        object_text,
        inherited_text,
        sid_text,
    ] = f.map(pytext::strip);
    let name = pytext::string(type_text).to_uppercase();
    let ace_type = ACE_TYPES
        .iter()
        .chain(CONDITIONAL_TYPES.iter())
        .find(|(_, n)| *n == name)
        .map(|(t, _)| *t)
        .ok_or_else(|| {
            sddl_invalid(format!("unknown ACE type: {:?}", pytext::string(type_text)))
        })?;
    let flags = flags_from_sddl(flags_text, &ACE_FLAGS)?;
    let mask = mask_from_chars(mask_text)?;
    let sid = sid_from_sddl(&pytext::string(sid_text), domain)?;
    let conditional = is_conditional(ace_type);
    if conditional != condition_field.is_some() {
        let what = if conditional { "missing" } else { "unexpected" };
        return Err(sddl_invalid(format!("condition {what}: {:?}", shown())));
    }
    let guid = |g: &[char]| -> Result<Option<Guid>> {
        if g.is_empty() {
            return Ok(None);
        }
        pytext::string(g)
            .parse()
            .map(Some)
            .map_err(|_| sddl_invalid(format!("invalid GUID in {:?}", shown())))
    };
    let object = guid(object_text)?;
    let inherited = guid(inherited_text)?;
    if let Some(condition_field) = condition_field {
        if ace_type != ACCESS_ALLOWED_CALLBACK_OBJECT && (object.is_some() || inherited.is_some()) {
            return Err(sddl_invalid(format!(
                "GUID in an ACE without object: {:?}",
                shown()
            )));
        }
        let field = pytext::string(condition_field);
        let wrap = |e: ConditionError| {
            let message = match e {
                ConditionError::Invalid { message, .. } => message,
                other => other.to_string(),
            };
            sddl_invalid(format!(
                "{message}: {:?}",
                pytext::string(pytext::strip(condition_field))
            ))
        };
        let data = if ace_type == SYSTEM_RESOURCE_ATTRIBUTE {
            let attribute =
                condition::resource_attribute_from_sddl(&field, domain).map_err(wrap)?;
            condition::encode_resource_attribute(&attribute, samba).map_err(wrap)?
        } else {
            let node = condition::condition_from_sddl(&field, domain).map_err(wrap)?;
            condition::encode_condition(&node).map_err(wrap)?
        };
        let mut body = if ace_type == ACCESS_ALLOWED_CALLBACK_OBJECT {
            object_body(mask, object, inherited)
        } else {
            mask.to_le_bytes().to_vec()
        };
        sid.write_to(&mut body);
        body.extend(data);
        return Ok(Ace {
            ace_type,
            flags,
            body,
        });
    }
    if ace_type <= SYSTEM_ALARM {
        if !object_text.is_empty() || !inherited_text.is_empty() {
            return Err(sddl_invalid(format!("GUID in a simple ACE: {:?}", shown())));
        }
        return Ok(Ace::simple(ace_type, mask, &sid, flags)?);
    }
    Ok(Ace::object(ace_type, mask, &sid, flags, object, inherited)?)
}

fn acl_to_sddl(acl: &Acl, bits: u16, domain: Option<&Sid>) -> Result<String> {
    let mut out: String = ACL_FLAGS
        .iter()
        .filter(|(_, b)| bits & b != 0)
        .map(|(c, _)| *c)
        .collect();
    for a in &acl.aces {
        out.push_str(&ace_to_sddl(a, domain)?);
    }
    Ok(out)
}

/// The descriptor in SDDL, in Samba's form (see the module header).
pub fn sd_to_sddl(sd: &SecurityDescriptor, domain: Option<&Sid>) -> Result<String> {
    let mut out = String::new();
    if let Some(owner) = &sd.owner {
        out.push_str("O:");
        out.push_str(&sid_to_sddl(owner, domain));
    }
    if let Some(group) = &sd.group {
        out.push_str("G:");
        out.push_str(&sid_to_sddl(group, domain));
    }
    // As Samba: an ACL announced present but absent (zero offset) is not written.
    if let (true, Some(dacl)) = (sd.control & SE_DACL_PRESENT != 0, &sd.dacl) {
        out.push_str("D:");
        out.push_str(&acl_to_sddl(dacl, sd.control, domain)?);
    }
    if let (true, Some(sacl)) = (sd.control & SE_SACL_PRESENT != 0, &sd.sacl) {
        out.push_str("S:");
        out.push_str(&acl_to_sddl(sacl, sd.control >> 1, domain)?);
    }
    Ok(out)
}

/// Whitespace removed, except in a condition (seventh field of an ACE, depth 2) and in a
/// quoted string, where it separates or belongs to the terms.
fn without_blanks(text: &[char]) -> Vec<char> {
    let mut out = Vec::with_capacity(text.len());
    let mut depth: i64 = 0;
    let mut quote = false;
    for &c in text {
        if c == '"' {
            quote = !quote;
        } else if !quote {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
            } else if pytext::is_space(c) && depth < 2 {
                continue;
            }
        }
        out.push(c);
    }
    out
}

/// Splits `O:…G:…D:…S:…`; an "X:" in parentheses or quotes does not split.
fn sections(text: &[char]) -> Result<Vec<(char, &[char])>> {
    let shown = || pytext::string(text);
    let mut found: Vec<(char, usize)> = Vec::new();
    let mut ends: Vec<usize> = Vec::new();
    let mut depth: i64 = 0;
    let mut quote = false;
    for (i, &c) in text.iter().enumerate() {
        if c == '"' {
            quote = !quote;
        } else if quote {
            continue;
        } else if c == '(' {
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth < 0 {
                return Err(sddl_invalid(format!(
                    "extra closing parenthesis: {:?}",
                    shown()
                )));
            }
        } else if depth == 0 && "OGDS".contains(c) && at(text, i + 1) == Some(':') {
            if !found.is_empty() {
                ends.push(i);
            } else if i != 0 {
                return Err(sddl_invalid(format!(
                    "text before the first section: {:?}",
                    shown()
                )));
            }
            found.push((c, i + 2));
        }
    }
    if depth != 0 || quote {
        return Err(sddl_invalid(format!(
            "unclosed parenthesis or quote: {:?}",
            shown()
        )));
    }
    if found.is_empty() {
        if !text.is_empty() {
            return Err(sddl_invalid(format!("no section: {:?}", shown())));
        }
        return Ok(Vec::new());
    }
    ends.push(text.len());
    let mut out: Vec<(char, &[char])> = Vec::new();
    for ((name, start), end) in found.into_iter().zip(ends) {
        if out.iter().any(|(n, _)| *n == name) {
            return Err(sddl_invalid(format!("duplicate section: {:?}", shown())));
        }
        // A section that starts after the next one's start (`O:` right before `G:`) is
        // empty, as with Python's slicing.
        out.push((name, sub(text, start, end)));
    }
    Ok(out)
}

/// The top-level parenthesised groups (the ACEs of an ACL); `SddlInvalid` for text outside
/// a group. A double quote outside a group only toggles the quote state, as in Python.
fn groups(text: &[char]) -> Result<Vec<&[char]>> {
    let mut out = Vec::new();
    let mut depth: i64 = 0;
    let mut quote = false;
    let mut start = 0;
    for (i, &c) in text.iter().enumerate() {
        if c == '"' {
            quote = !quote;
            continue;
        }
        if quote {
            continue;
        }
        if c == '(' {
            if depth == 0 {
                start = i;
            }
            depth += 1;
        } else if c == ')' {
            depth -= 1;
            if depth == 0 {
                out.push(sub(text, start, i + 1));
            }
        } else if depth == 0 {
            return Err(sddl_invalid(format!(
                "text outside an ACE: {:?}",
                pytext::string(text)
            )));
        }
    }
    Ok(out)
}

/// SDDL → descriptor, byte for byte as Samba's `from_sddl` (ACLs in revision 4).
///
/// The round trip bytes → SDDL → bytes holds up to content: the revision of an ACL, the
/// `SE_*_DEFAULTED` control bits and any ACE padding are not written in SDDL. Conditional
/// and resource attribute ACEs are read in Samba's form as in Windows'; `samba`: see
/// [`ace_from_sddl`].
pub fn sd_from_sddl(text: &str, domain: Option<&Sid>, samba: bool) -> Result<SecurityDescriptor> {
    let chars = without_blanks(&pytext::chars(text));
    let sections = sections(&chars)?;
    let get = |n: char| {
        sections
            .iter()
            .find(|(name, _)| *name == n)
            .map(|(_, t)| *t)
    };
    let mut control = SE_SELF_RELATIVE;
    let owner = get('O')
        .map(|t| sid_from_sddl(&pytext::string(t), domain))
        .transpose()?;
    let group = get('G')
        .map(|t| sid_from_sddl(&pytext::string(t), domain))
        .transpose()?;
    let mut acl = |letter: char, present: u16, shift: u32| -> Result<Option<Acl>> {
        let Some(content) = get(letter) else {
            return Ok(None);
        };
        let split = pytext::find(content, '(', 0).unwrap_or(content.len());
        let (head, rest) = (sub(content, 0, split), from(content, split));
        control |= present | (flags_from_sddl(head, &ACL_FLAGS)? << shift);
        let aces = groups(rest)?
            .into_iter()
            .map(|g| ace_from_chars(g, domain, samba))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(Acl {
            revision: ACL_REVISION_DS,
            aces,
        }))
    };
    let dacl = acl('D', SE_DACL_PRESENT, 0)?;
    let sacl = acl('S', SE_SACL_PRESENT, 1)?;
    Ok(SecurityDescriptor {
        revision: REVISION,
        control,
        owner,
        group,
        sacl,
        dacl,
    })
}

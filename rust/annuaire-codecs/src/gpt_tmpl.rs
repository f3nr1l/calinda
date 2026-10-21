// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `GptTmpl.inf`: security settings of a GPO (MS-GPSB 2.2), reading and writing.
//!
//! The file is `Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf` in the folder of the GPO,
//! a security template in INF form: sections `[Name]` followed by lines `key = value`. The
//! GPMC writes it in UTF-16LE with a BOM and CRLF line endings, `[Unicode]` first and
//! `[Version]` (`signature="$CHICAGO$"`, `Revision=1`) last; `samba-tool gpo manage security
//! set` writes UTF-8 without BOM nor these two sections.
//!
//! Sections read by the tool:
//! - `[System Access]`: password and lockout policies, one integer per key;
//! - `[Kerberos Policy]`: ticket lifetimes;
//! - `[Privilege Rights]`: user rights, `SeXxxPrivilege = *SID,*SID,name` (an empty value
//!   says "nobody", which is not "not defined");
//! - `[Group Membership]`: restricted groups, `*SID__Members = …` (members imposed on the
//!   group) and `*SID__Memberof = …` (groups it must belong to).
//!
//! Any other section is kept as is.
//!
//! Byte-for-byte round trip: the file is kept line by line, line endings included; a change
//! rewrites only the lines it touches. Section and key names compare without case, as
//! Windows does.

use std::fmt;

use crate::pytext::{self, lstrip_str as lstrip, strip_str as strip};

/// Place of the file in the folder of a GPO (the case of `Machine` varies).
pub const PATH: &str = "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf";

pub const SYSTEM_ACCESS: &str = "System Access";
pub const KERBEROS: &str = "Kerberos Policy";
pub const PRIVILEGE_RIGHTS: &str = "Privilege Rights";
pub const GROUP_MEMBERSHIP: &str = "Group Membership";
pub const UNICODE: &str = "Unicode";
pub const VERSION: &str = "Version";

pub const MEMBERS: &str = "__Members";
pub const MEMBER_OF: &str = "__Memberof";

/// Order of the sections in a file of the GPMC or of `secedit /export`: a new section goes
/// before the first present section that follows it in this order.
pub const ORDER: [&str; 11] = [
    UNICODE,
    SYSTEM_ACCESS,
    KERBEROS,
    "Event Audit",
    "Registry Values",
    PRIVILEGE_RIGHTS,
    GROUP_MEMBERSHIP,
    "Service General Setting",
    "Registry Keys",
    "File Security",
    VERSION,
];

/// Order of the keys of `[System Access]`, as the GPMC writes them.
pub const SYSTEM_ACCESS_KEYS: [&str; 17] = [
    "MinimumPasswordAge",
    "MaximumPasswordAge",
    "MinimumPasswordLength",
    "PasswordComplexity",
    "PasswordHistorySize",
    "LockoutBadCount",
    "ResetLockoutCount",
    "LockoutDuration",
    "AllowAdministratorLockout",
    "RequireLogonToChangePassword",
    "ForceLogoffWhenHourExpire",
    "NewAdministratorName",
    "NewGuestName",
    "ClearTextPassword",
    "LSAAnonymousNameLookup",
    "EnableAdminAccount",
    "EnableGuestAccount",
];

/// Order of the keys of `[Kerberos Policy]`.
pub const KERBEROS_KEYS: [&str; 5] = [
    "MaxTicketAge",
    "MaxRenewAge",
    "MaxServiceAge",
    "MaxClockSkew",
    "TicketValidateClient",
];

/// Why a file or a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InfError {
    /// The bytes are not text in the detected encoding.
    Unreadable,
    /// A character cannot be written in the encoding of the file (ANSI).
    Unencodable(char),
    /// The value of a key is not an integer.
    NotAnInteger { key: String, value: String },
}

impl fmt::Display for InfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable => write!(f, "GptTmpl.inf: unreadable text"),
            Self::Unencodable(c) => write!(f, "GptTmpl.inf: {c:?} has no Windows-1252 byte"),
            Self::NotAnInteger { key, value } => {
                write!(f, "GptTmpl.inf: {key:?} is not an integer ({value})")
            }
        }
    }
}

impl std::error::Error for InfError {}

/// Encoding of the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// GPMC, `secedit`.
    Utf16Le,
    /// samba-tool.
    Utf8,
    /// ANSI file (Windows-1252).
    Cp1252,
}

impl Encoding {
    /// Python's codec name (`utf-16-le`, `utf-8`, `cp1252`).
    pub fn name(self) -> &'static str {
        match self {
            Self::Utf16Le => "utf-16-le",
            Self::Utf8 => "utf-8",
            Self::Cp1252 => "cp1252",
        }
    }
}

/// A section: its name (without brackets) and its lines, header included, each with its
/// line ending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: String,
    pub lines: Vec<String>,
}

/// A whole file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inf {
    pub encoding: Encoding,
    pub bom: bool,
    /// Line ending of the first line; used for the lines added.
    pub line_ending: String,
    /// Lines before the first section (comments, empty lines).
    pub prologue: Vec<String>,
    pub sections: Vec<Section>,
}

/// An entry of `[Group Membership]`. `None`: the line does not exist (not defined); empty
/// list: defined and empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestrictedGroup {
    pub group: String,
    pub members: Option<Vec<String>>,
    pub member_of: Option<Vec<String>>,
}

// --- Windows-1252 ------------------------------------------------------------------------------

/// Bytes 0x80 to 0x9F of Windows-1252; `None` for the five undefined ones (refused, as
/// Python's codec does).
const CP1252_HIGH: [Option<char>; 32] = [
    Some('\u{20ac}'),
    None,
    Some('\u{201a}'),
    Some('\u{0192}'),
    Some('\u{201e}'),
    Some('\u{2026}'),
    Some('\u{2020}'),
    Some('\u{2021}'),
    Some('\u{02c6}'),
    Some('\u{2030}'),
    Some('\u{0160}'),
    Some('\u{2039}'),
    Some('\u{0152}'),
    None,
    Some('\u{017d}'),
    None,
    None,
    Some('\u{2018}'),
    Some('\u{2019}'),
    Some('\u{201c}'),
    Some('\u{201d}'),
    Some('\u{2022}'),
    Some('\u{2013}'),
    Some('\u{2014}'),
    Some('\u{02dc}'),
    Some('\u{2122}'),
    Some('\u{0161}'),
    Some('\u{203a}'),
    Some('\u{0153}'),
    None,
    Some('\u{017e}'),
    Some('\u{0178}'),
];

fn cp1252_decode(bytes: &[u8]) -> Option<String> {
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9f => CP1252_HIGH.get(usize::from(b - 0x80)).copied().flatten(),
            _ => Some(char::from(b)),
        })
        .collect()
}

fn cp1252_encode(text: &str) -> Result<Vec<u8>, InfError> {
    text.chars()
        .map(|c| match u32::from(c) {
            n @ (0..=0x7f | 0xa0..=0xff) => Ok(n as u8),
            _ => CP1252_HIGH
                .iter()
                .position(|&h| h == Some(c))
                .map(|i| 0x80 + i as u8)
                .ok_or(InfError::Unencodable(c)),
        })
        .collect()
}

fn utf16le_decode(bytes: &[u8]) -> Option<String> {
    if bytes.len() % 2 != 0 {
        return None;
    }
    let units = bytes.chunks_exact(2).map(|p| {
        u16::from_le_bytes([
            p.first().copied().unwrap_or(0),
            p.last().copied().unwrap_or(0),
        ])
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .ok()
}

fn decode_text(bytes: &[u8]) -> Result<(String, Encoding, bool), InfError> {
    if let Some(rest) = bytes.strip_prefix(b"\xff\xfe") {
        let text = utf16le_decode(rest).ok_or(InfError::Unreadable)?;
        return Ok((text, Encoding::Utf16Le, true));
    }
    if let Some(rest) = bytes.strip_prefix(b"\xef\xbb\xbf") {
        let text = String::from_utf8(rest.to_vec()).map_err(|_| InfError::Unreadable)?;
        return Ok((text, Encoding::Utf8, true));
    }
    // UTF-16 without BOM: one zero byte in two in the first ASCII characters.
    if let [b0, 0, _, 0, ..] = bytes
        && *b0 != 0
    {
        let text = utf16le_decode(bytes).ok_or(InfError::Unreadable)?;
        return Ok((text, Encoding::Utf16Le, false));
    }
    match String::from_utf8(bytes.to_vec()) {
        Ok(text) => Ok((text, Encoding::Utf8, false)),
        Err(_) => cp1252_decode(bytes)
            .map(|t| (t, Encoding::Cp1252, false))
            .ok_or(InfError::Unreadable),
    }
}

// --- Lines ----------------------------------------------------------------------------------

/// Lines of `text`, each with its ending (`\r\n`, `\n` or `\r`); the last may have none.
fn split_lines(text: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        let end = match b {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => i + 2,
            b'\r' | b'\n' => i + 1,
            _ => {
                i += 1;
                continue;
            }
        };
        lines.push(text.get(start..end).unwrap_or_default().to_owned());
        start = end;
        i = end;
    }
    if start < text.len() {
        lines.push(text.get(start..).unwrap_or_default().to_owned());
    }
    lines
}

/// The line without its ending.
fn content(line: &str) -> &str {
    line.trim_end_matches(['\r', '\n'])
}

fn has_ending(line: &str) -> bool {
    content(line).len() != line.len()
}

fn section_name(line: &str) -> Option<String> {
    let text = strip(content(line));
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    Some(strip(inner).to_owned())
}

/// `key = value` of a line, both stripped; `None` for an empty line, a comment (`;`) or a
/// line without `=`.
fn key_value(line: &str) -> Option<(String, String)> {
    let text = content(line);
    if strip(text).is_empty() || lstrip(text).starts_with(';') {
        return None;
    }
    let (key, value) = text.split_once('=')?;
    Some((strip(key).to_owned(), strip(value).to_owned()))
}

fn same(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// Before an insertion at `position`, gives its line ending to the line before it if it has
/// none (last line of a file without final line ending).
fn terminate(lines: &mut [String], position: usize, ending: &str) {
    if let Some(previous) = position.checked_sub(1).and_then(|p| lines.get_mut(p))
        && !has_ending(previous)
    {
        previous.push_str(ending);
    }
}

fn rank(name: &str) -> Option<usize> {
    ORDER.iter().position(|o| same(o, name))
}

fn key_order(section: &str) -> &'static [&'static str] {
    if same(section, SYSTEM_ACCESS) {
        &SYSTEM_ACCESS_KEYS
    } else if same(section, KERBEROS) {
        &KERBEROS_KEYS
    } else {
        &[]
    }
}

/// `*S-1-5-32-544,*S-1-5-32-545,Guest` → the entries, stripped, empty ones left out.
pub fn list(text: &str) -> Vec<String> {
    text.split(',')
        .map(strip)
        .filter(|e| !e.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The SID of an entry `*S-…`; `None` for an account name.
pub fn sid_of(entry: &str) -> Option<&str> {
    entry.strip_prefix('*')
}

/// The entry of a SID, as the GPMC writes it: `*S-…`.
pub fn sid_entry(sid: &str) -> String {
    format!("*{sid}")
}

/// Python's `int()` in base 10. Python also takes other Unicode decimal digits and integers
/// beyond 64 bits: both are refused here.
fn python_int(text: &str) -> Option<i64> {
    let value = pytext::py_int(&pytext::chars(text), 10)?.to_i128()?;
    i64::try_from(value).ok()
}

impl Inf {
    /// The file cut into sections; an error if it is not text.
    pub fn read(bytes: &[u8]) -> Result<Self, InfError> {
        let (text, encoding, bom) = decode_text(bytes)?;
        let lines = split_lines(&text);
        let line_ending = lines
            .first()
            .map(|l| l.get(content(l).len()..).unwrap_or_default().to_owned())
            .filter(|e| !e.is_empty())
            .unwrap_or_else(|| {
                if encoding == Encoding::Utf16Le {
                    "\r\n".to_owned()
                } else {
                    "\n".to_owned()
                }
            });
        let mut prologue = Vec::new();
        let mut sections: Vec<Section> = Vec::new();
        for line in lines {
            if let Some(name) = section_name(&line) {
                sections.push(Section {
                    name,
                    lines: vec![line],
                });
            } else if let Some(current) = sections.last_mut() {
                current.lines.push(line);
            } else {
                prologue.push(line);
            }
        }
        Ok(Self {
            encoding,
            bom,
            line_ending,
            prologue,
            sections,
        })
    }

    /// The bytes of the file; the original ones if nothing changed.
    pub fn write(&self) -> Result<Vec<u8>, InfError> {
        let text: String = self
            .prologue
            .iter()
            .chain(self.sections.iter().flat_map(|s| &s.lines))
            .map(String::as_str)
            .collect();
        let mut out = Vec::with_capacity(text.len() * 2 + 3);
        match self.encoding {
            Encoding::Utf16Le => {
                if self.bom {
                    out.extend_from_slice(b"\xff\xfe");
                }
                for unit in text.encode_utf16() {
                    out.extend_from_slice(&unit.to_le_bytes());
                }
            }
            Encoding::Utf8 => {
                if self.bom {
                    out.extend_from_slice(b"\xef\xbb\xbf");
                }
                out.extend_from_slice(text.as_bytes());
            }
            Encoding::Cp1252 => {
                if self.bom {
                    out.extend_from_slice(b"\xef\xbb\xbf");
                }
                out.extend(cp1252_encode(&text)?);
            }
        }
        Ok(out)
    }

    /// An empty file as the GPMC writes it: UTF-16LE with BOM, CRLF, `[Unicode]` and
    /// `[Version]`.
    pub fn new_gpmc() -> Self {
        let e = "\r\n";
        Self {
            encoding: Encoding::Utf16Le,
            bom: true,
            line_ending: e.to_owned(),
            prologue: Vec::new(),
            sections: vec![
                Section {
                    name: UNICODE.to_owned(),
                    lines: vec![format!("[{UNICODE}]{e}"), format!("Unicode=yes{e}")],
                },
                Section {
                    name: VERSION.to_owned(),
                    lines: vec![
                        format!("[{VERSION}]{e}"),
                        format!("signature=\"$CHICAGO$\"{e}"),
                        format!("Revision=1{e}"),
                    ],
                },
            ],
        }
    }

    fn section_index(&self, name: &str) -> Option<usize> {
        self.sections.iter().position(|s| same(&s.name, name))
    }

    /// The first section of this name (case ignored).
    pub fn section(&self, name: &str) -> Option<&Section> {
        self.section_index(name).and_then(|i| self.sections.get(i))
    }

    /// The `key = value` pairs of a section, in file order (empty if the section is absent).
    pub fn values(&self, section: &str) -> Vec<(String, String)> {
        self.section(section)
            .map(|s| {
                s.lines
                    .iter()
                    .skip(1)
                    .filter_map(|l| key_value(l))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The value of a key (the last one if repeated); `None` if it is not defined.
    pub fn value(&self, section: &str, key: &str) -> Option<String> {
        self.values(section)
            .into_iter()
            .rfind(|(k, _)| same(k, key))
            .map(|(_, v)| v)
    }

    /// An integer value (`[System Access]`, `[Kerberos Policy]`); `None` if not defined.
    pub fn integer(&self, section: &str, key: &str) -> Result<Option<i64>, InfError> {
        let Some(text) = self.value(section, key) else {
            return Ok(None);
        };
        python_int(&text)
            .map(Some)
            .ok_or_else(|| InfError::NotAnInteger {
                key: key.to_owned(),
                value: text,
            })
    }

    /// `[Privilege Rights]`: right → entries, in file order. An empty value is kept (the
    /// right is granted to nobody); a key repeated with the same spelling keeps its first
    /// place and its last value.
    pub fn rights(&self) -> Vec<(String, Vec<String>)> {
        let mut rights: Vec<(String, Vec<String>)> = Vec::new();
        for (key, value) in self.values(PRIVILEGE_RIGHTS) {
            match rights.iter_mut().find(|(k, _)| *k == key) {
                Some(entry) => entry.1 = list(&value),
                None => rights.push((key, list(&value))),
            }
        }
        rights
    }

    pub fn right(&self, name: &str) -> Option<Vec<String>> {
        self.value(PRIVILEGE_RIGHTS, name).map(|v| list(&v))
    }

    /// `[Group Membership]` grouped by group, in order of first appearance.
    pub fn restricted_groups(&self) -> Vec<RestrictedGroup> {
        let mut groups: Vec<(String, RestrictedGroup)> = Vec::new();
        for (key, value) in self.values(GROUP_MEMBERSHIP) {
            let lower = key.to_lowercase();
            let (suffix, members) = if lower.ends_with(&MEMBERS.to_lowercase()) {
                (MEMBERS, true)
            } else if lower.ends_with(&MEMBER_OF.to_lowercase()) {
                (MEMBER_OF, false)
            } else {
                continue;
            };
            // Python slices by code points: drop as many characters as the suffix has.
            let keep = key.chars().count().saturating_sub(suffix.len());
            let group: String = key.chars().take(keep).collect();
            let id = group.to_lowercase();
            let index = match groups.iter().position(|(g, _)| *g == id) {
                Some(i) => i,
                None => {
                    groups.push((
                        id,
                        RestrictedGroup {
                            group,
                            members: None,
                            member_of: None,
                        },
                    ));
                    groups.len() - 1
                }
            };
            if let Some((_, entry)) = groups.get_mut(index) {
                if members {
                    entry.members = Some(list(&value));
                } else {
                    entry.member_of = Some(list(&value));
                }
            }
        }
        groups.into_iter().map(|(_, g)| g).collect()
    }

    /// True if the file defines nothing (only `[Unicode]` and `[Version]`).
    pub fn is_empty(&self) -> bool {
        !self.sections.iter().any(|s| {
            !same(&s.name, UNICODE)
                && !same(&s.name, VERSION)
                && s.lines.iter().skip(1).any(|l| key_value(l).is_some())
        })
    }

    fn one_only(&self, section: &str, key: &str) -> bool {
        self.values(section)
            .iter()
            .filter(|(k, _)| same(k, key))
            .count()
            == 1
    }

    fn existing_key(&self, section: &str, key: &str) -> String {
        self.values(section)
            .into_iter()
            .map(|(k, _)| k)
            .find(|k| same(k, key))
            .unwrap_or_else(|| key.to_owned())
    }

    /// `self` with the section `name`, added empty at its place if missing; returns its
    /// index.
    fn with_section(&mut self, name: &str) -> usize {
        if let Some(i) = self.section_index(name) {
            return i;
        }
        let new = Section {
            name: name.to_owned(),
            lines: vec![format!("[{name}]{}", self.line_ending)],
        };
        let own_rank = rank(name);
        let position = self
            .sections
            .iter()
            .position(|s| matches!((rank(&s.name), own_rank), (Some(r), Some(o)) if r > o))
            .unwrap_or(self.sections.len());
        // The last line of the file may lack its ending: give it one before adding anything
        // after it (last section, or the prologue when there is none).
        if position == self.sections.len() {
            let lines = match self.sections.last_mut() {
                Some(last) => &mut last.lines,
                None => &mut self.prologue,
            };
            let end = lines.len();
            terminate(lines, end, &self.line_ending);
        }
        self.sections.insert(position, new);
        position
    }

    /// `self` where `key` is `text` in `section`; `None` removes the key (not defined).
    ///
    /// The existing line is replaced in place (its spelling of the key kept) and its
    /// duplicates removed; a new key goes at its place in the order of the GPMC, else after
    /// the last `key = value` line of the section, a new section at its place in the order of
    /// the GPMC. A section emptied of all keys by a removal goes away. Nothing changes if
    /// the value is already this one.
    pub fn set(&self, section: &str, key: &str, text: Option<&str>) -> Self {
        let current = self.value(section, key);
        if current.as_deref() == text && (text.is_none() || self.one_only(section, key)) {
            return self.clone();
        }
        if text.is_none() && self.section(section).is_none() {
            return self.clone();
        }
        let mut inf = self.clone();
        let index = inf.with_section(section);
        let ending = inf.line_ending.clone();
        let Some(s) = inf.sections.get(index) else {
            return inf;
        };
        let order: Vec<String> = key_order(section)
            .iter()
            .map(|k| k.to_lowercase())
            .collect();
        let own = order.iter().position(|k| *k == key.to_lowercase());
        let mut lines: Vec<String> = s.lines.iter().take(1).cloned().collect();
        let mut done = text.is_none();
        let mut last_pair = 0;
        let mut before: Option<usize> = None;
        for line in s.lines.iter().skip(1) {
            let pair = key_value(line);
            if before.is_none()
                && let (Some(own), Some((k, _))) = (own, &pair)
                && order
                    .iter()
                    .position(|o| *o == k.to_lowercase())
                    .is_some_and(|r| r > own)
            {
                before = Some(lines.len());
            }
            if let Some((k, _)) = &pair
                && same(k, key)
            {
                if let (false, Some(t)) = (done, text) {
                    let line_end = line.get(content(line).len()..).unwrap_or_default();
                    let line_end = if line_end.is_empty() {
                        &ending
                    } else {
                        line_end
                    };
                    lines.push(format!("{k} = {t}{line_end}"));
                    last_pair = lines.len();
                    done = true;
                }
                continue;
            }
            lines.push(line.clone());
            if pair.is_some() {
                last_pair = lines.len();
            }
        }
        if let (false, Some(t)) = (done, text) {
            let position = before.unwrap_or(if last_pair == 0 { 1 } else { last_pair });
            terminate(&mut lines, position, &ending);
            lines.insert(position.min(lines.len()), format!("{key} = {t}{ending}"));
        }
        if text.is_none() && !lines.iter().skip(1).any(|l| key_value(l).is_some()) {
            inf.sections.remove(index);
            return inf;
        }
        if let Some(s) = inf.sections.get_mut(index) {
            s.lines = lines;
        }
        inf
    }

    /// `set` of an integer value: left as is if it already has this value, even written
    /// otherwise (`007`).
    pub fn set_integer(&self, section: &str, key: &str, number: Option<i64>) -> Self {
        if let Ok(current) = self.integer(section, key)
            && current == number
            && (number.is_none() || self.one_only(section, key))
        {
            return self.clone();
        }
        self.set(section, key, number.map(|n| n.to_string()).as_deref())
    }

    /// The right `name` granted to `entries` (`*SID` or names), in this order; `None`: not
    /// defined; empty list: granted to nobody.
    pub fn set_right(&self, name: &str, entries: Option<&[String]>) -> Self {
        if let Some(e) = entries
            && self.right(name).as_deref() == Some(e)
            && self.one_only(PRIVILEGE_RIGHTS, name)
        {
            return self.clone();
        }
        self.set(
            PRIVILEGE_RIGHTS,
            name,
            entries.map(|e| e.join(",")).as_deref(),
        )
    }

    /// Indices (in `section.lines`) of the lines `group__Members` and `group__Memberof`.
    fn group_lines(section: &Section, group: &str) -> Vec<usize> {
        let targets = [
            format!("{group}{MEMBERS}").to_lowercase(),
            format!("{group}{MEMBER_OF}").to_lowercase(),
        ];
        section
            .lines
            .iter()
            .enumerate()
            .skip(1)
            .filter(|(_, l)| key_value(l).is_some_and(|(k, _)| targets.contains(&k.to_lowercase())))
            .map(|(i, _)| i)
            .collect()
    }

    /// The restricted group `group` (`*SID` or name), written as the GPMC does: two
    /// neighbouring lines, `group__Memberof` then `group__Members`, always both. An empty
    /// list is written `= `. Existing lines keep the spelling of their key.
    pub fn set_group(&self, group: &str, members: &[String], member_of: &[String]) -> Self {
        let current = self
            .restricted_groups()
            .into_iter()
            .find(|g| same(&g.group, group));
        let name = current
            .as_ref()
            .map_or_else(|| group.to_owned(), |g| g.group.clone());
        if let (Some(cur), Some(s)) = (&current, self.section(GROUP_MEMBERSHIP)) {
            let indices = Self::group_lines(s, &name);
            let neighbours = matches!(indices.as_slice(), [a, b] if *b == a + 1);
            let first = indices
                .first()
                .and_then(|&i| s.lines.get(i))
                .and_then(|l| key_value(l));
            let ordered =
                first.is_some_and(|(k, _)| k.to_lowercase().ends_with(&MEMBER_OF.to_lowercase()));
            if neighbours
                && ordered
                && cur.members.as_deref() == Some(members)
                && cur.member_of.as_deref() == Some(member_of)
            {
                return self.clone();
            }
        }
        let mut inf = self.clone();
        let index = inf.with_section(GROUP_MEMBERSHIP);
        let ending = inf.line_ending.clone();
        let key_of = inf.existing_key(GROUP_MEMBERSHIP, &format!("{name}{MEMBER_OF}"));
        let key_m = inf.existing_key(GROUP_MEMBERSHIP, &format!("{name}{MEMBERS}"));
        let Some(s) = inf.sections.get_mut(index) else {
            return inf;
        };
        let indices = Self::group_lines(s, &name);
        let new = [
            format!("{key_of} = {}{ending}", member_of.join(",")),
            format!("{key_m} = {}{ending}", members.join(",")),
        ];
        let mut lines: Vec<String> = s
            .lines
            .iter()
            .enumerate()
            .filter(|(i, _)| !indices.contains(i))
            .map(|(_, l)| l.clone())
            .collect();
        let position = match indices.first() {
            Some(&i) => i,
            None => lines
                .iter()
                .enumerate()
                .skip(1)
                .filter(|(_, l)| key_value(l).is_some())
                .map(|(i, _)| i + 1)
                .next_back()
                .unwrap_or(1),
        };
        let position = position.min(lines.len());
        terminate(&mut lines, position, &ending);
        lines.splice(position..position, new);
        s.lines = lines;
        inf
    }

    /// `self` without the restricted group `group` (section removed if it empties).
    pub fn remove_group(&self, group: &str) -> Self {
        let Some(index) = self.section_index(GROUP_MEMBERSHIP) else {
            return self.clone();
        };
        let Some(s) = self.sections.get(index) else {
            return self.clone();
        };
        let indices = Self::group_lines(s, group);
        if indices.is_empty() {
            return self.clone();
        }
        let lines: Vec<String> = s
            .lines
            .iter()
            .enumerate()
            .filter(|(i, _)| !indices.contains(i))
            .map(|(_, l)| l.clone())
            .collect();
        let mut inf = self.clone();
        if !lines.iter().skip(1).any(|l| key_value(l).is_some()) {
            inf.sections.remove(index);
        } else if let Some(s) = inf.sections.get_mut(index) {
            s.lines = lines;
        }
        inf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn windows(text: &str) -> Vec<u8> {
        let mut out = vec![0xff, 0xfe];
        for u in text.replace('\n', "\r\n").encode_utf16() {
            out.extend_from_slice(&u.to_le_bytes());
        }
        out
    }

    #[test]
    fn round_trip_and_values() {
        let bytes = windows("[Unicode]\nUnicode=yes\n[System Access]\nMinimumPasswordLength = 7\n");
        let inf = Inf::read(&bytes).unwrap();
        assert_eq!(inf.write().unwrap(), bytes);
        assert_eq!(inf.encoding, Encoding::Utf16Le);
        assert_eq!(
            inf.integer(SYSTEM_ACCESS, "minimumpasswordlength"),
            Ok(Some(7))
        );
        let changed = inf.set_integer(SYSTEM_ACCESS, "MinimumPasswordAge", Some(1));
        assert_eq!(
            changed.values(SYSTEM_ACCESS)[0],
            ("MinimumPasswordAge".to_owned(), "1".to_owned())
        );
    }

    #[test]
    fn line_without_ending() {
        let inf = Inf::read(b"[System Access]\nMinimumPasswordLength = 3").unwrap();
        let inf = inf.set_integer(SYSTEM_ACCESS, "LockoutBadCount", Some(5));
        assert_eq!(
            inf.write().unwrap(),
            b"[System Access]\nMinimumPasswordLength = 3\nLockoutBadCount = 5\n"
        );
        let inf = Inf::read(b"; vide").unwrap();
        let inf = inf.set_integer(SYSTEM_ACCESS, "LockoutBadCount", Some(5));
        assert_eq!(
            inf.write().unwrap(),
            b"; vide\n[System Access]\nLockoutBadCount = 5\n"
        );
    }

    #[test]
    fn groups() {
        let inf = Inf::read(b"[Group Membership]\n*S-1-5-32-544__Memberof = ").unwrap();
        let inf = inf.set_group("*S-1-5-32-545", &["*S-1-5-11".to_owned()], &[]);
        assert_eq!(
            inf.write().unwrap(),
            b"[Group Membership]\n*S-1-5-32-544__Memberof = \n\
              *S-1-5-32-545__Memberof = \n*S-1-5-32-545__Members = *S-1-5-11\n"
        );
        let g = inf.restricted_groups();
        assert_eq!(g.len(), 2);
        assert_eq!(g[1].members.as_deref(), Some(&["*S-1-5-11".to_owned()][..]));
        let inf = inf
            .remove_group("*s-1-5-32-545")
            .remove_group("*S-1-5-32-544");
        assert!(inf.section(GROUP_MEMBERSHIP).is_none());
    }

    #[test]
    fn encodings() {
        let ansi = b"[System Access]\r\nNewGuestName = \"Invit\xe9\"\r\n";
        let inf = Inf::read(ansi).unwrap();
        assert_eq!(inf.encoding, Encoding::Cp1252);
        assert_eq!(
            inf.value(SYSTEM_ACCESS, "NewGuestName").unwrap(),
            "\"Invité\""
        );
        assert_eq!(inf.write().unwrap(), ansi);
        assert!(Inf::read(b"\xff\xfe\x00\xd8").is_err());
        assert!(Inf::read(b"\x81").is_err());
        assert_eq!(python_int(" -1_000 "), Some(-1000));
        assert_eq!(python_int("007"), Some(7));
        assert_eq!(python_int("1__0"), None);
        assert_eq!(python_int("beaucoup"), None);
    }
}

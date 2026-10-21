// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `Registry.pol`: registry settings of a GPO (MS-GPREG 2.1, 2.2), reading and writing.
//!
//! Header `PReg` and version 1 (little-endian), then entries `[key;value;type;size;data]`,
//! brackets and semicolons in UTF-16LE like the strings, key and value name ended by a
//! NUL. The size counts the bytes of the data, terminators included. Nothing else in the
//! file: `encode(read(b)) == b`.
//!
//! Special value names (case ignored, MS-GPREG 2.2.1):
//! - `**del.<value>`: the GPO **deletes** the value ("disabled" setting);
//! - `**delvals.`: deletes all the values of the key (the GPMC writes `**delVals.`);
//! - `**DeleteValues`: deletes the values named in the data (`a;b`);
//! - `**DeleteKeys`: deletes the subkeys named in the data;
//! - `**SecureKey`: DWORD 1, the key is reachable by administrators only; 0, ACL restored.
//!
//! The data of the deletion markers is free: the GPMC writes an empty string (`00 00`),
//! the policy editor and samba-tool a space (`20 00 00 00`); both read back identically.

use std::fmt;

use crate::read::le_u32;

pub const SIGNATURE: &[u8; 4] = b"PReg";
pub const VERSION: u32 = 1;
/// A `Registry.pol` without entry.
pub const HEADER: [u8; 8] = *b"PReg\x01\x00\x00\x00";

pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

const TYPE_NAMES: [(u32, &str); 8] = [
    (REG_NONE, "NONE"),
    (REG_SZ, "SZ"),
    (REG_EXPAND_SZ, "EXPAND_SZ"),
    (REG_BINARY, "BINARY"),
    (REG_DWORD, "DWORD"),
    (REG_DWORD_BIG_ENDIAN, "DWORD_BIG_ENDIAN"),
    (REG_MULTI_SZ, "MULTI_SZ"),
    (REG_QWORD, "QWORD"),
];

pub const DEL_PREFIX: &str = "**del.";
pub const DELVALS: &str = "**delvals.";
pub const DELETE_VALUES: &str = "**DeleteValues";
pub const DELETE_KEYS: &str = "**DeleteKeys";
pub const SECURE_KEY: &str = "**SecureKey";
/// Data of a deletion marker written by the tool: a space, as the policy editor does.
pub const DEL_DATA: [u8; 4] = [0x20, 0, 0, 0];

/// Why a file or a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryPolError {
    MissingSignature,
    UnknownVersion(u32),
    /// A bracket or a semicolon expected at this byte.
    Expected {
        expected: char,
        position: usize,
    },
    UnterminatedString,
    Truncated,
    /// UTF-16 that does not decode.
    UnreadableText,
    /// Empty key, or NUL in a key or a value name.
    BadKeyOrName,
    /// NUL inside a text value.
    NulInText,
    /// Integer out of the range of its type.
    IntegerOutOfRange(u64),
    /// The value does not suit the type (integer for DWORD and QWORD, text for SZ…).
    WrongKind(&'static str),
    /// Data longer than 2^32 - 1 bytes.
    TooLong,
}

impl fmt::Display for RegistryPolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSignature => write!(f, "Registry.pol: no PReg signature"),
            Self::UnknownVersion(v) => write!(f, "Registry.pol: unknown version {v}"),
            Self::Expected { expected, position } => {
                write!(f, "Registry.pol: {expected:?} expected at byte {position}")
            }
            Self::UnterminatedString => write!(f, "Registry.pol: string not terminated"),
            Self::Truncated => write!(f, "Registry.pol: truncated entry"),
            Self::UnreadableText => write!(f, "Registry.pol: unreadable text"),
            Self::BadKeyOrName => {
                write!(f, "Registry.pol: empty key, or NUL in a key or a name")
            }
            Self::NulInText => write!(f, "Registry.pol: NUL character in a text"),
            Self::IntegerOutOfRange(v) => write!(f, "Registry.pol: integer out of range: {v}"),
            Self::WrongKind(kind) => write!(f, "Registry.pol: {kind} expected"),
            Self::TooLong => write!(f, "Registry.pol: data too long"),
        }
    }
}

impl std::error::Error for RegistryPolError {}

/// Kind of an entry whose value name starts with `**`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Special {
    Del,
    DelVals,
    DeleteValues,
    DeleteKeys,
    SecureKey,
}

impl Special {
    /// The name of the Python model (`del`, `delvals`…).
    pub fn name(self) -> &'static str {
        match self {
            Self::Del => "del",
            Self::DelVals => "delvals",
            Self::DeleteValues => "deletevalues",
            Self::DeleteKeys => "deletekeys",
            Self::SecureKey => "securekey",
        }
    }

    /// The kind of a value name, `None` for an ordinary one.
    pub fn of(value_name: &str) -> Option<Self> {
        let lower = value_name.to_lowercase();
        if lower.starts_with(DELVALS) {
            Some(Self::DelVals)
        } else if lower.starts_with(DEL_PREFIX) {
            Some(Self::Del)
        } else if lower == DELETE_VALUES.to_lowercase() {
            Some(Self::DeleteValues)
        } else if lower == DELETE_KEYS.to_lowercase() {
            Some(Self::DeleteKeys)
        } else if lower == SECURE_KEY.to_lowercase() {
            Some(Self::SecureKey)
        } else {
            None
        }
    }
}

/// A value as the registry holds it: integer (DWORD, QWORD), text (SZ, EXPAND_SZ), list of
/// texts (MULTI_SZ), bytes otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    Integer(u64),
    Text(String),
    Texts(Vec<String>),
    Bytes(Vec<u8>),
}

/// One entry of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub key: String,
    pub value_name: String,
    pub rtype: u32,
    pub data: Vec<u8>,
}

fn utf16(text: &str) -> impl Iterator<Item = u8> + '_ {
    text.encode_utf16().flat_map(u16::to_le_bytes)
}

fn decode_utf16(bytes: &[u8]) -> Result<String, RegistryPolError> {
    if bytes.len() % 2 != 0 {
        return Err(RegistryPolError::UnreadableText);
    }
    let units = bytes
        .chunks_exact(2)
        .map(|p| u16::from_le_bytes(p.try_into().unwrap_or_default()));
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|_| RegistryPolError::UnreadableText)
}

/// Name of a type (`DWORD`…), its number for an unknown one.
pub fn type_name(rtype: u32) -> String {
    TYPE_NAMES
        .iter()
        .find(|(t, _)| *t == rtype)
        .map_or_else(|| rtype.to_string(), |(_, n)| (*n).to_owned())
}

/// Data of a value, as the registry stores it (inverse of `Entry::interpret`).
pub fn encode_value(rtype: u32, value: &RegValue) -> Result<Vec<u8>, RegistryPolError> {
    match (rtype, value) {
        (REG_DWORD | REG_DWORD_BIG_ENDIAN | REG_QWORD, RegValue::Integer(v)) => {
            let small = u32::try_from(*v);
            match rtype {
                REG_QWORD => Ok(v.to_le_bytes().to_vec()),
                REG_DWORD => small
                    .map(|s| s.to_le_bytes().to_vec())
                    .map_err(|_| RegistryPolError::IntegerOutOfRange(*v)),
                _ => small
                    .map(|s| s.to_be_bytes().to_vec())
                    .map_err(|_| RegistryPolError::IntegerOutOfRange(*v)),
            }
        }
        (REG_DWORD | REG_DWORD_BIG_ENDIAN | REG_QWORD, _) => {
            Err(RegistryPolError::WrongKind("an integer"))
        }
        (REG_SZ | REG_EXPAND_SZ, RegValue::Text(t)) => {
            if t.contains('\0') {
                return Err(RegistryPolError::NulInText);
            }
            Ok(utf16(t).chain([0, 0]).collect())
        }
        (REG_SZ | REG_EXPAND_SZ, _) => Err(RegistryPolError::WrongKind("a text")),
        (REG_MULTI_SZ, RegValue::Texts(texts)) => {
            let mut out = Vec::new();
            for t in texts.iter().filter(|t| !t.is_empty()) {
                if t.contains('\0') {
                    return Err(RegistryPolError::NulInText);
                }
                out.extend(utf16(t).chain([0, 0]));
            }
            out.extend([0, 0]);
            Ok(out)
        }
        (REG_MULTI_SZ, _) => Err(RegistryPolError::WrongKind("a list of texts")),
        (_, RegValue::Bytes(b)) => Ok(b.clone()),
        (_, _) => Err(RegistryPolError::WrongKind("bytes")),
    }
}

impl Entry {
    /// Entry that sets `value` for `rtype`.
    pub fn from_value(
        key: &str,
        name: &str,
        rtype: u32,
        value: &RegValue,
    ) -> Result<Self, RegistryPolError> {
        Ok(Self {
            key: key.to_owned(),
            value_name: name.to_owned(),
            rtype,
            data: encode_value(rtype, value)?,
        })
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }

    pub fn type_name(&self) -> String {
        type_name(self.rtype)
    }

    pub fn special(&self) -> Option<Special> {
        Special::of(&self.value_name)
    }

    /// `**del.<value>`, `**delvals.`, `**DeleteValues` or `**DeleteKeys`: the GPO removes
    /// instead of setting.
    pub fn is_deletion(&self) -> bool {
        matches!(
            self.special(),
            Some(Special::Del | Special::DelVals | Special::DeleteValues | Special::DeleteKeys)
        )
    }

    /// The value aimed at: without `**del.` for a deletion marker.
    pub fn name(&self) -> &str {
        if self.special() == Some(Special::Del) {
            // The six characters of `**del.` are ASCII (a lower-case match).
            self.value_name.get(DEL_PREFIX.len()..).unwrap_or_default()
        } else {
            &self.value_name
        }
    }

    /// The data according to the type.
    pub fn interpret(&self) -> Result<RegValue, RegistryPolError> {
        let d = &self.data;
        Ok(match (self.rtype, d.len()) {
            (REG_DWORD, 4) => RegValue::Integer(le_u32(d, 0).unwrap_or_default().into()),
            (REG_DWORD_BIG_ENDIAN, 4) => RegValue::Integer(u64::from(u32::from_be_bytes(
                d.as_slice().try_into().unwrap_or_default(),
            ))),
            (REG_QWORD, 8) => RegValue::Integer(u64::from_le_bytes(
                d.as_slice().try_into().unwrap_or_default(),
            )),
            (REG_SZ | REG_EXPAND_SZ, _) => {
                let text = decode_utf16(d)?;
                RegValue::Text(text.split('\0').next().unwrap_or_default().to_owned())
            }
            (REG_MULTI_SZ, _) => RegValue::Texts(
                decode_utf16(d)?
                    .split('\0')
                    .filter(|t| !t.is_empty())
                    .map(str::to_owned)
                    .collect(),
            ),
            _ => RegValue::Bytes(d.clone()),
        })
    }

    fn write_to(&self, out: &mut Vec<u8>) -> Result<(), RegistryPolError> {
        if self.key.is_empty() || self.key.contains('\0') || self.value_name.contains('\0') {
            return Err(RegistryPolError::BadKeyOrName);
        }
        let size = u32::try_from(self.data.len()).map_err(|_| RegistryPolError::TooLong)?;
        out.extend(utf16("["));
        out.extend(utf16(&self.key));
        out.extend(utf16("\0;"));
        out.extend(utf16(&self.value_name));
        out.extend(utf16("\0;"));
        out.extend_from_slice(&self.rtype.to_le_bytes());
        out.extend(utf16(";"));
        out.extend_from_slice(&size.to_le_bytes());
        out.extend(utf16(";"));
        out.extend_from_slice(&self.data);
        out.extend(utf16("]"));
        Ok(())
    }
}

fn expect(bytes: &[u8], position: usize, c: char) -> Result<usize, RegistryPolError> {
    let unit = u16::try_from(u32::from(c))
        .unwrap_or_default()
        .to_le_bytes();
    if bytes.get(position..position + 2) == Some(&unit[..]) {
        Ok(position + 2)
    } else {
        Err(RegistryPolError::Expected {
            expected: c,
            position,
        })
    }
}

/// UTF-16LE string ended by a NUL; position after the NUL.
fn string(bytes: &[u8], position: usize) -> Result<(String, usize), RegistryPolError> {
    let mut end = position;
    loop {
        match bytes.get(end..end + 2) {
            None => return Err(RegistryPolError::UnterminatedString),
            Some([0, 0]) => {
                let text = decode_utf16(bytes.get(position..end).unwrap_or_default())?;
                return Ok((text, end + 2));
            }
            Some(_) => end += 2,
        }
    }
}

/// The entries of a `Registry.pol`, in file order.
pub fn read(bytes: &[u8]) -> Result<Vec<Entry>, RegistryPolError> {
    if bytes.len() < 8 || bytes.get(..4) != Some(&SIGNATURE[..]) {
        return Err(RegistryPolError::MissingSignature);
    }
    let version = le_u32(bytes, 4).ok_or(RegistryPolError::MissingSignature)?;
    if version != VERSION {
        return Err(RegistryPolError::UnknownVersion(version));
    }
    let mut entries = Vec::new();
    let mut position = 8;
    while position < bytes.len() {
        position = expect(bytes, position, '[')?;
        let (key, p) = string(bytes, position)?;
        position = expect(bytes, p, ';')?;
        let (value_name, p) = string(bytes, position)?;
        position = expect(bytes, p, ';')?;
        let rtype = le_u32(bytes, position).ok_or(RegistryPolError::Truncated)?;
        position = expect(bytes, position + 4, ';')?;
        let size = le_u32(bytes, position).ok_or(RegistryPolError::Truncated)?;
        position = expect(bytes, position + 4, ';')?;
        let size = usize::try_from(size).map_err(|_| RegistryPolError::Truncated)?;
        let data = bytes
            .get(position..position.saturating_add(size))
            .ok_or(RegistryPolError::Truncated)?
            .to_vec();
        position = expect(bytes, position + size, ']')?;
        entries.push(Entry {
            key,
            value_name,
            rtype,
            data,
        });
    }
    Ok(entries)
}

/// The file: header then the entries in the given order.
pub fn encode(entries: &[Entry]) -> Result<Vec<u8>, RegistryPolError> {
    let mut out = HEADER.to_vec();
    for e in entries {
        e.write_to(&mut out)?;
    }
    Ok(out)
}

// --- Changes (pure: a new list, the rest in the same order) -----------------------------------

fn same_key(a: &str, b: &str) -> bool {
    a.to_lowercase() == b.to_lowercase()
}

/// The last entry that sets or removes `key`!`name` (case ignored, as the registry does);
/// `None` if the file says nothing of it.
pub fn value<'a>(entries: &'a [Entry], key: &str, name: &str) -> Option<&'a Entry> {
    let name = name.to_lowercase();
    let del = format!("{DEL_PREFIX}{name}");
    entries.iter().rfind(|e| {
        if !same_key(&e.key, key) {
            return false;
        }
        let lower = e.value_name.to_lowercase();
        lower == name || lower == del || lower.starts_with(DELVALS)
    })
}

/// `e` sets or disables the value `key`!`name` (not `**delvals.` nor the other markers).
fn aims(e: &Entry, key: &str, name: &str) -> bool {
    same_key(&e.key, key)
        && matches!(e.special(), None | Some(Special::Del))
        && e.name().to_lowercase() == name.to_lowercase()
}

/// `new` in place of the first entry `aimed` designates (the others removed); else after
/// the last entry of the same key, as the GPMC does, or at the end.
fn in_place(entries: &[Entry], new: Entry, aimed: impl Fn(&Entry) -> bool) -> Vec<Entry> {
    let mut result = Vec::with_capacity(entries.len() + 1);
    let mut placed = false;
    for e in entries {
        if aimed(e) {
            if !placed {
                result.push(new.clone());
                placed = true;
            }
            continue;
        }
        result.push(e.clone());
    }
    if !placed {
        let at = result
            .iter()
            .rposition(|e| same_key(&e.key, &new.key))
            .map_or(result.len(), |i| i + 1);
        result.insert(at, new);
    }
    result
}

/// Sets the entry: replaces, in its place, the one that set or disabled the same value
/// (`**del.` included), or the same marker of the key (`**DeleteValues`…); else adds it
/// after the last entry of its key, or at the end. The rest does not move.
pub fn set(entries: &[Entry], entry: Entry) -> Vec<Entry> {
    match entry.special() {
        None | Some(Special::Del) => {
            let (key, name) = (entry.key.clone(), entry.name().to_owned());
            in_place(entries, entry, |e| aims(e, &key, &name))
        }
        special => {
            let key = entry.key.clone();
            in_place(entries, entry, |e| {
                same_key(&e.key, &key) && e.special() == special
            })
        }
    }
}

/// The GPO deletes the value on the computers ("disabled"): `**del.<name>` in place of what
/// set it.
pub fn disable(entries: &[Entry], key: &str, name: &str) -> Vec<Entry> {
    set(
        entries,
        Entry {
            key: key.to_owned(),
            value_name: format!("{DEL_PREFIX}{name}"),
            rtype: REG_SZ,
            data: DEL_DATA.to_vec(),
        },
    )
}

/// The GPO deletes all the values of the key (`**delvals.`).
pub fn delete_values(entries: &[Entry], key: &str) -> Vec<Entry> {
    set(
        entries,
        Entry {
            key: key.to_owned(),
            value_name: DELVALS.to_owned(),
            rtype: REG_SZ,
            data: DEL_DATA.to_vec(),
        },
    )
}

/// The GPO says nothing more of the value ("not configured"): removes what sets or
/// disables it. `name` `None`: removes everything about the key itself (values and
/// markers), not about its subkeys.
pub fn remove(entries: &[Entry], key: &str, name: Option<&str>) -> Vec<Entry> {
    entries
        .iter()
        .filter(|e| match name {
            None => !same_key(&e.key, key),
            Some(n) => !aims(e, key, n),
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = r"Software\Policies\Annuaire\J7P";

    #[test]
    fn round_trip_and_values() {
        let entries = vec![
            Entry::from_value(KEY, "Entier", REG_DWORD, &RegValue::Integer(1)).unwrap(),
            Entry::from_value(KEY, "Texte", REG_SZ, &RegValue::Text("Été".into())).unwrap(),
            Entry::from_value(
                KEY,
                "Liste",
                REG_MULTI_SZ,
                &RegValue::Texts(vec!["a".into(), String::new(), "b".into()]),
            )
            .unwrap(),
        ];
        let bytes = encode(&entries).unwrap();
        assert_eq!(read(&bytes).unwrap(), entries);
        assert_eq!(
            entries[2].interpret().unwrap(),
            RegValue::Texts(vec!["a".into(), "b".into()])
        );
        assert_eq!(read(&HEADER).unwrap(), []);
        assert!(read(b"PReg\x02\x00\x00\x00").is_err());
        assert!(encode_value(REG_DWORD, &RegValue::Integer(1 << 32)).is_err());
        assert!(encode_value(REG_SZ, &RegValue::Text("a\0".into())).is_err());
    }

    #[test]
    fn changes() {
        let a = Entry::from_value(KEY, "A", REG_DWORD, &RegValue::Integer(1)).unwrap();
        let b = Entry::from_value(KEY, "B", REG_DWORD, &RegValue::Integer(2)).unwrap();
        let other = Entry::from_value("Autre", "C", REG_DWORD, &RegValue::Integer(3)).unwrap();
        let entries = vec![a.clone(), other.clone(), b.clone()];
        let disabled = disable(&entries, &KEY.to_lowercase(), "a");
        assert_eq!(disabled[0].value_name, "**del.a");
        assert_eq!(disabled[0].special(), Some(Special::Del));
        assert_eq!(value(&disabled, KEY, "A").unwrap().value_name, "**del.a");
        let new = Entry::from_value(KEY, "D", REG_DWORD, &RegValue::Integer(4)).unwrap();
        let added = set(&entries, new.clone());
        assert_eq!(added, vec![a.clone(), other.clone(), b.clone(), new]);
        assert_eq!(remove(&entries, KEY, None), vec![other.clone()]);
        assert_eq!(remove(&entries, KEY, Some("b")), vec![a, other]);
        assert_eq!(
            delete_values(&entries, KEY).last().unwrap().value_name,
            DELVALS
        );
    }
}

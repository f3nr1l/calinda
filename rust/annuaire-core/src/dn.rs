// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Distinguished names (RFC 4514): splitting into components and composing.
//!
//! Port of `annuaire/core/dn.py`, limited to what Active Directory writes: one attribute
//! per RDN (no `+`), text values (no `#` BER form). Found on the lab: the comma of OU names
//! is escaped (`R&D\, Innovation`), the line feed of conflict names `CNF:` is escaped as
//! `\0A`, accents and apostrophes stay as they are (UTF-8).

use std::fmt;

/// Escaped by a plain `\` when composing; `=` is not required by the RFC but AD escapes it.
const SPECIAL: &str = ",+\"\\<>;=";
/// Accepted after a `\` when reading (RFC 4514, 3, `escaped`).
const ESCAPABLE: &str = " \"#+,;<=>\\";
/// Forbidden unescaped in a value (RFC 4514, 3, `stringchar`).
const FORBIDDEN: &str = "\"+;<>\0";

/// One RDN: attribute (original case) and value without escaping.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Component {
    pub attribute: String,
    pub value: String,
}

impl Component {
    pub fn new(attribute: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            attribute: attribute.into(),
            value: value.into(),
        }
    }
}

/// Why a DN was refused; the Python module words each case as `dn.py` does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnError {
    NoEquals {
        dn: String,
    },
    InvalidType {
        attribute: String,
        dn: Option<String>,
    },
    BerValue {
        dn: String,
    },
    InvalidEscape {
        position: usize,
        dn: String,
    },
    MultiValued {
        dn: String,
    },
    Unescaped {
        c: char,
        dn: String,
    },
    NotUtf8 {
        dn: String,
    },
}

impl fmt::Display for DnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEquals { dn } => write!(f, "DN without `=`: {dn:?}"),
            Self::InvalidType {
                attribute,
                dn: Some(dn),
            } => write!(f, "invalid attribute type {attribute:?} in {dn:?}"),
            Self::InvalidType {
                attribute,
                dn: None,
            } => write!(f, "invalid attribute type: {attribute:?}"),
            Self::BerValue { dn } => write!(f, "BER value (`#…`) not supported: {dn:?}"),
            Self::InvalidEscape { position, dn } => {
                write!(f, "invalid escape at position {position}: {dn:?}")
            }
            Self::MultiValued { dn } => write!(f, "multi-valued RDN not supported: {dn:?}"),
            Self::Unescaped { c, dn } => write!(f, "unescaped character {c:?}: {dn:?}"),
            Self::NotUtf8 { dn } => write!(f, "hexadecimal escapes outside UTF-8: {dn:?}"),
        }
    }
}

impl std::error::Error for DnError {}

/// `[A-Za-z][A-Za-z0-9-]*` or `[0-9]+(\.[0-9]+)*`.
pub fn valid_type(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => chars.all(|c| c.is_ascii_alphanumeric() || c == '-'),
        Some(c) if c.is_ascii_digit() => name
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
        _ => false,
    }
}

/// Components of a DN, from the leaf to the root; the empty DN gives none.
pub fn split(dn: &str) -> Result<Vec<Component>, DnError> {
    if dn.is_empty() {
        return Ok(Vec::new());
    }
    let chars: Vec<char> = dn.chars().collect();
    let n = chars.len();
    let at = |i: usize| chars.get(i).copied();
    let mut components = Vec::new();
    let mut i = 0;
    loop {
        let Some(equals) = (i..n).find(|&k| at(k) == Some('=')) else {
            return Err(DnError::NoEquals { dn: dn.to_owned() });
        };
        let attribute: String = chars.get(i..equals).unwrap_or_default().iter().collect();
        if !valid_type(&attribute) {
            return Err(DnError::InvalidType {
                attribute,
                dn: Some(dn.to_owned()),
            });
        }
        i = equals + 1;
        if at(i) == Some('#') {
            return Err(DnError::BerValue { dn: dn.to_owned() });
        }
        let mut value: Vec<u8> = Vec::new();
        while let Some(c) = at(i).filter(|&c| c != ',') {
            if c == '\\' {
                let pair: Option<(char, char)> = at(i + 1).zip(at(i + 2));
                if let Some((a, b)) =
                    pair.filter(|(a, b)| a.is_ascii_hexdigit() && b.is_ascii_hexdigit())
                {
                    let byte =
                        (a.to_digit(16).unwrap_or(0) * 16 + b.to_digit(16).unwrap_or(0)) as u8;
                    value.push(byte);
                    i += 3;
                    continue;
                }
                if let Some(next) = at(i + 1).filter(|c| ESCAPABLE.contains(*c)) {
                    let mut buffer = [0u8; 4];
                    value.extend_from_slice(next.encode_utf8(&mut buffer).as_bytes());
                    i += 2;
                    continue;
                }
                return Err(DnError::InvalidEscape {
                    position: i,
                    dn: dn.to_owned(),
                });
            }
            if FORBIDDEN.contains(c) {
                if c == '+' {
                    return Err(DnError::MultiValued { dn: dn.to_owned() });
                }
                return Err(DnError::Unescaped {
                    c,
                    dn: dn.to_owned(),
                });
            }
            let mut buffer = [0u8; 4];
            value.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            i += 1;
        }
        let text = String::from_utf8(value).map_err(|_| DnError::NotUtf8 { dn: dn.to_owned() })?;
        components.push(Component::new(attribute, text));
        if i >= n {
            return Ok(components);
        }
        i += 1; // the comma
    }
}

/// Escapes an RDN value as AD does: `\,` etc., control characters as `\XX`.
pub fn escape_value(value: &str) -> String {
    let count = value.chars().count();
    let mut escaped = String::with_capacity(value.len());
    for (position, c) in value.chars().enumerate() {
        if SPECIAL.contains(c) {
            escaped.push('\\');
            escaped.push(c);
        } else if (c as u32) < 0x20 || c as u32 == 0x7F {
            escaped.push_str(&format!("\\{:02X}", c as u32));
        } else if c == '#' && position == 0 {
            escaped.push_str("\\#");
        } else if c == ' ' && (position == 0 || position + 1 == count) {
            escaped.push_str("\\ ");
        } else {
            escaped.push(c);
        }
    }
    escaped
}

/// DN string from its components (leaf to root).
pub fn compose(components: &[Component]) -> Result<String, DnError> {
    if let Some(bad) = components.iter().find(|c| !valid_type(&c.attribute)) {
        return Err(DnError::InvalidType {
            attribute: bad.attribute.clone(),
            dn: None,
        });
    }
    Ok(components
        .iter()
        .map(|c| format!("{}={}", c.attribute, escape_value(&c.value)))
        .collect::<Vec<_>>()
        .join(","))
}

/// Comparable form of a DN (escapes normalized, case ignored), as `changes.cle_dn`.
pub fn key(dn: &str) -> Result<String, DnError> {
    Ok(compose(&split(dn)?)?.to_lowercase())
}

/// DN of the parent, as `changes.parent_dn`.
pub fn parent(dn: &str) -> Result<String, DnError> {
    compose(split(dn)?.get(1..).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_and_composes() {
        let dn = "CN=Dupont\\, Jean,OU=R&D\\, Innovation,DC=lab,DC=test";
        let parts = split(dn).unwrap();
        assert_eq!(parts[0], Component::new("CN", "Dupont, Jean"));
        assert_eq!(parts[1].value, "R&D, Innovation");
        assert_eq!(compose(&parts).unwrap(), dn);
        assert_eq!(split("").unwrap(), []);
        let conflict = split("CN=a\\0ACNF:1234,DC=x").unwrap();
        assert_eq!(conflict[0].value, "a\nCNF:1234");
        assert_eq!(compose(&conflict).unwrap(), "CN=a\\0ACNF:1234,DC=x");
        assert_eq!(split("CN=\\c3\\a9t\\c3\\a9").unwrap()[0].value, "été");
        assert_eq!(escape_value("#a b "), "\\#a b\\ ");
        assert_eq!(key("CN=A\\2c B,DC=X").unwrap(), "cn=a\\, b,dc=x");
        assert_eq!(parent("CN=a,OU=b,DC=c").unwrap(), "OU=b,DC=c");
        assert_eq!(parent("DC=c").unwrap(), "");
    }

    #[test]
    fn refuses_what_ad_does_not_write() {
        assert!(matches!(split("CN"), Err(DnError::NoEquals { .. })));
        assert!(matches!(split("C N=a"), Err(DnError::InvalidType { .. })));
        assert!(matches!(split("CN=#04"), Err(DnError::BerValue { .. })));
        assert!(matches!(
            split("CN=a\\x"),
            Err(DnError::InvalidEscape { position: 4, .. })
        ));
        assert!(matches!(
            split("CN=a+SN=b"),
            Err(DnError::MultiValued { .. })
        ));
        assert!(matches!(
            split("CN=a;b"),
            Err(DnError::Unescaped { c: ';', .. })
        ));
        assert!(matches!(split("CN=\\ff"), Err(DnError::NotUtf8 { .. })));
        assert!(compose(&[Component::new("a b", "x")]).is_err());
    }
}

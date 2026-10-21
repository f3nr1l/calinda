// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! GUID: 16 bytes in mixed order (MS-DTYP 2.3.4.2) ⇄ canonical text.
//!
//! In the binary form the first three fields (4, 2 and 2 bytes) are little-endian and the
//! last 8 bytes are in order: `bf967aba-0de6-11d0-a285-00aa003049e2` is stored as
//! `ba 7a 96 bf e6 0d d0 11 a2 85 00 aa 00 30 49 e2`.

use std::fmt;
use std::str::FromStr;

/// Length of the binary form.
pub const SIZE: usize = 16;

/// Why a GUID was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuidError {
    /// Binary form of another length than 16 bytes.
    InvalidLength(usize),
    /// Text not of the form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, braces optional.
    MalformedText(String),
}

impl fmt::Display for GuidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(n) => write!(f, "GUID of {n} bytes instead of {SIZE}"),
            Self::MalformedText(t) => write!(f, "malformed GUID text: {t:?}"),
        }
    }
}

impl std::error::Error for GuidError {}

/// A GUID, kept in its binary form (the one of the directory).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Guid([u8; SIZE]);

impl Guid {
    /// The nil GUID.
    pub const NIL: Self = Self([0; SIZE]);

    pub const fn from_bytes(bytes: [u8; SIZE]) -> Self {
        Self(bytes)
    }

    /// Decodes the 16 bytes of an `objectGUID`, `schemaIDGUID`…
    pub fn decode(bytes: &[u8]) -> Result<Self, GuidError> {
        bytes
            .try_into()
            .map(Self)
            .map_err(|_| GuidError::InvalidLength(bytes.len()))
    }

    /// Reads a GUID at `position` inside a structure; returns it and the position after it.
    pub fn read(bytes: &[u8], position: usize) -> Result<(Self, usize), GuidError> {
        let end = position.saturating_add(SIZE);
        let slice = bytes.get(position..end).ok_or(GuidError::InvalidLength(
            bytes.len().saturating_sub(position),
        ))?;
        Ok((Self::decode(slice)?, end))
    }

    pub const fn as_bytes(&self) -> &[u8; SIZE] {
        &self.0
    }

    /// Binary form.
    pub fn encode(&self) -> Vec<u8> {
        self.0.to_vec()
    }

    /// Upper-case text between braces, as in `gPLink` and the extension lists of GPOs.
    pub fn to_braced_upper(&self) -> String {
        format!("{{{}}}", self.to_string().to_ascii_uppercase())
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// Canonical lower-case form, without braces.
impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a0, a1, a2, a3, b0, b1, c0, c1, d @ ..] = self.0;
        let [d0, d1, e @ ..] = d;
        write!(
            f,
            "{a3:02x}{a2:02x}{a1:02x}{a0:02x}-{b1:02x}{b0:02x}-{c1:02x}{c0:02x}-"
        )?;
        write!(f, "{d0:02x}{d1:02x}-")?;
        e.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// Parses the text form, with or without braces, in either case.
impl FromStr for Guid {
    type Err = GuidError;

    fn from_str(text: &str) -> Result<Self, GuidError> {
        let malformed = || GuidError::MalformedText(text.to_owned());
        let inner = match text.strip_prefix('{') {
            Some(rest) => rest.strip_suffix('}').ok_or_else(malformed)?,
            None if text.ends_with('}') => return Err(malformed()),
            None => text,
        };
        let raw = inner.as_bytes();
        if raw.len() != 36 {
            return Err(malformed());
        }
        let mut digits = [0u8; 32];
        let mut n = 0;
        for (i, &c) in raw.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(malformed());
                }
                continue;
            }
            let value = char::from(c).to_digit(16).ok_or_else(malformed)?;
            // 32 hexadecimal digits: the length and the four dashes are checked.
            *digits.get_mut(n).ok_or_else(malformed)? = value as u8;
            n += 1;
        }
        let mut plain = [0u8; SIZE];
        for (o, pair) in plain.iter_mut().zip(digits.chunks_exact(2)) {
            if let [high, low] = pair {
                *o = high << 4 | low;
            }
        }
        let [p0, p1, p2, p3, p4, p5, p6, p7, rest @ ..] = plain;
        let [p8, p9, p10, p11, p12, p13, p14, p15] = rest;
        Ok(Self([
            p3, p2, p1, p0, p5, p4, p7, p6, p8, p9, p10, p11, p12, p13, p14, p15,
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_order() {
        let guid: Guid = "bf967aba-0de6-11d0-a285-00aa003049e2".parse().unwrap();
        assert_eq!(
            guid.encode(),
            [
                0xba, 0x7a, 0x96, 0xbf, 0xe6, 0x0d, 0xd0, 0x11, 0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30,
                0x49, 0xe2
            ]
        );
        assert_eq!(guid.to_string(), "bf967aba-0de6-11d0-a285-00aa003049e2");
        assert_eq!(
            guid.to_braced_upper(),
            "{BF967ABA-0DE6-11D0-A285-00AA003049E2}"
        );
        assert_eq!(
            "{BF967ABA-0DE6-11D0-A285-00AA003049E2}"
                .parse::<Guid>()
                .unwrap(),
            guid
        );
    }

    #[test]
    fn invalid_length() {
        for n in [0, 15, 17] {
            assert!(Guid::decode(&vec![0; n]).is_err());
        }
    }

    #[test]
    fn invalid_text() {
        for text in [
            "",
            "bf967aba0de611d0a28500aa003049e2",
            "{bf967aba-0de6-11d0-a285-00aa003049e2",
            "bf967aba-0de6-11d0-a285-00aa003049e2}",
            "bf967aba-0de6-11d0-a285-00aa003049eg",
            "bf967aba-0de6-11d0-a285-00aa003049e٢",
            "+f967aba-0de6-11d0-a285-00aa003049e2",
        ] {
            assert!(text.parse::<Guid>().is_err(), "{text}");
        }
    }
}

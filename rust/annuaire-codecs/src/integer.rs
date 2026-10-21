// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Integers of the LDAP syntaxes `Integer` (32 bits) and `Large Integer` (64 bits).
//!
//! The directory sends them as signed decimal text (`userAccountControl`, `groupType`,
//! `pwdLastSet`, `maxPwdAge`…). Reading is strict: ASCII only, no space, no `+`, no
//! leading zero, no `-0`, value within the signed bounds of the requested width.

use std::fmt;

/// Width of an LDAP integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Width {
    Bits32,
    Bits64,
}

impl Width {
    /// 32 or 64; any other width is refused.
    pub fn from_bits(bits: u32) -> Result<Self, IntegerError> {
        match bits {
            32 => Ok(Self::Bits32),
            64 => Ok(Self::Bits64),
            _ => Err(IntegerError::UnsupportedWidth(bits)),
        }
    }

    fn bounds(self) -> (i64, i64) {
        match self {
            Self::Bits32 => (i32::MIN.into(), i32::MAX.into()),
            Self::Bits64 => (i64::MIN, i64::MAX),
        }
    }

    fn bits(self) -> u32 {
        match self {
            Self::Bits32 => 32,
            Self::Bits64 => 64,
        }
    }
}

/// Why an integer was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegerError {
    NotAscii,
    Malformed(String),
    /// The value does not fit in the width (the text is kept: it may not fit in an `i64`).
    OutOfRange {
        value: String,
        bits: u32,
    },
    UnsupportedWidth(u32),
}

impl fmt::Display for IntegerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAscii => write!(f, "LDAP integer: non-ASCII character"),
            Self::Malformed(t) => write!(f, "malformed LDAP integer: {t:?}"),
            Self::OutOfRange { value, bits } => {
                write!(
                    f,
                    "{value} out of the bounds of a signed {bits}-bit integer"
                )
            }
            Self::UnsupportedWidth(bits) => write!(f, "unsupported width: {bits}"),
        }
    }
}

impl std::error::Error for IntegerError {}

/// Reads a signed integer of `width` written in ASCII decimal.
pub fn decode(bytes: &[u8], width: Width) -> Result<i64, IntegerError> {
    let text = std::str::from_utf8(bytes)
        .ok()
        .filter(|t| t.is_ascii())
        .ok_or(IntegerError::NotAscii)?;
    let digits = text.strip_prefix('-').unwrap_or(text);
    let well_formed = !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
        && text != "-0";
    if !well_formed {
        return Err(IntegerError::Malformed(text.to_owned()));
    }
    let out_of_range = || IntegerError::OutOfRange {
        value: text.to_owned(),
        bits: width.bits(),
    };
    let value: i64 = text.parse().map_err(|_| out_of_range())?;
    check_bounds(value, width).map_err(|_| out_of_range())?;
    Ok(value)
}

/// Writes a signed integer of `width` in ASCII decimal.
pub fn encode(value: i64, width: Width) -> Result<Vec<u8>, IntegerError> {
    check_bounds(value, width)?;
    Ok(value.to_string().into_bytes())
}

/// Refuses a value that does not fit in a signed integer of `width`.
pub fn check_bounds(value: i64, width: Width) -> Result<(), IntegerError> {
    let (low, high) = width.bounds();
    if (low..=high).contains(&value) {
        Ok(())
    } else {
        Err(IntegerError::OutOfRange {
            value: value.to_string(),
            bits: width.bits(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid() {
        for text in [
            "",
            "-",
            "+1",
            " 1",
            "1 ",
            "01",
            "-0",
            "1.0",
            "0x10",
            "١",
            "9223372036854775808",
        ] {
            assert!(decode(text.as_bytes(), Width::Bits64).is_err(), "{text}");
        }
    }

    #[test]
    fn bounds() {
        assert_eq!(decode(b"-2147483648", Width::Bits32), Ok(-(1 << 31)));
        assert!(decode(b"2147483648", Width::Bits32).is_err());
        assert_eq!(decode(b"-9223372036854775808", Width::Bits64), Ok(i64::MIN));
        assert!(encode(1 << 31, Width::Bits32).is_err());
        assert!(Width::from_bits(16).is_err());
    }
}

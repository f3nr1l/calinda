// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Python's text rules that the SDDL reader depends on (`str.isspace`, `str.strip`,
//! `int(text, base)`, `bytes.fromhex`), reproduced so that the reader accepts and refuses
//! exactly what the Python reference does. Text is handled as `[char]`: Python's indexing,
//! and the positions of the condition errors are those of Python.

/// `str.isspace()`: Unicode White_Space plus the four ASCII separators U+001C to U+001F.
pub(crate) fn is_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `text[start:end]`, empty when out of bounds (as Python's slicing, for `start <= end`).
pub(crate) fn sub(text: &[char], start: usize, end: usize) -> &[char] {
    let end = end.min(text.len());
    text.get(start.min(end)..end).unwrap_or_default()
}

/// `text[start:]`.
pub(crate) fn from(text: &[char], start: usize) -> &[char] {
    sub(text, start, text.len())
}

pub(crate) fn at(text: &[char], i: usize) -> Option<char> {
    text.get(i).copied()
}

fn strip_with(text: &[char], space: fn(char) -> bool) -> &[char] {
    let start = text.iter().position(|&c| !space(c)).unwrap_or(text.len());
    let end = text
        .iter()
        .rposition(|&c| !space(c))
        .map_or(start, |i| i + 1);
    sub(text, start, end)
}

/// `str.strip()` without arguments.
pub(crate) fn strip(text: &[char]) -> &[char] {
    strip_with(text, is_space)
}

/// `str.strip()` on a `&str`.
pub(crate) fn strip_str(text: &str) -> &str {
    text.trim_matches(is_space)
}

/// `str.lstrip()` on a `&str`.
pub(crate) fn lstrip_str(text: &str) -> &str {
    text.trim_start_matches(is_space)
}

pub(crate) fn string(text: &[char]) -> String {
    text.iter().collect()
}

pub(crate) fn chars(text: &str) -> Vec<char> {
    text.chars().collect()
}

/// `text.find(needle, start)` for one character.
pub(crate) fn find(text: &[char], needle: char, start: usize) -> Option<usize> {
    from(text, start)
        .iter()
        .position(|&c| c == needle)
        .map(|i| i + start)
}

pub(crate) fn starts_with(text: &[char], prefix: &str) -> bool {
    let mut it = text.iter();
    prefix.chars().all(|p| it.next() == Some(&p))
}

/// The first two characters in lower case, as `text[:2].lower()`.
pub(crate) fn head2_lower(text: &[char]) -> String {
    sub(text, 0, 2).iter().collect::<String>().to_lowercase()
}

/// An integer as Python's `int()` returns it, kept exact where the codecs look at it:
/// sign, magnitude (below 2^128) and magnitude modulo 2^64.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PyInt {
    negative: bool,
    /// `None` from 2^128 on.
    magnitude: Option<u128>,
    /// Magnitude modulo 2^64.
    low: u64,
}

impl PyInt {
    pub fn from_i128(value: i128) -> Self {
        let m = value.unsigned_abs();
        Self {
            negative: value < 0,
            magnitude: Some(m),
            low: m as u64,
        }
    }

    /// The value, if it fits in `i128`.
    pub fn to_i128(self) -> Option<i128> {
        let m = i128::try_from(self.magnitude?).ok()?;
        Some(if self.negative { -m } else { m })
    }

    /// `value & 0xFFFF_FFFF_FFFF_FFFF` (two's complement for a negative value).
    pub fn mask64(self) -> u64 {
        if self.negative {
            self.low.wrapping_neg()
        } else {
            self.low
        }
    }

    pub(crate) fn neg(self) -> Self {
        Self {
            negative: !self.negative && self.magnitude != Some(0),
            ..self
        }
    }

    /// `self > bound` for a non-negative `bound`.
    pub(crate) fn gt(self, bound: u128) -> bool {
        !self.negative && self.magnitude.is_none_or(|m| m > bound)
    }

    pub fn is_negative(self) -> bool {
        self.negative
    }
}

impl std::fmt::Display for PyInt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.magnitude {
            Some(m) => write!(f, "{}{m}", if self.negative { "-" } else { "" }),
            None => write!(f, "{}…", if self.negative { "-" } else { "" }),
        }
    }
}

/// `int(text, base)` for base 0, 2, 8, 10 or 16; `None` where Python raises `ValueError`.
/// Only ASCII digits are accepted (Python also takes other Unicode decimal digits).
pub(crate) fn py_int(text: &[char], base: u32) -> Option<PyInt> {
    // `int` strips with its own test of whitespace, without U+001C to U+001F.
    let s = strip_with(text, char::is_whitespace);
    let (negative, s) = match s {
        ['-', rest @ ..] => (true, rest),
        ['+', rest @ ..] => (false, rest),
        _ => (false, s),
    };
    let (base, prefixed, s) = match s {
        ['0', p, rest @ ..] => {
            let prefix_base = match p.to_ascii_lowercase() {
                'x' => 16,
                'o' => 8,
                'b' => 2,
                _ => 0,
            };
            if prefix_base != 0 && (base == 0 || base == prefix_base) {
                (prefix_base, true, rest)
            } else {
                (base, false, s)
            }
        }
        _ => (base, false, s),
    };
    let base0 = base == 0;
    let base = if base0 { 10 } else { base };
    // Underscores: one at a time, between digits, or right after a prefix.
    let mut magnitude = Some(0u128);
    let mut low = 0u64;
    let mut seen_digit = false;
    let mut after_underscore = false;
    let mut all_zero = true;
    for (i, &c) in s.iter().enumerate() {
        if c == '_' {
            if after_underscore || (!seen_digit && !(prefixed && i == 0)) {
                return None;
            }
            after_underscore = true;
            continue;
        }
        let d = c.to_digit(base).filter(|_| c.is_ascii())?;
        all_zero &= d == 0;
        seen_digit = true;
        after_underscore = false;
        magnitude = magnitude
            .and_then(|m| m.checked_mul(u128::from(base)))
            .and_then(|m| m.checked_add(u128::from(d)));
        low = low.wrapping_mul(u64::from(base)).wrapping_add(u64::from(d));
    }
    if !seen_digit || after_underscore {
        return None;
    }
    // Base 0 without prefix: no leading zero on a non-zero number ("010" is refused).
    if base0 && !prefixed && s.first() == Some(&'0') && !all_zero {
        return None;
    }
    Some(PyInt {
        negative: negative && magnitude != Some(0),
        magnitude,
        low,
    })
}

/// `bytes.fromhex(text)`: pairs of hexadecimal digits, ASCII whitespace allowed between
/// pairs.
pub(crate) fn from_hex(text: &[char]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut rest = text;
    loop {
        match rest {
            [] => return Some(out),
            [' ' | '\t' | '\n' | '\u{0b}' | '\u{0c}' | '\r', tail @ ..] => rest = tail,
            [high, low, tail @ ..] => {
                let byte = high.to_digit(16)? * 16 + low.to_digit(16)?;
                out.push(u8::try_from(byte).ok()?);
                rest = tail;
            }
            [_] => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn int(s: &str, base: u32) -> Option<i128> {
        py_int(&chars(s), base).and_then(PyInt::to_i128)
    }

    #[test]
    fn int_like_python() {
        assert_eq!(int("0x_ff", 16), Some(255));
        assert_eq!(int("0x__ff", 16), None);
        assert_eq!(int("0xff_", 16), None);
        assert_eq!(int("_1", 10), None);
        assert_eq!(int("1_0", 10), Some(10));
        assert_eq!(int(" 5 ", 10), Some(5));
        assert_eq!(int("-0x5", 16), Some(-5));
        assert_eq!(int("0x-5", 16), None);
        assert_eq!(int("010", 0), None);
        assert_eq!(int("00", 0), Some(0));
        assert_eq!(int("0_0", 0), Some(0));
        assert_eq!(int("0b1", 0), Some(1));
        assert_eq!(int("0b1", 16), Some(0xb1));
        assert_eq!(int("0X1", 0), Some(1));
        assert_eq!(int("0o7", 8), Some(7));
        assert_eq!(int("0x", 16), None);
        assert_eq!(int("", 10), None);
        assert_eq!(int("5\u{1c}", 10), None);
        assert_eq!(int("-_1", 10), None);
        assert_eq!(int("0_7", 8), Some(7));
        assert_eq!(int("08", 8), None);
        let huge = py_int(&chars(&"9".repeat(50)), 10).unwrap();
        assert!(huge.gt(u128::MAX - 1) && huge.to_i128().is_none());
        assert_eq!(
            py_int(&chars("-0x10000000000000001"), 16).unwrap().mask64(),
            u64::MAX
        );
    }

    #[test]
    fn fromhex_like_python() {
        let h = |s: &str| from_hex(&chars(s));
        assert_eq!(h("01  02"), Some(vec![1, 2]));
        assert_eq!(h("0 1"), None);
        assert_eq!(h(" 01\n"), Some(vec![1]));
        assert_eq!(h("01\u{a0}02"), None);
        assert_eq!(h("0"), None);
    }

    #[test]
    fn strip_like_python() {
        assert_eq!(string(strip(&chars("\u{1c} a b\u{3000}"))), "a b");
        assert_eq!(strip_str("\u{1f} a\u{a0}\u{3000}"), "a");
        assert_eq!(lstrip_str("\u{85}b "), "b ");
        assert_eq!(strip_str("\u{200b}x"), "\u{200b}x");
        assert_eq!(string(sub(&chars("abc"), 2, 1)), "");
        assert_eq!(string(from(&chars("abc"), 5)), "");
    }
}

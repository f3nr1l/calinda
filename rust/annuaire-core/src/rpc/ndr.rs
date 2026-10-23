// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! NDR 2.0 (C706 chapter 14), the little-endian subset the interfaces of ADR 0023 use:
//! primitives aligned on their size from the start of the stub, unique pointers (a referent
//! id, the pointed data deferred to after the structure that holds the pointer), conformant
//! and varying strings of UTF-16 units, conformant byte arrays. The interfaces lay out their
//! structures and deferred data themselves, in the order NDR prescribes.

use crate::smb::{SmbError, client::ErrorKind};

/// A stub ended before a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Short(pub &'static str);

impl std::fmt::Display for Short {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NDR stub too short or malformed ({})", self.0)
    }
}

impl From<Short> for SmbError {
    fn from(s: Short) -> Self {
        SmbError::new(ErrorKind::Protocol, s.to_string())
    }
}

/// A stub being written.
#[derive(Debug, Default, Clone)]
pub struct Writer {
    pub buf: Vec<u8>,
    referent: u32,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn align(&mut self, n: usize) -> &mut Self {
        while self.buf.len() % n != 0 {
            self.buf.push(0);
        }
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.align(2);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.align(4);
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// A non-null unique pointer: a new referent id (its data is written later by the caller).
    pub fn pointer(&mut self) -> &mut Self {
        self.referent += 4;
        let id = 0x0002_0000 + self.referent;
        self.u32(id)
    }

    pub fn null(&mut self) -> &mut Self {
        self.u32(0)
    }

    /// A pointer that is null when `present` is false.
    pub fn pointer_if(&mut self, present: bool) -> &mut Self {
        if present { self.pointer() } else { self.null() }
    }

    /// `[string] wchar_t*` data: maximum count, offset, actual count, units, terminating null
    /// included.
    pub fn string(&mut self, text: &str) -> &mut Self {
        let units: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
        let count = u32::try_from(units.len()).unwrap_or(u32::MAX);
        self.u32(count).u32(0).u32(count);
        for u in units {
            self.buf.extend_from_slice(&u.to_le_bytes());
        }
        self
    }

    /// A unique pointer to a string, then the string (top-level parameter: not deferred).
    pub fn unique_string(&mut self, text: Option<&str>) -> &mut Self {
        match text {
            Some(t) => self.pointer().string(t),
            None => self.null(),
        }
    }

    /// `[size_is(n)] unsigned char*` data: conformant count then the bytes.
    pub fn bytes(&mut self, data: &[u8]) -> &mut Self {
        self.u32(u32::try_from(data.len()).unwrap_or(u32::MAX));
        self.buf.extend_from_slice(data);
        self
    }
}

/// A stub being read, with bounds checked at every field.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pub at: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    pub fn u8_at(&self, at: usize) -> Option<u8> {
        self.buf.get(at).copied()
    }

    pub fn u16_at(&self, at: usize) -> Option<u16> {
        let b = self.buf.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes(b.try_into().ok()?))
    }

    pub fn u32_at(&self, at: usize) -> Option<u32> {
        let b = self.buf.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
    }

    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.at)
    }

    fn align(&mut self, n: usize) {
        self.at = self.at.div_ceil(n) * n;
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, Short> {
        self.align(2);
        let v = self.u16_at(self.at).ok_or(Short(what))?;
        self.at += 2;
        Ok(v)
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, Short> {
        self.align(4);
        let v = self.u32_at(self.at).ok_or(Short(what))?;
        self.at += 4;
        Ok(v)
    }

    /// A unique pointer: true when it is not null (its data comes later).
    pub fn pointer(&mut self, what: &'static str) -> Result<bool, Short> {
        Ok(self.u32(what)? != 0)
    }

    /// `[string] wchar_t*` data, without its terminating null.
    pub fn string(&mut self, what: &'static str) -> Result<String, Short> {
        let max = self.u32(what)? as usize;
        let offset = self.u32(what)? as usize;
        let actual = self.u32(what)? as usize;
        if offset != 0 || actual > max {
            return Err(Short(what));
        }
        let len = actual.checked_mul(2).ok_or(Short(what))?;
        let bytes = self
            .buf
            .get(self.at..self.at.checked_add(len).ok_or(Short(what))?)
            .ok_or(Short(what))?;
        self.at += len;
        let mut units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes(c.try_into().unwrap_or([0, 0])))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16(&units).map_err(|_| Short(what))
    }

    /// `[size_is(n)] unsigned char*` data.
    pub fn bytes(&mut self, what: &'static str) -> Result<Vec<u8>, Short> {
        let len = self.u32(what)? as usize;
        let bytes = self
            .buf
            .get(self.at..self.at.checked_add(len).ok_or(Short(what))?)
            .ok_or(Short(what))?
            .to_vec();
        self.at += len;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_is_conformant_and_varying() {
        let mut w = Writer::new();
        w.u16(1).string("ab");
        assert_eq!(
            w.buf,
            [
                1, 0, 0, 0, // u16 then alignment
                3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, // max, offset, actual
                b'a', 0, b'b', 0, 0, 0
            ]
        );
        let mut r = Reader::new(&w.buf);
        assert_eq!(r.u16("n").unwrap(), 1);
        assert_eq!(r.string("s").unwrap(), "ab");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn pointers_and_bytes() {
        let mut w = Writer::new();
        w.pointer().null().pointer_if(true).bytes(&[9, 8, 7]).u32(5);
        let mut r = Reader::new(&w.buf);
        assert!(r.pointer("a").unwrap());
        assert!(!r.pointer("b").unwrap());
        assert!(r.pointer("c").unwrap());
        assert_eq!(r.bytes("d").unwrap(), [9, 8, 7]);
        assert_eq!(r.u32("e").unwrap(), 5);
        // The two referent ids differ.
        assert_ne!(&w.buf[0..4], &w.buf[8..12]);
    }

    #[test]
    fn short_stubs_are_errors() {
        let mut r = Reader::new(&[3, 0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0, b'a', 0]);
        assert!(r.string("s").is_err());
        let mut r = Reader::new(&[0xFF, 0xFF, 0xFF, 0x7F]);
        assert!(r.bytes("b").is_err());
        let mut r = Reader::new(&[2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0]);
        assert!(r.string("offset").is_err());
    }
}

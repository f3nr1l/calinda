// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Little-endian fields: bounds-checked reads in untrusted bytes, and a growing buffer to
//! write a message.

/// `len` bytes at `at`, `None` past the end.
pub(crate) fn bytes_at(b: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    b.get(at..at.checked_add(len)?)
}

fn array_at<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    bytes_at(b, at, N)?.try_into().ok()
}

pub(crate) fn u8_at(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}

pub(crate) fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    array_at(b, at).map(u16::from_le_bytes)
}

pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    array_at(b, at).map(u32::from_le_bytes)
}

pub(crate) fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    array_at(b, at).map(u64::from_le_bytes)
}

pub(crate) fn array16_at(b: &[u8], at: usize) -> Option<[u8; 16]> {
    array_at(b, at)
}

/// UTF-16LE text, as SMB carries names.
pub(crate) fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// UTF-16LE bytes as text; `None` for an odd length or an unpaired surrogate.
pub(crate) fn from_utf16(b: &[u8]) -> Option<String> {
    if b.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| {
            u16::from_le_bytes([
                c.first().copied().unwrap_or(0),
                c.get(1).copied().unwrap_or(0),
            ])
        })
        .collect();
    String::from_utf16(&units).ok()
}

/// A message being written: little-endian fields appended in order.
#[derive(Debug, Default, Clone)]
pub(crate) struct Writer {
    pub(crate) buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Zero bytes up to a multiple of `n`.
    pub(crate) fn align(&mut self, n: usize) -> &mut Self {
        while self.buf.len() % n != 0 {
            self.buf.push(0);
        }
        self
    }

    /// Overwrites a 16-bit field written earlier.
    pub(crate) fn set_u16(&mut self, at: usize, v: u16) {
        if let Some(slot) = self.buf.get_mut(at..at + 2) {
            slot.copy_from_slice(&v.to_le_bytes());
        }
    }

    /// Overwrites a 32-bit field written earlier.
    pub(crate) fn set_u32(&mut self, at: usize, v: u32) {
        if let Some(slot) = self.buf.get_mut(at..at + 4) {
            slot.copy_from_slice(&v.to_le_bytes());
        }
    }
}

/// A length or an offset that must fit its field; messages are far below these limits.
pub(crate) fn to_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

pub(crate) fn to_u32(n: usize) -> u32 {
    u32::try_from(n).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_bounded() {
        let b = [1u8, 2, 3, 4, 5];
        assert_eq!(u16_at(&b, 0), Some(0x0201));
        assert_eq!(u32_at(&b, 1), Some(0x0504_0302));
        assert_eq!(u32_at(&b, 2), None);
        assert_eq!(bytes_at(&b, usize::MAX, 2), None);
    }

    #[test]
    fn utf16_round_trip() {
        let encoded = utf16("lab.test\\Policies\\été");
        assert_eq!(
            from_utf16(&encoded).as_deref(),
            Some("lab.test\\Policies\\été")
        );
        assert_eq!(from_utf16(&[0x41]), None);
    }

    #[test]
    fn writer_aligns_and_patches() {
        let mut w = Writer::new();
        w.u8(1).u16(0).align(8);
        assert_eq!(w.len(), 8);
        w.set_u16(1, 0xABCD);
        assert_eq!(w.buf, [1, 0xCD, 0xAB, 0, 0, 0, 0, 0]);
    }
}

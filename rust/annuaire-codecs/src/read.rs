// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Bounds-checked reads in untrusted bytes: `None` instead of a panic.

/// `len` bytes at `at`.
pub(crate) fn bytes_at(b: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    b.get(at..at.checked_add(len)?)
}

/// `N` bytes at `at`, as an array.
pub(crate) fn array_at<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    bytes_at(b, at, N)?.try_into().ok()
}

pub(crate) fn u8_at(b: &[u8], at: usize) -> Option<u8> {
    b.get(at).copied()
}

pub(crate) fn le_u16(b: &[u8], at: usize) -> Option<u16> {
    array_at(b, at).map(u16::from_le_bytes)
}

pub(crate) fn be_u16(b: &[u8], at: usize) -> Option<u16> {
    array_at(b, at).map(u16::from_be_bytes)
}

pub(crate) fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    array_at(b, at).map(u32::from_le_bytes)
}

pub(crate) fn be_u32(b: &[u8], at: usize) -> Option<u32> {
    array_at(b, at).map(u32::from_be_bytes)
}

pub(crate) fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    array_at(b, at).map(u64::from_le_bytes)
}

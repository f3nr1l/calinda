// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! SID: binary form (MS-DTYP 2.4.2.2) ⇄ structure ⇄ `S-1-…` text (MS-DTYP 2.4.2.1).
//!
//! Binary: revision (1 byte, always 1), sub-authority count (1 byte, at most 15),
//! authority (6 bytes, big-endian), then the sub-authorities (4 bytes each, little-endian).

use std::fmt;
use std::str::FromStr;

/// The only SID revision.
pub const REVISION: u8 = 1;
/// Maximum number of sub-authorities.
pub const MAX_SUB_AUTHORITIES: usize = 15;
/// Authorities are 48-bit numbers.
pub const MAX_AUTHORITY: u64 = (1 << 48) - 1;

const NT_AUTHORITY: u64 = 5;
const NT_DOMAIN: u32 = 21;

/// Why a SID was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SidError {
    /// Fewer than 8 bytes for the header.
    TruncatedHeader,
    /// Fewer bytes than the announced sub-authorities need.
    Truncated { count: u8 },
    /// Revision other than 1.
    InvalidRevision(u8),
    /// More than 15 sub-authorities.
    TooManySubAuthorities(usize),
    /// Bytes left after a SID that should fill the whole value.
    TrailingBytes(usize),
    /// Authority does not fit in 48 bits.
    AuthorityOutOfRange,
    /// Sub-authority does not fit in 32 bits.
    SubAuthorityOutOfRange,
    /// Text not of the form `S-1-…`.
    MalformedText(String),
    /// The SID has no sub-authority to remove.
    NoSubAuthority,
    /// `S-1-5-21-a-b-c` expected.
    NotADomainSid(String),
}

impl fmt::Display for SidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedHeader => write!(f, "truncated SID: incomplete header"),
            Self::Truncated { count } => {
                write!(f, "truncated SID: {count} sub-authorities announced")
            }
            Self::InvalidRevision(r) => write!(f, "invalid SID revision: {r}"),
            Self::TooManySubAuthorities(n) => write!(f, "too many sub-authorities: {n}"),
            Self::TrailingBytes(n) => write!(f, "SID followed by {n} extra bytes"),
            Self::AuthorityOutOfRange => write!(f, "SID authority out of range"),
            Self::SubAuthorityOutOfRange => write!(f, "SID sub-authority out of range"),
            Self::MalformedText(t) => write!(f, "malformed SID text: {t:?}"),
            Self::NoSubAuthority => write!(f, "SID without sub-authority"),
            Self::NotADomainSid(t) => write!(f, "not a domain SID: {t}"),
        }
    }
}

impl std::error::Error for SidError {}

/// A security identifier. `Copy`, no allocation: 15 sub-authorities at most.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Sid {
    authority: u64,
    count: u8,
    subs: [u32; MAX_SUB_AUTHORITIES],
}

impl Sid {
    /// SID of revision 1 from its authority (48 bits) and sub-authorities (15 at most).
    pub fn new(authority: u64, sub_authorities: &[u32]) -> Result<Self, SidError> {
        if authority > MAX_AUTHORITY {
            return Err(SidError::AuthorityOutOfRange);
        }
        if sub_authorities.len() > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(sub_authorities.len()));
        }
        let mut subs = [0; MAX_SUB_AUTHORITIES];
        subs.get_mut(..sub_authorities.len())
            .ok_or(SidError::TooManySubAuthorities(sub_authorities.len()))?
            .copy_from_slice(sub_authorities);
        Ok(Self {
            authority,
            // At most 15: checked above.
            count: sub_authorities.len() as u8,
            subs,
        })
    }

    /// Always 1.
    pub fn revision(&self) -> u8 {
        REVISION
    }

    pub fn authority(&self) -> u64 {
        self.authority
    }

    pub fn sub_authorities(&self) -> &[u32] {
        self.subs.get(..usize::from(self.count)).unwrap_or(&[])
    }

    /// Reads a SID at `position`; returns it and the position after it.
    ///
    /// For the structures that hold SIDs (security descriptors, ACEs).
    pub fn read(bytes: &[u8], position: usize) -> Result<(Self, usize), SidError> {
        let header: [u8; 8] = bytes
            .get(position..)
            .and_then(|rest| rest.get(..8))
            .and_then(|h| h.try_into().ok())
            .ok_or(SidError::TruncatedHeader)?;
        let [revision, count, a0, a1, a2, a3, a4, a5] = header;
        if revision != REVISION {
            return Err(SidError::InvalidRevision(revision));
        }
        if usize::from(count) > MAX_SUB_AUTHORITIES {
            return Err(SidError::TooManySubAuthorities(count.into()));
        }
        let authority = u64::from_be_bytes([0, 0, a0, a1, a2, a3, a4, a5]);
        let end = position + 8 + 4 * usize::from(count);
        let body = bytes
            .get(position + 8..end)
            .ok_or(SidError::Truncated { count })?;
        let mut subs = [0; MAX_SUB_AUTHORITIES];
        for (sub, chunk) in subs.iter_mut().zip(body.chunks_exact(4)) {
            *sub = u32::from_le_bytes(chunk.try_into().unwrap_or_default());
        }
        Ok((
            Self {
                authority,
                count,
                subs,
            },
            end,
        ))
    }

    /// Decodes a binary SID that fills `bytes` exactly (attribute `objectSid`).
    pub fn decode(bytes: &[u8]) -> Result<Self, SidError> {
        let (sid, end) = Self::read(bytes, 0)?;
        if end != bytes.len() {
            return Err(SidError::TrailingBytes(bytes.len() - end));
        }
        Ok(sid)
    }

    /// Length of the binary form.
    pub fn binary_len(&self) -> usize {
        8 + 4 * usize::from(self.count)
    }

    /// Appends the binary form to `out`.
    pub fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[REVISION, self.count]);
        let [_, _, authority @ ..] = self.authority.to_be_bytes();
        out.extend_from_slice(&authority);
        for sub in self.sub_authorities() {
            out.extend_from_slice(&sub.to_le_bytes());
        }
    }

    /// Binary form.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.binary_len());
        self.write_to(&mut out);
        out
    }

    /// True for `S-1-5-21-a-b-c` (the SID of the domain itself).
    pub fn is_domain_sid(&self) -> bool {
        self.authority == NT_AUTHORITY
            && self.count == 4
            && self.sub_authorities().first() == Some(&NT_DOMAIN)
    }

    /// RID of a domain account SID (`S-1-5-21-a-b-c-RID`), else `None`.
    pub fn rid(&self) -> Option<u32> {
        if self.count == 5 && self.domain().is_ok_and(|d| d.is_domain_sid()) {
            self.sub_authorities().last().copied()
        } else {
            None
        }
    }

    /// The SID without its last sub-authority (the domain, for an account SID).
    pub fn domain(&self) -> Result<Self, SidError> {
        let subs = self.sub_authorities();
        match subs.split_last() {
            Some((_, head)) => Self::new(self.authority, head),
            None => Err(SidError::NoSubAuthority),
        }
    }

    /// Account SID of the domain `self` from its RID (see `primaryGroupID`).
    pub fn with_rid(&self, rid: u32) -> Result<Self, SidError> {
        if !self.is_domain_sid() {
            return Err(SidError::NotADomainSid(self.to_string()));
        }
        let mut subs = [0; 5];
        subs[..4].copy_from_slice(self.sub_authorities());
        subs[4] = rid;
        Self::new(self.authority, &subs)
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

/// `S-1-…` form; the authority in hexadecimal (`0x` and 12 digits) from 2^32 on.
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.authority < 1 << 32 {
            write!(f, "S-{REVISION}-{}", self.authority)?;
        } else {
            write!(f, "S-{REVISION}-0x{:012X}", self.authority)?;
        }
        for sub in self.sub_authorities() {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

/// Parses `S-1-…` (the `S` in either case); decimal numbers may have leading zeros.
impl FromStr for Sid {
    type Err = SidError;

    fn from_str(text: &str) -> Result<Self, SidError> {
        let malformed = || SidError::MalformedText(text.to_owned());
        let rest = text
            .strip_prefix("S-1-")
            .or_else(|| text.strip_prefix("s-1-"))
            .ok_or_else(malformed)?;
        let mut parts = rest.split('-');
        let first = parts.next().ok_or_else(malformed)?;
        let authority = match first
            .strip_prefix("0x")
            .or_else(|| first.strip_prefix("0X"))
        {
            Some(hex) => {
                if hex.len() != 12 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(malformed());
                }
                u64::from_str_radix(hex, 16).map_err(|_| malformed())?
            }
            None => parse_decimal(first).ok_or_else(malformed)?,
        };
        let mut subs = Vec::with_capacity(MAX_SUB_AUTHORITIES);
        for part in parts {
            let value = parse_decimal(part).ok_or_else(malformed)?;
            subs.push(u32::try_from(value).map_err(|_| SidError::SubAuthorityOutOfRange)?);
        }
        if authority > MAX_AUTHORITY {
            return Err(SidError::AuthorityOutOfRange);
        }
        Self::new(authority, &subs)
    }
}

/// ASCII decimal digits, at least one; `u64::MAX` for values that overflow (always out of
/// range for a SID, as in Python where the number is unbounded).
fn parse_decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(text.bytes().fold(0u64, |acc, b| {
        acc.saturating_mul(10).saturating_add(u64::from(b - b'0'))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn hexadecimal_authority() {
        let sid = Sid::new(1 << 40, &[7]).unwrap();
        assert_eq!(sid.to_string(), "S-1-0x010000000000-7");
        assert_eq!("s-1-0x010000000000-7".parse::<Sid>().unwrap(), sid);
        assert_eq!(Sid::decode(&sid.encode()).unwrap(), sid);
    }

    #[test]
    fn no_sub_authority() {
        let sid = Sid::decode(&hex("010000000000000f")).unwrap();
        assert_eq!(sid.to_string(), "S-1-15");
        assert_eq!(sid.rid(), None);
        assert!(sid.domain().is_err());
    }

    #[test]
    fn invalid_binary() {
        for text in [
            "",
            "0101000000",
            "0102000000000005200000",
            "020100000000000512000000",
            &format!("0110000000000005{}", "00000000".repeat(16)),
            "010100000000000512000000ff",
        ] {
            assert!(Sid::decode(&hex(text)).is_err(), "{text}");
        }
    }

    #[test]
    fn read_inside_a_structure() {
        let mut bytes = vec![0xaa];
        bytes.extend(hex("010100000000000512000000"));
        bytes.push(0xbb);
        let (sid, end) = Sid::read(&bytes, 1).unwrap();
        assert_eq!(sid.to_string(), "S-1-5-18");
        assert_eq!(end, 13);
    }

    #[test]
    fn invalid_text() {
        for text in [
            "",
            "S-1",
            "S-2-5-18",
            "S-1-5-",
            "S-1-5--1",
            "X-1-5-18",
            "S-1-5-4294967296",
            "S-1-281474976710656",
            "S-1-0x01000000000-7",
            "S-1-5-١",
        ] {
            assert!(text.parse::<Sid>().is_err(), "{text}");
        }
    }

    #[test]
    fn invalid_structure() {
        assert!(Sid::new(1 << 48, &[18]).is_err());
        assert!(Sid::new(5, &[0; 16]).is_err());
    }

    #[test]
    fn domain_and_rid() {
        let account: Sid = "S-1-5-21-1-2-3-1104".parse().unwrap();
        let domain = account.domain().unwrap();
        assert_eq!(domain.to_string(), "S-1-5-21-1-2-3");
        assert!(domain.is_domain_sid());
        assert_eq!(
            domain.with_rid(513).unwrap(),
            "S-1-5-21-1-2-3-513".parse().unwrap()
        );
        assert!(account.with_rid(513).is_err());
        assert_eq!("S-1-5-32-544".parse::<Sid>().unwrap().rid(), None);
        assert_eq!("S-1-5-21-1-2-3-4-5".parse::<Sid>().unwrap().rid(), None);
    }
}

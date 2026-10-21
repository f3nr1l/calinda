// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS record of an AD-integrated zone: value of `dnsRecord` (MS-DNSP 2.3.2.2).
//!
//! 24-byte header, little-endian **except the TTL**:
//!
//! ```text
//! DataLength (2)  Type (2)  Version (1, = 5)  Rank (1)  Flags (2)  Serial (4)
//! TtlSeconds (4, big-endian)  Reserved (4)  TimeStamp (4)  Data (DataLength)
//! ```
//!
//! `TimeStamp` counts hours since 1601-01-01 UTC; 0 = static record (never aged). The data
//! (MS-DNSP 2.2.2.2.4) is in network order:
//!
//! - A: 4 bytes; AAAA: 16 bytes;
//! - NS, CNAME, PTR (and DNAME, MB, MD, MF, MG, MR): a `DNS_COUNT_NAME`;
//! - MX: preference (2) and a name; SRV: priority (2), weight (2), port (2) and a name;
//! - SOA: serial, refresh, retry, expire, minimum (4 each), primary server, responsible;
//! - TXT: strings, each preceded by its length (1 byte);
//! - type 0: tombstoned node, FILETIME (8 bytes, little-endian) of the tombstoning.
//!
//! `DNS_COUNT_NAME`: length (1 byte, of the label sequence including the final zero), label
//! count (1), then each label preceded by its length, and a zero.
//!
//! No record breaks the display: an unknown type, or data that does not read back to the
//! same bytes (malformed, or a form the encoder would not reproduce), stays `Raw`. A record
//! decoded then encoded always gives the same bytes. Only an unreadable header (fewer than
//! 24 bytes, wrong announced length) is an error.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::read::{be_u16, be_u32, bytes_at, le_u16, le_u32, le_u64, u8_at};
use crate::time::{self, TimeError, UtcTime};

pub const VERSION: u8 = 5;
pub const HEADER_SIZE: usize = 24;

// Types (MS-DNSP 2.2.2.1.1, numbers of RFC 1035 and later).
pub const TOMBSTONE: u16 = 0;
pub const A: u16 = 1;
pub const NS: u16 = 2;
pub const MD: u16 = 3;
pub const MF: u16 = 4;
pub const CNAME: u16 = 5;
pub const SOA: u16 = 6;
pub const MB: u16 = 7;
pub const MG: u16 = 8;
pub const MR: u16 = 9;
pub const PTR: u16 = 12;
pub const MX: u16 = 15;
pub const TXT: u16 = 16;
pub const AAAA: u16 = 28;
pub const SRV: u16 = 33;
pub const DNAME: u16 = 39;

const TYPE_NAMES: &[(u16, &str)] = &[
    (TOMBSTONE, "TOMBSTONE"),
    (A, "A"),
    (NS, "NS"),
    (MD, "MD"),
    (MF, "MF"),
    (CNAME, "CNAME"),
    (SOA, "SOA"),
    (MB, "MB"),
    (MG, "MG"),
    (MR, "MR"),
    (10, "NULL"),
    (11, "WKS"),
    (PTR, "PTR"),
    (13, "HINFO"),
    (14, "MINFO"),
    (MX, "MX"),
    (TXT, "TXT"),
    (17, "RP"),
    (18, "AFSDB"),
    (19, "X25"),
    (20, "ISDN"),
    (21, "RT"),
    (24, "SIG"),
    (25, "KEY"),
    (AAAA, "AAAA"),
    (29, "LOC"),
    (30, "NXT"),
    (SRV, "SRV"),
    (34, "ATMA"),
    (35, "NAPTR"),
    (DNAME, "DNAME"),
    (43, "DS"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (49, "DHCID"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (0xFF01, "WINS"),
    (0xFF02, "WINSR"),
];

/// Rank of authoritative zone data: the case of every ordinary record.
pub const RANK_ZONE: u8 = 0xF0;

/// Ranks (MS-DNSP 2.2.2.2.4.1, `DNS_RPC_RECORD_FLAGS`): where the record comes from.
const RANK_NAMES: &[(u8, &str)] = &[
    (0x00, "NONE"),
    (0x01, "CACHE_BIT"),
    (0x08, "ROOT_HINT"),
    (0x20, "OUTSIDE_GLUE"),
    (0x31, "CACHE_NA_ADDITIONAL"),
    (0x41, "CACHE_NA_AUTHORITY"),
    (0x51, "CACHE_A_ADDITIONAL"),
    (0x61, "CACHE_NA_ANSWER"),
    (0x71, "CACHE_A_AUTHORITY"),
    (0x80, "GLUE"),
    (0x82, "NS_GLUE"),
    (0xC1, "CACHE_A_ANSWER"),
    (RANK_ZONE, "ZONE"),
];

const NAME_TYPES: [u16; 9] = [NS, MD, MF, CNAME, MB, MG, MR, PTR, DNAME];

/// Name of a type (`A`, `SRV`…), `TYPEn` for an unknown one.
pub fn type_name(rtype: u16) -> String {
    TYPE_NAMES
        .iter()
        .find(|(t, _)| *t == rtype)
        .map_or_else(|| format!("TYPE{rtype}"), |(_, n)| (*n).to_owned())
}

/// Name of a rank (`ZONE`…), `0xNN` for an unknown one.
pub fn rank_name(rank: u8) -> String {
    RANK_NAMES
        .iter()
        .find(|(r, _)| *r == rank)
        .map_or_else(|| format!("0x{rank:02x}"), |(_, n)| (*n).to_owned())
}

/// Why a record, a name or some data was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// Fewer than 24 bytes.
    ShortHeader(usize),
    /// Announced data length different from the bytes that follow the header.
    LengthMismatch { announced: u16, received: usize },
    /// Data longer than 65 535 bytes.
    DataTooLong(usize),
    /// Data of a known type that does not read (kept as `Raw` by `read_data`).
    Data(DataError),
}

/// Why the data of a known type was kept raw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataError {
    WrongLength {
        rtype: u16,
        length: usize,
    },
    Truncated(u16),
    NameTruncated,
    NameBeyondData,
    LabelOutOfName,
    InvalidLabelLength,
    MissingFinalZero,
    ExtraBytes(usize),
    TxtTruncated,
    NotUtf8,
    /// Label empty or longer than 63 bytes, when encoding.
    BadLabel {
        length: usize,
        name: String,
    },
    NameTooLong(String),
    TxtStringTooLong,
    /// Reads, but would not be written back to the same bytes.
    NotReproducible,
}

impl fmt::Display for DataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { rtype, length } => {
                write!(f, "{} of length {length}", type_name(*rtype))
            }
            Self::Truncated(t) => write!(f, "truncated {}", type_name(*t)),
            Self::NameTruncated => write!(f, "truncated DNS name"),
            Self::NameBeyondData => write!(f, "DNS name longer than the data"),
            Self::LabelOutOfName => write!(f, "DNS label outside the name"),
            Self::InvalidLabelLength => write!(f, "DNS label of invalid length"),
            Self::MissingFinalZero => write!(f, "DNS name without final zero"),
            Self::ExtraBytes(n) => write!(f, "{n} extra bytes after the name"),
            Self::TxtTruncated => write!(f, "truncated TXT string"),
            Self::NotUtf8 => write!(f, "text is not UTF-8"),
            Self::BadLabel { length, name } => write!(f, "DNS label of {length} bytes in {name:?}"),
            Self::NameTooLong(n) => write!(f, "DNS name too long: {n:?}"),
            Self::TxtStringTooLong => write!(f, "TXT string longer than 255 bytes"),
            Self::NotReproducible => write!(f, "form not reproducible byte for byte"),
        }
    }
}

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader(n) => {
                write!(f, "dnsRecord of {n} bytes, header of {HEADER_SIZE}")
            }
            Self::LengthMismatch {
                announced,
                received,
            } => write!(
                f,
                "dnsRecord: {announced} bytes of data announced, {received} received"
            ),
            Self::DataTooLong(n) => write!(f, "DNS data of {n} bytes, more than 65 535"),
            Self::Data(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DataError {}
impl std::error::Error for DnsError {}

impl From<DataError> for DnsError {
    fn from(e: DataError) -> Self {
        Self::Data(e)
    }
}

/// Data of a record, by type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordData {
    /// A or AAAA.
    Address(IpAddr),
    /// NS, CNAME, PTR…: a domain name, without final dot.
    Name(String),
    Mx {
        preference: u16,
        target: String,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Soa {
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
        primary_server: String,
        responsible: String,
    },
    /// Strings of a TXT, in order.
    Txt(Vec<String>),
    /// Type 0: FILETIME of the tombstoning.
    Tombstone(u64),
    /// Unknown type (`error` is `None`), or data that does not read back to the same bytes.
    Raw {
        bytes: Vec<u8>,
        error: Option<DataError>,
    },
}

/// A record: header fields and data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub rtype: u16,
    pub data: RecordData,
    pub rank: u8,
    pub flags: u16,
    /// Serial of the zone when the record was written (not the one of the SOA).
    pub serial: u32,
    pub ttl: u32,
    /// Hours since 1601 (last dynamic refresh); 0 = static.
    pub timestamp: u32,
    pub version: u8,
    pub reserved: u32,
}

impl Record {
    /// A record with the defaults of the Python model (rank ZONE, TTL 3600, static).
    pub fn new(rtype: u16, data: RecordData) -> Self {
        Self {
            rtype,
            data,
            rank: RANK_ZONE,
            flags: 0,
            serial: 0,
            ttl: 3600,
            timestamp: 0,
            version: VERSION,
            reserved: 0,
        }
    }

    pub fn type_name(&self) -> String {
        type_name(self.rtype)
    }

    pub fn rank_name(&self) -> String {
        rank_name(self.rank)
    }

    pub fn is_static(&self) -> bool {
        self.timestamp == 0
    }

    /// Date of the timestamp; `None` for a static record.
    pub fn date(&self) -> Result<Option<UtcTime>, TimeError> {
        hours_to_utc(self.timestamp)
    }

    /// Value of `dnsRecord` → record; an error only if the header is unreadable.
    pub fn decode(bytes: &[u8]) -> Result<Self, DnsError> {
        let short = || DnsError::ShortHeader(bytes.len());
        let length = le_u16(bytes, 0).ok_or_else(short)?;
        let rtype = le_u16(bytes, 2).ok_or_else(short)?;
        let version = u8_at(bytes, 4).ok_or_else(short)?;
        let rank = u8_at(bytes, 5).ok_or_else(short)?;
        let flags = le_u16(bytes, 6).ok_or_else(short)?;
        let serial = le_u32(bytes, 8).ok_or_else(short)?;
        let ttl = be_u32(bytes, 12).ok_or_else(short)?;
        let reserved = le_u32(bytes, 16).ok_or_else(short)?;
        let timestamp = le_u32(bytes, 20).ok_or_else(short)?;
        let data = bytes.get(HEADER_SIZE..).unwrap_or_default();
        if data.len() != usize::from(length) {
            return Err(DnsError::LengthMismatch {
                announced: length,
                received: data.len(),
            });
        }
        Ok(Self {
            rtype,
            data: read_data(rtype, data),
            rank,
            flags,
            serial,
            ttl,
            timestamp,
            version,
            reserved,
        })
    }

    /// Record → value of `dnsRecord`.
    pub fn encode(&self) -> Result<Vec<u8>, DnsError> {
        let data = encode_data(&self.data)?;
        let length = u16::try_from(data.len()).map_err(|_| DnsError::DataTooLong(data.len()))?;
        let mut out = Vec::with_capacity(HEADER_SIZE + data.len());
        out.extend_from_slice(&length.to_le_bytes());
        out.extend_from_slice(&self.rtype.to_le_bytes());
        out.extend_from_slice(&[self.version, self.rank]);
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.serial.to_le_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&self.reserved.to_le_bytes());
        out.extend_from_slice(&self.timestamp.to_le_bytes());
        out.extend_from_slice(&data);
        Ok(out)
    }

    /// Data in a readable form, close to the one of DNS tools (no final dot).
    ///
    /// An error only for a tombstone dated after the year 9999.
    pub fn data_text(&self) -> Result<String, TimeError> {
        Ok(match &self.data {
            RecordData::Address(address) => address.to_string(),
            RecordData::Name(name) => name.clone(),
            RecordData::Mx { preference, target } => format!("{preference} {target}"),
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            } => format!("{priority} {weight} {port} {target}"),
            RecordData::Soa {
                serial,
                refresh,
                retry,
                expire,
                minimum,
                primary_server,
                responsible,
            } => format!(
                "{primary_server} {responsible} {serial} {refresh} {retry} {expire} {minimum}"
            ),
            RecordData::Txt(strings) => strings
                .iter()
                .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
                .collect::<Vec<_>>()
                .join(" "),
            RecordData::Tombstone(nttime) => tombstone_text(*nttime)?,
            RecordData::Raw { bytes, .. } => bytes
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" "),
        })
    }
}

/// Date of the tombstoning in the form of Python's `datetime.isoformat()` (microseconds,
/// `+00:00`), or the raw number when it carries no date.
fn tombstone_text(nttime: u64) -> Result<String, TimeError> {
    let date = i64::try_from(nttime)
        .map_err(|_| TimeError::NtTimeOutOfRange(i64::MAX))
        .and_then(time::nttime_to_utc)?;
    let Some(date) = date else {
        return Ok(nttime.to_string());
    };
    let c = date.civil();
    let micro = c.fraction / 10;
    let fraction = if micro == 0 {
        String::new()
    } else {
        format!(".{micro:06}")
    };
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}+00:00",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    ))
}

/// Hours since 1601 (DNS timestamp, zone aging) → UTC date; 0 → `None`.
pub fn hours_to_utc(hours: u32) -> Result<Option<UtcTime>, TimeError> {
    if hours == 0 {
        return Ok(None);
    }
    time::NT_EPOCH
        .add_seconds(i64::from(hours) * 3600)
        .map(Some)
        .ok_or(TimeError::OutOfRange)
}

/// Date → whole hours since 1601 (floored).
pub fn utc_to_hours(date: UtcTime) -> i64 {
    date.seconds_since(time::NT_EPOCH).div_euclid(3600)
}

// --- DNS_COUNT_NAME and strings ----------------------------------------------------------------

/// Reads a `DNS_COUNT_NAME`; returns the name (labels joined by dots, no final dot; empty
/// for the root) and the position after it.
pub fn read_name(bytes: &[u8], position: usize) -> Result<(String, usize), DataError> {
    let length = u8_at(bytes, position).ok_or(DataError::NameTruncated)?;
    let count = u8_at(bytes, position + 1).ok_or(DataError::NameTruncated)?;
    let start = position + 2;
    let end = start + usize::from(length);
    if end > bytes.len() {
        return Err(DataError::NameBeyondData);
    }
    let mut labels = Vec::with_capacity(usize::from(count));
    let mut cursor = start;
    for _ in 0..count {
        if cursor >= end {
            return Err(DataError::LabelOutOfName);
        }
        let size = usize::from(u8_at(bytes, cursor).ok_or(DataError::LabelOutOfName)?);
        if size == 0 || cursor + 1 + size > end {
            return Err(DataError::InvalidLabelLength);
        }
        let label = bytes_at(bytes, cursor + 1, size).ok_or(DataError::InvalidLabelLength)?;
        labels.push(std::str::from_utf8(label).map_err(|_| DataError::NotUtf8)?);
        cursor += 1 + size;
    }
    if cursor >= end || u8_at(bytes, cursor) != Some(0) {
        return Err(DataError::MissingFinalZero);
    }
    Ok((labels.join("."), end))
}

/// Name (with or without final dot) → `DNS_COUNT_NAME`.
pub fn encode_name(name: &str) -> Result<Vec<u8>, DataError> {
    let name = name.strip_suffix('.').unwrap_or(name);
    let labels: Vec<&str> = if name.is_empty() {
        Vec::new()
    } else {
        name.split('.').collect()
    };
    let mut body = Vec::with_capacity(name.len() + 2);
    for label in &labels {
        if !(1..64).contains(&label.len()) {
            return Err(DataError::BadLabel {
                length: label.len(),
                name: name.to_owned(),
            });
        }
        body.push(label.len() as u8);
        body.extend_from_slice(label.as_bytes());
    }
    body.push(0);
    let too_long = || DataError::NameTooLong(name.to_owned());
    let length = u8::try_from(body.len()).map_err(|_| too_long())?;
    let count = u8::try_from(labels.len()).map_err(|_| too_long())?;
    let mut out = Vec::with_capacity(body.len() + 2);
    out.extend_from_slice(&[length, count]);
    out.extend_from_slice(&body);
    Ok(out)
}

fn read_strings(bytes: &[u8]) -> Result<Vec<String>, DataError> {
    let mut strings = Vec::new();
    let mut cursor = 0;
    while let Some(size) = u8_at(bytes, cursor) {
        let raw = bytes_at(bytes, cursor + 1, usize::from(size)).ok_or(DataError::TxtTruncated)?;
        strings.push(String::from_utf8(raw.to_vec()).map_err(|_| DataError::NotUtf8)?);
        cursor += 1 + usize::from(size);
    }
    Ok(strings)
}

fn encode_strings(strings: &[String], out: &mut Vec<u8>) -> Result<(), DataError> {
    for s in strings {
        let size = u8::try_from(s.len()).map_err(|_| DataError::TxtStringTooLong)?;
        out.push(size);
        out.extend_from_slice(s.as_bytes());
    }
    Ok(())
}

// --- Data ----------------------------------------------------------------------------------------

fn exactly(bytes: &[u8], end: usize) -> Result<(), DataError> {
    if end == bytes.len() {
        Ok(())
    } else {
        Err(DataError::ExtraBytes(bytes.len().saturating_sub(end)))
    }
}

fn decode_data(rtype: u16, bytes: &[u8]) -> Result<RecordData, DataError> {
    let wrong_length = || DataError::WrongLength {
        rtype,
        length: bytes.len(),
    };
    Ok(match rtype {
        A => {
            let octets: [u8; 4] = bytes.try_into().map_err(|_| wrong_length())?;
            RecordData::Address(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        AAAA => {
            let octets: [u8; 16] = bytes.try_into().map_err(|_| wrong_length())?;
            RecordData::Address(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        t if NAME_TYPES.contains(&t) => {
            let (name, end) = read_name(bytes, 0)?;
            exactly(bytes, end)?;
            RecordData::Name(name)
        }
        MX => {
            let preference = be_u16(bytes, 0).ok_or(DataError::Truncated(MX))?;
            let (target, end) = read_name(bytes, 2)?;
            exactly(bytes, end)?;
            RecordData::Mx { preference, target }
        }
        SRV => {
            let truncated = || DataError::Truncated(SRV);
            let priority = be_u16(bytes, 0).ok_or_else(truncated)?;
            let weight = be_u16(bytes, 2).ok_or_else(truncated)?;
            let port = be_u16(bytes, 4).ok_or_else(truncated)?;
            let (target, end) = read_name(bytes, 6)?;
            exactly(bytes, end)?;
            RecordData::Srv {
                priority,
                weight,
                port,
                target,
            }
        }
        SOA => {
            let field = |i: usize| be_u32(bytes, 4 * i).ok_or(DataError::Truncated(SOA));
            let (serial, refresh, retry, expire, minimum) =
                (field(0)?, field(1)?, field(2)?, field(3)?, field(4)?);
            let (primary_server, next) = read_name(bytes, 20)?;
            let (responsible, end) = read_name(bytes, next)?;
            exactly(bytes, end)?;
            RecordData::Soa {
                serial,
                refresh,
                retry,
                expire,
                minimum,
                primary_server,
                responsible,
            }
        }
        TXT => RecordData::Txt(read_strings(bytes)?),
        TOMBSTONE => {
            if bytes.len() != 8 {
                return Err(wrong_length());
            }
            RecordData::Tombstone(le_u64(bytes, 0).ok_or_else(wrong_length)?)
        }
        _ => RecordData::Raw {
            bytes: bytes.to_vec(),
            error: None,
        },
    })
}

/// Data alone (no header), in network order.
pub fn encode_data(data: &RecordData) -> Result<Vec<u8>, DataError> {
    let mut out = Vec::new();
    match data {
        RecordData::Address(IpAddr::V4(a)) => out.extend_from_slice(&a.octets()),
        RecordData::Address(IpAddr::V6(a)) => out.extend_from_slice(&a.octets()),
        RecordData::Name(name) => out = encode_name(name)?,
        RecordData::Mx { preference, target } => {
            out.extend_from_slice(&preference.to_be_bytes());
            out.extend(encode_name(target)?);
        }
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for n in [priority, weight, port] {
                out.extend_from_slice(&n.to_be_bytes());
            }
            out.extend(encode_name(target)?);
        }
        RecordData::Soa {
            serial,
            refresh,
            retry,
            expire,
            minimum,
            primary_server,
            responsible,
        } => {
            for n in [serial, refresh, retry, expire, minimum] {
                out.extend_from_slice(&n.to_be_bytes());
            }
            out.extend(encode_name(primary_server)?);
            out.extend(encode_name(responsible)?);
        }
        RecordData::Txt(strings) => encode_strings(strings, &mut out)?,
        RecordData::Tombstone(nttime) => out.extend_from_slice(&nttime.to_le_bytes()),
        RecordData::Raw { bytes, .. } => out.extend_from_slice(bytes),
    }
    Ok(out)
}

/// Data of a type → decoded value; `Raw` if the type is unknown or if the bytes do not
/// read back to the same bytes. Never fails.
pub fn read_data(rtype: u16, bytes: &[u8]) -> RecordData {
    let raw = |error| RecordData::Raw {
        bytes: bytes.to_vec(),
        error: Some(error),
    };
    match decode_data(rtype, bytes) {
        Ok(data) => match encode_data(&data) {
            Ok(again) if again == bytes => data,
            Ok(_) => raw(DataError::NotReproducible),
            Err(e) => raw(e),
        },
        Err(e) => raw(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(rtype: u16, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
        out.extend_from_slice(&rtype.to_le_bytes());
        out.extend_from_slice(&[5, 0xf0, 0, 0, 1, 0, 0, 0]);
        out.extend_from_slice(&900u32.to_be_bytes());
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(data);
        out
    }

    #[test]
    fn build_and_encode() {
        let cases = [
            (A, RecordData::Address("192.168.1.27".parse().unwrap())),
            (AAAA, RecordData::Address("2001:db8::1b".parse().unwrap())),
            (CNAME, RecordData::Name("dc1.lab.test".into())),
            (
                MX,
                RecordData::Mx {
                    preference: 10,
                    target: "mail.lab.test".into(),
                },
            ),
            (
                TXT,
                RecordData::Txt(vec!["v=spf1 -all".into(), "guillemet \" é".into()]),
            ),
            (TOMBSTONE, RecordData::Tombstone(134_363_878_295_882_240)),
            (
                99,
                RecordData::Raw {
                    bytes: vec![1, 2],
                    error: None,
                },
            ),
        ];
        for (rtype, data) in cases {
            let mut r = Record::new(rtype, data);
            r.ttl = 900;
            assert_eq!(Record::decode(&r.encode().unwrap()).unwrap(), r);
            assert!(!r.data_text().unwrap().is_empty());
        }
        assert_eq!(encode_name("dc1.lab.test."), encode_name("dc1.lab.test"));
        assert_eq!(encode_name("").unwrap(), [1, 0, 0]);
        assert_eq!(read_name(&[1, 0, 0], 0).unwrap(), (String::new(), 3));
    }

    #[test]
    fn malformed_kept_raw() {
        for (rtype, data) in [
            (A, &b"\x01\x02\x03"[..]),
            (CNAME, b"\x05\x01\x03abc"),
            (CNAME, b"\x05\x01\x03abc\x00\x00"),
            (SRV, b"\x00\x01"),
            (TXT, b"\x09abc"),
            (CNAME, b"\x04\x01\x02\xff\xfe\x00"),
            (CNAME, b"\x06\x02\x03abc\x00\x00"),
        ] {
            let bytes = record(rtype, data);
            let r = Record::decode(&bytes).unwrap();
            assert!(
                matches!(r.data, RecordData::Raw { error: Some(_), .. }),
                "{rtype} {data:?}"
            );
            assert_eq!(r.encode().unwrap(), bytes);
        }
        let long = b"\x10\x01\x03abc\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(matches!(read_data(CNAME, long), RecordData::Raw { .. }));
    }

    #[test]
    fn unreadable_header() {
        assert!(Record::decode(&[]).is_err());
        assert!(Record::decode(&[0; 23]).is_err());
        assert!(encode_name(&format!("{}.test", "a".repeat(64))).is_err());
        assert!(encode_name("a..b").is_err());
    }

    #[test]
    fn texts() {
        let srv = Record::new(
            SRV,
            RecordData::Srv {
                priority: 0,
                weight: 100,
                port: 389,
                target: "dc1.lab.test".into(),
            },
        );
        assert_eq!(srv.data_text().unwrap(), "0 100 389 dc1.lab.test");
        let txt = Record::new(TXT, RecordData::Txt(vec!["a\"b".into(), "c".into()]));
        assert_eq!(txt.data_text().unwrap(), "\"a\\\"b\" \"c\"");
        let tomb = Record::new(TOMBSTONE, RecordData::Tombstone(134_363_878_295_882_240));
        assert_eq!(
            tomb.data_text().unwrap(),
            "2026-10-13T17:57:09.588224+00:00"
        );
        let never = Record::new(TOMBSTONE, RecordData::Tombstone(0));
        assert_eq!(never.data_text().unwrap(), "0");
    }

    #[test]
    fn hours() {
        let date = hours_to_utc(3_732_254).unwrap().unwrap();
        assert_eq!(utc_to_hours(date), 3_732_254);
        assert_eq!(hours_to_utc(0), Ok(None));
    }
}

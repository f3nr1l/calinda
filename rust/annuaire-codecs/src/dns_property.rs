// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Settings of an AD-integrated DNS zone: values of `dNSProperty` (MS-DNSP 2.3.2.1).
//!
//! One value per setting, little-endian:
//!
//! ```text
//! DataLength (4)  NameLength (4)  Flag (4)  Version (4, = 1)  Id (4)  Data (DataLength)
//! Name (rest, unused)
//! ```
//!
//! MS-DNSP gives `Name` one byte; Samba writes four (`uint32`), all zero. What follows the
//! data is kept as is (`tail`), so that a value read then encoded gives the same bytes
//! whatever its form. The data is not interpreted when decoding: `value` does it on demand
//! for the integer settings, and an unknown id stays readable as raw bytes.
//!
//! `ZoneSettings` sums up the settings of a zone for display. A zone without `dNSProperty`
//! (`_msdcs` with Samba) has the defaults of the server, which the directory does not tell:
//! they stay unknown (`None`).

use std::fmt;

use crate::read::{bytes_at, le_u32};

pub const VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 20;
/// The `Name` field as Samba writes it.
pub const SAMBA_TAIL: [u8; 4] = [0; 4];

// Ids (MS-DNSP 2.3.2.1.1, `DSPROPERTY_ZONE_*`).
pub const TYPE: u32 = 0x01;
pub const ALLOW_UPDATE: u32 = 0x02;
pub const SECURE_TIME: u32 = 0x08;
pub const NOREFRESH_INTERVAL: u32 = 0x10;
pub const SCAVENGING_SERVERS: u32 = 0x11;
pub const AGING_ENABLED_TIME: u32 = 0x12;
pub const REFRESH_INTERVAL: u32 = 0x20;
pub const AGING_STATE: u32 = 0x40;
pub const DELETED_FROM_HOSTNAME: u32 = 0x80;
pub const MASTER_SERVERS: u32 = 0x81;
pub const AUTO_NS_SERVERS: u32 = 0x82;
pub const DCPROMO_CONVERT: u32 = 0x83;
pub const SCAVENGING_SERVERS_DA: u32 = 0x90;
pub const MASTER_SERVERS_DA: u32 = 0x91;
pub const NS_SERVERS_DA: u32 = 0x92;
pub const NODE_DBFLAGS: u32 = 0x100;

const NAMES: &[(u32, &str)] = &[
    (TYPE, "TYPE"),
    (ALLOW_UPDATE, "ALLOW_UPDATE"),
    (SECURE_TIME, "SECURE_TIME"),
    (NOREFRESH_INTERVAL, "NOREFRESH_INTERVAL"),
    (SCAVENGING_SERVERS, "SCAVENGING_SERVERS"),
    (AGING_ENABLED_TIME, "AGING_ENABLED_TIME"),
    (REFRESH_INTERVAL, "REFRESH_INTERVAL"),
    (AGING_STATE, "AGING_STATE"),
    (DELETED_FROM_HOSTNAME, "DELETED_FROM_HOSTNAME"),
    (MASTER_SERVERS, "MASTER_SERVERS"),
    (AUTO_NS_SERVERS, "AUTO_NS_SERVERS"),
    (DCPROMO_CONVERT, "DCPROMO_CONVERT"),
    (SCAVENGING_SERVERS_DA, "SCAVENGING_SERVERS_DA"),
    (MASTER_SERVERS_DA, "MASTER_SERVERS_DA"),
    (NS_SERVERS_DA, "NS_SERVERS_DA"),
    (NODE_DBFLAGS, "NODE_DBFLAGS"),
];

/// Settings whose data is a little-endian integer (1, 2, 4 or 8 bytes).
const INTEGERS: [u32; 9] = [
    TYPE,
    ALLOW_UPDATE,
    SECURE_TIME,
    NOREFRESH_INTERVAL,
    AGING_ENABLED_TIME,
    REFRESH_INTERVAL,
    AGING_STATE,
    DCPROMO_CONVERT,
    NODE_DBFLAGS,
];

/// Settings summed up by `ZoneSettings`.
const SUMMED_UP: [u32; 6] = [
    TYPE,
    ALLOW_UPDATE,
    AGING_STATE,
    NOREFRESH_INTERVAL,
    REFRESH_INTERVAL,
    AGING_ENABLED_TIME,
];

/// Why a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyError {
    /// Fewer than 20 bytes.
    ShortHeader(usize),
    /// Announced data longer than the bytes after the header.
    Truncated { announced: u32, received: usize },
    /// Data longer than 2^32 - 1 bytes, or integer that does not fit its size.
    TooLong,
}

impl fmt::Display for PropertyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShortHeader(n) => write!(f, "dNSProperty of {n} bytes, header of {HEADER_SIZE}"),
            Self::Truncated {
                announced,
                received,
            } => write!(
                f,
                "dNSProperty: {announced} bytes announced, {received} received"
            ),
            Self::TooLong => write!(f, "dNSProperty data too long"),
        }
    }
}

impl std::error::Error for PropertyError {}

/// Name of an id (`ALLOW_UPDATE`…), `0x…` for an unknown one.
pub fn id_name(id: u32) -> String {
    NAMES
        .iter()
        .find(|(i, _)| *i == id)
        .map_or_else(|| format!("0x{id:x}"), |(_, n)| (*n).to_owned())
}

/// Value of a setting: integer for the numeric settings of known size, raw bytes otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    Integer(u64),
    Bytes(Vec<u8>),
}

/// One `dNSProperty` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneProperty {
    pub id: u32,
    pub data: Vec<u8>,
    pub flag: u32,
    pub version: u32,
    pub name_length: u32,
    /// Bytes after the data (field `Name`), kept as is.
    pub tail: Vec<u8>,
}

impl ZoneProperty {
    /// A setting with the defaults of the Python model (version 1, Samba's tail).
    pub fn new(id: u32, data: Vec<u8>) -> Self {
        Self {
            id,
            data,
            flag: 0,
            version: VERSION,
            name_length: 0,
            tail: SAMBA_TAIL.to_vec(),
        }
    }

    /// Integer setting in the form Samba writes (ALLOW_UPDATE on 1 byte, SECURE_TIME on 8,
    /// the others on 4), or on `size` bytes.
    pub fn integer(id: u32, value: u64, size: Option<usize>) -> Result<Self, PropertyError> {
        let size = size.unwrap_or(match id {
            ALLOW_UPDATE => 1,
            SECURE_TIME => 8,
            _ => 4,
        });
        let bytes = value.to_le_bytes();
        let (data, rest) = bytes
            .split_at_checked(size.min(8))
            .ok_or(PropertyError::TooLong)?;
        if rest.iter().any(|&b| b != 0) {
            return Err(PropertyError::TooLong);
        }
        let mut data = data.to_vec();
        data.resize(size, 0);
        Ok(Self::new(id, data))
    }

    pub fn name(&self) -> String {
        id_name(self.id)
    }

    /// Integer for the numeric settings of known size, raw bytes otherwise.
    pub fn value(&self) -> PropertyValue {
        if INTEGERS.contains(&self.id) && matches!(self.data.len(), 1 | 2 | 4 | 8) {
            let mut bytes = [0; 8];
            for (b, d) in bytes.iter_mut().zip(&self.data) {
                *b = *d;
            }
            PropertyValue::Integer(u64::from_le_bytes(bytes))
        } else {
            PropertyValue::Bytes(self.data.clone())
        }
    }

    /// Value of `dNSProperty` → setting; an error if the header or the announced length do
    /// not fit in the bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PropertyError> {
        let short = || PropertyError::ShortHeader(bytes.len());
        let length = le_u32(bytes, 0).ok_or_else(short)?;
        let name_length = le_u32(bytes, 4).ok_or_else(short)?;
        let flag = le_u32(bytes, 8).ok_or_else(short)?;
        let version = le_u32(bytes, 12).ok_or_else(short)?;
        let id = le_u32(bytes, 16).ok_or_else(short)?;
        let truncated = || PropertyError::Truncated {
            announced: length,
            received: bytes.len().saturating_sub(HEADER_SIZE),
        };
        let size = usize::try_from(length).map_err(|_| truncated())?;
        let data = bytes_at(bytes, HEADER_SIZE, size).ok_or_else(truncated)?;
        Ok(Self {
            id,
            data: data.to_vec(),
            flag,
            version,
            name_length,
            tail: bytes.get(HEADER_SIZE + size..).unwrap_or_default().to_vec(),
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, PropertyError> {
        let length = u32::try_from(self.data.len()).map_err(|_| PropertyError::TooLong)?;
        let mut out = Vec::with_capacity(HEADER_SIZE + self.data.len() + self.tail.len());
        for n in [length, self.name_length, self.flag, self.version, self.id] {
            out.extend_from_slice(&n.to_le_bytes());
        }
        out.extend_from_slice(&self.data);
        out.extend_from_slice(&self.tail);
        Ok(out)
    }
}

/// `DNS_ZONE_TYPE_*` (MS-DNSP 2.2.5.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZoneType {
    Cache = 0,
    Primary = 1,
    Secondary = 2,
    Stub = 3,
    Forwarder = 4,
    SecondaryCache = 5,
}

/// `fAllowUpdate` (MS-DNSP 2.2.6.1.1, `DNS_ZONE_UPDATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicUpdate {
    None = 0,
    /// Non-secure **and** secure.
    NonSecure = 1,
    Secure = 2,
}

/// A known value of an enumeration, or the raw integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Known<T> {
    Known(T),
    Other(u64),
}

impl ZoneType {
    fn from_value(v: u64) -> Known<Self> {
        match v {
            0 => Known::Known(Self::Cache),
            1 => Known::Known(Self::Primary),
            2 => Known::Known(Self::Secondary),
            3 => Known::Known(Self::Stub),
            4 => Known::Known(Self::Forwarder),
            5 => Known::Known(Self::SecondaryCache),
            _ => Known::Other(v),
        }
    }
}

impl DynamicUpdate {
    fn from_value(v: u64) -> Known<Self> {
        match v {
            0 => Known::Known(Self::None),
            1 => Known::Known(Self::NonSecure),
            2 => Known::Known(Self::Secure),
            _ => Known::Other(v),
        }
    }
}

/// Settings of a zone as its `dNSProperty` values give them; `None` when absent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ZoneSettings {
    pub zone_type: Option<Known<ZoneType>>,
    pub dynamic_update: Option<Known<DynamicUpdate>>,
    pub aging: Option<bool>,
    /// No-refresh interval (hours).
    pub no_refresh_interval: Option<u64>,
    /// Refresh interval (hours).
    pub refresh_interval: Option<u64>,
    /// Hours since 1601 from which scavenging is allowed (0: no date).
    pub aging_enabled_time: Option<u64>,
    /// Settings not summed up here (unknown ones included), kept.
    pub others: Vec<ZoneProperty>,
    /// Values whose header does not read.
    pub unreadable: usize,
}

impl ZoneSettings {
    /// Summary of the `dNSProperty` values of a zone; an unreadable value is counted, never
    /// an error. For an id present twice, the last value wins.
    pub fn from_values<'a>(values: impl IntoIterator<Item = &'a [u8]>) -> Self {
        let mut settings = Self::default();
        let mut integers: Vec<(u32, u64)> = Vec::new();
        for bytes in values {
            let Ok(p) = ZoneProperty::decode(bytes) else {
                settings.unreadable += 1;
                continue;
            };
            match p.value() {
                PropertyValue::Integer(v) if SUMMED_UP.contains(&p.id) => {
                    integers.retain(|(id, _)| *id != p.id);
                    integers.push((p.id, v));
                }
                _ => settings.others.push(p),
            }
        }
        let get = |id| integers.iter().find(|(i, _)| *i == id).map(|(_, v)| *v);
        settings.zone_type = get(TYPE).map(ZoneType::from_value);
        settings.dynamic_update = get(ALLOW_UPDATE).map(DynamicUpdate::from_value);
        settings.aging = get(AGING_STATE).map(|v| v != 0);
        settings.no_refresh_interval = get(NOREFRESH_INTERVAL);
        settings.refresh_interval = get(REFRESH_INTERVAL);
        settings.aging_enabled_time = get(AGING_ENABLED_TIME);
        settings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_summary() {
        let allow = ZoneProperty::integer(ALLOW_UPDATE, 2, None).unwrap();
        let bytes = allow.encode().unwrap();
        assert_eq!(bytes.len(), HEADER_SIZE + 1 + 4);
        assert_eq!(ZoneProperty::decode(&bytes).unwrap(), allow);
        let aging = ZoneProperty::integer(AGING_STATE, 1, None)
            .unwrap()
            .encode()
            .unwrap();
        let unknown = ZoneProperty::new(0x77, vec![1, 2, 3]).encode().unwrap();
        let s = ZoneSettings::from_values([&bytes[..], &aging, &unknown, &[0u8; 3][..]]);
        assert_eq!(s.dynamic_update, Some(Known::Known(DynamicUpdate::Secure)));
        assert_eq!(s.aging, Some(true));
        assert_eq!(s.zone_type, None);
        assert_eq!(s.others.len(), 1);
        assert_eq!(s.unreadable, 1);
        assert!(ZoneProperty::integer(ALLOW_UPDATE, 256, None).is_err());
    }
}

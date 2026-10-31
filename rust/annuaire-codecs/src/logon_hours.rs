// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Logon hours of an account (`logonHours`, MS-ADTS 2.2.18 and MS-SAMR 2.2.7.5): 21 bytes, one
//! bit per hour of the week, **in UTC**. Bit 0 of byte 0 is Sunday from 00:00 to 01:00 UTC,
//! bit 1 the next hour, and so on: hour `h` of the week (0 to 167) is bit `h % 8` of byte
//! `h / 8`. A set bit allows the logon. The attribute absent allows every hour; ADUC writes
//! 21 bytes `0xFF` once the grid has been opened and confirmed.
//!
//! ADUC shows the grid in local time: hour `h` of the local week is hour `h - offset` of the
//! UTC week, the offset being that of the local time zone in whole hours (a zone with half
//! hours is rounded toward zero, as the grid has only whole hours).

use std::fmt;

/// Bytes of the attribute.
pub const LEN: usize = 21;
/// Hours in a week.
pub const HOURS: usize = 168;

/// Why a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogonHoursError {
    /// Not 21 bytes.
    Length(usize),
}

impl fmt::Display for LogonHoursError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length(n) => write!(f, "logonHours: 21 bytes expected, {n} read"),
        }
    }
}

impl std::error::Error for LogonHoursError {}

/// The hours of a week in UTC, `true` where the logon is allowed; index 0 is Sunday
/// 00:00 UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LogonHours(pub [bool; HOURS]);

impl Default for LogonHours {
    /// Every hour allowed (the attribute absent).
    fn default() -> Self {
        Self([true; HOURS])
    }
}

impl LogonHours {
    /// No hour allowed.
    pub fn none() -> Self {
        Self([false; HOURS])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, LogonHoursError> {
        if bytes.len() != LEN {
            return Err(LogonHoursError::Length(bytes.len()));
        }
        let mut hours = [false; HOURS];
        for (h, slot) in hours.iter_mut().enumerate() {
            *slot = bytes.get(h / 8).is_some_and(|b| b & (1 << (h % 8)) != 0);
        }
        Ok(Self(hours))
    }

    /// The value of the attribute, absent read as every hour allowed.
    pub fn from_attribute(values: &[Vec<u8>]) -> Result<Self, LogonHoursError> {
        match values.first() {
            None => Ok(Self::default()),
            Some(bytes) => Self::decode(bytes),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = vec![0u8; LEN];
        for (h, allowed) in self.0.iter().enumerate() {
            if *allowed && let Some(byte) = bytes.get_mut(h / 8) {
                *byte |= 1 << (h % 8);
            }
        }
        bytes
    }

    /// Every hour allowed.
    pub fn all_allowed(&self) -> bool {
        self.0.iter().all(|&a| a)
    }

    /// Number of hours allowed in the week.
    pub fn allowed(&self) -> usize {
        self.0.iter().filter(|&&a| a).count()
    }

    /// Hour of the UTC week that is local hour `hour` of local day `day` (0 Sunday to 6
    /// Saturday), the local time being `offset` hours ahead of UTC (negative west of
    /// Greenwich).
    pub fn utc_index(day: usize, hour: usize, offset: i32) -> usize {
        let local = i64::try_from(day * 24 + hour).unwrap_or(0);
        let utc = (local - i64::from(offset)).rem_euclid(HOURS as i64);
        usize::try_from(utc).unwrap_or(0)
    }

    /// Allowed at local hour `hour` of local day `day` (0 Sunday).
    pub fn local(&self, day: usize, hour: usize, offset: i32) -> bool {
        self.0
            .get(Self::utc_index(day, hour, offset))
            .copied()
            .unwrap_or(false)
    }

    /// Sets local hour `hour` of local day `day` (0 Sunday).
    pub fn set_local(&mut self, day: usize, hour: usize, offset: i32, allowed: bool) {
        if let Some(slot) = self.0.get_mut(Self::utc_index(day, hour, offset)) {
            *slot = allowed;
        }
    }

    /// The local grid: seven days from Sunday, 24 hours each.
    pub fn local_grid(&self, offset: i32) -> [[bool; 24]; 7] {
        let mut grid = [[false; 24]; 7];
        for (day, row) in grid.iter_mut().enumerate() {
            for (hour, cell) in row.iter_mut().enumerate() {
                *cell = self.local(day, hour, offset);
            }
        }
        grid
    }

    /// From a local grid (seven days from Sunday).
    pub fn from_local_grid(grid: &[[bool; 24]; 7], offset: i32) -> Self {
        let mut hours = Self::none();
        for (day, row) in grid.iter().enumerate() {
            for (hour, allowed) in row.iter().enumerate() {
                hours.set_local(day, hour, offset, *allowed);
            }
        }
        hours
    }
}

/// Offset in whole hours of a time zone `seconds` ahead of UTC, rounded toward zero.
pub fn offset_hours(seconds: i64) -> i32 {
    i32::try_from(seconds / 3600).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_in_order() {
        let mut bytes = vec![0u8; LEN];
        bytes[0] = 0b0000_0001; // Sunday 00:00 UTC
        bytes[1] = 0b0000_0010; // Sunday 09:00 UTC
        bytes[20] = 0b1000_0000; // Saturday 23:00 UTC
        let hours = LogonHours::decode(&bytes).unwrap();
        assert_eq!(hours.allowed(), 3);
        assert!(hours.0[0] && hours.0[9] && hours.0[167]);
        assert_eq!(hours.encode(), bytes);
        assert_eq!(
            LogonHours::decode(&[0; 20]),
            Err(LogonHoursError::Length(20))
        );
        assert!(LogonHours::from_attribute(&[]).unwrap().all_allowed());
        assert_eq!(LogonHours::default().encode(), vec![0xFF; LEN]);
    }

    #[test]
    fn local_time() {
        // Martinique, UTC-4: Monday 08:00 local is Monday 12:00 UTC.
        assert_eq!(LogonHours::utc_index(1, 8, -4), 24 + 12);
        // Sunday 22:00 local is Monday 02:00 UTC; Sunday 01:00 in UTC+2 is Saturday 23:00.
        assert_eq!(LogonHours::utc_index(0, 22, -4), 26);
        assert_eq!(LogonHours::utc_index(0, 1, 2), 167);
        // Monday to Friday, 08:00 to 18:00 local, read back the same.
        let mut grid = [[false; 24]; 7];
        for row in grid.iter_mut().skip(1).take(5) {
            for cell in row.iter_mut().skip(8).take(10) {
                *cell = true;
            }
        }
        let hours = LogonHours::from_local_grid(&grid, -4);
        assert_eq!(hours.allowed(), 50);
        assert_eq!(hours.local_grid(-4), grid);
        assert!(hours.0[24 + 12] && !hours.0[24 + 11]);
        assert_eq!(offset_hours(-4 * 3600), -4);
        assert_eq!(offset_hours(5 * 3600 + 1800), 5);
        assert_eq!(offset_hours(-(3 * 3600 + 1800)), -3);
    }
}

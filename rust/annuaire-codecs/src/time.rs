// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Times of Active Directory: FILETIME (dates), negative durations, GeneralizedTime.
//!
//! - **Date** (`pwdLastSet`, `lastLogonTimestamp`, `accountExpires`, `lockoutTime`…): 64-bit
//!   integer, hundreds of nanoseconds since 1601-01-01 UTC (FILETIME, MS-DTYP 2.3.3). 0 and
//!   `0x7FFFFFFFFFFFFFFF` are not dates: "never" for `accountExpires` (MS-ADA1), "change
//!   required" for `pwdLastSet` 0. The meaning belongs to the model; here these two values
//!   simply have no date.
//! - **Duration** (`maxPwdAge`, `minPwdAge`, `lockoutDuration`, `lockOutObservationWindow`,
//!   `forceLogoff`): 64-bit integer, **negative or zero**, in hundreds of nanoseconds;
//!   -2^63 means "never" (no limit).
//! - **GeneralizedTime** (`whenCreated`, `whenChanged`): text `YYYYMMDDhhmmss.0Z`.
//!
//! Dates are UTC, years 1 to 9999 (the range of Python's `datetime`), with a resolution of
//! 100 ns: no truncation to the microsecond, unlike Python.

use std::fmt;

/// Hundreds of nanoseconds per second.
pub const TICKS_PER_SECOND: i64 = 10_000_000;
/// Seconds between 1601-01-01 and 1970-01-01.
pub const UNIX_OFFSET: i64 = 11_644_473_600;
/// FILETIME "never" (`accountExpires` of an account never set).
pub const NTTIME_NEVER: i64 = i64::MAX;
/// Duration "never" (no limit).
pub const DURATION_NEVER: i64 = i64::MIN;

const SECONDS_PER_DAY: i64 = 86_400;
/// Days from 0001-01-01 to 1601-01-01.
const DAYS_TO_1601: i64 = 584_388;
/// Days from 0001-01-01 to 10000-01-01: first day out of range.
const DAYS_TO_10000: i64 = 3_652_059;

/// Why a time was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeError {
    /// FILETIME outside 0..=0x7FFFFFFFFFFFFFFF.
    NtTimeOutOfRange(i64),
    /// FILETIME after 9999-12-31.
    BeyondYear9999(i64),
    /// 1601-01-01T00:00:00Z is FILETIME 0, which means "never".
    DateIsNever,
    /// Date before 1601, or arithmetic out of the 64-bit range.
    OutOfRange,
    /// Duration that is positive (or out of range).
    InvalidDuration(i64),
    /// Negative number of seconds for a duration.
    NegativeSeconds(i64),
    /// Text not of the GeneralizedTime form.
    MalformedGeneralizedTime(String),
    /// GeneralizedTime with an impossible date, or out of the years 1 to 9999.
    InvalidGeneralizedTime(String),
    /// Fields that do not make a date.
    InvalidDate,
}

impl fmt::Display for TimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NtTimeOutOfRange(v) => write!(f, "FILETIME out of range: {v}"),
            Self::BeyondYear9999(v) => write!(f, "FILETIME beyond the year 9999: {v}"),
            Self::DateIsNever => write!(f, "the date 1601-01-01T00:00:00Z is the same as never"),
            Self::OutOfRange => write!(f, "date out of the FILETIME range"),
            Self::InvalidDuration(v) => {
                write!(f, "invalid AD duration (must be negative or zero): {v}")
            }
            Self::NegativeSeconds(v) => write!(f, "negative duration: {v} s"),
            Self::MalformedGeneralizedTime(t) => write!(f, "malformed GeneralizedTime: {t:?}"),
            Self::InvalidGeneralizedTime(t) => write!(f, "invalid GeneralizedTime: {t:?}"),
            Self::InvalidDate => write!(f, "invalid date"),
        }
    }
}

impl std::error::Error for TimeError {}

/// An instant in UTC, years 1 to 9999, resolution 100 ns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UtcTime {
    /// Hundreds of nanoseconds since 0001-01-01T00:00:00Z.
    ticks: i64,
}

/// The fields of a `UtcTime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Civil {
    pub year: i32,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    /// Hundreds of nanoseconds within the second, 0 to 9 999 999.
    pub fraction: u32,
}

/// Days from 0000-03-01 (proleptic Gregorian), H. Hinnant's `days_from_civil`.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `days_from_civil(1, 1, 1)`: day 0 of `UtcTime`.
const EPOCH_DAYS: i64 = 306;

/// 1601-01-01T00:00:00Z, origin of FILETIME and of the DNS timestamps.
pub const NT_EPOCH: UtcTime = UtcTime {
    ticks: DAYS_TO_1601 * SECONDS_PER_DAY * TICKS_PER_SECOND,
};

impl UtcTime {
    /// From its fields; `InvalidDate` for an impossible date or a year out of 1 to 9999.
    pub fn from_civil(c: Civil) -> Result<Self, TimeError> {
        let (year, month, day) = (i64::from(c.year), i64::from(c.month), i64::from(c.day));
        let valid = (1..=9999).contains(&year)
            && (1..=12).contains(&month)
            && day >= 1
            && day <= days_in_month(year, month)
            && c.hour < 24
            && c.minute < 60
            && c.second < 60
            && i64::from(c.fraction) < TICKS_PER_SECOND;
        if !valid {
            return Err(TimeError::InvalidDate);
        }
        let days = days_from_civil(year, month, day) - EPOCH_DAYS;
        let seconds = days * SECONDS_PER_DAY
            + i64::from(c.hour) * 3600
            + i64::from(c.minute) * 60
            + i64::from(c.second);
        Ok(Self {
            ticks: seconds * TICKS_PER_SECOND + i64::from(c.fraction),
        })
    }

    /// From ticks since 0001-01-01; `None` out of the years 1 to 9999.
    fn from_ticks(ticks: i64) -> Option<Self> {
        (0..DAYS_TO_10000 * SECONDS_PER_DAY * TICKS_PER_SECOND)
            .contains(&ticks)
            .then_some(Self { ticks })
    }

    pub fn civil(&self) -> Civil {
        let seconds = self.ticks.div_euclid(TICKS_PER_SECOND);
        let fraction = self.ticks.rem_euclid(TICKS_PER_SECOND);
        let days = seconds.div_euclid(SECONDS_PER_DAY);
        let in_day = seconds.rem_euclid(SECONDS_PER_DAY);
        let (year, month, day) = civil_from_days(days + EPOCH_DAYS);
        // All in range: ticks are within the years 1 to 9999.
        Civil {
            year: year as i32,
            month: month as u8,
            day: day as u8,
            hour: (in_day / 3600) as u8,
            minute: (in_day / 60 % 60) as u8,
            second: (in_day % 60) as u8,
            fraction: fraction as u32,
        }
    }

    /// Seconds since 1970-01-01 (floored).
    pub fn unix_seconds(&self) -> i64 {
        self.ticks.div_euclid(TICKS_PER_SECOND) - (DAYS_TO_1601 * SECONDS_PER_DAY + UNIX_OFFSET)
    }

    /// Whole seconds from `earlier` to `self` (floored).
    pub fn seconds_since(&self, earlier: Self) -> i64 {
        (self.ticks - earlier.ticks).div_euclid(TICKS_PER_SECOND)
    }

    /// The same instant shifted by `seconds` (positive or negative); `None` out of range.
    pub fn add_seconds(&self, seconds: i64) -> Option<Self> {
        seconds
            .checked_mul(TICKS_PER_SECOND)
            .and_then(|t| self.ticks.checked_add(t))
            .and_then(Self::from_ticks)
    }
}

// --- FILETIME dates -----------------------------------------------------------------------

fn check_nttime(nttime: i64) -> Result<(), TimeError> {
    if nttime < 0 {
        Err(TimeError::NtTimeOutOfRange(nttime))
    } else {
        Ok(())
    }
}

/// True if the value carries no date (0 or `0x7FFFFFFFFFFFFFFF`).
pub fn is_never(nttime: i64) -> Result<bool, TimeError> {
    check_nttime(nttime)?;
    Ok(nttime == 0 || nttime == NTTIME_NEVER)
}

/// UTC date, or `None` for "never"; `BeyondYear9999` after 9999-12-31.
pub fn nttime_to_utc(nttime: i64) -> Result<Option<UtcTime>, TimeError> {
    if is_never(nttime)? {
        return Ok(None);
    }
    nttime
        .checked_add(NT_EPOCH.ticks)
        .and_then(UtcTime::from_ticks)
        .map(Some)
        .ok_or(TimeError::BeyondYear9999(nttime))
}

/// ISO 8601 UTC with 7 decimals (`2026-10-13T10:14:33.4609680Z`), or `None`.
pub fn nttime_to_iso(nttime: i64) -> Result<Option<String>, TimeError> {
    Ok(nttime_to_utc(nttime)?.map(|t| {
        let c = t.civil();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:07}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second, c.fraction
        )
    }))
}

/// Unix seconds, rounded to the nearest second (like `nttime2unix` of Samba), or `None`.
pub fn nttime_to_unix(nttime: i64) -> Result<Option<i64>, TimeError> {
    if is_never(nttime)? {
        return Ok(None);
    }
    // Rounded half up, without overflow near 2^63.
    let rounded =
        nttime / TICKS_PER_SECOND + i64::from(nttime % TICKS_PER_SECOND >= TICKS_PER_SECOND / 2);
    Ok(Some(rounded - UNIX_OFFSET))
}

/// FILETIME of a date; 1601-01-01T00:00:00Z and earlier dates are refused.
pub fn utc_to_nttime(time: UtcTime) -> Result<i64, TimeError> {
    let nttime = time.ticks - NT_EPOCH.ticks;
    check_nttime(nttime).map_err(|_| TimeError::OutOfRange)?;
    if nttime == 0 {
        return Err(TimeError::DateIsNever);
    }
    Ok(nttime)
}

/// FILETIME of a Unix timestamp.
pub fn unix_to_nttime(seconds: i64) -> Result<i64, TimeError> {
    let nttime = seconds
        .checked_add(UNIX_OFFSET)
        .and_then(|s| s.checked_mul(TICKS_PER_SECOND))
        .ok_or(TimeError::OutOfRange)?;
    check_nttime(nttime)?;
    Ok(nttime)
}

// --- Durations -----------------------------------------------------------------------------

fn check_duration(ticks: i64) -> Result<(), TimeError> {
    if ticks > 0 {
        Err(TimeError::InvalidDuration(ticks))
    } else {
        Ok(())
    }
}

/// True for -2^63 (`forceLogoff`, `maxPwdAge`… without limit).
pub fn duration_is_never(ticks: i64) -> Result<bool, TimeError> {
    check_duration(ticks)?;
    Ok(ticks == DURATION_NEVER)
}

/// Duration in whole seconds (positive), or `None` for "never".
pub fn duration_to_seconds(ticks: i64) -> Result<Option<i64>, TimeError> {
    if duration_is_never(ticks)? {
        return Ok(None);
    }
    Ok(Some(-ticks / TICKS_PER_SECOND))
}

/// Duration in whole microseconds (positive), or `None` for "never".
pub fn duration_to_micros(ticks: i64) -> Result<Option<i64>, TimeError> {
    if duration_is_never(ticks)? {
        return Ok(None);
    }
    Ok(Some(-ticks / 10))
}

/// Value to store for a duration of `seconds` (positive or zero).
pub fn seconds_to_duration(seconds: i64) -> Result<i64, TimeError> {
    if seconds < 0 {
        return Err(TimeError::NegativeSeconds(seconds));
    }
    // -2^63 is not a multiple of 10^7: a valid duration is never "never".
    seconds
        .checked_mul(-TICKS_PER_SECOND)
        .ok_or(TimeError::InvalidDuration(i64::MIN))
}

// --- GeneralizedTime ------------------------------------------------------------------------

/// Parses a GeneralizedTime (RFC 4517 § 3.3.13) with seconds; the fraction is kept to the
/// microsecond (truncated), as Python does.
pub fn decode_generalized_time(text: &str) -> Result<UtcTime, TimeError> {
    let malformed = || TimeError::MalformedGeneralizedTime(text.to_owned());
    let invalid = || TimeError::InvalidGeneralizedTime(text.to_owned());
    let bytes = text.as_bytes();
    let (head, rest) = bytes.split_at_checked(14).ok_or_else(malformed)?;
    if !head.iter().all(u8::is_ascii_digit) {
        return Err(malformed());
    }
    let number = |range: std::ops::Range<usize>| -> i64 {
        head.get(range)
            .unwrap_or_default()
            .iter()
            .fold(0, |acc, b| acc * 10 + i64::from(b - b'0'))
    };
    // The zone: `Z` or `+hhmm` / `-hhmm` at the end.
    let (body, offset) = match rest {
        [body @ .., b'Z'] => (body, 0),
        [body @ .., sign @ (b'+' | b'-'), h1, h2, m1, m2]
            if [h1, h2, m1, m2].iter().all(|b| b.is_ascii_digit()) =>
        {
            let hours = i64::from(h1 - b'0') * 10 + i64::from(h2 - b'0');
            let minutes = i64::from(m1 - b'0') * 10 + i64::from(m2 - b'0');
            let offset = hours * 3600 + minutes * 60;
            (body, if *sign == b'+' { offset } else { -offset })
        }
        _ => return Err(malformed()),
    };
    // The fraction: nothing, or `.` / `,` and at least one digit.
    let micros = match body {
        [] => 0,
        [b'.' | b',', digits @ ..]
            if !digits.is_empty() && digits.iter().all(u8::is_ascii_digit) =>
        {
            digits
                .iter()
                .chain(std::iter::repeat(&b'0'))
                .take(6)
                .fold(0, |acc, b| acc * 10 + u32::from(b - b'0'))
        }
        _ => return Err(malformed()),
    };
    let civil = Civil {
        year: i32::try_from(number(0..4)).map_err(|_| invalid())?,
        month: u8::try_from(number(4..6)).map_err(|_| invalid())?,
        day: u8::try_from(number(6..8)).map_err(|_| invalid())?,
        hour: u8::try_from(number(8..10)).map_err(|_| invalid())?,
        minute: u8::try_from(number(10..12)).map_err(|_| invalid())?,
        second: u8::try_from(number(12..14)).map_err(|_| invalid())?,
        fraction: micros * 10,
    };
    let local = UtcTime::from_civil(civil).map_err(|_| invalid())?;
    local.add_seconds(-offset).ok_or_else(invalid)
}

/// The form written by AD: `YYYYMMDDhhmmss.0Z`, to the second, in UTC.
pub fn encode_generalized_time(time: UtcTime) -> String {
    let c = time.civil();
    format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}.0Z",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn civil(year: i32, month: u8, day: u8) -> Civil {
        Civil {
            year,
            month,
            day,
            hour: 0,
            minute: 0,
            second: 0,
            fraction: 0,
        }
    }

    #[test]
    fn epochs() {
        let t1601 = UtcTime::from_civil(civil(1601, 1, 1)).unwrap();
        assert_eq!(
            t1601.ticks,
            DAYS_TO_1601 * SECONDS_PER_DAY * TICKS_PER_SECOND
        );
        let t1970 = UtcTime::from_civil(civil(1970, 1, 1)).unwrap();
        assert_eq!(t1970.unix_seconds(), 0);
        let last = UtcTime::from_civil(civil(9999, 12, 31)).unwrap();
        assert!(last.add_seconds(SECONDS_PER_DAY).is_none());
        assert!(UtcTime::from_civil(civil(10000, 1, 1)).is_err());
        assert!(UtcTime::from_civil(civil(0, 1, 1)).is_err());
        assert!(UtcTime::from_civil(civil(2023, 2, 29)).is_err());
        assert!(UtcTime::from_civil(civil(2024, 2, 29)).is_ok());
        assert_eq!(UtcTime::from_civil(civil(1, 1, 1)).unwrap().ticks, 0);
    }

    #[test]
    fn round_trip_of_days() {
        for days in (0..DAYS_TO_10000).step_by(997) {
            let t = UtcTime::from_ticks(days * SECONDS_PER_DAY * TICKS_PER_SECOND).unwrap();
            assert_eq!(UtcTime::from_civil(t.civil()).unwrap(), t);
        }
    }

    #[test]
    fn nttime() {
        assert_eq!(nttime_to_iso(0), Ok(None));
        assert_eq!(nttime_to_iso(NTTIME_NEVER), Ok(None));
        assert!(is_never(-1).is_err());
        assert_eq!(
            nttime_to_iso(1).unwrap().unwrap(),
            "1601-01-01T00:00:00.0000001Z"
        );
        assert!(nttime_to_iso(NTTIME_NEVER - 1).is_err());
        assert_eq!(unix_to_nttime(0), Ok(UNIX_OFFSET * TICKS_PER_SECOND));
        assert_eq!(nttime_to_unix(NTTIME_NEVER - 1), Ok(Some(910_692_730_085)));
        assert_eq!(nttime_to_unix(5_000_000), Ok(Some(1 - UNIX_OFFSET)));
        assert_eq!(nttime_to_unix(4_999_999), Ok(Some(-UNIX_OFFSET)));
        assert!(unix_to_nttime(-UNIX_OFFSET - 1).is_err());
        let t1601 = UtcTime::from_civil(civil(1601, 1, 1)).unwrap();
        assert_eq!(utc_to_nttime(t1601), Err(TimeError::DateIsNever));
    }

    #[test]
    fn durations() {
        assert_eq!(duration_to_seconds(DURATION_NEVER), Ok(None));
        assert_eq!(
            duration_to_seconds(-36_288_000_000_000),
            Ok(Some(3_628_800))
        );
        assert!(duration_to_seconds(1).is_err());
        assert_eq!(seconds_to_duration(60), Ok(-600_000_000));
        assert!(seconds_to_duration(-1).is_err());
        assert!(seconds_to_duration(i64::MAX).is_err());
    }

    #[test]
    fn generalized_time() {
        let t = decode_generalized_time("20261013101433.0Z").unwrap();
        assert_eq!(encode_generalized_time(t), "20261013101433.0Z");
        let shifted = decode_generalized_time("20261013121433,5+0200").unwrap();
        assert_eq!(shifted.civil().fraction, 5_000_000);
        assert_eq!(shifted.add_seconds(0), Some(shifted));
        assert_eq!(encode_generalized_time(shifted), "20261013101433.0Z");
        for bad in [
            "20261013101433",
            "20261013101433.Z",
            "2026101310143Z",
            "20261013101460Z",
            "00000101000000Z",
            "00010101000000+0100",
            "20261013101433+02",
            "２0261013101433Z",
        ] {
            assert!(decode_generalized_time(bad).is_err(), "{bad}");
        }
        let early = decode_generalized_time("09990101000000Z").unwrap();
        assert_eq!(encode_generalized_time(early), "09990101000000.0Z");
    }
}

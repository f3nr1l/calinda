// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Reading of an input of the attribute editor (J4.4, `lire_saisie` of
//! `annuaire.core.syntaxes`): the LDAP value of a text, checked against the syntax of the
//! schema and its bounds (`rangeLower`, `rangeUpper`: length in characters of a string, in
//! bytes of a byte string, value of an integer). A refused input gives a message to show as
//! is. A date (large integer of `DATE_ATTRIBUTES`, generalized or UTC time) is also typed as
//! `DD/MM/YYYY hh:mm`, local time. The form to edit of a value is `schema::edit_text`.

use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::time::{self, Civil, UtcTime};
use annuaire_codecs::{Guid, Sid};
use annuaire_core::dn;
use annuaire_core::schema::{self, AttributeDescription, EDITABLE_SYNTAXES, PWD_LAST_SET, Syntax};
use gtk::glib;

use crate::attribute_views::syntax_label;
use crate::i18n::{fill, tr};

const PRINTABLE_EXTRA: &str = " '()+,-./:?=";
const NEVER: [&str; 2] = ["jamais", "never"];

fn length(description: &AttributeDescription, n: usize, unit: &str) -> Result<(), String> {
    let n = i64::try_from(n).unwrap_or(i64::MAX);
    if let Some(low) = description.lower.filter(|&low| n < low) {
        return Err(fill(
            &tr("At least {n} {unite} (rangeLower)."),
            &[("n", &low.to_string()), ("unite", unit)],
        ));
    }
    if let Some(high) = description.upper.filter(|&high| n > high) {
        return Err(fill(
            &tr("At most {n} {unite} (rangeUpper)."),
            &[("n", &high.to_string()), ("unite", unit)],
        ));
    }
    Ok(())
}

/// `_valeur_entiere`: decimal or `0x…`; the unsigned form (flags in hexadecimal) is brought
/// back to the sign.
fn integer_value(description: &AttributeDescription, text: &str) -> Result<i64, String> {
    let t: String = text
        .chars()
        .filter(|c| !matches!(c, ' ' | '\u{202f}' | '\u{a0}'))
        .collect();
    let lower = t.to_lowercase();
    let parsed = if let Some(hex) = lower.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else if let Some(hex) = lower.strip_prefix("-0x") {
        i128::from_str_radix(hex, 16).ok().map(|v| -v)
    } else {
        lower.parse::<i128>().ok()
    };
    let mut value = parsed.ok_or_else(|| tr("Integer expected."))?;
    let bits: u32 = if schema::width(description) == Width::Bits64 {
        64
    } else {
        32
    };
    let (full, half) = (1i128 << bits, 1i128 << (bits - 1));
    if (half..full).contains(&value) {
        value -= full;
    }
    if !(-half..half).contains(&value) {
        return Err(fill(
            &tr("Integer outside the {bits}-bit range."),
            &[("bits", &bits.to_string())],
        ));
    }
    let value = i64::try_from(value).map_err(|_| tr("Integer expected."))?;
    if let Some(low) = description.lower.filter(|&low| value < low) {
        return Err(fill(
            &tr("At least {n} (rangeLower)."),
            &[("n", &low.to_string())],
        ));
    }
    if let Some(high) = description.upper.filter(|&high| value > high) {
        return Err(fill(
            &tr("At most {n} (rangeUpper)."),
            &[("n", &high.to_string())],
        ));
    }
    Ok(value)
}

fn digits(text: &str, min: usize, max: usize) -> Option<i32> {
    (text.len() >= min && text.len() <= max && text.chars().all(|c| c.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

/// `DD/MM/YYYY [hh:mm[:ss]]`, local time, as Unix seconds; None if it is not the form
/// (`_date_locale`).
fn local_date(text: &str) -> Result<Option<i64>, String> {
    let (date, clock) = match text.split_once(char::is_whitespace) {
        Some((date, clock)) => (date, Some(clock.trim_start())),
        None => (text, None),
    };
    let parts: Vec<&str> = date.split('/').collect();
    let [day, month, year] = parts.as_slice() else {
        return Ok(None);
    };
    let (Some(day), Some(month), Some(year)) =
        (digits(day, 1, 2), digits(month, 1, 2), digits(year, 4, 4))
    else {
        return Ok(None);
    };
    let (mut hour, mut minute, mut second) = (0, 0, 0);
    if let Some(clock) = clock {
        let fields: Vec<&str> = clock.split(':').collect();
        let parsed = match fields.as_slice() {
            [h, m] => (digits(h, 1, 2), digits(m, 2, 2), Some(0)),
            [h, m, s] => (digits(h, 1, 2), digits(m, 2, 2), digits(s, 2, 2)),
            _ => return Ok(None),
        };
        let (Some(h), Some(m), Some(s)) = parsed else {
            return Ok(None);
        };
        (hour, minute, second) = (h, m, s);
    }
    let impossible = || tr("Impossible date.");
    if year < 1 || hour > 23 || minute > 59 || second > 59 {
        return Err(impossible());
    }
    glib::DateTime::from_local(year, month, day, hour, minute, f64::from(second))
        .map(|d| Some(d.to_unix()))
        .map_err(|_| impossible())
}

fn utc_of_unix(seconds: i64) -> Option<UtcTime> {
    time::nttime_to_utc(time::unix_to_nttime(seconds).ok()?)
        .ok()
        .flatten()
}

/// `AAMMJJhhmmssZ` (years 69 to 99 in the 1900s, as `strptime`).
fn utc_time(text: &str) -> Option<UtcTime> {
    let body = text.strip_suffix('Z')?;
    if body.len() != 12 || !body.is_ascii() {
        return None;
    }
    let field = |i: usize| -> Option<u8> { digits(body.get(i..i + 2)?, 2, 2)?.try_into().ok() };
    let short = i32::from(field(0)?);
    let civil = Civil {
        year: if short >= 69 {
            1900 + short
        } else {
            2000 + short
        },
        month: field(2)?,
        day: field(4)?,
        hour: field(6)?,
        minute: field(8)?,
        second: field(10)?,
        fraction: 0,
    };
    UtcTime::from_civil(civil).ok()
}

/// `_octets`: hexadecimal, separators and `0x` allowed.
fn bytes(text: &str) -> Result<Vec<u8>, String> {
    let error = || tr("Hexadecimal bytes expected (“01 a2 ff”).");
    let t: String = text
        .chars()
        .filter(|c| !(c.is_whitespace() || *c == ':' || *c == '-'))
        .collect();
    let t = if t.to_lowercase().starts_with("0x") {
        t.get(2..).unwrap_or("").to_owned()
    } else {
        t
    };
    if t.len() % 2 != 0 || !t.is_ascii() {
        return Err(error());
    }
    (0..t.len())
        .step_by(2)
        .map(|i| {
            t.get(i..i + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(error)
        })
        .collect()
}

/// `_dn`.
fn check_dn(text: &str) -> Result<(), String> {
    match dn::split(text) {
        Ok(components) if !components.is_empty() => Ok(()),
        _ => Err(tr("Distinguished name (DN) expected: “CN=…,OU=…,DC=…”.")),
    }
}

/// `[0-9]+(\.[0-9]+)+` or `[A-Za-z][A-Za-z0-9-]*`.
fn is_oid(text: &str) -> bool {
    let numeric = text.contains('.')
        && text
            .split('.')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()));
    let mut chars = text.chars();
    let name = chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '-');
    numeric || name
}

/// LDAP value of an input; a message if the syntax or the bounds refuse it. An empty input is
/// refused: clearing is removing the value (`lire_saisie`).
pub fn read_input(description: &AttributeDescription, text: &str) -> Result<Vec<u8>, String> {
    let syntax = description.syntax;
    if !EDITABLE_SYNTAXES.contains(&syntax) {
        return Err(fill(
            &tr("This syntax cannot be modified here ({syntaxe})."),
            &[("syntaxe", &syntax_label(syntax))],
        ));
    }
    let text = text.trim();
    if text.is_empty() {
        return Err(tr("Empty value: to clear it, remove the value."));
    }
    match syntax {
        Syntax::Boolean => match text.to_lowercase().as_str() {
            "true" | "vrai" | "oui" => Ok(b"TRUE".to_vec()),
            "false" | "faux" | "non" => Ok(b"FALSE".to_vec()),
            _ => Err(tr("TRUE or FALSE expected.")),
        },
        Syntax::Integer | Syntax::Enumeration | Syntax::LargeInteger => {
            if schema::is_date(description) {
                if NEVER.contains(&text.to_lowercase().as_str()) {
                    return Ok(time::NTTIME_NEVER.to_string().into_bytes());
                }
                if let Some(seconds) = local_date(text)? {
                    let nttime =
                        time::unix_to_nttime(seconds).map_err(|_| tr("Impossible date."))?;
                    return Ok(nttime.to_string().into_bytes());
                }
            }
            let value = integer_value(description, text)?;
            if description.name.to_lowercase() == PWD_LAST_SET && value != 0 && value != -1 {
                return Err(tr(
                    "pwdLastSet only accepts 0 (change required) or -1 (now).",
                ));
            }
            integer::encode(value, schema::width(description)).map_err(|_| tr("Integer expected."))
        }
        Syntax::GeneralizedTime | Syntax::UtcTime => {
            let utc = syntax == Syntax::UtcTime;
            let date = match local_date(text)? {
                Some(seconds) => utc_of_unix(seconds),
                None if utc => utc_time(text),
                None => time::decode_generalized_time(text).ok(),
            };
            let Some(date) = date else {
                return Err(fill(
                    &tr("Date expected: DD/MM/YYYY hh:mm (local time) or {forme}."),
                    &[(
                        "forme",
                        if utc {
                            "AAMMJJhhmmssZ"
                        } else {
                            "AAAAMMJJhhmmss.0Z"
                        },
                    )],
                ));
            };
            if utc {
                let c = date.civil();
                Ok(format!(
                    "{:02}{:02}{:02}{:02}{:02}{:02}Z",
                    c.year.rem_euclid(100),
                    c.month,
                    c.day,
                    c.hour,
                    c.minute,
                    c.second
                )
                .into_bytes())
            } else {
                Ok(time::encode_generalized_time(date).into_bytes())
            }
        }
        Syntax::Sid => text
            .parse::<Sid>()
            .map(|s| s.encode())
            .map_err(|_| tr("SID expected: “S-1-5-21-…”.")),
        Syntax::Octets => {
            let braceless = text.trim_matches(|c| c == '{' || c == '}');
            let value = if schema::is_guid(description)
                && text.contains('-')
                && braceless.chars().count() == 36
            {
                braceless
                    .parse::<Guid>()
                    .map(|g| g.encode())
                    .map_err(|_| tr("GUID expected: “01234567-89ab-cdef-0123-456789abcdef”."))?
            } else {
                bytes(text)?
            };
            length(description, value.len(), &tr("bytes"))?;
            Ok(value)
        }
        Syntax::Dn => {
            check_dn(text)?;
            Ok(text.as_bytes().to_vec())
        }
        Syntax::DnBinary => {
            let error = || tr("Expected form: “B:<number of digits>:<hexadecimal>:<DN>”.");
            let rest = text.strip_prefix("B:").ok_or_else(error)?;
            let (count, rest) = rest.split_once(':').ok_or_else(error)?;
            let (hex, target) = rest.split_once(':').ok_or_else(error)?;
            let count = digits(count, 1, usize::MAX).ok_or_else(error)?;
            if target.is_empty()
                || !hex.chars().all(|c| c.is_ascii_hexdigit())
                || usize::try_from(count).ok() != Some(hex.len())
                || hex.len() % 2 != 0
            {
                return Err(error());
            }
            check_dn(target)?;
            Ok(text.as_bytes().to_vec())
        }
        Syntax::DnString => {
            let error = || tr("Expected form: “S:<length>:<text>:<DN>”.");
            let rest = text.strip_prefix("S:").ok_or_else(error)?;
            let (count, rest) = rest.split_once(':').ok_or_else(error)?;
            let count = digits(count, 1, usize::MAX).ok_or_else(error)?;
            // `(.*):(.+)`: the last colon followed by at least one character.
            let split = rest
                .char_indices()
                .filter(|&(i, c)| c == ':' && i + 1 < rest.len())
                .map(|(i, _)| i)
                .next_back()
                .ok_or_else(error)?;
            let (value, target) = (
                rest.get(..split).unwrap_or(""),
                rest.get(split + 1..).unwrap_or(""),
            );
            if usize::try_from(count).ok() != Some(value.chars().count()) {
                return Err(error());
            }
            check_dn(target)?;
            Ok(text.as_bytes().to_vec())
        }
        Syntax::Oid => {
            if is_oid(text) {
                Ok(text.as_bytes().to_vec())
            } else {
                Err(tr("OID (“1.2.840.…”) or LDAP name expected."))
            }
        }
        _ => {
            // Strings: the input is kept as is, but the spaces at the start and at the end.
            if syntax == Syntax::Numeric && !text.chars().all(|c| c.is_ascii_digit() || c == ' ') {
                return Err(tr("Digits and spaces only."));
            }
            if syntax == Syntax::Printable
                && !text
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || PRINTABLE_EXTRA.contains(c))
            {
                return Err(tr(
                    "Allowed characters: unaccented letters, digits, space and ' ( ) + , - . / : ? =",
                ));
            }
            if syntax == Syntax::Ia5 && !text.is_ascii() {
                return Err(tr("ASCII characters only."));
            }
            if text
                .chars()
                .any(|c| (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r'))
            {
                return Err(tr("Control character rejected."));
            }
            length(description, text.chars().count(), &tr("characters"))?;
            Ok(text.as_bytes().to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(name: &str, syntax: Syntax) -> AttributeDescription {
        AttributeDescription {
            name: name.into(),
            syntax,
            single: true,
            lower: None,
            upper: None,
            system: false,
            constructed: false,
            link: None,
            guid: Vec::new(),
        }
    }

    #[test]
    fn inputs() {
        let int = d("x", Syntax::Integer);
        assert_eq!(read_input(&int, " 0x80000000 ").unwrap(), b"-2147483648");
        assert_eq!(read_input(&int, "1 000").unwrap(), b"1000");
        assert!(read_input(&int, "0x100000000").is_err());
        assert!(read_input(&int, "abc").is_err());
        assert!(read_input(&int, " ").is_err());
        assert!(read_input(&d("pwdLastSet", Syntax::LargeInteger), "5").is_err());
        assert_eq!(
            read_input(&d("accountExpires", Syntax::LargeInteger), "jamais").unwrap(),
            b"9223372036854775807"
        );
        assert_eq!(
            read_input(&d("b", Syntax::Boolean), "Vrai").unwrap(),
            b"TRUE"
        );
        assert_eq!(
            read_input(&d("o", Syntax::Octets), "0x01:a2-ff").unwrap(),
            vec![1, 0xa2, 0xff]
        );
        assert!(read_input(&d("o", Syntax::Octets), "1").is_err());
        assert_eq!(
            read_input(&d("t", Syntax::GeneralizedTime), "20261231120000.0Z").unwrap(),
            b"20261231120000.0Z"
        );
        assert_eq!(
            read_input(&d("t", Syntax::UtcTime), "991231120000Z").unwrap(),
            b"991231120000Z"
        );
        assert!(read_input(&d("t", Syntax::GeneralizedTime), "31/02/2026").is_err());
        assert!(read_input(&d("n", Syntax::Dn), "pas un DN").is_err());
        assert!(read_input(&d("n", Syntax::Dn), "CN=a,DC=b").is_ok());
        assert!(read_input(&d("n", Syntax::DnBinary), "B:2:0a:CN=a,DC=b").is_ok());
        assert!(read_input(&d("n", Syntax::DnBinary), "B:3:0a:CN=a,DC=b").is_err());
        assert!(read_input(&d("n", Syntax::DnString), "S:3:a:b:CN=a").is_ok());
        assert!(read_input(&d("o", Syntax::Oid), "1.2.840").is_ok());
        assert!(read_input(&d("o", Syntax::Oid), "1.").is_err());
        assert!(read_input(&d("p", Syntax::Printable), "é").is_err());
        let mut bounded = d("s", Syntax::Unicode);
        bounded.upper = Some(3);
        assert!(read_input(&bounded, "abcd").is_err());
        assert_eq!(read_input(&bounded, " été ").unwrap(), "été".as_bytes());
    }
}

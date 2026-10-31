// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The local administrator password of a computer, kept by LAPS (J9.4, ADR 0025).
//!
//! Two schemas: **Windows LAPS** (`msLAPS-Password`, a JSON object `{"n": account, "t": date
//! of the update in hexadecimal FILETIME, "p": password}`, and `msLAPS-PasswordExpirationTime`)
//! and the **legacy** Microsoft LAPS (`ms-Mcs-AdmPwd`, the password in clear, and
//! `ms-Mcs-AdmPwdExpirationTime`). The encrypted form of Windows LAPS
//! (`msLAPS-EncryptedPassword`, DPAPI-NG) is recognised and said, not read (J9b).
//!
//! The passwords are confidential attributes (`searchFlags` bit 7): a DC that refuses them to
//! the account bound leaves them out of the answer, without error. A computer whose expiration
//! date is readable but whose password is not is therefore said « refused », the right that is
//! missing named (`CONTROL_ACCESS` on the attribute, « All extended rights »).
//!
//! Read on the DC, never through the local copy (its white list has none of these
//! attributes), never journaled: a password lives in a [`Secret`], whose `Debug` masks it.
//! « Expire now » writes the expiration date only, journaled; its inverse is the date of before.

use std::fmt;
use std::time::Duration;

use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::time;

use crate::actions::ActionError;
use crate::changes::{Change, Changeset, Operation, Read, Values};
use crate::connection::{Connection, Failure};
use crate::error::{LdapError, code};
use crate::search;
use crate::sysvol::realm_of;

pub const PASSWORD: &str = "msLAPS-Password";
pub const EXPIRATION: &str = "msLAPS-PasswordExpirationTime";
pub const ENCRYPTED: &str = "msLAPS-EncryptedPassword";
pub const ENCRYPTED_HISTORY: &str = "msLAPS-EncryptedPasswordHistory";
pub const ENCRYPTED_DSRM: &str = "msLAPS-EncryptedDSRMPassword";
pub const LEGACY_PASSWORD: &str = "ms-Mcs-AdmPwd";
pub const LEGACY_EXPIRATION: &str = "ms-Mcs-AdmPwdExpirationTime";

/// What is read of a computer (its version too, for « Expire now »).
pub const ATTRIBUTES: [&str; 8] = [
    "uSNChanged",
    PASSWORD,
    EXPIRATION,
    ENCRYPTED,
    ENCRYPTED_HISTORY,
    ENCRYPTED_DSRM,
    LEGACY_PASSWORD,
    LEGACY_EXPIRATION,
];

/// A secret read on the DC: shown only on demand, never in a `Debug`, a log or a journal.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// The value itself, for the display asked or the clipboard.
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(crate::changes::MASKED_VALUE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schema {
    /// Windows LAPS (`msLAPS-*`).
    Windows,
    /// Microsoft LAPS, the legacy one (`ms-Mcs-AdmPwd*`).
    Legacy,
}

impl Schema {
    pub fn expiration_attribute(self) -> &'static str {
        match self {
            Self::Windows => EXPIRATION,
            Self::Legacy => LEGACY_EXPIRATION,
        }
    }

    pub fn password_attribute(self) -> &'static str {
        match self {
            Self::Windows => PASSWORD,
            Self::Legacy => LEGACY_PASSWORD,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// The password was read.
    Readable,
    /// Kept encrypted (`msLAPS-EncryptedPassword`): readable in a later version (J9b).
    Encrypted,
    /// The expiration date is there, the password is not given: the account bound has not the
    /// right to read it (confidential attribute).
    Refused,
    /// The value is not what the schema says (JSON of `msLAPS-Password`).
    Malformed(String),
}

/// The password of one schema on the object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Managed {
    pub schema: Schema,
    pub state: State,
    /// The account managed (Windows LAPS: `n`; legacy: not said).
    pub account: Option<String>,
    pub password: Option<Secret>,
    /// Date of the last update (FILETIME; Windows LAPS: `t`).
    pub updated: Option<i64>,
    /// Expiration date (FILETIME); None if absent.
    pub expiration: Option<i64>,
    /// The values of the expiration attribute as read (for its change).
    pub expiration_values: Values,
}

/// What LAPS keeps on a computer, read on the DC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reading {
    pub dn: String,
    /// Windows LAPS first, then the legacy schema; empty: not managed by LAPS (or the
    /// expiration date itself is not readable).
    pub managed: Vec<Managed>,
    /// The encrypted history or DSRM password are there (J9b).
    pub encrypted_extra: bool,
    pub read: Read,
}

impl Reading {
    pub fn get(&self, schema: Schema) -> Option<&Managed> {
        self.managed.iter().find(|m| m.schema == schema)
    }
}

/// Why `msLAPS-Password` is not understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

/// The JSON of `msLAPS-Password`: account, date of the update (FILETIME), password.
pub fn decode_windows(value: &[u8]) -> Result<(String, Option<i64>, Secret), JsonError> {
    let parsed: serde_json::Value =
        serde_json::from_slice(value).map_err(|e| JsonError(e.to_string()))?;
    let field = |name: &str| parsed.get(name).and_then(serde_json::Value::as_str);
    let password = field("p").ok_or_else(|| JsonError("p".into()))?;
    let account = field("n").unwrap_or_default().to_owned();
    let updated = field("t")
        .and_then(|t| u64::from_str_radix(t, 16).ok())
        .and_then(|t| i64::try_from(t).ok());
    Ok((account, updated, Secret::new(password.to_owned())))
}

fn first<'a>(attributes: &'a [(String, Values)], name: &str) -> Option<&'a [u8]> {
    attributes
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(Vec::as_slice)
}

fn values(attributes: &[(String, Values)], name: &str) -> Values {
    attributes
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn large(value: &[u8]) -> Option<i64> {
    integer::decode(value, Width::Bits64).ok()
}

/// What the attributes read say (pure).
pub fn interpret(dn: &str, attributes: &[(String, Values)], read: Read) -> Reading {
    let mut managed = Vec::new();
    let expiration_values = values(attributes, EXPIRATION);
    let clear = first(attributes, PASSWORD);
    let encrypted = first(attributes, ENCRYPTED).is_some();
    if clear.is_some() || encrypted || !expiration_values.is_empty() {
        let mut entry = Managed {
            schema: Schema::Windows,
            state: State::Refused,
            account: None,
            password: None,
            updated: None,
            expiration: expiration_values.first().and_then(|v| large(v)),
            expiration_values,
        };
        if let Some(clear) = clear {
            match decode_windows(clear) {
                Ok((account, updated, password)) => {
                    entry.state = State::Readable;
                    entry.account = (!account.is_empty()).then_some(account);
                    entry.updated = updated;
                    entry.password = Some(password);
                }
                Err(JsonError(e)) => entry.state = State::Malformed(e),
            }
        } else if encrypted {
            entry.state = State::Encrypted;
        }
        managed.push(entry);
    }
    let legacy_expiration = values(attributes, LEGACY_EXPIRATION);
    let legacy = first(attributes, LEGACY_PASSWORD);
    if legacy.is_some() || !legacy_expiration.is_empty() {
        managed.push(Managed {
            schema: Schema::Legacy,
            state: if legacy.is_some() {
                State::Readable
            } else {
                State::Refused
            },
            account: None,
            password: legacy.map(|p| Secret::new(String::from_utf8_lossy(p).into_owned())),
            updated: None,
            expiration: legacy_expiration.first().and_then(|v| large(v)),
            expiration_values: legacy_expiration,
        });
    }
    Reading {
        dn: dn.to_owned(),
        managed,
        encrypted_extra: first(attributes, ENCRYPTED_HISTORY).is_some()
            || first(attributes, ENCRYPTED_DSRM).is_some(),
        read,
    }
}

/// Reads LAPS on the computer `dn`, on the DC of `connection` (blocking); None if the object
/// does not exist.
pub fn read(connection: &Connection, dn: &str) -> Result<Option<Reading>, Failure> {
    let dn = dn.to_owned();
    connection.run(true, move |link| {
        let attributes: Vec<String> = ATTRIBUTES.iter().map(|&a| a.to_owned()).collect();
        let entry = search::read_entry(
            link.session.as_mut(),
            &dn,
            &attributes,
            "(objectClass=computer)",
            None,
            Some(link.timeout),
        )?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let usn = entry
            .values("uSNChanged")
            .first()
            .and_then(|v| large(v))
            .ok_or_else(|| LdapError::new(code::DECODING_ERROR, "uSNChanged absent"))?;
        let mut reading = interpret(
            &entry.dn,
            &entry.attributes,
            Read {
                dc: link.state.dc.clone(),
                usn,
            },
        );
        // J9.7: if the Windows password is kept encrypted, read it through MS-GKDI.
        if reading
            .get(Schema::Windows)
            .is_some_and(|m| m.state == State::Encrypted)
        {
            if let Some(encrypted) = first(&entry.attributes, ENCRYPTED) {
                decrypt_windows(&mut reading, encrypted, &link.state.dc, link.timeout);
            }
        }
        Ok(Some(reading))
    })
}

/// Tries to read the encrypted Windows LAPS password in place (J9.7): asks the DC for the group
/// key and decrypts. On success the entry becomes readable; on failure it stays « encrypted »,
/// which the sheet reports. Blocking: one GetKey round trip to the DC.
fn decrypt_windows(reading: &mut Reading, encrypted: &[u8], dc: &str, timeout: Duration) {
    let realm = realm_of(dc);
    let Ok(plaintext) = crate::dpapi::decrypt_laps_value(encrypted, dc, &realm, timeout) else {
        return;
    };
    // Windows stores the JSON as UTF-8 in the clear attribute; the encrypted content may be
    // UTF-16LE, so fall back to that.
    let decoded =
        decode_windows(&plaintext).or_else(|_| decode_windows(&utf16le_to_utf8(&plaintext)));
    if let (Some(entry), Ok((account, updated, password))) = (
        reading
            .managed
            .iter_mut()
            .find(|m| m.schema == Schema::Windows),
        decoded,
    ) {
        entry.state = State::Readable;
        entry.account = (!account.is_empty()).then_some(account);
        entry.updated = updated;
        entry.password = Some(password);
    }
}

/// UTF-16LE bytes to UTF-8 bytes (the encrypted LAPS JSON may be UTF-16LE).
fn utf16le_to_utf8(b: &[u8]) -> Vec<u8> {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap_or([0, 0])))
        .collect();
    String::from_utf16_lossy(&units).into_bytes()
}

/// The FILETIME of now.
pub fn now() -> i64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    time::unix_to_nttime(seconds).unwrap_or(0)
}

/// « Expire now »: the expiration date of `schema` set to `at` (FILETIME), as
/// `Set-LapsADPasswordExpirationTime`; the computer changes its password at its next policy
/// processing. The inverse gives the date of before.
pub fn expire_now(reading: &Reading, schema: Schema, at: i64) -> Result<Changeset, ActionError> {
    let managed = reading
        .get(schema)
        .ok_or_else(|| ActionError::Change(format!("{}: LAPS", reading.dn)))?;
    Ok(Changeset {
        operations: vec![Operation::modify(
            &reading.dn,
            vec![Change::new(
                schema.expiration_attribute(),
                managed.expiration_values.clone(),
                vec![at.to_string().into_bytes()],
            )?],
            Some(reading.read.clone()),
        )?],
        remarks: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes(pairs: &[(&str, &[u8])]) -> Vec<(String, Values)> {
        pairs
            .iter()
            .map(|(a, v)| ((*a).to_owned(), vec![v.to_vec()]))
            .collect()
    }

    fn read() -> Read {
        Read {
            dc: "wdc1".into(),
            usn: 42,
        }
    }

    #[test]
    fn windows_laps_in_clear() {
        // As `Get-LapsADPassword` reads it: the date of the JSON is hexadecimal.
        let json = br#"{"n":"Administrateur","t":"1dd4a3b2c1d0e0f","p":"S3cret+Value"}"#;
        let reading = interpret(
            "CN=PC,DC=x",
            &attributes(&[(PASSWORD, json), (EXPIRATION, b"134000000000000000")]),
            read(),
        );
        let windows = reading.get(Schema::Windows).unwrap();
        assert_eq!(windows.state, State::Readable);
        assert_eq!(windows.account.as_deref(), Some("Administrateur"));
        assert_eq!(windows.updated, Some(0x1dd_4a3b_2c1d_0e0f));
        assert_eq!(windows.expiration, Some(134_000_000_000_000_000));
        assert_eq!(
            windows.password.as_ref().map(Secret::reveal),
            Some("S3cret+Value")
        );
        // Never in a debug form.
        assert!(!format!("{reading:?}").contains("S3cret"));
        assert!(reading.get(Schema::Legacy).is_none());
    }

    #[test]
    fn refused_encrypted_and_absent() {
        let refused = interpret(
            "CN=PC,DC=x",
            &attributes(&[(EXPIRATION, b"134000000000000000")]),
            read(),
        );
        assert_eq!(refused.get(Schema::Windows).unwrap().state, State::Refused);
        let encrypted = interpret(
            "CN=PC,DC=x",
            &attributes(&[(ENCRYPTED, b"\x01\x02"), (EXPIRATION, b"1")]),
            read(),
        );
        assert_eq!(
            encrypted.get(Schema::Windows).unwrap().state,
            State::Encrypted
        );
        assert!(interpret("CN=PC,DC=x", &[], read()).managed.is_empty());
        let malformed = interpret("CN=PC,DC=x", &attributes(&[(PASSWORD, b"{")]), read());
        assert!(matches!(
            malformed.get(Schema::Windows).unwrap().state,
            State::Malformed(_)
        ));
    }

    #[test]
    fn legacy_laps() {
        let reading = interpret(
            "CN=PC,DC=x",
            &attributes(&[
                (LEGACY_PASSWORD, b"Old-Style-1"),
                (LEGACY_EXPIRATION, b"133900000000000000"),
            ]),
            read(),
        );
        let legacy = reading.get(Schema::Legacy).unwrap();
        assert_eq!(legacy.state, State::Readable);
        assert_eq!(
            legacy.password.as_ref().map(Secret::reveal),
            Some("Old-Style-1")
        );
        let refused = interpret(
            "CN=PC,DC=x",
            &attributes(&[(LEGACY_EXPIRATION, b"133900000000000000")]),
            read(),
        );
        assert_eq!(refused.get(Schema::Legacy).unwrap().state, State::Refused);
    }

    #[test]
    fn expire_now_changes_the_date_only() {
        let reading = interpret(
            "CN=PC,DC=x",
            &attributes(&[
                (PASSWORD, br#"{"n":"a","t":"1","p":"x"}"#),
                (EXPIRATION, b"134000000000000000"),
            ]),
            read(),
        );
        let changeset = expire_now(&reading, Schema::Windows, 133_000_000_000_000_000).unwrap();
        let Some(Operation::Modify { changes, read, .. }) = changeset.operations.first() else {
            panic!("one modification expected");
        };
        assert_eq!(read.as_ref().map(|r| r.usn), Some(42));
        assert_eq!(changes.len(), 1);
        assert!(expire_now(&reading, Schema::Legacy, 1).is_err());
        assert!(now() > 133_000_000_000_000_000);
    }

    #[test]
    fn never_in_the_local_copy() {
        #[cfg(feature = "local-copy")]
        for attribute in ATTRIBUTES
            .iter()
            .skip(1)
            .chain(&["msFVE-RecoveryPassword", "msFVE-KeyPackage"])
        {
            assert!(!crate::store::white_listed(attribute), "{attribute}");
        }
        for attribute in ATTRIBUTES
            .iter()
            .skip(1)
            .filter(|a| !a.contains("Expiration"))
        {
            assert!(crate::changes::is_sensitive(attribute), "{attribute}");
        }
    }
}

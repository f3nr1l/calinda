// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! BitLocker recovery passwords kept in the directory (J9.5, ADR 0025).
//!
//! Windows backs up a recovery password of a volume as an object `msFVE-RecoveryInformation`
//! under the computer (`manage-bde -protectors -adbackup`, `Backup-BitLockerKeyProtector`, or
//! the policy that requires the backup): its name is the date of the backup followed by the
//! identifier of the password between braces (`2026-10-28T22:15:01-04:00{3E8F…}`),
//! `msFVE-RecoveryGuid` the same identifier, `msFVE-VolumeGuid` the volume,
//! `msFVE-RecoveryPassword` the 48 digits. The password and the key package are confidential:
//! a DC that refuses them to the account bound leaves them out, said « refused ».
//!
//! The search by identifier is the one of the Windows tool (« Find BitLocker recovery
//! password » of ADUC): the first eight characters of the identifier the recovery screen
//! shows, looked for in the names of the objects of the domain.

use annuaire_codecs::Guid;

use crate::connection::Connection;
use crate::laps::Secret;
use crate::membership;
use crate::search::SearchError;
use crate::session::Entry;

pub const CLASS: &str = "msFVE-RecoveryInformation";
pub const PASSWORD: &str = "msFVE-RecoveryPassword";
pub const RECOVERY_GUID: &str = "msFVE-RecoveryGuid";
pub const VOLUME_GUID: &str = "msFVE-VolumeGuid";
pub const KEY_PACKAGE: &str = "msFVE-KeyPackage";

const ATTRIBUTES: [&str; 5] = ["name", "whenCreated", RECOVERY_GUID, VOLUME_GUID, PASSWORD];

/// Characters of the identifier that the search takes.
pub const PREFIX_LENGTH: usize = 8;

/// One recovery password of the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovery {
    pub dn: String,
    /// The computer it is under.
    pub computer: String,
    /// Identifier of the password, as Windows shows it (upper case, without braces).
    pub id: Option<String>,
    pub volume: Option<String>,
    /// The date of the backup, as the name of the object gives it (local time of the station,
    /// with its offset).
    pub date: String,
    /// `whenCreated` (generalized time), when the name has no date.
    pub created: String,
    /// None: refused to the account bound (confidential attribute).
    pub password: Option<Secret>,
}

fn guid_text(value: &[u8]) -> Option<String> {
    Guid::decode(value)
        .ok()
        .map(|g| g.to_string().to_uppercase())
}

fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

/// An object read (pure).
pub fn interpret(entry: &Entry) -> Recovery {
    let name = text(entry, "name");
    let (date, braced) = name.split_once('{').unwrap_or((name.as_str(), ""));
    let id = entry
        .values(RECOVERY_GUID)
        .first()
        .and_then(|v| guid_text(v))
        .or_else(|| {
            let id = braced.trim_end_matches('}');
            (!id.is_empty()).then(|| id.to_uppercase())
        });
    let computer = crate::changes::parent_dn(&entry.dn).unwrap_or_default();
    Recovery {
        dn: entry.dn.clone(),
        computer,
        id,
        volume: entry.values(VOLUME_GUID).first().and_then(|v| guid_text(v)),
        date: date.to_owned(),
        created: text(entry, "whenCreated"),
        password: entry
            .values(PASSWORD)
            .first()
            .map(|v| Secret::new(String::from_utf8_lossy(v).into_owned())),
    }
}

/// The first eight characters of an identifier typed (braces, spaces and the rest ignored),
/// in upper case; None if they are not eight hexadecimal digits.
pub fn prefix(typed: &str) -> Option<String> {
    let start: String = typed
        .trim()
        .trim_start_matches('{')
        .chars()
        .take(PREFIX_LENGTH)
        .collect();
    (start.len() == PREFIX_LENGTH && start.chars().all(|c| c.is_ascii_hexdigit()))
        .then(|| start.to_uppercase())
}

fn sorted(mut found: Vec<Recovery>) -> Vec<Recovery> {
    // The most recent first: the name begins with the date.
    found.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.dn.cmp(&b.dn)));
    found
}

fn read(connection: &Connection, base: &str, filter: String) -> Result<Vec<Recovery>, SearchError> {
    let attributes = ATTRIBUTES.iter().map(|&a| a.to_owned()).collect();
    let entries = membership::search_all(connection, base, filter, attributes)?;
    Ok(sorted(entries.iter().map(interpret).collect()))
}

/// The recovery passwords under the computer `dn` (blocking).
pub fn under(connection: &Connection, dn: &str) -> Result<Vec<Recovery>, SearchError> {
    read(connection, dn, format!("(objectClass={CLASS})"))
}

/// The recovery passwords of the domain whose identifier begins with `prefix` (eight
/// hexadecimal digits, from [`prefix`]), under `base` (blocking).
pub fn search(
    connection: &Connection,
    base: &str,
    prefix: &str,
) -> Result<Vec<Recovery>, SearchError> {
    // Hexadecimal digits only (checked by `prefix`): nothing to escape in the filter.
    let found = read(
        connection,
        base,
        format!("(&(objectClass={CLASS})(name=*{{{prefix}*))"),
    )?;
    Ok(found
        .into_iter()
        .filter(|r| r.id.as_ref().is_some_and(|id| id.starts_with(prefix)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_read() {
        let guid: Guid = "3e8f1a2b-4c5d-6e7f-8091-a2b3c4d5e6f7".parse().unwrap();
        let entry = Entry {
            dn: "CN=2026-10-28T22:15:01-04:00{3E8F1A2B-4C5D-6E7F-8091-A2B3C4D5E6F7},CN=PC1,OU=X,DC=x"
                .into(),
            attributes: vec![
                (
                    "name".into(),
                    vec![b"2026-10-28T22:15:01-04:00{3E8F1A2B-4C5D-6E7F-8091-A2B3C4D5E6F7}".to_vec()],
                ),
                (RECOVERY_GUID.into(), vec![guid.encode().to_vec()]),
                (
                    PASSWORD.into(),
                    vec![b"111111-222222-333333-444444-555555-666666-777777-888888".to_vec()],
                ),
            ],
        };
        let recovery = interpret(&entry);
        assert_eq!(recovery.computer, "CN=PC1,OU=X,DC=x");
        assert_eq!(
            recovery.id.as_deref(),
            Some("3E8F1A2B-4C5D-6E7F-8091-A2B3C4D5E6F7")
        );
        assert_eq!(recovery.date, "2026-10-28T22:15:01-04:00");
        assert!(recovery.password.is_some());
        assert!(!format!("{recovery:?}").contains("111111"));
        // Refused: the password left out by the DC.
        let refused = Entry {
            attributes: entry.attributes.iter().take(2).cloned().collect(),
            ..entry
        };
        assert!(interpret(&refused).password.is_none());
    }

    #[test]
    fn prefixes() {
        assert_eq!(prefix("3e8f1a2b").as_deref(), Some("3E8F1A2B"));
        assert_eq!(
            prefix(" {3E8F1A2B-4C5D-6E7F-8091-A2B3C4D5E6F7} ").as_deref(),
            Some("3E8F1A2B")
        );
        assert_eq!(prefix("3E8F1A2"), None);
        assert_eq!(prefix("3E8F1A2Z"), None);
    }
}

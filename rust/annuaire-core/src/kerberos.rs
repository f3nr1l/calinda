// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The Kerberos ticket of the session (`annuaire.core.kerberos`), for the Rust interface:
//! which principal, until when (R4.1), and a ticket obtained by password, as `kinit` (R4.2).
//! The read is local (no exchange with the KDC); everything here still runs off the
//! interface thread (a KCM cache is a local service that can be slow, a KDC a remote one).

use std::time::{Duration, SystemTime};

use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::GSS_NT_KRB5_PRINCIPAL;

use crate::profile::valid_dns_name;

/// `GSS_C_INDEFINITE`: a credential without end.
const INDEFINITE: Duration = Duration::from_secs(0xFFFF_FFFF);

/// A ticket of the cache: principal and end of validity (None: without limit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub principal: String,
    pub end: Option<SystemTime>,
}

impl Ticket {
    pub fn realm(&self) -> &str {
        self.principal
            .rsplit_once('@')
            .map_or("", |(_, realm)| realm)
    }

    /// True if the ticket is of the realm of `domain` (`lab.test` → `LAB.TEST`).
    pub fn valid_for(&self, domain: &str) -> bool {
        self.realm() == realm_of_domain(domain)
    }
}

/// Kerberos realm of an AD domain: its DNS name in upper case.
pub fn realm_of_domain(domain: &str) -> String {
    domain.to_uppercase()
}

/// The ticket of `principal`, or the default one, from the cache of the session (`lire_ticket`).
/// None if there is none, or if it expired.
pub fn read_ticket(principal: Option<&str>) -> Option<Ticket> {
    let name = match principal {
        Some(p) => Some(Name::new(p.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL)).ok()?),
        None => None,
    };
    let cred = Cred::acquire(name.as_ref(), None, CredUsage::Initiate, None).ok()?;
    let remaining = cred.lifetime().ok()?;
    let found = cred.name().ok()?.to_string();
    ticket_from(found, remaining, SystemTime::now())
}

/// Why a typed account cannot be a principal (`principal_depuis_saisie`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrincipalError {
    /// `Identifiant invalide : « utilisateur » ou « utilisateur@ROYAUME ».`
    Invalid,
    /// `L'identifiant contient un caractère non permis.`
    ForbiddenCharacter,
    /// `Précisez le royaume : « utilisateur@ROYAUME ».`
    NoRealm,
    /// `Royaume invalide : {royaume}.`
    InvalidRealm(String),
}

/// The full principal of what the user typed: `administrator` becomes
/// `administrator@LAB.TEST` (default realm), `administrator@lab.test` becomes
/// `administrator@LAB.TEST` (an AD realm is always in upper case).
pub fn principal_from_input(input: &str, realm: Option<&str>) -> Result<String, PrincipalError> {
    let text = input.trim();
    let (user, typed) = match text.rsplit_once('@') {
        Some((user, typed)) => (user, typed),
        None => (text, realm.unwrap_or("")),
    };
    if user.is_empty() || user.contains('@') {
        return Err(PrincipalError::Invalid);
    }
    if user
        .chars()
        .any(|c| (c as u32) < 0x20 || matches!(c, '\x7f' | '/' | '\\'))
    {
        return Err(PrincipalError::ForbiddenCharacter);
    }
    if typed.is_empty() {
        return Err(PrincipalError::NoRealm);
    }
    if !valid_dns_name(&typed.to_lowercase()) {
        return Err(PrincipalError::InvalidRealm(typed.to_owned()));
    }
    Ok(format!("{user}@{}", typed.to_uppercase()))
}

/// Why no ticket was obtained (`traduire_gss` and the end of `obtenir_ticket`); the
/// interface words it, with the detail of GSSAPI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TicketErrorKind {
    /// `Mot de passe refusé pour {principal}.`
    PasswordRefused,
    /// `Le compte {principal} est inconnu du domaine.`
    UnknownAccount,
    /// `Le mot de passe de {principal} a expiré : il faut le changer d'abord.`
    PasswordExpired,
    /// `Le compte {principal} est désactivé, verrouillé ou expiré.`
    Revoked,
    /// `L'horloge du poste et celle du contrôleur de domaine diffèrent trop.`
    ClockSkew,
    /// `Aucun serveur Kerberos ne répond pour le royaume {royaume}.`
    NoKdc,
    /// `Impossible d'obtenir un ticket Kerberos.`
    Other,
    /// `Le ticket a été obtenu mais n'a pas pu être rangé dans le cache Kerberos.`
    NotStored,
    /// `Le ticket a été obtenu mais n'est pas lisible dans le cache Kerberos.`
    NotReadable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketError {
    pub kind: TicketErrorKind,
    pub detail: String,
}

/// Fragments (in lower case) of the messages of MIT krb5, seen against the KDC of Samba.
const PASSWORD_REFUSED: [&str; 3] = [
    "preauthentication failed",
    "password incorrect",
    "decrypt integrity",
];

/// The kind of a failure to obtain a ticket, from the message of GSSAPI (`traduire_gss`).
pub fn sort_gss_error(detail: &str) -> TicketErrorKind {
    let low = detail.to_lowercase();
    let has = |fragments: &[&str]| fragments.iter().any(|f| low.contains(f));
    if has(&PASSWORD_REFUSED) {
        TicketErrorKind::PasswordRefused
    } else if has(&["not found in kerberos database"]) {
        TicketErrorKind::UnknownAccount
    } else if has(&["password has expired"]) {
        TicketErrorKind::PasswordExpired
    } else if has(&["revoked"]) {
        TicketErrorKind::Revoked
    } else if has(&["clock skew"]) {
        TicketErrorKind::ClockSkew
    } else if has(&[
        "cannot find kdc",
        "cannot contact any kdc",
        "network address",
    ]) {
        TicketErrorKind::NoKdc
    } else {
        TicketErrorKind::Other
    }
}

/// Asks the KDC for a ticket and stores it in the cache of the session, as `kinit`
/// (`obtenir_ticket`); it becomes the default ticket of the cache. `password` (UTF-8) is
/// overwritten with zeros as soon as GSSAPI has read it, whether the call succeeds or not.
pub fn obtain_ticket(principal: &str, password: &mut Vec<u8>) -> Result<Ticket, TicketError> {
    let acquired = (|| {
        let name = Name::new(principal.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?;
        let text = std::str::from_utf8(password).unwrap_or("");
        Cred::acquire_with_password(Some(&name), text, None, CredUsage::Initiate, None)
    })();
    password.fill(0);
    std::hint::black_box(&password);
    password.clear();
    let cred = acquired.map_err(|e| {
        let detail = e.to_string();
        TicketError {
            kind: sort_gss_error(&detail),
            detail,
        }
    })?;
    cred.store(true, true, CredUsage::Initiate, None)
        .map_err(|e| TicketError {
            kind: TicketErrorKind::NotStored,
            detail: e.to_string(),
        })?;
    read_ticket(Some(principal)).ok_or_else(|| TicketError {
        kind: TicketErrorKind::NotReadable,
        detail: principal.to_owned(),
    })
}

fn ticket_from(principal: String, remaining: Duration, now: SystemTime) -> Option<Ticket> {
    if remaining.is_zero() {
        return None;
    }
    let end = if remaining == INDEFINITE {
        None
    } else {
        Some(now + remaining)
    };
    Some(Ticket { principal, end })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_of_a_lifetime() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let p = || "Administrator@LAB.TEST".to_owned();
        assert_eq!(ticket_from(p(), Duration::ZERO, now), None);
        let t = ticket_from(p(), Duration::from_secs(60), now).unwrap();
        assert_eq!(t.end, Some(now + Duration::from_secs(60)));
        assert_eq!(ticket_from(p(), INDEFINITE, now).unwrap().end, None);
        assert_eq!(t.realm(), "LAB.TEST");
        assert!(t.valid_for("lab.test") && !t.valid_for("win.test"));
    }

    #[test]
    fn principal_of_an_input() {
        let lab = Some("LAB.TEST");
        assert_eq!(
            principal_from_input(" administrator ", lab).as_deref(),
            Ok("administrator@LAB.TEST")
        );
        assert_eq!(
            principal_from_input("administrator@lab.test", None).as_deref(),
            Ok("administrator@LAB.TEST")
        );
        assert_eq!(
            principal_from_input("a@b@lab.test", None),
            Err(PrincipalError::Invalid)
        );
        assert_eq!(principal_from_input("", lab), Err(PrincipalError::Invalid));
        assert_eq!(
            principal_from_input("a/b", lab),
            Err(PrincipalError::ForbiddenCharacter)
        );
        assert_eq!(
            principal_from_input("a", None),
            Err(PrincipalError::NoRealm)
        );
        assert_eq!(
            principal_from_input("administrator@", None),
            Err(PrincipalError::NoRealm)
        );
        assert_eq!(
            principal_from_input("@LAB.TEST", None),
            Err(PrincipalError::Invalid)
        );
        assert_eq!(
            principal_from_input("admin\0", lab),
            Err(PrincipalError::ForbiddenCharacter)
        );
        assert_eq!(
            principal_from_input("jean dupont", lab).as_deref(),
            Ok("jean dupont@LAB.TEST")
        );
        assert_eq!(
            principal_from_input("admin@EXAMPLE.COM", lab).as_deref(),
            Ok("admin@EXAMPLE.COM")
        );
        assert!(principal_from_input("administrator@lab..test", None).is_err());
        assert_eq!(
            principal_from_input("a@LAB_TEST", None),
            Err(PrincipalError::InvalidRealm("LAB_TEST".into()))
        );
    }

    #[test]
    fn gss_errors() {
        // Messages of MIT krb5 seen in the Python tests (`test_kerberos.py`).
        let cases = [
            (
                "Major (851968): Unspecified GSS failure, Minor (2529638936): Preauthentication failed",
                TicketErrorKind::PasswordRefused,
            ),
            (
                "Client 'x@LAB.TEST' not found in Kerberos database",
                TicketErrorKind::UnknownAccount,
            ),
            ("Password has expired", TicketErrorKind::PasswordExpired),
            (
                "Client's credentials have been revoked",
                TicketErrorKind::Revoked,
            ),
            ("Clock skew too great", TicketErrorKind::ClockSkew),
            (
                "Cannot find KDC for realm \"NULLE.PART\"",
                TicketErrorKind::NoKdc,
            ),
            ("something else", TicketErrorKind::Other),
        ];
        for (detail, kind) in cases {
            assert_eq!(sort_gss_error(detail), kind, "{detail}");
        }
    }

    #[test]
    fn no_ticket_for_an_unknown_principal() {
        // Local read of the cache: a principal that no cache holds gives nothing.
        assert!(read_ticket(Some("personne@NULLE.PART")).is_none());
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Messages of the errors of the core (`annuaire.core.erreurs.traduire` and the `echec_*`
//! functions of `_rust.py`): the core gives typed errors and their category, the interface
//! words them with the messages of the Python catalogue.

use annuaire_core::connection::{ConnectFailure, Failure};
use annuaire_core::error::{Category, LdapError, categorize, code};
use annuaire_core::membership::MembershipError;
use annuaire_core::rootdse::RootDseError;
use annuaire_core::search::SearchError;
use annuaire_core::smb::ErrorKind;
use annuaire_core::smb::msg::status;
use annuaire_core::store::LineError;
use annuaire_core::sync::SyncError;
use annuaire_core::sysvol::{self, SysvolError};

use crate::i18n::{fill, tr};

/// A message for the user, the technical detail, and what the interface does about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub message: String,
    pub detail: String,
    /// No valid ticket: ask for one, then try again (`ErreurTicket`).
    pub ticket: bool,
    /// A Kerberos failure: the state of the ticket is read again (`ErreurKerberos`).
    pub kerberos: bool,
}

impl Problem {
    fn new(message: String, detail: String) -> Self {
        Self {
            message,
            detail,
            ticket: false,
            kerberos: false,
        }
    }
}

/// The phrase of a refusal of a write (`_message_ldap`); None: no translation.
fn ldap_message(error: &LdapError) -> Option<String> {
    let low = error.info.to_lowercase();
    // 0000052D: ERROR_PASSWORD_RESTRICTION (Windows); Samba writes "password is too short"…
    let password = low.contains("0000052d") || low.contains("password");
    let text = match error.code {
        code::INSUFFICIENT_ACCESS => tr(
            "Insufficient rights for this operation. If the object is an OU, it may be protected from accidental deletion.",
        ),
        code::CONSTRAINT_VIOLATION | code::UNWILLING_TO_PERFORM if password => tr(
            "The password does not meet the domain policy (length, complexity, history, minimum age).",
        ),
        code::CONSTRAINT_VIOLATION => {
            tr("The server refuses a value: schema or domain constraint not met.")
        }
        code::UNWILLING_TO_PERFORM => {
            tr("The domain controller is unwilling to perform this operation.")
        }
        code::ALREADY_EXISTS => tr("An object with this name already exists."),
        code::NO_SUCH_OBJECT => tr("The object does not exist or no longer exists."),
        code::INVALID_SYNTAX => tr("Invalid value for this attribute (schema syntax or range)."),
        code::OBJECT_CLASS_VIOLATION => {
            tr("Required attribute missing, or not allowed for this object type.")
        }
        code::NOT_ALLOWED_ON_NONLEAF => {
            tr("The object contains other objects: move or delete them first.")
        }
        code::NAMING_VIOLATION => tr("This name is not allowed at this location in the directory."),
        _ => return None,
    };
    Some(text)
}

/// An LDAP error with a clear message (`traduire`).
pub fn ldap_problem(error: &LdapError, dc: &str) -> Problem {
    let on = if dc.is_empty() {
        String::new()
    } else {
        format!(" ({dc})")
    };
    let with = |template: String| fill(&template, &[("dc", &on)]);
    let detail = error.detail();
    let category = categorize(error);
    let message = match category {
        Category::Ticket => tr("No valid Kerberos ticket for this domain: get one (kinit)."),
        Category::ChannelBinding => {
            with(tr("The domain controller refused TLS channel binding{dc}."))
        }
        Category::StrongerAuth => with(tr(
            "The domain controller requires a different encryption level{dc}.",
        )),
        Category::TooWeak => with(tr("Unable to get an encrypted connection{dc}.")),
        Category::UnknownService => {
            let this = if dc.is_empty() {
                tr("this DC")
            } else {
                dc.to_owned()
            };
            fill(
                &tr(
                    "Kerberos does not know the LDAP service of {dc}: check the DC name and reverse DNS resolution (rdns = false).",
                ),
                &[("dc", &this)],
            )
        }
        Category::ClockSkew => {
            tr("The clocks of this computer and of the domain controller differ too much.")
        }
        Category::Certificate => with(tr(
            "The domain controller's certificate could not be verified{dc}.",
        )),
        Category::Unreachable => with(tr("The domain controller is not responding{dc}.")),
        Category::Timeout => tr("The domain controller took too long to respond."),
        Category::Unavailable => with(tr("The domain controller is unavailable{dc}.")),
        Category::Kerberos => with(tr("Kerberos authentication failed{dc}.")),
        Category::Ldap => ldap_message(error).unwrap_or_else(|| {
            let description = error.desc();
            if description.is_empty() {
                tr("LDAP error")
            } else {
                description.to_owned()
            }
        }),
    };
    Problem {
        ticket: category == Category::Ticket,
        kerberos: matches!(
            category,
            Category::UnknownService | Category::ClockSkew | Category::Kerberos
        ),
        ..Problem::new(message, detail)
    }
}

/// A failure to connect (`echec_aucun_dc`, `echec_liaison`, `echec_tls`…).
pub fn connect_problem(failure: &ConnectFailure, domain: &str) -> Problem {
    match failure {
        ConnectFailure::NoDc { domain, failures } => {
            let details: Vec<String> = failures
                .iter()
                .map(|(dc, error)| format!("{dc} : {}", ldap_problem(error, dc).detail))
                .collect();
            Problem::new(
                fill(
                    &tr("No domain controller of “{domaine}” responded."),
                    &[("domaine", domain)],
                ),
                details.join(" ; "),
            )
        }
        ConnectFailure::Bind { dc, error } => ldap_problem(error, dc),
        ConnectFailure::Tls { dc, error } => Problem::new(
            fill(
                &tr(
                    "TLS negotiation with {dc} failed: its certificate may not be signed by the profile's CA.",
                ),
                &[("dc", dc)],
            ),
            ldap_problem(error, dc).detail,
        ),
        ConnectFailure::NotEncrypted { dc, ssf } => Problem::new(
            fill(
                &tr("The connection with {dc} is not encrypted."),
                &[("dc", dc)],
            ),
            format!("SSF SASL {ssf} < {}", annuaire_core::connection::SSF_MIN),
        ),
        ConnectFailure::RootDse { error, .. } => match error {
            RootDseError::NotADirectory => Problem::new(
                tr(
                    "This server does not identify itself as an Active Directory domain controller.",
                ),
                crate::codec_texts::codec_message(&error.to_string()),
            ),
            RootDseError::InvalidInteger { .. } => Problem::new(
                crate::codec_texts::codec_message(&error.to_string()),
                String::new(),
            ),
        },
        ConnectFailure::Resolve(error) if error.unreachable => Problem::new(
            tr("This computer's DNS server is not responding."),
            error.detail.clone(),
        ),
        ConnectFailure::Resolve(error) => Problem::new(
            fill(
                &tr("No domain controller found for “{domaine}”."),
                &[("domaine", domain)],
            ),
            error.detail.clone(),
        ),
        ConnectFailure::Closed => Problem::new(
            tr("The connection has been closed."),
            "connexion fermée".into(),
        ),
    }
}

pub fn failure_problem(failure: &Failure, domain: &str) -> Problem {
    match failure {
        Failure::Connect(failure) => connect_problem(failure, domain),
        Failure::Ldap { dc, error } => ldap_problem(error, dc),
    }
}

pub fn search_problem(error: &SearchError, domain: &str) -> Problem {
    match error {
        SearchError::Ldap { dc, error } => ldap_problem(error, dc),
        SearchError::Connect(failure) => connect_problem(failure, domain),
        SearchError::Reconnected { from, to } => Problem::new(
            tr("The connection was re-established during the search; run it again."),
            format!("génération {from} → {to}"),
        ),
        SearchError::Closed => Problem::new(
            tr("The connection has been closed."),
            "connexion fermée".into(),
        ),
    }
}

/// Message of groups that could not be read (`groupes_de`).
pub fn membership_message(error: &MembershipError, domain: &str) -> String {
    match error {
        MembershipError::Failure(failure) => failure_problem(failure, domain).message,
        MembershipError::Search(error) => search_problem(error, domain).message,
        MembershipError::Missing(dn) => fill(&tr("The object {dn} does not exist."), &[("dn", dn)]),
    }
}

/// Message of a failed synchronization of the local copy, for the tooltip of the status
/// bar (`ErreurAnnuaire.message`, or the text of the exception).
pub fn sync_message(error: &SyncError, domain: &str) -> String {
    match error {
        SyncError::Failure(failure) => failure_problem(failure, domain).message,
        SyncError::Search(error) => search_problem(error, domain).message,
        SyncError::Line(LineError::Ranged(dn)) => fill(
            &tr("{dn}: member received by ranges, to complete first"),
            &[("dn", dn)],
        ),
        SyncError::Line(LineError::MemberWithoutGuid(dn)) => fill(
            &tr("{dn}: value of member without GUID (extended DN expected)"),
            &[("dn", dn)],
        ),
        SyncError::Line(LineError::NoGuid(dn)) => {
            fill(&tr("object without GUID: {dn}"), &[("dn", dn)])
        }
        SyncError::Store(error) => error.to_string(),
        SyncError::Unreadable(what) => fill(&tr("Unreadable on the DC: {quoi}"), &[("quoi", what)]),
        SyncError::Closed => tr("The connection has been closed."),
    }
}

/// The phrase of a refusal of the SYSVOL server (`_message_statut`).
fn status_message(code: u32, path: &str) -> String {
    let text = if sysvol::absent(code) {
        tr("“{chemin}” does not exist on the SYSVOL.")
    } else if code == status::OBJECT_NAME_COLLISION {
        tr("“{chemin}” already exists on the SYSVOL.")
    } else if code == status::ACCESS_DENIED {
        tr("Access denied to “{chemin}” on the SYSVOL.")
    } else if code == status::DIRECTORY_NOT_EMPTY {
        tr("The folder “{chemin}” is not empty.")
    } else if code == status::SHARING_VIOLATION {
        tr("“{chemin}” is open in another program.")
    } else {
        tr("The SYSVOL refused the operation on “{chemin}” (0x{statut:08X}).")
    };
    fill(
        &text,
        &[("chemin", path), ("statut:08X", &format!("{code:08X}"))],
    )
}

/// A SYSVOL error (`ErreurSysvol`, `erreur_session`): the class of the Python core, the
/// message, the detail; `ticket` and `kerberos` as `traduire`.
pub fn sysvol_problem(error: &SysvolError, dc: &str) -> (&'static str, Problem) {
    match error {
        SysvolError::Status {
            status: code,
            path,
            detail,
        }
        | SysvolError::Reread {
            status: code,
            path,
            detail,
        } => (
            "ErreurSysvol",
            Problem::new(status_message(*code, path), detail.clone()),
        ),
        SysvolError::Session(e) => {
            let detail = e.to_string();
            let (class, template) = match e.kind {
                ErrorKind::Unreachable | ErrorKind::Timeout => (
                    "ErreurInjoignable",
                    tr("The SYSVOL of {dc} is not responding."),
                ),
                ErrorKind::Ticket => (
                    "ErreurTicket",
                    tr("No valid Kerberos ticket to read the SYSVOL of {dc}."),
                ),
                ErrorKind::NoEncryption => (
                    "ErreurSecurite",
                    tr("{dc} cannot encrypt the SMB session (SMB 3 required)."),
                ),
                ErrorKind::Smb2Only => (
                    "ErreurSecurite",
                    tr(
                        "{dc} only offers SMB 2, which cannot encrypt the SYSVOL session. For an older domain controller, enable “Allow SMB 2 with signing only” in the domain profile.",
                    ),
                ),
                ErrorKind::Kerberos => (
                    "ErreurKerberos",
                    tr("Kerberos refuses the SMB session with {dc}."),
                ),
                ErrorKind::Status(_) | ErrorKind::Protocol => {
                    ("ErreurAnnuaire", tr("Unable to read the SYSVOL of {dc}."))
                }
            };
            let mut problem = Problem::new(fill(&template, &[("dc", dc)]), detail);
            problem.ticket = class == "ErreurTicket";
            problem.kerberos = class == "ErreurKerberos";
            (class, problem)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        let ticket = LdapError::new(
            code::LOCAL_ERROR,
            "SASL(-1): generic failure: GSSAPI Error: No Kerberos credentials available",
        );
        let p = ldap_problem(&ticket, "dc1.lab.test");
        assert!(p.ticket && !p.kerberos);
        assert_eq!(
            p.message,
            "No valid Kerberos ticket for this domain: get one (kinit)."
        );
        let down = LdapError::server_down("");
        assert_eq!(
            ldap_problem(&down, "dc1.lab.test").message,
            "The domain controller is not responding (dc1.lab.test)."
        );
        let exists = LdapError::new(code::ALREADY_EXISTS, "");
        assert_eq!(
            ldap_problem(&exists, "").message,
            "An object with this name already exists."
        );
    }
}

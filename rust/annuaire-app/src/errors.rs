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
use annuaire_core::srvsvc::{self, werror};
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

/// Why the owner of a file or folder could not be written (J8.7, ADR 0023 § 5): the right or
/// the privilege the server asks, as the lab measured it on Samba and Windows.
pub fn owner_refusal(code: u32, path: &str) -> String {
    let text = match code {
        status::ACCESS_DENIED => tr(
            "The server refuses this account to take ownership of “{chemin}”: it needs the “Take ownership” permission on the element, or the “Take ownership of files or other objects” privilege (SeTakeOwnershipPrivilege) on the server; on Windows, the “Restore files and directories” privilege (SeRestorePrivilege) also gives it.",
        ),
        // STATUS_INVALID_OWNER
        0xC000_005A => tr(
            "The server refuses this owner for “{chemin}”: giving ownership to another account, or to a group the account is not a member of, needs the “Restore files and directories” privilege (SeRestorePrivilege) on the server.",
        ),
        // STATUS_PRIVILEGE_NOT_HELD
        0xC000_0061 => tr(
            "The server refuses to change the owner of “{chemin}”: the account does not hold the privilege it needs (SeTakeOwnershipPrivilege or SeRestorePrivilege).",
        ),
        _ => tr("The server refused to change the owner of “{chemin}” (0x{statut:08X})."),
    };
    fill(
        &text,
        &[("chemin", path), ("statut:08X", &format!("{code:08X}"))],
    )
}

/// Why the auditing entries (SACL) of a file or folder could not be read or written (J8.7).
pub fn audit_refusal(code: u32, path: &str) -> String {
    let text = match code {
        // STATUS_PRIVILEGE_NOT_HELD
        0xC000_0061 => tr(
            "The server refuses the auditing entries of “{chemin}” to this account: it needs the “Manage auditing and security log” privilege (SeSecurityPrivilege) on the server.",
        ),
        status::ACCESS_DENIED => tr(
            "The server refuses to write the auditing entries of “{chemin}”: besides SeSecurityPrivilege, the account needs the “Change permissions” permission on the element.",
        ),
        _ => tr("The server refused the auditing entries of “{chemin}” (0x{statut:08X})."),
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

/// An error of a file or folder of a share (ADR 0023 § 5): refusals in clear, session errors
/// naming the file server rather than the SYSVOL.
pub fn file_problem(error: &SysvolError, server: &str) -> Problem {
    let SysvolError::Session(e) = error else {
        return sysvol_problem(error, server).1;
    };
    let template = match e.kind {
        ErrorKind::Unreachable | ErrorKind::Timeout => tr("{serveur} is not responding."),
        ErrorKind::Ticket => tr("No valid Kerberos ticket to open the share on {serveur}."),
        ErrorKind::NoEncryption => tr(
            "{serveur} cannot encrypt the SMB session (SMB 3 required, or SMB 2 with signing allowed in the domain profile).",
        ),
        // A file server limited to SMB 2 (ADR 0021): the option of the profile to enable.
        ErrorKind::Smb2Only => tr(
            "{serveur} only offers SMB 2, which cannot encrypt the session. For an older server, enable “Allow SMB 2 with signing only” in the domain profile.",
        ),
        ErrorKind::Kerberos => tr("Kerberos refuses the SMB session with {serveur}."),
        // STATUS_BAD_NETWORK_NAME
        ErrorKind::Status(0xC000_00CC) => tr("This share does not exist on {serveur}."),
        ErrorKind::Status(status::ACCESS_DENIED) => {
            tr("{serveur} refuses this account access to the share.")
        }
        ErrorKind::Status(_) | ErrorKind::Protocol => tr("Unable to read the share on {serveur}."),
    };
    let mut problem = Problem::new(fill(&template, &[("serveur", server)]), e.to_string());
    problem.ticket = e.kind == ErrorKind::Ticket;
    problem.kerberos = e.kind == ErrorKind::Kerberos;
    problem
}

/// `ERROR_ALREADY_EXISTS`: a key of Samba's registry configuration that is there already.
const ALREADY_EXISTS: u32 = annuaire_core::winreg::werror::ALREADY_EXISTS;

/// The phrase of a Win32 refusal of the share service, or of Samba's registry configuration
/// (ADR 0023 § 4 and § 9).
fn share_refusal(code: u32, server: &str) -> String {
    let text = match code {
        werror::ACCESS_DENIED => tr(
            "{serveur} refuses the operation on its shares. On Samba, the account needs SeDiskOperatorPrivilege (net rpc rights grant), for the shares and for their registry configuration; a share defined in smb.conf is created, changed or deleted only through the add, change and delete share commands.",
        ),
        werror::NERR_DUPLICATE_SHARE | werror::FILE_EXISTS | ALREADY_EXISTS => {
            tr("A share with this name already exists on {serveur}.")
        }
        werror::NERR_NET_NAME_NOT_FOUND => tr("This share does not exist on {serveur}."),
        werror::NERR_UNKNOWN_DEVICE_DIR
        | werror::FILE_NOT_FOUND
        | werror::PATH_NOT_FOUND
        | werror::BAD_PATHNAME => tr("The folder does not exist on {serveur}: create it first."),
        werror::INVALID_NAME => {
            tr("{serveur} refuses this share name, or does not have this share.")
        }
        werror::INVALID_PARAMETER => tr("{serveur} refuses a value of the share."),
        werror::NOT_SUPPORTED | werror::INVALID_LEVEL => {
            tr("{serveur} does not support this operation on its shares.")
        }
        _ => tr("{serveur} refused the operation on its shares (Win32 error {code})."),
    };
    fill(&text, &[("serveur", server), ("code", &code.to_string())])
}

/// An error of the share service of a file server (`ErreurPartage`): refusals in clear,
/// session errors as for the SYSVOL; `ticket` and `kerberos` as `traduire`.
pub fn share_problem(error: &srvsvc::Error, server: &str) -> Problem {
    use annuaire_core::rpc::RpcError;
    let detail = error.to_string();
    let (message, ticket, kerberos) = match error {
        srvsvc::Error::Refused { code, .. } => (share_refusal(*code, server), false, false),
        srvsvc::Error::Rpc(RpcError::Smb(e)) => {
            let template = match e.kind {
                ErrorKind::Unreachable | ErrorKind::Timeout => tr("{serveur} is not responding."),
                ErrorKind::Ticket => tr("No valid Kerberos ticket for {serveur}."),
                ErrorKind::NoEncryption => {
                    tr("{serveur} cannot encrypt the SMB session (SMB 3 required).")
                }
                ErrorKind::Smb2Only => tr(
                    "{serveur} only offers SMB 2, which cannot encrypt the session. For an older server, enable “Allow SMB 2 with signing only” in the domain profile.",
                ),
                ErrorKind::Kerberos => tr("Kerberos refuses the SMB session with {serveur}."),
                ErrorKind::Status(status::ACCESS_DENIED) => {
                    tr("{serveur} refuses this account the list of its shares.")
                }
                ErrorKind::Status(_) | ErrorKind::Protocol => {
                    tr("Unable to read the shares of {serveur}.")
                }
            };
            (
                fill(&template, &[("serveur", server)]),
                e.kind == ErrorKind::Ticket,
                e.kind == ErrorKind::Kerberos,
            )
        }
        srvsvc::Error::Rpc(_) => (
            fill(
                &tr("{serveur} does not answer as a file server (share service)."),
                &[("serveur", server)],
            ),
            false,
            false,
        ),
    };
    Problem {
        ticket,
        kerberos,
        ..Problem::new(message, detail)
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

    #[test]
    fn file_server_limited_to_smb2() {
        // A file server, not the SYSVOL of a DC: the option of the profile named.
        let error = SysvolError::Session(annuaire_core::smb::SmbError::new(
            ErrorKind::Smb2Only,
            "no SMB 3 dialect in common (NEGOTIATE: STATUS_NOT_SUPPORTED)",
        ));
        assert_eq!(
            file_problem(&error, "fs1.lab.test").message,
            "fs1.lab.test only offers SMB 2, which cannot encrypt the session. For an older server, enable “Allow SMB 2 with signing only” in the domain profile."
        );
    }
}

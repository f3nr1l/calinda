// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Kerberos authentication of an SMB session, on the user's credential cache (GSSAPI, MIT).

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::error::{Error as GssError, MajorFlags};
use libgssapi::name::Name;
use libgssapi::oid::{GSS_INQ_SSPI_SESSION_KEY, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL, OidSet};

use super::spnego;

/// Why the authentication failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    /// No usable ticket in the cache (none, expired, cache unreadable).
    Ticket(String),
    /// Another refusal of Kerberos (unknown principal, clock skew, rejected by the server…).
    Kerberos(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ticket(d) | Self::Kerberos(d) => f.write_str(d),
        }
    }
}

impl std::error::Error for AuthError {}

/// Sorts a GSSAPI error the way `sysvol._traduire` sorts the text of smbprotocol.
fn sort(error: &GssError) -> AuthError {
    let text = error.to_string();
    let lower = text.to_lowercase();
    let ticket = error.major.contains(MajorFlags::GSS_S_NO_CRED)
        || error.major.contains(MajorFlags::GSS_S_CREDENTIALS_EXPIRED)
        || lower.contains("no credentials")
        || lower.contains("ticket expired")
        || lower.contains("credentials cache");
    if ticket {
        AuthError::Ticket(text)
    } else {
        AuthError::Kerberos(text)
    }
}

/// The client side of the security exchange of a session setup.
pub trait Authenticator {
    /// The next token to send: the first one for `None`, then one for each token of the
    /// server; `None` when there is nothing more to send.
    fn step(&mut self, input: Option<&[u8]>) -> Result<Option<Vec<u8>>, AuthError>;
    /// The exchange is over on the client side.
    fn complete(&self) -> bool;
    /// Key of the established context.
    fn session_key(&self) -> Result<Vec<u8>, AuthError>;
}

/// Kerberos through the credential cache (`KRB5CCNAME`), SPNEGO wrapping our own.
pub struct Kerberos {
    ctx: ClientCtx,
    started: bool,
}

impl std::fmt::Debug for Kerberos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kerberos")
            .field("started", &self.started)
            .finish()
    }
}

impl Kerberos {
    /// For the CIFS service of `server` in `realm`: `cifs/<server>@<REALM>`, a Kerberos
    /// name, not a host-based service, so that no DNS canonicalization applies.
    pub fn new(server: &str, realm: &str) -> Result<Self, AuthError> {
        let mut mechs = OidSet::new().map_err(|e| sort(&e))?;
        mechs.add(&GSS_MECH_KRB5).map_err(|e| sort(&e))?;
        let cred =
            Cred::acquire(None, None, CredUsage::Initiate, Some(&mechs)).map_err(|e| sort(&e))?;
        let target = format!("cifs/{}@{}", server.to_lowercase(), realm.to_uppercase());
        let name =
            Name::new(target.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL)).map_err(|e| sort(&e))?;
        let flags = CtxFlags::GSS_C_MUTUAL_FLAG
            | CtxFlags::GSS_C_INTEG_FLAG
            | CtxFlags::GSS_C_SEQUENCE_FLAG
            | CtxFlags::GSS_C_CONF_FLAG;
        Ok(Self {
            ctx: ClientCtx::new(Some(cred), name, flags, Some(&GSS_MECH_KRB5)),
            started: false,
        })
    }
}

impl Authenticator for Kerberos {
    fn step(&mut self, input: Option<&[u8]>) -> Result<Option<Vec<u8>>, AuthError> {
        if !self.started {
            // A hint from the server (in the negotiate response) is not an input of the
            // first step.
            self.started = true;
            let token = self.ctx.step(None, None).map_err(|e| sort(&e))?;
            return Ok(token.map(|t| spnego::init(&t)));
        }
        let Some(input) = input else {
            return Ok(None);
        };
        let response = spnego::response(input)
            .ok_or_else(|| AuthError::Kerberos("invalid SPNEGO response".into()))?;
        if response.state == Some(spnego::REJECT) {
            return Err(AuthError::Kerberos(
                "the server rejected Kerberos (SPNEGO)".into(),
            ));
        }
        match response.token {
            Some(token) if !self.ctx.is_complete() => {
                let next = self.ctx.step(Some(&token), None).map_err(|e| sort(&e))?;
                // The Kerberos mechanism is one round: nothing follows the AP-REP. A token
                // here would need its own SPNEGO wrapping, which no DC asks for.
                if next.is_some_and(|t| !t.is_empty()) {
                    return Err(AuthError::Kerberos(
                        "unexpected Kerberos continuation".into(),
                    ));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn complete(&self) -> bool {
        self.ctx.is_complete()
    }

    fn session_key(&self) -> Result<Vec<u8>, AuthError> {
        let values = self
            .ctx
            .inquire_sec_context_by_oid(&GSS_INQ_SSPI_SESSION_KEY)
            .map_err(|e| sort(&e))?;
        values
            .into_iter()
            .next()
            .filter(|k| !k.is_empty())
            .ok_or_else(|| AuthError::Kerberos("no session key".into()))
    }
}

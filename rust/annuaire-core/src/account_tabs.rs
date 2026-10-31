// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! What the account tabs of the sheet read and build (J9.3, ADR 0024): Kerberos delegation
//! (`userAccountControl`, `msDS-AllowedToDelegateTo`), resource-based constrained delegation
//! (`msDS-AllowedToActOnBehalfOfOtherIdentity`, a security descriptor read and written by the
//! SDDL codec), service principal names and their uniqueness in the forest (global catalog),
//! protection against accidental deletion as read on an object. The logon hours are a codec
//! (`annuaire_codecs::logon_hours`); the workstations a plain attribute.
//!
//! Nothing here writes: the sheet puts the values in its draft, and the draft becomes one
//! changeset by the common path (preview, verification, journal, inverse, ADR 0006).

use annuaire_codecs::Sid;
use annuaire_codecs::sd::{self, Ace, Acl, SecurityDescriptor};
use annuaire_codecs::sddl::{self, SddlError};
use annuaire_codecs::uac::UserAccountControl;

use crate::changes::Values;
use crate::connection::{Connection, Failure};
use crate::error::LdapError;
use crate::ldap3_session::Ldap3Dialer;
use crate::membership::MembershipError;
use crate::search::{self, SD_DACL};
use crate::session::{Scope, SearchRequest, Session};

pub const LOGON_HOURS: &str = "logonHours";
pub const WORKSTATIONS: &str = "userWorkstations";
pub const SPN: &str = "servicePrincipalName";
pub const DELEGATE_TO: &str = "msDS-AllowedToDelegateTo";
pub const RBCD: &str = "msDS-AllowedToActOnBehalfOfOtherIdentity";

// --- Kerberos delegation ------------------------------------------------------------------

/// The choice of the « Delegation » tab of ADUC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delegation {
    /// « Do not trust this account for delegation ».
    None,
    /// « Trust for delegation to any service (Kerberos only) »: `TRUSTED_FOR_DELEGATION`.
    Unconstrained,
    /// « Trust for delegation to specified services only » (`msDS-AllowedToDelegateTo`);
    /// `any_protocol`: « Use any authentication protocol », the protocol transition
    /// (`TRUSTED_TO_AUTH_FOR_DELEGATION`), otherwise « Use Kerberos only ».
    Constrained { any_protocol: bool },
}

const DELEGATION_FLAGS: u32 = UserAccountControl::TRUSTED_FOR_DELEGATION
    | UserAccountControl::TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION;

impl Delegation {
    /// As ADUC reads it: the flag of unconstrained delegation first, then the protocol
    /// transition, then a list of services.
    pub fn of(uac: u32, services: usize) -> Self {
        let flags = UserAccountControl(uac);
        if flags.contains(UserAccountControl::TRUSTED_FOR_DELEGATION) {
            Self::Unconstrained
        } else if flags.contains(UserAccountControl::TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) {
            Self::Constrained { any_protocol: true }
        } else if services > 0 {
            Self::Constrained {
                any_protocol: false,
            }
        } else {
            Self::None
        }
    }

    /// `userAccountControl` with the flags of this choice, the others kept.
    pub fn uac(self, uac: u32) -> u32 {
        let kept = uac & !DELEGATION_FLAGS;
        match self {
            Self::None
            | Self::Constrained {
                any_protocol: false,
            } => kept,
            Self::Unconstrained => kept | UserAccountControl::TRUSTED_FOR_DELEGATION,
            Self::Constrained { any_protocol: true } => {
                kept | UserAccountControl::TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION
            }
        }
    }

    /// The list of services is written only for a constrained delegation; otherwise it is
    /// emptied, as ADUC does.
    pub fn keeps_services(self) -> bool {
        matches!(self, Self::Constrained { .. })
    }
}

// --- Resource-based constrained delegation ------------------------------------------------

/// The rights Windows gives each account allowed (`Set-ADComputer
/// -PrincipalsAllowedToDelegateToAccount`): `CCDCLCSWRPWPDTLOCRSDRCWDWO`; only the allow
/// ACE counts for the KDC.
const RBCD_RIGHTS: &str = "CCDCLCSWRPWPDTLOCRSDRCWDWO";

/// Why the descriptor of `msDS-AllowedToActOnBehalfOfOtherIdentity` cannot be read or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RbcdError {
    Descriptor(String),
    Sddl(SddlError),
}

impl std::fmt::Display for RbcdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Descriptor(e) => write!(f, "msDS-AllowedToActOnBehalfOfOtherIdentity: {e}"),
            Self::Sddl(e) => write!(f, "msDS-AllowedToActOnBehalfOfOtherIdentity: {e}"),
        }
    }
}

impl From<SddlError> for RbcdError {
    fn from(e: SddlError) -> Self {
        Self::Sddl(e)
    }
}

fn rbcd_descriptor(values: &[Vec<u8>]) -> Result<Option<SecurityDescriptor>, RbcdError> {
    values
        .first()
        .map(|raw| {
            SecurityDescriptor::decode(raw).map_err(|e| RbcdError::Descriptor(e.to_string()))
        })
        .transpose()
}

fn allows(ace: &Ace) -> bool {
    ace.ace_type == sd::ACCESS_ALLOWED
}

/// The accounts allowed to delegate to this one: the SIDs of the allow ACEs of the
/// descriptor, in its order, without duplicate.
pub fn rbcd_sids(values: &[Vec<u8>]) -> Result<Vec<Sid>, RbcdError> {
    let mut sids = Vec::new();
    let aces = rbcd_descriptor(values)?
        .and_then(|d| d.dacl)
        .map(|d| d.aces)
        .unwrap_or_default();
    for sid in aces.iter().filter(|a| allows(a)).filter_map(Ace::sid) {
        if !sids.contains(&sid) {
            sids.push(sid);
        }
    }
    Ok(sids)
}

/// The descriptor in SDDL, for the eye (sheet, preview).
pub fn rbcd_sddl(values: &[Vec<u8>]) -> Result<Option<String>, RbcdError> {
    rbcd_descriptor(values)?
        .map(|d| sddl::sd_to_sddl(&d, None).map_err(RbcdError::from))
        .transpose()
}

/// The value to write so that exactly `sids` are allowed: the descriptor read, its allow
/// ACEs of the accounts removed taken out and those added put at the end, everything else
/// kept (deny ACEs, owner); a new descriptor as Windows writes it (`O:BAD:(A;;…;;;SID)`)
/// when there was none. No account and nothing else in the descriptor: the attribute is
/// emptied, as `Set-ADComputer -PrincipalsAllowedToDelegateToAccount $null` does.
pub fn rbcd_value(present: &[Vec<u8>], sids: &[Sid]) -> Result<Values, RbcdError> {
    let mut descriptor = match rbcd_descriptor(present)? {
        Some(d) => d,
        None => sddl::sd_from_sddl("O:BAD:", None, false)?,
    };
    let mut acl = descriptor.dacl.take().unwrap_or(Acl {
        revision: sd::ACL_REVISION_DS,
        aces: Vec::new(),
    });
    acl.aces
        .retain(|a| !allows(a) || a.sid().is_some_and(|s| sids.contains(&s)));
    for sid in sids {
        if !acl.aces.iter().any(|a| allows(a) && a.sid() == Some(*sid)) {
            acl.aces.push(sddl::ace_from_sddl(
                &format!("(A;;{RBCD_RIGHTS};;;{sid})"),
                None,
                false,
            )?);
        }
    }
    if acl.aces.is_empty() {
        return Ok(Vec::new());
    }
    descriptor.dacl = Some(acl);
    descriptor.control |= sd::SE_DACL_PRESENT;
    let bytes = descriptor
        .encode()
        .map_err(|e| RbcdError::Descriptor(e.to_string()))?;
    // The bytes read back unchanged: nothing to write.
    if present.first().is_some_and(|p| {
        SecurityDescriptor::decode(p).ok() == SecurityDescriptor::decode(&bytes).ok()
    }) {
        return Ok(present.to_vec());
    }
    Ok(vec![bytes])
}

// --- Service principal names ----------------------------------------------------------------

/// Why a service principal name is refused before any write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpnError {
    /// Not `service/host[:port][/name]`.
    Form(String),
}

/// `service/host[:port][/service name]` (MS-ADTS 2.2.21, form checked by the DC as well):
/// two to three parts, none empty, no space; the port, if any, a number.
pub fn check_spn(text: &str) -> Result<(), SpnError> {
    let refused = || Err(SpnError::Form(text.to_owned()));
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return refused();
    }
    let parts: Vec<&str> = text.split('/').collect();
    if !(2..=3).contains(&parts.len()) || parts.iter().any(|p| p.is_empty()) {
        return refused();
    }
    if let Some((host, port)) = parts.get(1).and_then(|h| h.rsplit_once(':'))
        && (host.is_empty() || port.parse::<u16>().is_err())
    {
        return refused();
    }
    Ok(())
}

/// The objects of the forest that carry `spn`, read on the global catalog of the DC the
/// connection is bound to (`servicePrincipalName` is in the partial attribute set), the
/// object `except` left out. Two accounts with the same SPN break Kerberos for that service
/// (`KRB_AP_ERR_MODIFIED`, or the KDC refuses with `KDC_ERR_PRINCIPAL_NOT_UNIQUE`). Blocking.
pub fn spn_owners(
    connection: &Connection,
    spn: &str,
    except: &str,
) -> Result<Vec<String>, Failure> {
    let dc = connection.run(true, |link| Ok(link.state.dc.clone()))?;
    let dialer = Ldap3Dialer {
        profile: connection.profile().clone(),
        delays: connection.delays(),
    };
    let ldap = |error: LdapError| Failure::Ldap {
        dc: dc.clone(),
        error,
    };
    let filter = search::eq(SPN, search::Value::Text(spn)).map_err(|e| {
        ldap(LdapError::new(
            crate::error::code::FILTER_ERROR,
            e.to_string(),
        ))
    })?;
    let mut dialed = dialer.connect_global_catalog(&dc).map_err(ldap)?;
    let answer = dialed.session.search_wait(
        SearchRequest {
            base: String::new(),
            scope: Scope::Subtree,
            filter,
            attributes: vec!["1.1".into()],
            controls: Vec::new(),
            size_limit: 0,
        },
        Some(connection.delays().operation),
    );
    dialed.session.unbind();
    let mut owners: Vec<String> = answer
        .map_err(ldap)?
        .into_entries()
        .into_iter()
        .map(|e| e.dn)
        .filter(|dn| !dn.eq_ignore_ascii_case(except))
        .collect();
    owners.sort();
    owners.dedup();
    Ok(owners)
}

/// An account of the domain that offers services, for the choice of the services of a
/// constrained delegation (« Add Services » of ADUC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub dn: String,
    pub name: String,
    pub spns: Vec<String>,
}

/// The accounts of the domain whose name, logon name or DNS name starts with `text` and that
/// have SPNs, sorted by name (50 at most). Blocking.
pub fn service_accounts(
    connection: &Connection,
    text: &str,
) -> Result<Vec<ServiceAccount>, MembershipError> {
    let text = text.trim();
    let names: Vec<String> = ["name", "sAMAccountName", "dNSHostName"]
        .iter()
        .filter_map(|a| search::starts_with(a, text).ok())
        .collect();
    let filter = format!(
        "(&(servicePrincipalName=*){})",
        search::or(&names).unwrap_or_default()
    );
    let base = connection.run(true, |link| {
        Ok(link.state.root_dse.default_naming_context.clone())
    })?;
    let entries =
        crate::membership::search_all(connection, &base, filter, vec!["name".into(), SPN.into()])?;
    let mut accounts: Vec<ServiceAccount> = entries
        .into_iter()
        .map(|e| {
            let text = |v: &Vec<u8>| String::from_utf8_lossy(v).into_owned();
            let mut spns: Vec<String> = e.values(SPN).iter().map(text).collect();
            spns.sort_by_key(|s| s.to_lowercase());
            ServiceAccount {
                name: e.values("name").first().map(text).unwrap_or_default(),
                dn: e.dn,
                spns,
            }
        })
        .collect();
    accounts.sort_by_key(|a| a.name.to_lowercase());
    accounts.truncate(50);
    Ok(accounts)
}

/// The bound account may write the RBCD descriptor of `dn`: the attribute is in its
/// `allowedAttributesEffective`, as the prior verification of a write requires. Both schemas
/// declare it `systemOnly`; Windows lets an administrator write it all the same, Samba 4.22
/// does not (« can only be modified as system »). Blocking.
pub fn rbcd_writable(connection: &Connection, dn: &str) -> Result<bool, Failure> {
    let dn = dn.to_owned();
    connection.run(true, move |link| {
        let entry = search::read_entry(
            link.session.as_mut(),
            &dn,
            &["allowedAttributesEffective".to_owned()],
            "(objectClass=*)",
            None,
            Some(link.timeout),
        )?;
        Ok(entry.is_some_and(|e| {
            e.values("allowedAttributesEffective")
                .iter()
                .any(|v| v.eq_ignore_ascii_case(RBCD.as_bytes()))
        }))
    })
}

// --- Protection against accidental deletion -------------------------------------------------

/// The object is protected against accidental deletion: an explicit deny of « delete » and
/// « delete subtree » to Everyone on it, whoever set it (ADUC, ADAC, `Set-ADObject
/// -ProtectedFromAccidentalDeletion`, Calinda). Read on `connection`, DACL alone. Blocking.
pub fn read_protection(connection: &Connection, dn: &str) -> Result<Option<bool>, Failure> {
    let dn = dn.to_owned();
    connection.run(true, move |link| {
        let entry = search::read_entry(
            link.session.as_mut(),
            &dn,
            &[crate::actions::SD.to_owned()],
            "(objectClass=*)",
            Some(SD_DACL),
            Some(link.timeout),
        )?;
        Ok(entry.and_then(|e| {
            e.values(crate::actions::SD)
                .first()
                .and_then(|raw| SecurityDescriptor::decode(raw).ok())
                .map(|d| d.is_protected())
        }))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    #[test]
    fn delegation_choices() {
        let normal = UserAccountControl::NORMAL_ACCOUNT;
        assert_eq!(Delegation::of(normal, 0), Delegation::None);
        assert_eq!(
            Delegation::of(normal, 2),
            Delegation::Constrained {
                any_protocol: false
            }
        );
        let t2a = normal | UserAccountControl::TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION;
        assert_eq!(
            Delegation::of(t2a, 1),
            Delegation::Constrained { any_protocol: true }
        );
        let any = normal | UserAccountControl::TRUSTED_FOR_DELEGATION;
        assert_eq!(Delegation::of(any, 3), Delegation::Unconstrained);
        assert_eq!(Delegation::Unconstrained.uac(t2a), any);
        assert_eq!(Delegation::None.uac(any | 2), normal | 2);
        assert_eq!(Delegation::Constrained { any_protocol: true }.uac(any), t2a);
        assert!(!Delegation::Unconstrained.keeps_services());
    }

    #[test]
    fn rbcd_as_windows_writes_it() {
        let a = sid("S-1-5-21-1-2-3-1105");
        let b = sid("S-1-5-21-1-2-3-1106");
        let written = rbcd_value(&[], &[a]).unwrap();
        assert_eq!(written.len(), 1);
        assert_eq!(
            rbcd_sddl(&written).unwrap().unwrap(),
            "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1105)"
        );
        assert_eq!(rbcd_sids(&written).unwrap(), vec![a]);
        let both = rbcd_value(&written, &[a, b]).unwrap();
        assert_eq!(rbcd_sids(&both).unwrap(), vec![a, b]);
        assert_eq!(rbcd_value(&both, &[a, b]).unwrap(), both);
        assert_eq!(
            rbcd_sids(&rbcd_value(&both, &[b]).unwrap()).unwrap(),
            vec![b]
        );
        assert!(rbcd_value(&both, &[]).unwrap().is_empty());
        // A deny written by another tool is kept, the attribute then stays.
        let with_deny = sddl::sd_from_sddl(
            "O:BAD:(D;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1107)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1105)",
            None,
            false,
        )
        .unwrap()
        .encode()
        .unwrap();
        let kept = rbcd_value(&[with_deny], &[]).unwrap();
        assert_eq!(
            rbcd_sddl(&kept).unwrap().unwrap(),
            "O:BAD:(D;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-1-2-3-1107)"
        );
        assert!(rbcd_sids(&kept).unwrap().is_empty());
        assert!(rbcd_sids(&[b"junk".to_vec()]).is_err());
    }

    #[test]
    fn spn_forms() {
        for good in [
            "HTTP/web.lab.test",
            "MSSQLSvc/sql.lab.test:1433",
            "ldap/dc1.lab.test/lab.test",
            "HOST/WEB",
        ] {
            assert_eq!(check_spn(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "HTTP",
            "HTTP/",
            "/web",
            "HTTP/web lab",
            "HTTP/web:port",
            "a/b/c/d",
        ] {
            assert!(check_spn(bad).is_err(), "{bad}");
        }
    }
}

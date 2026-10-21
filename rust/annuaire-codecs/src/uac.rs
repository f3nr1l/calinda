// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Flags of accounts and groups: `userAccountControl`, `groupType`, `sAMAccountType`.
//!
//! The three attributes are signed 32-bit integers (syntax `Integer`). Flag names are those
//! of Samba without prefix (`UF_`, `GROUP_TYPE_`, `GTYPE_`, `ATYPE_`); values from MS-ADTS
//! 2.2.16 (`userAccountControl`), MS-ADTS 2.2.12 and MS-SAMR 2.2.1.11 (`groupType`),
//! MS-SAMR 2.2.1.9 (`sAMAccountType`).

use std::fmt;

/// Why a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UacError {
    /// Unknown `sAMAccountType`.
    UnknownSamAccountType(i32),
    /// A Builtin group is always a security group.
    BuiltinDistribution,
}

impl fmt::Display for UacError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSamAccountType(v) => write!(f, "unknown sAMAccountType: {v:#x}"),
            Self::BuiltinDistribution => write!(f, "a Builtin group is always a security group"),
        }
    }
}

impl std::error::Error for UacError {}

/// The flag of `table` present in `value`, in increasing order of value.
fn names(value: u32, table: &'static [(u32, &'static str)]) -> Vec<&'static str> {
    table
        .iter()
        .filter(|(bit, _)| value & bit != 0)
        .map(|&(_, name)| name)
        .collect()
}

// --- userAccountControl ---------------------------------------------------------------------

/// Flags of `userAccountControl` (MS-ADTS 2.2.16); unknown bits are kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct UserAccountControl(pub u32);

impl UserAccountControl {
    pub const SCRIPT: u32 = 0x0000_0001;
    pub const ACCOUNTDISABLE: u32 = 0x0000_0002;
    pub const HOMEDIR_REQUIRED: u32 = 0x0000_0008;
    pub const LOCKOUT: u32 = 0x0000_0010;
    pub const PASSWD_NOTREQD: u32 = 0x0000_0020;
    pub const PASSWD_CANT_CHANGE: u32 = 0x0000_0040;
    pub const ENCRYPTED_TEXT_PASSWORD_ALLOWED: u32 = 0x0000_0080;
    pub const TEMP_DUPLICATE_ACCOUNT: u32 = 0x0000_0100;
    pub const NORMAL_ACCOUNT: u32 = 0x0000_0200;
    pub const INTERDOMAIN_TRUST_ACCOUNT: u32 = 0x0000_0800;
    pub const WORKSTATION_TRUST_ACCOUNT: u32 = 0x0000_1000;
    pub const SERVER_TRUST_ACCOUNT: u32 = 0x0000_2000;
    pub const DONT_EXPIRE_PASSWD: u32 = 0x0001_0000;
    pub const MNS_LOGON_ACCOUNT: u32 = 0x0002_0000;
    pub const SMARTCARD_REQUIRED: u32 = 0x0004_0000;
    pub const TRUSTED_FOR_DELEGATION: u32 = 0x0008_0000;
    pub const NOT_DELEGATED: u32 = 0x0010_0000;
    pub const USE_DES_KEY_ONLY: u32 = 0x0020_0000;
    pub const DONT_REQUIRE_PREAUTH: u32 = 0x0040_0000;
    pub const PASSWORD_EXPIRED: u32 = 0x0080_0000;
    pub const TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION: u32 = 0x0100_0000;
    pub const NO_AUTH_DATA_REQUIRED: u32 = 0x0200_0000;
    pub const PARTIAL_SECRETS_ACCOUNT: u32 = 0x0400_0000;
    pub const USE_AES_KEYS: u32 = 0x0800_0000;

    const NAMES: &[(u32, &str)] = &[
        (Self::SCRIPT, "SCRIPT"),
        (Self::ACCOUNTDISABLE, "ACCOUNTDISABLE"),
        (Self::HOMEDIR_REQUIRED, "HOMEDIR_REQUIRED"),
        (Self::LOCKOUT, "LOCKOUT"),
        (Self::PASSWD_NOTREQD, "PASSWD_NOTREQD"),
        (Self::PASSWD_CANT_CHANGE, "PASSWD_CANT_CHANGE"),
        (
            Self::ENCRYPTED_TEXT_PASSWORD_ALLOWED,
            "ENCRYPTED_TEXT_PASSWORD_ALLOWED",
        ),
        (Self::TEMP_DUPLICATE_ACCOUNT, "TEMP_DUPLICATE_ACCOUNT"),
        (Self::NORMAL_ACCOUNT, "NORMAL_ACCOUNT"),
        (Self::INTERDOMAIN_TRUST_ACCOUNT, "INTERDOMAIN_TRUST_ACCOUNT"),
        (Self::WORKSTATION_TRUST_ACCOUNT, "WORKSTATION_TRUST_ACCOUNT"),
        (Self::SERVER_TRUST_ACCOUNT, "SERVER_TRUST_ACCOUNT"),
        (Self::DONT_EXPIRE_PASSWD, "DONT_EXPIRE_PASSWD"),
        (Self::MNS_LOGON_ACCOUNT, "MNS_LOGON_ACCOUNT"),
        (Self::SMARTCARD_REQUIRED, "SMARTCARD_REQUIRED"),
        (Self::TRUSTED_FOR_DELEGATION, "TRUSTED_FOR_DELEGATION"),
        (Self::NOT_DELEGATED, "NOT_DELEGATED"),
        (Self::USE_DES_KEY_ONLY, "USE_DES_KEY_ONLY"),
        (Self::DONT_REQUIRE_PREAUTH, "DONT_REQUIRE_PREAUTH"),
        (Self::PASSWORD_EXPIRED, "PASSWORD_EXPIRED"),
        (
            Self::TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION,
            "TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION",
        ),
        (Self::NO_AUTH_DATA_REQUIRED, "NO_AUTH_DATA_REQUIRED"),
        (Self::PARTIAL_SECRETS_ACCOUNT, "PARTIAL_SECRETS_ACCOUNT"),
        (Self::USE_AES_KEYS, "USE_AES_KEYS"),
    ];

    /// Flags of a stored (signed) value.
    pub fn decode(value: i32) -> Self {
        Self(value as u32)
    }

    /// Signed value to store.
    pub fn encode(self) -> i32 {
        self.0 as i32
    }

    pub fn contains(self, flag: u32) -> bool {
        self.0 & flag == flag
    }

    /// Names of the known flags present, in increasing order of value.
    pub fn names(self) -> Vec<&'static str> {
        names(self.0, Self::NAMES)
    }
}

// --- groupType ---------------------------------------------------------------------------------

/// Flags of `groupType` (MS-ADTS 2.2.12).
pub mod group_flags {
    pub const BUILTIN_LOCAL_GROUP: u32 = 0x0000_0001;
    pub const ACCOUNT_GROUP: u32 = 0x0000_0002;
    pub const RESOURCE_GROUP: u32 = 0x0000_0004;
    pub const UNIVERSAL_GROUP: u32 = 0x0000_0008;
    pub const APP_BASIC_GROUP: u32 = 0x0000_0010;
    pub const APP_QUERY_GROUP: u32 = 0x0000_0020;
    pub const SECURITY_ENABLED: u32 = 0x8000_0000;

    pub(super) const NAMES: &[(u32, &str)] = &[
        (BUILTIN_LOCAL_GROUP, "BUILTIN_LOCAL_GROUP"),
        (ACCOUNT_GROUP, "ACCOUNT_GROUP"),
        (RESOURCE_GROUP, "RESOURCE_GROUP"),
        (UNIVERSAL_GROUP, "UNIVERSAL_GROUP"),
        (APP_BASIC_GROUP, "APP_BASIC_GROUP"),
        (APP_QUERY_GROUP, "APP_QUERY_GROUP"),
        (SECURITY_ENABLED, "SECURITY_ENABLED"),
    ];
}

/// Names of the known `groupType` flags present, in increasing order of value.
pub fn group_flag_names(flags: u32) -> Vec<&'static str> {
    names(flags, group_flags::NAMES)
}

/// Scope of a group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Builtin,
    Global,
    DomainLocal,
    Universal,
}

impl Scope {
    /// The name used by the test vectors (`builtin`, `global`, `domaine_local`, `universel`).
    pub fn vector_name(self) -> &'static str {
        match self {
            Self::Builtin => "builtin",
            Self::Global => "global",
            Self::DomainLocal => "domaine_local",
            Self::Universal => "universel",
        }
    }
}

/// The seven usual combinations of `groupType` (constants `GTYPE_*` of Samba).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum GType {
    SecurityBuiltinLocalGroup = 0x8000_0005,
    SecurityDomainLocalGroup = 0x8000_0004,
    SecurityGlobalGroup = 0x8000_0002,
    SecurityUniversalGroup = 0x8000_0008,
    DistributionGlobalGroup = 0x0000_0002,
    DistributionDomainLocalGroup = 0x0000_0004,
    DistributionUniversalGroup = 0x0000_0008,
}

impl GType {
    const ALL: [Self; 7] = [
        Self::SecurityBuiltinLocalGroup,
        Self::SecurityDomainLocalGroup,
        Self::SecurityGlobalGroup,
        Self::SecurityUniversalGroup,
        Self::DistributionGlobalGroup,
        Self::DistributionDomainLocalGroup,
        Self::DistributionUniversalGroup,
    ];

    pub fn from_value(value: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|g| *g as u32 == value)
    }

    /// Samba's name without `GTYPE_`.
    pub fn name(self) -> &'static str {
        match self {
            Self::SecurityBuiltinLocalGroup => "SECURITY_BUILTIN_LOCAL_GROUP",
            Self::SecurityDomainLocalGroup => "SECURITY_DOMAIN_LOCAL_GROUP",
            Self::SecurityGlobalGroup => "SECURITY_GLOBAL_GROUP",
            Self::SecurityUniversalGroup => "SECURITY_UNIVERSAL_GROUP",
            Self::DistributionGlobalGroup => "DISTRIBUTION_GLOBAL_GROUP",
            Self::DistributionDomainLocalGroup => "DISTRIBUTION_DOMAIN_LOCAL_GROUP",
            Self::DistributionUniversalGroup => "DISTRIBUTION_UNIVERSAL_GROUP",
        }
    }
}

/// `groupType` decoded.
///
/// `scope` is `None` for a combination outside the four scopes (AzMan application groups,
/// inconsistent values); `gtype` is `None` outside the seven usual combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupType {
    pub value: i32,
    pub scope: Option<Scope>,
    pub security: bool,
    pub gtype: Option<GType>,
}

impl GroupType {
    pub fn unsigned(&self) -> u32 {
        self.value as u32
    }

    /// Decodes the signed value of `groupType`.
    pub fn decode(value: i32) -> Self {
        use group_flags::*;
        let raw = value as u32;
        let scope = if raw & BUILTIN_LOCAL_GROUP != 0 {
            Some(Scope::Builtin)
        } else {
            let scopes = [
                (Scope::Global, ACCOUNT_GROUP),
                (Scope::DomainLocal, RESOURCE_GROUP),
                (Scope::Universal, UNIVERSAL_GROUP),
            ];
            let mut present = scopes.iter().filter(|(_, bit)| raw & bit != 0);
            match (present.next(), present.next()) {
                (Some((scope, _)), None) => Some(*scope),
                _ => None,
            }
        };
        Self {
            value,
            scope,
            security: raw & SECURITY_ENABLED != 0,
            gtype: GType::from_value(raw),
        }
    }

    /// Signed value of `groupType` for a scope and a kind.
    ///
    /// `Builtin` is accepted only as a security group (Builtin groups are made by the DC).
    pub fn encode(scope: Scope, security: bool) -> Result<i32, UacError> {
        use group_flags::*;
        let mut flags = match scope {
            Scope::Builtin if !security => return Err(UacError::BuiltinDistribution),
            Scope::Builtin => BUILTIN_LOCAL_GROUP | RESOURCE_GROUP,
            Scope::Global => ACCOUNT_GROUP,
            Scope::DomainLocal => RESOURCE_GROUP,
            Scope::Universal => UNIVERSAL_GROUP,
        };
        if security {
            flags |= SECURITY_ENABLED;
        }
        Ok(flags as i32)
    }
}

// --- sAMAccountType ----------------------------------------------------------------------------

/// Values of `sAMAccountType` (MS-SAMR 2.2.1.9), Samba's names `ATYPE_*`.
///
/// A universal group has the same type as a global group: only `groupType` tells them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum SamAccountType {
    DomainObject = 0x0000_0000,
    SecurityGlobalGroup = 0x1000_0000,
    DistributionGlobalGroup = 0x1000_0001,
    SecurityLocalGroup = 0x2000_0000,
    DistributionLocalGroup = 0x2000_0001,
    NormalAccount = 0x3000_0000,
    WorkstationTrust = 0x3000_0001,
    InterdomainTrust = 0x3000_0002,
    AppBasicGroup = 0x4000_0000,
    AppQueryGroup = 0x4000_0001,
}

impl SamAccountType {
    const ALL: [(Self, &'static str); 10] = [
        (Self::DomainObject, "DOMAIN_OBJECT"),
        (Self::SecurityGlobalGroup, "SECURITY_GLOBAL_GROUP"),
        (Self::DistributionGlobalGroup, "DISTRIBUTION_GLOBAL_GROUP"),
        (Self::SecurityLocalGroup, "SECURITY_LOCAL_GROUP"),
        (Self::DistributionLocalGroup, "DISTRIBUTION_LOCAL_GROUP"),
        (Self::NormalAccount, "NORMAL_ACCOUNT"),
        (Self::WorkstationTrust, "WORKSTATION_TRUST"),
        (Self::InterdomainTrust, "INTERDOMAIN_TRUST"),
        (Self::AppBasicGroup, "APP_BASIC_GROUP"),
        (Self::AppQueryGroup, "APP_QUERY_GROUP"),
    ];

    /// Type of SAM account; `UnknownSamAccountType` for an unknown value.
    pub fn decode(value: i32) -> Result<Self, UacError> {
        Self::ALL
            .iter()
            .find(|(t, _)| *t as i32 == value)
            .map(|(t, _)| *t)
            .ok_or(UacError::UnknownSamAccountType(value))
    }

    /// Samba's name without `ATYPE_`.
    pub fn name(self) -> &'static str {
        Self::ALL
            .iter()
            .find(|(t, _)| *t == self)
            .map_or("", |(_, n)| n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uac_keeps_unknown_bits() {
        let uac = UserAccountControl::decode(0x8000_0202_u32 as i32);
        assert_eq!(uac.names(), ["ACCOUNTDISABLE", "NORMAL_ACCOUNT"]);
        assert_eq!(uac.encode(), 0x8000_0202_u32 as i32);
    }

    #[test]
    fn group_types() {
        let builtin = GroupType::decode(-2_147_483_643);
        assert_eq!(builtin.scope, Some(Scope::Builtin));
        assert_eq!(builtin.gtype, Some(GType::SecurityBuiltinLocalGroup));
        assert!(builtin.security);
        assert_eq!(GroupType::encode(Scope::Builtin, true), Ok(-2_147_483_643));
        assert!(GroupType::encode(Scope::Builtin, false).is_err());
        let mixed = GroupType::decode(0x6);
        assert_eq!((mixed.scope, mixed.gtype), (None, None));
    }
}

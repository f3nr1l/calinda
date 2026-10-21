// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Object model: raw LDAP entries turned into typed, immutable AD objects.
//!
//! Port of `annuaire/core/modele.py`. [`object_from_entry`] chooses the kind from
//! `objectClass` and decodes the attributes with the codecs; no I/O. What depends on the
//! time or the domain (locked, expired) takes the instant and the policy as arguments.

use std::collections::BTreeMap;
use std::fmt;

use annuaire_codecs::guid::GuidError;
use annuaire_codecs::integer::{self, IntegerError, Width};
use annuaire_codecs::sid::SidError;
use annuaire_codecs::time::{self, TimeError, UtcTime};
use annuaire_codecs::uac::{GroupType, UserAccountControl};
use annuaire_codecs::{Guid, Sid};

use crate::session::{Attributes, Entry};

pub const COMMON_ATTRIBUTES: [&str; 7] = [
    "objectClass",
    "objectGUID",
    "name",
    "description",
    "whenCreated",
    "whenChanged",
    "uSNChanged",
];
pub const ACCOUNT_ATTRIBUTES: [&str; 11] = [
    "sAMAccountName",
    "objectSid",
    "userAccountControl",
    "primaryGroupID",
    "memberOf",
    "pwdLastSet",
    "accountExpires",
    "lockoutTime",
    "lastLogonTimestamp",
    "lastLogon",
    "userPrincipalName",
];
pub const USER_ATTRIBUTES: [&str; 4] = ["givenName", "sn", "displayName", "mail"];
pub const COMPUTER_ATTRIBUTES: [&str; 3] =
    ["dNSHostName", "operatingSystem", "operatingSystemVersion"];
pub const GROUP_ATTRIBUTES: [&str; 2] = ["groupType", "member"];
/// To read on the root of the domain (`defaultNamingContext`).
pub const POLICY_ATTRIBUTES: [&str; 3] = ["lockoutDuration", "lockoutThreshold", "maxPwdAge"];

/// Everything the model reads: to ask for to build any object (`modele.ATTRIBUTS`).
pub fn attributes() -> Vec<&'static str> {
    let mut all: Vec<&'static str> = Vec::new();
    for name in COMMON_ATTRIBUTES
        .iter()
        .chain(&ACCOUNT_ATTRIBUTES)
        .chain(&USER_ATTRIBUTES)
        .chain(&COMPUTER_ATTRIBUTES)
        .chain(&GROUP_ATTRIBUTES)
    {
        if !all.contains(name) {
            all.push(name);
        }
    }
    all
}

/// An attribute that the codecs refuse: better refuse than show a wrong value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelError {
    Utf8 {
        attribute: &'static str,
    },
    Integer {
        attribute: &'static str,
        error: IntegerError,
    },
    Time {
        attribute: &'static str,
        error: TimeError,
    },
    Guid(GuidError),
    Sid(SidError),
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Utf8 { attribute } => write!(f, "{attribute}: invalid UTF-8"),
            Self::Integer { attribute, error } => write!(f, "{attribute}: {error}"),
            Self::Time { attribute, error } => write!(f, "{attribute}: {error}"),
            Self::Guid(error) => write!(f, "objectGUID: {error}"),
            Self::Sid(error) => write!(f, "objectSid: {error}"),
        }
    }
}

impl std::error::Error for ModelError {}

// ---------------------------------------------------------------------------
// Reading raw values

fn values<'a>(attributes: &'a Attributes, name: &str) -> &'a [Vec<u8>] {
    attributes
        .iter()
        .find(|(n, _)| n == name)
        .or_else(|| {
            attributes
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
        })
        .map_or(&[], |(_, v)| v.as_slice())
}

fn first<'a>(attributes: &'a Attributes, name: &str) -> Option<&'a [u8]> {
    values(attributes, name).first().map(Vec::as_slice)
}

fn text(attributes: &Attributes, name: &'static str) -> Result<String, ModelError> {
    first(attributes, name).map_or(Ok(String::new()), |v| {
        String::from_utf8(v.to_vec()).map_err(|_| ModelError::Utf8 { attribute: name })
    })
}

fn texts(attributes: &Attributes, name: &'static str) -> Result<Vec<String>, ModelError> {
    values(attributes, name)
        .iter()
        .map(|v| String::from_utf8(v.clone()).map_err(|_| ModelError::Utf8 { attribute: name }))
        .collect()
}

fn integer(
    attributes: &Attributes,
    name: &'static str,
    width: Width,
) -> Result<Option<i64>, ModelError> {
    first(attributes, name)
        .map(|v| {
            integer::decode(v, width).map_err(|error| ModelError::Integer {
                attribute: name,
                error,
            })
        })
        .transpose()
}

fn date(attributes: &Attributes, name: &'static str) -> Result<Option<UtcTime>, ModelError> {
    let Some(value) = first(attributes, name) else {
        return Ok(None);
    };
    if !value.is_ascii() {
        return Err(ModelError::Utf8 { attribute: name });
    }
    let text = String::from_utf8_lossy(value);
    time::decode_generalized_time(&text)
        .map(Some)
        .map_err(|error| ModelError::Time {
            attribute: name,
            error,
        })
}

fn has_ranges(attributes: &Attributes, name: &str) -> bool {
    let prefix = format!("{};range=", name.to_lowercase());
    attributes
        .iter()
        .any(|(n, _)| n.to_lowercase().starts_with(&prefix))
}

// ---------------------------------------------------------------------------
// Policy of the domain

/// Settings of the domain that bear on the state of an account; raw durations, negative
/// hundreds of nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DomainPolicy {
    /// `lockoutDuration`; -2^63: locked until an administrator unlocks.
    pub lockout_duration: i64,
    /// `lockoutThreshold`; 0: no lockout.
    pub lockout_threshold: i64,
    /// `maxPwdAge`.
    pub max_password_age: i64,
}

impl Default for DomainPolicy {
    fn default() -> Self {
        Self {
            lockout_duration: time::DURATION_NEVER,
            lockout_threshold: 0,
            max_password_age: time::DURATION_NEVER,
        }
    }
}

/// Policy read on the root of the domain; absent values: the defaults (infinite lockout
/// duration, the careful choice).
pub fn policy_from_attributes(attributes: &Attributes) -> Result<DomainPolicy, ModelError> {
    let default = DomainPolicy::default();
    Ok(DomainPolicy {
        lockout_duration: integer(attributes, "lockoutDuration", Width::Bits64)?
            .unwrap_or(default.lockout_duration),
        lockout_threshold: integer(attributes, "lockoutThreshold", Width::Bits32)?
            .unwrap_or(default.lockout_threshold),
        max_password_age: integer(attributes, "maxPwdAge", Width::Bits64)?
            .unwrap_or(default.max_password_age),
    })
}

// ---------------------------------------------------------------------------
// Last activity

/// The attribute that gave the date of last activity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActivitySource {
    LastLogonTimestamp,
    LastLogon,
    PwdLastSet,
}

impl ActivitySource {
    /// Name of the attribute (value of `SourceActivite`).
    pub fn attribute(self) -> &'static str {
        match self {
            Self::LastLogonTimestamp => "lastLogonTimestamp",
            Self::LastLogon => "lastLogon",
            Self::PwdLastSet => "pwdLastSet",
        }
    }
}

/// Date of last activity of an account, with its source. `nttime` 0: no trace; `dc` only
/// for `lastLogon`, proper to each DC.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LastActivity {
    pub nttime: i64,
    pub source: Option<ActivitySource>,
    pub dc: Option<String>,
}

/// Most recent of the dates given (J1.6); 0 and "never" are ignored. `last_logons`:
/// `lastLogon` read on each DC. `pwd_last_set` only for a computer, whose password renews
/// itself every 30 days while it runs. On a tie, the order of the arguments wins.
pub fn compute_activity(
    last_logon_timestamp: Option<i64>,
    last_logons: &BTreeMap<String, i64>,
    pwd_last_set: Option<i64>,
) -> LastActivity {
    let mut candidates: Vec<LastActivity> = Vec::new();
    if let Some(n) = last_logon_timestamp {
        candidates.push(LastActivity {
            nttime: n,
            source: Some(ActivitySource::LastLogonTimestamp),
            dc: None,
        });
    }
    for (dc, &n) in last_logons {
        candidates.push(LastActivity {
            nttime: n,
            source: Some(ActivitySource::LastLogon),
            dc: Some(dc.clone()),
        });
    }
    if let Some(n) = pwd_last_set {
        candidates.push(LastActivity {
            nttime: n,
            source: Some(ActivitySource::PwdLastSet),
            dc: None,
        });
    }
    let mut best = LastActivity::default();
    for candidate in candidates {
        let never = candidate.nttime == 0 || candidate.nttime == time::NTTIME_NEVER;
        if !never && candidate.nttime > best.nttime {
            best = candidate;
        }
    }
    best
}

/// True if the last activity is before `threshold`. An account that never logged on is
/// judged on its creation date; without any date, it is inactive. Dates as NTTIME values,
/// whose order is the order of the dates.
pub fn is_inactive(activity: &LastActivity, created: Option<i64>, threshold: i64) -> bool {
    if activity.nttime != 0 {
        return activity.nttime < threshold;
    }
    created.is_none_or(|c| c < threshold)
}

// ---------------------------------------------------------------------------
// Objects

/// Kind of an object (`TypeObjet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    User,
    Computer,
    Group,
    Ou,
    Container,
    Contact,
    Unknown,
}

impl Kind {
    /// Value of `TypeObjet`.
    pub fn name(self) -> &'static str {
        match self {
            Self::User => "utilisateur",
            Self::Computer => "ordinateur",
            Self::Group => "groupe",
            Self::Ou => "ou",
            Self::Container => "conteneur",
            Self::Contact => "contact",
            Self::Unknown => "inconnu",
        }
    }
}

const CONTAINERS: [&str; 4] = ["container", "builtindomain", "lostandfound", "domaindns"];

/// Kind of the model from `objectClass` (without case).
pub fn kind_of(classes: &[String]) -> Kind {
    let lower: Vec<String> = classes.iter().map(|c| c.to_lowercase()).collect();
    let has = |c: &str| lower.iter().any(|l| l == c);
    if has("computer") {
        Kind::Computer
    } else if has("user") {
        Kind::User // inetOrgPerson derives from it too
    } else if has("group") {
        Kind::Group
    } else if has("contact") {
        Kind::Contact
    } else if has("organizationalunit") {
        Kind::Ou
    } else if CONTAINERS.iter().any(|c| has(c)) {
        Kind::Container
    } else {
        Kind::Unknown
    }
}

/// Attributes every object has.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Common {
    pub dn: String,
    /// `objectClass`, from the most general to the most specific.
    pub classes: Vec<String>,
    /// `name` (the RDN without escaping).
    pub name: String,
    pub guid: Option<Guid>,
    pub description: String,
    pub created: Option<UtcTime>,
    pub modified: Option<UtcTime>,
    /// `uSNChanged`, proper to the DC read.
    pub usn_changed: Option<i64>,
}

/// What users and computers have in common (class `user`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Account {
    pub sam_account_name: String,
    pub upn: String,
    pub sid: Option<Sid>,
    pub uac: u32,
    pub primary_group_id: Option<i64>,
    /// Direct groups, without the primary group (absent from `memberOf`).
    pub member_of: Vec<String>,
    pub pwd_last_set: Option<i64>,
    pub account_expires: Option<i64>,
    pub lockout_time: Option<i64>,
    pub last_logon_timestamp: Option<i64>,
    /// Proper to the DC that answered (not replicated).
    pub last_logon: Option<i64>,
}

impl Account {
    pub fn active(&self) -> bool {
        !UserAccountControl(self.uac).contains(UserAccountControl::ACCOUNTDISABLE)
    }

    pub fn password_never_expires(&self) -> bool {
        UserAccountControl(self.uac).contains(UserAccountControl::DONT_EXPIRE_PASSWD)
    }

    /// `pwdLastSet` = 0: change required at next logon (MS-ADA3).
    pub fn must_change_password(&self) -> bool {
        self.pwd_last_set == Some(0)
    }

    /// SID of the primary group: SID of the domain + `primaryGroupID` (J1.7).
    pub fn primary_group_sid(&self) -> Option<Sid> {
        let sid = self.sid?;
        let rid = u32::try_from(self.primary_group_id?).ok()?;
        sid.domain().ok()?.with_rid(rid).ok()
    }

    /// `accountExpires` is a past date (0 and the maximum: never).
    pub fn expired(&self, now: UtcTime) -> bool {
        match self.account_expires {
            None | Some(0) | Some(time::NTTIME_NEVER) => false,
            Some(expires) => time::utc_to_nttime(now).is_ok_and(|n| expires <= n),
        }
    }

    /// Lockout in progress (MS-ADTS 3.1.1.4.5.17, `msDS-User-Account-Control-Computed`):
    /// `lockoutTime` set, and an infinite lockout duration or an end still to come.
    pub fn locked(&self, policy: &DomainPolicy, now: UtcTime) -> bool {
        let Some(lockout) = self.lockout_time.filter(|&t| t != 0) else {
            return false;
        };
        if policy.lockout_duration == time::DURATION_NEVER {
            return true;
        }
        let Some(end) = lockout.checked_sub(policy.lockout_duration) else {
            return true;
        };
        time::utc_to_nttime(now).is_ok_and(|n| end > n)
    }

    fn logons(&self) -> BTreeMap<String, i64> {
        self.last_logon
            .map(|n| (String::new(), n))
            .into_iter()
            .collect()
    }
}

/// An AD object of the model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    User {
        common: Common,
        account: Account,
        given_name: String,
        surname: String,
        display_name: String,
        mail: String,
    },
    Computer {
        common: Common,
        account: Account,
        /// In lower case.
        dns_name: String,
        os: String,
        os_version: String,
    },
    Group {
        common: Common,
        sam_account_name: String,
        sid: Option<Sid>,
        group_type: Option<GroupType>,
        mail: String,
        member_of: Vec<String>,
        /// `member` as received; incomplete if `members_partial`: read by ranges then.
        members: Vec<String>,
        /// The server answered with a range (`member;range=…`, Windows beyond 1 500).
        members_partial: bool,
    },
    Contact {
        common: Common,
        display_name: String,
        mail: String,
    },
    Ou(Common),
    Container(Common),
    Unknown(Common),
}

impl Object {
    pub fn kind(&self) -> Kind {
        match self {
            Self::User { .. } => Kind::User,
            Self::Computer { .. } => Kind::Computer,
            Self::Group { .. } => Kind::Group,
            Self::Contact { .. } => Kind::Contact,
            Self::Ou(_) => Kind::Ou,
            Self::Container(_) => Kind::Container,
            Self::Unknown(_) => Kind::Unknown,
        }
    }

    pub fn common(&self) -> &Common {
        match self {
            Self::User { common, .. }
            | Self::Computer { common, .. }
            | Self::Group { common, .. }
            | Self::Contact { common, .. }
            | Self::Ou(common)
            | Self::Container(common)
            | Self::Unknown(common) => common,
        }
    }

    pub fn account(&self) -> Option<&Account> {
        match self {
            Self::User { account, .. } | Self::Computer { account, .. } => Some(account),
            _ => None,
        }
    }

    /// From the attributes read alone (one DC); a computer's password renewal counts.
    pub fn last_activity(&self) -> Option<LastActivity> {
        match self {
            Self::User { account, .. } => Some(compute_activity(
                account.last_logon_timestamp,
                &account.logons(),
                None,
            )),
            Self::Computer { account, .. } => Some(compute_activity(
                account.last_logon_timestamp,
                &account.logons(),
                account.pwd_last_set,
            )),
            _ => None,
        }
    }
}

fn common(dn: &str, attributes: &Attributes) -> Result<Common, ModelError> {
    Ok(Common {
        dn: dn.to_owned(),
        classes: texts(attributes, "objectClass")?,
        name: text(attributes, "name")?,
        guid: first(attributes, "objectGUID")
            .map(Guid::decode)
            .transpose()
            .map_err(ModelError::Guid)?,
        description: text(attributes, "description")?,
        created: date(attributes, "whenCreated")?,
        modified: date(attributes, "whenChanged")?,
        usn_changed: integer(attributes, "uSNChanged", Width::Bits64)?,
    })
}

fn sid(attributes: &Attributes) -> Result<Option<Sid>, ModelError> {
    first(attributes, "objectSid")
        .map(Sid::decode)
        .transpose()
        .map_err(ModelError::Sid)
}

fn account(attributes: &Attributes) -> Result<Account, ModelError> {
    let uac = integer(attributes, "userAccountControl", Width::Bits32)?;
    Ok(Account {
        sam_account_name: text(attributes, "sAMAccountName")?,
        upn: text(attributes, "userPrincipalName")?,
        sid: sid(attributes)?,
        uac: uac.map_or(0, |v| v as u32),
        primary_group_id: integer(attributes, "primaryGroupID", Width::Bits32)?,
        member_of: texts(attributes, "memberOf")?,
        pwd_last_set: integer(attributes, "pwdLastSet", Width::Bits64)?,
        account_expires: integer(attributes, "accountExpires", Width::Bits64)?,
        lockout_time: integer(attributes, "lockoutTime", Width::Bits64)?,
        last_logon_timestamp: integer(attributes, "lastLogonTimestamp", Width::Bits64)?,
        last_logon: integer(attributes, "lastLogon", Width::Bits64)?,
    })
}

/// Typed object from a raw LDAP entry (attributes: [`attributes`]). A malformed attribute is
/// an error (codecs): better refuse than show a wrong value.
pub fn object_from_entry(entry: &Entry) -> Result<Object, ModelError> {
    let attributes = &entry.attributes;
    let common = common(&entry.dn, attributes)?;
    Ok(match kind_of(&common.classes) {
        Kind::User => {
            let account = account(attributes)?;
            Object::User {
                given_name: text(attributes, "givenName")?,
                surname: text(attributes, "sn")?,
                display_name: text(attributes, "displayName")?,
                mail: text(attributes, "mail")?,
                common,
                account,
            }
        }
        Kind::Computer => {
            let account = account(attributes)?;
            Object::Computer {
                dns_name: text(attributes, "dNSHostName")?.to_lowercase(),
                os: text(attributes, "operatingSystem")?,
                os_version: text(attributes, "operatingSystemVersion")?,
                common,
                account,
            }
        }
        Kind::Group => {
            let group_type = integer(attributes, "groupType", Width::Bits32)?;
            Object::Group {
                sam_account_name: text(attributes, "sAMAccountName")?,
                sid: sid(attributes)?,
                group_type: group_type.map(|v| GroupType::decode(v as i32)),
                mail: text(attributes, "mail")?,
                member_of: texts(attributes, "memberOf")?,
                members: texts(attributes, "member")?,
                members_partial: has_ranges(attributes, "member"),
                common,
            }
        }
        Kind::Contact => Object::Contact {
            display_name: text(attributes, "displayName")?,
            mail: text(attributes, "mail")?,
            common,
        },
        Kind::Ou => Object::Ou(common),
        Kind::Container => Object::Container(common),
        Kind::Unknown => Object::Unknown(common),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(dn: &str, pairs: &[(&str, &[&[u8]])]) -> Entry {
        Entry {
            dn: dn.into(),
            attributes: pairs
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.iter().map(|b| b.to_vec()).collect()))
                .collect(),
        }
    }

    const SID: &[u8] = &[
        1, 5, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 0xE9, 3, 0, 0,
    ];

    #[test]
    fn builds_a_user() {
        let e = entry(
            "CN=a,DC=lab,DC=test",
            &[
                (
                    "objectClass",
                    &[b"top", b"person", b"organizationalPerson", b"user"],
                ),
                ("objectSid", &[SID]),
                ("userAccountControl", &[b"514"]),
                ("primaryGroupID", &[b"513"]),
                ("whenCreated", &[b"20261013120000.0Z"]),
                ("pwdLastSet", &[b"0"]),
                ("givenName", &[b"Ana\xc3\xafs"]),
            ],
        );
        let object = object_from_entry(&e).unwrap();
        assert_eq!(object.kind(), Kind::User);
        let account = object.account().unwrap();
        assert!(!account.active() && account.must_change_password());
        assert_eq!(
            account.primary_group_sid().unwrap().to_string(),
            "S-1-5-21-1-2-3-513"
        );
        let Object::User { given_name, .. } = &object else {
            panic!()
        };
        assert_eq!(given_name, "Anaïs");
        assert!(object.common().created.is_some());
    }

    #[test]
    fn kinds_and_groups() {
        let names = |c: &[&str]| kind_of(&c.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>());
        assert_eq!(names(&["top", "user", "computer"]), Kind::Computer);
        assert_eq!(names(&["top", "inetOrgPerson", "user"]), Kind::User);
        assert_eq!(names(&["top", "builtinDomain"]), Kind::Container);
        assert_eq!(names(&["top", "domainDNS"]), Kind::Container);
        assert_eq!(names(&["top", "dnsNode"]), Kind::Unknown);
        let g = entry(
            "CN=g",
            &[
                ("objectClass", &[b"group"]),
                ("groupType", &[b"-2147483646"]),
                ("member;range=0-1499", &[b"CN=x"]),
            ],
        );
        let Object::Group {
            group_type,
            members_partial,
            members,
            ..
        } = object_from_entry(&g).unwrap()
        else {
            panic!()
        };
        assert!(members_partial && members.is_empty());
        assert!(group_type.unwrap().security);
        let bad = entry(
            "CN=b",
            &[("objectClass", &[b"user"]), ("objectSid", &[b"x"])],
        );
        assert!(matches!(object_from_entry(&bad), Err(ModelError::Sid(_))));
        let bad = entry("CN=b", &[("objectClass", &[b"user"]), ("name", &[b"\xff"])]);
        assert!(matches!(
            object_from_entry(&bad),
            Err(ModelError::Utf8 { .. })
        ));
    }

    #[test]
    fn activity_and_lockout() {
        let mut logons = BTreeMap::new();
        logons.insert("dc2".to_owned(), 300);
        logons.insert("dc1".to_owned(), 300);
        let a = compute_activity(Some(200), &logons, Some(time::NTTIME_NEVER));
        assert_eq!((a.nttime, a.dc.as_deref()), (300, Some("dc1")));
        assert_eq!(
            compute_activity(None, &BTreeMap::new(), None),
            LastActivity::default()
        );
        let account = Account {
            lockout_time: Some(1_000),
            ..Account::default()
        };
        let now = time::nttime_to_utc(2_000).unwrap().unwrap();
        assert!(account.locked(&DomainPolicy::default(), now));
        let policy = DomainPolicy {
            lockout_duration: -500,
            ..DomainPolicy::default()
        };
        assert!(!account.locked(&policy, now));
        assert!(!Account::default().expired(now));
        assert_eq!(attributes().len(), 27);
    }
}

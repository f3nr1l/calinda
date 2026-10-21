// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Security settings of a GPO (J7.5, `annuaire.core.strategie_securite`): password, lockout,
//! user rights, restricted groups; and their effect on the domain object (ADR 0014).
//!
//! The content is that of `GptTmpl.inf` (`annuaire_codecs::gpt_tmpl`). This module gives its
//! meaning:
//!
//! - the settings of `[System Access]` the « Password Policy » and « Account Lockout Policy »
//!   pages show, with their bounds (those of the GPMC editor) and the attribute of the domain
//!   object that matches them;
//! - the rights of `[Privilege Rights]` (their names in the Windows editor are said by the
//!   interface);
//! - the scope of the account policy: **it holds for the accounts of the domain only from a GPO
//!   linked to the root of the domain**. Linked to an OU, it only sets the local accounts of the
//!   computers of the OU;
//! - the writing into the domain object. Under Windows, the PDC emulator itself applies the
//!   policy of the GPOs linked to the domain to the domain object (`minPwdLength`,
//!   `lockoutThreshold`…), at each refresh of its policy. Samba does not (except with `apply
//!   group policies = yes`, and then for four settings only): the KDC and the password check
//!   read the attributes of the domain object, which `samba-tool domain passwordsettings set`
//!   writes. The tool thus writes them too, in the same changeset as the GPO, when the DC is a
//!   Samba (`vendorName` of the RootDSE).
//!
//! The texts (titles, explanations, units) are those of the interface.

use std::collections::BTreeMap;
use std::sync::Arc;

use annuaire_codecs::gplink::GpLink;
use annuaire_codecs::gpt_tmpl::{self as gt, Inf};
use annuaire_codecs::time;

use crate::changes::{Change, Changeset, Operation, Read};
use crate::connection::{Connection, Link};
use crate::error::code;
use crate::gpo::Part;
use crate::gpo_content::{self as gc, ContentChange, ContentRead};
use crate::gpo_write::{self as gw, GpoError, Step};
use crate::messages::{Catalog, Msg};
use crate::session::{Entry, Scope};
use crate::sysvol;
use crate::sysvol_write::SysvolSession;

/// Hundreds of nanoseconds.
const MINUTE: i64 = 60 * time::TICKS_PER_SECOND;
const DAY: i64 = 24 * 60 * MINUTE;

/// `pwdProperties`: complexity required (MS-SAMR 2.2.3.10).
pub const DOMAIN_PASSWORD_COMPLEX: i64 = 0x1;
/// `pwdProperties`: passwords stored with reversible encryption.
pub const DOMAIN_PASSWORD_STORE_CLEARTEXT: i64 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Page {
    Password,
    Lockout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Number,
    Boolean,
}

/// A setting of `[System Access]` the tool shows (`Reglage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingDef {
    pub key: &'static str,
    pub page: Page,
    pub kind: Kind,
    pub minimum: i64,
    pub maximum: i64,
    /// Value that, in the file, says « no limit » (`-1`); `None` if the setting has none.
    pub never: Option<i64>,
    /// Attribute of the domain object carrying this setting.
    pub attribute: &'static str,
    /// Value proposed when the setting is defined (that of the GPMC or of Windows).
    pub suggested: i64,
}

const fn number(
    key: &'static str,
    page: Page,
    minimum: i64,
    maximum: i64,
    never: Option<i64>,
    attribute: &'static str,
    suggested: i64,
) -> SettingDef {
    SettingDef {
        key,
        page,
        kind: Kind::Number,
        minimum,
        maximum,
        never,
        attribute,
        suggested,
    }
}

const fn boolean(key: &'static str, suggested: i64) -> SettingDef {
    SettingDef {
        key,
        page: Page::Password,
        kind: Kind::Boolean,
        minimum: 0,
        maximum: 1,
        never: None,
        attribute: "pwdProperties",
        suggested,
    }
}

pub const SETTINGS: [SettingDef; 9] = [
    number(
        "PasswordHistorySize",
        Page::Password,
        0,
        24,
        None,
        "pwdHistoryLength",
        24,
    ),
    number(
        "MaximumPasswordAge",
        Page::Password,
        1,
        999,
        Some(-1),
        "maxPwdAge",
        42,
    ),
    number(
        "MinimumPasswordAge",
        Page::Password,
        0,
        998,
        None,
        "minPwdAge",
        1,
    ),
    number(
        "MinimumPasswordLength",
        Page::Password,
        0,
        14,
        None,
        "minPwdLength",
        7,
    ),
    boolean("PasswordComplexity", 1),
    boolean("ClearTextPassword", 0),
    number(
        "LockoutBadCount",
        Page::Lockout,
        0,
        999,
        None,
        "lockoutThreshold",
        10,
    ),
    number(
        "LockoutDuration",
        Page::Lockout,
        1,
        99999,
        Some(-1),
        "lockoutDuration",
        10,
    ),
    number(
        "ResetLockoutCount",
        Page::Lockout,
        1,
        99999,
        None,
        "lockOutObservationWindow",
        10,
    ),
];

pub const DOMAIN_ATTRIBUTES: [&str; 8] = [
    "minPwdLength",
    "pwdHistoryLength",
    "minPwdAge",
    "maxPwdAge",
    "pwdProperties",
    "lockoutThreshold",
    "lockoutDuration",
    "lockOutObservationWindow",
];

pub fn setting(key: &str) -> Option<&'static SettingDef> {
    SETTINGS.iter().find(|r| r.key.eq_ignore_ascii_case(key))
}

pub fn settings(page: Page) -> impl Iterator<Item = &'static SettingDef> {
    SETTINGS.iter().filter(move |r| r.page == page)
}

/// A user right (`[Privilege Rights]`): the name of its constant, and whether it gives in
/// practice the control of the machine (to grant to administrators only) (`Droit`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Right {
    pub name: &'static str,
    pub sensitive: bool,
}

const fn right(name: &'static str, sensitive: bool) -> Right {
    Right { name, sensitive }
}

/// In the order of the Python table (the interface sorts them by title).
pub const RIGHTS: [Right; 45] = [
    right("SeTrustedCredManAccessPrivilege", true),
    right("SeNetworkLogonRight", false),
    right("SeTcbPrivilege", true),
    right("SeMachineAccountPrivilege", false),
    right("SeIncreaseQuotaPrivilege", false),
    right("SeInteractiveLogonRight", false),
    right("SeRemoteInteractiveLogonRight", false),
    right("SeBackupPrivilege", true),
    right("SeChangeNotifyPrivilege", false),
    right("SeSystemtimePrivilege", false),
    right("SeTimeZonePrivilege", false),
    right("SeCreatePagefilePrivilege", false),
    right("SeCreateTokenPrivilege", true),
    right("SeCreateGlobalPrivilege", false),
    right("SeCreatePermanentPrivilege", false),
    right("SeCreateSymbolicLinkPrivilege", false),
    right("SeDebugPrivilege", true),
    right("SeDenyNetworkLogonRight", false),
    right("SeDenyBatchLogonRight", false),
    right("SeDenyServiceLogonRight", false),
    right("SeDenyInteractiveLogonRight", false),
    right("SeDenyRemoteInteractiveLogonRight", false),
    right("SeEnableDelegationPrivilege", true),
    right("SeRemoteShutdownPrivilege", false),
    right("SeAuditPrivilege", false),
    right("SeImpersonatePrivilege", true),
    right("SeIncreaseWorkingSetPrivilege", false),
    right("SeIncreaseBasePriorityPrivilege", false),
    right("SeLoadDriverPrivilege", true),
    right("SeLockMemoryPrivilege", false),
    right("SeBatchLogonRight", false),
    right("SeServiceLogonRight", false),
    right("SeSecurityPrivilege", true),
    right("SeRelabelPrivilege", false),
    right("SeSystemEnvironmentPrivilege", false),
    right("SeManageVolumePrivilege", true),
    right("SeProfileSingleProcessPrivilege", false),
    right("SeSystemProfilePrivilege", false),
    right("SeUndockPrivilege", false),
    right("SeAssignPrimaryTokenPrivilege", true),
    right("SeRestorePrivilege", true),
    right("SeShutdownPrivilege", false),
    right("SeSyncAgentPrivilege", true),
    right("SeTakeOwnershipPrivilege", true),
    right("SeDelegateSessionUserImpersonatePrivilege", false),
];

pub fn known_right(name: &str) -> Option<&'static Right> {
    RIGHTS.iter().find(|r| r.name.eq_ignore_ascii_case(name))
}

// --- Reading of the file ------------------------------------------------------------------

/// Value defined in the GPO, or `None` (not defined; unreadable counts as not defined)
/// (`valeur`).
pub fn value(inf: &Inf, r: &SettingDef) -> Option<i64> {
    inf.integer(gt::SYSTEM_ACCESS, r.key).ok().flatten()
}

/// Why a value or a policy is refused; the interface says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityProblem {
    OutOfBounds {
        key: &'static str,
        n: i64,
        min: i64,
        max: i64,
    },
    /// The minimum age must be below the maximum age.
    MinimumAge { min: i64, max: i64 },
    /// The counter reset window is longer than the lockout duration.
    ResetWindow { window: i64, duration: i64 },
}

/// The setting defined to `n` (`None`: not defined); refused out of the bounds (`poser`).
pub fn set(inf: &Inf, r: &SettingDef, n: Option<i64>) -> Result<Inf, SecurityProblem> {
    if let Some(n) = n
        && Some(n) != r.never
        && !(r.minimum..=r.maximum).contains(&n)
    {
        return Err(SecurityProblem::OutOfBounds {
            key: r.key,
            n,
            min: r.minimum,
            max: r.maximum,
        });
    }
    Ok(inf.set_integer(gt::SYSTEM_ACCESS, r.key, n))
}

/// Inconsistencies that prevent writing (the GPMC refuses them): minimum age at least equal to
/// the maximum age, counter reset window longer than the lockout (`problemes`).
pub fn problems(inf: &Inf) -> Vec<SecurityProblem> {
    let get = |k| inf.integer(gt::SYSTEM_ACCESS, k).ok().flatten();
    let mut out = Vec::new();
    if let (Some(min), Some(max)) = (get("MinimumPasswordAge"), get("MaximumPasswordAge"))
        && max > 0
        && min >= max
    {
        out.push(SecurityProblem::MinimumAge { min, max });
    }
    if let (Some(duration), Some(window)) = (get("LockoutDuration"), get("ResetLockoutCount"))
        && duration > 0
        && window > duration
    {
        out.push(SecurityProblem::ResetWindow { window, duration });
    }
    out
}

// --- Domain object ------------------------------------------------------------------------

/// AD duration → number of days or minutes; -1 for « never ».
fn duration(ticks: i64, unit: i64) -> i64 {
    if ticks == time::DURATION_NEVER {
        return -1;
    }
    ticks.checked_neg().map_or(-1, |t| t.div_euclid(unit))
}

fn to_duration(n: i64, unit: i64) -> i64 {
    if n < 0 {
        time::DURATION_NEVER
    } else {
        n.saturating_mul(unit).saturating_neg()
    }
}

/// What the domain object applies, said as in `GptTmpl.inf` (`PolitiqueDomaine`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainPolicy {
    /// Key of `[System Access]` → value (days, minutes, number, 0/1; -1 for « never »).
    pub values: BTreeMap<String, i64>,
    pub pwd_properties: i64,
}

impl DomainPolicy {
    pub fn of(&self, r: &SettingDef) -> Option<i64> {
        self.values.get(r.key).copied()
    }
}

fn attribute_number(attributes: &[(String, Option<Vec<u8>>)], name: &str) -> Option<i64> {
    attributes
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.as_ref())
        .filter(|v| !v.is_empty())
        .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse().ok())
}

/// Reads the attributes of the domain object (raw text values) (`politique_domaine`).
pub fn domain_policy(attributes: &[(String, Option<Vec<u8>>)]) -> DomainPolicy {
    let mut values = BTreeMap::new();
    for (key, name) in [
        ("MinimumPasswordLength", "minPwdLength"),
        ("PasswordHistorySize", "pwdHistoryLength"),
        ("LockoutBadCount", "lockoutThreshold"),
    ] {
        if let Some(n) = attribute_number(attributes, name) {
            values.insert(key.to_owned(), n);
        }
    }
    for (key, name, unit) in [
        ("MinimumPasswordAge", "minPwdAge", DAY),
        ("MaximumPasswordAge", "maxPwdAge", DAY),
        ("LockoutDuration", "lockoutDuration", MINUTE),
        ("ResetLockoutCount", "lockOutObservationWindow", MINUTE),
    ] {
        if let Some(n) = attribute_number(attributes, name) {
            values.insert(key.to_owned(), duration(n, unit));
        }
    }
    let properties = attribute_number(attributes, "pwdProperties").unwrap_or(0);
    values.insert(
        "PasswordComplexity".into(),
        i64::from(properties & DOMAIN_PASSWORD_COMPLEX != 0),
    );
    values.insert(
        "ClearTextPassword".into(),
        i64::from(properties & DOMAIN_PASSWORD_STORE_CLEARTEXT != 0),
    );
    DomainPolicy {
        values,
        pwd_properties: properties,
    }
}

/// Value of the attribute of the domain; `None` if Windows ignores this setting (seen on the
/// PDC emulator of WIN.TEST: `MaximumPasswordAge = 0` leaves `maxPwdAge` as it is, only -1 says
/// « never expires ») (`_valeur_attribut`).
fn attribute_value(r: &SettingDef, n: i64) -> Option<i64> {
    match r.attribute {
        "maxPwdAge" if n == 0 => None,
        "minPwdAge" | "maxPwdAge" => Some(to_duration(n, DAY)),
        "lockoutDuration" | "lockOutObservationWindow" => Some(to_duration(n, MINUTE)),
        _ => Some(n),
    }
}

/// The changes of the domain object that carry there the settings defined in `inf` (those the
/// GPO leaves undefined are not touched), as `samba-tool domain passwordsettings set`.
/// `pwdProperties` keeps its other bits (`changements_domaine`).
pub fn domain_changes(
    inf: &Inf,
    attributes: &[(String, Option<Vec<u8>>)],
) -> Result<Vec<Change>, GpoError> {
    let before_properties = attribute_number(attributes, "pwdProperties").unwrap_or(0);
    let mut properties = before_properties;
    let mut wanted: BTreeMap<&str, i64> = BTreeMap::new();
    for r in &SETTINGS {
        let Some(n) = value(inf, r) else { continue };
        if r.attribute == "pwdProperties" {
            let bit = if r.key == "PasswordComplexity" {
                DOMAIN_PASSWORD_COMPLEX
            } else {
                DOMAIN_PASSWORD_STORE_CLEARTEXT
            };
            properties = if n != 0 {
                properties | bit
            } else {
                properties & !bit
            };
        } else if let Some(v) = attribute_value(r, n) {
            wanted.insert(r.attribute, v);
        }
    }
    if properties != before_properties {
        wanted.insert("pwdProperties", properties);
    }
    let mut changes = Vec::new();
    for attribute in DOMAIN_ATTRIBUTES {
        let Some(v) = wanted.get(attribute) else {
            continue;
        };
        let new = v.to_string().into_bytes();
        let before = attributes
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attribute))
            .and_then(|(_, v)| v.clone())
            .filter(|v| !v.is_empty());
        if before.as_ref() == Some(&new) {
            continue;
        }
        changes.push(Change::new(
            attribute,
            before.into_iter().collect(),
            vec![new],
        )?);
    }
    Ok(changes)
}

// --- Fine-grained password policies (PSO), read only --------------------------------------

/// A fine-grained password policy (`msDS-PasswordSettings`): it replaces the policy of the
/// domain for the accounts and global groups it applies to; the smallest precedence wins
/// (`Pso`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoSummary {
    pub dn: String,
    pub name: String,
    pub precedence: i64,
    /// Same keys and units as `DomainPolicy::values`.
    pub values: BTreeMap<String, i64>,
    /// DNs of the accounts and groups.
    pub applies_to: Vec<String>,
}

const PSO_NUMBERS: [(&str, &str, i64); 7] = [
    ("MinimumPasswordLength", "msDS-MinimumPasswordLength", 0),
    ("PasswordHistorySize", "msDS-PasswordHistoryLength", 0),
    ("LockoutBadCount", "msDS-LockoutThreshold", 0),
    ("MinimumPasswordAge", "msDS-MinimumPasswordAge", DAY),
    ("MaximumPasswordAge", "msDS-MaximumPasswordAge", DAY),
    ("LockoutDuration", "msDS-LockoutDuration", MINUTE),
    ("ResetLockoutCount", "msDS-LockoutObservationWindow", MINUTE),
];
const PSO_BOOLEANS: [(&str, &str); 2] = [
    ("PasswordComplexity", "msDS-PasswordComplexityEnabled"),
    (
        "ClearTextPassword",
        "msDS-PasswordReversibleEncryptionEnabled",
    ),
];

fn text(entry: &Entry, name: &str) -> String {
    entry
        .values(name)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

pub fn pso_from_entry(entry: &Entry) -> PsoSummary {
    let mut values = BTreeMap::new();
    for (key, attribute, unit) in PSO_NUMBERS {
        if let Ok(n) = text(entry, attribute).trim().parse::<i64>() {
            values.insert(
                key.to_owned(),
                if unit == 0 { n } else { duration(n, unit) },
            );
        }
    }
    for (key, attribute) in PSO_BOOLEANS {
        let t = text(entry, attribute);
        if !t.is_empty() {
            values.insert(key.to_owned(), i64::from(t.eq_ignore_ascii_case("TRUE")));
        }
    }
    PsoSummary {
        dn: entry.dn.clone(),
        name: text(entry, "name"),
        precedence: text(entry, "msDS-PasswordSettingsPrecedence")
            .trim()
            .parse()
            .unwrap_or(0),
        values,
        applies_to: entry
            .values("msDS-PSOAppliesTo")
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect(),
    }
}

/// The PSOs of the domain, by precedence (none if the container is unreadable) (`lire_psos`).
fn read_psos(link: &mut Link) -> Result<Vec<PsoSummary>, Step> {
    let base = crate::pso::container(&link.state.root_dse.default_naming_context);
    let mut names = vec![
        "name",
        "msDS-PasswordSettingsPrecedence",
        "msDS-PSOAppliesTo",
    ];
    names.extend(PSO_NUMBERS.iter().map(|(_, a, _)| *a));
    names.extend(PSO_BOOLEANS.iter().map(|(_, a)| *a));
    let filter = format!("(objectClass={})", crate::pso::CLASS);
    let entries = match gw::search(link, &base, Scope::OneLevel, &filter, &names) {
        Err(e) if e.code == code::NO_SUCH_OBJECT => return Ok(Vec::new()),
        other => other?,
    };
    let mut psos: Vec<PsoSummary> = entries.iter().map(pso_from_entry).collect();
    psos.sort_by(|a, b| (a.precedence, &a.name).cmp(&(b.precedence, &b.name)));
    Ok(psos)
}

// --- Scope --------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// Linked (enabled link) to the root of the domain: the account policy holds for the domain.
    Domain,
    /// Linked only to OUs or sites: it only sets the local accounts.
    Elsewhere,
    Unlinked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountScope {
    pub reach: Reach,
    /// GUIDs of the GPOs linked to the root before this one (higher precedence): where they
    /// define a setting, the domain applies their value.
    pub prior: Vec<String>,
}

/// Where the account policy of the GPO `guid` applies, from the links of the root of the domain
/// and those of the other containers (OUs, sites). A disabled link does not count (`portee`).
pub fn scope(root: &GpLink, elsewhere: &[GpLink], guid: &str) -> AccountScope {
    let guid = guid.to_uppercase();
    let mut before = Vec::new();
    for link in root.by_precedence() {
        let Some(g) = link.guid() else { continue };
        if link.disabled() {
            continue;
        }
        if g == guid {
            return AccountScope {
                reach: Reach::Domain,
                prior: before,
            };
        }
        before.push(g);
    }
    let linked = elsewhere.iter().any(|links| {
        links
            .links()
            .any(|l| l.guid().as_deref() == Some(guid.as_str()) && !l.disabled())
    });
    AccountScope {
        reach: if linked {
            Reach::Elsewhere
        } else {
            Reach::Unlinked
        },
        prior: Vec::new(),
    }
}

/// `scope` from the inventory of the « Group Policy » window (`portee_comptes`).
pub fn account_scope(directory: &crate::gpo::GpoDirectory, guid: &str) -> AccountScope {
    let mut root = GpLink::default();
    let mut others = Vec::new();
    for c in directory.containers.iter().chain(&directory.linked_sites) {
        if c.dn.eq_ignore_ascii_case(&directory.domain) {
            root = c.gplink.clone();
        } else {
            others.push(c.gplink.clone());
        }
    }
    scope(&root, &others, guid)
}

/// `inf` without the settings a GPO of higher precedence already defines (those, the domain
/// takes from it), and the keys of the settings so set aside (`masquer_prioritaires`).
pub fn mask_prior(inf: &Inf, prior: &[Inf]) -> (Inf, Vec<&'static str>) {
    let mut inf = inf.clone();
    let mut aside = Vec::new();
    for r in &SETTINGS {
        if value(&inf, r).is_none() {
            continue;
        }
        if prior.iter().any(|p| value(p, r).is_some()) {
            inf = inf.set_integer(gt::SYSTEM_ACCESS, r.key, None);
            aside.push(r.key);
        }
    }
    (inf, aside)
}

// --- Reading and writing on the write DC --------------------------------------------------

/// Client-side extension « Security » (SceCli).
pub const SECURITY_CSE: &str = "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}";
/// Extension of the « Security Settings » editor (computer part).
pub const SECURITY_TOOL: &str = "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}";
/// Relative to the `Machine` folder of the GPO.
pub const PATH: &str = "Microsoft/Windows NT/SecEdit/GptTmpl.inf";

pub fn extension() -> (String, String) {
    (SECURITY_CSE.to_owned(), SECURITY_TOOL.to_owned())
}

/// Security settings of a GPO read on the write DC, with what is needed to say their effect:
/// scope, policy of the domain object, nature of the DC (`SecuriteLue`).
#[derive(Debug, Clone)]
pub struct SecurityRead {
    pub dn: String,
    pub name: String,
    /// Content of the file, or `Inf::new_gpmc()` if it does not exist.
    pub inf: Inf,
    pub exists: bool,
    pub scope: AccountScope,
    pub domain: DomainPolicy,
    pub samba: bool,
    /// Names of the GPOs linked to the root with a higher precedence.
    pub prior_names: Vec<String>,
    pub psos: Vec<PsoSummary>,
}

/// What `read` keeps to write: the content read, the root entry, the files of the prior GPOs.
struct Reading {
    content: ContentRead,
    security: SecurityRead,
    root: Entry,
    prior: Vec<Inf>,
}

fn root_entry(link: &mut Link) -> Result<Entry, Step> {
    let base = link.state.root_dse.default_naming_context.clone();
    let mut names: Vec<String> = vec!["uSNChanged".into(), "gPLink".into()];
    names.extend(DOMAIN_ATTRIBUTES.iter().map(|a| (*a).to_owned()));
    crate::search::read_entry(
        link.session.as_mut(),
        &base,
        &names,
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )?
    .ok_or(Step::Gpo(GpoError::DomainUnreadable { dn: base }))
}

fn attributes(entry: &Entry) -> Vec<(String, Option<Vec<u8>>)> {
    DOMAIN_ATTRIBUTES
        .iter()
        .map(|a| ((*a).to_owned(), entry.values(a).first().cloned()))
        .collect()
}

fn root_scope(link: &mut Link, root: &Entry, guid: &str) -> Result<AccountScope, Step> {
    let links = root
        .values("gPLink")
        .first()
        .map(|v| GpLink::decode(v).unwrap_or_else(|_| GpLink::parse(&String::from_utf8_lossy(v))))
        .unwrap_or_default();
    let found = scope(&links, &[], guid);
    if found.reach == Reach::Domain {
        return Ok(found);
    }
    let base = root.dn.to_lowercase();
    let elsewhere: Vec<GpLink> = gw::linked_containers(link, guid)?
        .iter()
        .filter(|c| c.dn.to_lowercase() != base)
        .map(gw::ContainerRead::links)
        .collect();
    Ok(scope(&links, &elsewhere, guid))
}

/// Name and `GptTmpl.inf` of the GPOs `guids` (those that have one) (`_prioritaires`).
fn prior(
    link: &mut Link,
    session: &mut SysvolSession,
    guids: &[String],
) -> Result<Vec<(String, Inf)>, Step> {
    if guids.is_empty() {
        return Ok(Vec::new());
    }
    let base = link.state.root_dse.default_naming_context.clone();
    let domain = gw::domain_dns(&base);
    let pieces: Vec<&str> = PATH.split('/').collect();
    let paths: Vec<String> = guids
        .iter()
        .map(|guid| {
            let mut all = vec![gw::gpo_folder(&domain, guid)];
            all.push("Machine".into());
            all.extend(pieces.iter().map(|p| (*p).to_owned()));
            let refs: Vec<&str> = all.iter().map(String::as_str).collect();
            sysvol::join(&refs)
        })
        .collect();
    let contents = session.client()?.read(&paths)?;
    let mut out = Vec::new();
    for (guid, content) in guids.iter().zip(contents) {
        let Some(bytes) = content.filter(|c| !c.is_empty()) else {
            continue;
        };
        let entry = crate::search::read_entry(
            link.session.as_mut(),
            &gw::gpo_dn(&base, guid),
            &["displayName".to_owned()],
            "(objectClass=*)",
            None,
            Some(link.timeout),
        )?;
        let name = entry
            .as_ref()
            .and_then(|e| e.values("displayName").first().cloned())
            .map_or_else(
                || guid.clone(),
                |v| String::from_utf8_lossy(&v).into_owned(),
            );
        if let Ok(inf) = Inf::read(&bytes) {
            out.push((name, inf));
        }
    }
    Ok(out)
}

fn inf_path() -> String {
    PATH.replace('/', "\\")
}

fn read_on(link: &mut Link, session: &mut SysvolSession, dn: &str) -> Result<Reading, Step> {
    let content = gc::read_contents(link, session, dn, &[(Part::Computer, vec![inf_path()])])?
        .into_iter()
        .next()
        .ok_or(Step::Gpo(GpoError::Missing { dn: dn.to_owned() }))?;
    let raw = content.content(&inf_path())?.map(<[u8]>::to_vec);
    let inf = match &raw {
        Some(bytes) if !bytes.is_empty() => {
            Inf::read(bytes).map_err(|e| GpoError::Invalid(e.to_string()))?
        }
        _ => Inf::new_gpmc(),
    };
    let root = root_entry(link)?;
    let found = root_scope(link, &root, &content.gpo.guid())?;
    let prior = prior(link, session, &found.prior)?;
    let security = SecurityRead {
        dn: content.gpo.dn.clone(),
        name: content.gpo.name(),
        inf,
        exists: raw.is_some(),
        scope: found,
        domain: domain_policy(&attributes(&root)),
        samba: link.state.root_dse.samba(),
        prior_names: prior.iter().map(|(n, _)| n.clone()).collect(),
        psos: read_psos(link)?,
    };
    Ok(Reading {
        content,
        security,
        root,
        prior: prior.into_iter().map(|(_, i)| i).collect(),
    })
}

/// Reads on the PDC emulator the `GptTmpl.inf` of the GPO `dn`, its scope and the policy of the
/// domain object (`lire_securite`). Blocking.
pub fn read_security(connection: &Connection, dn: &str) -> Result<SecurityRead, GpoError> {
    let dn = dn.to_owned();
    gw::on_dc(connection, move |link, session| {
        Ok(read_on(link, session, &dn)?.security)
    })
}

fn defines_accounts(inf: &Inf) -> bool {
    SETTINGS.iter().any(|r| value(inf, r).is_some())
}

/// The `ContentChange` that gives the file the content `after` (`ecrire_securite`, first half).
pub fn file_change(security: &SecurityRead, after: &Inf) -> Result<ContentChange, GpoError> {
    let errors = problems(after);
    if !errors.is_empty() {
        return Err(GpoError::Security(errors));
    }
    let invalid = |e: gt::InfError| GpoError::Invalid(e.to_string());
    let before = if security.exists {
        Some(security.inf.write().map_err(invalid)?)
    } else {
        None
    };
    let mut new = Some(after.write().map_err(invalid)?);
    if before.is_none() && after.is_empty() {
        new = None; // nothing to create
    }
    if new == before {
        return Ok(ContentChange::default());
    }
    let (add, remove) = if after.is_empty() {
        (Vec::new(), vec![extension()])
    } else {
        (vec![extension()], Vec::new())
    };
    Ok(ContentChange {
        files: vec![(inf_path(), new)],
        add_extensions: add,
        remove_extensions: remove,
        remarks: Vec::new(),
    })
}

/// `cs` followed, on Samba and for a GPO linked to the root, by the `Modify` of the domain
/// object that carries there the account policy `after`; remarks of scope (`_avec_domaine`).
fn with_domain(
    cs: Changeset,
    security: &SecurityRead,
    after: &Inf,
    root: Option<&Entry>,
    prior: &[Inf],
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let mut operations = cs.operations;
    let mut remarks = cs.remarks;
    let accounts = defines_accounts(after) || defines_accounts(&security.inf);
    if accounts && security.scope.reach != Reach::Domain {
        remarks.push(catalog.text(&Msg::GpoSecurityNotAtRoot));
    } else if accounts && !security.samba {
        remarks.push(catalog.text(&Msg::GpoSecurityPdcApplies));
    } else if let (true, Some(root)) = (accounts, root) {
        let (effective, aside) = mask_prior(after, prior);
        let changes = domain_changes(&effective, &attributes(root))?;
        if !changes.is_empty() {
            let dc = operations
                .iter()
                .find_map(|op| match op {
                    Operation::Modify { read: Some(r), .. } => Some(r.dc.clone()),
                    _ => None,
                })
                .unwrap_or_default();
            let usn = root
                .values("uSNChanged")
                .first()
                .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse().ok())
                .unwrap_or(0);
            operations.push(Operation::modify(
                &root.dn,
                changes,
                Some(Read { dc, usn }),
            )?);
            remarks.push(catalog.text(&Msg::GpoSecuritySamba));
        }
        if !aside.is_empty() {
            remarks.push(catalog.text(&Msg::GpoSecurityPrior {
                names: security.prior_names.join(", "),
                keys: aside.iter().map(|k| (*k).to_owned()).collect(),
            }));
        }
    }
    Ok(Changeset {
        operations,
        remarks,
    })
}

fn is_inf_file(path: &str) -> bool {
    sysvol::key(path).ends_with(&sysvol::key(&format!("Machine\\{}", inf_path())))
}

/// For the GPO editor, which writes the content of all its sections in one changeset
/// (`gpo_content::write_contents`): if `cs` writes the `GptTmpl.inf` of the GPO `dn`, the
/// « domain object » continuation, read on the same DC. Else `cs` as is (`completer_domaine`).
pub(crate) fn complete_domain(
    link: &mut Link,
    session: &mut SysvolSession,
    dn: &str,
    cs: Changeset,
    catalog: &dyn Catalog,
) -> Result<Changeset, Step> {
    let mut new: Option<Inf> = None;
    for op in &cs.operations {
        match op {
            Operation::WriteFile { path, content, .. } if is_inf_file(path) => {
                new = Some(Inf::read(content).map_err(|e| GpoError::Invalid(e.to_string()))?);
            }
            Operation::DeleteFile { path, .. } if is_inf_file(path) => new = Some(Inf::new_gpmc()),
            _ => {}
        }
    }
    let Some(new) = new else { return Ok(cs) };
    let reading = read_on(link, session, dn)?;
    Ok(with_domain(
        cs,
        &reading.security,
        &new,
        Some(&reading.root),
        &reading.prior,
        catalog,
    )?)
}

/// A change of the content of `GptTmpl.inf`, made on the content read again.
pub type InfChange = Arc<dyn Fn(&Inf) -> Result<Inf, SecurityProblem> + Send + Sync>;

/// Reads on the PDC emulator the `GptTmpl.inf` of the GPO, applies `change` (pure, on the thread
/// of the connection) to the content read, and returns one changeset for the file, the version,
/// the extension and, on Samba, the domain object (`preparer_securite`). Blocking.
pub fn prepare_security(
    connection: &Connection,
    dn: &str,
    change: InfChange,
    domain: bool,
    catalog: Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let dn = dn.to_owned();
    gw::on_dc(connection, move |link, session| {
        let reading = read_on(link, session, &dn)?;
        let after = change(&reading.security.inf).map_err(|p| GpoError::Security(vec![p]))?;
        let file = file_change(&reading.security, &after)?;
        let cs = gc::write_content(&reading.content, &file, catalog.as_ref())?;
        let root = domain.then_some(&reading.root);
        Ok(with_domain(
            cs,
            &reading.security,
            &after,
            root,
            &reading.prior,
            catalog.as_ref(),
        )?)
    })
}

#[cfg(test)]
mod tests;

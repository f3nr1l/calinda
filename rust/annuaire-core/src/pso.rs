// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Fine-grained password policies (PSO): faithful reading and writing (ADR 0014 § 6,
//! `annuaire.core.pso`).
//!
//! A PSO is an object `msDS-PasswordSettings` under `CN=Password Settings Container,
//! CN=System` of the domain. It replaces the policy of the domain for the accounts and the
//! global security groups it targets (`msDS-PSOAppliesTo`, linked attribute: DNs of the
//! targets); between several PSOs, the smallest precedence wins, and a PSO linked to the
//! account itself wins over those of its groups. The DC computes the one that applies to an
//! account: `msDS-ResultantPSO`, a constructed attribute.
//!
//! The ten settings are mandatory (class of the schema); the durations are in the format of
//! the AD durations: hundreds of nanoseconds, negative, -2⁶³ for « never ». They are kept
//! **as they are** (`Settings`), to the hundred of nanoseconds: a PSO written by `samba-tool`
//! or by `New-ADFineGrainedPasswordPolicy` is read without rounding, and a modification writes
//! only the attributes that change.
//!
//! Checks (`problems`): those of the schema (bounds) and those Windows and `samba-tool`
//! enforce: minimum age less than the maximum age (unless « never expires »), lockout
//! observation window at most its duration (unless « until unlocked »).
//!
//! Writing: `create` (Add), `modify` (Modify guarded by `uSNChanged`), `delete` (Delete, the
//! inverse creates the object again with its targets); everything goes through the common
//! preview, the journal and Ctrl+Z.

use crate::changes::{AttributeMap, Change, ChangeError, Changeset, Operation, Read, dn_key};
use crate::connection::{Connection, Failure, Link};
use crate::dn::{self, Component};
use crate::error::{LdapError, code};
use crate::search;
use crate::session::{Entry, Scope};

pub const CONTAINER: &str = "CN=Password Settings Container,CN=System";
pub const CLASS: &str = "msDS-PasswordSettings";
pub const TARGETS: &str = "msDS-PSOAppliesTo";
/// Constructed attribute of an account: DN of the PSO that applies to it (absent: the
/// domain).
pub const RESULTANT: &str = "msDS-ResultantPSO";

/// Units of the AD durations: hundreds of nanoseconds.
pub const SECOND: i64 = 10_000_000;
pub const MINUTE: i64 = 60 * SECOND;
pub const HOUR: i64 = 60 * MINUTE;
pub const DAY: i64 = 24 * HOUR;
/// « Never »: -2⁶³.
pub const NEVER: i64 = i64::MIN;

/// What a field holds (`Genre`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Integer,
    Boolean,
    Duration,
}

/// The settings of a PSO, values as stored (durations in hundreds of ns) (`Reglages`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub precedence: i64,
    pub min_length: i64,
    pub history: i64,
    pub complexity: bool,
    pub reversible: bool,
    pub min_age: i64,
    pub max_age: i64,
    pub lockout_threshold: i64,
    pub lockout_duration: i64,
    pub lockout_window: i64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            precedence: 10,
            min_length: 7,
            history: 24,
            complexity: true,
            reversible: false,
            min_age: -DAY,
            max_age: -42 * DAY,
            lockout_threshold: 0,
            lockout_duration: -30 * MINUTE,
            lockout_window: -30 * MINUTE,
        }
    }
}

/// A field of the settings (`Champ`): its name (the one of Python, for the texts), attribute,
/// kind and bounds of the integers (`rangeLower`/`rangeUpper` of the schema).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field {
    pub name: &'static str,
    pub attribute: &'static str,
    pub kind: Kind,
    pub minimum: i64,
    pub maximum: i64,
}

pub const FIELDS: [Field; 10] = [
    Field {
        name: "priorite",
        attribute: "msDS-PasswordSettingsPrecedence",
        kind: Kind::Integer,
        minimum: 1,
        maximum: 2_147_483_647,
    },
    Field {
        name: "longueur_minimale",
        attribute: "msDS-MinimumPasswordLength",
        kind: Kind::Integer,
        minimum: 0,
        maximum: 255,
    },
    Field {
        name: "historique",
        attribute: "msDS-PasswordHistoryLength",
        kind: Kind::Integer,
        minimum: 0,
        maximum: 65535,
    },
    Field {
        name: "complexite",
        attribute: "msDS-PasswordComplexityEnabled",
        kind: Kind::Boolean,
        minimum: 0,
        maximum: 0,
    },
    Field {
        name: "chiffrement_reversible",
        attribute: "msDS-PasswordReversibleEncryptionEnabled",
        kind: Kind::Boolean,
        minimum: 0,
        maximum: 0,
    },
    Field {
        name: "age_minimal",
        attribute: "msDS-MinimumPasswordAge",
        kind: Kind::Duration,
        minimum: 0,
        maximum: 0,
    },
    Field {
        name: "age_maximal",
        attribute: "msDS-MaximumPasswordAge",
        kind: Kind::Duration,
        minimum: 0,
        maximum: 0,
    },
    Field {
        name: "seuil_verrouillage",
        attribute: "msDS-LockoutThreshold",
        kind: Kind::Integer,
        minimum: 0,
        maximum: 65535,
    },
    Field {
        name: "duree_verrouillage",
        attribute: "msDS-LockoutDuration",
        kind: Kind::Duration,
        minimum: 0,
        maximum: 0,
    },
    Field {
        name: "fenetre_verrouillage",
        attribute: "msDS-LockoutObservationWindow",
        kind: Kind::Duration,
        minimum: 0,
        maximum: 0,
    },
];

/// A value of a field: an integer (duration included) or a boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldValue {
    Number(i64),
    Flag(bool),
}

impl Settings {
    pub fn get(&self, name: &str) -> FieldValue {
        match name {
            "priorite" => FieldValue::Number(self.precedence),
            "longueur_minimale" => FieldValue::Number(self.min_length),
            "historique" => FieldValue::Number(self.history),
            "complexite" => FieldValue::Flag(self.complexity),
            "chiffrement_reversible" => FieldValue::Flag(self.reversible),
            "age_minimal" => FieldValue::Number(self.min_age),
            "age_maximal" => FieldValue::Number(self.max_age),
            "seuil_verrouillage" => FieldValue::Number(self.lockout_threshold),
            "duree_verrouillage" => FieldValue::Number(self.lockout_duration),
            _ => FieldValue::Number(self.lockout_window),
        }
    }

    pub fn set(&mut self, name: &str, value: FieldValue) {
        let number = match value {
            FieldValue::Number(n) => n,
            FieldValue::Flag(b) => i64::from(b),
        };
        let flag = matches!(value, FieldValue::Flag(true)) || number != 0;
        match name {
            "priorite" => self.precedence = number,
            "longueur_minimale" => self.min_length = number,
            "historique" => self.history = number,
            "complexite" => self.complexity = flag,
            "chiffrement_reversible" => self.reversible = flag,
            "age_minimal" => self.min_age = number,
            "age_maximal" => self.max_age = number,
            "seuil_verrouillage" => self.lockout_threshold = number,
            "duree_verrouillage" => self.lockout_duration = number,
            _ => self.lockout_window = number,
        }
    }
}

pub fn encode(field: &Field, value: FieldValue) -> Vec<u8> {
    match value {
        FieldValue::Flag(b) if field.kind == Kind::Boolean => {
            if b {
                b"TRUE".to_vec()
            } else {
                b"FALSE".to_vec()
            }
        }
        FieldValue::Flag(b) => i64::from(b).to_string().into_bytes(),
        FieldValue::Number(n) => n.to_string().into_bytes(),
    }
}

pub fn decode(field: &Field, raw: &[u8]) -> Option<FieldValue> {
    let text = std::str::from_utf8(raw).ok()?.trim();
    if field.kind == Kind::Boolean {
        return Some(FieldValue::Flag(text.eq_ignore_ascii_case("TRUE")));
    }
    text.parse().ok().map(FieldValue::Number)
}

/// A PSO read on the write DC, with its version (guard of the modifications) (`PsoLue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsoRead {
    pub dn: String,
    pub name: String,
    pub description: String,
    pub settings: Settings,
    /// DNs of the accounts and groups targeted (`msDS-PSOAppliesTo`).
    pub targets: Vec<String>,
    pub read: Option<Read>,
    /// Values read, attribute by attribute (to write only what changes).
    pub raw: AttributeMap,
}

fn values<'a>(entry: &'a Entry, attribute: &str) -> &'a [Vec<u8>] {
    entry.values(attribute)
}

/// A PSO read; a setting absent (partial read rights) keeps its default value of `Settings`,
/// without writing anything as long as it is not changed (`pso_depuis_entree`).
pub fn pso_from_entry(entry: &Entry, read: Option<Read>) -> PsoRead {
    let mut settings = Settings::default();
    for field in &FIELDS {
        if let Some(v) = values(entry, field.attribute)
            .first()
            .and_then(|v| decode(field, v))
        {
            settings.set(field.name, v);
        }
    }
    let text = |attribute: &str| {
        values(entry, attribute)
            .first()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default()
    };
    let mut name = text("name");
    if name.is_empty() {
        name = entry
            .dn
            .split_once(',')
            .map_or(entry.dn.as_str(), |(first, _)| first)
            .split_once('=')
            .map_or("", |(_, v)| v)
            .to_owned();
    }
    PsoRead {
        dn: entry.dn.clone(),
        name,
        description: text("description"),
        settings,
        targets: values(entry, TARGETS)
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect(),
        read,
        raw: entry.attributes.clone(),
    }
}

pub fn container(base: &str) -> String {
    format!("{CONTAINER},{base}")
}

pub fn pso_dn(base: &str, name: &str) -> String {
    let rdn = dn::compose(&[Component {
        attribute: "CN".into(),
        value: name.to_owned(),
    }])
    .unwrap_or_else(|_| format!("CN={name}"));
    format!("{rdn},{}", container(base))
}

fn attributes() -> Vec<String> {
    let mut out: Vec<String> = ["uSNChanged", "objectClass", "name", "description", TARGETS]
        .iter()
        .map(|&a| a.to_owned())
        .collect();
    out.extend(FIELDS.iter().map(|f| f.attribute.to_owned()));
    out
}

fn usn(entry: &Entry) -> i64 {
    entry
        .values("uSNChanged")
        .first()
        .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse().ok())
        .unwrap_or(0)
}

/// The PSOs of the domain with their version, by precedence then by name; none if the
/// container is unreadable for this account (`lire_psos`). Blocking.
pub fn read_psos(connection: &Connection) -> Result<Vec<PsoRead>, Failure> {
    connection.run(true, |link| {
        let base = container(&link.state.root_dse.default_naming_context);
        let names: Vec<String> = attributes();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        let filter = format!("(objectClass={CLASS})");
        let entries =
            match crate::gpo::search_all(link, &base, Scope::OneLevel, &filter, &names, &[]) {
                Err(e) if e.code == code::NO_SUCH_OBJECT => return Ok(Vec::new()),
                other => other?,
            };
        let dc = link.state.dc.clone();
        let mut psos: Vec<PsoRead> = entries
            .iter()
            .map(|e| {
                pso_from_entry(
                    e,
                    Some(Read {
                        dc: dc.clone(),
                        usn: usn(e),
                    }),
                )
            })
            .collect();
        psos.sort_by_cached_key(|p| (p.settings.precedence, p.name.to_lowercase()));
        Ok(psos)
    })
}

fn read_entry(
    link: &mut Link,
    dn_text: &str,
    names: &[String],
) -> Result<Option<Entry>, LdapError> {
    search::read_entry(
        link.session.as_mut(),
        dn_text,
        names,
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )
}

/// A PSO read again with its version, just before preparing a write (`lire_pso`). Blocking.
pub fn read_pso(connection: &Connection, dn_text: &str) -> Result<Option<PsoRead>, Failure> {
    let dn_text = dn_text.to_owned();
    connection.run(true, move |link| {
        let entry = read_entry(link, &dn_text, &attributes())?;
        let dc = link.state.dc.clone();
        Ok(entry.map(|e| {
            let read = Read { dc, usn: usn(&e) };
            pso_from_entry(&e, Some(read))
        }))
    })
}

const DOMAIN: [(&str, &str); 7] = [
    ("longueur_minimale", "minPwdLength"),
    ("historique", "pwdHistoryLength"),
    ("age_minimal", "minPwdAge"),
    ("age_maximal", "maxPwdAge"),
    ("seuil_verrouillage", "lockoutThreshold"),
    ("duree_verrouillage", "lockoutDuration"),
    ("fenetre_verrouillage", "lockOutObservationWindow"),
];
const COMPLEX: i64 = 0x1;
const REVERSIBLE: i64 = 0x10;

/// The policy of the domain object, as a PSO (precedence meaningless): what the accounts no
/// PSO targets get, and the starting point of a new PSO, as `samba-tool domain
/// passwordsettings pso create` (`reglages_du_domaine`).
pub fn domain_settings(entry: &Entry) -> Settings {
    let mut settings = Settings::default();
    let number = |attribute: &str| {
        values(entry, attribute)
            .first()
            .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse::<i64>().ok())
    };
    for (name, attribute) in DOMAIN {
        if let Some(n) = number(attribute) {
            settings.set(name, FieldValue::Number(n));
        }
    }
    if let Some(properties) = number("pwdProperties") {
        settings.complexity = properties & COMPLEX != 0;
        settings.reversible = properties & REVERSIBLE != 0;
    }
    settings
}

/// The password and lockout policy of the domain object (`lire_domaine`). Blocking.
pub fn read_domain(connection: &Connection) -> Result<Settings, Failure> {
    connection.run(true, |link| {
        let base = link.state.root_dse.default_naming_context.clone();
        let mut names: Vec<String> = DOMAIN.iter().map(|(_, a)| (*a).to_owned()).collect();
        names.push("pwdProperties".into());
        Ok(read_entry(link, &base, &names)?
            .map(|e| domain_settings(&e))
            .unwrap_or_default())
    })
}

// --- Checks (pure) -------------------------------------------------------------------------------

/// What prevents writing settings, said by the interface (`problemes`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    OutOfRange {
        field: &'static str,
        value: i64,
        minimum: i64,
        maximum: i64,
    },
    InvalidDuration {
        field: &'static str,
        value: i64,
    },
    MinAgeNotBelowMax,
    WindowLongerThanDuration,
}

fn magnitude(duration: i64) -> i128 {
    -i128::from(duration)
}

/// What prevents writing these settings: bounds of the schema, positive durations,
/// inconsistent ages and lockout. Empty: the settings can be written (`problemes`).
pub fn problems(settings: &Settings) -> Vec<Problem> {
    let mut out = Vec::new();
    for field in &FIELDS {
        let FieldValue::Number(value) = settings.get(field.name) else {
            continue;
        };
        match field.kind {
            Kind::Integer if !(field.minimum..=field.maximum).contains(&value) => {
                out.push(Problem::OutOfRange {
                    field: field.name,
                    value,
                    minimum: field.minimum,
                    maximum: field.maximum,
                });
            }
            Kind::Duration if !(NEVER..=0).contains(&value) => out.push(Problem::InvalidDuration {
                field: field.name,
                value,
            }),
            _ => {}
        }
    }
    let (min, max) = (settings.min_age, settings.max_age);
    if max != 0 && max != NEVER && magnitude(min) >= magnitude(max) {
        out.push(Problem::MinAgeNotBelowMax);
    }
    let (duration, window) = (settings.lockout_duration, settings.lockout_window);
    if duration != NEVER && magnitude(window) > magnitude(duration) {
        out.push(Problem::WindowLongerThanDuration);
    }
    out
}

/// Why a PSO cannot be written as asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PsoError {
    EmptyName,
    NameTooLong,
    Problems(Vec<Problem>),
    Invalid(String),
}

impl From<ChangeError> for PsoError {
    fn from(e: ChangeError) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// The name of a PSO (its `cn`), trimmed (`verifier_nom`).
pub fn check_name(name: &str) -> Result<String, PsoError> {
    let clean = name.trim();
    if clean.is_empty() {
        return Err(PsoError::EmptyName);
    }
    if clean.chars().count() > 64 {
        return Err(PsoError::NameTooLong);
    }
    Ok(clean.to_owned())
}

fn check(settings: &Settings) -> Result<(), PsoError> {
    let found = problems(settings);
    if found.is_empty() {
        Ok(())
    } else {
        Err(PsoError::Problems(found))
    }
}

fn key(dn_text: &str) -> String {
    dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

fn unique_targets(targets: &[String]) -> Vec<String> {
    let mut seen: Vec<(String, String)> = Vec::new();
    for dn_text in targets {
        let k = key(dn_text);
        if !seen.iter().any(|(x, _)| *x == k) {
            seen.push((k, dn_text.clone()));
        }
    }
    seen.into_iter().map(|(_, d)| d).collect()
}

// --- Writing (pure: changesets) ------------------------------------------------------------------

/// A new PSO under the container of the domain `base`, with its ten settings and its targets
/// (`creer`).
pub fn create(
    base: &str,
    name: &str,
    settings: &Settings,
    targets: &[String],
    description: &str,
) -> Result<Changeset, PsoError> {
    let name = check_name(name)?;
    check(settings)?;
    let mut attributes: AttributeMap = vec![
        (
            "objectClass".into(),
            vec![b"top".to_vec(), CLASS.as_bytes().to_vec()],
        ),
        ("cn".into(), vec![name.as_bytes().to_vec()]),
    ];
    for field in &FIELDS {
        attributes.push((
            field.attribute.to_owned(),
            vec![encode(field, settings.get(field.name))],
        ));
    }
    if !description.trim().is_empty() {
        attributes.push((
            "description".into(),
            vec![description.trim().as_bytes().to_vec()],
        ));
    }
    let list = unique_targets(targets);
    if !list.is_empty() {
        attributes.push((
            TARGETS.into(),
            list.iter().map(|d| d.as_bytes().to_vec()).collect(),
        ));
    }
    Ok(Changeset {
        operations: vec![Operation::add(&pso_dn(base, &name), attributes)?],
        remarks: Vec::new(),
    })
}

/// The attributes that change, guarded by the version read; `targets` None: the targets do
/// not change. An empty changeset if nothing changes (`modifier`).
pub fn modify(
    pso: &PsoRead,
    settings: &Settings,
    targets: Option<&[String]>,
    description: Option<&str>,
) -> Result<Changeset, PsoError> {
    check(settings)?;
    let raw = |attribute: &str| -> Vec<Vec<u8>> {
        pso.raw
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attribute))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let mut changes = Vec::new();
    for field in &FIELDS {
        let wanted = settings.get(field.name);
        let before = raw(field.attribute);
        if before
            .first()
            .and_then(|v| decode(field, v))
            .is_some_and(|v| v == wanted)
        {
            continue; // same value, written otherwise (« true »): nothing to write
        }
        changes.push(Change::new(
            field.attribute,
            before.into_iter().take(1).collect(),
            vec![encode(field, wanted)],
        )?);
    }
    if let Some(description) = description {
        let clean = description.trim();
        if clean != pso.description {
            let before: Vec<Vec<u8>> = raw("description").into_iter().take(1).collect();
            let after: Vec<Vec<u8>> = if clean.is_empty() {
                Vec::new()
            } else {
                vec![clean.as_bytes().to_vec()]
            };
            if !before.is_empty() || !after.is_empty() {
                changes.push(Change::new("description", before, after)?);
            }
        }
    }
    if let Some(targets) = targets {
        let wanted = unique_targets(targets);
        let removed: Vec<Vec<u8>> = pso
            .targets
            .iter()
            .filter(|d| !wanted.iter().any(|w| key(w) == key(d)))
            .map(|d| d.as_bytes().to_vec())
            .collect();
        let added: Vec<Vec<u8>> = wanted
            .iter()
            .filter(|w| !pso.targets.iter().any(|d| key(d) == key(w)))
            .map(|w| w.as_bytes().to_vec())
            .collect();
        if !removed.is_empty() || !added.is_empty() {
            changes.push(Change::new(TARGETS, removed, added)?);
        }
    }
    if changes.is_empty() {
        return Ok(Changeset::default());
    }
    Ok(Changeset {
        operations: vec![Operation::modify(&pso.dn, changes, pso.read.clone())?],
        remarks: Vec::new(),
    })
}

/// Deletion; the inverse creates the PSO again with its settings and its targets
/// (`supprimer`).
pub fn delete(pso: &PsoRead) -> Result<Changeset, PsoError> {
    Ok(Changeset {
        operations: vec![Operation::delete(&pso.dn, pso.read.clone(), Vec::new())?],
        remarks: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(dn_text: &str, attributes: &[(&str, &[&str])]) -> Entry {
        Entry {
            dn: dn_text.into(),
            attributes: attributes
                .iter()
                .map(|(a, v)| {
                    (
                        (*a).to_owned(),
                        v.iter().map(|x| x.as_bytes().to_vec()).collect(),
                    )
                })
                .collect(),
        }
    }

    #[test]
    fn read_create_modify_delete() {
        let base = "DC=lab,DC=test";
        let read = entry(
            &pso_dn(base, "Admins"),
            &[
                ("name", &["Admins"]),
                ("msDS-PasswordSettingsPrecedence", &["5"]),
                ("msDS-PasswordComplexityEnabled", &["true"]),
                ("msDS-MaximumPasswordAge", &["-36288000000000"]),
                (TARGETS, &["CN=G,DC=lab,DC=test"]),
            ],
        );
        let pso = pso_from_entry(
            &read,
            Some(Read {
                dc: "dc1".into(),
                usn: 3,
            }),
        );
        assert_eq!(pso.name, "Admins");
        assert_eq!(pso.settings.precedence, 5);
        assert!(pso.settings.complexity);
        assert_eq!(pso.settings.max_age, -42 * DAY);
        assert_eq!(pso.settings.min_length, 7); // absent: the default, not written
        // « true » read, true wanted: not written again; the absent ones are written.
        let cs = modify(&pso, &pso.settings, None, None).unwrap();
        let Operation::Modify { changes, .. } = &cs.operations[0] else {
            panic!("modification expected");
        };
        let names: Vec<&str> = changes.iter().map(|c| c.attribute.as_str()).collect();
        assert!(!names.contains(&"msDS-PasswordComplexityEnabled"));
        assert!(!names.contains(&"msDS-PasswordSettingsPrecedence"));
        assert!(names.contains(&"msDS-MinimumPasswordLength"));
        let targets = vec![
            "cn=g,dc=lab,dc=test".to_owned(),
            "CN=U,DC=lab,DC=test".to_owned(),
        ];
        let mut full = pso.clone();
        full.raw = FIELDS
            .iter()
            .map(|f| {
                (
                    f.attribute.to_owned(),
                    vec![encode(f, pso.settings.get(f.name))],
                )
            })
            .collect();
        let cs = modify(&full, &pso.settings, Some(&targets), Some(" note ")).unwrap();
        let Operation::Modify { changes, .. } = &cs.operations[0] else {
            panic!("modification expected");
        };
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[1].added, [b"CN=U,DC=lab,DC=test".to_vec()]);
        assert!(
            modify(&full, &pso.settings, None, None)
                .unwrap()
                .operations
                .is_empty()
        );

        let created = create(base, "  Nouvelle ", &Settings::default(), &targets, "").unwrap();
        let Operation::Add { dn, attributes } = &created.operations[0] else {
            panic!("add expected");
        };
        assert_eq!(dn, &pso_dn(base, "Nouvelle"));
        assert_eq!(attributes.len(), 2 + 10 + 1);
        assert!(matches!(
            create(base, " ", &Settings::default(), &[], ""),
            Err(PsoError::EmptyName)
        ));
        assert!(matches!(
            create(base, &"x".repeat(65), &Settings::default(), &[], ""),
            Err(PsoError::NameTooLong)
        ));
        assert!(matches!(
            &delete(&pso).unwrap().operations[0],
            Operation::Delete { .. }
        ));
    }

    #[test]
    fn checks() {
        assert!(problems(&Settings::default()).is_empty());
        let bad = Settings {
            precedence: 0,
            min_length: 300,
            min_age: -50 * DAY,
            lockout_window: -60 * MINUTE,
            max_age: 5,
            ..Settings::default()
        };
        let found = problems(&bad);
        assert_eq!(
            found,
            [
                Problem::OutOfRange {
                    field: "priorite",
                    value: 0,
                    minimum: 1,
                    maximum: 2_147_483_647
                },
                Problem::OutOfRange {
                    field: "longueur_minimale",
                    value: 300,
                    minimum: 0,
                    maximum: 255
                },
                Problem::InvalidDuration {
                    field: "age_maximal",
                    value: 5
                },
                Problem::MinAgeNotBelowMax,
                Problem::WindowLongerThanDuration,
            ]
        );
        // Never expires, until unlocked: no comparison.
        let never = Settings {
            max_age: NEVER,
            lockout_duration: NEVER,
            lockout_window: -60 * MINUTE,
            ..Settings::default()
        };
        assert!(problems(&never).is_empty());
        let domain = entry(
            "DC=lab,DC=test",
            &[("minPwdLength", &["12"]), ("pwdProperties", &["17"])],
        );
        let s = domain_settings(&domain);
        assert_eq!((s.min_length, s.complexity, s.reversible), (12, true, true));
    }
}

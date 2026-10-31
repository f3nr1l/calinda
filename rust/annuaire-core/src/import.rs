// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Import of users, groups, contacts and computers from a CSV file (J9.8, ADR 0026).
//!
//! The file is read whole and **checked line by line before any write**: kind of object, name,
//! container, identifier, each attribute (known to the schema, writable, allowed by the class,
//! value accepted by its syntax and its bounds — the reading is the one of the attribute
//! editor, given by the caller), duplicates within the file (DN, `sAMAccountName`,
//! `userPrincipalName`) and in the directory, groups to join, home folder. Each line gets its
//! report; the lines without problem become the items of a change in bulk (`bulk`), written by
//! batches, each batch one changeset.
//!
//! A line is built by the builders of the unit creation (`actions::create_user`,
//! `create_group`, `computers::create_computer`, `create_contact`): the defaults are those of
//! the dialogs (account disabled without a password, `userAccountControl` 4128 for a computer,
//! `%username%` expanded in the profile and the home folder, folder created on its share with
//! the permissions of ADUC, ADR 0027); the other columns are added to the creation, and win over
//! what the builder put.
//!
//! **Columns**: an LDAP name (`sAMAccountName`), a label the interface knows (`Prénom`), or one
//! of the columns of the import itself, in English or in French, the names of `New-ADUser`
//! included (`Name`, `Path`, `AccountPassword`, `Enabled`, `ChangePasswordAtLogon`,
//! `GroupScope`, `GroupCategory`): `type`, `name`, `path`, `password`, `enabled`,
//! `changePasswordAtLogon`, `groupScope`, `groupCategory`, `memberOf` (groups to join: DN or
//! `sAMAccountName`).
//!
//! **Passwords**: read in the file, or generated (16 characters, the four kinds) when the
//! option asks it or when an enabled account has none; a password read is checked against the
//! length and the complexity of the domain. The generated ones are given back to the caller,
//! which hands them to the administrator; none is journaled (ADR 0006 § 4).

use std::collections::{HashMap, HashSet};

use annuaire_codecs::csv::{self, Table};
use annuaire_codecs::uac::Scope as GroupScope;

use crate::actions::{self, ActionError, NewUser};
use crate::bulk::{Item, Membership};
use crate::changes::{AttributeMap, Operation, Read, dn_key};
use crate::computers::{self, NewComputer, NewContact, PasswordRule};
use crate::connection::{Connection, Failure};
use crate::dn;
use crate::error::LdapError;
use crate::home_folder::{self, NewFolder, Plan, PlanError};
use crate::schema::{AttributeDescription, Schema};
use crate::search::{self, Burst, BurstAnswer};
use crate::session::{Entry, Scope};

/// Length of a generated password.
pub const GENERATED_LENGTH: usize = 16;
/// Values per `(|(sAMAccountName=…)…)` search of the duplicates in the directory.
const PER_FILTER: usize = 50;

/// What a line creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    User,
    Group,
    Contact,
    Computer,
}

impl Kind {
    /// The kind written in the column `type`: English, French or the LDAP class.
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_lowercase().as_str() {
            "user" | "utilisateur" | "inetorgperson" => Some(Self::User),
            "group" | "groupe" => Some(Self::Group),
            "contact" => Some(Self::Contact),
            "computer" | "ordinateur" => Some(Self::Computer),
            _ => None,
        }
    }

    /// The most derived class, which says what attributes are allowed.
    pub fn class(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Contact => "contact",
            Self::Computer => "computer",
        }
    }

    /// Accounts: an identifier unique in the domain.
    pub fn account(self) -> bool {
        self != Self::Contact
    }
}

/// What a column of the file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Kind,
    Name,
    Path,
    Password,
    Enabled,
    ChangeAtLogon,
    GroupScope,
    GroupCategory,
    MemberOf,
    /// An attribute of the schema, in its spelling.
    Attribute(String),
    /// Known neither to the import nor to the schema: its values are refused.
    Unknown(String),
    /// Empty header: the column is left aside.
    Ignored,
}

/// Columns of the import itself, by every name it reads (lower case).
fn pseudo(name: &str) -> Option<Target> {
    Some(match name {
        "type" | "objectclass" | "classe" | "genre" => Target::Kind,
        "name" | "nom" | "cn" => Target::Name,
        "path" | "ou" | "parent" | "conteneur" | "emplacement" => Target::Path,
        "password" | "accountpassword" | "motdepasse" | "mot de passe" | "unicodepwd" => {
            Target::Password
        }
        "enabled" | "actif" | "activé" | "active" => Target::Enabled,
        "changepasswordatlogon" | "changer le mot de passe" | "changement obligatoire" => {
            Target::ChangeAtLogon
        }
        "groupscope" | "étendue" | "etendue" => Target::GroupScope,
        "groupcategory" | "catégorie" | "categorie" => Target::GroupCategory,
        "memberof" | "groupes" | "membre de" => Target::MemberOf,
        _ => return None,
    })
}

/// What each header says: a column of the import, an attribute of the schema (by its LDAP
/// name, or a label of the interface in `labels`, lower case → LDAP name), or unknown.
pub fn targets(
    header: &[String],
    schema: &Schema,
    labels: &HashMap<String, String>,
) -> Vec<Target> {
    header
        .iter()
        .map(|h| {
            let text = h.trim();
            let lower = text.to_lowercase();
            if text.is_empty() {
                return Target::Ignored;
            }
            if let Some(t) = pseudo(&lower) {
                return t;
            }
            if let Some(d) = schema.attribute(text) {
                return Target::Attribute(d.name.clone());
            }
            match labels.get(&lower).and_then(|a| schema.attribute(a)) {
                Some(d) => Target::Attribute(d.name.clone()),
                None => Target::Unknown(text.to_owned()),
            }
        })
        .collect()
}

/// How the file is imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    /// For the lines without a column `type`.
    pub kind: Kind,
    /// For the lines without a column `path` (or with an empty one).
    pub parent: String,
    /// Separator of the fields; None: guessed.
    pub separator: Option<char>,
    /// Separator of the values of a multivalued attribute.
    pub values_separator: String,
    /// Generate the password of every account, even when the file gives one.
    pub generate: bool,
    /// For the lines without a column `enabled`.
    pub enable: bool,
    /// For the lines without a column `changePasswordAtLogon`.
    pub change_at_next_logon: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            kind: Kind::User,
            parent: String::new(),
            separator: None,
            values_separator: crate::export::VALUES_SEPARATOR.to_owned(),
            generate: false,
            enable: true,
            change_at_next_logon: true,
        }
    }
}

/// What can be wrong with a line; the interface says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    UnknownKind(String),
    NoName,
    NoIdentifier,
    /// From the builder of the unit creation (invalid identifier, refused default password…).
    Action(ActionError),
    InvalidPath(String),
    PathMissing(String),
    UnknownColumn(String),
    /// `systemOnly`, constructed, or a back link.
    NotWritable(String),
    NotAllowed {
        attribute: String,
        class: String,
    },
    Value {
        attribute: String,
        message: String,
    },
    SeveralValues(String),
    /// A column for another kind of object (`groupScope` on a user).
    NotForKind(String),
    InvalidFlag {
        column: String,
        value: String,
    },
    /// The same DN, identifier or UPN on an earlier line of the file.
    DuplicateInFile {
        what: Unique,
        value: String,
        line: usize,
    },
    /// Already in the directory: the object that has it.
    InDirectory {
        what: Unique,
        value: String,
        dn: String,
    },
    GroupMissing(String),
    /// An enabled account without a password, and none generated.
    NoPassword,
    PasswordTooShort {
        minimum: usize,
    },
    PasswordNotComplex,
    /// The home folder cannot be created (share or parent missing, file of that name).
    HomeFolder {
        unc: String,
        refusal: home_folder::Refusal,
    },
    /// The file server of the home folder cannot be read.
    HomeFolderServer {
        server: String,
        message: String,
    },
}

/// What must be unique.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Unique {
    Dn,
    Identifier,
    Upn,
}

/// What a line says besides its problems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    PasswordGenerated,
    /// The home folder exists: left as it is.
    HomeFolderExists(String),
    HomeFolderCreated(String),
}

/// The report of a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// Line of the file where the record starts.
    pub line: usize,
    pub kind: Option<Kind>,
    pub name: String,
    pub dn: String,
    pub identifier: String,
    pub problems: Vec<Problem>,
    pub notes: Vec<Note>,
    /// Its item in `Checked::items`, for a line without problem.
    pub item: Option<usize>,
}

/// A generated password, for the administrator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generated {
    pub line: usize,
    pub identifier: String,
    pub dn: String,
    pub password: String,
}

/// The file checked: a report per line, the items of the lines to import, the passwords
/// generated for them.
#[derive(Debug, Clone, Default)]
pub struct Checked {
    pub separator: char,
    pub columns: Vec<Target>,
    pub lines: Vec<Line>,
    pub items: Vec<Item>,
    pub generated: Vec<Generated>,
}

impl Checked {
    pub fn refused(&self) -> usize {
        self.lines.iter().filter(|l| !l.problems.is_empty()).count()
    }
}

/// Why the file cannot be checked at all.
#[derive(Debug, Clone)]
pub enum ImportError {
    Csv(csv::CsvError),
    /// No line after the header.
    Empty,
    Failure(Failure),
}

/// The reading of a value by its syntax (the one of the attribute editor).
pub type Reader<'a> = dyn Fn(&AttributeDescription, &str) -> Result<Vec<u8>, String> + 'a;

// --- Passwords --------------------------------------------------------------------------------

/// The four kinds of characters of the complexity of Windows.
fn kinds(password: &str) -> usize {
    [
        password.chars().any(|c| c.is_uppercase()),
        password.chars().any(|c| c.is_lowercase()),
        password.chars().any(|c| c.is_ascii_digit()),
        password.chars().any(|c| !c.is_alphanumeric()),
    ]
    .iter()
    .filter(|&&k| k)
    .count()
}

/// Checks a password read in the file against the policy of the domain: length, three kinds
/// of characters among four, not the identifier (MS-ADTS 3.1.1.3.1.5 and the complexity
/// filter of Windows, account name part).
pub fn password_problem(password: &str, identifier: &str, rule: &PasswordRule) -> Option<Problem> {
    if password.chars().count() < rule.min_length {
        return Some(Problem::PasswordTooShort {
            minimum: rule.min_length,
        });
    }
    let named = identifier.chars().count() > 2
        && password
            .to_lowercase()
            .contains(&identifier.trim_end_matches('$').to_lowercase());
    if rule.complex && (kinds(password) < 3 || named) {
        return Some(Problem::PasswordNotComplex);
    }
    None
}

/// A password of `length` characters (at least 16), each of the four kinds present, drawn
/// from the system OpenSSL; no character that is read wrong (`0O1lI`).
pub fn generate_password(length: usize) -> Result<String, ActionError> {
    const SETS: [&[u8]; 4] = [
        b"ABCDEFGHJKLMNPQRSTUVWXYZ",
        b"abcdefghijkmnopqrstuvwxyz",
        b"23456789",
        b"-_.:!#%&*+=?@",
    ];
    let length = length.max(GENERATED_LENGTH);
    loop {
        let mut bytes = vec![0u8; length * 2];
        openssl::rand::rand_bytes(&mut bytes).map_err(|e| ActionError::Change(e.to_string()))?;
        let all: Vec<u8> = SETS.iter().flat_map(|s| s.iter().copied()).collect();
        let password: String = bytes
            .chunks(2)
            .map(|pair| {
                let n = pair.iter().fold(0usize, |n, b| (n << 8) | usize::from(*b));
                char::from(all.get(n % all.len()).copied().unwrap_or(b'x'))
            })
            .collect();
        if kinds(&password) == 4 {
            return Ok(password);
        }
    }
}

// --- Reading of the lines --------------------------------------------------------------------

fn flag(text: &str) -> Option<bool> {
    match text.trim().to_lowercase().as_str() {
        "true" | "vrai" | "oui" | "yes" | "1" | "$true" => Some(true),
        "false" | "faux" | "non" | "no" | "0" | "$false" => Some(false),
        _ => None,
    }
}

fn scope(text: &str) -> Option<GroupScope> {
    match text.trim().to_lowercase().replace([' ', '-'], "").as_str() {
        "global" | "globale" => Some(GroupScope::Global),
        "domainlocal" | "localdedomaine" | "domainelocal" => Some(GroupScope::DomainLocal),
        "universal" | "universelle" => Some(GroupScope::Universal),
        _ => None,
    }
}

fn category(text: &str) -> Option<bool> {
    match text.trim().to_lowercase().as_str() {
        "security" | "sécurité" | "securite" => Some(true),
        "distribution" => Some(false),
        _ => None,
    }
}

/// Attributes the classes allow, with their parents and linked auxiliaries (lower case); empty
/// if the schema does not describe the class.
fn allowed(schema: &Schema, class: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut seen = HashSet::new();
    let mut to_see = vec![class.to_owned()];
    while let Some(name) = to_see.pop() {
        if !seen.insert(name.to_lowercase()) {
            continue;
        }
        for c in schema.ancestry(&name) {
            out.extend(
                c.mandatory
                    .iter()
                    .chain(&c.optional)
                    .map(|a| a.to_lowercase()),
            );
            to_see.extend(c.auxiliaries.iter().cloned());
        }
    }
    out
}

/// What a line asks, read without the directory.
#[derive(Debug, Clone)]
struct Asked {
    kind: Option<Kind>,
    name: String,
    parent: String,
    identifier: String,
    upn: String,
    password: Option<String>,
    enable: bool,
    change: bool,
    scope: GroupScope,
    security: bool,
    member_of: Vec<String>,
    /// Other attributes, in the order of the columns.
    attributes: AttributeMap,
}

impl Default for Asked {
    fn default() -> Self {
        Self {
            kind: None,
            name: String::new(),
            parent: String::new(),
            identifier: String::new(),
            upn: String::new(),
            password: None,
            enable: false,
            change: false,
            scope: GroupScope::Global,
            security: true,
            member_of: Vec::new(),
            attributes: Vec::new(),
        }
    }
}

fn text_of(attributes: &AttributeMap, name: &str) -> String {
    attributes
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(name))
        .and_then(|(_, v)| v.first())
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

#[allow(clippy::too_many_lines)]
fn read_line(
    fields: &[String],
    columns: &[Target],
    schema: &Schema,
    options: &Options,
    reader: &Reader<'_>,
    problems: &mut Vec<Problem>,
) -> Asked {
    let mut asked = Asked {
        enable: options.enable,
        change: options.change_at_next_logon,
        security: true,
        ..Asked::default()
    };
    let cell = |target: &Target| {
        columns
            .iter()
            .zip(fields)
            .find(|(t, _)| *t == target)
            .map(|(_, f)| f.trim().to_owned())
            .filter(|f| !f.is_empty())
    };
    asked.kind = match cell(&Target::Kind) {
        None => Some(options.kind),
        Some(text) => {
            let kind = Kind::parse(&text);
            if kind.is_none() {
                problems.push(Problem::UnknownKind(text));
            }
            kind
        }
    };
    let kind = asked.kind.unwrap_or(options.kind);
    asked.name = cell(&Target::Name).unwrap_or_default();
    asked.parent = cell(&Target::Path).unwrap_or_else(|| options.parent.clone());
    asked.password = cell(&Target::Password);
    for (target, slot) in [
        (Target::Enabled, &mut asked.enable),
        (Target::ChangeAtLogon, &mut asked.change),
    ] {
        if let Some(text) = cell(&target) {
            match flag(&text) {
                Some(v) => *slot = v,
                None => problems.push(Problem::InvalidFlag {
                    column: format!("{target:?}"),
                    value: text,
                }),
            }
        }
    }
    if let Some(text) = cell(&Target::GroupScope) {
        match scope(&text) {
            Some(s) if kind == Kind::Group => asked.scope = s,
            Some(_) => problems.push(Problem::NotForKind("groupScope".into())),
            None => problems.push(Problem::InvalidFlag {
                column: "groupScope".into(),
                value: text,
            }),
        }
    }
    if let Some(text) = cell(&Target::GroupCategory) {
        match category(&text) {
            Some(c) if kind == Kind::Group => asked.security = c,
            Some(_) => problems.push(Problem::NotForKind("groupCategory".into())),
            None => problems.push(Problem::InvalidFlag {
                column: "groupCategory".into(),
                value: text,
            }),
        }
    }
    if let Some(text) = cell(&Target::MemberOf) {
        asked.member_of = text
            .split(options.values_separator.as_str())
            .map(str::trim)
            .filter(|g| !g.is_empty())
            .map(str::to_owned)
            .collect();
    }
    let permitted = allowed(schema, kind.class());
    for (target, field) in columns.iter().zip(fields) {
        let field = field.trim();
        if field.is_empty() {
            continue;
        }
        let name = match target {
            Target::Unknown(name) => {
                problems.push(Problem::UnknownColumn(name.clone()));
                continue;
            }
            Target::Attribute(name) => name,
            _ => continue,
        };
        let Some(d) = schema.attribute(name) else {
            problems.push(Problem::UnknownColumn(name.clone()));
            continue;
        };
        if d.system || d.constructed || d.back_link() {
            problems.push(Problem::NotWritable(d.name.clone()));
            continue;
        }
        if !permitted.is_empty() && !permitted.contains(&d.name.to_lowercase()) {
            problems.push(Problem::NotAllowed {
                attribute: d.name.clone(),
                class: kind.class().to_owned(),
            });
            continue;
        }
        let texts: Vec<&str> = if d.single {
            vec![field]
        } else {
            field
                .split(options.values_separator.as_str())
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .collect()
        };
        let mut values = Vec::new();
        for t in texts {
            match reader(d, t) {
                Ok(v) => values.push(v),
                Err(message) => problems.push(Problem::Value {
                    attribute: d.name.clone(),
                    message,
                }),
            }
        }
        if d.single && values.len() > 1 {
            problems.push(Problem::SeveralValues(d.name.clone()));
        }
        match asked
            .attributes
            .iter_mut()
            .find(|(a, _)| a.eq_ignore_ascii_case(&d.name))
        {
            Some((_, existing)) => existing.extend(values),
            None => asked.attributes.push((d.name.clone(), values)),
        }
    }
    asked.identifier = text_of(&asked.attributes, "sAMAccountName");
    asked.upn = text_of(&asked.attributes, "userPrincipalName");
    if asked.name.is_empty() {
        // As New-ADUser: the name may come from the display name, or the given name and surname.
        let display = text_of(&asked.attributes, "displayName");
        let full = format!(
            "{} {}",
            text_of(&asked.attributes, "givenName"),
            text_of(&asked.attributes, "sn")
        );
        asked.name = if display.is_empty() {
            full.trim().to_owned()
        } else {
            display
        };
    }
    if asked.name.is_empty() {
        problems.push(Problem::NoName);
    }
    match asked.kind.map(|_| kind) {
        Some(Kind::User) if asked.identifier.is_empty() => problems.push(Problem::NoIdentifier),
        Some(Kind::Computer) if asked.identifier.is_empty() => {
            asked.identifier = format!("{}$", computers::proposed_identifier(&asked.name));
        }
        Some(Kind::Group) if asked.identifier.is_empty() => asked.identifier = asked.name.clone(),
        _ => {}
    }
    asked
}

/// The DN of a line: `CN=name` under its container.
fn line_dn(asked: &Asked) -> Result<String, Problem> {
    if asked.name.trim().is_empty() {
        return Err(Problem::NoName);
    }
    if dn::split(&asked.parent).is_err() || asked.parent.trim().is_empty() {
        return Err(Problem::InvalidPath(asked.parent.clone()));
    }
    let rdn = dn::compose(&[dn::Component::new("CN", asked.name.trim())])
        .map_err(|_| Problem::InvalidPath(asked.parent.clone()))?;
    Ok(format!("{rdn},{}", asked.parent.trim()))
}

// --- In the directory --------------------------------------------------------------------------

/// What the directory says of the file: objects at the DNs, owners of the identifiers and the
/// UPN, containers present, groups found (by DN or identifier, lower case).
#[derive(Debug, Default)]
struct Found {
    dns: HashSet<String>,
    identifiers: HashMap<String, String>,
    upns: HashMap<String, String>,
    parents: HashSet<String>,
    groups: HashMap<String, (String, Read)>,
}

fn usn(entry: &Entry) -> Option<i64> {
    entry.values("uSNChanged").first().and_then(|v| {
        annuaire_codecs::integer::decode(v, annuaire_codecs::integer::Width::Bits64).ok()
    })
}

fn lookup(
    connection: &Connection,
    dns: Vec<String>,
    parents: Vec<String>,
    identifiers: Vec<String>,
    upns: Vec<String>,
    groups: Vec<String>,
) -> Result<Found, Failure> {
    connection.run(true, move |link| {
        let base = link.state.root_dse.default_naming_context.clone();
        let dc = link.state.dc.clone();
        let mut found = Found::default();
        let one = |attribute: &str, values: &[String]| -> Result<String, LdapError> {
            let clauses: Vec<String> = values
                .iter()
                .filter_map(|v| search::eq(attribute, search::Value::Text(v)).ok())
                .collect();
            search::or(&clauses)
                .map_err(|e| LdapError::new(crate::error::code::FILTER_ERROR, e.to_string()))
        };
        let attributes: Vec<String> = [
            "sAMAccountName",
            "userPrincipalName",
            "uSNChanged",
            "objectClass",
        ]
        .map(str::to_owned)
        .to_vec();
        // Objects at the DNs and containers: base reads.
        for (list, into_parents) in [(&dns, false), (&parents, true)] {
            for chunk in list.chunks(crate::export::CHUNK) {
                let mut burst = Burst::new();
                for d in chunk {
                    burst.search(
                        link.session.as_mut(),
                        d,
                        Scope::Base,
                        "(objectClass=*)",
                        &["1.1".to_owned()],
                        0,
                        None,
                    )?;
                }
                for (d, answer) in chunk
                    .iter()
                    .zip(burst.receive(link.session.as_mut(), Some(link.timeout))?)
                {
                    if matches!(&answer, BurstAnswer::Entries(e) if !e.is_empty()) {
                        let k = dn_key(d).unwrap_or_else(|_| d.to_lowercase());
                        if into_parents {
                            found.parents.insert(k);
                        } else {
                            found.dns.insert(k);
                        }
                    }
                }
            }
        }
        // Identifiers and UPN: one search for each fifty, from the root of the domain.
        for (attribute, list, into) in [
            ("sAMAccountName", &identifiers, 0),
            ("userPrincipalName", &upns, 1),
        ] {
            for chunk in list.chunks(PER_FILTER) {
                let filter = one(attribute, chunk)?;
                let mut burst = Burst::new();
                burst.search(
                    link.session.as_mut(),
                    &base,
                    Scope::Subtree,
                    &filter,
                    &attributes,
                    0,
                    None,
                )?;
                for answer in burst.receive(link.session.as_mut(), Some(link.timeout))? {
                    let BurstAnswer::Entries(entries) = answer else {
                        continue;
                    };
                    for e in entries {
                        let value = e
                            .values(attribute)
                            .first()
                            .map(|v| String::from_utf8_lossy(v).to_lowercase())
                            .unwrap_or_default();
                        let map = if into == 0 {
                            &mut found.identifiers
                        } else {
                            &mut found.upns
                        };
                        map.insert(value, e.dn.clone());
                    }
                }
            }
        }
        // Groups: by DN, or by identifier.
        let mut burst = Burst::new();
        let mut asked = Vec::new();
        for g in &groups {
            let rank = if dn::split(g).is_ok() && g.contains('=') {
                burst.search(
                    link.session.as_mut(),
                    g,
                    Scope::Base,
                    "(objectClass=group)",
                    &attributes,
                    0,
                    None,
                )?
            } else {
                let filter = format!(
                    "(&(objectClass=group){})",
                    search::eq("sAMAccountName", search::Value::Text(g))
                        .unwrap_or_else(|_| "(sAMAccountName=*)".into())
                );
                burst.search(
                    link.session.as_mut(),
                    &base,
                    Scope::Subtree,
                    &filter,
                    &attributes,
                    2,
                    None,
                )?
            };
            asked.push((g.to_lowercase(), rank));
        }
        let answers = burst.receive(link.session.as_mut(), Some(link.timeout))?;
        for (k, rank) in asked {
            if let Some(BurstAnswer::Entries(entries)) = answers.get(rank) {
                if let [entry] = entries.as_slice() {
                    if let Some(n) = usn(entry) {
                        found.groups.insert(
                            k,
                            (
                                entry.dn.clone(),
                                Read {
                                    dc: dc.clone(),
                                    usn: n,
                                },
                            ),
                        );
                    }
                }
            }
        }
        Ok(found)
    })
}

// --- The whole ---------------------------------------------------------------------------------

/// Builds the creation of a line (one `Add`, the attributes of the file added).
fn build(
    kind: Kind,
    asked: &Asked,
    password: Option<&str>,
    rule: &PasswordRule,
) -> Result<Operation, ActionError> {
    let parent = asked.parent.trim();
    let changeset = match kind {
        Kind::User => actions::create_user(
            parent,
            &NewUser {
                full_name: asked.name.clone(),
                identifier: asked.identifier.clone(),
                upn: asked.upn.clone(),
                given_name: text_of(&asked.attributes, "givenName"),
                surname: text_of(&asked.attributes, "sn"),
                password: password.map(str::to_owned),
                change_at_next_logon: asked.change,
                enable: asked.enable,
                profile_path: text_of(&asked.attributes, "profilePath"),
                home_drive: text_of(&asked.attributes, "homeDrive"),
                home_directory: text_of(&asked.attributes, "homeDirectory"),
            },
        )?,
        Kind::Group => actions::create_group(
            parent,
            &asked.name,
            &asked.identifier,
            asked.scope,
            asked.security,
            &text_of(&asked.attributes, "description"),
        )?,
        Kind::Contact => computers::create_contact(
            parent,
            &NewContact {
                full_name: asked.name.clone(),
                ..NewContact::default()
            },
        )?,
        Kind::Computer => computers::create_computer(
            parent,
            &NewComputer {
                name: asked.name.clone(),
                identifier: asked.identifier.clone(),
                description: text_of(&asked.attributes, "description"),
                ..NewComputer::default()
            },
            rule,
        )?,
    };
    let Some(Operation::Add { dn, mut attributes }) = changeset.operations.into_iter().next()
    else {
        return Err(ActionError::EmptyName);
    };
    // The builder expanded %username% and trimmed: its values of these stay.
    let kept = ["profilePath", "homeDirectory", "sAMAccountName"];
    for (name, values) in &asked.attributes {
        if values.is_empty()
            || (kept.iter().any(|k| k.eq_ignore_ascii_case(name))
                && attributes.iter().any(|(a, _)| a.eq_ignore_ascii_case(name)))
        {
            continue;
        }
        match attributes
            .iter_mut()
            .find(|(a, _)| a.eq_ignore_ascii_case(name))
        {
            Some((_, existing)) => *existing = values.clone(),
            None => attributes.push((name.clone(), values.clone())),
        }
    }
    Operation::add(&dn, attributes).map_err(|e| ActionError::Change(e.to_string()))
}

fn sam_of(attributes: &AttributeMap) -> String {
    text_of(attributes, "sAMAccountName")
}

/// Checks `bytes` (a whole file) and builds the items of its valid lines. Blocking: one round
/// trip per two hundred objects read, one search per fifty identifiers, one SMB session per
/// share of the home folders.
#[allow(clippy::too_many_lines)]
pub fn check(
    connection: &Connection,
    bytes: &[u8],
    schema: &Schema,
    labels: &HashMap<String, String>,
    options: &Options,
    reader: &Reader<'_>,
    rule: &PasswordRule,
) -> Result<Checked, ImportError> {
    let table: Table = csv::read(bytes, options.separator).map_err(ImportError::Csv)?;
    let mut records = table.records.into_iter();
    let header = records.next().ok_or(ImportError::Empty)?;
    let columns = targets(&header.fields, schema, labels);
    let records: Vec<_> = records.collect();
    if records.is_empty() {
        return Err(ImportError::Empty);
    }
    let mut lines = Vec::with_capacity(records.len());
    let mut asked_all = Vec::with_capacity(records.len());
    for record in &records {
        let mut problems = Vec::new();
        let asked = read_line(
            &record.fields,
            &columns,
            schema,
            options,
            reader,
            &mut problems,
        );
        let dn = match line_dn(&asked) {
            Ok(dn) => dn,
            Err(p) => {
                if !problems.contains(&p) {
                    problems.push(p);
                }
                String::new()
            }
        };
        lines.push(Line {
            line: record.line,
            kind: asked.kind,
            name: asked.name.clone(),
            dn,
            identifier: asked.identifier.clone(),
            problems,
            notes: Vec::new(),
            item: None,
        });
        asked_all.push(asked);
    }
    // Duplicates within the file: the first line keeps it.
    let mut first: HashMap<(Unique, String), usize> = HashMap::new();
    for (line, asked) in lines.iter_mut().zip(&asked_all) {
        let kind = asked.kind.unwrap_or(options.kind);
        let mut keys = Vec::new();
        if !line.dn.is_empty() {
            keys.push((
                Unique::Dn,
                dn_key(&line.dn).unwrap_or_else(|_| line.dn.to_lowercase()),
                line.dn.clone(),
            ));
        }
        if kind.account() && !asked.identifier.is_empty() {
            keys.push((
                Unique::Identifier,
                asked.identifier.to_lowercase(),
                asked.identifier.clone(),
            ));
        }
        if !asked.upn.is_empty() {
            keys.push((Unique::Upn, asked.upn.to_lowercase(), asked.upn.clone()));
        }
        for (what, k, value) in keys {
            match first.get(&(what, k.clone())) {
                Some(&earlier) => line.problems.push(Problem::DuplicateInFile {
                    what,
                    value,
                    line: earlier,
                }),
                None => {
                    first.insert((what, k), line.line);
                }
            }
        }
    }
    // The directory.
    let distinct = |values: Vec<String>| {
        let mut seen = HashSet::new();
        values
            .into_iter()
            .filter(|v| !v.is_empty() && seen.insert(v.to_lowercase()))
            .collect::<Vec<_>>()
    };
    let found = lookup(
        connection,
        distinct(lines.iter().map(|l| l.dn.clone()).collect()),
        distinct(
            asked_all
                .iter()
                .map(|a| a.parent.trim().to_owned())
                .collect(),
        ),
        distinct(
            asked_all
                .iter()
                .filter(|a| a.kind.unwrap_or(options.kind).account())
                .map(|a| a.identifier.clone())
                .collect(),
        ),
        distinct(asked_all.iter().map(|a| a.upn.clone()).collect()),
        distinct(asked_all.iter().flat_map(|a| a.member_of.clone()).collect()),
    )
    .map_err(ImportError::Failure)?;
    for (line, asked) in lines.iter_mut().zip(&asked_all) {
        let kind = asked.kind.unwrap_or(options.kind);
        let parent = asked.parent.trim();
        if !parent.is_empty()
            && dn::split(parent).is_ok()
            && !found
                .parents
                .contains(&dn_key(parent).unwrap_or_else(|_| parent.to_lowercase()))
        {
            line.problems.push(Problem::PathMissing(parent.to_owned()));
        }
        if !line.dn.is_empty() && found.dns.contains(&dn_key(&line.dn).unwrap_or_default()) {
            line.problems.push(Problem::InDirectory {
                what: Unique::Dn,
                value: line.dn.clone(),
                dn: line.dn.clone(),
            });
        }
        if kind.account() {
            if let Some(owner) = found.identifiers.get(&asked.identifier.to_lowercase()) {
                line.problems.push(Problem::InDirectory {
                    what: Unique::Identifier,
                    value: asked.identifier.clone(),
                    dn: owner.clone(),
                });
            }
        }
        if let Some(owner) = found.upns.get(&asked.upn.to_lowercase()) {
            line.problems.push(Problem::InDirectory {
                what: Unique::Upn,
                value: asked.upn.clone(),
                dn: owner.clone(),
            });
        }
        for g in &asked.member_of {
            if !found.groups.contains_key(&g.to_lowercase()) {
                line.problems.push(Problem::GroupMissing(g.clone()));
            }
        }
    }
    // Passwords and creations.
    let mut built: Vec<Option<(Operation, Option<String>)>> = Vec::with_capacity(lines.len());
    for (line, asked) in lines.iter_mut().zip(&asked_all) {
        let kind = asked.kind.unwrap_or(options.kind);
        if !line.problems.is_empty() || asked.kind.is_none() {
            built.push(None);
            continue;
        }
        let mut generated = None;
        let password = if kind == Kind::User {
            match (&asked.password, options.generate) {
                (Some(p), false) => {
                    if let Some(problem) = password_problem(p, &asked.identifier, rule) {
                        line.problems.push(problem);
                    }
                    Some(p.clone())
                }
                (None, false) if !asked.enable => None,
                _ => match generate_password(rule.min_length) {
                    Ok(p) => {
                        generated = Some(p.clone());
                        line.notes.push(Note::PasswordGenerated);
                        Some(p)
                    }
                    Err(e) => {
                        line.problems.push(Problem::Action(e));
                        None
                    }
                },
            }
        } else {
            None
        };
        if kind == Kind::User && asked.enable && password.is_none() {
            line.problems.push(Problem::NoPassword);
        }
        if !line.problems.is_empty() {
            built.push(None);
            continue;
        }
        match build(kind, asked, password.as_deref(), rule) {
            Ok(op) => built.push(Some((op, generated))),
            Err(e) => {
                line.problems.push(Problem::Action(e));
                built.push(None);
            }
        }
    }
    // Home folders of the users created (ADR 0027), one session per share.
    let mut folders = Vec::new();
    let mut folder_of = Vec::new();
    for (i, b) in built.iter().enumerate() {
        let Some((Operation::Add { dn, attributes }, _)) = b else {
            continue;
        };
        let directory = text_of(attributes, "homeDirectory");
        if text_of(attributes, "homeDrive").trim().is_empty() || directory.trim().is_empty() {
            continue;
        }
        folders.push(NewFolder {
            dn: dn.clone(),
            sam: sam_of(attributes),
            directory,
        });
        folder_of.push(i);
    }
    let mut extra: HashMap<usize, Operation> = HashMap::new();
    if !folders.is_empty() {
        let plans =
            home_folder::plan_new_many(connection, &folders).map_err(ImportError::Failure)?;
        for (i, plan) in folder_of.into_iter().zip(plans) {
            let Some(line) = lines.get_mut(i) else {
                continue;
            };
            match plan {
                Ok(None) => {}
                Ok(Some(Plan::Exists { unc })) => line.notes.push(Note::HomeFolderExists(unc)),
                Ok(Some(Plan::Create(op))) => {
                    if let Operation::CreateShareFolder { unc, .. } = op.as_ref() {
                        line.notes.push(Note::HomeFolderCreated(unc.clone()));
                    }
                    extra.insert(i, *op);
                }
                Err(PlanError::Refused { unc, refusal }) => {
                    line.problems.push(Problem::HomeFolder { unc, refusal });
                }
                Err(PlanError::Server { server, error }) => {
                    line.problems.push(Problem::HomeFolderServer {
                        server,
                        message: error.to_string(),
                    });
                }
                Err(PlanError::Failure(f)) => return Err(ImportError::Failure(f)),
            }
        }
    }
    let mut checked = Checked {
        separator: table.separator,
        columns,
        ..Checked::default()
    };
    for (i, ((mut line, asked), b)) in lines.into_iter().zip(asked_all).zip(built).enumerate() {
        if let (Some((op, generated)), true) = (b, line.problems.is_empty()) {
            let dn = op.dn().to_owned();
            let mut operations = vec![op];
            operations.extend(extra.remove(&i));
            let memberships = asked
                .member_of
                .iter()
                .filter_map(|g| found.groups.get(&g.to_lowercase()))
                .map(|(group, read)| Membership {
                    group: group.clone(),
                    read: Some(read.clone()),
                    member: dn.clone(),
                    add: true,
                })
                .collect();
            if let Some(password) = generated {
                checked.generated.push(Generated {
                    line: line.line,
                    identifier: line.identifier.clone(),
                    dn: dn.clone(),
                    password,
                });
            }
            line.item = Some(checked.items.len());
            checked.items.push(Item {
                label: format!("{} ({})", line.name, line.line),
                operations,
                memberships,
            });
        }
        checked.lines.push(line);
    }
    Ok(checked)
}

/// The file of the generated passwords, for the administrator (ADR 0026 § 4): line,
/// identifier, DN, password.
pub fn passwords_file(generated: &[Generated], separator: char) -> String {
    let rows: Vec<Vec<String>> = generated
        .iter()
        .map(|g| {
            vec![
                g.line.to_string(),
                g.identifier.clone(),
                g.dn.clone(),
                g.password.clone(),
            ]
        })
        .collect();
    csv::write(
        &["line", "sAMAccountName", "dn", "password"],
        &rows,
        separator,
        true,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::Syntax;

    fn description(name: &str, syntax: Syntax, single: bool) -> AttributeDescription {
        AttributeDescription {
            name: name.into(),
            syntax,
            single,
            lower: None,
            upper: Some(64),
            system: name == "objectSid",
            constructed: false,
            link: None,
            guid: Vec::new(),
        }
    }

    fn schema() -> Schema {
        let mut s = Schema::default();
        for d in [
            description("sAMAccountName", Syntax::Unicode, true),
            description("userPrincipalName", Syntax::Unicode, true),
            description("givenName", Syntax::Unicode, true),
            description("sn", Syntax::Unicode, true),
            description("displayName", Syntax::Unicode, true),
            description("description", Syntax::Unicode, false),
            description("otherTelephone", Syntax::Unicode, false),
            description("employeeNumber", Syntax::Unicode, true),
            description("objectSid", Syntax::Sid, true),
            description("countryCode", Syntax::Integer, true),
        ] {
            s.attributes.insert(d.name.to_lowercase(), d);
        }
        s
    }

    fn reader(d: &AttributeDescription, text: &str) -> Result<Vec<u8>, String> {
        if d.syntax == Syntax::Integer && text.parse::<i32>().is_err() {
            return Err("integer expected".into());
        }
        Ok(text.as_bytes().to_vec())
    }

    #[test]
    fn columns_by_every_name() {
        let header: Vec<String> = [
            "Name",
            "Path",
            "prénom",
            "SamAccountName",
            "AccountPassword",
            "inconnu",
            "",
        ]
        .map(str::to_owned)
        .to_vec();
        let labels: HashMap<String, String> =
            [("prénom".to_owned(), "givenName".to_owned())].into();
        assert_eq!(
            targets(&header, &schema(), &labels),
            vec![
                Target::Name,
                Target::Path,
                Target::Attribute("givenName".into()),
                Target::Attribute("sAMAccountName".into()),
                Target::Password,
                Target::Unknown("inconnu".into()),
                Target::Ignored,
            ]
        );
    }

    #[test]
    fn a_line_read() {
        let columns = vec![
            Target::Attribute("givenName".into()),
            Target::Attribute("sn".into()),
            Target::Attribute("sAMAccountName".into()),
            Target::Attribute("otherTelephone".into()),
            Target::Attribute("countryCode".into()),
            Target::Attribute("objectSid".into()),
            Target::Unknown("x".into()),
            Target::Enabled,
        ];
        let fields: Vec<String> = [
            "Élise",
            "Martin",
            "e.martin",
            "01 | 02",
            "pas un entier",
            "S-1",
            "v",
            "peut-être",
        ]
        .map(str::to_owned)
        .to_vec();
        let options = Options {
            parent: "OU=X,DC=x".into(),
            ..Options::default()
        };
        let mut problems = Vec::new();
        let asked = read_line(
            &fields,
            &columns,
            &schema(),
            &options,
            &reader,
            &mut problems,
        );
        assert_eq!(asked.name, "Élise Martin");
        assert_eq!(asked.identifier, "e.martin");
        assert_eq!(
            asked
                .attributes
                .iter()
                .find(|(a, _)| a == "otherTelephone")
                .map(|(_, v)| v.len()),
            Some(2)
        );
        assert!(problems.contains(&Problem::NotWritable("objectSid".into())));
        assert!(problems.contains(&Problem::UnknownColumn("x".into())));
        assert!(
            problems.iter().any(
                |p| matches!(p, Problem::Value { attribute, .. } if attribute == "countryCode")
            )
        );
        assert!(
            problems
                .iter()
                .any(|p| matches!(p, Problem::InvalidFlag { .. }))
        );
        assert_eq!(line_dn(&asked).unwrap(), "CN=Élise Martin,OU=X,DC=x");
    }

    #[test]
    fn creation_with_the_defaults_and_the_columns() {
        let asked = Asked {
            kind: Some(Kind::User),
            name: "Élise Martin".into(),
            parent: "OU=X,DC=x".into(),
            identifier: "e.martin".into(),
            enable: true,
            change: true,
            attributes: vec![
                ("sAMAccountName".into(), vec![b"e.martin".to_vec()]),
                ("homeDrive".into(), vec![b"H:".to_vec()]),
                (
                    "homeDirectory".into(),
                    vec![b"\\\\fs1\\Home\\%username%".to_vec()],
                ),
                ("employeeNumber".into(), vec![b"42".to_vec()]),
            ],
            ..Asked::default()
        };
        let rule = PasswordRule {
            samba: true,
            complex: true,
            min_length: 7,
        };
        let op = build(Kind::User, &asked, Some("Bonjour-2026"), &rule).unwrap();
        let Operation::Add { dn, attributes } = op else {
            panic!("a creation expected");
        };
        assert_eq!(dn, "CN=Élise Martin,OU=X,DC=x");
        assert_eq!(
            text_of(&attributes, "homeDirectory"),
            "\\\\fs1\\Home\\e.martin"
        );
        assert_eq!(text_of(&attributes, "employeeNumber"), "42");
        assert_eq!(text_of(&attributes, "userAccountControl"), "512");
        assert_eq!(text_of(&attributes, "pwdLastSet"), "0");
        assert!(attributes.iter().any(|(a, _)| a == "unicodePwd"));
    }

    #[test]
    fn passwords() {
        let rule = PasswordRule {
            samba: false,
            complex: true,
            min_length: 8,
        };
        assert_eq!(
            password_problem("court1A", "x", &rule),
            Some(Problem::PasswordTooShort { minimum: 8 })
        );
        assert_eq!(
            password_problem("toutminuscule", "x", &rule),
            Some(Problem::PasswordNotComplex)
        );
        assert_eq!(
            password_problem("Ae.martin-2026", "e.martin", &rule),
            Some(Problem::PasswordNotComplex)
        );
        assert_eq!(password_problem("Bonjour-2026", "e.martin", &rule), None);
        for _ in 0..20 {
            let p = generate_password(8).unwrap();
            assert_eq!(p.chars().count(), GENERATED_LENGTH);
            assert_eq!(kinds(&p), 4);
            assert!(password_problem(&p, "e.martin", &rule).is_none());
        }
    }

    #[test]
    fn group_flags() {
        assert_eq!(scope("Domain Local"), Some(GroupScope::DomainLocal));
        assert_eq!(scope("universelle"), Some(GroupScope::Universal));
        assert_eq!(category("Distribution"), Some(false));
        assert_eq!(flag("$true"), Some(true));
        assert_eq!(Kind::parse("Ordinateur"), Some(Kind::Computer));
    }
}

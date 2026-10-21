// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Security of an object (J4.1, J4.2, `annuaire.core.securite`): reading of the descriptor,
//! names of the GUIDs and of the SIDs, and the templates of the delegation wizard that the
//! « Security » tab recognises (`annuaire.core.delegation`, reading part).
//!
//! `read_nomenclature` gathers, once per session and per domain, what names the GUIDs of a
//! descriptor: classes and attributes of the schema (read by the source and shared with the
//! attribute editor), rights of `CN=Extended-Rights`, default descriptors of the classes and
//! SID of the domain. Everything is read on the DC, not in the local copy (ADR 0011).
//!
//! `read_security` reads the descriptor of an object with the SD flags control: owner, group
//! and DACL, plus the SACL if the account may (otherwise a second reading without it), the
//! DACLs of its ancestors up to the root of its partition (origin of the inherited ACEs) and
//! the names of the SIDs it quotes. The rest is pure.

use std::collections::{HashMap, HashSet};

use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::{Guid, Sid, condition, sddl};

use crate::connection::{Connection, Failure, Link};
use crate::dn;
use crate::error::{LdapError, code};
use crate::schema::Schema;
use crate::search::{self, SD_DACL, SD_SACL, SD_WITHOUT_SACL, Value};
use crate::session::{Entry, Scope, SearchRequest};

pub const SD: &str = "nTSecurityDescriptor";
pub const SD_WITH_SACL: i64 = SD_WITHOUT_SACL | SD_SACL;

fn guid(text: &str) -> Guid {
    text.parse().unwrap_or(Guid::from_bytes([0; 16]))
}

// GUIDs in common use (base schema of AD, the same in every forest).
pub fn class_user() -> Guid {
    guid("bf967aba-0de6-11d0-a285-00aa003049e2")
}
pub fn class_group() -> Guid {
    guid("bf967a9c-0de6-11d0-a285-00aa003049e2")
}
pub fn class_computer() -> Guid {
    guid("bf967a86-0de6-11d0-a285-00aa003049e2")
}
pub fn class_ou() -> Guid {
    guid("bf967aa5-0de6-11d0-a285-00aa003049e2")
}
pub fn class_inetorgperson() -> Guid {
    guid("4828cc14-1437-45bc-9b07-ad6f015e5f28")
}
pub fn attribute_pwdlastset() -> Guid {
    guid("bf967a0a-0de6-11d0-a285-00aa003049e2")
}
pub fn attribute_member() -> Guid {
    guid("bf9679c0-0de6-11d0-a285-00aa003049e2")
}
pub fn right_reset_password() -> Guid {
    guid("00299570-246d-11d0-a768-00aa006e0529")
}
pub fn write_dns_name() -> Guid {
    guid("72e39547-7b18-11d1-adef-00c04fd8d5cd")
}
pub fn write_spn() -> Guid {
    guid("f3a64788-5306-11d1-a9c5-0000f80367c1")
}
pub fn set_account_restrictions() -> Guid {
    guid("4c164200-20c0-11d0-a768-00aa006e0529")
}

// `validAccesses` of an entry of CN=Extended-Rights (MS-ADTS 5.1.3.2.1).
const VALID_SET: u32 = sd::ADS_RIGHT_DS_READ_PROP | sd::ADS_RIGHT_DS_WRITE_PROP;
const VALID_WRITE: u32 = sd::ADS_RIGHT_DS_SELF;

/// What the GUID of an ACE names (`Genre`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Class,
    Attribute,
    ExtendedRight,
    PropertySet,
    ValidatedWrite,
}

/// A name of a GUID (`NomGuid`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GuidName {
    /// `lDAPDisplayName` (class, attribute) or `displayName` (rights of Extended-Rights).
    pub name: String,
    pub kind: Kind,
    /// `cn` of the entry of Extended-Rights (`User-Force-Change-Password`), empty otherwise.
    pub cn: String,
}

impl GuidName {
    pub fn new(name: &str, kind: Kind, cn: &str) -> Self {
        Self {
            name: name.into(),
            kind,
            cn: cn.into(),
        }
    }
}

/// Which kind of GUID a right names (MS-ADTS 5.1.3.2), by order of preference.
const KINDS_BY_RIGHT: [(u32, Kind); 5] = [
    (sd::ADS_RIGHT_DS_SELF, Kind::ValidatedWrite),
    (sd::ADS_RIGHT_DS_CONTROL_ACCESS, Kind::ExtendedRight),
    (
        sd::ADS_RIGHT_DS_READ_PROP | sd::ADS_RIGHT_DS_WRITE_PROP,
        Kind::PropertySet,
    ),
    (
        sd::ADS_RIGHT_DS_READ_PROP | sd::ADS_RIGHT_DS_WRITE_PROP,
        Kind::Attribute,
    ),
    (
        sd::ADS_RIGHT_DS_CREATE_CHILD | sd::ADS_RIGHT_DS_DELETE_CHILD,
        Kind::Class,
    ),
];

/// Names of the GUIDs and SIDs of a domain, read once (`Nomenclature`, ADR 0011).
#[derive(Debug, Clone, Default)]
pub struct Nomenclature {
    pub domain_sid: Option<Sid>,
    /// A GUID may name two things: the validated write « DNS host name » has the GUID of the
    /// attribute `dNSHostName`. The mask of the ACE decides (`name`).
    pub guids: HashMap<Guid, Vec<GuidName>>,
    /// `lDAPDisplayName` in lower case → `schemaIDGUID`.
    pub classes: HashMap<String, Guid>,
    /// `lDAPDisplayName` of a class in lower case → `defaultSecurityDescriptor` (SDDL).
    pub defaults: HashMap<String, String>,
}

impl Nomenclature {
    /// The name of `guid`; with the mask of the ACE, the one of the kind its rights aim at.
    pub fn name(&self, guid: Option<&Guid>, mask: u32) -> Option<&GuidName> {
        let names = self.guids.get(guid?)?;
        for (rights, kind) in KINDS_BY_RIGHT {
            if mask & rights != 0
                && let Some(n) = names.iter().find(|n| n.kind == kind)
            {
                return Some(n);
            }
        }
        names.first()
    }

    pub fn class_guid(&self, name: &str) -> Option<Guid> {
        self.classes.get(&name.to_lowercase()).copied()
    }

    pub fn class_guids(&self, classes: &[String]) -> HashSet<Guid> {
        classes.iter().filter_map(|c| self.class_guid(c)).collect()
    }
}

/// What the directory says of a SID: the object that carries it (`NomSid`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidName {
    pub sid: Sid,
    pub name: String,
    pub dn: String,
    pub classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ancestor {
    pub dn: String,
    pub classes: Vec<String>,
    /// DACL, plus the SACL when the one of the object could be read; None if unreadable.
    pub descriptor: Option<SecurityDescriptor>,
}

/// The descriptor of an object and what explains it (`LectureSecurite`).
#[derive(Debug, Clone)]
pub struct SecurityReading {
    pub dn: String,
    pub classes: Vec<String>,
    pub raw: Vec<u8>,
    pub descriptor: SecurityDescriptor,
    /// True if the SACL was asked and given (right `SeSecurityPrivilege`).
    pub sacl_read: bool,
    /// From the parent to the root of the partition.
    pub ancestors: Vec<Ancestor>,
    pub names: HashMap<Sid, SidName>,
    pub dc: String,
}

// --- Reading ------------------------------------------------------------------------------

fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

fn texts(entry: &Entry, attribute: &str) -> Vec<String> {
    entry
        .values(attribute)
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect()
}

/// What the nomenclature adds to the schema (`Complements`).
#[derive(Debug, Clone, Default)]
pub struct Complements {
    pub domain_sid: Option<Sid>,
    /// Entries of `CN=Extended-Rights` (`cn`, `displayName`, `rightsGuid`, `validAccesses`).
    pub rights: Vec<Entry>,
    /// `lDAPDisplayName` of a class in lower case → `defaultSecurityDescriptor`.
    pub defaults: HashMap<String, String>,
}

/// Nomenclature from the schema and the complements read (`nomenclature_depuis`, pure).
pub fn nomenclature_from(schema: &Schema, complements: &Complements) -> Nomenclature {
    let mut nomenclature = Nomenclature {
        domain_sid: complements.domain_sid,
        defaults: complements.defaults.clone(),
        ..Nomenclature::default()
    };
    // In the order of the Python dictionaries: classes, attributes, rights.
    let mut classes: Vec<(&String, &Vec<u8>)> = schema.classes.iter().collect();
    classes.sort();
    for (name, raw) in classes {
        let Ok(guid) = Guid::decode(raw) else {
            continue;
        };
        nomenclature
            .guids
            .entry(guid)
            .or_default()
            .push(GuidName::new(name, Kind::Class, ""));
        nomenclature.classes.insert(name.to_lowercase(), guid);
    }
    let mut attributes: Vec<_> = schema.attributes.values().collect();
    attributes.sort_by(|a, b| a.name.cmp(&b.name));
    for description in attributes {
        if let Ok(guid) = Guid::decode(&description.guid) {
            nomenclature
                .guids
                .entry(guid)
                .or_default()
                .push(GuidName::new(&description.name, Kind::Attribute, ""));
        }
    }
    for e in &complements.rights {
        let Ok(guid) = text(e, "rightsGuid").parse::<Guid>() else {
            continue;
        };
        let accesses: u32 = text(e, "validAccesses").parse().unwrap_or(0);
        let kind = if accesses & VALID_SET != 0 {
            Kind::PropertySet
        } else if accesses & VALID_WRITE != 0 {
            Kind::ValidatedWrite
        } else {
            Kind::ExtendedRight
        };
        let display = text(e, "displayName");
        let cn = text(e, "cn");
        let name = if display.is_empty() { &cn } else { &display };
        nomenclature
            .guids
            .entry(guid)
            .or_default()
            .push(GuidName::new(name, kind, &cn));
    }
    nomenclature
}

fn search_wait(
    link: &mut Link,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<Entry>, LdapError> {
    let request = SearchRequest {
        base: base.to_owned(),
        scope,
        filter: filter.to_owned(),
        attributes: attributes.iter().map(|&a| a.to_owned()).collect(),
        controls: Vec::new(),
        size_limit: 0,
    };
    Ok(link
        .session
        .search_wait(request, Some(link.timeout))?
        .into_entries())
}

/// SID of the domain, rights of `CN=Extended-Rights` and default descriptors of the classes
/// (about 330 entries, one operation) (`lire_complements`). Blocking.
pub fn read_complements(connection: &Connection) -> Result<Complements, Failure> {
    connection.run(true, |link| {
        let root = link.state.root_dse.clone();
        let domain = search::read_entry(
            link.session.as_mut(),
            &root.default_naming_context,
            &["objectSid".to_owned()],
            "(objectClass=*)",
            None,
            Some(link.timeout),
        )?;
        let domain_sid = domain
            .as_ref()
            .and_then(|d| d.values("objectSid").first().cloned())
            .and_then(|v| Sid::decode(&v).ok());
        let rights = search_wait(
            link,
            &format!("CN=Extended-Rights,{}", root.configuration_naming_context),
            Scope::OneLevel,
            "(objectClass=controlAccessRight)",
            &["cn", "displayName", "rightsGuid", "validAccesses"],
        )?;
        let classes = search_wait(
            link,
            &root.schema_naming_context,
            Scope::OneLevel,
            "(&(objectClass=classSchema)(defaultSecurityDescriptor=*))",
            &["lDAPDisplayName", "defaultSecurityDescriptor"],
        )?;
        let defaults = classes
            .iter()
            .filter(|e| !text(e, "lDAPDisplayName").is_empty())
            .map(|e| {
                (
                    text(e, "lDAPDisplayName").to_lowercase(),
                    text(e, "defaultSecurityDescriptor"),
                )
            })
            .collect();
        Ok(Complements {
            domain_sid,
            rights,
            defaults,
        })
    })
}

/// DN of the ancestors of `dn`, from the parent to the root of its partition (included)
/// (`_ancetres`).
pub fn ancestors(dn_text: &str, roots: &[String]) -> Vec<String> {
    let Ok(components) = dn::split(dn_text) else {
        return Vec::new();
    };
    let keys: HashSet<String> = roots
        .iter()
        .filter(|r| !r.is_empty())
        .filter_map(|r| dn::split(r).ok().and_then(|c| dn::compose(&c).ok()))
        .map(|r| r.to_lowercase())
        .collect();
    let mut out = Vec::new();
    for i in 1..components.len() {
        let Ok(parent) = dn::compose(components.get(i..).unwrap_or_default()) else {
            break;
        };
        let last = keys.contains(&parent.to_lowercase());
        out.push(parent);
        if last {
            break;
        }
    }
    out
}

const SD_ATTRIBUTES: [&str; 2] = ["objectClass", SD];

fn read_with(link: &mut Link, dn_text: &str, flags: i64) -> Result<Option<Entry>, LdapError> {
    let attributes: Vec<String> = SD_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect();
    search::read_entry(
        link.session.as_mut(),
        dn_text,
        &attributes,
        "(objectClass=*)",
        Some(flags),
        Some(link.timeout),
    )
}

/// The object with its descriptor: SACL included if the account may (`_lire_descripteur`).
fn read_descriptor(link: &mut Link, dn_text: &str) -> Result<(Option<Entry>, bool), LdapError> {
    match read_with(link, dn_text, SD_WITH_SACL) {
        Ok(None) => return Ok((None, false)),
        Ok(Some(entry)) => {
            let with_sacl = entry
                .values(SD)
                .first()
                .and_then(|v| SecurityDescriptor::decode(v).ok())
                .is_some_and(|d| d.control & sd::SE_SACL_PRESENT != 0);
            if with_sacl {
                return Ok((Some(entry), true));
            }
        }
        Err(e) if e.code == code::INSUFFICIENT_ACCESS => {}
        Err(e) => return Err(e),
    }
    // Without the right to read the SACL, Samba and AD give the descriptor without it or
    // nothing at all: owner, group and DACL read again alone.
    Ok((read_with(link, dn_text, SD_WITHOUT_SACL)?, false))
}

/// SIDs of a descriptor: owner, group, those of the ACEs and of their conditions.
fn sids(descriptor: &SecurityDescriptor) -> HashSet<Sid> {
    let mut out: HashSet<Sid> = descriptor
        .owner
        .into_iter()
        .chain(descriptor.group)
        .collect();
    for acl in [&descriptor.dacl, &descriptor.sacl].into_iter().flatten() {
        for ace in &acl.aces {
            out.extend(ace_sids(ace));
        }
    }
    out
}

/// The SID of the ACE, then those its condition quotes (`sids_de_l_ace`).
pub fn ace_sids(ace: &Ace) -> Vec<Sid> {
    let mut out: Vec<Sid> = ace.sid().into_iter().collect();
    if is_conditional(ace.ace_type)
        && ace.ace_type != sd::SYSTEM_RESOURCE_ATTRIBUTE
        && let Ok(node) = condition::read_condition(ace.data())
    {
        cited_sids(&node, &mut out);
    }
    let mut seen = HashSet::new();
    out.retain(|s| seen.insert(*s));
    out
}

fn cited_sids(node: &condition::Node, out: &mut Vec<Sid>) {
    match node {
        condition::Node::Sid(sid) => out.push(*sid),
        condition::Node::Composite(nodes) => nodes.iter().for_each(|n| cited_sids(n, out)),
        condition::Node::Operation { operands, .. } => {
            operands.iter().for_each(|n| cited_sids(n, out));
        }
        _ => {}
    }
}

/// ACEs followed by a condition or a resource attribute (`TYPES_CONDITIONNELS`).
pub fn is_conditional(ace_type: u8) -> bool {
    sddl::CONDITIONAL_TYPES.iter().any(|(t, _)| *t == ace_type)
}

/// Objects of the directory that carry these SIDs, by batches of 50; a SID without an object
/// is absent from the result (`resoudre_sids`).
pub(crate) fn resolve_sids(
    link: &mut Link,
    base: &str,
    sids: &HashSet<Sid>,
) -> Result<HashMap<Sid, SidName>, LdapError> {
    let mut list: Vec<&Sid> = sids.iter().collect();
    list.sort_by_key(|s| s.to_string());
    let mut names = HashMap::new();
    for batch in list.chunks(50) {
        let filters: Vec<String> = batch
            .iter()
            .filter_map(|s| search::eq("objectSid", Value::Bytes(&s.encode())).ok())
            .collect();
        let filter = search::or(&filters).unwrap_or_default();
        for e in search_wait(
            link,
            base,
            Scope::Subtree,
            &filter,
            &["objectSid", "name", "sAMAccountName", "objectClass"],
        )? {
            let Some(sid) = e
                .values("objectSid")
                .first()
                .and_then(|v| Sid::decode(v).ok())
            else {
                continue;
            };
            let name = Some(text(&e, "name"))
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| text(&e, "sAMAccountName"));
            names.insert(
                sid,
                SidName {
                    sid,
                    name,
                    dn: e.dn.clone(),
                    classes: texts(&e, "objectClass"),
                },
            );
        }
    }
    Ok(names)
}

/// Objects of the directory that carry these SIDs (`nommer_sids`): to name the delegates in
/// the preview. Blocking.
pub fn name_sids(
    connection: &Connection,
    sids: HashSet<Sid>,
) -> Result<HashMap<Sid, SidName>, Failure> {
    connection.run(true, move |link| {
        let base = link.state.root_dse.default_naming_context.clone();
        resolve_sids(link, &base, &sids)
    })
}

/// Descriptor of `dn`, DACLs of its ancestors and names of the SIDs quoted (None: object
/// absent) (`lire_securite`). Blocking.
pub fn read_security(
    connection: &Connection,
    dn_text: &str,
) -> Result<Option<SecurityReading>, Failure> {
    let dn_text = dn_text.to_owned();
    connection.run(true, move |link| {
        let (entry, sacl_read) = read_descriptor(link, &dn_text)?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        let Some(raw) = entry.values(SD).first().cloned() else {
            return Err(LdapError::new(
                code::INSUFFICIENT_ACCESS,
                "descripteur de sécurité illisible",
            ));
        };
        let descriptor = SecurityDescriptor::decode(&raw)
            .map_err(|e| LdapError::new(code::DECODING_ERROR, e.to_string()))?;
        let root = link.state.root_dse.clone();
        let roots = [
            root.default_naming_context.clone(),
            root.configuration_naming_context.clone(),
            root.schema_naming_context.clone(),
            format!("DC=DomainDnsZones,{}", root.root_domain_naming_context),
            format!("DC=ForestDnsZones,{}", root.root_domain_naming_context),
        ];
        let flags = SD_DACL | if sacl_read { SD_SACL } else { 0 };
        let mut parents = Vec::new();
        for parent in ancestors(&entry.dn, &roots) {
            let read = match read_with(link, &parent, flags) {
                Ok(read) => read,
                Err(e) if e.code == code::INSUFFICIENT_ACCESS => None,
                Err(e) => return Err(e),
            };
            parents.push(Ancestor {
                classes: read
                    .as_ref()
                    .map(|e| texts(e, "objectClass"))
                    .unwrap_or_default(),
                descriptor: read
                    .as_ref()
                    .and_then(|e| e.values(SD).first().cloned())
                    .and_then(|v| SecurityDescriptor::decode(&v).ok()),
                dn: parent,
            });
        }
        let names = resolve_sids(link, &root.default_naming_context, &sids(&descriptor))?;
        Ok(Some(SecurityReading {
            classes: texts(&entry, "objectClass"),
            dn: entry.dn,
            raw,
            descriptor,
            sacl_read,
            ancestors: parents,
            names,
            dc: link.state.dc.clone(),
        }))
    })
}

// --- Analysis (pure) ----------------------------------------------------------------------

/// The ACE passes to the child objects (`transmise`: in the directory, CI is enough).
pub fn transmitted(ace: &Ace) -> bool {
    ace.flags & (sd::CONTAINER_INHERIT_ACE | sd::OBJECT_INHERIT_ACE) != 0
}

type Signature = (u8, bool, u32, Option<Sid>, Option<Guid>, Option<Guid>);

fn signature(ace: &Ace) -> Signature {
    (
        ace.ace_type,
        ace.is_deny(),
        ace.mask(),
        ace.sid(),
        ace.object_type(),
        ace.inherited_object_type(),
    )
}

/// The nearest ancestor that carries the inherited ACE `ace` as explicit (same kind, mask,
/// SID and GUIDs, transmissible); None if it is not found (`origine`).
pub fn origin<'a>(ace: &Ace, ancestors: &'a [Ancestor]) -> Option<&'a Ancestor> {
    let wanted = signature(ace);
    for ancestor in ancestors {
        let Some(descriptor) = &ancestor.descriptor else {
            continue;
        };
        let candidates = [&descriptor.dacl, &descriptor.sacl]
            .into_iter()
            .flatten()
            .flat_map(|acl| acl.aces.iter());
        for candidate in candidates {
            if transmitted(candidate) && signature(candidate) == wanted {
                if !candidate.is_inherited() {
                    return Some(ancestor);
                }
                break; // inherited there too: up again
            }
        }
    }
    None
}

/// The ACE with its generic rights translated, as the DC writes it (`_sans_generiques`).
pub fn without_generic(ace: &Ace) -> Ace {
    let mask = sd::translate_generic(ace.mask());
    let mut body = mask.to_le_bytes().to_vec();
    body.extend_from_slice(ace.body.get(4..).unwrap_or_default());
    Ace {
        ace_type: ace.ace_type,
        flags: ace.flags,
        body,
    }
}

/// ACEs of the default descriptor of the most precise class of the object
/// (`aces_par_defaut`).
pub fn default_aces(nomenclature: &Nomenclature, classes: &[String]) -> HashSet<Ace> {
    for class in classes.iter().rev() {
        let Some(text) = nomenclature.defaults.get(&class.to_lowercase()) else {
            continue;
        };
        let Ok(descriptor) = sddl::sd_from_sddl(text, nomenclature.domain_sid.as_ref(), false)
        else {
            return HashSet::new();
        };
        return descriptor
            .dacl
            .iter()
            .flat_map(|acl| acl.aces.iter())
            .map(without_generic)
            .collect();
    }
    HashSet::new()
}

/// The explicit ACE comes from the default descriptor of the class (not a delegation)
/// (`par_defaut`).
pub fn is_default(ace: &Ace, defaults: &HashSet<Ace>) -> bool {
    !ace.is_inherited() && (defaults.contains(ace) || defaults.contains(&without_generic(ace)))
}

// --- Templates of the delegation wizard (`delegation`, reading part) ------------------------

/// Classes the wizard offers to delegate on (`CLASSES_CIBLES`).
pub const TARGET_CLASSES: [&str; 3] = ["organizationalUnit", "container", "domainDNS"];

const CI: u8 = sd::CONTAINER_INHERIT_ACE;
const CIIO: u8 = sd::CONTAINER_INHERIT_ACE | sd::INHERIT_ONLY_ACE;
const CC_DC: u32 = sd::ADS_RIGHT_DS_CREATE_CHILD | sd::ADS_RIGHT_DS_DELETE_CHILD;
const RP_WP: u32 = sd::ADS_RIGHT_DS_READ_PROP | sd::ADS_RIGHT_DS_WRITE_PROP;

/// An ACE of a template, without the SID of the delegate (`Gabarit`).
#[derive(Debug, Clone, Copy)]
pub struct Pattern {
    pub flags: u8,
    pub mask: u32,
    pub object_type: Option<Guid>,
    pub inherited_type: Option<Guid>,
}

impl Pattern {
    pub fn ace(&self, sid: &Sid) -> Option<Ace> {
        Ace::object(
            sd::ACCESS_ALLOWED_OBJECT,
            self.mask,
            sid,
            self.flags,
            self.object_type,
            self.inherited_type,
        )
        .ok()
    }
}

/// Which template of the wizard (`Modele.ident`): the interface names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Template {
    ResetPasswords,
    GroupMembers,
    JoinComputers,
    ReadUsers,
    ManageUsers,
}

impl Template {
    pub const ALL: [Self; 5] = [
        Self::ResetPasswords,
        Self::GroupMembers,
        Self::JoinComputers,
        Self::ReadUsers,
        Self::ManageUsers,
    ];

    /// Where the template comes from (`delegwiz.inf`).
    pub fn reference(self) -> &'static str {
        match self {
            Self::ResetPasswords => "delegwiz.inf, template2",
            Self::GroupMembers => "delegwiz.inf, template5",
            Self::JoinComputers => {
                "delegwiz.inf, templates 32, 33 et 37, plus écritures validées et restrictions de compte"
            }
            Self::ReadUsers => "delegwiz.inf, template3",
            Self::ManageUsers => "delegwiz.inf, template1",
        }
    }

    pub fn patterns(self) -> Vec<Pattern> {
        let p = |flags, mask, object_type, inherited_type| Pattern {
            flags,
            mask,
            object_type,
            inherited_type,
        };
        let user = Some(class_user());
        let computer = Some(class_computer());
        match self {
            Self::ResetPasswords => vec![
                p(
                    CIIO,
                    sd::ADS_RIGHT_DS_CONTROL_ACCESS,
                    Some(right_reset_password()),
                    user,
                ),
                p(CIIO, RP_WP, Some(attribute_pwdlastset()), user),
            ],
            Self::GroupMembers => vec![p(
                CIIO,
                RP_WP,
                Some(attribute_member()),
                Some(class_group()),
            )],
            Self::JoinComputers => vec![
                p(CI, CC_DC, computer, None),
                p(
                    CIIO,
                    sd::ADS_RIGHT_DS_CONTROL_ACCESS,
                    Some(right_reset_password()),
                    computer,
                ),
                p(
                    CIIO,
                    sd::ADS_RIGHT_DS_SELF,
                    Some(write_dns_name()),
                    computer,
                ),
                p(CIIO, sd::ADS_RIGHT_DS_SELF, Some(write_spn()), computer),
                p(CIIO, RP_WP, Some(set_account_restrictions()), computer),
            ],
            Self::ReadUsers => vec![p(CIIO, sd::ADS_RIGHT_DS_READ_PROP, None, user)],
            Self::ManageUsers => vec![
                p(CI, CC_DC, user, None),
                p(CIIO, sd::DS_FULL_CONTROL, None, user),
            ],
        }
    }

    pub fn aces(self, sid: &Sid) -> Vec<Ace> {
        self.patterns().iter().filter_map(|p| p.ace(sid)).collect()
    }
}

/// A template found entire, as explicit ACEs, in a DACL (`DelegationTrouvee`).
#[derive(Debug, Clone)]
pub struct FoundDelegation {
    pub sid: Sid,
    pub template: Template,
    pub aces: Vec<Ace>,
}

/// Templates present entire, as explicit ACEs, in the DACL, by SID (`delegations`).
pub fn delegations(descriptor: &SecurityDescriptor) -> Vec<FoundDelegation> {
    let Some(dacl) = &descriptor.dacl else {
        return Vec::new();
    };
    let explicit: HashSet<&Ace> = dacl.aces.iter().filter(|a| !a.is_inherited()).collect();
    let mut sids: Vec<Sid> = Vec::new();
    for sid in dacl
        .aces
        .iter()
        .filter(|a| !a.is_inherited())
        .filter_map(Ace::sid)
    {
        if !sids.contains(&sid) {
            sids.push(sid);
        }
    }
    let mut found = Vec::new();
    for sid in sids {
        for template in Template::ALL {
            let aces = template.aces(&sid);
            if !aces.is_empty() && aces.iter().all(|a| explicit.contains(a)) {
                found.push(FoundDelegation {
                    sid,
                    template,
                    aces,
                });
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ancestors_up_to_the_partition() {
        let roots = ["DC=lab,DC=test".to_owned()];
        assert_eq!(
            ancestors("CN=a,OU=B,OU=C,DC=lab,DC=test", &roots),
            [
                "OU=B,OU=C,DC=lab,DC=test",
                "OU=C,DC=lab,DC=test",
                "DC=lab,DC=test"
            ]
        );
    }

    #[test]
    fn delegation_recognised() {
        let sid: Sid = "S-1-5-21-1-2-3-1105".parse().unwrap();
        let mut aces = Template::ResetPasswords.aces(&sid);
        aces.push(Ace::simple(sd::ACCESS_ALLOWED, sd::READ_CONTROL, &sid, 0).unwrap());
        let descriptor = SecurityDescriptor {
            revision: 1,
            control: sd::SE_DACL_PRESENT | sd::SE_SELF_RELATIVE,
            owner: None,
            group: None,
            sacl: None,
            dacl: Some(sd::Acl {
                revision: sd::ACL_REVISION_DS,
                aces,
            }),
        };
        let found = delegations(&descriptor);
        assert_eq!(found.len(), 1);
        assert_eq!(
            found.first().map(|f| f.template),
            Some(Template::ResetPasswords)
        );
    }

    #[test]
    fn generic_rights_translated() {
        let sid: Sid = "S-1-1-0".parse().unwrap();
        let ace = Ace::simple(sd::ACCESS_ALLOWED, sd::GENERIC_ALL, &sid, 0).unwrap();
        assert_eq!(without_generic(&ace).mask(), sd::DS_FULL_CONTROL);
    }
}

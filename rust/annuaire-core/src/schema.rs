// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Schema of the directory: description of the attributes and of the classes (J4.4,
//! `annuaire.core.schema`), and the values of an attribute according to its syntax
//! (`annuaire.core.syntaxes`, the reading part; the reading of an input, whose messages the
//! interface writes, is `inputs` of the application).
//!
//! The attribute editor needs, for each attribute, its syntax (`attributeSyntax`,
//! `oMSyntax`, and `oMObjectClass` for the « object » syntaxes 127), its number of values
//! (`isSingleValued`), its bounds (`rangeLower`, `rangeUpper`) and what makes it read-only:
//! `systemOnly`, `systemFlags` & `FLAG_ATTR_IS_CONSTRUCTED`, an odd `linkID` (back link
//! kept by the DC, as `memberOf`). The security descriptor translates the GUIDs of
//! attributes and classes (`schemaIDGUID`) into names.
//!
//! The schema is read once per domain (a paged search under `schemaNamingContext`: 1,768
//! entries on the lab) and kept in memory by the source; it does not go into the local copy.
//! Pure, apart from `read_schema`.

use std::collections::HashMap;

use annuaire_codecs::integer::{self, Width};

use crate::connection::{Connection, Failure};
use crate::search::{Search, SearchError};
use crate::session::{Entry, Scope};
use crate::source::{PAGE_SIZE, search_blocking};

/// Attributes read from the schema.
pub const SCHEMA_ATTRIBUTES: [&str; 20] = [
    "objectClass",
    "lDAPDisplayName",
    "attributeSyntax",
    "oMSyntax",
    "oMObjectClass",
    "isSingleValued",
    "rangeLower",
    "rangeUpper",
    "systemOnly",
    "systemFlags",
    "linkID",
    "schemaIDGUID",
    // classSchema: inheritance, auxiliary classes and allowed attributes.
    "subClassOf",
    "objectClassCategory",
    "auxiliaryClass",
    "systemAuxiliaryClass",
    "mayContain",
    "systemMayContain",
    "mustContain",
    "systemMustContain",
];

pub const SCHEMA_FILTER: &str = "(|(objectClass=attributeSchema)(objectClass=classSchema))";

/// `systemFlags`: attribute computed by the DC at reading, never stored (MS-ADTS 2.2.10).
pub const FLAG_ATTR_IS_CONSTRUCTED: i64 = 0x4;

// `oMObjectClass` (BER) of the « object » syntaxes (oMSyntax 127), MS-ADTS 3.1.1.2.2.2.
const OM_DN_BINARY: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x01, 0x01, 0x0b];
const OM_DN_STRING: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x01, 0x01, 0x0c];
const OM_OR_NAME: &[u8] = &[0x56, 0x06, 0x01, 0x02, 0x05, 0x0b, 0x1d];
const OM_REPLICA_LINK: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x14, 0x01, 0x01, 0x01, 0x06];
const OM_ACCESS_POINT: &[u8] = &[0x2b, 0x0c, 0x02, 0x87, 0x73, 0x1c, 0x00, 0x85, 0x3e];

/// Syntax of an attribute, as the editor decodes it (`Syntaxe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Syntax {
    Dn,
    Oid,
    CaseString,
    Teletex,
    Printable,
    Ia5,
    Numeric,
    DnBinary,
    OrName,
    Boolean,
    Integer,
    Enumeration,
    Octets,
    ReplicaLink,
    UtcTime,
    GeneralizedTime,
    Unicode,
    PresentationAddress,
    DnString,
    AccessPoint,
    Descriptor,
    LargeInteger,
    Sid,
    Unknown,
}

/// Syntax from the triple of the schema (MS-ADTS 3.1.1.2.2.2); `Unknown` otherwise
/// (`syntaxe_de`).
pub fn syntax_of(attribute_syntax: &str, om_syntax: i64, om_object_class: &[u8]) -> Syntax {
    if om_syntax == 127 {
        let object = match (attribute_syntax, om_object_class) {
            ("2.5.5.7", OM_DN_BINARY) => Some(Syntax::DnBinary),
            ("2.5.5.7", OM_OR_NAME) => Some(Syntax::OrName),
            ("2.5.5.10", OM_REPLICA_LINK) => Some(Syntax::ReplicaLink),
            ("2.5.5.14", OM_DN_STRING) => Some(Syntax::DnString),
            ("2.5.5.14", OM_ACCESS_POINT) => Some(Syntax::AccessPoint),
            // Object class absent or unexpected: the most common form of the syntax.
            ("2.5.5.7", _) => Some(Syntax::DnBinary),
            ("2.5.5.10", _) => Some(Syntax::ReplicaLink),
            ("2.5.5.14", _) => Some(Syntax::DnString),
            _ => None,
        };
        if let Some(syntax) = object {
            return syntax;
        }
    }
    match (attribute_syntax, om_syntax) {
        ("2.5.5.1", 127) => Syntax::Dn,
        ("2.5.5.2", 6) => Syntax::Oid,
        ("2.5.5.3", 27) => Syntax::CaseString,
        ("2.5.5.4", 20) => Syntax::Teletex,
        ("2.5.5.5", 19) => Syntax::Printable,
        ("2.5.5.5", 22) => Syntax::Ia5,
        ("2.5.5.6", 18) => Syntax::Numeric,
        ("2.5.5.8", 1) => Syntax::Boolean,
        ("2.5.5.9", 2) => Syntax::Integer,
        ("2.5.5.9", 10) => Syntax::Enumeration,
        ("2.5.5.10", 4) => Syntax::Octets,
        ("2.5.5.11", 23) => Syntax::UtcTime,
        ("2.5.5.11", 24) => Syntax::GeneralizedTime,
        ("2.5.5.12", 64) => Syntax::Unicode,
        ("2.5.5.13", 127) => Syntax::PresentationAddress,
        ("2.5.5.15", 66) => Syntax::Descriptor,
        ("2.5.5.16", 65) => Syntax::LargeInteger,
        ("2.5.5.17", 4) => Syntax::Sid,
        _ => Syntax::Unknown,
    }
}

/// An `attributeSchema`: what the editor must know of an attribute (`DescriptionAttribut`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeDescription {
    /// `lDAPDisplayName`, in the case of the schema.
    pub name: String,
    pub syntax: Syntax,
    /// `isSingleValued`.
    pub single: bool,
    pub lower: Option<i64>,
    pub upper: Option<i64>,
    /// `systemOnly`: only the DC writes it.
    pub system: bool,
    /// Computed by the DC at reading (`FLAG_ATTR_IS_CONSTRUCTED`).
    pub constructed: bool,
    /// `linkID`: even for a forward link (`member`), odd for its back link (`memberOf`).
    pub link: Option<i64>,
    /// `schemaIDGUID` (16 bytes), for the object ACEs.
    pub guid: Vec<u8>,
}

impl AttributeDescription {
    pub fn back_link(&self) -> bool {
        self.link.is_some_and(|l| l % 2 != 0)
    }
}

/// `objectClassCategory` of a class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    Class88,
    Structural,
    Abstract,
    Auxiliary,
}

/// A `classSchema`: inheritance, linked auxiliary classes, allowed attributes
/// (`DescriptionClasse`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDescription {
    pub name: String,
    /// `subClassOf` (`top` for `top` itself).
    pub parent: String,
    pub category: Category,
    /// `auxiliaryClass` and `systemAuxiliaryClass`.
    pub auxiliaries: Vec<String>,
    /// `mayContain` and `systemMayContain`.
    pub optional: Vec<String>,
    /// `mustContain` and `systemMustContain`.
    pub mandatory: Vec<String>,
}

/// Attributes and classes of the schema, by name (without case) and by GUID.
#[derive(Debug, Clone, Default)]
pub struct Schema {
    /// Key: name in lower case.
    pub attributes: HashMap<String, AttributeDescription>,
    /// Name of a class (case of the schema) → `schemaIDGUID`.
    pub classes: HashMap<String, Vec<u8>>,
    names_by_guid: HashMap<Vec<u8>, String>,
    /// Key: name of the class in lower case.
    pub class_descriptions: HashMap<String, ClassDescription>,
}

impl Schema {
    pub fn class(&self, name: &str) -> Option<&ClassDescription> {
        self.class_descriptions.get(&name.to_lowercase())
    }

    /// The class and its parents (`subClassOf`) up to `top`, from the class to `top`.
    pub fn ancestry(&self, name: &str) -> Vec<&ClassDescription> {
        let mut chain: Vec<&ClassDescription> = Vec::new();
        let mut current = self.class(name);
        while let Some(class) = current {
            if chain.iter().any(|c| c.name == class.name) {
                break;
            }
            chain.push(class);
            current = (!class.parent.is_empty())
                .then(|| self.class(&class.parent))
                .flatten();
        }
        chain
    }

    /// Description of an attribute; `name` may carry an option (`member;range=0-1499`).
    pub fn attribute(&self, name: &str) -> Option<&AttributeDescription> {
        let base = name.split(';').next().unwrap_or(name);
        self.attributes.get(&base.to_lowercase())
    }

    /// Name of the attribute or of the class whose `schemaIDGUID` this is.
    pub fn name_of_guid(&self, guid: &[u8]) -> Option<&str> {
        self.names_by_guid.get(guid).map(String::as_str)
    }
}

fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

fn number(entry: &Entry, attribute: &str) -> Option<i64> {
    integer::decode(entry.values(attribute).first()?, Width::Bits64).ok()
}

fn true_(entry: &Entry, attribute: &str) -> bool {
    text(entry, attribute).eq_ignore_ascii_case("TRUE")
}

fn texts(entry: &Entry, attributes: &[&str]) -> Vec<String> {
    attributes
        .iter()
        .flat_map(|a| entry.values(a))
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect()
}

/// An `attributeSchema` read; None without `lDAPDisplayName` (`description_depuis_entree`).
pub fn description_from_entry(entry: &Entry) -> Option<AttributeDescription> {
    let name = text(entry, "lDAPDisplayName");
    if name.is_empty() {
        return None;
    }
    Some(AttributeDescription {
        syntax: syntax_of(
            &text(entry, "attributeSyntax"),
            number(entry, "oMSyntax").unwrap_or(0),
            entry
                .values("oMObjectClass")
                .first()
                .map_or(&[][..], Vec::as_slice),
        ),
        single: true_(entry, "isSingleValued"),
        lower: number(entry, "rangeLower"),
        upper: number(entry, "rangeUpper"),
        system: true_(entry, "systemOnly"),
        constructed: number(entry, "systemFlags").unwrap_or(0) & FLAG_ATTR_IS_CONSTRUCTED != 0,
        link: number(entry, "linkID"),
        guid: entry
            .values("schemaIDGUID")
            .first()
            .cloned()
            .unwrap_or_default(),
        name,
    })
}

fn class_from_entry(entry: &Entry, name: &str) -> ClassDescription {
    let category = match number(entry, "objectClassCategory").unwrap_or(0) {
        0 => Category::Class88,
        2 => Category::Abstract,
        3 => Category::Auxiliary,
        _ => Category::Structural,
    };
    ClassDescription {
        name: name.to_owned(),
        parent: text(entry, "subClassOf"),
        category,
        auxiliaries: texts(entry, &["auxiliaryClass", "systemAuxiliaryClass"]),
        optional: texts(entry, &["mayContain", "systemMayContain"]),
        mandatory: texts(entry, &["mustContain", "systemMustContain"]),
    }
}

/// Schema from the `attributeSchema` and `classSchema` read (the other entries are ignored)
/// (`schema_depuis_entrees`).
pub fn schema_from_entries<'a>(entries: impl IntoIterator<Item = &'a Entry>) -> Schema {
    let mut schema = Schema::default();
    for entry in entries {
        let kinds: Vec<String> = entry
            .values("objectClass")
            .iter()
            .map(|v| String::from_utf8_lossy(v).to_lowercase())
            .collect();
        if kinds.iter().any(|k| k == "attributeschema") {
            let Some(description) = description_from_entry(entry) else {
                continue;
            };
            if !description.guid.is_empty() {
                schema
                    .names_by_guid
                    .insert(description.guid.clone(), description.name.clone());
            }
            schema
                .attributes
                .insert(description.name.to_lowercase(), description);
        } else if kinds.iter().any(|k| k == "classschema") {
            let name = text(entry, "lDAPDisplayName");
            if name.is_empty() {
                continue;
            }
            if let Some(guid) = entry.values("schemaIDGUID").first() {
                schema.classes.insert(name.clone(), guid.clone());
                schema.names_by_guid.insert(guid.clone(), name.clone());
            }
            schema
                .class_descriptions
                .insert(name.to_lowercase(), class_from_entry(entry, &name));
        }
    }
    schema
}

/// Why the schema could not be read.
#[derive(Debug, Clone)]
pub enum SchemaError {
    Failure(Failure),
    Search(SearchError),
}

/// Reads the whole schema on the DC of the connection (paged search). Blocking.
pub fn read_schema(connection: &Connection) -> Result<Schema, SchemaError> {
    let base = connection
        .run(true, |link| {
            Ok(link.state.root_dse.schema_naming_context.clone())
        })
        .map_err(SchemaError::Failure)?;
    let search = Search {
        base,
        scope: Scope::OneLevel,
        filter: SCHEMA_FILTER.into(),
        attributes: SCHEMA_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect(),
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls: Vec::new(),
    };
    let mut entries = Vec::new();
    search_blocking(connection, search, &mut |page| {
        entries.extend(page);
        true
    })
    .map_err(SchemaError::Search)?;
    Ok(schema_from_entries(&entries))
}

// --- Values according to their syntax (`syntaxes`) ----------------------------------------

/// Large integers that are FILETIME dates (hundreds of ns since 1601, UTC): a list, as in
/// the Windows console (`ATTRIBUTS_DATE`).
pub const DATE_ATTRIBUTES: [&str; 13] = [
    "accountexpires",
    "pwdlastset",
    "lastlogon",
    "lastlogontimestamp",
    "lastlogoff",
    "badpasswordtime",
    "lockouttime",
    "msds-lastsuccessfulinteractivelogontime",
    "msds-lastfailedinteractivelogontime",
    "msds-userpasswordexpirytimecomputed",
    "creationtime",
    "msds-cached-membership-time-stamp",
    "dscorepropagationdata",
];

/// Large integers that are negative durations (hundreds of ns) (`ATTRIBUTS_DUREE`).
pub const DURATION_ATTRIBUTES: [&str; 9] = [
    "maxpwdage",
    "minpwdage",
    "lockoutduration",
    "lockoutobservationwindow",
    "forcelogoff",
    "msds-maximumpasswordage",
    "msds-minimumpasswordage",
    "msds-lockoutduration",
    "msds-lockoutobservationwindow",
];

/// Syntaxes the editor can read back from an input (`EDITABLES`).
pub const EDITABLE_SYNTAXES: [Syntax; 18] = [
    Syntax::Dn,
    Syntax::Oid,
    Syntax::CaseString,
    Syntax::Teletex,
    Syntax::Printable,
    Syntax::Ia5,
    Syntax::Numeric,
    Syntax::DnBinary,
    Syntax::Boolean,
    Syntax::Integer,
    Syntax::Enumeration,
    Syntax::Octets,
    Syntax::UtcTime,
    Syntax::GeneralizedTime,
    Syntax::Unicode,
    Syntax::DnString,
    Syntax::LargeInteger,
    Syntax::Sid,
];

/// `pwdLastSet`: the DC only takes 0 (change required) and -1 (now).
pub const PWD_LAST_SET: &str = "pwdlastset";

/// Width of an integer of this syntax: 32 bits for `Integer` and `Enumeration`, 64 for
/// `Large Integer` (`bits`).
pub fn width(description: &AttributeDescription) -> Width {
    if description.syntax == Syntax::LargeInteger {
        Width::Bits64
    } else {
        Width::Bits32
    }
}

pub fn is_date(description: &AttributeDescription) -> bool {
    description.syntax == Syntax::LargeInteger
        && DATE_ATTRIBUTES.contains(&description.name.to_lowercase().as_str())
}

/// Octets named as a GUID (`objectGUID`, `schemaIDGUID`, `msDS-…Guid`) (`est_guid`).
pub fn is_guid(description: &AttributeDescription) -> bool {
    description.syntax == Syntax::Octets && description.name.to_lowercase().ends_with("guid")
}

/// Form to edit of a value, that the reading of an input takes back as is: octets in
/// hexadecimal, SID and GUID as text, the rest as stored (`texte_saisie`).
pub fn edit_text(description: &AttributeDescription, value: &[u8]) -> String {
    if description.syntax == Syntax::Sid
        && let Ok(sid) = annuaire_codecs::Sid::decode(value)
    {
        return sid.to_string();
    }
    if is_guid(description)
        && value.len() == 16
        && let Ok(guid) = annuaire_codecs::Guid::decode(value)
    {
        return guid.to_string();
    }
    if matches!(
        description.syntax,
        Syntax::Octets | Syntax::Sid | Syntax::ReplicaLink | Syntax::Descriptor
    ) {
        return hex(value);
    }
    String::from_utf8_lossy(value).into_owned()
}

/// Octets as `01 a2 ff` (`bytes.hex(" ")`).
pub fn hex(value: &[u8]) -> String {
    value
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(dn: &str, attributes: &[(&str, &[&[u8]])]) -> Entry {
        Entry {
            dn: dn.into(),
            attributes: attributes
                .iter()
                .map(|(n, vs)| ((*n).to_owned(), vs.iter().map(|v| v.to_vec()).collect()))
                .collect(),
        }
    }

    #[test]
    fn syntaxes() {
        assert_eq!(syntax_of("2.5.5.12", 64, b""), Syntax::Unicode);
        assert_eq!(syntax_of("2.5.5.7", 127, OM_OR_NAME), Syntax::OrName);
        assert_eq!(syntax_of("2.5.5.7", 127, b"?"), Syntax::DnBinary);
        assert_eq!(syntax_of("2.5.5.1", 127, b""), Syntax::Dn);
        assert_eq!(syntax_of("9.9", 1, b""), Syntax::Unknown);
    }

    #[test]
    fn schema_read_from_entries() {
        let member_of = entry(
            "CN=Is-Member-Of-DL,CN=Schema",
            &[
                ("objectClass", &[b"top", b"attributeSchema"]),
                ("lDAPDisplayName", &[b"memberOf"]),
                ("attributeSyntax", &[b"2.5.5.1"]),
                ("oMSyntax", &[b"127"]),
                ("isSingleValued", &[b"FALSE"]),
                ("systemOnly", &[b"TRUE"]),
                ("linkID", &[b"3"]),
                ("schemaIDGUID", &[&[7u8; 16]]),
            ],
        );
        let user = entry(
            "CN=User,CN=Schema",
            &[
                ("objectClass", &[b"top", b"classSchema"]),
                ("lDAPDisplayName", &[b"user"]),
                ("subClassOf", &[b"organizationalPerson"]),
                ("objectClassCategory", &[b"1"]),
                ("mayContain", &[b"pager"]),
                ("schemaIDGUID", &[&[9u8; 16]]),
            ],
        );
        let schema = schema_from_entries([&member_of, &user]);
        let d = schema.attribute("MEMBEROF;range=0-1499").unwrap();
        assert_eq!(d.syntax, Syntax::Dn);
        assert!(!d.single && d.system && d.back_link());
        assert_eq!(schema.name_of_guid(&[7u8; 16]), Some("memberOf"));
        assert_eq!(schema.name_of_guid(&[9u8; 16]), Some("user"));
        let class = schema.class("USER").unwrap();
        assert_eq!(class.parent, "organizationalPerson");
        assert_eq!(class.category, Category::Structural);
        assert_eq!(schema.ancestry("user").len(), 1);
    }

    #[test]
    fn edit_texts() {
        let d = |name: &str, syntax| AttributeDescription {
            name: name.into(),
            syntax,
            single: true,
            lower: None,
            upper: None,
            system: false,
            constructed: false,
            link: None,
            guid: Vec::new(),
        };
        assert_eq!(
            edit_text(&d("x", Syntax::Octets), &[1, 0xa2, 0xff]),
            "01 a2 ff"
        );
        assert_eq!(
            edit_text(&d("cn", Syntax::Unicode), "été".as_bytes()),
            "été"
        );
        assert!(is_date(&d("pwdLastSet", Syntax::LargeInteger)));
        assert!(is_guid(&d("objectGUID", Syntax::Octets)));
    }
}

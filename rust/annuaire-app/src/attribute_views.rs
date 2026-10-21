// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Attribute editor of the sheet (J4.4, `annuaire.vue.attributs`, reading part): what it
//! shows, without GTK. The equivalent of the « Attribute Editor » tab of the Windows console.
//! List: the attributes received for the object (`*` and a few constructed ones) and those
//! its class allows without a value (`allowedAttributes`); never a secret. Each value is
//! decoded according to the syntax of the schema. An attribute is read-only, with its reason,
//! if it is computed by the DC, a back link, `systemOnly`, the name of the object, its class
//! or its descriptor, of a syntax the editor does not read back, returned by ranges, or
//! absent of `allowedAttributesEffective`. The changes waiting in the draft of the sheet are
//! shown in place of the values read; the auxiliary classes offered by the schema are computed
//! here too.

use std::collections::{BTreeSet, HashMap, HashSet};

use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::time;
use annuaire_codecs::uac::{SamAccountType, UserAccountControl, group_flag_names};
use annuaire_codecs::{Guid, Sid, sddl};
use annuaire_core::changes::{is_sensitive, text_value};
use annuaire_core::dn;
use annuaire_core::schema::{
    self, AttributeDescription, Category, DATE_ATTRIBUTES, DURATION_ATTRIBUTES, EDITABLE_SYNTAXES,
    PWD_LAST_SET, Schema, Syntax,
};
use annuaire_core::session::Attributes;

use crate::i18n::{fill, tr};
use crate::sheet_views::AttributeEdit;
use crate::views;

/// Read for the editor: the whole object, the attributes its class allows and those the
/// account can write, a few constructed attributes that `*` does not give
/// (`ATTRIBUTS_EDITEUR`).
pub const EDITOR_ATTRIBUTES: [&str; 7] = [
    "*",
    "allowedAttributes",
    "allowedAttributesEffective",
    "memberOf",
    "canonicalName",
    "msDS-User-Account-Control-Computed",
    "nTSecurityDescriptor",
];

/// Read to decide, not shown (computed for the account that reads).
const HIDDEN: [&str; 2] = ["allowedattributes", "allowedattributeseffective"];

/// Values shown in the cell of the table; all in the dialog.
pub const SUMMED_VALUES: usize = 3;
pub const SUMMED_OCTETS: usize = 32;

// --- Decoding for the display ------------------------------------------------------------

/// Name of a syntax, as the interface shows it.
pub fn syntax_label(syntax: Syntax) -> String {
    match syntax {
        Syntax::Dn => "DN".into(),
        Syntax::Oid => "OID".into(),
        Syntax::OrName => "OR-Name".into(),
        Syntax::Sid => "SID".into(),
        Syntax::CaseString => tr("Case-sensitive string"),
        Syntax::Teletex => tr("Teletex string"),
        Syntax::Printable => tr("Printable string"),
        Syntax::Ia5 => tr("IA5 string"),
        Syntax::Numeric => tr("Numeric string"),
        Syntax::DnBinary => tr("DN with binary"),
        Syntax::Boolean => tr("Boolean"),
        Syntax::Integer => tr("Integer"),
        Syntax::Enumeration => tr("Enumeration"),
        Syntax::Octets => tr("Octet string"),
        Syntax::ReplicaLink => tr("Replica link"),
        Syntax::UtcTime => tr("UTC time"),
        Syntax::GeneralizedTime => tr("Generalized time"),
        Syntax::Unicode => tr("Unicode string"),
        Syntax::PresentationAddress => tr("Presentation address"),
        Syntax::DnString => tr("DN with string"),
        Syntax::AccessPoint => tr("Access point"),
        Syntax::Descriptor => tr("Security descriptor"),
        Syntax::LargeInteger => tr("Large integer"),
        Syntax::Unknown => tr("Unknown"),
    }
}

fn hex(value: &[u8], limit: Option<usize>) -> String {
    let n = value.len().to_string();
    match limit {
        Some(limit) if value.len() > limit => fill(
            &tr("{octets}… ({n} bytes)"),
            &[
                ("octets", &schema::hex(value.get(..limit).unwrap_or(value))),
                ("n", &n),
            ],
        ),
        _ => fill(
            &tr("{octets} ({n} bytes)"),
            &[("octets", &schema::hex(value)), ("n", &n)],
        ),
    }
}

fn text_or_hex(value: &[u8], limit: Option<usize>) -> String {
    text_value(value).map_or_else(|| hex(value, limit), str::to_owned)
}

fn flags_text(n: i64, names: &[&str]) -> String {
    #[allow(clippy::cast_sign_loss)] // the flags are the 32 bits of the value
    let hexa = format!("0x{:x}", (n as u64) & 0xFFFF_FFFF);
    if names.is_empty() {
        format!("{n} ({hexa})")
    } else {
        fill(
            &tr("{n} ({hexa}: {noms})"),
            &[
                ("n", &n.to_string()),
                ("hexa", &hexa),
                ("noms", &names.join(", ")),
            ],
        )
    }
}

fn integer_text(description: &AttributeDescription, value: &[u8]) -> Option<String> {
    let n = integer::decode(value, schema::width(description)).ok()?;
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let low = (n as u64 & 0xFFFF_FFFF) as u32;
    Some(match description.name.to_lowercase().as_str() {
        "useraccountcontrol" | "msds-user-account-control-computed" => {
            flags_text(n, &UserAccountControl(low).names())
        }
        "grouptype" => flags_text(n, &group_flag_names(low)),
        "samaccounttype" => i32::try_from(n)
            .ok()
            .and_then(|v| SamAccountType::decode(v).ok())
            .map_or_else(|| n.to_string(), |t| format!("{n} ({})", t.name())),
        _ => n.to_string(),
    })
}

/// A duration in days, hours and minutes (`_texte_duree`).
fn duration_text(seconds: i64) -> String {
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, minutes) = (rest / 3600, rest % 3600 / 60);
    let mut parts = Vec::new();
    if days != 0 {
        parts.push(fill(
            &tr("{n} d"),
            &[("n", &views::number(days.unsigned_abs()))],
        ));
    }
    if hours != 0 {
        parts.push(fill(&tr("{n} h"), &[("n", &hours.to_string())]));
    }
    if minutes != 0 || parts.is_empty() {
        parts.push(fill(&tr("{n} min"), &[("n", &minutes.to_string())]));
    }
    parts.join(" ")
}

/// Date or duration in clear first (the cell of the table is cut), the number after
/// (`_grand_entier`).
fn large_integer_text(description: &AttributeDescription, value: &[u8]) -> Option<String> {
    let n = integer::decode(value, Width::Bits64).ok()?;
    let lower = description.name.to_lowercase();
    if DATE_ATTRIBUTES.contains(&lower.as_str()) {
        if n == -1 {
            return Some(format!("{} ({n})", tr("now")));
        }
        if n == 0 || time::is_never(n).unwrap_or(false) {
            return Some(format!("{} ({n})", tr("never")));
        }
        let seconds = time::nttime_to_unix(n).ok()??;
        return Some(format!("{} ({n})", views::format_unix(seconds)));
    }
    if DURATION_ATTRIBUTES.contains(&lower.as_str()) && n <= 0 {
        if time::duration_is_never(n).unwrap_or(false) {
            return Some(format!("{} ({n})", tr("never")));
        }
        if let Ok(Some(micros)) = time::duration_to_micros(n) {
            return Some(format!("{} ({n})", duration_text(micros / 1_000_000)));
        }
    }
    Some(n.to_string())
}

fn date_text(text: &str, utc: bool) -> String {
    let decoded = if utc {
        // YYMMDDhhmmssZ, the century as `strptime` gives it (1969-2068).
        text.strip_suffix('Z')
            .filter(|t| t.len() == 12 && t.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|t| {
                let year: i32 = t[..2].parse().ok()?;
                let century = if year < 69 { "20" } else { "19" };
                time::decode_generalized_time(&format!("{century}{t}Z")).ok()
            })
    } else {
        time::decode_generalized_time(text).ok()
    };
    match decoded {
        Some(date) => format!("{} ({text})", views::format_unix(date.unix_seconds())),
        None => text.to_owned(),
    }
}

fn descriptor_text(value: &[u8]) -> Option<String> {
    let sd = SecurityDescriptor::decode(value).ok()?;
    sddl::sd_to_sddl(&sd, None).ok()
}

/// A value in clear according to the syntax; `complete`: without cutting the octets
/// (dialog). A secret is never decoded (`montrer`).
pub fn show(
    description: Option<&AttributeDescription>,
    name: &str,
    value: &[u8],
    complete: bool,
) -> String {
    if is_sensitive(name) {
        return tr("<hidden>");
    }
    let limit = (!complete).then_some(SUMMED_OCTETS);
    let Some(description) = description else {
        return text_or_hex(value, limit);
    };
    let shown = match description.syntax {
        Syntax::Boolean => {
            let text = text_or_hex(value, limit);
            Some(match text.as_str() {
                "TRUE" => tr("True"),
                "FALSE" => tr("False"),
                _ => text,
            })
        }
        Syntax::Integer | Syntax::Enumeration => integer_text(description, value),
        Syntax::LargeInteger => large_integer_text(description, value),
        Syntax::GeneralizedTime | Syntax::UtcTime => std::str::from_utf8(value)
            .ok()
            .filter(|t| t.is_ascii())
            .map(|t| date_text(t, description.syntax == Syntax::UtcTime)),
        Syntax::Sid => Sid::decode(value).ok().map(|s| s.to_string()),
        Syntax::Octets if schema::is_guid(description) && value.len() == 16 => {
            Guid::decode(value).ok().map(|g| g.to_string())
        }
        Syntax::Octets | Syntax::ReplicaLink => Some(hex(value, limit)),
        Syntax::Descriptor => descriptor_text(value),
        _ => Some(text_or_hex(value, limit)),
    };
    shown.unwrap_or_else(|| hex(value, limit))
}

// --- Rows of the table -------------------------------------------------------------------

/// An attribute of the object, as the editor shows it (`LigneAttribut`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeLine {
    pub name: String,
    pub description: Option<AttributeDescription>,
    /// Read on the DC.
    pub values: Vec<Vec<u8>>,
    /// After the change waiting in the draft (the values read if there is none).
    pub wanted: Vec<Vec<u8>>,
    /// The wanted values, in clear.
    pub texts: Vec<String>,
    /// Why the attribute cannot be changed here; None: it could be.
    pub reason: Option<String>,
}

impl AttributeLine {
    pub fn filled(&self) -> bool {
        !self.wanted.is_empty()
    }

    pub fn modified(&self) -> bool {
        self.wanted != self.values
    }

    pub fn editable(&self) -> bool {
        self.reason.is_none()
    }

    pub fn single(&self) -> bool {
        self.description.as_ref().is_none_or(|d| d.single)
    }

    /// Cell « Value »: the first values, or « not set ».
    pub fn summary(&self) -> String {
        if self.texts.is_empty() {
            return tr("<not set>");
        }
        let mut start = self
            .texts
            .iter()
            .take(SUMMED_VALUES)
            .map(|t| t.replace('\n', " "))
            .collect::<Vec<_>>()
            .join("; ");
        let rest = self.texts.len().saturating_sub(SUMMED_VALUES);
        if rest > 0 {
            start.push_str(&fill(
                &tr(" … and {n} more"),
                &[("n", &views::number(rest as u64))],
            ));
        }
        start
    }

    /// Cell « Type »: syntax, « multi-valued » if so.
    pub fn kind(&self) -> String {
        match &self.description {
            None => tr("Not in the schema"),
            Some(d) if d.single => syntax_label(d.syntax),
            Some(d) => fill(
                &tr("{syntaxe}, multi-valued"),
                &[("syntaxe", &syntax_label(d.syntax))],
            ),
        }
    }

    /// Cell « State »: modified, read-only, or nothing.
    pub fn state(&self) -> String {
        if self.modified() {
            tr("modified")
        } else if self.reason.is_some() {
            tr("read-only")
        } else {
            String::new()
        }
    }
}

struct Context<'a> {
    rdn: &'a str,
    effective: &'a HashSet<String>,
    read_only: bool,
}

fn reason(
    name: &str,
    description: Option<&AttributeDescription>,
    ranged: bool,
    context: &Context<'_>,
) -> Option<String> {
    let lower = name.to_lowercase();
    if context.read_only {
        return Some(tr("Read-only profile."));
    }
    let Some(description) = description else {
        return Some(tr(
            "Not in the schema that was read: the editor cannot write it.",
        ));
    };
    if description.constructed {
        return Some(tr("Computed by the controller on each read, never stored."));
    }
    if description.back_link() {
        return Some(tr(
            "Back link maintained by the controller: it follows the linked attribute of the other object (memberOf follows member).",
        ));
    }
    if description.system {
        return Some(tr(
            "Reserved for the system (systemOnly): only the controller writes it.",
        ));
    }
    if lower == context.rdn.to_lowercase() || lower == "name" || lower == "distinguishedname" {
        return Some(tr(
            "Name of the object: it changes by renaming the object (F2).",
        ));
    }
    if lower == "objectclass" {
        return Some(tr(
            "Class of the object: its auxiliary classes are changed with “Auxiliary Classes…”.",
        ));
    }
    if lower == "ntsecuritydescriptor" {
        return Some(tr("Security descriptor: “Security” tab."));
    }
    if !EDITABLE_SYNTAXES.contains(&description.syntax) {
        return Some(fill(
            &tr("Syntax “{syntaxe}”: cannot be edited here."),
            &[("syntaxe", &syntax_label(description.syntax))],
        ));
    }
    if ranged {
        return Some(tr(
            "Returned in ranges (too many values): “Members” tab for member.",
        ));
    }
    if !context.effective.contains(&lower) {
        return Some(tr(
            "This account is not allowed to modify it (allowedAttributesEffective).",
        ));
    }
    None
}

/// Every attribute of the object, filled or allowed by its class, by name; never a secret.
/// `attributes`: read with `EDITOR_ATTRIBUTES`; `edits`: changes waiting (`lignes`).
pub fn lines(
    dn_text: &str,
    attributes: &Attributes,
    schema: &Schema,
    edits: &[AttributeEdit],
    read_only: bool,
) -> Vec<AttributeLine> {
    let edit_of = |lower: &str| edits.iter().find(|e| e.attribute.to_lowercase() == lower);
    let mut received: HashMap<String, Vec<Vec<u8>>> = HashMap::new();
    let mut received_names: HashMap<String, String> = HashMap::new();
    let mut ranged: HashSet<String> = HashSet::new();
    for (name, values) in attributes {
        let (base, option) = name.split_once(';').unwrap_or((name.as_str(), ""));
        let lower = base.to_lowercase();
        if option.to_lowercase().starts_with("range=") {
            ranged.insert(lower.clone());
        }
        received_names
            .entry(lower.clone())
            .or_insert_with(|| base.to_owned());
        received
            .entry(lower)
            .or_default()
            .extend(values.iter().cloned());
    }
    let list = |name: &str| -> HashSet<String> {
        received
            .get(name)
            .into_iter()
            .flatten()
            .map(|v| String::from_utf8_lossy(v).to_lowercase())
            .collect()
    };
    let mut allowed = list("allowedattributes");
    // Absent from the answer: empty (the server leaves out an attribute without value).
    let mut effective = list("allowedattributeseffective");
    // Auxiliary classes added in the editor, not written yet: their attributes can already be
    // edited (same request, the class first: `sheet_views::prepare_changeset`).
    if let Some(classes) = edit_of("objectclass") {
        let brought: HashSet<String> = classes
            .wanted
            .iter()
            .filter(|n| !classes.origin.contains(n))
            .flat_map(|n| class_attributes(schema, &String::from_utf8_lossy(n)))
            .map(|a| a.to_lowercase())
            .collect();
        allowed.extend(brought.iter().cloned());
        // Samba never names objectClass in allowedAttributesEffective, even for an
        // administrator: an account that can write the object may try, the DC decides.
        if !effective.is_empty() {
            effective.extend(brought);
        }
    }
    let rdn = dn::split(dn_text)
        .ok()
        .and_then(|c| c.first().map(|c| c.attribute.clone()))
        .unwrap_or_default();
    let context = Context {
        rdn: &rdn,
        effective: &effective,
        read_only,
    };
    let names: BTreeSet<&String> = received.keys().chain(allowed.iter()).collect();
    let mut out: Vec<AttributeLine> = names
        .into_iter()
        .filter(|lower| !HIDDEN.contains(&lower.as_str()) && !is_sensitive(lower))
        .map(|lower| {
            let description = schema.attribute(lower).cloned();
            let name = description.as_ref().map_or_else(
                || {
                    received_names
                        .get(lower)
                        .cloned()
                        .unwrap_or_else(|| lower.clone())
                },
                |d| d.name.clone(),
            );
            let values = received.get(lower).cloned().unwrap_or_default();
            let wanted = edit_of(lower).map_or_else(|| values.clone(), |e| e.wanted.clone());
            let reason = reason(
                &name,
                description.as_ref(),
                ranged.contains(lower),
                &context,
            );
            let texts = wanted
                .iter()
                .map(|v| show(description.as_ref(), &name, v, false))
                .collect();
            AttributeLine {
                name,
                description,
                values,
                wanted,
                texts,
                reason,
            }
        })
        .collect();
    out.sort_by_cached_key(|l| gtk::glib::casefold(&l.name).to_string());
    out
}

/// Search by name (substring, without case), « filled only », « editable only »
/// (`filtrer`).
pub fn filter<'a>(
    all: &'a [AttributeLine],
    text: &str,
    filled: bool,
    editable: bool,
) -> Vec<&'a AttributeLine> {
    let key = gtk::glib::casefold(text.trim()).to_string();
    all.iter()
        .filter(|x| {
            (key.is_empty() || gtk::glib::casefold(&x.name).contains(&key))
                && (!filled || x.filled())
                && (!editable || x.editable())
        })
        .collect()
}

pub fn describe_count(shown: usize, total: usize) -> String {
    if shown == total {
        fill(
            &tr("{n} attributes"),
            &[("n", &views::number(total as u64))],
        )
    } else {
        fill(
            &tr("{montres} attributes out of {total}"),
            &[
                ("montres", &views::number(shown as u64)),
                ("total", &views::number(total as u64)),
            ],
        )
    }
}

/// Subtitle of the dialog: syntax, number of values, bounds (`description_attribut`).
pub fn attribute_description(line: &AttributeLine) -> String {
    let Some(d) = &line.description else {
        return tr("Not in the schema");
    };
    let mut parts = vec![
        syntax_label(d.syntax),
        if d.single {
            tr("single value")
        } else {
            tr("multiple values")
        },
    ];
    if d.lower.is_some() || d.upper.is_some() {
        let bound = |b: Option<i64>| b.map_or_else(|| "…".to_owned(), |b| b.to_string());
        parts.push(fill(
            &tr("from {bas} to {haut}"),
            &[("bas", &bound(d.lower)), ("haut", &bound(d.upper))],
        ));
    }
    parts.join(", ")
}

/// Form expected of an input, according to the syntax (`aide_saisie`).
pub fn input_help(line: &AttributeLine) -> String {
    let Some(d) = &line.description else {
        return String::new();
    };
    if schema::is_date(d) {
        return tr("Number (FILETIME), “never”, or date DD/MM/YYYY hh:mm (local time).");
    }
    if d.name.to_lowercase() == PWD_LAST_SET {
        return tr("0: change required; -1: now.");
    }
    if schema::is_guid(d) {
        return tr("GUID (01234567-89ab-cdef-0123-456789abcdef) or hexadecimal bytes.");
    }
    match d.syntax {
        Syntax::Boolean => tr("TRUE or FALSE (true, false)."),
        Syntax::Integer => tr("32-bit integer (decimal or 0x…)."),
        Syntax::Enumeration => tr("32-bit integer."),
        Syntax::LargeInteger => tr("64-bit integer."),
        Syntax::GeneralizedTime => tr("DD/MM/YYYY hh:mm (local time) or YYYYMMDDhhmmss.0Z."),
        Syntax::UtcTime => tr("DD/MM/YYYY hh:mm (local time) or YYMMDDhhmmssZ."),
        Syntax::Sid => tr("SID: S-1-5-21-…"),
        Syntax::Octets => tr("Hexadecimal bytes: 01 a2 ff."),
        Syntax::Dn => tr("Distinguished name: CN=…,OU=…,DC=…"),
        Syntax::DnBinary => tr("B:<number of digits>:<hexadecimal>:<DN>"),
        Syntax::DnString => tr("S:<length>:<text>:<DN>"),
        Syntax::Oid => tr("OID (1.2.840.…) or LDAP name."),
        Syntax::Numeric => tr("Digits and spaces."),
        Syntax::Printable => tr("Unaccented letters, digits, space and ' ( ) + , - . / : ? ="),
        Syntax::Ia5 => tr("ASCII characters."),
        _ => String::new(),
    }
}

// --- Auxiliary classes -------------------------------------------------------------------

/// Attributes a class allows, its parents included (`top` excluded: every class has it)
/// (`attributs_de_classe`).
pub fn class_attributes(schema: &Schema, name: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for class in schema.ancestry(name) {
        if class.name.eq_ignore_ascii_case("top") {
            continue;
        }
        for a in class.mandatory.iter().chain(&class.optional) {
            if !out.contains(a) {
                out.push(a.clone());
            }
        }
    }
    out
}

/// Attributes these classes allow, their parents and their linked auxiliaries
/// (`_permis_par`).
fn allowed_by(schema: &Schema, classes: &[String]) -> HashSet<String> {
    let mut allowed = HashSet::new();
    let mut seen = HashSet::new();
    let mut to_see: Vec<String> = classes.to_vec();
    while let Some(name) = to_see.pop() {
        if !seen.insert(name.to_lowercase()) {
            continue;
        }
        for class in schema.ancestry(&name) {
            allowed.extend(
                class
                    .mandatory
                    .iter()
                    .chain(&class.optional)
                    .map(|a| a.to_lowercase()),
            );
            to_see.extend(class.auxiliaries.iter().cloned());
        }
    }
    allowed
}

/// An auxiliary class offered for the object, and what it brings (`ClasseAuxiliaire`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuxiliaryClass {
    pub name: String,
    /// In `objectClass` as read on the DC.
    pub read: bool,
    /// In `objectClass` after the change waiting.
    pub wanted: bool,
    /// Attributes the class allows (parents included).
    pub attributes: Vec<String>,
    /// Those the object does not already have by its other classes.
    pub new: Vec<String>,
    pub mandatory: Vec<String>,
    /// Why it cannot be removed now; None: free.
    pub reason: Option<String>,
}

impl AuxiliaryClass {
    pub fn subtitle(&self) -> String {
        if self.attributes.is_empty() {
            tr("Brings no attribute.")
        } else if self.new.is_empty() {
            fill(
                &tr("Attributes already allowed by the class of the object: {liste}"),
                &[("liste", &self.attributes.join(", "))],
            )
        } else {
            fill(&tr("Brings: {liste}"), &[("liste", &self.new.join(", "))])
        }
    }
}

/// The auxiliary classes the schema offers for an object of these classes (`auxiliaryClass`
/// and `systemAuxiliaryClass` of its classes and of their parents), plus those the object
/// already carries. `wanted`: `objectClass` after the change waiting; `filled`: attributes that
/// will have a value (lower case). A class cannot be removed while it alone allows a filled
/// attribute (the DC would refuse: objectClassViolation) (`classes_auxiliaires`).
pub fn auxiliary_classes(
    classes: &[String],
    schema: &Schema,
    wanted: &[String],
    filled: &HashSet<String>,
) -> Vec<AuxiliaryClass> {
    let read: HashSet<String> = classes.iter().map(|c| c.to_lowercase()).collect();
    let mut offered: Vec<String> = Vec::new();
    let has = |list: &[String], name: &str| list.iter().any(|o| o.eq_ignore_ascii_case(name));
    for class in classes {
        let structural = schema
            .class(class)
            .is_some_and(|d| d.category != Category::Auxiliary);
        if !structural {
            continue;
        }
        for d in schema.ancestry(class) {
            for a in &d.auxiliaries {
                if !has(&offered, a) {
                    offered.push(a.clone());
                }
            }
        }
    }
    for class in classes.iter().chain(wanted) {
        if let Some(d) = schema.class(class)
            && d.category == Category::Auxiliary
            && !has(&offered, class)
        {
            offered.push(d.name.clone());
        }
    }
    let mut out: Vec<AuxiliaryClass> = offered
        .iter()
        .filter_map(|name| {
            let d = schema.class(name)?;
            let is_wanted = has(wanted, name);
            let brought = class_attributes(schema, &d.name);
            let others: Vec<String> = wanted
                .iter()
                .filter(|v| !v.eq_ignore_ascii_case(name))
                .cloned()
                .collect();
            let elsewhere = allowed_by(schema, &others);
            let new: Vec<String> = brought
                .iter()
                .filter(|a| !elsewhere.contains(&a.to_lowercase()))
                .cloned()
                .collect();
            let blocking: Vec<&String> = new
                .iter()
                .filter(|a| filled.contains(&a.to_lowercase()))
                .collect();
            let reason = (is_wanted && !blocking.is_empty()).then(|| {
                fill(
                    &tr("First remove the values of: {liste}."),
                    &[(
                        "liste",
                        &blocking
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                    )],
                )
            });
            Some(AuxiliaryClass {
                name: d.name.clone(),
                read: read.contains(&d.name.to_lowercase()),
                wanted: is_wanted,
                attributes: brought,
                new,
                mandatory: d.mandatory.clone(),
                reason,
            })
        })
        .collect();
    out.sort_by_cached_key(|c| gtk::glib::casefold(&c.name).to_string());
    out
}

/// The edit of `objectClass` that sets the auxiliary classes `chosen` (names) and removes the
/// other classes offered; the other values do not move (`edition_classes`).
pub fn classes_edit(
    read: &[Vec<u8>],
    classes: &[AuxiliaryClass],
    chosen: &HashSet<String>,
) -> AttributeEdit {
    let offered: HashSet<String> = classes.iter().map(|c| c.name.to_lowercase()).collect();
    let chosen: HashSet<String> = chosen.iter().map(|c| c.to_lowercase()).collect();
    let lower = |v: &[u8]| String::from_utf8_lossy(v).to_lowercase();
    let mut wanted: Vec<Vec<u8>> = read
        .iter()
        .filter(|v| !offered.contains(&lower(v)) || chosen.contains(&lower(v)))
        .cloned()
        .collect();
    let already: HashSet<String> = wanted.iter().map(|v| lower(v)).collect();
    wanted.extend(
        classes
            .iter()
            .filter(|c| {
                chosen.contains(&c.name.to_lowercase()) && !already.contains(&c.name.to_lowercase())
            })
            .map(|c| c.name.as_bytes().to_vec()),
    );
    AttributeEdit {
        attribute: "objectClass".to_owned(),
        single: false,
        origin: read.to_vec(),
        wanted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn description(name: &str, syntax: Syntax, single: bool) -> AttributeDescription {
        AttributeDescription {
            name: name.into(),
            syntax,
            single,
            lower: None,
            upper: None,
            system: false,
            constructed: false,
            link: None,
            guid: Vec::new(),
        }
    }

    #[test]
    fn values_in_clear() {
        let uac = description("userAccountControl", Syntax::Integer, true);
        assert_eq!(
            show(Some(&uac), "userAccountControl", b"514", false),
            "514 (0x202: ACCOUNTDISABLE, NORMAL_ACCOUNT)"
        );
        let flag = description("isCriticalSystemObject", Syntax::Boolean, true);
        assert_eq!(show(Some(&flag), "x", b"TRUE", false), "True");
        let age = description("maxPwdAge", Syntax::LargeInteger, true);
        assert_eq!(
            show(Some(&age), "maxPwdAge", b"-36288000000000", false),
            "42 d (-36288000000000)"
        );
        let octets = description("x", Syntax::Octets, true);
        assert_eq!(show(Some(&octets), "x", &[0, 1], false), "00 01 (2 bytes)");
        assert_eq!(show(None, "unicodePwd", b"secret", false), "<hidden>");
        assert_eq!(show(None, "x", b"texte", false), "texte");
    }

    #[test]
    fn lines_and_reasons() {
        let mut schema_entries = Vec::new();
        for (name, syntax, single) in [
            ("cn", ("2.5.5.12", "64"), true),
            ("description", ("2.5.5.12", "64"), true),
            ("pager", ("2.5.5.12", "64"), true),
        ] {
            schema_entries.push(annuaire_core::session::Entry {
                dn: format!("CN={name},CN=Schema"),
                attributes: vec![
                    ("objectClass".into(), vec![b"attributeSchema".to_vec()]),
                    ("lDAPDisplayName".into(), vec![name.as_bytes().to_vec()]),
                    ("attributeSyntax".into(), vec![syntax.0.as_bytes().to_vec()]),
                    ("oMSyntax".into(), vec![syntax.1.as_bytes().to_vec()]),
                    (
                        "isSingleValued".into(),
                        vec![if single {
                            b"TRUE".to_vec()
                        } else {
                            b"FALSE".to_vec()
                        }],
                    ),
                ],
            });
        }
        let schema = annuaire_core::schema::schema_from_entries(&schema_entries);
        let attributes: Attributes = vec![
            ("cn".into(), vec![b"alice".to_vec()]),
            ("description".into(), vec![b"x".to_vec()]),
            (
                "allowedAttributes".into(),
                vec![b"pager".to_vec(), b"cn".to_vec()],
            ),
            (
                "allowedAttributesEffective".into(),
                vec![b"description".to_vec()],
            ),
            ("unicodePwd".into(), vec![b"s".to_vec()]),
        ];
        let all = lines("CN=alice,DC=x", &attributes, &schema, &[], false);
        let names: Vec<&str> = all.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["cn", "description", "pager"]);
        let [cn, description, pager] = all.as_slice() else {
            panic!("three lines expected");
        };
        assert!(
            cn.reason
                .as_deref()
                .is_some_and(|r| r.starts_with("Name of the object"))
        );
        assert!(description.editable());
        assert!(!pager.filled());
        assert_eq!(pager.summary(), "<not set>");
        assert_eq!(filter(&all, "DESC", false, false).len(), 1);
        assert_eq!(filter(&all, "", true, false).len(), 2);
        assert_eq!(describe_count(1, 3), "1 attributes out of 3");
        let edited = lines(
            "CN=alice,DC=x",
            &attributes,
            &schema,
            &[AttributeEdit {
                attribute: "Description".into(),
                single: true,
                origin: vec![b"x".to_vec()],
                wanted: vec![b"y".to_vec()],
            }],
            false,
        );
        let changed = edited.iter().find(|l| l.name == "description").unwrap();
        assert_eq!(
            (changed.state().as_str(), changed.summary().as_str()),
            ("modified", "y")
        );
        let read_only = lines("CN=alice,DC=x", &attributes, &schema, &[], true);
        assert!(
            read_only
                .iter()
                .all(|l| l.reason.as_deref() == Some("Read-only profile."))
        );
    }
}

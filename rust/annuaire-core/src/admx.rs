// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Administrative templates: ADMX and ADML files (J7.2, `annuaire.core.admx`), without network.
//!
//! An ADMX declares a namespace (`<target prefix namespace>`), those it cites (`<using>`),
//! « supported on » definitions, categories and policies; its ADML (same name, in a language
//! folder `fr-FR`, `en-US`…) carries the texts (`$(string.ID)`) and the presentations
//! (`$(presentation.ID)`: the controls of the sheet). A reference `prefix:name` resolves through
//! the namespace of the prefix, which links categories from one file to another (most have
//! their parent in `Windows.admx`).
//!
//! `analyze(files, language)` builds a `Store` from the bytes of the files; `admx_store` reads
//! them on the SYSVOL and keeps the local cache. An unreadable file is set aside and its error
//! kept (`Store::errors`): the rest of the store serves anyway.
//!
//! Reference: « Group Policy ADMX » schema of Microsoft (`policyDefinitions`,
//! `policyDefinitionResources`).

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value as Json, json};
use unicode_normalization::UnicodeNormalization;

use crate::xml::Node;

// --- Model --------------------------------------------------------------------------------

/// Part of the GPO a policy goes to: `Machine`, `User` or both (`Classe`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Machine,
    User,
    Both,
}

impl Class {
    pub fn value(self) -> &'static str {
        match self {
            Self::Machine => "Machine",
            Self::User => "User",
            Self::Both => "Both",
        }
    }

    pub fn of(text: &str) -> Option<Self> {
        [Self::Machine, Self::User, Self::Both]
            .into_iter()
            .find(|c| c.value() == text)
    }

    /// True if a policy of this class goes to `part` (`vaut_pour`).
    pub fn applies_to(self, part: Self) -> bool {
        self == Self::Both || self == part
    }
}

/// A registry value written by the ADMX (`<decimal value>`, `<longDecimal value>`,
/// `<string>`, `<delete/>`) (`Valeur`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmxValue {
    Decimal(i128),
    Long(i128),
    String(String),
    Delete,
}

impl AdmxValue {
    fn kind(&self) -> &'static str {
        match self {
            Self::Decimal(_) => "decimal",
            Self::Long(_) => "longDecimal",
            Self::String(_) => "string",
            Self::Delete => "delete",
        }
    }
}

/// An item of a `valueList` (`enabledList`, `trueList`, item of an `enum`…): a value set
/// elsewhere than on the main value; `key` already resolved (`ItemListe`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListItem {
    pub key: String,
    pub value_name: String,
    pub value: AdmxValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ElementKind {
    Boolean,
    Decimal,
    Long,
    Text,
    Enum,
    List,
    MultiText,
}

impl ElementKind {
    pub const ALL: [Self; 7] = [
        Self::Boolean,
        Self::Decimal,
        Self::Long,
        Self::Text,
        Self::Enum,
        Self::List,
        Self::MultiText,
    ];

    pub fn value(self) -> &'static str {
        match self {
            Self::Boolean => "boolean",
            Self::Decimal => "decimal",
            Self::Long => "longDecimal",
            Self::Text => "text",
            Self::Enum => "enum",
            Self::List => "list",
            Self::MultiText => "multiText",
        }
    }

    pub fn of(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.value() == text)
    }
}

/// An item of an `enum`: label, value and list of values set with it (`Choix`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Choice {
    pub label: String,
    pub value: Option<AdmxValue>,
    pub list: Vec<ListItem>,
}

/// An option of a policy (`<elements>`). One structure for the seven kinds: the fields without
/// meaning keep their default. `key` is resolved (that of the element, else that of the
/// policy).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub kind: ElementKind,
    pub id: String,
    pub key: String,
    pub value_name: String,
    pub required: bool,
    // decimal, longDecimal
    pub minimum: i128,
    pub maximum: i128,
    /// `storeAsText`: the number is written as REG_SZ.
    pub as_text: bool,
    /// `soft`: does not overwrite a value already on the computer.
    pub soft: bool,
    // text, multiText, list
    pub max_length: i128,
    /// `expandable`: REG_EXPAND_SZ.
    pub expandable: bool,
    pub max_strings: i128,
    // boolean
    pub true_value: Option<AdmxValue>,
    pub false_value: Option<AdmxValue>,
    pub true_list: Vec<ListItem>,
    pub false_list: Vec<ListItem>,
    // enum
    pub choices: Vec<Choice>,
    // list
    /// `valuePrefix`: names `prefix1`, `prefix2`…; `None`: the name is the value.
    pub prefix: Option<String>,
    pub additive: bool,
    /// `explicitValue`: the user types the name and the value.
    pub explicit: bool,
}

impl Element {
    pub fn new(kind: ElementKind, id: &str, key: &str) -> Self {
        Self {
            kind,
            id: id.to_owned(),
            key: key.to_owned(),
            value_name: String::new(),
            required: false,
            minimum: 0,
            maximum: 9999,
            as_text: false,
            soft: false,
            max_length: 1023,
            expandable: false,
            max_strings: 0,
            true_value: None,
            false_value: None,
            true_list: Vec::new(),
            false_list: Vec::new(),
            choices: Vec::new(),
            prefix: None,
            additive: false,
            explicit: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ControlKind {
    CheckBox,
    Decimal,
    LongDecimal,
    Text,
    MultiText,
    DropdownList,
    ListBox,
    ComboBox,
    Static,
}

impl ControlKind {
    pub const ALL: [Self; 9] = [
        Self::CheckBox,
        Self::Decimal,
        Self::LongDecimal,
        Self::Text,
        Self::MultiText,
        Self::DropdownList,
        Self::ListBox,
        Self::ComboBox,
        Self::Static,
    ];

    pub fn value(self) -> &'static str {
        match self {
            Self::CheckBox => "checkBox",
            Self::Decimal => "decimalTextBox",
            Self::LongDecimal => "longDecimalTextBox",
            Self::Text => "textBox",
            Self::MultiText => "multiTextBox",
            Self::DropdownList => "dropdownList",
            Self::ListBox => "listBox",
            Self::ComboBox => "comboBox",
            Self::Static => "text",
        }
    }

    pub fn of(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.value() == text)
    }
}

/// A control of an ADML presentation, in the order of the sheet. `ref_id` names the element
/// (`refId`); a static text has none. `default`: `defaultChecked`, `defaultValue`,
/// `defaultItem` or `<default>`, as written (`Controle`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub kind: ControlKind,
    pub ref_id: String,
    pub label: String,
    pub default: Option<String>,
    pub suggestions: Vec<String>,
    /// Dropdown list: false if `noSort`.
    pub sort: bool,
    /// `spinStep` of a numeric field.
    pub step: i128,
}

impl Control {
    fn new(kind: ControlKind, ref_id: &str, label: &str, default: Option<String>) -> Self {
        Self {
            kind,
            ref_id: ref_id.to_owned(),
            label: label.to_owned(),
            default,
            suggestions: Vec::new(),
            sort: true,
            step: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Category {
    /// `namespace:name`, unique in the store.
    pub ident: String,
    pub name: String,
    pub label: String,
    pub explain: String,
    /// Identifier of the parent category; `None` at the root (or parent not found).
    pub parent: Option<String>,
    pub file: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// `namespace:name`.
    pub ident: String,
    pub name: String,
    pub class: Class,
    pub label: String,
    pub explain: String,
    pub category: Option<String>,
    pub supported: String,
    pub key: String,
    pub value_name: String,
    pub enabled_value: Option<AdmxValue>,
    pub disabled_value: Option<AdmxValue>,
    pub enabled_list: Vec<ListItem>,
    pub disabled_list: Vec<ListItem>,
    pub elements: Vec<Element>,
    pub presentation: Vec<Control>,
    pub file: String,
}

impl Policy {
    pub fn element(&self, id: &str) -> Option<&Element> {
        self.elements.iter().find(|e| e.id == id)
    }
}

/// The whole analyzed store (`Magasin`). Categories and policies in the order of the files;
/// `language`: that of the ADMLs kept for most files.
#[derive(Debug, Clone, Default)]
pub struct Store {
    pub categories: Vec<Category>,
    pub policies: Vec<Policy>,
    pub language: String,
    pub files: usize,
    pub errors: Vec<String>,
    category_index: HashMap<String, usize>,
    policy_index: HashMap<String, usize>,
    children: HashMap<Option<String>, Vec<usize>>,
    by_category: HashMap<Option<String>, Vec<usize>>,
    texts: Vec<String>,
}

impl Store {
    pub fn new(
        categories: Vec<Category>,
        policies: Vec<Policy>,
        language: &str,
        files: usize,
        errors: Vec<String>,
    ) -> Self {
        let category_index = categories
            .iter()
            .enumerate()
            .map(|(i, c)| (c.ident.clone(), i))
            .collect();
        let policy_index = policies
            .iter()
            .enumerate()
            .map(|(i, p)| (p.ident.clone(), i))
            .collect();
        let mut store = Self {
            categories,
            policies,
            language: language.to_owned(),
            files,
            errors,
            category_index,
            policy_index,
            ..Self::default()
        };
        store.prepare();
        store
    }

    pub fn category(&self, ident: &str) -> Option<&Category> {
        self.category_index
            .get(ident)
            .and_then(|&i| self.categories.get(i))
    }

    pub fn policy(&self, ident: &str) -> Option<&Policy> {
        self.policy_index
            .get(ident)
            .and_then(|&i| self.policies.get(i))
    }

    /// Builds the indexes of the tree and of the search (`preparer`).
    fn prepare(&mut self) {
        let mut children: HashMap<Option<String>, Vec<usize>> = HashMap::new();
        for (i, c) in self.categories.iter().enumerate() {
            children.entry(c.parent.clone()).or_default().push(i);
        }
        for list in children.values_mut() {
            list.sort_by_cached_key(|&i| self.categories.get(i).map(|c| fold(&c.label)));
        }
        let mut by_category: HashMap<Option<String>, Vec<usize>> = HashMap::new();
        for (i, p) in self.policies.iter().enumerate() {
            by_category.entry(p.category.clone()).or_default().push(i);
        }
        for list in by_category.values_mut() {
            list.sort_by_cached_key(|&i| self.policies.get(i).map(|p| fold(&p.label)));
        }
        self.children = children;
        self.by_category = by_category;
        self.texts = self
            .policies
            .iter()
            .map(|s| {
                normalize(
                    &[
                        s.label.as_str(),
                        &s.explain,
                        &s.name,
                        &s.key,
                        &s.value_name,
                        &s.supported,
                    ]
                    .join("\n"),
                )
            })
            .collect();
    }

    /// Child categories (roots for `None`), by label; with `part`, only those holding, at any
    /// depth, a policy of this part (`sous_categories`).
    pub fn subcategories(&self, parent: Option<&str>, part: Option<Class>) -> Vec<&Category> {
        let key = parent.map(str::to_owned);
        let list: Vec<&Category> = self
            .children
            .get(&key)
            .map(|v| v.iter().filter_map(|&i| self.categories.get(i)).collect())
            .unwrap_or_default();
        match part {
            None => list,
            Some(part) => list
                .into_iter()
                .filter(|c| self.contains(&c.ident, part))
                .collect(),
        }
    }

    /// Policies directly in `category`, by label (`strategies_de`).
    pub fn policies_of(&self, category: Option<&str>, part: Option<Class>) -> Vec<&Policy> {
        let key = category.map(str::to_owned);
        self.by_category
            .get(&key)
            .map(|v| {
                v.iter()
                    .filter_map(|&i| self.policies.get(i))
                    .filter(|p| part.is_none_or(|part| p.class.applies_to(part)))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn contains(&self, category: &str, part: Class) -> bool {
        self.contains_seen(category, part, &mut HashSet::new())
    }

    fn contains_seen(&self, category: &str, part: Class, seen: &mut HashSet<String>) -> bool {
        if !seen.insert(category.to_owned()) {
            return false;
        }
        if !self.policies_of(Some(category), Some(part)).is_empty() {
            return true;
        }
        self.subcategories(Some(category), None)
            .iter()
            .any(|c| self.contains_seen(&c.ident, part, seen))
    }

    /// Categories from the root down to `category` included (`chemin`).
    pub fn path(&self, category: Option<&str>) -> Vec<&Category> {
        let mut path = Vec::new();
        let mut seen = HashSet::new();
        let mut current = category.map(str::to_owned);
        while let Some(ident) = current {
            let Some(c) = self.category(&ident) else {
                break;
            };
            if !seen.insert(ident) {
                break;
            }
            path.push(c);
            current = c.parent.clone();
        }
        path.reverse();
        path
    }

    /// Full text, without case or accents: each word must appear in the label, the
    /// explanation, the name, the key, the value or the « supported on ». The policies whose
    /// label holds every word first, then the others, each by label (`chercher`).
    pub fn search(&self, text: &str, part: Option<Class>, limit: Option<usize>) -> Vec<&Policy> {
        let normalized = normalize(text);
        let words: Vec<&str> = normalized.split_whitespace().collect();
        if words.is_empty() {
            return Vec::new();
        }
        let mut in_label = Vec::new();
        let mut elsewhere = Vec::new();
        for (p, t) in self.policies.iter().zip(&self.texts) {
            if part.is_some_and(|part| !p.class.applies_to(part)) {
                continue;
            }
            if words.iter().all(|w| t.contains(w)) {
                let label = normalize(&p.label);
                if words.iter().all(|w| label.contains(w)) {
                    in_label.push(p);
                } else {
                    elsewhere.push(p);
                }
            }
        }
        in_label.sort_by_cached_key(|p| fold(&p.label));
        elsewhere.sort_by_cached_key(|p| fold(&p.label));
        in_label.extend(elsewhere);
        if let Some(limit) = limit {
            in_label.truncate(limit);
        }
        in_label
    }
}

/// Lower case for sorting (`str.casefold`).
pub fn fold(text: &str) -> String {
    text.to_lowercase().replace('ß', "ss")
}

/// Lower case without accents or ligatures (« Œuvre » → « oeuvre »), for the search
/// (`normaliser`).
pub fn normalize(text: &str) -> String {
    fold(text)
        .nfkd()
        .filter(|c| !unicode_normalization::char::is_combining_mark(*c))
        .collect::<String>()
        .replace('œ', "oe")
        .replace('æ', "ae")
}

// --- Languages ----------------------------------------------------------------------------

pub const FALLBACK_LANGUAGE: &str = "en-US";

/// Languages of the user in the form of the ADML folders (`fr-FR`), from `LANGUAGE`,
/// `LC_ALL`, `LC_MESSAGES` then `LANG`; `en-US` last (`langues_preferees`).
pub fn preferred_languages(env: &dyn Fn(&str) -> Option<String>) -> Vec<String> {
    let mut raw: Vec<String> = Vec::new();
    if let Some(v) = env("LANGUAGE").filter(|v| !v.is_empty()) {
        raw.extend(v.split(':').map(str::to_owned));
    }
    for name in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Some(v) = env(name).filter(|v| !v.is_empty()) {
            raw.push(v);
            break;
        }
    }
    let mut languages: Vec<String> = Vec::new();
    for r in raw {
        let base = r.split('.').next().unwrap_or_default();
        let base = base.split('@').next().unwrap_or_default();
        if base.is_empty() || base == "C" || base == "POSIX" {
            continue;
        }
        let base = base.replace('_', "-");
        let (language, country) = base.split_once('-').unwrap_or((&base, ""));
        let form = if country.is_empty() {
            language.to_lowercase()
        } else {
            format!("{}-{}", language.to_lowercase(), country.to_uppercase())
        };
        if !languages.contains(&form) {
            languages.push(form);
        }
    }
    if !languages.iter().any(|l| l == FALLBACK_LANGUAGE) {
        languages.push(FALLBACK_LANGUAGE.to_owned());
    }
    languages
}

/// The language folder to read among `available`: the first preferred present (case ignored;
/// `fr` stands for `fr-FR`, `fr-CA`…), then `en-US`, then the first folder. `None` if there
/// is none (`choisir_langue`).
pub fn choose_language(available: &[String], preferred: &[String]) -> Option<String> {
    let mut sorted: Vec<&String> = available.iter().collect();
    sorted.sort_by_key(|d| d.to_lowercase());
    let fallback = FALLBACK_LANGUAGE.to_owned();
    for p in preferred.iter().chain(std::iter::once(&fallback)) {
        let lower = p.to_lowercase();
        if let Some(d) = sorted.iter().find(|d| d.to_lowercase() == lower) {
            return Some((*d).clone());
        }
        if !p.contains('-') {
            let prefix = format!("{lower}-");
            if let Some(d) = sorted
                .iter()
                .find(|d| d.to_lowercase().starts_with(&prefix))
            {
                return Some((*d).clone());
            }
        }
    }
    sorted.first().map(|d| (*d).clone())
}

// --- Analysis -----------------------------------------------------------------------------

/// Decodes the bytes of a file (UTF-16 by its byte-order mark, UTF-8 otherwise) and parses it;
/// some ADMLs of Microsoft, in UTF-16, declare `encoding="unicode"`, which does not matter here.
fn parse(bytes: &[u8], file: &str) -> Result<Node, String> {
    let text = match bytes {
        [0xff, 0xfe, rest @ ..] => utf16(rest, u16::from_le_bytes),
        [0xfe, 0xff, rest @ ..] => utf16(rest, u16::from_be_bytes),
        [0xef, 0xbb, 0xbf, rest @ ..] => {
            String::from_utf8(rest.to_vec()).map_err(|e| e.to_string())
        }
        _ => String::from_utf8(bytes.to_vec()).map_err(|e| e.to_string()),
    }
    .map_err(|e| unreadable(file, &e))?;
    Node::parse(&text).map_err(|e| unreadable(file, &e.to_string()))
}

fn unreadable(file: &str, error: &str) -> String {
    format!("{file}: unreadable XML ({error}).")
}

fn utf16(bytes: &[u8], unit: fn([u8; 2]) -> u16) -> Result<String, String> {
    let units = bytes.chunks_exact(2).map(|p| {
        unit([
            p.first().copied().unwrap_or(0),
            p.get(1).copied().unwrap_or(0),
        ])
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|e| e.to_string())
}

fn local(tag: &str) -> &str {
    tag.rsplit('}').next().unwrap_or(tag)
}

fn child<'a>(e: &'a Node, name: &str) -> Option<&'a Node> {
    e.children.iter().find(|c| local(&c.tag) == name)
}

fn all<'a>(e: Option<&'a Node>, name: &'a str) -> impl Iterator<Item = &'a Node> + 'a {
    e.into_iter()
        .flat_map(|e| e.children.iter())
        .filter(move |c| local(&c.tag) == name)
}

fn yes(value: Option<&str>) -> bool {
    value
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("true")
}

fn integer(value: Option<&str>, default: i128) -> i128 {
    value
        .unwrap_or_default()
        .trim()
        .parse::<i128>()
        .unwrap_or(default)
}

/// The identifier of a reference `$(string.ID)` or `$(presentation.ID)`.
fn reference(text: &str) -> Option<&str> {
    let inner = text.strip_prefix("$(")?.strip_suffix(')')?;
    let id = inner
        .strip_prefix("string.")
        .or_else(|| inner.strip_prefix("presentation."))?;
    (!id.contains(')')).then_some(id)
}

/// The content of an ADML: texts and presentations by identifier (`Ressources`).
#[derive(Debug, Clone, Default)]
pub struct Resources {
    pub texts: HashMap<String, String>,
    pub presentations: HashMap<String, Vec<Control>>,
}

impl Resources {
    /// `$(string.ID)` resolved; the identifier itself if missing; the text as is if it is not
    /// a reference.
    pub fn text(&self, r: Option<&str>) -> String {
        let Some(r) = r.filter(|r| !r.is_empty()) else {
            return String::new();
        };
        match reference(r.trim()) {
            None => r.to_owned(),
            Some(id) => self.texts.get(id).cloned().unwrap_or_else(|| id.to_owned()),
        }
    }
}

pub fn read_adml(bytes: &[u8], file: &str) -> Result<Resources, String> {
    let root = parse(bytes, file)?;
    let resources = child(&root, "resources");
    let mut r = Resources::default();
    for s in all(resources.and_then(|x| child(x, "stringTable")), "string") {
        r.texts
            .insert(s.get_or("id", "").to_owned(), s.text.clone());
    }
    for p in all(
        resources.and_then(|x| child(x, "presentationTable")),
        "presentation",
    ) {
        r.presentations.insert(
            p.get_or("id", "").to_owned(),
            p.children.iter().map(control).collect(),
        );
    }
    Ok(r)
}

fn control(c: &Node) -> Control {
    let Some(kind) = ControlKind::of(local(&c.tag)).filter(|k| *k != ControlKind::Static) else {
        return Control::new(ControlKind::Static, "", c.all_text().trim(), None);
    };
    let ref_id = c.get_or("refId", "");
    if matches!(kind, ControlKind::Text | ControlKind::ComboBox) {
        let label = child(c, "label")
            .map(|l| l.text.trim().to_owned())
            .unwrap_or_default();
        let default_tag = if kind == ControlKind::Text {
            "defaultValue"
        } else {
            "default"
        };
        let mut control = Control::new(
            kind,
            ref_id,
            &label,
            child(c, default_tag).map(|d| d.text.clone()),
        );
        control.suggestions = all(Some(c), "suggestion").map(|s| s.text.clone()).collect();
        control.sort = !yes(c.get("noSort"));
        return control;
    }
    let text = c.text.trim();
    match kind {
        ControlKind::CheckBox => Control::new(
            kind,
            ref_id,
            text,
            c.get("defaultChecked").map(str::to_owned),
        ),
        ControlKind::Decimal | ControlKind::LongDecimal => {
            let mut control =
                Control::new(kind, ref_id, text, c.get("defaultValue").map(str::to_owned));
            control.step = integer(c.get("spinStep"), 1);
            control
        }
        ControlKind::DropdownList => {
            let mut control =
                Control::new(kind, ref_id, text, c.get("defaultItem").map(str::to_owned));
            control.sort = !yes(c.get("noSort"));
            control
        }
        _ => Control::new(kind, ref_id, text, None),
    }
}

/// An ADMX being assembled (`_Fichier`).
struct File {
    name: String,
    namespace: String,
    prefixes: HashMap<String, String>,
    root: Node,
    resources: Resources,
}

impl File {
    /// `prefix:name` → `namespace:name`; without prefix, the namespace of the file.
    fn qualify(&self, r: &str) -> String {
        match r.split_once(':') {
            None => format!("{}:{r}", self.namespace),
            Some((prefix, name)) => format!(
                "{}:{name}",
                self.prefixes.get(prefix).map_or(prefix, String::as_str)
            ),
        }
    }
}

fn header(bytes: &[u8], name: &str, resources: Resources) -> Result<File, String> {
    let root = parse(bytes, name)?;
    if local(&root.tag) != "policyDefinitions" {
        return Err(format!("{name}: not an ADMX file."));
    }
    let spaces = child(&root, "policyNamespaces");
    let target = spaces.and_then(|s| child(s, "target"));
    let Some(target) = target.filter(|t| t.get("namespace").is_some_and(|n| !n.is_empty())) else {
        return Err(format!("{name}: no namespace."));
    };
    let namespace = target.get_or("namespace", "").to_owned();
    let mut prefixes = HashMap::from([(target.get_or("prefix", "").to_owned(), namespace.clone())]);
    for u in all(spaces, "using") {
        prefixes.insert(
            u.get_or("prefix", "").to_owned(),
            u.get_or("namespace", "").to_owned(),
        );
    }
    Ok(File {
        name: name.to_owned(),
        namespace,
        prefixes,
        root,
        resources,
    })
}

/// The first child of `<value>`, `<enabledValue>`…; `None` if absent (`_valeur`).
fn value(e: Option<&Node>) -> Option<AdmxValue> {
    for f in &e?.children {
        match local(&f.tag) {
            "decimal" => return Some(AdmxValue::Decimal(integer(f.get("value"), 0))),
            "longDecimal" => return Some(AdmxValue::Long(integer(f.get("value"), 0))),
            "string" => return Some(AdmxValue::String(f.text.clone())),
            "delete" => return Some(AdmxValue::Delete),
            _ => {}
        }
    }
    None
}

fn list(e: Option<&Node>, key: &str) -> Vec<ListItem> {
    let Some(e) = e else { return Vec::new() };
    let default = e.get("defaultKey").filter(|k| !k.is_empty()).unwrap_or(key);
    all(Some(e), "item")
        .filter_map(|i| {
            value(child(i, "value")).map(|v| ListItem {
                key: i
                    .get("key")
                    .filter(|k| !k.is_empty())
                    .unwrap_or(default)
                    .to_owned(),
                value_name: i.get_or("valueName", "").to_owned(),
                value: v,
            })
        })
        .collect()
}

fn element(e: &Node, policy_key: &str, f: &File) -> Option<Element> {
    let kind = ElementKind::of(local(&e.tag))?;
    let key = e.get("key").filter(|k| !k.is_empty()).unwrap_or(policy_key);
    let mut out = Element::new(kind, e.get_or("id", ""), key);
    out.value_name = e.get_or("valueName", "").to_owned();
    out.required = yes(e.get("required"));
    out.soft = yes(e.get("soft"));
    match kind {
        ElementKind::Decimal | ElementKind::Long => {
            out.minimum = integer(e.get("minValue"), 0);
            out.maximum = integer(e.get("maxValue"), 9999);
            out.as_text = yes(e.get("storeAsText"));
        }
        ElementKind::Text | ElementKind::MultiText => {
            out.max_length = integer(e.get("maxLength"), 1023);
            out.expandable = yes(e.get("expandable"));
            out.max_strings = integer(e.get("maxStrings"), 0);
        }
        ElementKind::Boolean => {
            out.true_value = value(child(e, "trueValue"));
            out.false_value = value(child(e, "falseValue"));
            out.true_list = list(child(e, "trueList"), key);
            out.false_list = list(child(e, "falseList"), key);
        }
        ElementKind::Enum => {
            out.choices = all(Some(e), "item")
                .map(|i| Choice {
                    label: f.resources.text(i.get("displayName")),
                    value: value(child(i, "value")),
                    list: list(child(i, "valueList"), key),
                })
                .collect();
        }
        ElementKind::List => {
            out.prefix = e
                .get("valuePrefix")
                .filter(|p| !p.is_empty())
                .map(str::to_owned);
            out.additive = yes(e.get("additive"));
            out.explicit = yes(e.get("explicitValue"));
            out.expandable = yes(e.get("expandable"));
        }
    }
    Some(out)
}

fn presentation(r: Option<&str>, resources: &Resources) -> Vec<Control> {
    let Some(r) = r.filter(|r| !r.is_empty()) else {
        return Vec::new();
    };
    let id = reference(r.trim()).unwrap_or(r);
    resources.presentations.get(id).cloned().unwrap_or_default()
}

/// A file of the store: name of the ADMX, its bytes, those of its ADML.
pub type TemplateFile = (String, Vec<u8>, Option<Vec<u8>>);

/// Store of the files `name.admx` → (bytes of the ADMX, bytes of the ADML or `None`). The
/// references between files (category parents, « supported on ») are resolved once all is
/// read; a parent not found puts the category at the root (`analyser`).
pub fn analyze(files: &[TemplateFile], language: &str) -> Store {
    let mut errors: Vec<String> = Vec::new();
    let mut read: Vec<File> = Vec::new();
    let mut sorted: Vec<&TemplateFile> = files.iter().collect();
    sorted.sort_by_key(|(name, _, _)| name.to_lowercase());
    for (name, admx, adml) in sorted {
        let resources = match adml {
            Some(bytes) => read_adml(bytes, name).unwrap_or_else(|e| {
                errors.push(e);
                Resources::default()
            }),
            None => Resources::default(),
        };
        if adml.is_none() {
            errors.push(format!("{name}: no ADML file, texts missing."));
        }
        match header(admx, name, resources) {
            Ok(f) => read.push(f),
            Err(e) => errors.push(e),
        }
    }

    // « Supported on »: definitions of every file (Windows.admx above all).
    let mut supported: HashMap<String, String> = HashMap::new();
    for f in &read {
        let definitions = child(&f.root, "supportedOn").and_then(|s| child(s, "definitions"));
        for d in all(definitions, "definition") {
            supported.insert(
                format!("{}:{}", f.namespace, d.get_or("name", "")),
                f.resources.text(d.get("displayName")),
            );
        }
    }

    let mut categories: Vec<Category> = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for f in &read {
        for c in all(child(&f.root, "categories"), "category") {
            let name = c.get_or("name", "");
            let ident = format!("{}:{name}", f.namespace);
            let label = f.resources.text(c.get("displayName"));
            let category = Category {
                ident: ident.clone(),
                name: name.to_owned(),
                label: if label.is_empty() {
                    name.to_owned()
                } else {
                    label
                },
                explain: f.resources.text(c.get("explainText")),
                parent: child(c, "parentCategory").map(|p| f.qualify(p.get_or("ref", ""))),
                file: f.name.clone(),
            };
            match index.get(&ident).and_then(|&i| categories.get_mut(i)) {
                Some(old) => *old = category,
                None => {
                    index.insert(ident, categories.len());
                    categories.push(category);
                }
            }
        }
    }
    // Parent missing from the store: at the root.
    let known: HashSet<String> = categories.iter().map(|c| c.ident.clone()).collect();
    for c in &mut categories {
        if c.parent.as_ref().is_some_and(|p| !known.contains(p)) {
            c.parent = None;
        }
    }

    let mut policies: Vec<Policy> = Vec::new();
    let mut pindex: HashMap<String, usize> = HashMap::new();
    for f in &read {
        for p in all(child(&f.root, "policies"), "policy") {
            match policy(p, f, &supported, &known) {
                Err(e) => errors.push(format!("{}: {e}", f.name)),
                Ok(s) => match pindex.get(&s.ident).and_then(|&i| policies.get_mut(i)) {
                    Some(old) => *old = s,
                    None => {
                        pindex.insert(s.ident.clone(), policies.len());
                        policies.push(s);
                    }
                },
            }
        }
    }
    Store::new(categories, policies, language, read.len(), errors)
}

fn policy(
    p: &Node,
    f: &File,
    supported: &HashMap<String, String>,
    categories: &HashSet<String>,
) -> Result<Policy, String> {
    let name = p.get_or("name", "");
    let class = Class::of(p.get_or("class", ""))
        .ok_or_else(|| format!("policy {name}: unknown class “{}”.", p.get_or("class", "")))?;
    let key = p.get_or("key", "");
    let category = child(p, "parentCategory")
        .map(|c| f.qualify(c.get_or("ref", "")))
        .filter(|c| categories.contains(c));
    let support = child(p, "supportedOn").map_or_else(String::new, |s| {
        let r = s.get_or("ref", "");
        supported
            .get(&f.qualify(r))
            .cloned()
            .unwrap_or_else(|| r.to_owned())
    });
    let elements = child(p, "elements")
        .map(|e| {
            e.children
                .iter()
                .filter_map(|x| element(x, key, f))
                .collect()
        })
        .unwrap_or_default();
    let label = f.resources.text(p.get("displayName"));
    Ok(Policy {
        ident: format!("{}:{name}", f.namespace),
        name: name.to_owned(),
        class,
        label: if label.is_empty() {
            name.to_owned()
        } else {
            label
        },
        explain: f.resources.text(p.get("explainText")),
        category,
        supported: support,
        key: key.to_owned(),
        value_name: p.get_or("valueName", "").to_owned(),
        enabled_value: value(child(p, "enabledValue")),
        disabled_value: value(child(p, "disabledValue")),
        enabled_list: list(child(p, "enabledList"), key),
        disabled_list: list(child(p, "disabledList"), key),
        elements,
        presentation: presentation(p.get("presentation"), &f.resources),
        file: f.name.clone(),
    })
}

// --- JSON form (local cache), the same as the Python application ------------------------------

/// Version of the JSON form; a cache of another version is ignored.
pub const FORMAT: i64 = 1;

fn number(n: i128) -> Json {
    i64::try_from(n)
        .map(Json::from)
        .or_else(|_| u64::try_from(n).map(Json::from))
        .unwrap_or(Json::Null)
}

fn read_number(v: &Json) -> Option<i128> {
    v.as_i64()
        .map(i128::from)
        .or_else(|| v.as_u64().map(i128::from))
}

fn value_json(v: Option<&AdmxValue>) -> Json {
    match v {
        None => Json::Null,
        Some(v) => {
            let data = match v {
                AdmxValue::Decimal(n) | AdmxValue::Long(n) => number(*n),
                AdmxValue::String(s) => Json::from(s.as_str()),
                AdmxValue::Delete => Json::Null,
            };
            json!([v.kind(), data])
        }
    }
}

fn value_read(d: &Json) -> Result<Option<AdmxValue>, String> {
    if d.is_null() {
        return Ok(None);
    }
    let kind = d.get(0).and_then(Json::as_str).ok_or("value")?;
    let data = d.get(1).ok_or("value")?;
    Ok(Some(match kind {
        "decimal" => AdmxValue::Decimal(read_number(data).unwrap_or(0)),
        "longDecimal" => AdmxValue::Long(read_number(data).unwrap_or(0)),
        "string" => AdmxValue::String(data.as_str().unwrap_or_default().to_owned()),
        "delete" => AdmxValue::Delete,
        other => return Err(format!("value kind {other}")),
    }))
}

fn items_json(items: &[ListItem]) -> Json {
    Json::Array(
        items
            .iter()
            .map(|i| json!([i.key, i.value_name, value_json(Some(&i.value))]))
            .collect(),
    )
}

fn items_read(d: &Json) -> Result<Vec<ListItem>, String> {
    let mut out = Vec::new();
    for x in d.as_array().ok_or("items")? {
        if let Some(v) = value_read(x.get(2).ok_or("item")?)? {
            out.push(ListItem {
                key: text(x.get(0))?,
                value_name: text(x.get(1))?,
                value: v,
            });
        }
    }
    Ok(out)
}

fn text(v: Option<&Json>) -> Result<String, String> {
    v.and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "text expected".to_owned())
}

fn optional_text(v: Option<&Json>) -> Result<Option<String>, String> {
    match v {
        Some(Json::Null) => Ok(None),
        v => text(v).map(Some),
    }
}

fn element_json(e: &Element) -> Json {
    let mut d = Map::new();
    d.insert("genre".into(), e.kind.value().into());
    d.insert("id".into(), e.id.clone().into());
    d.insert("cle".into(), e.key.clone().into());
    let default = Element::new(e.kind, &e.id, &e.key);
    // Only what differs from the default, in the order of the fields of the Python class.
    if e.value_name != default.value_name {
        d.insert("nom_valeur".into(), e.value_name.clone().into());
    }
    if e.required {
        d.insert("requis".into(), true.into());
    }
    for (name, v, dv) in [
        ("minimum", e.minimum, default.minimum),
        ("maximum", e.maximum, default.maximum),
    ] {
        if v != dv {
            d.insert(name.into(), number(v));
        }
    }
    for (name, v, dv) in [
        ("en_texte", e.as_text, default.as_text),
        ("souple", e.soft, default.soft),
    ] {
        if v != dv {
            d.insert(name.into(), v.into());
        }
    }
    if e.max_length != default.max_length {
        d.insert("longueur_max".into(), number(e.max_length));
    }
    if e.expandable != default.expandable {
        d.insert("extensible".into(), e.expandable.into());
    }
    if e.max_strings != default.max_strings {
        d.insert("chaines_max".into(), number(e.max_strings));
    }
    if e.true_value.is_some() {
        d.insert("vrai".into(), value_json(e.true_value.as_ref()));
    }
    if e.false_value.is_some() {
        d.insert("faux".into(), value_json(e.false_value.as_ref()));
    }
    if !e.true_list.is_empty() {
        d.insert("liste_vrai".into(), items_json(&e.true_list));
    }
    if !e.false_list.is_empty() {
        d.insert("liste_faux".into(), items_json(&e.false_list));
    }
    if !e.choices.is_empty() {
        d.insert(
            "choix".into(),
            Json::Array(
                e.choices
                    .iter()
                    .map(|c| json!([c.label, value_json(c.value.as_ref()), items_json(&c.list)]))
                    .collect(),
            ),
        );
    }
    if let Some(p) = &e.prefix {
        d.insert("prefixe".into(), p.clone().into());
    }
    if e.additive {
        d.insert("additif".into(), true.into());
    }
    if e.explicit {
        d.insert("explicite".into(), true.into());
    }
    Json::Object(d)
}

fn element_read(d: &Json) -> Result<Element, String> {
    let kind = ElementKind::of(d.get("genre").and_then(Json::as_str).unwrap_or_default())
        .ok_or("element kind")?;
    let mut e = Element::new(kind, &text(d.get("id"))?, &text(d.get("cle"))?);
    let o = d.as_object().ok_or("element")?;
    for (name, v) in o {
        let boolean = || {
            v.as_bool()
                .ok_or_else(|| format!("{name}: boolean expected"))
        };
        let n = || read_number(v).ok_or_else(|| format!("{name}: integer expected"));
        match name.as_str() {
            "genre" | "id" | "cle" => {}
            "nom_valeur" => e.value_name = text(Some(v))?,
            "requis" => e.required = boolean()?,
            "minimum" => e.minimum = n()?,
            "maximum" => e.maximum = n()?,
            "en_texte" => e.as_text = boolean()?,
            "souple" => e.soft = boolean()?,
            "longueur_max" => e.max_length = n()?,
            "extensible" => e.expandable = boolean()?,
            "chaines_max" => e.max_strings = n()?,
            "vrai" => e.true_value = value_read(v)?,
            "faux" => e.false_value = value_read(v)?,
            "liste_vrai" => e.true_list = items_read(v)?,
            "liste_faux" => e.false_list = items_read(v)?,
            "choix" => {
                e.choices = v
                    .as_array()
                    .ok_or("choices")?
                    .iter()
                    .map(|c| {
                        Ok(Choice {
                            label: text(c.get(0))?,
                            value: value_read(c.get(1).ok_or("choice")?)?,
                            list: items_read(c.get(2).ok_or("choice")?)?,
                        })
                    })
                    .collect::<Result<_, String>>()?;
            }
            "prefixe" => e.prefix = optional_text(Some(v))?,
            "additif" => e.additive = boolean()?,
            "explicite" => e.explicit = boolean()?,
            other => return Err(format!("unknown field {other}")),
        }
    }
    Ok(e)
}

fn control_json(c: &Control) -> Json {
    json!([
        c.kind.value(),
        c.ref_id,
        c.label,
        c.default,
        c.suggestions,
        c.sort,
        number(c.step)
    ])
}

fn control_read(d: &Json) -> Result<Control, String> {
    let kind = ControlKind::of(d.get(0).and_then(Json::as_str).unwrap_or_default())
        .ok_or("control kind")?;
    Ok(Control {
        kind,
        ref_id: text(d.get(1))?,
        label: text(d.get(2))?,
        default: optional_text(d.get(3))?,
        suggestions: d
            .get(4)
            .and_then(Json::as_array)
            .ok_or("suggestions")?
            .iter()
            .map(|s| text(Some(s)))
            .collect::<Result<_, _>>()?,
        sort: d.get(5).and_then(Json::as_bool).ok_or("sort")?,
        step: d.get(6).and_then(read_number).ok_or("step")?,
    })
}

/// The JSON form of the store (`vers_json`).
pub fn to_json(m: &Store) -> Json {
    json!({
        "format": FORMAT,
        "langue": m.language,
        "fichiers": m.files,
        "erreurs": m.errors,
        "categories": m.categories.iter().map(|c| json!([c.ident, c.name, c.label, c.explain, c.parent, c.file])).collect::<Vec<_>>(),
        "strategies": m.policies.iter().map(|s| json!({
            "ident": s.ident,
            "nom": s.name,
            "classe": s.class.value(),
            "libelle": s.label,
            "explication": s.explain,
            "categorie": s.category,
            "prise_en_charge": s.supported,
            "cle": s.key,
            "nom_valeur": s.value_name,
            "active": value_json(s.enabled_value.as_ref()),
            "desactivee": value_json(s.disabled_value.as_ref()),
            "liste_active": items_json(&s.enabled_list),
            "liste_desactivee": items_json(&s.disabled_list),
            "elements": s.elements.iter().map(element_json).collect::<Vec<_>>(),
            "presentation": s.presentation.iter().map(control_json).collect::<Vec<_>>(),
            "fichier": s.file,
        })).collect::<Vec<_>>(),
    })
}

/// The store from its JSON form; an error if the form is not that of this version
/// (`depuis_json`).
pub fn from_json(d: &Json) -> Result<Store, String> {
    if d.get("format").and_then(Json::as_i64) != Some(FORMAT) {
        return Err("cache of the templates of another version".into());
    }
    let mut categories = Vec::new();
    for c in d
        .get("categories")
        .and_then(Json::as_array)
        .ok_or("categories")?
    {
        categories.push(Category {
            ident: text(c.get(0))?,
            name: text(c.get(1))?,
            label: text(c.get(2))?,
            explain: text(c.get(3))?,
            parent: optional_text(c.get(4))?,
            file: text(c.get(5))?,
        });
    }
    let mut policies = Vec::new();
    for s in d
        .get("strategies")
        .and_then(Json::as_array)
        .ok_or("policies")?
    {
        policies.push(Policy {
            ident: text(s.get("ident"))?,
            name: text(s.get("nom"))?,
            class: Class::of(&text(s.get("classe"))?).ok_or("class")?,
            label: text(s.get("libelle"))?,
            explain: text(s.get("explication"))?,
            category: optional_text(s.get("categorie"))?,
            supported: text(s.get("prise_en_charge"))?,
            key: text(s.get("cle"))?,
            value_name: text(s.get("nom_valeur"))?,
            enabled_value: value_read(s.get("active").ok_or("active")?)?,
            disabled_value: value_read(s.get("desactivee").ok_or("desactivee")?)?,
            enabled_list: items_read(s.get("liste_active").ok_or("liste_active")?)?,
            disabled_list: items_read(s.get("liste_desactivee").ok_or("liste_desactivee")?)?,
            elements: s
                .get("elements")
                .and_then(Json::as_array)
                .ok_or("elements")?
                .iter()
                .map(element_read)
                .collect::<Result<_, _>>()?,
            presentation: s
                .get("presentation")
                .and_then(Json::as_array)
                .ok_or("presentation")?
                .iter()
                .map(control_read)
                .collect::<Result<_, _>>()?,
            file: text(s.get("fichier"))?,
        });
    }
    let errors = d
        .get("erreurs")
        .and_then(Json::as_array)
        .map(|e| {
            e.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(Store::new(
        categories,
        policies,
        d.get("langue").and_then(Json::as_str).unwrap_or_default(),
        d.get("fichiers")
            .and_then(Json::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(0),
        errors,
    ))
}

#[cfg(test)]
pub(crate) mod tests;

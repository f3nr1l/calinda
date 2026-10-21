// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Administrative templates in the GPO editor (J7.3, `annuaire.vue.modeles`), without GTK: tree
//! of the categories, rows of the list of policies, texts of state and options, lines in clear
//! of the preview, raw entries of a `Registry.pol` and their input.

use std::collections::{BTreeMap, HashMap};

use annuaire_codecs::registry_pol::{self as rp, Entry, RegValue, Special};
use annuaire_core::admx::{Class, Element, ElementKind, Policy, Store};
use annuaire_core::gpo::Part;
use annuaire_core::policies::{self as pol, OptionValue, Setting, State};

use crate::gpo_editor_views::{Anchor, EditorNode, NodeData, anchor_key, part_label, part_value};
use crate::i18n::{fill, tr, tr_ctx};

pub const SECTION: &str = "admx";

pub fn class_of(part: Part) -> Class {
    match part {
        Part::Computer => Class::Machine,
        Part::User => Class::User,
    }
}

pub fn hive(part: Part) -> &'static str {
    match part {
        Part::Computer => "HKLM",
        Part::User => "HKCU",
    }
}

/// As the GPMC: a « setting » is enabled, disabled or not configured (`libelle_etat`).
pub fn state_label(state: State) -> String {
    match state {
        State::NotConfigured => tr("Not Configured"),
        State::Enabled => tr("Enabled"),
        State::Disabled => tr("Disabled"),
        State::Undetermined => tr("Configured (unrecognized values)"),
    }
}

// --- Tree ---------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewKind {
    Root,
    Category,
    All,
    Extra,
    Raw,
}

/// What a node of the section designates: a category, the root of the templates (category
/// `None`), « All Settings », the extra settings or the raw registry (`Vue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateView {
    pub part: Part,
    pub kind: ViewKind,
    pub category: Option<String>,
}

impl TemplateView {
    pub fn new(part: Part, kind: ViewKind) -> Self {
        Self {
            part,
            kind,
            category: None,
        }
    }
}

fn contains(store: &Store, class: Class, ident: &str, memo: &mut HashMap<String, bool>) -> bool {
    if let Some(&known) = memo.get(ident) {
        return known;
    }
    memo.insert(ident.to_owned(), false); // a cycle answers « no »
    let found = !store.policies_of(Some(ident), Some(class)).is_empty()
        || store
            .subcategories(Some(ident), None)
            .iter()
            .any(|c| contains(store, class, &c.ident, memo));
    memo.insert(ident.to_owned(), found);
    found
}

fn category_node(
    store: &Store,
    class: Class,
    part: Part,
    ident: &str,
    title: &str,
    memo: &mut HashMap<String, bool>,
    depth: usize,
) -> EditorNode {
    let mut children = Vec::new();
    if depth < 64 {
        for c in store.subcategories(Some(ident), None) {
            if contains(store, class, &c.ident, memo) {
                children.push(category_node(
                    store,
                    class,
                    part,
                    &c.ident,
                    &c.label,
                    memo,
                    depth + 1,
                ));
            }
        }
    }
    EditorNode::new(format!("{SECTION}:{}:{ident}", part_value(part)), title)
        .section(SECTION)
        .children(children)
        .data(NodeData::Templates(TemplateView {
            part,
            kind: ViewKind::Category,
            category: Some(ident.to_owned()),
        }))
}

/// The « Administrative Templates » node of the part and its children: the categories holding
/// policies of the part, « All Settings », « Extra Registry Settings » (if the `Registry.pol`
/// has some) and the raw registry. Without a store (absent, or not read yet): the raw registry
/// only (`noeuds`).
pub fn nodes(store: Option<&Store>, part: Part, extra: bool) -> Vec<(Anchor, Vec<EditorNode>)> {
    let p = part_value(part);
    let mut children = Vec::new();
    if let Some(store) = store {
        let class = class_of(part);
        let mut memo = HashMap::new();
        for c in store.subcategories(None, None) {
            if contains(store, class, &c.ident, &mut memo) {
                children.push(category_node(
                    store, class, part, &c.ident, &c.label, &mut memo, 0,
                ));
            }
        }
        children.push(
            EditorNode::new(format!("{SECTION}:{p}:tous"), tr("All Settings"))
                .section(SECTION)
                .icon("view-list-symbolic")
                .data(NodeData::Templates(TemplateView::new(part, ViewKind::All))),
        );
        if extra {
            children.push(
                EditorNode::new(
                    format!("{SECTION}:{p}:supplementaires"),
                    tr("Extra Registry Settings"),
                )
                .section(SECTION)
                .icon("dialog-question-symbolic")
                .data(NodeData::Templates(TemplateView::new(
                    part,
                    ViewKind::Extra,
                ))),
            );
        }
    }
    children.push(
        EditorNode::new(format!("{SECTION}:{p}:brut"), tr("Registry (raw)"))
            .section(SECTION)
            .icon("text-x-generic-symbolic")
            .data(NodeData::Templates(TemplateView::new(part, ViewKind::Raw))),
    );
    let root = EditorNode::new(
        anchor_key(part, Anchor::Templates),
        Anchor::Templates.title(),
    )
    .section(SECTION)
    .children(children)
    .data(NodeData::Templates(TemplateView::new(part, ViewKind::Root)));
    vec![(Anchor::Templates, vec![root])]
}

// --- Rows of the list ---------------------------------------------------------------------

/// A row of the list of policies (or a subcategory, first) (`Ligne`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub title: String,
    pub subtitle: String,
    pub icon: &'static str,
    pub policy: Option<String>,
    pub category: Option<String>,
    pub changed: bool,
    pub state: State,
}

impl Row {
    pub fn accessible(&self) -> String {
        if self.policy.is_none() {
            return fill(&tr("Folder {nom}"), &[("nom", &self.title)]);
        }
        let mut text = format!("{}, {}", self.title, self.subtitle);
        if self.changed {
            text.push_str(&tr_ctx("feminine", ", changed"));
        }
        text
    }
}

fn state_icon(state: State) -> &'static str {
    match state {
        State::NotConfigured => "document-properties-symbolic",
        State::Enabled => "object-select-symbolic",
        State::Disabled => "action-unavailable-symbolic",
        State::Undetermined => "dialog-question-symbolic",
    }
}

/// State of each policy of a part: read in the file, or that of the draft (`Etats`).
#[derive(Debug, Clone, Default)]
pub struct States {
    pub read: HashMap<String, Setting>,
    /// In the order the draft was made.
    pub draft: Vec<(String, Setting)>,
}

impl States {
    pub fn setting(&self, ident: &str) -> Setting {
        if let Some((_, s)) = self.draft.iter().find(|(i, _)| i == ident) {
            return s.clone();
        }
        self.read
            .get(ident)
            .cloned()
            .unwrap_or_else(|| Setting::new(State::NotConfigured))
    }

    pub fn in_draft(&self, ident: &str) -> bool {
        self.draft.iter().any(|(i, _)| i == ident)
    }

    /// Puts a setting in the draft (or takes it out if it comes back to what is read)
    /// (`regler`).
    pub fn set(&mut self, ident: &str, setting: Setting) {
        let read = self
            .read
            .get(ident)
            .cloned()
            .unwrap_or_else(|| Setting::new(State::NotConfigured));
        if setting == read {
            self.draft.retain(|(i, _)| i != ident);
        } else if let Some(slot) = self.draft.iter_mut().find(|(i, _)| i == ident) {
            slot.1 = setting;
        } else {
            self.draft.push((ident.to_owned(), setting));
        }
    }
}

pub fn policy_row(s: &Policy, states: &States, store: Option<&Store>, path: bool) -> Row {
    let setting = states.setting(&s.ident);
    let mut subtitle = state_label(setting.state);
    if let (true, Some(store)) = (path, store) {
        let folders: Vec<&str> = store
            .path(s.category.as_deref())
            .iter()
            .map(|c| c.label.as_str())
            .collect();
        if !folders.is_empty() {
            subtitle = format!("{subtitle} · {}", folders.join(" › "));
        }
    }
    Row {
        title: s.label.clone(),
        subtitle,
        icon: state_icon(setting.state),
        policy: Some(s.ident.clone()),
        category: None,
        changed: states.in_draft(&s.ident),
        state: setting.state,
    }
}

pub const LIMIT: usize = 2000;

/// What the list shows for `view`: the subcategories then the policies of the category; with a
/// search, the policies of the whole part matching it (path of category in the subtitle);
/// « configured only » keeps those that are not « not configured » (draft included) (`lignes`).
pub fn rows(
    store: &Store,
    part: Part,
    view: &TemplateView,
    states: &States,
    search: &str,
    configured: bool,
) -> Vec<Row> {
    let class = class_of(part);
    let keep = |s: &Policy| !configured || states.setting(&s.ident).state != State::NotConfigured;
    if !search.trim().is_empty() {
        return store
            .search(search, Some(class), None)
            .into_iter()
            .filter(|s| keep(s))
            .map(|s| policy_row(s, states, Some(store), true))
            .take(LIMIT)
            .collect();
    }
    if matches!(view.kind, ViewKind::All | ViewKind::Root)
        && (configured || view.kind == ViewKind::All)
    {
        let mut all: Vec<&Policy> = store
            .policies
            .iter()
            .filter(|s| s.class.applies_to(class) && keep(s))
            .collect();
        all.sort_by_cached_key(|s| annuaire_core::admx::fold(&s.label));
        return all
            .into_iter()
            .map(|s| policy_row(s, states, Some(store), true))
            .take(LIMIT)
            .collect();
    }
    let mut out = Vec::new();
    if !configured {
        out.extend(
            store
                .subcategories(view.category.as_deref(), Some(class))
                .iter()
                .map(|c| Row {
                    title: c.label.clone(),
                    subtitle: String::new(),
                    icon: "folder-symbolic",
                    policy: None,
                    category: Some(c.ident.clone()),
                    changed: false,
                    state: State::NotConfigured,
                }),
        );
    }
    out.extend(
        store
            .policies_of(view.category.as_deref(), Some(class))
            .into_iter()
            .filter(|s| keep(s))
            .map(|s| policy_row(s, states, None, false)),
    );
    out
}

// --- Options and preview ------------------------------------------------------------------

/// The label of an option: that of its control, else its identifier (`libelle_element`).
pub fn element_label(s: &Policy, e: &Element) -> String {
    let label = s
        .presentation
        .iter()
        .find(|c| c.ref_id == e.id)
        .map(|c| c.label.as_str())
        .unwrap_or_default();
    let text = if label.is_empty() {
        e.id.as_str()
    } else {
        label
    };
    text.trim_end_matches([' ', ':']).to_owned()
}

pub fn option_text(e: &Element, o: Option<&OptionValue>) -> String {
    if e.kind == ElementKind::Boolean {
        let yes = matches!(o, Some(OptionValue::Bool(true)))
            || matches!(o, Some(OptionValue::Int(n)) if *n != 0);
        return if yes { tr("yes") } else { tr("no") };
    }
    let Some(o) = o else {
        return tr("(empty)");
    };
    match o {
        OptionValue::Int(i) if e.kind == ElementKind::Enum => usize::try_from(*i)
            .ok()
            .and_then(|i| e.choices.get(i))
            .map_or_else(|| i.to_string(), |c| c.label.clone()),
        OptionValue::Texts(list) if list.is_empty() => tr("(empty)"),
        OptionValue::Pairs(list) if list.is_empty() => tr("(empty)"),
        OptionValue::Texts(list) => list.join(" ; "),
        OptionValue::Pairs(list) => list
            .iter()
            .map(|(n, v)| format!("{n} = {v}"))
            .collect::<Vec<_>>()
            .join(" ; "),
        OptionValue::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        OptionValue::Int(n) => n.to_string(),
        OptionValue::Text(t) => t.clone(),
    }
}

/// « Computer Configuration — Policy “X”: Enabled ; Option Y = 3 » (`ligne_apercu`).
pub fn preview_line(s: &Policy, part: Part, setting: &Setting) -> String {
    let mut text = fill(
        &tr("{partie} — Policy “{nom}”: {etat}"),
        &[
            ("partie", &part_label(part)),
            ("nom", &s.label),
            ("etat", &state_label(setting.state)),
        ],
    );
    if setting.state == State::Enabled {
        let options: Vec<String> = s
            .elements
            .iter()
            .map(|e| {
                fill(
                    &tr("{option} = {valeur}"),
                    &[
                        ("option", &element_label(s, e)),
                        ("valeur", &option_text(e, setting.option(&e.id))),
                    ],
                )
            })
            .collect();
        if !options.is_empty() {
            text.push_str(" ; ");
            text.push_str(&options.join(" ; "));
        }
    }
    text
}

/// The message of a refused option.
pub fn option_error_text(error: &pol::OptionError) -> String {
    use pol::OptionError as E;
    match error {
        E::Required => tr("Value required."),
        E::IntegerExpected => tr("Integer expected."),
        E::Range { min, max } => fill(
            &tr("Between {min} and {max}."),
            &[("min", &min.to_string()), ("max", &max.to_string())],
        ),
        E::MaxCharacters { n } => fill(&tr("{n} characters at most."), &[("n", &n.to_string())]),
        E::MaxLines { n } => fill(&tr("{n} lines at most."), &[("n", &n.to_string())]),
        E::MaxCharactersPerLine { n } => fill(
            &tr("{n} characters at most per line."),
            &[("n", &n.to_string())],
        ),
        E::UnknownChoice => tr("Unknown choice."),
        E::NameRequired => tr("Every line needs a name."),
        E::DuplicateName => tr("Two lines have the same name."),
    }
}

// --- Raw registry -------------------------------------------------------------------------

fn hex(bytes: &[u8], separator: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(separator)
}

/// The data of an entry in clear (`texte_donnees`).
pub fn data_text(e: &Entry) -> String {
    match e.interpret() {
        Err(_) => hex(&e.data, ""),
        Ok(RegValue::Bytes(b)) => hex(&b, " "),
        Ok(RegValue::Texts(list)) => list.join(" ; "),
        Ok(v) => pol::py_str(&v),
    }
}

/// (title, detail) of an entry: `HKLM\key\value` and what it does (`ligne_brute`).
pub fn raw_row(part: Part, e: &Entry) -> (String, String) {
    let root = format!("{}\\{}", hive(part), e.key);
    let lower = e.value_name.to_lowercase();
    if lower.starts_with("**delvals.") {
        return (root, tr("Deletes all values of the key"));
    }
    if lower.starts_with("**del.") {
        let name = e.value_name.get(6..).unwrap_or_default();
        return (format!("{root}\\{name}"), tr("Deletes the value"));
    }
    if e.value_name.starts_with("**") {
        return (
            format!("{root}\\{}", e.value_name),
            fill(&tr("Instruction {nom}"), &[("nom", &e.value_name)]),
        );
    }
    (
        format!("{root}\\{}", e.value_name),
        format!("{} {}", e.type_name(), data_text(e)),
    )
}

/// « Computer Configuration — Registry: entry HKLM\key\value removed » (`ligne_retrait`).
pub fn removal_line(part: Part, e: &Entry) -> String {
    let (name, _) = raw_row(part, e);
    fill(
        &tr("{partie} — Registry: entry {nom} removed"),
        &[("partie", &part_label(part)), ("nom", &name)],
    )
}

/// « Computer Configuration — Registry: entry HKLM\key\value added (DWORD 1) »
/// (`ligne_ajout`).
pub fn addition_line(part: Part, old: Option<&Entry>, new: &Entry) -> String {
    let (name, detail) = raw_row(part, new);
    let template = if old.is_none() {
        tr("{partie} — Registry: entry {nom} added ({detail})")
    } else {
        tr("{partie} — Registry: entry {nom} changed ({detail})")
    };
    fill(
        &template,
        &[
            ("partie", &part_label(part)),
            ("nom", &name),
            ("detail", &detail),
        ],
    )
}

// --- Input of a raw entry -----------------------------------------------------------------

/// Order of the « Part » list of the dialog.
pub const PARTS: [Part; 2] = [Part::Computer, Part::User];

/// What the entry typed does: set the value, delete it (`**del.`), or delete every value of
/// the key (`**delvals.`, lower case: the GPMC only reads this form in its report)
/// (`ActionBrute`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawAction {
    Set,
    Delete,
    DeleteAll,
}

/// Order of the « Action » list of the dialog.
pub const RAW_ACTIONS: [RawAction; 3] = [RawAction::Set, RawAction::Delete, RawAction::DeleteAll];

/// Types offered, in the order of the « Type » list of the dialog.
pub const RAW_TYPES: [u32; 6] = [
    rp::REG_SZ,
    rp::REG_EXPAND_SZ,
    rp::REG_DWORD,
    rp::REG_QWORD,
    rp::REG_MULTI_SZ,
    rp::REG_BINARY,
];

/// The dialog of a raw entry (`FormBrut`). `data` is the text typed: integer in decimal or in
/// hexadecimal according to `decimal` (DWORD, QWORD), bytes in hexadecimal (BINARY), one string
/// per line (MULTI_SZ), text otherwise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawForm {
    pub action: RawAction,
    pub key: String,
    pub name: String,
    pub rtype: u32,
    pub data: String,
    pub decimal: bool,
}

impl Default for RawForm {
    fn default() -> Self {
        Self {
            action: RawAction::Set,
            key: String::new(),
            name: String::new(),
            rtype: rp::REG_SZ,
            data: String::new(),
            decimal: true,
        }
    }
}

/// The form of an entry of the file (empty for a new entry); `None` if the dialog cannot
/// reproduce it exactly (other `**` instruction, rare type, data that does not read back): it
/// can then only be removed (`form_brut`).
pub fn raw_form(e: Option<&Entry>) -> Option<RawForm> {
    let Some(e) = e else {
        return Some(RawForm::default());
    };
    match e.special() {
        Some(Special::DelVals) => {
            return Some(RawForm {
                action: RawAction::DeleteAll,
                key: e.key.clone(),
                ..RawForm::default()
            });
        }
        Some(Special::Del) => {
            return Some(RawForm {
                action: RawAction::Delete,
                key: e.key.clone(),
                name: e.name().to_owned(),
                ..RawForm::default()
            });
        }
        Some(_) => return None,
        None => {}
    }
    if !RAW_TYPES.contains(&e.rtype) {
        return None;
    }
    let data = match e.interpret().ok()? {
        RegValue::Bytes(b) => hex(&b, " ").to_uppercase(),
        RegValue::Texts(list) => list.join("\n"),
        v => pol::py_str(&v),
    };
    let form = RawForm {
        action: RawAction::Set,
        key: e.key.clone(),
        name: e.value_name.clone(),
        rtype: e.rtype,
        data,
        decimal: true,
    };
    (raw_entry(&form).ok().as_ref() == Some(e)).then_some(form)
}

fn integer(text: &str, decimal: bool, bits: u32) -> Result<u64, String> {
    let parsed = parse_integer(text, if decimal { 10 } else { 16 });
    let Some(n) = parsed else {
        return Err(if decimal {
            tr("A decimal integer.")
        } else {
            tr("A hexadecimal integer.")
        });
    };
    let max = (1i128 << bits) - 1;
    if !(0..=max).contains(&n) {
        return Err(fill(
            &tr("Integer out of bounds: from 0 to {max}."),
            &[("max", &max.to_string())],
        ));
    }
    u64::try_from(n).map_err(|e| e.to_string())
}

/// An integer as Python's `int(text, base)` reads it: spaces around, a sign, `0x` in base 16.
fn parse_integer(text: &str, base: u32) -> Option<i128> {
    let t = text.trim();
    let (negative, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let rest = if base == 16 {
        rest.strip_prefix("0x")
            .or_else(|| rest.strip_prefix("0X"))
            .unwrap_or(rest)
    } else {
        rest
    };
    if rest.is_empty() || rest.starts_with(['+', '-']) {
        return None;
    }
    let n = i128::from_str_radix(rest, base).ok()?;
    Some(if negative { -n } else { n })
}

/// The value of the text typed; an error (message for the user) otherwise (`_valeur_saisie`).
fn typed_value(form: &RawForm) -> Result<RegValue, String> {
    let t = form.rtype;
    if t == rp::REG_DWORD || t == rp::REG_QWORD {
        let bits = if t == rp::REG_QWORD { 64 } else { 32 };
        return integer(&form.data, form.decimal, bits).map(RegValue::Integer);
    }
    if t == rp::REG_BINARY {
        let digits: String = form.data.chars().filter(|c| !c.is_whitespace()).collect();
        if digits.len() % 2 != 0 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(tr("Hexadecimal bytes (two digits per byte)."));
        }
        let bytes = (0..digits.len())
            .step_by(2)
            .filter_map(|i| {
                digits
                    .get(i..i + 2)
                    .and_then(|d| u8::from_str_radix(d, 16).ok())
            })
            .collect();
        return Ok(RegValue::Bytes(bytes));
    }
    if form.data.contains('\0') {
        return Err(tr("Null character not allowed."));
    }
    if t == rp::REG_MULTI_SZ {
        let text = form.data.replace("\r\n", "\n");
        let lines: Vec<&str> = text.split('\n').collect();
        if lines
            .iter()
            .take(lines.len().saturating_sub(1))
            .any(|l| l.is_empty())
        {
            return Err(tr("No empty line: the registry would take it for the end."));
        }
        return Ok(RegValue::Texts(
            lines
                .into_iter()
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect(),
        ));
    }
    Ok(RegValue::Text(form.data.clone()))
}

fn has_hive(key: &str) -> bool {
    let upper = key.to_uppercase();
    let first = upper.split('\\').next().unwrap_or_default();
    first == "HKLM"
        || first == "HKCU"
        || (first.starts_with("HKEY_")
            && first.len() > 5
            && first
                .chars()
                .skip(5)
                .all(|c| c.is_ascii_uppercase() || c == '_'))
}

/// What prevents writing the entry, by field (« cle », « nom », « type », « donnees »); empty if
/// nothing (`valider_brut`).
pub fn validate_raw(form: &RawForm) -> BTreeMap<&'static str, String> {
    let mut errors = BTreeMap::new();
    let key = form.key.trim();
    if key.is_empty() {
        errors.insert(
            "cle",
            tr("Enter the key, for example Software\\Vendor\\Product."),
        );
    } else if has_hive(key) {
        errors.insert(
            "cle",
            tr("Give the key without the hive: the part sets it."),
        );
    } else if key.starts_with('\\')
        || key.ends_with('\\')
        || key.contains("\\\\")
        || key.contains('\0')
    {
        errors.insert(
            "cle",
            tr(
                "A key is written Software\\Vendor\\Product, with no backslash at the start or end, and none doubled.",
            ),
        );
    }
    if form.name.contains('\0') {
        errors.insert("nom", tr("Null character not allowed."));
    } else if form.action == RawAction::Delete && form.name.is_empty() {
        errors.insert("nom", tr("Enter the value to delete."));
    } else if form.action != RawAction::DeleteAll && form.name.starts_with("**") {
        errors.insert("nom", tr("A name starting with “**” is a GPO instruction."));
    }
    if form.action == RawAction::Set {
        if !RAW_TYPES.contains(&form.rtype) {
            errors.insert("type", tr("Type not offered."));
        } else if let Err(e) = typed_value(form) {
            errors.insert("donnees", e);
        }
    }
    errors
}

/// The entry of the `Registry.pol` the form describes; an error if it is not valid
/// (`entree_brute`).
pub fn raw_entry(form: &RawForm) -> Result<Entry, String> {
    let errors = validate_raw(form);
    if !errors.is_empty() {
        return Err(errors.into_values().collect::<Vec<_>>().join(" "));
    }
    let key = form.key.trim().to_owned();
    match form.action {
        RawAction::DeleteAll => Ok(Entry {
            key,
            value_name: rp::DELVALS.to_owned(),
            rtype: rp::REG_SZ,
            data: rp::DEL_DATA.to_vec(),
        }),
        RawAction::Delete => Ok(Entry {
            key,
            value_name: format!("{}{}", rp::DEL_PREFIX, form.name),
            rtype: rp::REG_SZ,
            data: rp::DEL_DATA.to_vec(),
        }),
        RawAction::Set => Entry::from_value(&key, &form.name, form.rtype, &typed_value(form)?)
            .map_err(|e| crate::codec_texts::codec_message(&e.to_string())),
    }
}

/// The text of an integer written in the other base when « Decimal » is switched (`decimal` is
/// the new base); as is if it does not read in the old one (`convertir_entier`).
pub fn convert_integer(text: &str, decimal: bool) -> String {
    match parse_integer(text, if decimal { 16 } else { 10 }) {
        None => text.to_owned(),
        Some(n) if decimal => n.to_string(),
        Some(n) if n < 0 => format!("-{:X}", -n),
        Some(n) => format!("{n:X}"),
    }
}

/// A raw entry of the draft: (entry of the file it replaces or `None`, entry) (`Ajout`).
pub type Addition = (Option<Entry>, Entry);

/// The file after the gestures of the raw registry: entries removed, then each entry typed in
/// place of the one it changes (if the file read again still has it), else set as the GPMC
/// (`registry_pol::set`: in place of what aimed at the same value, or after the last entry of
/// its key) (`appliquer_bruts`).
pub fn apply_raw(entries: &[Entry], removals: &[Entry], additions: &[Addition]) -> Vec<Entry> {
    let mut result: Vec<Entry> = entries
        .iter()
        .filter(|e| !removals.contains(e))
        .cloned()
        .collect();
    for (old, new) in additions {
        if let Some(old) = old
            && let Some(i) = result.iter().position(|e| e == old)
            && let Some(slot) = result.get_mut(i)
        {
            *slot = new.clone();
        }
        result = rp::set(&result, new.clone());
    }
    result
}

/// The entries of the file after the settings of the draft, in the order of the draft
/// (`regler`).
pub fn apply_settings(entries: &[Entry], store: &Store, draft: &[(String, Setting)]) -> Vec<Entry> {
    let mut result = entries.to_vec();
    for (ident, setting) in draft {
        if let Some(p) = store.policy(ident) {
            result = pol::modify(&result, p, setting);
        }
    }
    result
}

#[cfg(test)]
mod tests;

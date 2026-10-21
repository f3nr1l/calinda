// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Setting of an ADMX policy in a `Registry.pol` (J7.3, `annuaire.core.strategies`), without
//! network.
//!
//! Reading: the state of a policy (not configured, enabled, disabled) and its options follow
//! from the entries of the file, as the GPMC editor and `Get-GPOReport` do it: the main value
//! compared with `enabledValue` / `disabledValue` (failing which, REG_DWORD 1 for « enabled »
//! and `**del.` for « disabled »), the lists `enabledList` / `disabledList`, then the values of
//! the options. Contrary clues give `Undetermined`.
//!
//! Writing: `modify(entries, policy, setting)` removes from the file every entry of the policy
//! (its **footprint**: values it sets, keys of its lists) and adds at the end those of the new
//! setting, in the order of the Windows editor (main value, list, options; `**delvals.` before
//! the values of a list). The other entries stay as they are and in their place: a setting the
//! ADMX does not know is kept (`extra`).

use std::collections::{BTreeMap, HashMap, HashSet};

use annuaire_codecs::registry_pol::{self as rp, Entry, RegValue};

use crate::admx::{AdmxValue, Class, ControlKind, Element, ElementKind, ListItem, Policy, Store};

/// Lower case: `Get-GPOReport` only ties to its ADMX policy a `**delvals.` written so; the
/// `**delVals.` of `Set-GPRegistryValue -Disable` shows as an « extra registry setting »
/// (seen on LAB.TEST and WIN.TEST, 2026-10-14).
pub const DELVALS_NAME: &str = "**delvals.";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    NotConfigured,
    Enabled,
    Disabled,
    /// The file says something, but neither « enabled » nor « disabled » follows from it.
    Undetermined,
}

/// Value of an option: boolean (boolean), integer (decimal, longDecimal, and the index of the
/// choice of an enum), text (text), list of texts (multiText, list) or of name, value pairs
/// (list with `explicitValue`). Absent from the map: nothing typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionValue {
    Bool(bool),
    Int(i128),
    Text(String),
    Texts(Vec<String>),
    Pairs(Vec<(String, String)>),
}

impl OptionValue {
    /// `None`, `""` or `()`: nothing typed.
    pub fn is_empty(value: Option<&Self>) -> bool {
        match value {
            None => true,
            Some(Self::Text(t)) => t.is_empty(),
            Some(Self::Texts(t)) => t.is_empty(),
            Some(Self::Pairs(p)) => p.is_empty(),
            Some(_) => false,
        }
    }
}

pub type Options = BTreeMap<String, Option<OptionValue>>;

/// A setting (`Reglage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Setting {
    pub state: State,
    pub options: Options,
}

impl Setting {
    pub fn new(state: State) -> Self {
        Self {
            state,
            options: Options::new(),
        }
    }

    pub fn option(&self, id: &str) -> Option<&OptionValue> {
        self.options.get(id).and_then(Option::as_ref)
    }
}

// --- Reading ------------------------------------------------------------------------------

fn pair(key: &str, name: &str) -> (String, String) {
    (key.to_lowercase(), name.to_lowercase())
}

/// Service entry (`**del.`, `**delvals.`, `**DeleteValues`…), not a value (`est_marque`).
pub fn is_marker(entry: &Entry) -> bool {
    entry.value_name.starts_with("**")
}

fn del_target(value_name: &str) -> Option<&str> {
    value_name
        .get(..6)
        .filter(|p| p.eq_ignore_ascii_case(rp::DEL_PREFIX))
        .and_then(|_| value_name.get(6..))
}

/// The entries of a `Registry.pol` replayed in order: what they set or remove in the end,
/// value by value (case ignored, as the registry) (`Registre`).
#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub entries: Vec<Entry>,
    values: HashMap<(String, String), (usize, Entry)>,
    deleted: HashSet<(String, String)>,
    emptied: HashSet<String>,
}

impl Registry {
    pub fn new(entries: &[Entry]) -> Self {
        let mut r = Self {
            entries: entries.to_vec(),
            ..Self::default()
        };
        for (seq, e) in entries.iter().enumerate() {
            let lower = e.value_name.to_lowercase();
            if lower.starts_with(DELVALS_NAME) {
                let key = e.key.to_lowercase();
                r.values.retain(|k, _| k.0 != key);
                r.emptied.insert(key);
            } else if let Some(target) = del_target(&e.value_name) {
                let k = pair(&e.key, target);
                r.values.remove(&k);
                r.deleted.insert(k);
            } else if !is_marker(e) {
                let k = pair(&e.key, &e.value_name);
                r.deleted.remove(&k);
                // A value set again keeps its place (as a dictionary).
                let seq = r.values.get(&k).map_or(seq, |(s, _)| *s);
                r.values.insert(k, (seq, e.clone()));
            }
        }
        r
    }

    pub fn value(&self, key: &str, name: &str) -> Option<&Entry> {
        self.values.get(&pair(key, name)).map(|(_, e)| e)
    }

    pub fn deleted(&self, key: &str, name: &str) -> bool {
        self.deleted.contains(&pair(key, name))
    }

    pub fn emptied(&self, key: &str) -> bool {
        self.emptied.contains(&key.to_lowercase())
    }

    /// The values of `key`, in the order they were set (`valeurs_de`).
    pub fn values_of(&self, key: &str) -> Vec<&Entry> {
        let lower = key.to_lowercase();
        let mut found: Vec<&(usize, Entry)> = self
            .values
            .iter()
            .filter(|(k, _)| k.0 == lower)
            .map(|(_, v)| v)
            .collect();
        found.sort_by_key(|(seq, _)| *seq);
        found.into_iter().map(|(_, e)| e).collect()
    }
}

fn interpret(e: &Entry) -> RegValue {
    e.interpret()
        .unwrap_or_else(|_| RegValue::Bytes(e.data.clone()))
}

fn int(v: &RegValue) -> Option<i128> {
    match v {
        RegValue::Integer(n) => Some(i128::from(*n)),
        _ => None,
    }
}

/// `str()` of a value read, as Python writes it.
pub fn py_str(v: &RegValue) -> String {
    match v {
        RegValue::Integer(n) => n.to_string(),
        RegValue::Text(t) => t.clone(),
        RegValue::Texts(list) => {
            let items: Vec<String> = list.iter().map(|t| format!("'{t}'")).collect();
            format!("[{}]", items.join(", "))
        }
        RegValue::Bytes(b) => {
            let inner: String = b
                .iter()
                .map(|&c| match c {
                    b'\\' => "\\\\".to_owned(),
                    b'\'' => "\\'".to_owned(),
                    0x20..=0x7e => char::from(c).to_string(),
                    b'\n' => "\\n".to_owned(),
                    b'\r' => "\\r".to_owned(),
                    b'\t' => "\\t".to_owned(),
                    _ => format!("\\x{c:02x}"),
                })
                .collect();
            format!("b'{inner}'")
        }
    }
}

fn number(e: &Entry) -> Option<i128> {
    match interpret(e) {
        RegValue::Integer(n) => Some(i128::from(n)),
        RegValue::Text(t) => t.trim().parse().ok(),
        _ => None,
    }
}

/// Does the registry set `value` (from the ADMX) at `key`!`name`? (`correspond`)
pub fn matches(registry: &Registry, key: &str, name: &str, value: &AdmxValue) -> bool {
    if *value == AdmxValue::Delete {
        return registry.deleted(key, name);
    }
    let Some(e) = registry.value(key, name) else {
        return false;
    };
    match value {
        AdmxValue::Decimal(n) => e.rtype == rp::REG_DWORD && int(&interpret(e)) == Some(*n),
        AdmxValue::Long(n) => e.rtype == rp::REG_QWORD && int(&interpret(e)) == Some(*n),
        AdmxValue::String(s) => {
            (e.rtype == rp::REG_SZ || e.rtype == rp::REG_EXPAND_SZ)
                && interpret(e) == RegValue::Text(s.clone())
        }
        AdmxValue::Delete => false,
    }
}

fn list_set(registry: &Registry, items: &[ListItem]) -> bool {
    !items.is_empty()
        && items
            .iter()
            .all(|i| matches(registry, &i.key, &i.value_name, &i.value))
}

const ONE: AdmxValue = AdmxValue::Decimal(1);
const ZERO: AdmxValue = AdmxValue::Decimal(0);
const DELETED: AdmxValue = AdmxValue::Delete;

/// The setting of a policy from a replayed registry (`lire_reglage`).
pub fn read_setting(policy: &Policy, registry: &Registry) -> Setting {
    let s = policy;
    let (mut enabled, mut disabled) = (0, 0);
    if !s.value_name.is_empty() {
        if matches(
            registry,
            &s.key,
            &s.value_name,
            s.enabled_value.as_ref().unwrap_or(&ONE),
        ) {
            enabled += 1;
        }
        if matches(
            registry,
            &s.key,
            &s.value_name,
            s.disabled_value.as_ref().unwrap_or(&DELETED),
        ) {
            disabled += 1;
        }
    }
    if list_set(registry, &s.enabled_list) {
        enabled += 1;
    }
    if list_set(registry, &s.disabled_list) {
        disabled += 1;
    }
    if enabled == 0 && disabled == 0 && !s.elements.is_empty() {
        let (mut present, mut removed) = (0, 0);
        for e in &s.elements {
            match e.kind {
                ElementKind::List => {
                    if !registry.values_of(&e.key).is_empty() {
                        present += 1;
                    } else if registry.emptied(&e.key) {
                        removed += 1;
                    }
                }
                ElementKind::Boolean => {
                    // Disabled, the policy writes the explicit « false » value of a check box:
                    // it does not prove the activation, unlike the implicit 0.
                    match read_option(e, registry) {
                        Some(OptionValue::Bool(true)) => present += 1,
                        Some(OptionValue::Bool(false)) => {
                            let explicit = e.false_value.is_some() || !e.false_list.is_empty();
                            let gone =
                                !e.value_name.is_empty() && registry.deleted(&e.key, &e.value_name);
                            if explicit || gone {
                                removed += 1;
                            } else {
                                present += 1;
                            }
                        }
                        _ => {}
                    }
                }
                _ if !e.value_name.is_empty() => {
                    if registry.value(&e.key, &e.value_name).is_some() {
                        present += 1;
                    } else if registry.deleted(&e.key, &e.value_name) {
                        removed += 1;
                    }
                }
                _ => {}
            }
        }
        if present > 0 {
            enabled = 1;
        } else if removed > 0 {
            disabled = 1;
        }
    }
    if enabled > disabled {
        return Setting {
            state: State::Enabled,
            options: s
                .elements
                .iter()
                .map(|e| (e.id.clone(), read_option(e, registry)))
                .collect(),
        };
    }
    if disabled > enabled {
        return Setting::new(State::Disabled);
    }
    if enabled > 0 || !footprint(s).within(&registry.entries).is_empty() {
        return Setting::new(State::Undetermined);
    }
    Setting::new(State::NotConfigured)
}

/// The value of an option from the registry; `None` if nothing says it (`lire_option`).
pub fn read_option(e: &Element, registry: &Registry) -> Option<OptionValue> {
    match e.kind {
        ElementKind::List => {
            let values = registry.values_of(&e.key);
            Some(if e.explicit {
                OptionValue::Pairs(
                    values
                        .iter()
                        .map(|v| (v.value_name.clone(), py_str(&interpret(v))))
                        .collect(),
                )
            } else {
                OptionValue::Texts(values.iter().map(|v| py_str(&interpret(v))).collect())
            })
        }
        ElementKind::Boolean => {
            if !e.value_name.is_empty() {
                if matches(
                    registry,
                    &e.key,
                    &e.value_name,
                    e.true_value.as_ref().unwrap_or(&ONE),
                ) {
                    return Some(OptionValue::Bool(true));
                }
                if matches(
                    registry,
                    &e.key,
                    &e.value_name,
                    e.false_value.as_ref().unwrap_or(&ZERO),
                ) {
                    return Some(OptionValue::Bool(false));
                }
                if e.false_value.is_none() && registry.deleted(&e.key, &e.value_name) {
                    return Some(OptionValue::Bool(false));
                }
            }
            if list_set(registry, &e.true_list) {
                return Some(OptionValue::Bool(true));
            }
            if list_set(registry, &e.false_list) {
                return Some(OptionValue::Bool(false));
            }
            None
        }
        ElementKind::Enum => {
            for (i, c) in e.choices.iter().enumerate() {
                let found = match (&c.value, e.value_name.is_empty()) {
                    (Some(v), false) => matches(registry, &e.key, &e.value_name, v),
                    _ => list_set(registry, &c.list),
                };
                if found {
                    return Some(OptionValue::Int(i128::try_from(i).unwrap_or_default()));
                }
            }
            None
        }
        _ => {
            let v = registry.value(&e.key, &e.value_name)?;
            match e.kind {
                ElementKind::Decimal | ElementKind::Long => number(v).map(OptionValue::Int),
                ElementKind::MultiText => Some(OptionValue::Texts(match interpret(v) {
                    RegValue::Texts(list) => list,
                    other => vec![py_str(&other)],
                })),
                _ => Some(OptionValue::Text(py_str(&interpret(v)))),
            }
        }
    }
}

/// The setting of a policy in the entries of a file (`lire`).
pub fn read(policy: &Policy, entries: &[Entry]) -> Setting {
    read_setting(policy, &Registry::new(entries))
}

// --- Footprint ----------------------------------------------------------------------------

/// What a policy can write: precise values and whole keys (lists) (`Empreinte`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Footprint {
    pub pairs: HashSet<(String, String)>,
    pub keys: HashSet<String>,
}

impl Footprint {
    pub fn contains(&self, entry: &Entry) -> bool {
        let key = entry.key.to_lowercase();
        if self.keys.contains(&key) {
            return true;
        }
        let name = match del_target(&entry.value_name) {
            Some(target) => target,
            None if is_marker(entry) => return false,
            None => &entry.value_name,
        };
        self.pairs.contains(&(key, name.to_lowercase()))
    }

    pub fn within(&self, entries: &[Entry]) -> Vec<Entry> {
        entries
            .iter()
            .filter(|e| self.contains(e))
            .cloned()
            .collect()
    }
}

pub fn footprint(policy: &Policy) -> Footprint {
    let s = policy;
    let mut f = Footprint::default();
    let items = |list: &[ListItem], f: &mut Footprint| {
        f.pairs
            .extend(list.iter().map(|i| pair(&i.key, &i.value_name)));
    };
    if !s.value_name.is_empty() {
        f.pairs.insert(pair(&s.key, &s.value_name));
    }
    items(&s.enabled_list, &mut f);
    items(&s.disabled_list, &mut f);
    for e in &s.elements {
        if e.kind == ElementKind::List {
            f.keys.insert(e.key.to_lowercase());
            continue;
        }
        if !e.value_name.is_empty() {
            f.pairs.insert(pair(&e.key, &e.value_name));
        }
        items(&e.true_list, &mut f);
        items(&e.false_list, &mut f);
        for c in &e.choices {
            items(&c.list, &mut f);
        }
    }
    f
}

/// Union of the footprints of the policies of `part`: what is not there is an « extra
/// setting » (`empreinte_magasin`).
pub fn store_footprint(store: &Store, part: Class) -> Footprint {
    let mut f = Footprint::default();
    for s in store.policies.iter().filter(|s| s.class.applies_to(part)) {
        let e = footprint(s);
        f.pairs.extend(e.pairs);
        f.keys.extend(e.keys);
    }
    f
}

/// Entries no policy of the store writes, in the order of the file (`supplementaires`).
pub fn extra(known: &Footprint, entries: &[Entry]) -> Vec<Entry> {
    entries
        .iter()
        .filter(|e| !known.contains(e))
        .cloned()
        .collect()
}

/// Identifiers of the policies of `part` the file says something about (`configurees`).
pub fn configured(store: &Store, part: Class, entries: &[Entry]) -> HashSet<String> {
    if entries.is_empty() {
        return HashSet::new();
    }
    let registry = Registry::new(entries);
    let pairs: HashSet<(String, String)> = entries
        .iter()
        .map(|e| pair(&e.key, del_target(&e.value_name).unwrap_or(&e.value_name)))
        .collect();
    let keys: HashSet<String> = entries.iter().map(|e| e.key.to_lowercase()).collect();
    store
        .policies
        .iter()
        .filter(|s| s.class.applies_to(part))
        .filter(|s| {
            let f = footprint(s);
            let touched = !f.pairs.is_disjoint(&pairs) || !f.keys.is_disjoint(&keys);
            touched && read_setting(s, &registry).state != State::NotConfigured
        })
        .map(|s| s.ident.clone())
        .collect()
}

// --- Writing ------------------------------------------------------------------------------

fn text_data(t: &str) -> Vec<u8> {
    t.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn dword(n: i128) -> Vec<u8> {
    u32::try_from(n).unwrap_or_default().to_le_bytes().to_vec()
}

fn qword(n: i128) -> Vec<u8> {
    u64::try_from(n).unwrap_or_default().to_le_bytes().to_vec()
}

fn entry(key: &str, name: &str, rtype: u32, data: Vec<u8>) -> Entry {
    Entry {
        key: key.to_owned(),
        value_name: name.to_owned(),
        rtype,
        data,
    }
}

/// The entry that sets an ADMX value (`entree_valeur`).
pub fn value_entry(key: &str, name: &str, value: &AdmxValue) -> Entry {
    match value {
        AdmxValue::Delete => entry(
            key,
            &format!("{}{name}", rp::DEL_PREFIX),
            rp::REG_SZ,
            rp::DEL_DATA.to_vec(),
        ),
        AdmxValue::Decimal(n) => entry(key, name, rp::REG_DWORD, dword(*n)),
        AdmxValue::Long(n) => entry(key, name, rp::REG_QWORD, qword(*n)),
        AdmxValue::String(s) => entry(key, name, rp::REG_SZ, text_data(s)),
    }
}

/// `**delvals.` on a key (`entree_vidage`).
pub fn empty_entry(key: &str) -> Entry {
    entry(key, DELVALS_NAME, rp::REG_SZ, rp::DEL_DATA.to_vec())
}

fn items(list: &[ListItem]) -> Vec<Entry> {
    list.iter()
        .map(|i| value_entry(&i.key, &i.value_name, &i.value))
        .collect()
}

fn option_entries(e: &Element, o: Option<&OptionValue>) -> Vec<Entry> {
    if e.kind == ElementKind::Boolean {
        let checked = match o {
            Some(OptionValue::Bool(b)) => *b,
            Some(OptionValue::Int(n)) => *n != 0,
            Some(OptionValue::Text(t)) => !t.is_empty(),
            Some(OptionValue::Texts(t)) => !t.is_empty(),
            Some(OptionValue::Pairs(p)) => !p.is_empty(),
            None => false,
        };
        if checked {
            let mut out = if e.value_name.is_empty() {
                Vec::new()
            } else {
                vec![value_entry(
                    &e.key,
                    &e.value_name,
                    e.true_value.as_ref().unwrap_or(&ONE),
                )]
            };
            out.extend(items(&e.true_list));
            return out;
        }
        // Unchecked without `falseValue`: `**del.`, as the Windows editor; a REG_DWORD 0
        // would be seen by `Get-GPOReport` as an extra registry setting (seen on LAB.TEST,
        // 2026-10-14). It still reads back as « unchecked ».
        let mut out = if e.value_name.is_empty() {
            Vec::new()
        } else {
            vec![value_entry(
                &e.key,
                &e.value_name,
                e.false_value.as_ref().unwrap_or(&DELETED),
            )]
        };
        out.extend(items(&e.false_list));
        return out;
    }
    let Some(o) = o else { return Vec::new() };
    match e.kind {
        ElementKind::List => {
            let mut out = if e.additive {
                Vec::new()
            } else {
                vec![empty_entry(&e.key)]
            };
            let rtype = if e.expandable {
                rp::REG_EXPAND_SZ
            } else {
                rp::REG_SZ
            };
            match o {
                OptionValue::Pairs(pairs) => {
                    for (name, data) in pairs {
                        out.push(entry(&e.key, name, rtype, text_data(data)));
                    }
                }
                OptionValue::Texts(texts) => {
                    for (rank, x) in texts.iter().enumerate() {
                        let name = match &e.prefix {
                            Some(p) => format!("{p}{}", rank + 1),
                            None => x.clone(),
                        };
                        out.push(entry(&e.key, &name, rtype, text_data(x)));
                    }
                }
                _ => {}
            }
            out
        }
        ElementKind::Enum => {
            let OptionValue::Int(i) = o else {
                return Vec::new();
            };
            let Some(c) = usize::try_from(*i).ok().and_then(|i| e.choices.get(i)) else {
                return Vec::new();
            };
            let mut out = match (&c.value, e.value_name.is_empty()) {
                (Some(v), false) => vec![value_entry(&e.key, &e.value_name, v)],
                _ => Vec::new(),
            };
            out.extend(items(&c.list));
            out
        }
        ElementKind::Decimal | ElementKind::Long => {
            let OptionValue::Int(n) = o else {
                return Vec::new();
            };
            if e.as_text {
                vec![entry(
                    &e.key,
                    &e.value_name,
                    rp::REG_SZ,
                    text_data(&n.to_string()),
                )]
            } else if e.kind == ElementKind::Decimal {
                vec![entry(&e.key, &e.value_name, rp::REG_DWORD, dword(*n))]
            } else {
                vec![entry(&e.key, &e.value_name, rp::REG_QWORD, qword(*n))]
            }
        }
        ElementKind::MultiText => {
            let texts: &[String] = match o {
                OptionValue::Texts(t) => t,
                _ => &[],
            };
            let mut data: Vec<u16> = Vec::new();
            for t in texts {
                data.extend(t.encode_utf16());
                data.push(0);
            }
            data.push(0);
            vec![entry(
                &e.key,
                &e.value_name,
                rp::REG_MULTI_SZ,
                data.into_iter().flat_map(u16::to_le_bytes).collect(),
            )]
        }
        _ => {
            let rtype = if e.expandable {
                rp::REG_EXPAND_SZ
            } else {
                rp::REG_SZ
            };
            let text = match o {
                OptionValue::Text(t) => t.clone(),
                OptionValue::Int(n) => n.to_string(),
                OptionValue::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
                OptionValue::Texts(t) => py_str(&RegValue::Texts(t.clone())),
                OptionValue::Pairs(_) => String::new(),
            };
            vec![entry(&e.key, &e.value_name, rtype, text_data(&text))]
        }
    }
}

/// The entries this setting writes, in the order of the Windows editor; one value is written
/// once (the last wins) (`entrees_reglage`).
pub fn setting_entries(policy: &Policy, setting: &Setting) -> Vec<Entry> {
    let s = policy;
    let mut out: Vec<Entry> = Vec::new();
    match setting.state {
        State::Enabled => {
            if !s.value_name.is_empty() {
                out.push(value_entry(
                    &s.key,
                    &s.value_name,
                    s.enabled_value.as_ref().unwrap_or(&ONE),
                ));
            }
            out.extend(items(&s.enabled_list));
            for e in &s.elements {
                out.extend(option_entries(e, setting.option(&e.id)));
            }
        }
        State::Disabled => {
            if !s.value_name.is_empty() {
                out.push(value_entry(
                    &s.key,
                    &s.value_name,
                    s.disabled_value.as_ref().unwrap_or(&DELETED),
                ));
            }
            out.extend(items(&s.disabled_list));
            for e in &s.elements {
                if e.kind == ElementKind::List {
                    out.push(empty_entry(&e.key));
                } else if e.kind == ElementKind::Boolean
                    && (e.false_value.is_some() || !e.false_list.is_empty())
                {
                    out.extend(option_entries(e, Some(&OptionValue::Bool(false))));
                } else if !e.value_name.is_empty() {
                    out.push(value_entry(&e.key, &e.value_name, &DELETED));
                }
            }
        }
        State::NotConfigured | State::Undetermined => {}
    }
    // An option that writes the main value (same key, same name) wins over it.
    let mut last: HashMap<(String, String), usize> = HashMap::new();
    for (i, x) in out.iter().enumerate() {
        last.insert(pair(&x.key, &x.value_name), i);
    }
    out.into_iter()
        .enumerate()
        .filter(|(i, x)| last.get(&pair(&x.key, &x.value_name)) == Some(i))
        .map(|(_, x)| x)
        .collect()
}

/// The entries of the file after this setting: those of the policy removed, the others kept
/// in their order, the new ones added at the end (`modifier`).
pub fn modify(entries: &[Entry], policy: &Policy, setting: &Setting) -> Vec<Entry> {
    let f = footprint(policy);
    let mut out: Vec<Entry> = entries.iter().filter(|e| !f.contains(e)).cloned().collect();
    out.extend(setting_entries(policy, setting));
    out
}

// --- Defaults and validation --------------------------------------------------------------

/// Options proposed when enabling a policy not configured: the defaults of the ADML
/// presentation (unchecked box, number 1, empty text, no choice) (`options_par_defaut`).
pub fn default_options(policy: &Policy) -> Options {
    let mut options = Options::new();
    for e in &policy.elements {
        let default = policy
            .presentation
            .iter()
            .find(|c| !c.ref_id.is_empty() && c.ref_id == e.id)
            .and_then(|c| c.default.clone());
        let value = match e.kind {
            ElementKind::Boolean => Some(OptionValue::Bool(
                default
                    .unwrap_or_default()
                    .trim()
                    .eq_ignore_ascii_case("true"),
            )),
            ElementKind::Decimal | ElementKind::Long => Some(OptionValue::Int(
                default.map_or(1, |d| d.trim().parse().unwrap_or(1)),
            )),
            ElementKind::Text => Some(OptionValue::Text(default.unwrap_or_default())),
            ElementKind::Enum => default
                .and_then(|d| d.trim().parse().ok())
                .map(OptionValue::Int),
            ElementKind::List | ElementKind::MultiText => Some(OptionValue::Texts(Vec::new())),
        };
        options.insert(e.id.clone(), value);
    }
    options
}

/// The kind of the control showing `element` (`genre_controle`).
pub fn control_kind(policy: &Policy, element: &Element) -> Option<ControlKind> {
    policy
        .presentation
        .iter()
        .find(|c| c.ref_id == element.id)
        .map(|c| c.kind)
}

/// Why an option is refused; the interface says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptionError {
    Required,
    IntegerExpected,
    Range { min: i128, max: i128 },
    MaxCharacters { n: i128 },
    MaxLines { n: i128 },
    MaxCharactersPerLine { n: i128 },
    UnknownChoice,
    NameRequired,
    DuplicateName,
}

/// Input errors by option (empty: all is well). Bounds of the numbers, length of the texts,
/// number of strings, required options, names of an explicit list (`valider`).
pub fn validate(policy: &Policy, options: &Options) -> BTreeMap<String, OptionError> {
    let mut errors = BTreeMap::new();
    for e in &policy.elements {
        let o = options.get(&e.id).and_then(Option::as_ref);
        let empty = OptionValue::is_empty(o);
        if e.required && empty && e.kind != ElementKind::Boolean {
            errors.insert(e.id.clone(), OptionError::Required);
            continue;
        }
        let Some(o) = o.filter(|_| !empty) else {
            continue;
        };
        let error = match (e.kind, o) {
            (ElementKind::Decimal | ElementKind::Long, OptionValue::Int(n)) => {
                (!(e.minimum..=e.maximum).contains(n)).then_some(OptionError::Range {
                    min: e.minimum,
                    max: e.maximum,
                })
            }
            (ElementKind::Decimal | ElementKind::Long, _) => Some(OptionError::IntegerExpected),
            (ElementKind::Text, OptionValue::Text(t)) => {
                (len(t) > e.max_length).then_some(OptionError::MaxCharacters { n: e.max_length })
            }
            (ElementKind::MultiText, OptionValue::Texts(lines)) => {
                if e.max_strings != 0 && len_of(lines.len()) > e.max_strings {
                    Some(OptionError::MaxLines { n: e.max_strings })
                } else if lines.iter().any(|t| len(t) > e.max_length) {
                    Some(OptionError::MaxCharactersPerLine { n: e.max_length })
                } else {
                    None
                }
            }
            (ElementKind::Enum, OptionValue::Int(i)) => usize::try_from(*i)
                .ok()
                .and_then(|i| e.choices.get(i))
                .is_none()
                .then_some(OptionError::UnknownChoice),
            (ElementKind::Enum, _) => Some(OptionError::UnknownChoice),
            (ElementKind::List, OptionValue::Pairs(pairs)) if e.explicit => {
                let names: Vec<String> = pairs.iter().map(|(n, _)| n.to_lowercase()).collect();
                if names.iter().any(String::is_empty) {
                    Some(OptionError::NameRequired)
                } else if names.iter().collect::<HashSet<_>>().len() != names.len() {
                    Some(OptionError::DuplicateName)
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(error) = error {
            errors.insert(e.id.clone(), error);
        }
    }
    errors
}

fn len(text: &str) -> i128 {
    len_of(text.chars().count())
}

fn len_of(n: usize) -> i128 {
    i128::try_from(n).unwrap_or(i128::MAX)
}

#[cfg(test)]
mod tests;

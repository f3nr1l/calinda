// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Group Policy Preferences (J7.6, `annuaire.vue.preferences`), without GTK: forms, validation,
//! rows, and the texts of the codec and of the draft.
//!
//! One form by family (`DriveForm`, `PrinterForm`, `ShortcutForm`, `RegistryForm`): what the
//! dialog shows, taken from an existing element (`form`) or by default; `validate` says, field
//! by field, what prevents saving (validation as typed); `to_element` makes the element of the
//! codec (new, or changed keeping what the form does not show). The properties are written in
//! the order of the GPMC console (MS-GPPREF). Texts of the lists and of the targeting.

use annuaire_core::gpo::Part;
use annuaire_core::gpo_preferences::Remark;
use annuaire_core::gpp::{
    self, Common, Document, EditableFilter, Element, Family, Filter, PreferencesError, Target,
};
use annuaire_core::xml::Node;

use crate::i18n::{fill, tr, tr_n};

/// Name of a family in the GPMC console (`nom_famille`).
pub fn family_name(family: Family) -> String {
    match family {
        Family::Drives => tr("Drive Maps"),
        Family::Printers => tr("Printers"),
        Family::Shortcuts => tr("Shortcuts"),
        Family::Registry => tr("Registry"),
    }
}

pub fn part_name(part: Part) -> String {
    match part {
        Part::Computer => tr("Computer Configuration"),
        Part::User => tr("User Configuration"),
    }
}

pub fn action_name(action: &str) -> String {
    match action {
        "C" => tr("Create"),
        "R" => tr("Replace"),
        "U" => tr("Update"),
        "D" => tr("Delete"),
        other => other.to_owned(),
    }
}

/// A file that cannot be read, said plainly (`ErreurPreferences`).
pub fn error_text(error: &PreferencesError) -> String {
    match error {
        PreferencesError::Dtd => tr("Preferences: a DTD is not accepted."),
        PreferencesError::Encoding => tr("Preferences: unsupported encoding (UTF-8 expected)."),
        PreferencesError::Malformed(e) => fill(
            &tr("Preferences: malformed XML ({erreur})."),
            &[("erreur", e)],
        ),
        PreferencesError::Root { root, expected } => fill(
            &tr("Preferences: root element “{racine}” instead of “{attendue}”."),
            &[("racine", root), ("attendue", expected)],
        ),
        PreferencesError::RootContent => tr("Preferences: unreadable root element content."),
        PreferencesError::Unclosed => tr("Preferences: unclosed tag."),
    }
}

/// What the preview says of a change of a family, element by element (`remarques`).
pub fn remarks_text(family: Family, part: Part, remarks: &[Remark]) -> Vec<String> {
    let place = fill(
        &tr("{famille} ({partie})"),
        &[
            ("famille", &family_name(family)),
            ("partie", &part_name(part)),
        ],
    );
    let count = |names: &[String]| u64::try_from(names.len()).unwrap_or(u64::MAX);
    remarks
        .iter()
        .map(|r| match r {
            Remark::Added(names) => fill(
                &tr_n("{lieu}: added {noms}.", "{lieu}: added {noms}.", count(names)),
                &[("lieu", &place), ("noms", &names.join(", "))],
            ),
            Remark::Changed(names) => fill(
                &tr_n("{lieu}: changed {noms}.", "{lieu}: changed {noms}.", count(names)),
                &[("lieu", &place), ("noms", &names.join(", "))],
            ),
            Remark::Removed(names) => fill(
                &tr_n("{lieu}: removed {noms}.", "{lieu}: removed {noms}.", count(names)),
                &[("lieu", &place), ("noms", &names.join(", "))],
            ),
            Remark::Reordered => fill(&tr("{lieu}: item order changed."), &[("lieu", &place)]),
            Remark::PasswordsRemoved(names) => fill(
                &tr(
                    "Stored password removed from: {noms} (MS14-025). The previous content, with its encrypted value, stays in the local journal for undo.",
                ),
                &[("noms", &names.join(", "))],
            ),
            Remark::Emptied => fill(
                &tr("{lieu}: no items left, the file is deleted."),
                &[("lieu", &place)],
            ),
        })
        .collect()
}

/// What prevents saving, by field (`Probleme`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub field: &'static str,
    pub message: String,
}

fn problem(field: &'static str, message: String) -> Problem {
    Problem { field, message }
}

// --- Forms --------------------------------------------------------------------------------

pub const DISPLAY: [&str; 3] = ["NOCHANGE", "SHOW", "HIDE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriveForm {
    pub action: String,
    pub path: String,
    pub letter: String,
    pub first_free: bool,
    pub label: String,
    pub reconnect: bool,
    pub this_drive: String,
    pub all_drives: String,
}

impl Default for DriveForm {
    fn default() -> Self {
        Self {
            action: "U".into(),
            path: String::new(),
            letter: "H".into(),
            first_free: false,
            label: String::new(),
            reconnect: false,
            this_drive: "NOCHANGE".into(),
            all_drives: "NOCHANGE".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrinterForm {
    pub action: String,
    pub path: String,
    pub default: bool,
    pub only_without_local: bool,
    pub delete_all: bool,
    pub location: String,
    pub comment: String,
    pub port: String,
    pub reconnect: bool,
    pub delete_port: bool,
}

impl Default for PrinterForm {
    fn default() -> Self {
        Self {
            action: "U".into(),
            path: String::new(),
            default: false,
            only_without_local: false,
            delete_all: false,
            location: String::new(),
            comment: String::new(),
            port: String::new(),
            reconnect: false,
            delete_port: false,
        }
    }
}

pub const TARGET_KINDS: [&str; 2] = ["FILESYSTEM", "URL"];
pub const WINDOWS: [&str; 3] = ["", "MIN", "MAX"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortcutForm {
    pub action: String,
    pub kind: String,
    pub path: String,
    pub target: String,
    pub arguments: String,
    pub start_in: String,
    pub window: String,
    pub comment: String,
    pub icon: String,
    pub icon_index: String,
}

impl Default for ShortcutForm {
    fn default() -> Self {
        Self {
            action: "U".into(),
            kind: "FILESYSTEM".into(),
            path: "%DesktopDir%\\".into(),
            target: String::new(),
            arguments: String::new(),
            start_in: String::new(),
            window: String::new(),
            comment: String::new(),
            icon: String::new(),
            icon_index: "0".into(),
        }
    }
}

pub const HIVES: [&str; 5] = [
    "HKEY_LOCAL_MACHINE",
    "HKEY_CURRENT_USER",
    "HKEY_CLASSES_ROOT",
    "HKEY_USERS",
    "HKEY_CURRENT_CONFIG",
];
pub const REGISTRY_TYPES: [&str; 6] = [
    "REG_SZ",
    "REG_EXPAND_SZ",
    "REG_MULTI_SZ",
    "REG_DWORD",
    "REG_QWORD",
    "REG_BINARY",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryForm {
    pub action: String,
    pub hive: String,
    pub key: String,
    pub name: String,
    pub default: bool,
    pub rtype: String,
    pub data: String,
    pub decimal: bool,
}

impl Default for RegistryForm {
    fn default() -> Self {
        Self {
            action: "U".into(),
            hive: "HKEY_CURRENT_USER".into(),
            key: String::new(),
            name: String::new(),
            default: false,
            rtype: "REG_SZ".into(),
            data: String::new(),
            decimal: true,
        }
    }
}

/// The form of a family (`Formulaire`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    Drive(DriveForm),
    Printer(PrinterForm),
    Shortcut(ShortcutForm),
    Registry(RegistryForm),
}

impl Form {
    pub fn action(&self) -> &str {
        match self {
            Self::Drive(f) => &f.action,
            Self::Printer(f) => &f.action,
            Self::Shortcut(f) => &f.action,
            Self::Registry(f) => &f.action,
        }
    }
}

fn yes(value: &str) -> bool {
    value == "1"
}

fn bit(value: bool) -> &'static str {
    if value { "1" } else { "0" }
}

fn prop(e: &Element, name: &str, default: &str) -> String {
    e.property(name).unwrap_or_else(|| default.to_owned())
}

/// The form of an existing element, or that of a new element of the family (`formulaire`).
pub fn form(family: Family, element: Option<&Element>, part: Part) -> Form {
    match family {
        Family::Drives => Form::Drive(element.map_or_else(DriveForm::default, |e| {
            let letter = prop(e, "letter", "");
            DriveForm {
                action: prop(e, "action", "U"),
                path: prop(e, "path", ""),
                letter: if letter.is_empty() {
                    "H".into()
                } else {
                    letter
                },
                first_free: prop(e, "useLetter", "1") == "0",
                label: prop(e, "label", ""),
                reconnect: yes(&prop(e, "persistent", "0")),
                this_drive: prop(e, "thisDrive", "NOCHANGE"),
                all_drives: prop(e, "allDrives", "NOCHANGE"),
            }
        })),
        Family::Printers => {
            Form::Printer(element.map_or_else(PrinterForm::default, |e| PrinterForm {
                action: prop(e, "action", "U"),
                path: prop(e, "path", ""),
                default: yes(&prop(e, "default", "0")),
                only_without_local: yes(&prop(e, "skipLocal", "0")),
                delete_all: yes(&prop(e, "deleteAll", "0")),
                location: prop(e, "location", ""),
                comment: prop(e, "comment", ""),
                port: prop(e, "port", ""),
                reconnect: yes(&prop(e, "persistent", "0")),
                delete_port: yes(&prop(e, "deleteMaps", "0")),
            }))
        }
        Family::Shortcuts => {
            Form::Shortcut(
                element.map_or_else(ShortcutForm::default, |e| ShortcutForm {
                    action: prop(e, "action", "U"),
                    kind: prop(e, "targetType", "FILESYSTEM"),
                    path: prop(e, "shortcutPath", ""),
                    target: prop(e, "targetPath", ""),
                    arguments: prop(e, "arguments", ""),
                    start_in: prop(e, "startIn", ""),
                    window: prop(e, "window", ""),
                    comment: prop(e, "comment", ""),
                    icon: prop(e, "iconPath", ""),
                    icon_index: prop(e, "iconIndex", "0"),
                }),
            )
        }
        Family::Registry => Form::Registry(match element {
            None => RegistryForm {
                hive: if part == Part::Computer {
                    "HKEY_LOCAL_MACHINE".into()
                } else {
                    "HKEY_CURRENT_USER".into()
                },
                ..RegistryForm::default()
            },
            Some(e) => {
                let rtype = prop(e, "type", "REG_SZ");
                let decimal = yes(&prop(e, "displayDecimal", "0"));
                RegistryForm {
                    action: prop(e, "action", "U"),
                    hive: prop(e, "hive", "HKEY_CURRENT_USER"),
                    key: prop(e, "key", ""),
                    name: prop(e, "name", ""),
                    default: yes(&prop(e, "default", "0")),
                    data: data_read(e, &rtype, decimal),
                    rtype,
                    decimal,
                }
            }
        }),
    }
}

/// Data of a registry element as the form shows them (`_donnees_lues`).
fn data_read(e: &Element, rtype: &str, decimal: bool) -> String {
    let value = prop(e, "value", "");
    if rtype == "REG_DWORD" || rtype == "REG_QWORD" {
        let n = if value.is_empty() {
            Some(0)
        } else {
            u64::from_str_radix(value.trim(), 16).ok()
        };
        return match n {
            None => value,
            Some(n) if decimal => n.to_string(),
            Some(n) => format!("{n:X}"),
        };
    }
    if rtype == "REG_MULTI_SZ" {
        let values: Vec<String> = e
            .node
            .find("Properties")
            .and_then(|p| p.find("Values"))
            .map(|v| {
                v.children
                    .iter()
                    .filter(|c| c.tag == "Value")
                    .map(|c| c.text.clone())
                    .collect()
            })
            .unwrap_or_default();
        if !values.is_empty() {
            return values.join("\n");
        }
    }
    value
}

// --- Validation ---------------------------------------------------------------------------

/// `\\server\share`: two backslashes, a server name without `\/:*?"<>|`, a backslash, a
/// share.
fn unc(path: &str) -> bool {
    let Some(rest) = path.strip_prefix("\\\\") else {
        return false;
    };
    let Some((server, share)) = rest.split_once('\\') else {
        return false;
    };
    !server.is_empty()
        && !server.chars().any(|c| "\\/:*?\"<>|".contains(c))
        && !share.is_empty()
        && !share.starts_with('\\')
}

fn shortcut_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('\\');
    trimmed.rsplit('\\').next().unwrap_or(trimmed)
}

fn port_ok(port: &str) -> bool {
    let upper = port.to_uppercase();
    (upper.starts_with("LPT") || upper.starts_with("COM"))
        && upper.len() == 4
        && upper
            .chars()
            .nth(3)
            .is_some_and(|c| ('1'..='9').contains(&c))
}

fn has_protocol(target: &str) -> bool {
    let mut chars = target.chars();
    if !chars.next().is_some_and(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    for c in chars {
        if c == ':' {
            return true;
        }
        if !(c.is_ascii_alphanumeric() || "+.-".contains(c)) {
            return false;
        }
    }
    false
}

/// What prevents saving the form, by field; empty if nothing (`valider`).
pub fn validate(form: &Form, part: Part) -> Vec<Problem> {
    let mut pb = Vec::new();
    if !gpp::ACTIONS.contains(&form.action()) {
        pb.push(problem("action", tr("Unknown action.")));
    }
    let user = part == Part::User;
    match form {
        Form::Drive(f) => {
            let path = f.path.trim();
            if f.action != "D" && path.is_empty() {
                pb.push(problem("chemin", tr("Enter the share location.")));
            } else if !path.is_empty() && !unc(path) {
                pb.push(problem(
                    "chemin",
                    tr("A share is written \\\\server\\share."),
                ));
            }
            let mut letters = f.letter.chars();
            if !(letters.next().is_some_and(|c| c.is_ascii_alphabetic())
                && letters.next().is_none())
            {
                pb.push(problem("lettre", tr("A letter from A to Z.")));
            }
            if !DISPLAY.contains(&f.this_drive.as_str())
                || !DISPLAY.contains(&f.all_drives.as_str())
            {
                pb.push(problem("affichage", tr("Unknown display option.")));
            }
            if !user {
                pb.push(problem(
                    "partie",
                    tr("Mapped drives exist only in User Configuration."),
                ));
            }
        }
        Form::Printer(f) => {
            let path = f.path.trim();
            if !(f.action == "D" && f.delete_all) && path.is_empty() {
                pb.push(problem("chemin", tr("Enter the printer share.")));
            } else if !path.is_empty() && !unc(path) {
                pb.push(problem(
                    "chemin",
                    tr("A shared printer is written \\\\server\\name."),
                ));
            }
            if !f.port.is_empty() && !port_ok(&f.port) {
                pb.push(problem(
                    "port",
                    tr("Local port: LPT1 to LPT9 or COM1 to COM9."),
                ));
            }
            if !user {
                pb.push(problem(
                    "partie",
                    tr("Shared printers exist only in User Configuration."),
                ));
            }
        }
        Form::Shortcut(f) => {
            let path = f.path.trim();
            let lower = path.to_lowercase();
            if path.is_empty() || path.ends_with('\\') || shortcut_name(path).is_empty() {
                pb.push(problem(
                    "chemin",
                    tr("Enter the location and name of the shortcut."),
                ));
            } else if lower.ends_with(".lnk") || lower.ends_with(".url") {
                pb.push(problem(
                    "chemin",
                    tr("Without extension: it is added when the shortcut is applied."),
                ));
            }
            if !TARGET_KINDS.contains(&f.kind.as_str()) {
                pb.push(problem("genre", tr("Target type not supported here.")));
            }
            if f.action != "D" {
                if f.target.trim().is_empty() {
                    pb.push(problem("cible", tr("Enter the shortcut target.")));
                } else if f.kind == "URL" && !has_protocol(&f.target) {
                    pb.push(problem("cible", tr("An address starts with its protocol.")));
                }
            }
            if !WINDOWS.contains(&f.window.as_str()) {
                pb.push(problem("fenetre", tr("Unknown window size.")));
            }
            if f.icon_index.is_empty() || !f.icon_index.chars().all(|c| c.is_ascii_digit()) {
                pb.push(problem("indice_icone", tr("A non-negative integer.")));
            }
        }
        Form::Registry(f) => {
            if !HIVES.contains(&f.hive.as_str()) {
                pb.push(problem("ruche", tr("Unknown hive.")));
            }
            let key = f.key.trim();
            if key.is_empty() {
                pb.push(problem("cle", tr("Enter the key path.")));
            } else if key.starts_with('\\') || key.ends_with('\\') || key.contains("\\\\") {
                pb.push(problem(
                    "cle",
                    tr("Key path without a leading or trailing backslash."),
                ));
            }
            if !REGISTRY_TYPES.contains(&f.rtype.as_str()) {
                pb.push(problem("type", tr("Unknown value type.")));
            } else if f.action != "D"
                && (!f.name.is_empty() || f.default)
                && let Err(e) = encode_data(f)
            {
                pb.push(problem("donnees", e));
            }
        }
    }
    pb
}

fn integer(text: &str, decimal: bool, bits: u32) -> Result<u64, String> {
    let t = text.trim();
    let (negative, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let rest = if decimal {
        rest
    } else {
        rest.strip_prefix("0x")
            .or_else(|| rest.strip_prefix("0X"))
            .unwrap_or(rest)
    };
    let parsed = if rest.is_empty() || rest.starts_with(['+', '-']) {
        None
    } else {
        i128::from_str_radix(rest, if decimal { 10 } else { 16 }).ok()
    };
    let Some(n) = parsed.map(|n| if negative { -n } else { n }) else {
        return Err(if decimal {
            tr("A decimal integer.")
        } else {
            tr("A hexadecimal integer.")
        });
    };
    if !(0..(1i128 << bits)).contains(&n) {
        return Err(fill(
            &tr("Integer out of range ({bits} bits)."),
            &[("bits", &bits.to_string())],
        ));
    }
    u64::try_from(n).map_err(|e| e.to_string())
}

/// (`value`, values of a REG_MULTI_SZ); an error if the data do not suit (`_encoder_donnees`).
fn encode_data(f: &RegistryForm) -> Result<(String, Vec<String>), String> {
    match f.rtype.as_str() {
        "REG_DWORD" => Ok((
            format!("{:08X}", integer(&f.data, f.decimal, 32)?),
            Vec::new(),
        )),
        "REG_QWORD" => Ok((
            format!("{:016X}", integer(&f.data, f.decimal, 64)?),
            Vec::new(),
        )),
        "REG_BINARY" => {
            let digits: String = f.data.chars().filter(|c| !c.is_whitespace()).collect();
            if digits.len() % 2 != 0 || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(tr("Hexadecimal bytes (two digits per byte)."));
            }
            Ok((digits.to_uppercase(), Vec::new()))
        }
        "REG_MULTI_SZ" => {
            let text = f.data.replace("\r\n", "\n");
            let mut lines: Vec<String> = text.split('\n').map(str::to_owned).collect();
            while lines.last().is_some_and(String::is_empty) {
                lines.pop();
            }
            Ok((lines.join(" "), lines))
        }
        _ => Ok((f.data.clone(), Vec::new())),
    }
}

/// Common options: « remove this item when it is no longer applied » only goes with the
/// action « Replace », as in the console (`valider_commun`).
pub fn validate_common(common: &Common, action: &str) -> Vec<Problem> {
    if common.remove_when_not_applied && action != "R" {
        return vec![problem(
            "retirer",
            tr("“Remove when no longer applied” requires the “Replace” action."),
        )];
    }
    Vec::new()
}

// --- Form → element -----------------------------------------------------------------------

type Properties = Vec<(String, String)>;

fn props(list: &[(&str, &str)]) -> Properties {
    list.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// What a form gives: name, status, Properties in the order of the console, children of
/// Properties.
type Built = (String, String, Properties, Option<Vec<Node>>);

/// The parts of an element made from a form (`_proprietes`).
fn properties(form: &Form) -> Result<Built, String> {
    Ok(match form {
        Form::Drive(f) => {
            let letter = f.letter.to_uppercase();
            let name = format!("{letter}:");
            (
                name.clone(),
                name,
                props(&[
                    ("action", &f.action),
                    ("thisDrive", &f.this_drive),
                    ("allDrives", &f.all_drives),
                    ("userName", ""),
                    ("path", f.path.trim()),
                    ("label", &f.label),
                    ("persistent", bit(f.reconnect)),
                    ("useLetter", bit(!f.first_free)),
                    ("letter", &letter),
                ]),
                None,
            )
        }
        Form::Printer(f) => {
            let path = f.path.trim();
            let name = if path.is_empty() {
                tr("All")
            } else {
                shortcut_name(path).to_owned()
            };
            (
                name.clone(),
                name,
                props(&[
                    ("action", &f.action),
                    ("comment", &f.comment),
                    ("path", path),
                    ("location", &f.location),
                    ("default", bit(f.default)),
                    ("skipLocal", bit(f.only_without_local)),
                    ("deleteAll", bit(f.delete_all)),
                    ("persistent", bit(f.reconnect)),
                    ("deleteMaps", bit(f.delete_port)),
                    ("port", &f.port.to_uppercase()),
                ]),
                None,
            )
        }
        Form::Shortcut(f) => {
            let path = f.path.trim();
            let name = shortcut_name(path).to_owned();
            let index = if f.icon_index.is_empty() {
                "0"
            } else {
                &f.icon_index
            };
            (
                name.clone(),
                name,
                props(&[
                    ("pidl", ""),
                    ("targetType", &f.kind),
                    ("action", &f.action),
                    ("comment", &f.comment),
                    ("shortcutKey", "0"),
                    ("startIn", &f.start_in),
                    ("arguments", &f.arguments),
                    ("iconIndex", index),
                    ("targetPath", f.target.trim()),
                    ("iconPath", &f.icon),
                    ("window", &f.window),
                    ("shortcutPath", path),
                ]),
                None,
            )
        }
        Form::Registry(f) => {
            let key = f.key.trim();
            let value_name = if f.default { "" } else { f.name.as_str() };
            let (name, status) = if value_name.is_empty() {
                (
                    key.to_owned(),
                    if f.default {
                        "(Default)".to_owned()
                    } else {
                        key.to_owned()
                    },
                )
            } else {
                (value_name.to_owned(), value_name.to_owned())
            };
            let (mut value, mut values) = (String::new(), Vec::new());
            let mut rtype = f.rtype.clone();
            if f.action != "D" && (!value_name.is_empty() || f.default) {
                (value, values) = encode_data(f)?;
            } else if value_name.is_empty() && !f.default {
                "REG_SZ".clone_into(&mut rtype); // element of a key, as the GroupPolicy module
            }
            let mut children = Vec::new();
            if !values.is_empty() {
                let mut container = Node::new("Values");
                for v in &values {
                    let mut child = Node::new("Value");
                    child.text.clone_from(v);
                    container.children.push(child);
                }
                children.push(container);
            }
            let decimal = f.decimal && (rtype == "REG_DWORD" || rtype == "REG_QWORD");
            (
                name,
                status,
                props(&[
                    ("action", &f.action),
                    ("displayDecimal", bit(decimal)),
                    ("default", bit(f.default)),
                    ("hive", &f.hive),
                    ("key", key),
                    ("name", value_name),
                    ("type", &rtype),
                    ("value", &value),
                ]),
                Some(children),
            )
        }
    })
}

/// The element of the codec: new (`old` `None`, `uid` given) or `old` changed (same `uid`,
/// unknowns kept, `cpassword` removed and with it the account) (`vers_element`).
pub fn to_element(
    family: Family,
    form: &Form,
    common: &Common,
    filters: &[Filter],
    old: Option<&Element>,
    uid: &str,
    instant: i64,
) -> Result<Element, String> {
    let (name, status, mut properties, children) = properties(form)?;
    let Some(old) = old else {
        return Ok(gpp::new_element(
            family,
            &name,
            &status,
            &properties,
            common,
            filters,
            uid,
            instant,
            &children.unwrap_or_default(),
        ));
    };
    if !old.has_password() {
        // The form does not show the account: the one there stays, unless it went with a
        // stored password (removed, and the account with it).
        properties.retain(|(k, _)| k != "userName");
    }
    let children = matches!(form, Form::Registry(_)).then(|| children.unwrap_or_default());
    Ok(gpp::modify_element(
        old,
        &name,
        &status,
        &properties,
        common,
        filters,
        instant,
        children.as_deref(),
    ))
}

// --- Lists and targeting ------------------------------------------------------------------

/// A row of the list of a family (`Ligne`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub title: String,
    pub subtitle: String,
    pub action: String,
    pub targeting: String,
    pub editable: bool,
    pub alert: String,
}

impl Row {
    pub fn accessible(&self) -> String {
        [
            &self.title,
            &self.action,
            &self.subtitle,
            &self.targeting,
            &self.alert,
        ]
        .iter()
        .filter(|m| !m.is_empty())
        .map(|m| m.as_str())
        .collect::<Vec<_>>()
        .join(", ")
    }
}

fn summary(family: Family, e: &Element) -> String {
    if e.tag() != family.description().tag {
        return fill(
            &tr("{balise} (cannot be edited here)"),
            &[("balise", e.tag())],
        );
    }
    match family {
        Family::Drives => {
            let path = prop(e, "path", "");
            if path.is_empty() {
                prop(e, "label", "")
            } else {
                path
            }
        }
        Family::Printers => prop(e, "path", ""),
        Family::Shortcuts => fill(
            &tr("{chemin} → {cible}"),
            &[
                ("chemin", &prop(e, "shortcutPath", "")),
                ("cible", &prop(e, "targetPath", "")),
            ],
        ),
        Family::Registry => {
            let default = prop(e, "default", "") == "1";
            let mut name = prop(e, "name", "");
            if name.is_empty() && default {
                name = tr("(Default)");
            }
            let path = format!("{}\\{}", prop(e, "hive", ""), prop(e, "key", ""));
            if name.is_empty() && !default {
                return path;
            }
            fill(
                &tr("{chemin}: {nom} = {valeur}"),
                &[
                    ("chemin", &path),
                    ("nom", &name),
                    ("valeur", &prop(e, "value", "")),
                ],
            )
        }
    }
}

pub fn row(family: Family, element: &Element) -> Row {
    let editable = element.editable(family.description());
    let mut title = if element.name().is_empty() {
        element.tag().to_owned()
    } else {
        element.name().to_owned()
    };
    if element.disabled() {
        title = fill(&tr("{titre} (disabled)"), &[("titre", &title)]);
    }
    Row {
        title,
        subtitle: summary(family, element),
        action: action_name(&element.action()),
        targeting: filters_summary(&element.filters()),
        editable,
        alert: if element.has_password() {
            tr("Stored password (MS14-025)")
        } else {
            String::new()
        },
    }
}

/// A filter in clear, without the logical link with the previous one (`texte_filtre`).
pub fn filter_text(f: &Filter) -> String {
    let f = match f {
        Filter::Raw(n) => {
            return fill(
                &tr("{balise} (cannot be edited here)"),
                &[("balise", &n.tag)],
            );
        }
        Filter::Editable(f) => f,
    };
    let not = f.negation();
    let who = || {
        if f.get_or("userContext", "1") == "1" {
            tr("the user")
        } else {
            tr("the computer")
        }
    };
    match f.target {
        Target::Group => {
            let template = if not {
                tr("{qui} is not a member of {nom}")
            } else {
                tr("{qui} is a member of {nom}")
            };
            fill(&template, &[("qui", &who()), ("nom", f.name())])
        }
        Target::Ou => {
            let template = if not {
                tr("{qui} is not in the OU {nom}")
            } else {
                tr("{qui} is in the OU {nom}")
            };
            let text = fill(&template, &[("qui", &who()), ("nom", f.name())]);
            if f.get_or("directMember", "0") == "1" {
                fill(&tr("{texte} (direct member)"), &[("texte", &text)])
            } else {
                text
            }
        }
        Target::Computer => {
            let template = if not {
                tr("the computer name is not {nom}")
            } else {
                tr("the computer name is {nom}")
            };
            fill(&template, &[("nom", f.name())])
        }
        Target::User => {
            let template = if not {
                tr("the user is not {nom}")
            } else {
                tr("the user is {nom}")
            };
            fill(&template, &[("nom", f.name())])
        }
    }
}

/// Each filter preceded by « and » or « or » (but the first), as the console
/// (`textes_filtres`).
pub fn filters_texts(filters: &[Filter]) -> Vec<String> {
    filters
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let t = filter_text(f);
            if i == 0 {
                t
            } else if f.or() {
                fill(&tr("or {filtre}"), &[("filtre", &t)])
            } else {
                fill(&tr("and {filtre}"), &[("filtre", &t)])
            }
        })
        .collect()
}

pub fn filters_summary(filters: &[Filter]) -> String {
    if filters.is_empty() {
        return String::new();
    }
    fill(
        &tr("Targeting: {filtres}"),
        &[("filtres", &filters_texts(filters).join(" "))],
    )
}

fn base(or: bool, not: bool) -> [(&'static str, &'static str); 2] {
    [("bool", if or { "OR" } else { "AND" }), ("not", bit(not))]
}

pub fn group_filter(name: &str, sid: &str, computer: bool, not: bool, or: bool) -> Filter {
    let [b, n] = base(or, not);
    Filter::Editable(EditableFilter::new(
        Target::Group,
        &[
            b,
            n,
            ("name", name),
            ("sid", sid),
            ("userContext", bit(!computer)),
        ],
    ))
}

pub fn ou_filter(dn: &str, computer: bool, direct: bool, not: bool, or: bool) -> Filter {
    let [b, n] = base(or, not);
    Filter::Editable(EditableFilter::new(
        Target::Ou,
        &[
            b,
            n,
            ("name", dn),
            ("userContext", bit(!computer)),
            ("directMember", bit(direct)),
        ],
    ))
}

pub fn computer_filter(name: &str, dns: bool, not: bool, or: bool) -> Filter {
    let [b, n] = base(or, not);
    Filter::Editable(EditableFilter::new(
        Target::Computer,
        &[
            b,
            n,
            ("type", if dns { "DNS" } else { "NETBIOS" }),
            ("name", name),
        ],
    ))
}

pub fn user_filter(name: &str, sid: &str, not: bool, or: bool) -> Filter {
    let [b, n] = base(or, not);
    Filter::Editable(EditableFilter::new(
        Target::User,
        &[b, n, ("name", name), ("sid", sid)],
    ))
}

/// Text of the banner if a file carries a `cpassword`; empty otherwise
/// (`alerte_mots_de_passe`).
pub fn passwords_alert(documents: &[(Part, &Document)]) -> String {
    let mut places = Vec::new();
    for (part, doc) in documents {
        for e in doc.passwords() {
            places.push(fill(
                &tr("{famille} “{nom}” ({partie})"),
                &[
                    ("famille", &family_name(doc.family)),
                    ("nom", e.name()),
                    ("partie", &part_name(*part)),
                ],
            ));
        }
    }
    if places.is_empty() {
        return String::new();
    }
    fill(
        &tr(
            "Password stored in a preference: {lieux}. It is encrypted with a key published by Microsoft (MS14-025) and readable by any domain user: edit the item (the password will be removed) and change that password.",
        ),
        &[("lieux", &places.join(", "))],
    )
}

#[cfg(test)]
mod tests;

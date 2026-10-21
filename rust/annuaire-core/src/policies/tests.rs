// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Settings of ADMX policies in a `Registry.pol` (`test_strategies.py`).

use super::*;
use crate::admx::tests::store;

const KEY: &str = "Software\\Policies\\Annuaire\\Essai";
const OPT: &str = "Software\\Policies\\Annuaire\\Options";

fn dword_entry(key: &str, name: &str, v: u32) -> Entry {
    entry(key, name, rp::REG_DWORD, v.to_le_bytes().to_vec())
}

fn sz(key: &str, name: &str, v: &str) -> Entry {
    entry(key, name, rp::REG_SZ, text_data(v))
}

fn del(key: &str, name: &str) -> Entry {
    entry(
        key,
        &format!("**del.{name}"),
        rp::REG_SZ,
        rp::DEL_DATA.to_vec(),
    )
}

fn view(entries: &[Entry]) -> Vec<(String, String, String, RegValue)> {
    entries
        .iter()
        .map(|e| {
            (
                e.key.clone(),
                e.value_name.clone(),
                e.type_name(),
                e.interpret().unwrap(),
            )
        })
        .collect()
}

fn t(s: &str) -> RegValue {
    RegValue::Text(s.into())
}

#[test]
fn values_enabled_disabled() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Valeurs").unwrap();
    let enabled = setting_entries(s, &Setting::new(State::Enabled));
    assert_eq!(
        view(&enabled),
        [
            (
                KEY.into(),
                "Mode".into(),
                "DWORD".into(),
                RegValue::Integer(2)
            ),
            (
                format!("{KEY}\\Liste"),
                "Active".into(),
                "SZ".into(),
                t("oui")
            ),
            (
                "Software\\Policies\\Annuaire\\Autre".into(),
                "Niveau".into(),
                "QWORD".into(),
                RegValue::Integer(5_000_000_000)
            ),
        ]
    );
    assert_eq!(read(s, &enabled), Setting::new(State::Enabled));
    let disabled = setting_entries(s, &Setting::new(State::Disabled));
    let v: Vec<(String, String, RegValue)> = view(&disabled)
        .into_iter()
        .map(|(k, n, _, v)| (k, n, v))
        .collect();
    assert_eq!(
        v,
        [
            (KEY.into(), "Mode".into(), RegValue::Integer(0)),
            (format!("{KEY}\\Liste"), "**del.Active".into(), t(" ")),
        ]
    );
    assert_eq!(read(s, &disabled).state, State::Disabled);
    assert_eq!(read(s, &[]).state, State::NotConfigured);
    // A value the ADMX does not plan: configured, but neither one nor the other.
    assert_eq!(
        read(s, &[dword_entry(KEY, "Mode", 9)]).state,
        State::Undetermined
    );
    // Only the « enabled » list: enabled anyway.
    assert_eq!(read(s, &enabled[1..]).state, State::Enabled);
}

#[test]
fn simple_value_by_default() {
    // Without `enabledValue` nor `disabledValue`: REG_DWORD 1, and `**del.` to disable.
    let m = store();
    let s = m.policy("Annuaire.Essai.Socle:Simple").unwrap();
    let key = "Software\\Policies\\Annuaire\\Socle";
    assert_eq!(
        setting_entries(s, &Setting::new(State::Enabled)),
        [dword_entry(key, "Simple", 1)]
    );
    assert_eq!(
        setting_entries(s, &Setting::new(State::Disabled)),
        [del(key, "Simple")]
    );
    assert_eq!(
        read(s, &[dword_entry(&key.to_uppercase(), "SIMPLE", 1)]).state,
        State::Enabled
    );
    assert_eq!(read(s, &[del(key, "Simple")]).state, State::Disabled);
    // Replayed in order: the last entry wins.
    assert_eq!(
        read(s, &[dword_entry(key, "Simple", 1), del(key, "Simple")]).state,
        State::Disabled
    );
    assert_eq!(
        read(s, &[del(key, "Simple"), dword_entry(key, "Simple", 1)]).state,
        State::Enabled
    );
}

fn options() -> Options {
    let texts = |v: &[&str]| OptionValue::Texts(v.iter().map(|x| (*x).to_owned()).collect());
    [
        ("Case", OptionValue::Bool(true)),
        ("CaseValeurs", OptionValue::Bool(true)),
        ("Nombre", OptionValue::Int(42)),
        ("NombreTexte", OptionValue::Int(300)),
        ("Grand", OptionValue::Int(8_000_000_000)),
        ("Texte", OptionValue::Text("court".into())),
        ("Chemin", OptionValue::Text("%windir%\\x".into())),
        ("Choix", OptionValue::Int(1)),
        ("Liste", texts(&["a", "b"])),
        (
            "Noms",
            OptionValue::Pairs(vec![("n1".into(), "v1".into()), ("n2".into(), "v2".into())]),
        ),
        ("Brute", texts(&["x", "y"])),
        ("Lignes", texts(&["l1", "l2"])),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), Some(v)))
    .collect()
}

#[test]
fn options_round_trip() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Options").unwrap();
    let setting = Setting {
        state: State::Enabled,
        options: options(),
    };
    let entries = setting_entries(s, &setting);
    let n = |v: u64| RegValue::Integer(v);
    let liste = format!("{OPT}\\Liste");
    let noms = format!("{OPT}\\Noms");
    let brute = format!("{OPT}\\Brute");
    let wanted: Vec<(String, &str, &str, RegValue)> = vec![
        (OPT.into(), "Case", "DWORD", n(1)),
        (OPT.into(), "CaseValeurs", "SZ", t("vrai")),
        (format!("{OPT}\\Vrai"), "Aussi", "DWORD", n(1)),
        (OPT.into(), "Nombre", "DWORD", n(42)),
        (OPT.into(), "NombreTexte", "SZ", t("300")),
        (OPT.into(), "Grand", "QWORD", n(8_000_000_000)),
        (OPT.into(), "Texte", "SZ", t("court")),
        (
            "Software\\Policies\\Annuaire\\Chemins".into(),
            "Chemin",
            "EXPAND_SZ",
            t("%windir%\\x"),
        ),
        (OPT.into(), "Choix", "SZ", t("deux")),
        (OPT.into(), "Extra", "DWORD", n(7)),
        (liste.clone(), "**delvals.", "SZ", t(" ")),
        (liste.clone(), "Element1", "SZ", t("a")),
        (liste, "Element2", "SZ", t("b")),
        (noms.clone(), "n1", "SZ", t("v1")),
        (noms, "n2", "SZ", t("v2")),
        (brute.clone(), "**delvals.", "SZ", t(" ")),
        (brute.clone(), "x", "SZ", t("x")),
        (brute, "y", "SZ", t("y")),
        (
            OPT.into(),
            "Lignes",
            "MULTI_SZ",
            RegValue::Texts(vec!["l1".into(), "l2".into()]),
        ),
    ];
    let wanted: Vec<(String, String, String, RegValue)> = wanted
        .into_iter()
        .map(|(k, a, b, v)| (k, a.to_owned(), b.to_owned(), v))
        .collect();
    assert_eq!(view(&entries), wanted);
    let again = read(s, &entries);
    assert_eq!(again.state, State::Enabled);
    assert_eq!(again.options, options());
}

#[test]
fn unchecked_boxes_and_choice() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Options").unwrap();
    let mut o = options();
    o.insert("Case".into(), Some(OptionValue::Bool(false)));
    o.insert("CaseValeurs".into(), Some(OptionValue::Bool(false)));
    o.insert("Choix".into(), Some(OptionValue::Int(2)));
    let entries = setting_entries(
        s,
        &Setting {
            state: State::Enabled,
            options: o,
        },
    );
    let by_name: HashMap<(String, String), &Entry> = entries
        .iter()
        .map(|e| ((e.key.clone(), e.value_name.clone()), e))
        .collect();
    // Unchecked without falseValue: **del., as Windows.
    assert!(by_name.contains_key(&(OPT.to_owned(), "**del.Case".to_owned())));
    assert_eq!(
        read_option(
            &s.elements[0],
            &Registry::new(&[dword_entry(OPT, "Case", 0)])
        ),
        Some(OptionValue::Bool(false))
    );
    assert_eq!(
        by_name[&(OPT.to_owned(), "CaseValeurs".to_owned())]
            .interpret()
            .unwrap(),
        t("faux")
    );
    assert!(!by_name.contains_key(&(format!("{OPT}\\Vrai"), "Aussi".to_owned())));
    // Choice « None »: <delete/>.
    assert!(by_name.contains_key(&(OPT.to_owned(), "**del.Choix".to_owned())));
    let again = read(s, &entries);
    assert_eq!(again.option("Case"), Some(&OptionValue::Bool(false)));
    assert_eq!(again.option("CaseValeurs"), Some(&OptionValue::Bool(false)));
    assert_eq!(again.option("Choix"), Some(&OptionValue::Int(2)));
}

#[test]
fn options_disabled() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Options").unwrap();
    let entries = setting_entries(s, &Setting::new(State::Disabled));
    let names: Vec<(String, String)> = entries
        .iter()
        .map(|e| (e.key.clone(), e.value_name.clone()))
        .collect();
    let has = |k: &str, n: &str| names.contains(&(k.to_owned(), n.to_owned()));
    assert!(has(OPT, "**del.Case"));
    assert!(has(OPT, "CaseValeurs"));
    assert!(has(&format!("{OPT}\\Liste"), "**delvals."));
    assert!(has(OPT, "**del.Nombre"));
    assert_eq!(read(s, &entries).state, State::Disabled);
}

#[test]
fn modify_keeps_the_rest() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Valeurs").unwrap();
    let other = dword_entry("Software\\Inconnu", "X", 3);
    let before = vec![
        other.clone(),
        dword_entry(KEY, "Mode", 0),
        sz(&format!("{KEY}\\Liste"), "Active", "non"),
        other.clone(),
    ];
    let after = modify(&before, s, &Setting::new(State::Enabled));
    assert_eq!(after[..2], [other.clone(), other.clone()]);
    assert_eq!(read(s, &after).state, State::Enabled);
    assert_eq!(
        modify(&after, s, &Setting::new(State::NotConfigured)),
        [other.clone(), other]
    );
}

#[test]
fn extra_and_configured() {
    let m = store();
    let known = store_footprint(&m, Class::User);
    let unknown = dword_entry("Software\\Inconnu", "X", 3);
    let list = sz(&format!("{OPT}\\Liste"), "Element9", "z");
    let machine = dword_entry(KEY, "Mode", 2);
    let entries = vec![
        unknown.clone(),
        list,
        machine.clone(),
        dword_entry("Software\\Policies\\Annuaire\\Socle", "Simple", 1),
    ];
    assert_eq!(extra(&known, &entries), [unknown, machine]);
    let set = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<HashSet<_>>();
    assert_eq!(
        configured(&m, Class::User, &entries),
        set(&["Annuaire.Essai:Options", "Annuaire.Essai.Socle:Simple"])
    );
    assert_eq!(
        configured(&m, Class::Machine, &entries),
        set(&["Annuaire.Essai:Valeurs", "Annuaire.Essai.Socle:Simple"])
    );
}

#[test]
fn defaults_and_validation() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Options").unwrap();
    let d = default_options(s);
    let get = |k: &str| d.get(k).cloned().flatten();
    assert_eq!(get("Case"), Some(OptionValue::Bool(true)));
    assert_eq!(get("CaseValeurs"), Some(OptionValue::Bool(false)));
    assert_eq!(get("Nombre"), Some(OptionValue::Int(5)));
    assert_eq!(get("NombreTexte"), Some(OptionValue::Int(1)));
    assert_eq!(get("Grand"), Some(OptionValue::Int(4_000_000_000)));
    assert_eq!(get("Texte"), Some(OptionValue::Text("abc".into())));
    assert_eq!(get("Chemin"), Some(OptionValue::Text("%windir%".into())));
    assert_eq!(get("Choix"), Some(OptionValue::Int(1)));
    assert_eq!(get("Liste"), Some(OptionValue::Texts(vec![])));
    assert!(validate(s, &d).is_empty());
    let mut bad = d.clone();
    bad.insert("Nombre".into(), Some(OptionValue::Int(100)));
    bad.insert("Texte".into(), Some(OptionValue::Text("x".repeat(11))));
    bad.insert("Choix".into(), None);
    bad.insert(
        "Lignes".into(),
        Some(OptionValue::Texts(vec![
            "a".into(),
            "b".into(),
            "c".into(),
            "d".into(),
        ])),
    );
    bad.insert(
        "Noms".into(),
        Some(OptionValue::Pairs(vec![
            ("a".into(), "1".into()),
            ("A".into(), "2".into()),
        ])),
    );
    let errors = validate(s, &bad);
    let keys: Vec<&str> = errors.keys().map(String::as_str).collect();
    assert_eq!(keys, ["Choix", "Lignes", "Nombre", "Noms", "Texte"]);
    assert_eq!(errors["Nombre"], OptionError::Range { min: 1, max: 99 });
    let with = |k: &str, v: Option<OptionValue>| {
        let mut o = d.clone();
        o.insert(k.into(), v);
        validate(s, &o)
    };
    assert_eq!(with("Nombre", None)["Nombre"], OptionError::Required);
    assert_eq!(
        with(
            "Noms",
            Some(OptionValue::Pairs(vec![(String::new(), "1".into())]))
        )["Noms"],
        OptionError::NameRequired
    );
    assert!(with("Grand", Some(OptionValue::Int(9_000_000_001))).contains_key("Grand"));
}

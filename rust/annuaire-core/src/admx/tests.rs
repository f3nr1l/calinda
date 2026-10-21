// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! ADMX and ADML (`test_admx.py`), on the two templates written for the tests
//! (`tests/modeles/`): every element, value lists, a parent category in another file, an ADML
//! in English only.

use std::path::PathBuf;

use super::*;

pub(crate) fn templates() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/modeles")
}

pub(crate) fn files(language: &str) -> Vec<TemplateFile> {
    let mut names: Vec<String> = std::fs::read_dir(templates())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".admx"))
        .collect();
    names.sort();
    names
        .into_iter()
        .map(|name| {
            let stem = name.trim_end_matches(".admx");
            let adml = [language, "en-US"].iter().find_map(|lg| {
                std::fs::read(templates().join(lg).join(format!("{stem}.adml"))).ok()
            });
            (
                name.clone(),
                std::fs::read(templates().join(&name)).unwrap(),
                adml,
            )
        })
        .collect()
}

pub(crate) fn store() -> Store {
    analyze(&files("fr-FR"), "fr-FR")
}

fn names(policies: &[&Policy]) -> Vec<String> {
    policies.iter().map(|p| p.name.clone()).collect()
}

#[test]
fn categories_across_files() {
    let m = store();
    let options = m.category("Annuaire.Essai:Options").unwrap();
    assert_eq!(options.label, "Options d'essai");
    assert_eq!(
        options.parent.as_deref(),
        Some("Annuaire.Essai.Socle:Systeme")
    );
    let path: Vec<&str> = m
        .path(Some(&options.ident))
        .iter()
        .map(|c| c.label.as_str())
        .collect();
    assert_eq!(path, ["Root", "System", "Options d'essai"]);
    // Parent not found: at the root.
    assert_eq!(m.category("Annuaire.Essai:Orpheline").unwrap().parent, None);
    assert_eq!(
        m.category("Annuaire.Essai.Socle:Systeme").unwrap().explain,
        "System settings."
    );
    assert!(m.errors.is_empty(), "{:?}", m.errors);
}

#[test]
fn tree_by_part() {
    let m = store();
    let roots = |part| {
        m.subcategories(None, Some(part))
            .iter()
            .map(|c| c.label.clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(roots(Class::Machine), ["Catégorie sans parent", "Root"]);
    assert_eq!(roots(Class::User), ["Root"]);
    assert_eq!(
        names(&m.policies_of(Some("Annuaire.Essai:Options"), Some(Class::Machine))),
        ["Valeurs"]
    );
    assert_eq!(
        names(&m.policies_of(Some("Annuaire.Essai:Options"), Some(Class::User))),
        ["Options"]
    );
    assert_eq!(
        names(&m.policies_of(Some("Annuaire.Essai.Socle:Racine"), Some(Class::Machine))),
        ["Simple"]
    );
    assert!(Class::Both.applies_to(Class::User));
}

#[test]
fn policy_values_and_lists() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Valeurs").unwrap();
    assert_eq!(s.class, Class::Machine);
    assert_eq!(s.label, "Valeurs et listes");
    assert!(s.explain.ends_with("Deuxième ligne de l'explication."));
    assert_eq!(s.supported, "Every version");
    assert_eq!(
        (s.key.as_str(), s.value_name.as_str()),
        ("Software\\Policies\\Annuaire\\Essai", "Mode")
    );
    assert_eq!(s.enabled_value, Some(AdmxValue::Decimal(2)));
    assert_eq!(s.disabled_value, Some(AdmxValue::Decimal(0)));
    assert_eq!(
        s.enabled_list,
        [
            ListItem {
                key: "Software\\Policies\\Annuaire\\Essai\\Liste".into(),
                value_name: "Active".into(),
                value: AdmxValue::String("oui".into()),
            },
            ListItem {
                key: "Software\\Policies\\Annuaire\\Autre".into(),
                value_name: "Niveau".into(),
                value: AdmxValue::Long(5_000_000_000),
            },
        ]
    );
    assert_eq!(s.disabled_list[0].value, AdmxValue::Delete);
}

#[test]
fn elements_and_presentation() {
    let m = store();
    let s = m.policy("Annuaire.Essai:Options").unwrap();
    let kinds: HashSet<ElementKind> = s.elements.iter().map(|e| e.kind).collect();
    assert_eq!(kinds.len(), ElementKind::ALL.len());
    let number = s.element("Nombre").unwrap();
    assert_eq!(
        (number.minimum, number.maximum, number.required),
        (1, 99, true)
    );
    let as_text = s.element("NombreTexte").unwrap();
    assert!(as_text.as_text && as_text.maximum == 500);
    assert_eq!(s.element("Grand").unwrap().maximum, 9_000_000_000);
    let path = s.element("Chemin").unwrap();
    assert!(path.expandable);
    assert_eq!(path.key, "Software\\Policies\\Annuaire\\Chemins");
    let text = s.element("Texte").unwrap();
    assert!(text.max_length == 10 && text.key == s.key);
    let check = s.element("CaseValeurs").unwrap();
    assert_eq!(check.true_value, Some(AdmxValue::String("vrai".into())));
    assert_eq!(check.false_value, Some(AdmxValue::String("faux".into())));
    assert_eq!(check.true_list[0].value_name, "Aussi");
    let choice = s.element("Choix").unwrap();
    let labels: Vec<&str> = choice.choices.iter().map(|c| c.label.as_str()).collect();
    assert_eq!(labels, ["Un", "Deux", "Aucun"]);
    assert_eq!(choice.choices[1].list[0].key, s.key);
    assert_eq!(choice.choices[2].value, Some(AdmxValue::Delete));
    let l = s.element("Liste").unwrap();
    assert!(l.prefix.as_deref() == Some("Element") && !l.explicit);
    let n = s.element("Noms").unwrap();
    assert!(n.explicit && n.additive && n.prefix.is_none());
    assert_eq!(s.element("Lignes").unwrap().max_strings, 3);
    assert_eq!(
        (s.presentation[0].kind, s.presentation[0].ref_id.as_str()),
        (ControlKind::Static, "")
    );
    let combo = s
        .presentation
        .iter()
        .find(|c| c.ref_id == "Chemin")
        .unwrap();
    assert_eq!(combo.kind, ControlKind::ComboBox);
    assert_eq!(combo.default.as_deref(), Some("%windir%"));
    assert_eq!(combo.suggestions, ["%temp%", "C:\\"]);
    assert!(!combo.sort);
    let n = s
        .presentation
        .iter()
        .find(|c| c.ref_id == "Nombre")
        .unwrap();
    assert_eq!((n.default.as_deref(), n.step), (Some("5"), 5));
    let t = s.presentation.iter().find(|c| c.ref_id == "Texte").unwrap();
    assert_eq!(
        (t.label.as_str(), t.default.as_deref()),
        ("Texte court", Some("abc"))
    );
}

#[test]
fn fallback_language() {
    let m = analyze(&files("de-DE"), "en-US");
    assert_eq!(
        m.policy("Annuaire.Essai:Valeurs").unwrap().label,
        "Values and lists"
    );
    // Without ADML: the identifiers, and the error said.
    let mut f = files("fr-FR");
    let essai = f.iter_mut().find(|x| x.0 == "essai.admx").unwrap();
    essai.2 = None;
    let m = analyze(&f, "");
    assert_eq!(m.policy("Annuaire.Essai:Valeurs").unwrap().label, "Valeurs");
    assert!(m.errors.iter().any(|e| e.contains("essai.admx")));
}

#[test]
fn unreadable_file_set_aside() {
    let mut f = files("fr-FR");
    f.push((
        "casse.admx".into(),
        b"<policyDefinitions><policies>".to_vec(),
        None,
    ));
    f.push(("autre.admx".into(), b"<racine/>".to_vec(), None));
    let m = analyze(&f, "");
    assert!(m.policy("Annuaire.Essai:Valeurs").is_some());
    assert_eq!(
        m.errors.iter().filter(|e| e.contains("casse.admx")).count(),
        2
    );
    assert!(
        m.errors
            .iter()
            .any(|e| e.contains("autre.admx") && e.contains("ADMX"))
    );
}

#[test]
fn adml_utf16_encoding_unicode() {
    // Some ADMLs of Microsoft are in UTF-16 and declare `encoding="unicode"`.
    let mut f = files("fr-FR");
    let essai = f.iter_mut().find(|x| x.0 == "essai.admx").unwrap();
    let text = String::from_utf8(essai.2.clone().unwrap())
        .unwrap()
        .replace("encoding=\"utf-8\"", "encoding=\"unicode\"");
    let mut utf16 = vec![0xff, 0xfe];
    utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
    essai.2 = Some(utf16);
    let m = analyze(&f, "");
    assert_eq!(
        m.policy("Annuaire.Essai:Valeurs").unwrap().label,
        "Valeurs et listes"
    );
}

#[test]
fn search() {
    let m = store();
    assert_eq!(names(&m.search("deuxieme LIGNE", None, None)), ["Valeurs"]);
    assert_eq!(names(&m.search("options", None, None)), ["Options"]);
    assert_eq!(names(&m.search("annuaire\\essai", None, None)), ["Valeurs"]);
    // Label first, then the rest; filter by part.
    assert_eq!(names(&m.search("stratégie", None, None)), ["Rangee"]);
    assert!(m.search("valeurs", Some(Class::User), None).is_empty());
    assert!(m.search("  ", None, None).is_empty());
    assert_eq!(normalize("Œuvre ÉCRAN"), "oeuvre ecran");
}

#[test]
fn preferred_and_chosen_languages() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    };
    assert_eq!(
        preferred_languages(&env(&[("LANG", "fr_FR.UTF-8")])),
        ["fr-FR", "en-US"]
    );
    assert_eq!(
        preferred_languages(&env(&[("LANGUAGE", "en:fr"), ("LANG", "fr_FR.UTF-8")])),
        ["en", "fr", "fr-FR", "en-US"]
    );
    assert_eq!(preferred_languages(&env(&[("LC_ALL", "C")])), ["en-US"]);
    let s = |v: &[&str]| v.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
    assert_eq!(
        choose_language(&s(&["en-US", "fr-FR"]), &s(&["fr-FR"])).as_deref(),
        Some("fr-FR")
    );
    assert_eq!(
        choose_language(&s(&["EN-us", "fr-CA"]), &s(&["fr"])).as_deref(),
        Some("fr-CA")
    );
    assert_eq!(
        choose_language(&s(&["de-DE", "en-US"]), &s(&["fr-FR"])).as_deref(),
        Some("en-US")
    );
    assert_eq!(
        choose_language(&s(&["de-DE"]), &s(&["fr-FR"])).as_deref(),
        Some("de-DE")
    );
    assert_eq!(choose_language(&[], &s(&["fr-FR"])), None);
}

#[test]
fn json_form() {
    let m = store();
    let text = serde_json::to_string(&to_json(&m)).unwrap();
    let again = from_json(&serde_json::from_str(&text).unwrap()).unwrap();
    assert_eq!(again.policies, m.policies);
    assert_eq!(again.categories, m.categories);
    assert_eq!(again.language, "fr-FR");
    assert!(from_json(&json!({"format": 0})).is_err());
    assert!(
        from_json(&json!({"format": FORMAT, "categories": [["x"]], "strategies": []})).is_err()
    );
}

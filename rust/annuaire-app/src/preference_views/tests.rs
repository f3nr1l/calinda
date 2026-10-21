// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Forms, validation and texts of the preferences (`test_vue_preferences.py`); the texts are
//! those of the source language (no catalogue in the tests).

#![allow(clippy::indexing_slicing)]

use std::path::PathBuf;

use serde_json::Value;

use super::*;

const INSTANT: i64 = 1_792_011_909;
const UID: &str = "{01234567-89AB-4CDE-8F01-23456789ABCD}";

fn doc(id: &str) -> Document {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vecteurs/preferences.json");
    let all: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let v = all["vecteurs"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == id)
        .unwrap();
    let hex = v["hex"].as_str().unwrap();
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let family = Family::ALL
        .into_iter()
        .find(|f| f.value() == v["attendu"]["famille"])
        .unwrap();
    gpp::read(&bytes, family).unwrap()
}

fn fields(form: &Form, part: Part) -> Vec<&'static str> {
    validate(form, part).iter().map(|p| p.field).collect()
}

fn drive(form: &Form) -> DriveForm {
    let Form::Drive(f) = form else { panic!() };
    f.clone()
}

#[test]
fn drive_form() {
    let d = doc("lecteurs-console");
    let e = d.elements()[0].clone();
    let f = drive(&form(Family::Drives, Some(&e), Part::User));
    assert_eq!(
        f,
        DriveForm {
            path: "\\\\srv-fichiers\\Partage commun".into(),
            label: "Commun".into(),
            reconnect: true,
            ..DriveForm::default()
        }
    );
    let check = |change: &dyn Fn(&mut DriveForm), part: Part| {
        let mut g = f.clone();
        change(&mut g);
        fields(&Form::Drive(g), part)
    };
    assert!(check(&|_| {}, Part::User).is_empty());
    assert_eq!(check(&|g| g.path = "srv\\x".into(), Part::User), ["chemin"]);
    assert_eq!(check(&|g| g.path = String::new(), Part::User), ["chemin"]);
    assert!(
        check(
            &|g| {
                g.action = "D".into();
                g.path = String::new();
            },
            Part::User
        )
        .is_empty()
    );
    assert_eq!(check(&|g| g.letter = "Ž".into(), Part::User), ["lettre"]);
    assert_eq!(check(&|_| {}, Part::Computer), ["partie"]);
    // Changed: uid, filters and unknowns kept; properties in the original order.
    let mut g = f.clone();
    g.letter = "k".into();
    g.first_free = true;
    let m = to_element(
        Family::Drives,
        &Form::Drive(g),
        &e.common(),
        &e.filters(),
        Some(&e),
        "x",
        INSTANT,
    )
    .unwrap();
    assert!(m.uid() == e.uid() && m.name() == "K:" && m.status() == "K:");
    let wanted: Vec<(String, String)> = [
        ("action", "U"),
        ("thisDrive", "NOCHANGE"),
        ("allDrives", "NOCHANGE"),
        ("userName", ""),
        ("path", "\\\\srv-fichiers\\Partage commun"),
        ("label", "Commun"),
        ("persistent", "1"),
        ("useLetter", "0"),
        ("letter", "K"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    assert_eq!(m.properties(), wanted);
    assert_eq!(m.filters().len(), 6);
    let n = to_element(
        Family::Drives,
        &Form::Drive(DriveForm {
            path: "\\\\a\\b".into(),
            ..DriveForm::default()
        }),
        &Common::default(),
        &[],
        None,
        UID,
        INSTANT,
    )
    .unwrap();
    assert_eq!(n.uid(), UID);
    assert_eq!(n.node.get("image"), Some("2"));
    assert_eq!(n.node.get("bypassErrors"), Some("1"));
}

#[test]
fn drive_password_removed() {
    let d = doc("lecteurs-cpassword");
    let e = d.elements()[0].clone();
    let f = form(Family::Drives, Some(&e), Part::User);
    let m = to_element(Family::Drives, &f, &e.common(), &[], Some(&e), "", INSTANT).unwrap();
    assert!(!m.has_password() && m.property("userName").as_deref() == Some(""));
    let text = passwords_alert(&[(Part::User, &d)]);
    assert!(text.contains("MS14-025") && text.contains("P:") && !text.contains("RmFjdGljZ"));
    assert_eq!(
        passwords_alert(&[(Part::User, &doc("lecteurs-console"))]),
        ""
    );
    assert!(!row(Family::Drives, &e).alert.is_empty());
}

#[test]
fn printer_form() {
    let d = doc("imprimantes-console");
    let (e, other) = (d.elements()[0].clone(), d.elements()[1].clone());
    let Form::Printer(f) = form(Family::Printers, Some(&e), Part::User) else {
        panic!()
    };
    assert!(f.default && f.location == "Rez-de-chaussée");
    assert!(validate(&Form::Printer(f.clone()), Part::User).is_empty());
    let mut g = f.clone();
    g.port = "LPT0".into();
    assert_eq!(fields(&Form::Printer(g), Part::User), ["port"]);
    let mut g = f.clone();
    g.action = "D".into();
    g.delete_all = true;
    g.path = String::new();
    assert!(fields(&Form::Printer(g), Part::User).is_empty());
    let mut g = f.clone();
    g.path = "\\\\srv\\Compta".into();
    let m = to_element(
        Family::Printers,
        &Form::Printer(g),
        &e.common(),
        &[],
        Some(&e),
        "",
        INSTANT,
    )
    .unwrap();
    assert_eq!(m.name(), "Compta");
    assert!(!other.editable(Family::Printers.description()));
    assert!(
        row(Family::Printers, &other)
            .subtitle
            .contains("cannot be edited")
    );
}

#[test]
fn shortcut_form() {
    let d = doc("raccourcis-console");
    let e = d.elements()[1].clone();
    let Form::Shortcut(f) = form(Family::Shortcuts, Some(&e), Part::Computer) else {
        panic!()
    };
    assert_eq!(f.kind, "URL");
    assert!(validate(&Form::Shortcut(f.clone()), Part::Computer).is_empty());
    let check = |change: &dyn Fn(&mut ShortcutForm)| {
        let mut g = f.clone();
        change(&mut g);
        fields(&Form::Shortcut(g), Part::User)
    };
    assert_eq!(check(&|g| g.target = "intranet".into()), ["cible"]);
    assert_eq!(check(&|g| g.path = "%DesktopDir%\\".into()), ["chemin"]);
    assert_eq!(
        check(&|g| g.path = "%DesktopDir%\\x.lnk".into()),
        ["chemin"]
    );
    assert_eq!(check(&|g| g.icon_index = "-1".into()), ["indice_icone"]);
    let mut g = f.clone();
    g.path = "%DesktopDir%\\Portail".into();
    let m = to_element(
        Family::Shortcuts,
        &Form::Shortcut(g),
        &e.common(),
        &[],
        Some(&e),
        "",
        INSTANT,
    )
    .unwrap();
    assert_eq!(m.name(), "Portail");
    assert_eq!(
        m.property("shortcutPath").as_deref(),
        Some("%DesktopDir%\\Portail")
    );
}

fn registry(rtype: &str, data: &str, decimal: bool) -> RegistryForm {
    RegistryForm {
        key: "Software\\Essai".into(),
        name: "V".into(),
        rtype: rtype.into(),
        data: data.into(),
        decimal,
        ..RegistryForm::default()
    }
}

#[test]
fn registry_data() {
    for (rtype, input, decimal, value) in [
        ("REG_DWORD", "42", true, "0000002A"),
        ("REG_DWORD", "2a", false, "0000002A"),
        ("REG_QWORD", "1234567890123", true, "0000011F71FB04CB"),
        ("REG_BINARY", "01 02 ff", false, "0102FF"),
        ("REG_SZ", "été & <x>", false, "été & <x>"),
        ("REG_MULTI_SZ", "un\ndeux\n", false, "un deux"),
    ] {
        let f = Form::Registry(registry(rtype, input, decimal));
        assert!(validate(&f, Part::User).is_empty(), "{input}");
        let e = to_element(
            Family::Registry,
            &f,
            &Common::default(),
            &[],
            None,
            UID,
            INSTANT,
        )
        .unwrap();
        assert_eq!(e.property("value").as_deref(), Some(value));
        let Form::Registry(again) = form(Family::Registry, Some(&e), Part::User) else {
            panic!()
        };
        if rtype == "REG_MULTI_SZ" {
            assert_eq!(again.data, "un\ndeux");
        }
    }
    for (rtype, input, decimal) in [
        ("REG_DWORD", "4294967296", true),
        ("REG_DWORD", "x", true),
        ("REG_QWORD", "-1", true),
        ("REG_BINARY", "0", false),
        ("REG_BINARY", "zz", false),
    ] {
        assert_eq!(
            fields(&Form::Registry(registry(rtype, input, decimal)), Part::User),
            ["donnees"]
        );
    }
}

#[test]
fn registry_key_and_default() {
    let key_only = |key: &str| {
        fields(
            &Form::Registry(RegistryForm {
                key: key.into(),
                ..RegistryForm::default()
            }),
            Part::User,
        )
    };
    assert_eq!(key_only("\\Software"), ["cle"]);
    assert_eq!(key_only(""), ["cle"]);
    let key = to_element(
        Family::Registry,
        &Form::Registry(RegistryForm {
            action: "D".into(),
            key: "Software\\X".into(),
            ..RegistryForm::default()
        }),
        &Common::default(),
        &[],
        None,
        UID,
        INSTANT,
    )
    .unwrap();
    assert_eq!((key.name(), key.status()), ("Software\\X", "Software\\X"));
    assert_eq!(key.property("type").as_deref(), Some("REG_SZ"));
    assert_eq!(key.property("name").as_deref(), Some(""));
    let default = to_element(
        Family::Registry,
        &Form::Registry(RegistryForm {
            key: "Software\\X".into(),
            default: true,
            name: "ignored".into(),
            data: "v".into(),
            ..RegistryForm::default()
        }),
        &Common::default(),
        &[],
        None,
        UID,
        INSTANT,
    )
    .unwrap();
    assert_eq!(
        (default.name(), default.status()),
        ("Software\\X", "(Default)")
    );
    assert_eq!(default.property("default").as_deref(), Some("1"));
    assert_eq!(default.property("name").as_deref(), Some(""));
}

#[test]
fn gpmc_registry_read_again() {
    // The elements written by the GroupPolicy module read and write again the same.
    let d = doc("registre-gpmc-lab-utilisateur");
    for e in d.elements() {
        let f = form(Family::Registry, Some(e), Part::User);
        assert!(validate(&f, Part::User).is_empty(), "{}", e.name());
        let m = to_element(
            Family::Registry,
            &f,
            &e.common(),
            &e.filters(),
            Some(e),
            "",
            INSTANT,
        )
        .unwrap();
        assert_eq!(m.properties(), e.properties(), "{}", e.name());
        assert_eq!((m.name(), m.status()), (e.name(), e.status()));
        let values = |x: &Element| {
            x.node
                .iter()
                .iter()
                .filter(|n| n.tag == "Value")
                .map(|n| n.text.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(values(&m), values(e));
    }
}

#[test]
fn filter_texts() {
    let d = doc("lecteurs-console");
    let e = d.elements()[0].clone();
    let texts = filters_texts(&e.filters());
    assert_eq!(texts[0], "the user is a member of LAB\\GG-Nantes-Direction");
    assert!(
        texts[1].starts_with("or the user is not in the OU OU=Départs"),
        "{}",
        texts[1]
    );
    assert_eq!(texts[2], "and the computer name is ANNUAIRE-POSTE1");
    assert_eq!(texts[3], "and the user is not LAB\\herve.humbert2");
    assert_eq!(texts[4], "and FilterCollection (cannot be edited here)");
    assert!(row(Family::Drives, &e).targeting.starts_with("Targeting: "));
    let f = group_filter("LAB\\G", "S-1-5-21-1-2-3-4", true, true, false);
    let Filter::Editable(g) = &f else { panic!() };
    let wanted: Vec<(String, String)> = [
        ("bool", "AND"),
        ("not", "1"),
        ("name", "LAB\\G"),
        ("sid", "S-1-5-21-1-2-3-4"),
        ("userContext", "0"),
        ("primaryGroup", "0"),
        ("localGroup", "0"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    assert_eq!(g.attributes, wanted);
    assert_eq!(filter_text(&f), "the computer is not a member of LAB\\G");
    let Filter::Editable(c) = computer_filter("p.lab.test", true, false, false) else {
        panic!()
    };
    assert_eq!(c.get_or("type", ""), "DNS");
    assert!(
        filter_text(&ou_filter("OU=X", false, true, false, false)).ends_with("(direct member)")
    );
    assert!(user_filter("LAB\\u", "S-1", false, true).or());
}

#[test]
fn rows() {
    let d = doc("registre-gpmc-lab-utilisateur");
    let rows: Vec<Row> = d
        .elements()
        .iter()
        .map(|e| row(Family::Registry, e))
        .collect();
    assert_eq!(rows[0].title, "Chaine");
    assert_eq!(rows[0].action, "Update");
    assert_eq!(
        rows[1].subtitle,
        "HKEY_CURRENT_USER\\Software\\Essai J7F: Entier = 0000002A"
    );
    assert_eq!(
        rows[3].subtitle,
        "HKEY_CURRENT_USER\\Software\\Essai J7F\\Vieux"
    );
    assert!(rows[4].subtitle.contains("(Default)"));
    assert!(rows.iter().all(|x| x.editable));
    assert!(rows[3].accessible().contains("Delete"));
}

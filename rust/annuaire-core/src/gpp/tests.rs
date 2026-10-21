// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The codec against the shared vectors and built cases (`test_codecs_preferences.py`).

use std::path::PathBuf;

use serde_json::Value;

use super::*;

/// 2026-10-14 21:05:09 UTC.
const INSTANT: i64 = 1_792_011_909;
const UID: &str = "{01234567-89AB-4CDE-8F01-23456789ABCD}";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn family(name: &str) -> Family {
    Family::ALL.into_iter().find(|f| f.value() == name).unwrap()
}

fn vectors() -> Vec<Value> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vecteurs/preferences.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["vecteurs"].as_array().unwrap().clone()
}

fn document(v: &Value) -> Document {
    read(
        &hex(v["hex"].as_str().unwrap()),
        family(v["attendu"]["famille"].as_str().unwrap()),
    )
    .unwrap()
}

fn vector(id: &str) -> Document {
    document(vectors().iter().find(|v| v["id"] == id).unwrap())
}

fn pairs(v: &Value) -> Vec<(String, String)> {
    v.as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_owned()))
        .collect()
}

fn props(list: &[(&str, &str)]) -> Vec<(String, String)> {
    list.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn timestamps() {
    assert_eq!(timestamp(INSTANT), "2026-10-14 21:05:09");
    assert_eq!(timestamp(1_767_323_045), "2026-01-02 03:04:05");
    assert_eq!(timestamp(0), "1970-01-01 00:00:00");
}

#[test]
fn vectors_round_trip() {
    for v in vectors() {
        let bytes = hex(v["hex"].as_str().unwrap());
        let doc = document(&v);
        assert_eq!(write(&doc), bytes, "{}", v["id"]);
        // Even without the origin: each piece keeps its bytes, the blanks their place.
        assert_eq!(
            write(&with_pieces(&doc, doc.pieces.clone())),
            bytes,
            "{}",
            v["id"]
        );
    }
}

#[test]
fn vectors_content() {
    for v in vectors() {
        let expected = &v["attendu"];
        let doc = document(&v);
        assert_eq!(doc.description().root, expected["racine"]);
        assert_eq!(doc.disabled(), expected["attributs"]["disabled"] == "1");
        let elements = expected["elements"].as_array().unwrap();
        assert_eq!(doc.elements().len(), elements.len());
        for (e, a) in doc.elements().into_iter().zip(elements) {
            assert_eq!(e.tag(), a["balise"]);
            assert_eq!(e.node.attributes, pairs(&a["attributs"]), "{}", v["id"]);
            if a["proprietes"].is_null() {
                assert!(e.node.find("Properties").is_none());
            } else {
                assert_eq!(e.properties(), pairs(&a["proprietes"]));
            }
            let values: Vec<String> = e
                .node
                .find("Properties")
                .and_then(|p| p.find("Values"))
                .map(|vs| {
                    vs.children
                        .iter()
                        .filter(|c| c.tag == "Value")
                        .map(|c| c.text.clone())
                        .collect()
                })
                .unwrap_or_default();
            let wanted: Vec<String> = a["valeurs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_str().unwrap().to_owned())
                .collect();
            assert_eq!(values, wanted);
            let children: Vec<&str> = e.node.children.iter().map(|c| c.tag.as_str()).collect();
            assert_eq!(
                children,
                a["enfants"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|x| x.as_str().unwrap())
                    .collect::<Vec<_>>()
            );
            let filters: Vec<Value> = e
                .filters()
                .iter()
                .map(|f| {
                    let attributes = match f {
                        Filter::Editable(f) => f.attributes.clone(),
                        Filter::Raw(n) => n.attributes.clone(),
                    };
                    let map: serde_json::Map<String, Value> = attributes
                        .into_iter()
                        .map(|(k, v)| (k, Value::String(v)))
                        .collect();
                    serde_json::json!({"balise": f.tag(), "attributs": map})
                })
                .collect();
            assert_eq!(Value::Array(filters), a["filtres"]);
        }
    }
}

#[test]
fn gpmc_extensions() {
    // The GroupPolicy module declares the registry pair alone (without the null CSE).
    let d = Family::Registry.description();
    for v in vectors() {
        if v["id"].as_str().unwrap().starts_with("registre-gpmc-") {
            assert_eq!(v["attendu"]["extensions"], format!("[{}{}]", d.cse, d.tool));
        }
    }
}

#[test]
fn change_keeps_the_other_elements() {
    let doc = vector("registre-gpmc-lab-utilisateur");
    let before = write(&doc);
    let e = doc.elements()[1].clone();
    let new = modify_element(
        &e,
        e.name(),
        e.status(),
        &props(&[("value", "00000007")]),
        &e.common(),
        &e.filters(),
        INSTANT,
        None,
    );
    let out = write(&replace(&doc, 1, new).unwrap());
    let contains = |hay: &[u8], needle: &[u8]| hay.windows(needle.len()).any(|w| w == needle);
    for (i, other) in doc.elements().iter().enumerate() {
        if i != 1 {
            assert!(contains(&out, other.raw.as_ref().unwrap()));
        }
    }
    assert!(!contains(&out, e.raw.as_ref().unwrap()));
    let again = read(&out, Family::Registry).unwrap();
    assert_eq!(again.elements()[1].property("value").unwrap(), "00000007");
    assert_eq!(again.elements()[1].uid(), e.uid());
    assert_eq!(again.elements()[1].changed(), "2026-10-14 21:05:09");
    // Style of the file: two spaces, CRLF, « /> » preceded by a space.
    let text = String::from_utf8(out[3..].to_vec()).unwrap();
    assert!(text.contains("  <Registry clsid=\"{9CD4B2F4"));
    assert!(text.contains("value=\"00000007\" />\r\n  </Registry>"));
    assert!(out.starts_with(b"\xef\xbb\xbf<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n"));
    assert_ne!(before, out);
}

#[test]
fn add_in_the_console_style() {
    let doc = vector("lecteurs-console");
    let e = new_element(
        Family::Drives,
        "K:",
        "K:",
        &props(&[("action", "C"), ("path", "\\\\srv\\x"), ("letter", "K")]),
        &Common {
            description: "à <b> & \"c\"".into(),
            ..Common::default()
        },
        &[Filter::Editable(EditableFilter::new(
            Target::Computer,
            &[("name", "PC1")],
        ))],
        UID,
        INSTANT,
        &[],
    );
    let out = write(&add(&doc, e));
    let text = String::from_utf8(out[3..].to_vec()).unwrap();
    let wanted = format!(
        "</Drive><Drive clsid=\"{{935D1B74-9CB8-4e3c-9914-7DD559B7A417}}\" name=\"K:\" \
status=\"K:\" image=\"0\" changed=\"2026-10-14 21:05:09\" uid=\"{UID}\" \
desc=\"à &lt;b&gt; &amp; &quot;c&quot;\" bypassErrors=\"1\">\
<Properties action=\"C\" path=\"\\\\srv\\x\" letter=\"K\"/>\
<Filters><FilterComputer bool=\"AND\" not=\"0\" type=\"NETBIOS\" name=\"PC1\"/></Filters>\
</Drive>\r\n</Drives>"
    );
    assert!(text.contains(&wanted), "{text}");
    let again = read(&out, Family::Drives).unwrap();
    assert_eq!(
        again.elements().last().unwrap().common().description,
        "à <b> & \"c\""
    );
    assert_eq!(again.elements().len(), 3);
}

#[test]
fn empty_root() {
    let doc = vector("lecteurs-racine-vide");
    assert!(doc.elements().is_empty());
    let e = new_element(
        Family::Drives,
        "H:",
        "H:",
        &props(&[("action", "U")]),
        &Common::default(),
        &[],
        UID,
        INSTANT,
        &[],
    );
    let out = write(&add(&doc, e));
    let again = read(&out, Family::Drives).unwrap();
    assert_eq!(again.elements()[0].name(), "H:");
    assert!(out.ends_with(b"</Drive>\r\n</Drives>"));
    assert!(
        write(&remove(&again, 0).unwrap())
            .ends_with(b"<Drives clsid=\"{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}\"></Drives>")
    );
}

#[test]
fn new_document_as_the_gpmc() {
    let doc = new_document(Family::Shortcuts);
    let e = new_element(
        Family::Shortcuts,
        "Calc",
        "Calc",
        &props(&[
            ("pidl", ""),
            ("targetType", "FILESYSTEM"),
            ("action", "U"),
            ("shortcutPath", "%DesktopDir%\\Calc"),
        ]),
        &Common::default(),
        &[],
        UID,
        INSTANT,
        &[],
    );
    let out = write(&add(&doc, e));
    let wanted = format!(
        "\u{feff}<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n\
<Shortcuts clsid=\"{{872ECB34-B2EC-401b-A585-D32574AA90EE}}\">\r\n  \
<Shortcut clsid=\"{{4F2F7C55-2790-433e-8127-0739D1CFA327}}\" name=\"Calc\" status=\"Calc\" \
image=\"2\" changed=\"2026-10-14 21:05:09\" uid=\"{UID}\" bypassErrors=\"1\">\r\n    \
<Properties pidl=\"\" targetType=\"FILESYSTEM\" action=\"U\" \
shortcutPath=\"%DesktopDir%\\Calc\" />\r\n  </Shortcut>\r\n</Shortcuts>"
    );
    assert_eq!(String::from_utf8(out.clone()).unwrap(), wanted);
    assert_eq!(
        read(&out, Family::Shortcuts).unwrap().elements()[0].name(),
        "Calc"
    );
}

#[test]
fn cpassword_reported_and_removed() {
    let doc = vector("lecteurs-cpassword");
    let e = doc.elements()[0].clone();
    assert!(e.has_password() && doc.passwords().len() == 1);
    let m = modify_element(
        &e,
        e.name(),
        e.status(),
        &props(&[("userName", "")]),
        &e.common(),
        &[],
        INSTANT,
        None,
    );
    assert!(!m.has_password());
    let out = write(&replace(&doc, 0, m).unwrap());
    assert!(!out.windows(9).any(|w| w == b"cpassword"));
    assert!(vector("lecteurs-console").passwords().is_empty());
    let n = new_element(
        Family::Drives,
        "H:",
        "H:",
        &props(&[("action", "U"), ("cpassword", "x")]),
        &Common::default(),
        &[],
        UID,
        INSTANT,
        &[],
    );
    assert!(n.property("cpassword").is_none());
}

#[test]
fn unknown_filters_kept() {
    let doc = vector("lecteurs-console");
    let e = doc.elements()[0].clone();
    let filters = e.filters();
    let kinds: Vec<bool> = filters
        .iter()
        .map(|f| matches!(f, Filter::Editable(_)))
        .collect();
    assert_eq!(kinds, [true, true, true, true, false, false]);
    assert!(filters[1].or() && filters[1].negation());
    let Filter::Editable(first) = &filters[0] else {
        panic!()
    };
    let mut new = vec![Filter::Editable(first.with(&[("name", "LAB\\Autre")]))];
    new.extend(filters[1..].iter().cloned());
    let m = modify_element(
        &e,
        e.name(),
        e.status(),
        &[],
        &e.common(),
        &new,
        INSTANT,
        None,
    );
    let out = write(&replace(&doc, 0, m).unwrap());
    let again = read(&out, Family::Drives).unwrap();
    let again = again.elements()[0].clone();
    let Filter::Editable(f) = &again.filters()[0] else {
        panic!()
    };
    assert_eq!(f.name(), "LAB\\Autre");
    let Filter::Raw(raw) = &again.filters()[4] else {
        panic!()
    };
    assert_eq!(raw.tag, "FilterCollection");
    let names: Vec<&str> = raw.children.iter().map(|c| c.get_or("name", "")).collect();
    assert_eq!(names, ["poste2.lab.test"]);
    let tags: Vec<&str> = again.node.children.iter().map(|c| c.tag.as_str()).collect();
    assert_eq!(tags, ["Properties", "Filters"]);
    // No filter any more: `Filters` goes.
    let m2 = modify_element(
        &e,
        e.name(),
        e.status(),
        &[],
        &e.common(),
        &[],
        INSTANT,
        None,
    );
    assert!(m2.node.find("Filters").is_none());
}

#[test]
fn order_and_raw_pieces() {
    let doc = vector("registre-collection");
    let kinds: Vec<bool> = doc
        .pieces
        .iter()
        .map(|p| matches!(p, Piece::Element(_)))
        .collect();
    assert_eq!(kinds, [false, true, true]);
    let d = shift(&doc, 0, 1).unwrap();
    let names: Vec<&str> = d.elements().iter().map(|e| e.name()).collect();
    assert_eq!(names, ["Cible", "Dossier"]);
    assert!(matches!(d.pieces[0], Piece::Raw(_)));
    let out = write(&d);
    let comment = "<!-- gardé tel quel -->".as_bytes();
    assert_eq!(
        out.windows(comment.len()).filter(|w| *w == comment).count(),
        1
    );
    let again = read(&out, Family::Registry).unwrap();
    let names: Vec<&str> = again.elements().iter().map(|e| e.name()).collect();
    assert_eq!(names, ["Cible", "Dossier"]);
    let registry = Family::Registry.description();
    assert!(!again.elements()[1].editable(registry));
    assert!(again.elements()[0].editable(registry));
    let names: Vec<String> = remove(&doc, 0)
        .unwrap()
        .elements()
        .iter()
        .map(|e| e.name().to_owned())
        .collect();
    assert_eq!(names, ["Cible"]);
    assert!(shift(&doc, 1, 1).is_none());
}

#[test]
fn disabled_family() {
    let doc = vector("raccourcis-desactives");
    assert!(doc.disabled() && doc.elements()[0].disabled());
    assert_eq!(doc.indentation().as_deref(), Some("\t"));
}

#[test]
fn refusals() {
    let utf16: Vec<u8> = "\u{feff}<?xml version='1.0' encoding='utf-16'?><Drives/>"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    for (bytes, wanted) in [
        (
            br#"<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><Drives clsid="x">&a;</Drives>"#
                .to_vec(),
            Some(PreferencesError::Dtd),
        ),
        (utf16, Some(PreferencesError::Encoding)),
        (
            br#"<?xml version="1.0" encoding="iso-8859-1"?><Drives/>"#.to_vec(),
            Some(PreferencesError::Encoding),
        ),
        (b"<Drives><Drive></Drives>".to_vec(), None),
        (
            b"<Printers/>".to_vec(),
            Some(PreferencesError::Root {
                root: "Printers".into(),
                expected: "Drives".into(),
            }),
        ),
    ] {
        let error = read(&bytes, Family::Drives).unwrap_err();
        match wanted {
            Some(w) => assert_eq!(error, w),
            None => assert!(matches!(error, PreferencesError::Malformed(_))),
        }
    }
}

#[test]
fn image_and_action() {
    let e = vector("registre-collection").elements()[1].clone();
    assert_eq!(e.node.get("image"), Some("7"));
    let m = modify_element(
        &e,
        e.name(),
        e.status(),
        &props(&[("action", "R")]),
        &e.common(),
        &[],
        INSTANT,
        None,
    );
    assert_eq!(m.node.get("image"), Some("6"));
    assert_eq!(m.action(), "R");
}

#[test]
fn common_options() {
    let e = vector("lecteurs-console").elements()[1].clone();
    assert_eq!(
        e.common(),
        Common {
            ignore_errors: true,
            user_context: true,
            remove_when_not_applied: true,
            ..Common::default()
        }
    );
    let m = modify_element(
        &e,
        e.name(),
        e.status(),
        &[],
        &Common {
            ignore_errors: false,
            disabled: true,
            ..Common::default()
        },
        &[],
        INSTANT,
        None,
    );
    assert!(!m.node.has("bypassErrors") && !m.node.has("removePolicy"));
    assert_eq!(m.node.get("disabled"), Some("1"));
    assert!(!m.node.has("userContext"));
}

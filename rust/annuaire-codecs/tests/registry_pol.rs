// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `registry_pol` against the shared vectors (samba-tool, GPMC on Samba, GPMC on Windows).

#![allow(clippy::indexing_slicing)]

mod common;

use annuaire_codecs::registry_pol::{self, Entry, RegValue};
use common::{to_hex, vectors};
use serde_json::{Value, json};

fn data_json(e: &Entry) -> Value {
    match e.interpret().unwrap() {
        RegValue::Integer(i) => json!(i),
        RegValue::Text(t) => json!(t),
        RegValue::Texts(t) => json!(t),
        RegValue::Bytes(b) => json!(to_hex(&b)),
    }
}

#[test]
fn registrypol_vectors() {
    for family in ["registrypol", "registrypol_gpmc", "registrypol_win"] {
        for v in vectors(family) {
            let entries = registry_pol::read(&v.bytes).unwrap();
            assert_eq!(registry_pol::encode(&entries).unwrap(), v.bytes, "{}", v.id);
            let expected = v.expected["entrees"].as_array().unwrap();
            assert_eq!(entries.len(), expected.len(), "{}", v.id);
            for (e, a) in entries.iter().zip(expected) {
                assert_eq!(e.key, a["cle"], "{}", v.id);
                assert_eq!(e.value_name, a["valeur"], "{}", v.id);
                assert_eq!(e.rtype, a["type"], "{}", v.id);
                assert_eq!(e.type_name(), a["type_nom"], "{}", v.id);
                assert_eq!(data_json(e), a["donnees"], "{} {}", v.id, e.value_name);
                if let Some(size) = a.get("taille") {
                    assert_eq!(e.size(), *size, "{}", v.id);
                }
                // Coded again from its value, an ordinary entry gives the same bytes.
                if e.special().is_none() {
                    let again =
                        Entry::from_value(&e.key, &e.value_name, e.rtype, &e.interpret().unwrap())
                            .unwrap();
                    assert_eq!(&again, e, "{}", v.id);
                }
            }
        }
    }
}

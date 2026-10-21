// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Shared test vectors of `tests/vecteurs/` (README there), the same files as the Python
//! tests read.

#![allow(dead_code, clippy::indexing_slicing)]

use std::path::PathBuf;

use serde_json::Value;

/// One vector: its id, its raw bytes and the expected decoded value (`attendu`).
pub struct Vector {
    pub id: String,
    pub bytes: Vec<u8>,
    pub expected: Value,
    pub raw: Value,
}

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vecteurs")
}

/// The vectors of a family (`sid`, `guid`…), in file order.
pub fn vectors(family: &str) -> Vec<Vector> {
    let path = directory().join(format!("{family}.json"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path:?}: {e}"));
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["format"], 1);
    assert_eq!(doc["famille"], family);
    let list = doc["vecteurs"].as_array().unwrap();
    assert!(!list.is_empty());
    list.iter()
        .map(|v| Vector {
            id: v["id"].as_str().unwrap().to_owned(),
            bytes: hex(v["hex"].as_str().unwrap()),
            expected: v["attendu"].clone(),
            raw: v.clone(),
        })
        .collect()
}

pub fn hex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hexadecimal");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `gplink` and `gpt_tmpl` against the shared vectors.

#![allow(clippy::indexing_slicing)]

mod common;

use annuaire_codecs::gplink::{self, GpLink};
use annuaire_codecs::gpt_tmpl::{self, Inf};
use common::vectors;
use serde_json::{Value, json};

#[test]
fn gplink_vectors() {
    for v in vectors("gplink") {
        let e = &v.expected;
        if v.id.starts_with("gpoptions-") {
            let value = gplink::decode_gpoptions(&v.bytes).unwrap();
            assert_eq!(value, e["valeur"], "{}", v.id);
            assert_eq!(gplink::inheritance_blocked(value), e["heritage_bloque"]);
            continue;
        }
        let g = GpLink::decode(&v.bytes).unwrap();
        assert_eq!(g.encode(), v.bytes, "{}", v.id);
        let links: Vec<Value> = g
            .links()
            .map(|l| {
                json!({
                    "dn": l.dn, "guid": l.guid(), "options": l.options,
                    "desactive": l.disabled(), "applique": l.enforced(),
                })
            })
            .collect();
        assert_eq!(json!(links), e["liens"], "{}", v.id);
    }
}

/// The section of `attendu.sections` as the tool reads it.
fn section_json(inf: &Inf, name: &str, expected: &Value) -> Value {
    if name == gpt_tmpl::PRIVILEGE_RIGHTS {
        return json!(inf.rights());
    }
    if name == gpt_tmpl::GROUP_MEMBERSHIP {
        // Samba reads an empty list (`X__Memberof = `) as `[""]`: empty strings left out on
        // both sides.
        return json!(
            inf.values(name)
                .iter()
                .map(|(k, v)| {
                    let (group, kind) = k.rsplit_once("__").unwrap();
                    json!([[group, kind], gpt_tmpl::list(v)])
                })
                .collect::<Vec<_>>()
        );
    }
    if expected[0].is_string() {
        // Raw lines ([Registry Values]).
        let section = inf.section(name).unwrap();
        return json!(
            section
                .lines
                .iter()
                .skip(1)
                .map(|l| l.trim_end_matches(['\r', '\n']))
                .collect::<Vec<_>>()
        );
    }
    json!(inf.values(name))
}

fn without_empty(v: &Value) -> Value {
    let rows = v.as_array().unwrap().iter().map(|row| {
        let list: Vec<&Value> = row[1]
            .as_array()
            .unwrap()
            .iter()
            .filter(|x| x.as_str() != Some(""))
            .collect();
        json!([row[0], list])
    });
    json!(rows.collect::<Vec<_>>())
}

#[test]
fn inf_vectors() {
    for v in vectors("inf") {
        let e = &v.expected;
        let inf = Inf::read(&v.bytes).unwrap();
        assert_eq!(inf.write().unwrap(), v.bytes, "{}", v.id);
        assert_eq!(
            inf.encoding.name().replace('-', ""),
            e["encodage"].as_str().unwrap().replace('-', ""),
            "{}",
            v.id
        );
        assert_eq!(inf.bom, e["bom"], "{}", v.id);
        for (name, expected) in e["sections"].as_object().unwrap() {
            let got = section_json(&inf, name, expected);
            if name == gpt_tmpl::GROUP_MEMBERSHIP {
                assert_eq!(without_empty(&got), without_empty(expected), "{}", v.id);
            } else {
                assert_eq!(&got, expected, "{} [{name}]", v.id);
            }
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `sid` and `guid` against the shared vectors.

#![allow(clippy::indexing_slicing)]

mod common;

use annuaire_codecs::{Guid, Sid};
use common::vectors;

#[test]
fn sid_vectors() {
    for v in vectors("sid") {
        let e = &v.expected;
        let sid = Sid::decode(&v.bytes).unwrap_or_else(|err| panic!("{}: {err}", v.id));
        assert_eq!(u64::from(sid.revision()), e["revision"], "{}", v.id);
        assert_eq!(sid.authority(), e["autorite"], "{}", v.id);
        let subs: Vec<u64> = sid.sub_authorities().iter().map(|&s| s.into()).collect();
        assert_eq!(serde_json::json!(subs), e["sous_autorites"], "{}", v.id);
        assert_eq!(serde_json::json!(sid.rid()), e["rid"], "{}", v.id);
        assert_eq!(sid.to_string(), e["texte"], "{}", v.id);
        let text = e["texte"].as_str().unwrap();
        assert_eq!(text.parse::<Sid>().unwrap(), sid, "{}", v.id);
        assert_eq!(sid.encode(), v.bytes, "{}", v.id);
    }
}

#[test]
fn guid_vectors() {
    for v in vectors("guid") {
        let guid = Guid::decode(&v.bytes).unwrap();
        let text = v.expected["texte"].as_str().unwrap();
        assert_eq!(guid.to_string(), text, "{}", v.id);
        assert_eq!(text.parse::<Guid>().unwrap(), guid, "{}", v.id);
        let braced = format!("{{{}}}", text.to_uppercase());
        assert_eq!(braced.parse::<Guid>().unwrap(), guid, "{}", v.id);
        assert_eq!(guid.encode(), v.bytes, "{}", v.id);
    }
}

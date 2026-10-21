// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `integer`, `time` and `uac` against the shared vectors.

#![allow(clippy::indexing_slicing)]

mod common;

use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::time;
use annuaire_codecs::uac::{GroupType, SamAccountType, UserAccountControl, group_flag_names};
use common::vectors;
use serde_json::json;

#[test]
fn time_vectors() {
    for v in vectors("temps") {
        let e = &v.expected;
        if v.id.starts_with("generalizedtime-") {
            let text = std::str::from_utf8(&v.bytes).unwrap();
            let t = time::decode_generalized_time(text).unwrap();
            assert_eq!(t.unix_seconds(), e["unix"], "{}", v.id);
            let c = t.civil();
            let iso = format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                c.year, c.month, c.day, c.hour, c.minute, c.second
            );
            assert_eq!(iso, e["iso"], "{}", v.id);
            assert_eq!(time::encode_generalized_time(t), text, "{}", v.id);
            continue;
        }
        let value = integer::decode(&v.bytes, Width::Bits64).unwrap();
        assert_eq!(integer::encode(value, Width::Bits64).unwrap(), v.bytes);
        if e.get("centaines_ns").is_some() {
            assert_eq!(value, e["centaines_ns"], "{}", v.id);
            assert_eq!(
                time::duration_is_never(value).unwrap(),
                e["jamais"],
                "{}",
                v.id
            );
            let seconds = time::duration_to_seconds(value).unwrap();
            assert_eq!(
                json!(seconds),
                e.get("secondes").cloned().unwrap_or_default()
            );
            if let Some(s) = seconds {
                assert_eq!(time::seconds_to_duration(s), Ok(value), "{}", v.id);
                assert_eq!(time::duration_to_micros(value), Ok(Some(s * 1_000_000)));
            }
            continue;
        }
        assert_eq!(value, e["nttime"], "{}", v.id);
        assert_eq!(time::is_never(value).unwrap(), e["jamais"], "{}", v.id);
        let iso = time::nttime_to_iso(value).unwrap();
        assert_eq!(
            json!(iso),
            e.get("iso").cloned().unwrap_or_default(),
            "{}",
            v.id
        );
        let unix = time::nttime_to_unix(value).unwrap();
        assert_eq!(
            json!(unix),
            e.get("unix").cloned().unwrap_or_default(),
            "{}",
            v.id
        );
        if let Some(t) = time::nttime_to_utc(value).unwrap() {
            // Full resolution: no loss of the last hundred nanoseconds.
            assert_eq!(time::utc_to_nttime(t), Ok(value), "{}", v.id);
        }
    }
}

#[test]
fn uac_vectors() {
    for v in vectors("uac") {
        let e = &v.expected;
        let value = integer::decode(&v.bytes, Width::Bits32).unwrap();
        assert_eq!(value, e["valeur"], "{}", v.id);
        let value = i32::try_from(value).unwrap();
        if v.id.starts_with("useraccountcontrol-") {
            let uac = UserAccountControl::decode(value);
            assert_eq!(json!(uac.names()), e["drapeaux"], "{}", v.id);
            assert_eq!(uac.encode(), value);
        } else if v.id.starts_with("grouptype-") {
            let g = GroupType::decode(value);
            assert_eq!(g.unsigned(), e["non_signe"], "{}", v.id);
            assert_eq!(json!(group_flag_names(g.unsigned())), e["drapeaux"]);
            assert_eq!(g.gtype.unwrap().name(), e["gtype"], "{}", v.id);
            assert_eq!(g.scope.unwrap().vector_name(), e["portee"], "{}", v.id);
            assert_eq!(g.security, e["securite"], "{}", v.id);
            assert_eq!(GroupType::encode(g.scope.unwrap(), g.security), Ok(value));
        } else {
            let t = SamAccountType::decode(value).unwrap();
            assert_eq!(t.name(), e["atype"], "{}", v.id);
        }
    }
}

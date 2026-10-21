// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Time of a decode and encode round trip over the shared vectors, codec by codec, in pure
//! Rust: `cargo run --release --example measure`. The Python side, and the Python module,
//! are measured by `rust/mesurer_codecs.py` on the same vectors.

#![allow(clippy::indexing_slicing)]

use std::hint::black_box;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use annuaire_codecs::dns_property::ZoneProperty;
use annuaire_codecs::dns_record::Record;
use annuaire_codecs::gplink::GpLink;
use annuaire_codecs::gpt_tmpl::Inf;
use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::{Guid, Sid, registry_pol};

fn vectors(family: &str) -> Vec<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/vecteurs")
        .join(format!("{family}.json"));
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["vecteurs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let h = v["hex"].as_str().unwrap();
            (0..h.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

/// Microseconds for one pass over all the vectors (best of five runs of `rounds` passes).
fn measure(name: &str, family: &str, round_trip: impl Fn(&[u8]) -> Vec<u8>) {
    let inputs = vectors(family);
    for i in &inputs {
        assert_eq!(&round_trip(i), i, "{name}");
    }
    let rounds = 2000;
    let best = (0..5)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..rounds {
                for i in &inputs {
                    black_box(round_trip(black_box(i)));
                }
            }
            start.elapsed()
        })
        .min()
        .unwrap_or(Duration::ZERO);
    let micros = best.as_secs_f64() * 1e6 / f64::from(rounds);
    println!("{name:12} {:3} vectors  {micros:9.2} µs", inputs.len());
}

fn main() {
    measure("sid", "sid", |b| Sid::decode(b).unwrap().encode());
    measure("guid", "guid", |b| Guid::decode(b).unwrap().encode());
    measure("dnsrecord", "dnsrecord", |b| {
        Record::decode(b).unwrap().encode().unwrap()
    });
    measure("dnsproperty", "dnsproperty", |b| {
        ZoneProperty::decode(b).unwrap().encode().unwrap()
    });
    measure("gplink", "gplink", |b| GpLink::decode(b).unwrap().encode());
    measure("registrypol", "registrypol_gpmc", |b| {
        registry_pol::encode(&registry_pol::read(b).unwrap()).unwrap()
    });
    measure("inf", "inf", |b| Inf::read(b).unwrap().write().unwrap());
    measure("sd", "sd", |b| {
        SecurityDescriptor::decode(b).unwrap().encode().unwrap()
    });
}

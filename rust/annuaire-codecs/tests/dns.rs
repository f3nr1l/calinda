// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `dns_record` and `dns_property` against the shared vectors.

#![allow(clippy::indexing_slicing)]

mod common;

use std::net::IpAddr;

use annuaire_codecs::dns_property::{PropertyValue, ZoneProperty, id_name};
use annuaire_codecs::dns_record::{HEADER_SIZE, Record, RecordData};
use annuaire_codecs::time;
use common::vectors;
use serde_json::{Value, json};

fn data_json(data: &RecordData) -> Value {
    match data {
        RecordData::Address(a) => json!(a.to_string()),
        RecordData::Name(n) => json!(n),
        RecordData::Mx { preference, target } => json!({"priorite": preference, "cible": target}),
        RecordData::Srv {
            priority,
            weight,
            port,
            target,
        } => json!({"priorite": priority, "poids": weight, "port": port, "cible": target}),
        RecordData::Soa {
            serial,
            refresh,
            retry,
            expire,
            minimum,
            primary_server,
            responsible,
        } => json!({
            "serie": serial, "rafraichissement": refresh, "nouvel_essai": retry,
            "expiration": expire, "minimum": minimum, "serveur": primary_server,
            "responsable": responsible,
        }),
        RecordData::Txt(strings) => json!(strings),
        RecordData::Tombstone(nttime) => json!({
            "nttime": nttime,
            "iso": time::nttime_to_iso(i64::try_from(*nttime).unwrap()).unwrap(),
        }),
        RecordData::Raw { .. } => panic!("data not decoded: {data:?}"),
    }
}

#[test]
fn dnsrecord_vectors() {
    for v in vectors("dnsrecord") {
        let e = &v.expected;
        let r = Record::decode(&v.bytes).unwrap();
        assert_eq!(r.encode().unwrap(), v.bytes, "{}", v.id);
        assert_eq!(
            v.bytes.len() - HEADER_SIZE,
            e["longueur_donnees"],
            "{}",
            v.id
        );
        assert_eq!(r.rtype, e["type"], "{}", v.id);
        assert_eq!(r.type_name(), e["type_nom"], "{}", v.id);
        assert_eq!(r.version, 5);
        assert_eq!(r.rank, e["rang"], "{}", v.id);
        assert_eq!(r.rank_name(), e["rang_nom"], "{}", v.id);
        assert_eq!(r.flags, 0);
        assert_eq!(r.serial, e["serie"], "{}", v.id);
        assert_eq!(r.ttl, e["ttl"], "{}", v.id);
        assert_eq!(r.reserved, e["reserve"], "{}", v.id);
        assert_eq!(r.timestamp, e["horodatage"], "{}", v.id);
        assert_eq!(r.is_static(), e["horodatage"] == 0);
        if let RecordData::Address(address) = r.data {
            // The oracle writes IPv6 addresses in full (README of the vectors).
            let expected: IpAddr = e["donnees"].as_str().unwrap().parse().unwrap();
            assert_eq!(address, expected, "{}", v.id);
        } else {
            assert_eq!(data_json(&r.data), e["donnees"], "{}", v.id);
        }
    }
}

#[test]
fn dnsproperty_vectors() {
    for v in vectors("dnsproperty") {
        let e = &v.expected;
        let p = ZoneProperty::decode(&v.bytes).unwrap();
        assert_eq!(p.encode().unwrap(), v.bytes, "{}", v.id);
        assert_eq!(p.data.len(), e["longueur_donnees"], "{}", v.id);
        assert_eq!(p.name_length, e["longueur_nom"], "{}", v.id);
        assert_eq!(p.flag, e["drapeau"], "{}", v.id);
        assert_eq!(p.version, e["version"], "{}", v.id);
        assert_eq!(p.id, e["id"], "{}", v.id);
        assert_eq!(id_name(p.id), e["id_nom"], "{}", v.id);
        match p.value() {
            PropertyValue::Integer(i) => assert_eq!(i, e["valeur"], "{}", v.id),
            PropertyValue::Bytes(b) => {
                let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
                assert_eq!(hex, e["valeur"], "{}", v.id);
            }
        }
    }
}

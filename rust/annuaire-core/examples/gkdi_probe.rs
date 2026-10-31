// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Sonde de J9.6/J9.7 contre un vrai DC. Hors CI (a besoin d'un DC et d'un ticket Kerberos).
//!
//! ```sh
//! # GetKey seul :
//! KRB5CCNAME=FILE:/tmp/win.ccache cargo run -p annuaire-core --example gkdi_probe \
//!   -- wdc1.win.test WIN.TEST S-1-5-21-...-500
//! # Déchiffrement d'un blob DPAPI-NG (hex) de bout en bout :
//! KRB5CCNAME=FILE:/tmp/win.ccache cargo run -p annuaire-core --example gkdi_probe \
//!   -- wdc1.win.test WIN.TEST --decrypt <hex>
//! ```

use std::time::Duration;

use annuaire_core::dpapi::blob::DpapiBlob;
use annuaire_core::dpapi::decrypt_content;
use annuaire_core::dpapi::envelope::GroupKeyEnvelope;
use annuaire_core::dpapi::security_descriptor::target_sd_for_sid;
use annuaire_core::rpc::gkdi::{self, CURRENT, KeyId};

fn hex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let host = args.get(1).map(String::as_str).unwrap_or("");
    let realm = args.get(2).map(String::as_str).unwrap_or("");
    let timeout = Duration::from_secs(20);

    if args.get(3).map(String::as_str) == Some("--laps") {
        let value = hex(args.get(4).map(String::as_str).unwrap_or(""));
        let clear = annuaire_core::dpapi::decrypt_laps_value(&value, host, realm, timeout)
            .expect("déchiffrement LAPS");
        println!("CLAIR {}", String::from_utf8_lossy(&clear));
        return;
    }

    if args.get(3).map(String::as_str) == Some("--decrypt") {
        let blob_bytes = hex(args.get(4).map(String::as_str).unwrap_or(""));
        let blob = DpapiBlob::parse(&blob_bytes).expect("blob illisible");
        let id = &blob.key_identifier;
        let key = KeyId {
            root_key_id: Some(id.root_key_id),
            l0: id.l0,
            l1: id.l1,
            l2: id.l2,
        };
        let gke_bytes =
            gkdi::fetch_group_key(host, realm, &blob.target_sd, &key, timeout).expect("GetKey");
        let gke = GroupKeyEnvelope::parse(&gke_bytes).expect("GroupKeyEnvelope");
        let clear = decrypt_content(&blob, &gke).expect("déchiffrement");
        println!("CLAIR {}", String::from_utf8_lossy(&clear));
        return;
    }

    let sid = args.get(3).map(String::as_str).unwrap_or("");
    let target_sd = target_sd_for_sid(sid).expect("SID invalide");
    let key = KeyId {
        root_key_id: None,
        l0: CURRENT,
        l1: CURRENT,
        l2: CURRENT,
    };
    match gkdi::fetch_group_key(host, realm, &target_sd, &key, timeout) {
        Ok(blob) => {
            println!("GetKey : {} octets", blob.len());
            match GroupKeyEnvelope::parse(&blob) {
                Ok(gke) => println!(
                    "GroupKeyEnvelope l0={} l1={} l2={} clé_publique={} l1_key={} l2_key={}",
                    gke.l0,
                    gke.l1,
                    gke.l2,
                    gke.is_public_key(),
                    gke.l1_key.len(),
                    gke.l2_key.len(),
                ),
                Err(e) => {
                    eprintln!("blob illisible : {e}");
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("échec GetKey : {e}");
            std::process::exit(1);
        }
    }
}

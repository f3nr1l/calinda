// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Trial of the groups and members served by the local copy (R4.10): for each DN, the
//! groups (direct, primary, recursive) and the members computed on the copy compared with
//! those read on the DC, with the times. The copy is the one of the profile (made or brought
//! up to date first).
//!
//!     KRB5CCNAME=FILE:… XDG_CACHE_HOME=… cargo run --example copy_membership \
//!         --features local-copy -- lab.test DN…

use std::sync::Arc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use annuaire_core::cache::{CacheSource, Source, SyncPhase};
use annuaire_core::profile::Profile;
use annuaire_core::source::{DirectSource, Item};
use annuaire_core::store::Store;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn dns(source: &dyn Source, dn: &str) -> Result<Vec<String>> {
    let pages = source.members(dn, Box::new(|| {}));
    let mut out = Vec::new();
    while let Some(page) = pages.flux.next_page() {
        for item in page.map_err(|e| format!("{e:?}"))? {
            out.push(match item {
                Item::Object(o) => o.common().dn.clone(),
                Item::Unreadable { dn, .. } => dn,
            });
        }
    }
    out.sort_by_key(|d| d.to_lowercase());
    Ok(out)
}

fn main() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let domain = arguments.next().ok_or("domain")?;
    let profile = Profile {
        cache: true,
        ..Profile::new(&domain)
    };
    let direct = Arc::new(DirectSource::new(profile.clone()));
    let store = Store::open(&annuaire_core::storage::cache_path(&domain, None))
        .map_err(|e| format!("{e:?}"))?;
    let copy = CacheSource::new(direct.clone(), store);
    let (sender, receiver) = mpsc::channel();
    copy.listen(Box::new(move |state| {
        let _ = sender.send(state.phase);
    }));
    copy.open().map_err(|e| format!("{e:?}"))?;
    let start = Instant::now();
    loop {
        match receiver.recv_timeout(Duration::from_secs(600))? {
            SyncPhase::UpToDate => break,
            SyncPhase::Failed => return Err("synchronisation en échec".into()),
            _ => {}
        }
    }
    println!("copie à jour en {:.1} s", start.elapsed().as_secs_f64());
    let mut differences = 0;
    for dn in arguments {
        let t = Instant::now();
        let on_dc = direct.groups(&dn).map_err(|e| format!("{e:?}"))?;
        let dc_time = t.elapsed();
        let t = Instant::now();
        let in_copy = copy.groups(&dn).map_err(|e| format!("{e:?}"))?;
        let copy_time = t.elapsed();
        let mut direct_dc = on_dc.direct.clone();
        let mut direct_copy = in_copy.direct.clone();
        direct_dc.sort_by_key(|d| d.to_lowercase());
        direct_copy.sort_by_key(|d| d.to_lowercase());
        let same = direct_dc == direct_copy
            && on_dc.primary == in_copy.primary
            && on_dc.recursive == in_copy.recursive;
        differences += usize::from(!same);
        println!(
            "groupes {dn} : {} ({} directs, {} en tout) DC {:.3} s, copie {:.3} s",
            if same { "identiques" } else { "DIFFÉRENTS" },
            direct_copy.len(),
            in_copy.recursive.as_ref().map_or(0, Vec::len),
            dc_time.as_secs_f64(),
            copy_time.as_secs_f64()
        );
        let t = Instant::now();
        let members_dc = dns(direct.as_ref(), &dn)?;
        let dc_time = t.elapsed();
        let t = Instant::now();
        let members_copy = dns(&copy, &dn)?;
        let copy_time = t.elapsed();
        let same = members_dc.len() == members_copy.len()
            && members_dc
                .iter()
                .zip(&members_copy)
                .all(|(a, b)| a.eq_ignore_ascii_case(b));
        differences += usize::from(!same);
        println!(
            "membres {dn} : {} ({}) DC {:.3} s, copie {:.3} s",
            if same { "identiques" } else { "DIFFÉRENTS" },
            members_copy.len(),
            dc_time.as_secs_f64(),
            copy_time.as_secs_f64()
        );
    }
    copy.close();
    if differences > 0 {
        return Err(format!("{differences} différences").into());
    }
    Ok(())
}

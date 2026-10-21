// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Walk of the GPO folders of a SYSVOL and reading of all their files and descriptors, as
//! the inventory of the GPOs does (ADR 0002, measures; ADR 0017).
//!
//!     KRB5CCNAME=FILE:… cargo run --release --example sysvol_walk -- dc1.lab.test lab.test

use std::time::{Duration, Instant};

use annuaire_core::sysvol::{INFO_OGD, Protection, Session};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let dc = args.next().ok_or("dc")?;
    let domain = args.next().ok_or("domain")?;
    let start = Instant::now();
    let mut session = Session::open(&dc, Protection::Encrypted, Duration::from_secs(30))?;
    let opened = start.elapsed();
    let policies = format!("{domain}\\Policies");
    let gpos: Vec<String> = session
        .list(&policies)?
        .into_iter()
        .filter(|p| p.ends_with('}'))
        .collect();
    let t = Instant::now();
    let trees = session.walk(&gpos)?;
    let mut files = Vec::new();
    let mut all = Vec::new();
    for tree in &trees {
        all.push(tree.root.clone());
        for e in &tree.entries {
            let path = format!("{}\\{}", tree.root, e.path);
            if !e.directory {
                files.push(path.clone());
            }
            all.push(path);
        }
    }
    let contents = session.read(&files)?;
    let descriptors = session.read_descriptors(&all, INFO_OGD)?;
    let bytes: usize = contents.iter().flatten().map(Vec::len).sum();
    println!(
        "session {opened:?}; {} GPO, {} elements, {} files ({bytes} bytes), {} descriptors in {:?}, {} round trips",
        gpos.len(),
        all.len(),
        files.len(),
        descriptors.iter().flatten().count(),
        t.elapsed(),
        session.round_trips()
    );
    session.close();
    Ok(())
}

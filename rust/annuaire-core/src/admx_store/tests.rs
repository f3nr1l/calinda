// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The store on the SYSVOL and its cache (`test_admx.py`, second half).

use std::os::unix::fs::PermissionsExt as _;

use super::*;
use crate::admx::tests::{files, templates};

const ROOT: &str = "lab.test\\Policies\\PolicyDefinitions";
/// 2026-10-14T12:00:00Z.
const WHEN: u64 = 134_364_528_000_000_000;

/// The test store as the SMB walk would see it.
struct Templates {
    present: bool,
    reads: Vec<Vec<String>>,
    contents: HashMap<String, Vec<u8>>,
    entries: Vec<Entry>,
}

impl Templates {
    fn new(present: bool) -> Self {
        let mut entries = Vec::new();
        let mut contents = HashMap::new();
        let mut paths = Vec::new();
        for e in std::fs::read_dir(templates()).unwrap() {
            let p = e.unwrap().path();
            paths.push(p.clone());
            if p.is_dir() {
                for f in std::fs::read_dir(&p).unwrap() {
                    paths.push(f.unwrap().path());
                }
            }
        }
        paths.sort();
        for p in paths {
            let relative = p
                .strip_prefix(templates())
                .unwrap()
                .to_string_lossy()
                .replace('/', "\\");
            let size = if p.is_file() {
                p.metadata().unwrap().len()
            } else {
                0
            };
            entries.push(Entry {
                path: relative.clone(),
                directory: p.is_dir(),
                size,
                modified: WHEN,
            });
            if p.is_file() {
                contents.insert(
                    sysvol::key(&sysvol::join(&[ROOT, &relative])),
                    std::fs::read(&p).unwrap(),
                );
            }
        }
        Self {
            present,
            reads: Vec::new(),
            contents,
            entries,
        }
    }

    fn tree(&self) -> Tree {
        Tree {
            root: ROOT.into(),
            present: self.present,
            entries: if self.present {
                self.entries.clone()
            } else {
                Vec::new()
            },
            unreadable: Vec::new(),
        }
    }
}

impl SysvolRead for Templates {
    fn walk(&mut self, roots: &[String]) -> sysvol::Result<Vec<Tree>> {
        assert_eq!(roots, [ROOT]);
        Ok(vec![self.tree()])
    }

    fn read(&mut self, paths: &[String]) -> sysvol::Result<Vec<Option<Vec<u8>>>> {
        self.reads.push(paths.to_vec());
        Ok(paths
            .iter()
            .map(|p| self.contents.get(&sysvol::key(p)).cloned())
            .collect())
    }
}

fn fr() -> Vec<String> {
    vec!["fr-FR".to_owned()]
}

fn temporary() -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "annuaire-admx-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn iso_dates() {
    assert_eq!(iso(WHEN), "2026-10-14T12:00:00+00:00");
    assert_eq!(iso(WHEN + 1_234_560), "2026-10-14T12:00:00.123456+00:00");
    assert_eq!(iso(0), "");
}

#[test]
fn plan_languages() {
    let mut s = Templates::new(true);
    let p = plan(&s.tree(), &fr());
    assert_eq!(
        p.files,
        [
            (
                "essai.admx".to_owned(),
                "essai.admx".to_owned(),
                Some("fr-FR\\essai.adml".to_owned())
            ),
            (
                "socle.admx".to_owned(),
                "socle.admx".to_owned(),
                Some("en-US\\socle.adml".to_owned())
            ),
        ]
    );
    assert!(p.language == "fr-FR" || p.language == "en-US");
    // The fingerprint of the Python application: both share the cache.
    assert_eq!(
        (p.fingerprint.as_str(), p.language.as_str(), p.size),
        (
            "4a3b0db81bdf09262b5d098d9cd15b3b54a2849d1f08a9ef9bd3a21de760a069",
            "fr-FR",
            8397
        )
    );
    let english = plan(&s.tree(), &["en-GB".to_owned()]);
    assert_eq!(english.files[0].2.as_deref(), Some("en-US\\essai.adml"));
    assert_ne!(english.fingerprint, p.fingerprint);
    // A size that changes changes the fingerprint.
    for e in &mut s.entries {
        if e.path == "essai.admx" {
            e.size += 1;
        }
    }
    assert_ne!(plan(&s.tree(), &fr()).fingerprint, p.fingerprint);
}

#[test]
fn loading_and_cache() {
    let dir = temporary();
    let mut s = Templates::new(true);
    let first = load_on(&mut s, "dc1.lab.test", "lab.test", &fr(), Some(&dir)).unwrap();
    assert!(!first.from_cache);
    assert!(s.reads.len() == 1 && s.reads[0].len() == 4);
    let store = first.store.as_ref().unwrap();
    assert_eq!(
        store.policy("Annuaire.Essai:Valeurs").unwrap().label,
        "Valeurs et listes"
    );
    let caches: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(caches.len(), 1);
    assert_eq!(
        caches[0].metadata().unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(dir.metadata().unwrap().permissions().mode() & 0o777, 0o700);
    let second = load_on(&mut s, "dc1.lab.test", "lab.test", &fr(), Some(&dir)).unwrap();
    assert!(second.from_cache && s.reads.len() == 1);
    assert_eq!(second.store.unwrap().policies, store.policies);
    // Damaged cache: read again and made again.
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(b"{").unwrap();
    std::fs::write(&caches[0], gz.finish().unwrap()).unwrap();
    let third = load_on(&mut s, "dc1.lab.test", "lab.test", &fr(), Some(&dir)).unwrap();
    assert!(!third.from_cache && s.reads.len() == 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn caches_kept() {
    let dir = temporary().with_extension("kept");
    let m = admx::analyze(&files("fr-FR"), "");
    for i in 0..KEPT_CACHES + 3 {
        write_cache(&m, &format!("{i:064x}"), Some(&dir)).unwrap();
        // Distinct modification times.
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names.iter().filter(|n| n.ends_with(".json.gz")).count(),
        KEPT_CACHES
    );
    assert!(!names.iter().any(|n| n.ends_with(".tmp")));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn store_absent() {
    let dir = temporary().with_extension("absent");
    let loading = load_on(
        &mut Templates::new(false),
        "dc1",
        "lab.test",
        &fr(),
        Some(&dir),
    )
    .unwrap();
    assert!(loading.store.is_none() && loading.path == ROOT);
}

#[test]
fn file_unreadable_on_the_sysvol() {
    let dir = temporary().with_extension("unreadable");
    let mut s = Templates::new(true);
    s.contents
        .remove(&sysvol::key(&sysvol::join(&[ROOT, "socle.admx"])));
    let loading = load_on(&mut s, "dc1", "lab.test", &fr(), Some(&dir)).unwrap();
    let store = loading.store.unwrap();
    assert!(store.errors.iter().any(|e| e.contains("socle.admx")));
    assert!(store.policy("Annuaire.Essai:Valeurs").is_some());
    let _ = std::fs::remove_dir_all(&dir);
}

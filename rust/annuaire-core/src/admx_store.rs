// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Central store of the administrative templates (J7.2, `annuaire.core.magasin_admx`): reading
//! on the SYSVOL and cache.
//!
//! The central store is `\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions`: the ADMXs at
//! the root, the ADMLs in one folder per language. It is read on the SYSVOL of the DC of the
//! connection, read-only.
//!
//! Reading 200 ADMXs and their ADMLs is 8 to 9 MB and half a second of analysis: the result is
//! kept in `$XDG_CACHE_HOME/calinda/modeles/<fingerprint>.json.gz`, the same files as the
//! Python application (same JSON form, same fingerprint). The fingerprint (SHA-256) covers the
//! name, the size and the date of each file kept, as the walk of the folder gives them: an
//! opening that finds the same fingerprint reads no file. A file changed on the SYSVOL changes
//! its date, hence the fingerprint, and the store is read again. The six latest caches are
//! kept.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::Instant;

use annuaire_codecs::time;

use crate::admx::{self, Store};
use crate::sysvol::{self, Entry, Tree};

pub const FOLDER: &str = "PolicyDefinitions";
pub const KEPT_CACHES: usize = 6;

/// Path of the central store, relative to the SYSVOL share.
pub fn store_path(domain: &str) -> String {
    sysvol::join(&[domain, "Policies", FOLDER])
}

/// What to read: for each ADMX (by name), its path and that of the ADML kept (`None` if no
/// language has one). Paths relative to the root of the store (`Plan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub files: Vec<(String, String, Option<String>)>,
    pub language: String,
    pub fingerprint: String,
    /// Bytes to read if the cache does not serve.
    pub size: u64,
}

/// Language folders in the order to try them, file by file.
fn language_order(available: &[String], preferred: &[String]) -> Vec<String> {
    let mut order = Vec::new();
    let mut left = available.to_vec();
    let mut wanted = preferred.to_vec();
    wanted.push(admx::FALLBACK_LANGUAGE.to_owned());
    while let Some(chosen) = admx::choose_language(&left, &wanted) {
        left.retain(|l| *l != chosen);
        order.push(chosen);
    }
    order
}

/// The date of an entry as Python writes it (`datetime.isoformat()`, UTC), empty if unknown.
fn iso(filetime: u64) -> String {
    let Ok(nt) = i64::try_from(filetime) else {
        return String::new();
    };
    if nt <= 0 {
        return String::new();
    }
    match time::nttime_to_utc(nt) {
        Ok(Some(t)) => {
            let c = t.civil();
            let micro = c.fraction / 10;
            let fraction = if micro == 0 {
                String::new()
            } else {
                format!(".{micro:06}")
            };
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}+00:00",
                c.year, c.month, c.day, c.hour, c.minute, c.second
            )
        }
        _ => String::new(),
    }
}

fn sign(e: &Entry) -> String {
    format!("{}|{}|{}", e.path.to_lowercase(), e.size, iso(e.modified))
}

/// Pure: from the walk of the store, the ADML of each ADMX in the first preferred language that
/// has it (then en-US, then another), and the fingerprint of the whole (`planifier`).
pub fn plan(tree: &Tree, preferred: &[String]) -> Plan {
    let root: Vec<&Entry> = tree
        .entries
        .iter()
        .filter(|e| !e.path.contains('\\'))
        .collect();
    let languages: Vec<String> = root
        .iter()
        .filter(|e| e.directory)
        .map(|e| e.path.clone())
        .collect();
    let mut admxs: Vec<&Entry> = root
        .iter()
        .copied()
        .filter(|e| !e.directory && e.path.to_lowercase().ends_with(".admx"))
        .collect();
    admxs.sort_by_key(|e| e.path.to_lowercase());
    let mut admls: HashMap<String, HashMap<String, &Entry>> = HashMap::new();
    for e in &tree.entries {
        if let Some((folder, name)) = e.path.split_once('\\') {
            let lower = name.to_lowercase();
            if !e.directory && !name.contains('\\') && lower.ends_with(".adml") {
                admls.entry(folder.to_lowercase()).or_default().insert(
                    lower.get(..lower.len() - 5).unwrap_or_default().to_owned(),
                    e,
                );
            }
        }
    }
    let order = language_order(&languages, preferred);
    let mut hasher = openssl::sha::Sha256::new();
    hasher.update(format!("admx {}\n", admx::FORMAT).as_bytes());
    let mut kept: HashMap<String, usize> = HashMap::new();
    let mut first_kept: Vec<String> = Vec::new();
    let mut files = Vec::new();
    let mut size = 0;
    for e in admxs {
        let lower = e.path.to_lowercase();
        let base = lower.get(..lower.len() - 5).unwrap_or_default();
        let found = order.iter().find_map(|lg| {
            admls
                .get(&lg.to_lowercase())
                .and_then(|m| m.get(base))
                .map(|a| (lg.clone(), *a))
        });
        files.push((
            e.path.clone(),
            e.path.clone(),
            found.as_ref().map(|(_, a)| a.path.clone()),
        ));
        size += e.size + found.as_ref().map_or(0, |(_, a)| a.size);
        if let Some((lg, _)) = &found {
            if !kept.contains_key(lg) {
                first_kept.push(lg.clone());
            }
            *kept.entry(lg.clone()).or_default() += 1;
        }
        let adml = found
            .as_ref()
            .map_or_else(|| "-".to_owned(), |(_, a)| sign(a));
        hasher.update(format!("{}\n{adml}\n", sign(e)).as_bytes());
    }
    // `Counter.most_common(1)`: the highest count, the first met among equals.
    let best = kept.values().max().copied();
    let language = first_kept
        .into_iter()
        .find(|l| kept.get(l).copied() == best)
        .unwrap_or_default();
    let fingerprint = hasher.finish().iter().map(|b| format!("{b:02x}")).collect();
    Plan {
        files,
        language,
        fingerprint,
        size,
    }
}

// --- Cache --------------------------------------------------------------------------------

pub fn templates_dir() -> PathBuf {
    crate::storage::cache_dir().join("modeles")
}

/// The store kept under this fingerprint; `None` if there is none or if it is unreadable (it
/// will be made again) (`lire_cache`).
pub fn read_cache(fingerprint: &str, dir: Option<&Path>) -> Option<Store> {
    let path = dir
        .map_or_else(templates_dir, Path::to_path_buf)
        .join(format!("{fingerprint}.json.gz"));
    let file = std::fs::File::open(&path).ok()?;
    let mut text = Vec::new();
    flate2::read::GzDecoder::new(file)
        .read_to_end(&mut text)
        .ok()?;
    let value: serde_json::Value = serde_json::from_slice(&text).ok()?;
    let store = admx::from_json(&value).ok()?;
    // The latest served is the last removed.
    let _ = std::fs::File::options()
        .append(true)
        .open(&path)
        .and_then(|f| f.set_modified(std::time::SystemTime::now()));
    Some(store)
}

/// Writes the cache (folder 0700, file 0600, atomic replacement) and keeps only the
/// `KEPT_CACHES` most recent (`ecrire_cache`).
pub fn write_cache(
    store: &Store,
    fingerprint: &str,
    dir: Option<&Path>,
) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let dir = dir.map_or_else(templates_dir, Path::to_path_buf);
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    let data = serde_json::to_vec(&admx::to_json(store)).map_err(std::io::Error::other)?;
    let temporary = dir.join(format!(".{fingerprint}.{}.tmp", std::process::id()));
    let written = (|| -> std::io::Result<PathBuf> {
        let file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        let mut gz = flate2::write::GzEncoder::new(file, flate2::Compression::new(6));
        gz.write_all(&data)?;
        gz.finish()?.sync_all()?;
        let path = dir.join(format!("{fingerprint}.json.gz"));
        std::fs::rename(&temporary, &path)?;
        Ok(path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    let path = written?;
    let mut caches: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&dir)?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(".json.gz"))
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p)))
        .collect();
    caches.sort_by_key(|c| std::cmp::Reverse(c.0));
    for (_, old) in caches.iter().skip(KEPT_CACHES) {
        let _ = std::fs::remove_file(old);
    }
    Ok(path)
}

// --- Reading ------------------------------------------------------------------------------

/// What reading the store asks of the SYSVOL (`LectureSysvol`): `sysvol::Session`, a double in
/// the tests.
pub trait SysvolRead {
    fn walk(&mut self, roots: &[String]) -> sysvol::Result<Vec<Tree>>;
    fn read(&mut self, paths: &[String]) -> sysvol::Result<Vec<Option<Vec<u8>>>>;
}

impl SysvolRead for sysvol::Session {
    fn walk(&mut self, roots: &[String]) -> sysvol::Result<Vec<Tree>> {
        sysvol::Session::walk(self, roots)
    }

    fn read(&mut self, paths: &[String]) -> sysvol::Result<Vec<Option<Vec<u8>>>> {
        sysvol::Session::read(self, paths)
    }
}

/// Result of an opening of the store (`Chargement`). `store` `None`: no central store on this
/// DC. `from_cache`: no file read. Durations in seconds (measures).
#[derive(Debug, Clone)]
pub struct Loading {
    pub dc: String,
    pub path: String,
    pub store: Option<Store>,
    pub from_cache: bool,
    pub plan: Option<Plan>,
    pub durations: Vec<(&'static str, f64)>,
}

/// Blocking: walk of the store, then the cache if it has the same fingerprint, else a grouped
/// read of every file kept, analysis and writing of the cache (`charger_sur`).
pub fn load_on(
    session: &mut dyn SysvolRead,
    dc: &str,
    domain: &str,
    preferred: &[String],
    dir: Option<&Path>,
) -> sysvol::Result<Loading> {
    let path = store_path(domain);
    let mut durations = Vec::new();
    let t = Instant::now();
    let tree = session
        .walk(std::slice::from_ref(&path))?
        .into_iter()
        .next()
        .unwrap_or(Tree {
            root: path.clone(),
            present: false,
            entries: Vec::new(),
            unreadable: Vec::new(),
        });
    durations.push(("parcours", t.elapsed().as_secs_f64()));
    let mut loading = Loading {
        dc: dc.to_owned(),
        path: path.clone(),
        store: None,
        from_cache: false,
        plan: None,
        durations,
    };
    if !tree.present {
        return Ok(loading);
    }
    let plan = plan(&tree, preferred);
    let t = Instant::now();
    if let Some(store) = read_cache(&plan.fingerprint, dir) {
        loading.durations.push(("cache", t.elapsed().as_secs_f64()));
        loading.store = Some(store);
        loading.from_cache = true;
        loading.plan = Some(plan);
        return Ok(loading);
    }
    let t = Instant::now();
    let wanted: Vec<String> = plan
        .files
        .iter()
        .flat_map(|(_, a, l)| std::iter::once(a).chain(l))
        .map(|x| sysvol::join(&[&path, x]))
        .collect();
    let read: HashMap<String, Option<Vec<u8>>> = wanted
        .iter()
        .map(|p| sysvol::key(p))
        .zip(session.read(&wanted)?)
        .collect();
    loading
        .durations
        .push(("lecture", t.elapsed().as_secs_f64()));
    let t = Instant::now();
    let get = |x: &str| {
        read.get(&sysvol::key(&sysvol::join(&[&path, x])))
            .cloned()
            .flatten()
    };
    let mut files = Vec::new();
    let mut missing = Vec::new();
    for (name, a, resources) in &plan.files {
        match get(a) {
            None => missing.push(name.clone()),
            Some(bytes) => files.push((name.clone(), bytes, resources.as_deref().and_then(get))),
        }
    }
    let mut store = admx::analyze(&files, &plan.language);
    store.errors.extend(
        missing
            .iter()
            .map(|n| format!("{n}: unreadable on the SYSVOL.")),
    );
    loading
        .durations
        .push(("analyse", t.elapsed().as_secs_f64()));
    let _ = write_cache(&store, &plan.fingerprint, dir);
    loading.store = Some(store);
    loading.plan = Some(plan);
    Ok(loading)
}

/// Why the store could not be read.
#[derive(Debug, Clone)]
pub enum LoadError {
    Failure(crate::connection::Failure),
    Sysvol(sysvol::SysvolError),
}

/// The central store read on the SYSVOL of the DC of the connection, with the cache of the
/// user (`charger`). Blocking.
pub fn load(
    connection: &crate::connection::Connection,
    preferred: &[String],
) -> Result<Loading, LoadError> {
    let (dc, base, protection) = connection
        .run(true, |link| {
            Ok((
                link.state.dc.clone(),
                link.state.root_dse.default_naming_context.clone(),
                link.sysvol,
            ))
        })
        .map_err(LoadError::Failure)?;
    let domain = crate::gpo_write::domain_dns(&base);
    let mut session = (crate::sysvol_write::opener(protection))(&dc).map_err(LoadError::Sysvol)?;
    let loading = load_on(&mut session, &dc, &domain, preferred, None).map_err(LoadError::Sysvol);
    session.close();
    loading
}

#[cfg(test)]
mod tests;

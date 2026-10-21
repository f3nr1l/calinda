// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Backup and restoration of a GPO (J5.6, ADR 0012, `annuaire.core.sauvegarde_gpo`).
//!
//! Archive: a dated `tar.gz` (`YYYYMMDDTHHMMSSZ_<name>_{GUID}.tar.gz`), readable without the
//! tool, the same format as the Python application (`format` 1):
//!
//! - `annuaire-gpo.json`: the manifest;
//! - `sysvol/…`: each file of the folder of the GPO, at its path relative to this folder.
//!
//! Attribute values: a string if UTF-8 text, otherwise `{"base64": …}` (as the journal).
//! Descriptors: self-relative binary in base64 (owner, group, DACL; never the SACL), and their
//! SDDL for human reading. `objets`: what lies under the GPO (`CN=User`, `CN=Machine`,
//! containers of the extensions), parents first, RDN relative to the GPO, without the
//! attributes the DC keeps. `liens`: for the record; a restoration links nothing (as the GPMC).
//!
//! Restoration, always through the common preview and the journal:
//!
//! - **identical** (same GUID): if the GPO no longer exists, it is created again as it was
//!   (object, descriptor, objects under it, folder, files and the ACL of each); if it exists,
//!   it is brought back to the saved state (attributes, descriptor, objects missing or extra,
//!   files and folders extra, missing or different, ACL), and its version is raised above the
//!   present one (user and computer + 1, `versionNumber` and `GPT.INI` together) for the
//!   computers to apply it again;
//! - **under a new GUID**: a new GPO, copy of the saved one (content, version, filtering), with
//!   the ACL of the folder computed again from its descriptor (`dsacl2fsacl`).
//!
//! An archive is read without trust: members limited to those the manifest declares, relative
//! paths without `..`, sizes and SHA-256 checked, nothing is extracted on the disk.

use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sddl;
use serde_json::{Map, Value, json};

use crate::changes::{
    self, AttributeMap, Change, Changeset, Operation, Read, Values, base64_decode, base64_encode,
    dn_key,
};
use crate::connection::{Connection, Link};
use crate::dn;
use crate::gpo::{self, version_of, versions};
use crate::gpo_write::{
    self, GPO_CLASS, GpoError, GpoRead, SD, Step, domain_dns, gpo_dn, gpo_folder, new_guid,
    unc_path,
};
use crate::messages::{Catalog, Msg};
use crate::session::Scope;
use crate::sysvol::{self, Element};
use crate::sysvol_write::{self, SysvolSession};

pub const FORMAT: i64 = 1;
pub const TYPE: &str = "annuaire-sauvegarde-gpo";
pub const MANIFEST: &str = "annuaire-gpo.json";
pub const SYSVOL_PREFIX: &str = "sysvol/";
/// Total content accepted when reading an archive (a guard against a trapped archive).
pub const MAX_SIZE: u64 = 512 * 1024 * 1024;
const MAX_MANIFEST: u64 = 16 * 1024 * 1024;

/// Attributes of the GPO the backup keeps and the restoration sets back; `cn` and
/// `gPCFileSysPath` follow the GUID, the descriptor is apart.
pub const RESTORED: [&str; 7] = [
    "displayName",
    "flags",
    "versionNumber",
    "gPCFunctionalityVersion",
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "gPCWQLFilter",
];

fn excluded(attribute: &str) -> bool {
    let lower = attribute.to_lowercase();
    changes::SYSTEM.contains(&lower.as_str())
        || [
            "ntsecuritydescriptor",
            "objectguid",
            "showinadvancedviewonly",
            "iscriticalsystemobject",
        ]
        .contains(&lower.as_str())
}

/// Archive unreadable, incomplete or altered (`ErreurSauvegarde`); the interface says it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackupError {
    ArchiveExists(String),
    NoManifest,
    UnknownFormat(String),
    PathRefused(String),
    FileMissing(String),
    UnexpectedSize(String),
    Altered(String),
    Unreadable(String),
    InvalidGuid(String),
    NoDescriptor,
    InvalidObject(String),
    OtherDomain(String),
}

/// `$XDG_DATA_HOME/calinda/sauvegardes-gpo`, or `~/.local/share/calinda/…`
/// (`dossier_par_defaut`).
pub fn default_folder() -> PathBuf {
    crate::storage::data_home()
        .join(crate::storage::APP_DIR)
        .join("sauvegardes-gpo")
}

/// Backup archives of the folder, the most recent first (by their dated name)
/// (`lister_archives`).
pub fn list_archives(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".tar.gz") && n.contains("_{") && n.contains('}'))
        })
        .collect();
    found.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
    found
}

// --- Model ----------------------------------------------------------------------------------------

/// An element of the folder (`ElementSauve`): path relative to the folder of the GPO,
/// separated by `\`, empty for the folder itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedElement {
    pub path: String,
    pub directory: bool,
    pub descriptor: Option<Vec<u8>>,
    pub content: Option<Vec<u8>>,
}

/// A link at the time of the backup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedLink {
    pub container: String,
    pub order: i64,
    pub options: i64,
}

/// A backup (`Sauvegarde`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub date: String,
    pub domain: String,
    pub dc: String,
    pub guid: String,
    pub dn: String,
    pub name: String,
    pub attributes: AttributeMap,
    pub descriptor: Vec<u8>,
    /// (RDN relative to the GPO, attributes), parents first.
    pub objects: Vec<(String, AttributeMap)>,
    pub elements: Vec<SavedElement>,
    pub links: Vec<SavedLink>,
}

impl Backup {
    pub fn values(&self, attribute: &str) -> Values {
        self.attributes
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attribute))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    pub fn version(&self) -> i64 {
        self.values("versionNumber")
            .first()
            .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse().ok())
            .unwrap_or(0)
    }
}

/// `[^\w.-]+` → `-`, then trimmed and cut at 60 characters, as Python.
fn clean_name(name: &str) -> String {
    let mut out = String::new();
    let mut dash = false;
    for c in name.chars() {
        if c.is_alphanumeric() || c == '_' || c == '.' || c == '-' {
            out.push(c);
            dash = false;
        } else if !dash {
            out.push('-');
            dash = true;
        }
    }
    let trimmed: String = out.trim_matches('-').chars().take(60).collect();
    if trimmed.is_empty() {
        "gpo".to_owned()
    } else {
        trimmed
    }
}

/// `AAAAMMJJTHHMMSSZ_<name>_{GUID}.tar.gz` (`_nom_fichier`).
pub fn file_name(backup: &Backup) -> String {
    let date: String = backup
        .date
        .replace(['-', ':'], "")
        .replace("+0000", "Z")
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == 'T' || *c == 'Z')
        .collect();
    format!("{date}_{}_{}.tar.gz", clean_name(&backup.name), backup.guid)
}

fn sd_json(bytes: Option<&[u8]>) -> Value {
    let Some(bytes) = bytes else {
        return Value::Null;
    };
    let text = SecurityDescriptor::decode(bytes)
        .ok()
        .and_then(|sd| sddl::sd_to_sddl(&sd, None).ok())
        .unwrap_or_default();
    json!({"base64": base64_encode(bytes), "sddl": text})
}

fn sd_from(value: Option<&Value>) -> Result<Option<Vec<u8>>, BackupError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let text = v
                .get("base64")
                .and_then(Value::as_str)
                .ok_or_else(|| BackupError::Unreadable("base64".into()))?;
            base64_decode(text)
                .map(Some)
                .map_err(|e| BackupError::Unreadable(e.to_string()))
        }
    }
}

fn relative(path: &str, root: &str) -> String {
    if sysvol::key(path) == sysvol::key(root) {
        return String::new();
    }
    path.get(root.trim_matches('\\').len() + 1..)
        .unwrap_or_default()
        .to_owned()
}

fn sha256(bytes: &[u8]) -> String {
    openssl::sha::sha256(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The manifest (`manifeste`).
pub fn manifest(backup: &Backup, root: &str) -> Value {
    let elements: Vec<Value> = backup
        .elements
        .iter()
        .map(|e| {
            let mut d = Map::new();
            d.insert("chemin".into(), json!(e.path));
            d.insert("dossier".into(), json!(e.directory));
            if !e.directory {
                let content = e.content.as_deref().unwrap_or_default();
                d.insert("taille".into(), json!(content.len()));
                d.insert("sha256".into(), json!(sha256(content)));
            }
            d.insert("descripteur".into(), sd_json(e.descriptor.as_deref()));
            Value::Object(d)
        })
        .collect();
    let objects: Vec<Value> = backup
        .objects
        .iter()
        .map(|(rdn, a)| json!({"rdn": rdn, "attributs": changes::attributes_to_json(a)}))
        .collect();
    let links: Vec<Value> = backup
        .links
        .iter()
        .map(|l| json!({"conteneur": l.container, "ordre": l.order, "options": l.options}))
        .collect();
    json!({
        "format": FORMAT,
        "type": TYPE,
        "date": backup.date,
        "domaine": backup.domain,
        "dc": backup.dc,
        "gpo": {
            "guid": backup.guid,
            "dn": backup.dn,
            "nom": backup.name,
            "attributs": changes::attributes_to_json(&backup.attributes),
            "descripteur": sd_json(Some(&backup.descriptor)),
            "objets": objects,
        },
        "liens": links,
        "sysvol": {"racine": root, "elements": elements},
    })
}

// --- Archive ---------------------------------------------------------------------------------------

/// Days since 1970-01-01 of a civil date (proleptic Gregorian).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `2026-10-16T12:34:56Z` → seconds since 1970 (0 if unreadable).
fn unix_seconds(date: &str) -> u64 {
    let n = |a: usize, b: usize| date.get(a..b).and_then(|t| t.parse::<i64>().ok());
    let (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(s)) =
        (n(0, 4), n(5, 7), n(8, 10), n(11, 13), n(14, 16), n(17, 19))
    else {
        return 0;
    };
    u64::try_from(days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s).unwrap_or(0)
}

/// The date of now, `2026-10-16T12:34:56Z`.
pub fn now() -> String {
    crate::writer::timestamp().replace("+00:00", "Z")
}

/// The archive in memory: the manifest, then each file under `sysvol/`.
pub fn archive_bytes(backup: &Backup) -> Result<Vec<u8>, BackupError> {
    let io = |e: std::io::Error| BackupError::Unreadable(e.to_string());
    let root = gpo_folder(&backup.domain, &backup.guid);
    let mtime = unix_seconds(&backup.date);
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(encoder);
    let mut add = |name: &str, bytes: &[u8]| -> Result<(), BackupError> {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o600);
        header.set_mtime(mtime);
        header.set_entry_type(tar::EntryType::Regular);
        tar.append_data(&mut header, name, bytes).map_err(io)
    };
    let text = serde_json::to_vec_pretty(&manifest(backup, &root))
        .map_err(|e| BackupError::Unreadable(e.to_string()))?;
    add(MANIFEST, &text)?;
    for e in backup.elements.iter().filter(|e| !e.directory) {
        let name = format!("{SYSVOL_PREFIX}{}", e.path.replace('\\', "/"));
        add(&name, e.content.as_deref().unwrap_or_default())?;
    }
    tar.into_inner().map_err(io)?.finish().map_err(io)
}

/// Writes the archive in `folder` (created if needed, private), without overwriting; returns
/// its path (`ecrire_archive`).
pub fn write_archive(backup: &Backup, folder: &Path) -> Result<PathBuf, BackupError> {
    use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
    let io = |e: std::io::Error| BackupError::Unreadable(e.to_string());
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(folder)
        .map_err(io)?;
    let target = folder.join(file_name(backup));
    if target.exists() {
        return Err(BackupError::ArchiveExists(target.display().to_string()));
    }
    let bytes = archive_bytes(backup)?;
    let temporary = folder.join(format!(
        ".sauvegarde-{}",
        new_guid().trim_matches(|c| c == '{' || c == '}')
    ));
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600))?;
        // Fails if the target appeared meanwhile.
        std::fs::hard_link(&temporary, &target)
    })();
    let _ = std::fs::remove_file(&temporary);
    written.map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            BackupError::ArchiveExists(target.display().to_string())
        } else {
            io(e)
        }
    })?;
    Ok(target)
}

fn safe_path(path: &str) -> bool {
    path.split('\\')
        .all(|m| !["", ".", ".."].contains(&m) && !m.contains('/'))
}

/// Reads and checks an archive (manifest, declared members, sizes, digests) (`lire_archive`).
pub fn read_archive(path: &Path) -> Result<Backup, BackupError> {
    let unreadable = |e: &dyn std::fmt::Display| BackupError::Unreadable(e.to_string());
    let file = std::fs::File::open(path).map_err(|e| unreadable(&e))?;
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(file));
    let mut members: HashMap<String, Option<Vec<u8>>> = HashMap::new();
    let mut total: u64 = 0;
    for entry in archive.entries().map_err(|e| unreadable(&e))? {
        let mut entry = entry.map_err(|e| unreadable(&e))?;
        let name = entry
            .path()
            .map_err(|e| unreadable(&e))?
            .to_string_lossy()
            .into_owned();
        let size = entry.header().size().map_err(|e| unreadable(&e))?;
        if !entry.header().entry_type().is_file() {
            members.insert(name, None);
            continue;
        }
        let limit = if name == MANIFEST {
            MAX_MANIFEST
        } else {
            MAX_SIZE
        };
        total += size;
        if size > limit || total > MAX_SIZE + MAX_MANIFEST {
            return Err(if name == MANIFEST {
                BackupError::NoManifest
            } else {
                BackupError::UnexpectedSize(name)
            });
        }
        let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
        entry.read_to_end(&mut bytes).map_err(|e| unreadable(&e))?;
        members.insert(name, Some(bytes));
    }
    let Some(Some(raw)) = members.get(MANIFEST) else {
        return Err(BackupError::NoManifest);
    };
    let doc: Value = serde_json::from_slice(raw).map_err(|e| unreadable(&e))?;
    if doc.get("type").and_then(Value::as_str) != Some(TYPE)
        || doc.get("format").and_then(Value::as_i64) != Some(FORMAT)
    {
        return Err(BackupError::UnknownFormat(
            doc.get("format").map(Value::to_string).unwrap_or_default(),
        ));
    }
    let text = |v: &Value, k: &str| -> Result<String, BackupError> {
        match v.get(k) {
            Some(Value::String(s)) => Ok(s.clone()),
            Some(other) => Ok(other.to_string()),
            None => Err(BackupError::Unreadable(k.to_owned())),
        }
    };
    let mut elements = Vec::new();
    let mut read_total: u64 = 0;
    let declared = doc
        .pointer("/sysvol/elements")
        .and_then(Value::as_array)
        .ok_or_else(|| BackupError::Unreadable("sysvol".into()))?;
    for d in declared {
        let rel = text(d, "chemin")?;
        if !rel.is_empty() && !safe_path(&rel) {
            return Err(BackupError::PathRefused(rel));
        }
        let directory = d
            .get("dossier")
            .and_then(Value::as_bool)
            .ok_or_else(|| BackupError::Unreadable("dossier".into()))?;
        let mut content = None;
        if !directory {
            let name = format!("{SYSVOL_PREFIX}{}", rel.replace('\\', "/"));
            let Some(Some(bytes)) = members.get(&name) else {
                return Err(BackupError::FileMissing(rel));
            };
            read_total += bytes.len() as u64;
            let size = d.get("taille").and_then(Value::as_u64);
            if size != Some(bytes.len() as u64) || read_total > MAX_SIZE {
                return Err(BackupError::UnexpectedSize(rel));
            }
            if d.get("sha256").and_then(Value::as_str) != Some(sha256(bytes).as_str()) {
                return Err(BackupError::Altered(rel));
            }
            content = Some(bytes.clone());
        }
        elements.push(SavedElement {
            path: rel,
            directory,
            descriptor: sd_from(d.get("descripteur"))?,
            content,
        });
    }
    let gpo = doc
        .get("gpo")
        .ok_or_else(|| BackupError::Unreadable("gpo".into()))?;
    let guid = text(gpo, "guid")?.to_uppercase();
    if !gpo::is_folder_guid(&guid) {
        return Err(BackupError::InvalidGuid(guid));
    }
    let descriptor = sd_from(gpo.get("descripteur"))?.ok_or(BackupError::NoDescriptor)?;
    let mut objects = Vec::new();
    for o in gpo
        .get("objets")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
    {
        let rdn = text(o, "rdn")?;
        if dn::split(&rdn).map_or(true, |c| c.is_empty()) {
            return Err(BackupError::InvalidObject(rdn));
        }
        let attributes = changes::attributes_from_json(o.get("attributs").unwrap_or(&Value::Null))
            .map_err(|e| unreadable(&e))?;
        objects.push((rdn, attributes));
    }
    let links = doc
        .get("liens")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .map(|l| SavedLink {
            container: l
                .get("conteneur")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            order: l.get("ordre").and_then(Value::as_i64).unwrap_or(0),
            options: l.get("options").and_then(Value::as_i64).unwrap_or(0),
        })
        .collect();
    Ok(Backup {
        date: text(&doc, "date")?,
        domain: text(&doc, "domaine")?,
        dc: text(&doc, "dc")?,
        guid,
        dn: text(gpo, "dn")?,
        name: text(gpo, "nom")?,
        attributes: changes::attributes_from_json(gpo.get("attributs").unwrap_or(&Value::Null))
            .map_err(|e| unreadable(&e))?,
        descriptor,
        objects,
        elements,
        links,
    })
}

// --- Reading on the DC ---------------------------------------------------------------------------

/// Objects under the GPO, parents first, without the attributes the DC keeps (`_sous_objets`).
fn sub_objects(link: &mut Link, dn_text: &str) -> Result<Vec<(String, AttributeMap)>, Step> {
    let mut entries = gpo_write::search(link, dn_text, Scope::Subtree, "(objectClass=*)", &["*"])?;
    let depth = dn::split(dn_text).map_or(0, |c| c.len());
    let key = dn_key(dn_text).unwrap_or_default();
    entries.sort_by_key(|e| dn::split(&e.dn).map_or(0, |c| c.len()));
    let mut objects = Vec::new();
    for e in entries {
        if dn_key(&e.dn).unwrap_or_default() == key {
            continue;
        }
        let components = dn::split(&e.dn).unwrap_or_default();
        let rdn = dn::compose(
            components
                .get(..components.len().saturating_sub(depth))
                .unwrap_or_default(),
        )
        .unwrap_or_default();
        let attributes = e
            .attributes
            .iter()
            .filter(|(a, _)| !excluded(a))
            .cloned()
            .collect();
        objects.push((rdn, attributes));
    }
    Ok(objects)
}

fn read_backup(
    link: &mut Link,
    session: &mut SysvolSession,
    dn_text: &str,
    date: &str,
) -> Result<Backup, Step> {
    let gpo = gpo_write::read_gpo(link, dn_text)?;
    let attributes: AttributeMap = RESTORED
        .iter()
        .filter_map(|a| {
            let v = gpo.values(a);
            (!v.is_empty()).then(|| ((*a).to_owned(), v.to_vec()))
        })
        .collect();
    let root = gpo.folder.clone();
    let elements = session
        .client()?
        .survey(&root, true, true)?
        .into_iter()
        .map(|e| SavedElement {
            path: relative(&e.path, &root),
            directory: e.directory,
            descriptor: e.descriptor,
            content: e.content,
        })
        .collect();
    let mut links = Vec::new();
    for container in gpo_write::linked_containers(link, &gpo.guid())? {
        let list = container.links();
        let n = list.links().count();
        for (position, l) in list.links().enumerate() {
            if l.guid().as_deref() == Some(gpo.guid().as_str()) {
                links.push(SavedLink {
                    container: container.dn.clone(),
                    order: i64::try_from(n - position).unwrap_or(0),
                    options: i64::try_from(l.options).unwrap_or(0),
                });
            }
        }
    }
    let base = link.state.root_dse.default_naming_context.clone();
    Ok(Backup {
        date: date.to_owned(),
        domain: domain_dns(&base),
        dc: link.state.dc.clone(),
        guid: gpo.guid(),
        dn: gpo.dn.clone(),
        name: gpo.name(),
        attributes,
        descriptor: gpo.descriptor()?.to_vec(),
        objects: sub_objects(link, &gpo.dn)?,
        elements,
        links,
    })
}

/// Reads the GPO (object, objects under it, SYSVOL folder with ACL, links) on the write DC and
/// writes it in a dated archive of `folder` (`sauvegarder`). Nothing is modified. Blocking.
pub fn back_up(connection: &Connection, dn_text: &str, folder: &Path) -> Result<PathBuf, GpoError> {
    let dn_text = dn_text.to_owned();
    let date = now();
    let backup = gpo_write::run(connection, move |link| {
        let mut session = SysvolSession::new(sysvol_write::opener(link.sysvol), &link.state.dc);
        let result = read_backup(link, &mut session, &dn_text, &date);
        session.close();
        result
    })?;
    write_archive(&backup, folder).map_err(GpoError::Backup)
}

// --- Restoration ---------------------------------------------------------------------------------

/// Version above the two, part by part (user in the 16 high bits) (`version_suivante`).
pub fn next_version(present: i64, saved: i64) -> i64 {
    let (a, b) = (versions(present), versions(saved));
    version_of(gpo::Versions {
        user: (a.user.max(b.user) + 1) & 0xFFFF,
        computer: (a.computer.max(b.computer) + 1) & 0xFFFF,
    })
}

fn sysvol_creation(
    dn_text: &str,
    root: &str,
    elements: &[SavedElement],
    forced_sd: Option<&[u8]>,
) -> Vec<Operation> {
    let mut sorted: Vec<&SavedElement> = elements.iter().collect();
    sorted.sort_by_key(|e| (e.path.matches('\\').count(), !e.directory));
    sorted
        .into_iter()
        .map(|e| {
            let path = sysvol::join(&[root, &e.path]);
            let sd = forced_sd
                .map(<[u8]>::to_vec)
                .or_else(|| e.descriptor.clone());
            if e.directory {
                Operation::CreateFolder {
                    dn: dn_text.to_owned(),
                    path,
                    descriptor: sd,
                }
            } else {
                Operation::WriteFile {
                    dn: dn_text.to_owned(),
                    path,
                    content: e.content.clone().unwrap_or_default(),
                    old: None,
                    descriptor: sd,
                }
            }
        })
        .collect()
}

fn creation_attributes(backup: &Backup, guid: &str, name: &str) -> AttributeMap {
    let mut attributes: AttributeMap = vec![
        ("objectClass".into(), vec![GPO_CLASS.as_bytes().to_vec()]),
        ("cn".into(), vec![guid.as_bytes().to_vec()]),
        (
            "gPCFileSysPath".into(),
            vec![unc_path(&backup.domain, guid).into_bytes()],
        ),
    ];
    for a in RESTORED {
        let v = backup.values(a);
        if !v.is_empty() {
            attributes.push((a.to_owned(), v));
        }
    }
    match attributes.iter_mut().find(|(a, _)| a == "displayName") {
        Some((_, v)) => *v = vec![name.as_bytes().to_vec()],
        None => attributes.push(("displayName".into(), vec![name.as_bytes().to_vec()])),
    }
    attributes
}

fn links_remark(backup: &Backup, catalog: &dyn Catalog) -> String {
    catalog.text(&Msg::GpoBackupLinks {
        links: backup
            .links
            .iter()
            .map(|l| l.container.as_str())
            .collect::<Vec<_>>()
            .join(", "),
    })
}

/// Creates the saved GPO again (pure) (`restaurer_absente`): under its GUID (identical, ACL
/// included) or under `guid` (copy: ACL of the folder computed again from the descriptor).
pub fn restore_absent(
    backup: &Backup,
    base: &str,
    guid: Option<&str>,
    name: Option<&str>,
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let guid = guid.map_or_else(|| backup.guid.clone(), str::to_uppercase);
    let copy = guid != backup.guid;
    let name = name.unwrap_or(&backup.name).trim().to_owned();
    let dn_text = gpo_dn(base, &guid);
    let mut attributes = creation_attributes(backup, &guid, &name);
    attributes.push((SD.into(), vec![backup.descriptor.clone()]));
    let mut operations = vec![Operation::add(&dn_text, attributes)?];
    for (rdn, a) in &backup.objects {
        operations.push(Operation::add(&format!("{rdn},{dn_text}"), a.clone())?);
    }
    let root = gpo_folder(&backup.domain, &guid);
    let forced = if copy {
        Some(gpo_write::file_bytes(&backup.descriptor)?)
    } else {
        None
    };
    operations.extend(sysvol_creation(
        &dn_text,
        &root,
        &backup.elements,
        forced.as_deref(),
    ));
    let mut remarks = vec![if copy {
        catalog.text(&Msg::GpoCopy {
            name: backup.name.clone(),
            old: backup.guid.clone(),
            guid,
        })
    } else {
        catalog.text(&Msg::GpoRecreated {
            name,
            guid,
            date: backup.date.clone(),
        })
    }];
    if !backup.links.is_empty() {
        remarks.push(links_remark(backup, catalog));
    }
    Ok(Changeset {
        operations,
        remarks,
    })
}

/// An object under the existing GPO: DN, version, attributes.
pub type Present = (String, Read, AttributeMap);

/// Brings the existing GPO back to the saved state (pure) (`restaurer_existante`). `objects`:
/// objects under the GPO; `elements`: its folder, contents and descriptors included.
pub fn restore_existing(
    backup: &Backup,
    gpo: &GpoRead,
    objects: &[Present],
    elements: &[Element],
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let present_version = gpo.text("versionNumber").trim().parse().unwrap_or(0);
    let version = next_version(present_version, backup.version());
    let mut operations = Vec::new();

    let mut changes = Vec::new();
    for a in RESTORED {
        let before = gpo.values(a).to_vec();
        let after = if a == "versionNumber" {
            vec![version.to_string().into_bytes()]
        } else {
            backup.values(a)
        };
        if before != after {
            let removed: Values = before
                .iter()
                .filter(|v| !after.contains(v))
                .cloned()
                .collect();
            let added: Values = after
                .iter()
                .filter(|v| !before.contains(v))
                .cloned()
                .collect();
            if !removed.is_empty() || !added.is_empty() {
                changes.push(Change::new(a, removed, added)?);
            }
        }
    }
    let descriptor = gpo.descriptor()?;
    if !sysvol_write::same_descriptor(Some(descriptor), Some(&backup.descriptor)) {
        changes.push(Change::new(
            SD,
            vec![descriptor.to_vec()],
            vec![backup.descriptor.clone()],
        )?);
    }
    if !changes.is_empty() {
        operations.push(Operation::modify(&gpo.dn, changes, Some(gpo.read.clone()))?);
    }

    let key = |d: &str| dn_key(d).unwrap_or_else(|_| d.to_lowercase());
    let saved: Vec<(String, String, &AttributeMap)> = backup
        .objects
        .iter()
        .map(|(rdn, a)| {
            let full = format!("{rdn},{}", gpo.dn);
            (key(&full), full, a)
        })
        .collect();
    let mut present: Vec<&Present> = objects.iter().collect();
    present.sort_by_key(|(d, _, _)| std::cmp::Reverse(dn::split(d).map_or(0, |c| c.len())));
    for (d, read, _) in present {
        if !saved.iter().any(|(k, _, _)| *k == key(d)) {
            operations.push(Operation::delete(d, Some(read.clone()), Vec::new())?);
        }
    }
    for (k, full, a) in &saved {
        if !objects.iter().any(|(d, _, _)| key(d) == *k) {
            operations.push(Operation::add(full, (*a).clone())?);
        }
    }

    let root = &gpo.folder;
    let actual: Vec<(String, &Element)> = elements
        .iter()
        .map(|e| (sysvol::key(&relative(&e.path, root)), e))
        .collect();
    let wanted: HashMap<String, &SavedElement> = backup
        .elements
        .iter()
        .map(|e| (sysvol::key(&e.path), e))
        .collect();
    let mut deepest: Vec<&(String, &Element)> = actual.iter().collect();
    deepest.sort_by_key(|(_, e)| std::cmp::Reverse(e.path.matches('\\').count()));
    for (k, e) in deepest {
        if wanted.get(k).is_none_or(|w| w.directory != e.directory) {
            operations.extend(gpo_write::folder_deletion(
                &gpo.dn,
                std::slice::from_ref(*e),
            ));
        }
    }
    let mut ordered: Vec<&SavedElement> = backup.elements.iter().collect();
    ordered.sort_by_key(|e| e.path.matches('\\').count());
    for s in ordered {
        let k = sysvol::key(&s.path);
        let path = sysvol::join(&[root, &s.path]);
        let mut content = s.content.clone().unwrap_or_default();
        if k == "gpt.ini" {
            content = gpo::gpt_ini_with_version(&content, version);
        }
        let present = actual.iter().find(|(x, _)| *x == k).map(|(_, e)| *e);
        let Some(present) = present.filter(|p| p.directory == s.directory) else {
            operations.push(if s.directory {
                Operation::CreateFolder {
                    dn: gpo.dn.clone(),
                    path,
                    descriptor: s.descriptor.clone(),
                }
            } else {
                Operation::WriteFile {
                    dn: gpo.dn.clone(),
                    path,
                    content,
                    old: None,
                    descriptor: s.descriptor.clone(),
                }
            });
            continue;
        };
        let old = present.content.clone().unwrap_or_default();
        if !s.directory && old != content {
            operations.push(Operation::WriteFile {
                dn: gpo.dn.clone(),
                path: path.clone(),
                content,
                old: Some(old),
                descriptor: None,
            });
        }
        if let (Some(want), Some(have)) = (&s.descriptor, &present.descriptor)
            && !sysvol_write::same_descriptor(Some(have), Some(want))
        {
            operations.push(Operation::SetDescriptor {
                dn: gpo.dn.clone(),
                path,
                before: have.clone(),
                after: want.clone(),
            });
        }
    }
    let v = versions(version);
    let mut remarks = vec![catalog.text(&Msg::GpoRestored {
        name: gpo.name(),
        date: backup.date.clone(),
        version,
        user: v.user,
        computer: v.computer,
    })];
    if !backup.links.is_empty() {
        remarks.push(links_remark(backup, catalog));
    }
    Ok(Changeset {
        operations,
        remarks,
    })
}

/// Changeset of a restoration: identical (the GPO exists or not), or a copy under a new GUID
/// (`new_guid`, with `name` if given). Read on the write DC (`preparer_restauration`).
/// Blocking.
pub fn prepare_restoration(
    connection: &Connection,
    backup: &Backup,
    copy: bool,
    name: Option<&str>,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let backup = backup.clone();
    let name = name.map(str::to_owned);
    gpo_write::on_dc(connection, move |link, session| {
        let base = link.state.root_dse.default_naming_context.clone();
        if domain_dns(&base) != backup.domain.to_lowercase() {
            return Err(GpoError::Backup(BackupError::OtherDomain(backup.domain.clone())).into());
        }
        if copy {
            let guid = new_guid();
            let wanted = name.clone().unwrap_or_else(|| backup.name.clone());
            return Ok(restore_absent(
                &backup,
                &base,
                Some(&guid),
                Some(&wanted),
                catalog.as_ref(),
            )?);
        }
        let dn_text = gpo_dn(&base, &backup.guid);
        let exists = search_one(link, &dn_text)?;
        if !exists {
            return Ok(restore_absent(
                &backup,
                &base,
                None,
                name.as_deref(),
                catalog.as_ref(),
            )?);
        }
        let gpo = gpo_write::read_gpo(link, &dn_text)?;
        let key = dn_key(&dn_text).unwrap_or_default();
        let mut objects = Vec::new();
        for entry in gpo_write::search(link, &dn_text, Scope::Subtree, "(objectClass=*)", &["*"])? {
            if dn_key(&entry.dn).unwrap_or_default() != key {
                let read = Read {
                    dc: link.state.dc.clone(),
                    usn: entry
                        .values("uSNChanged")
                        .first()
                        .and_then(|v| std::str::from_utf8(v).ok()?.parse().ok())
                        .unwrap_or(0),
                };
                objects.push((entry.dn.clone(), read, entry.attributes.clone()));
            }
        }
        let client = session.client()?;
        let found = if client.nature(&gpo.folder)?.is_some() {
            client.survey(&gpo.folder, true, true)?
        } else {
            Vec::new()
        };
        Ok(restore_existing(
            &backup,
            &gpo,
            &objects,
            &found,
            catalog.as_ref(),
        )?)
    })
}

fn search_one(link: &mut Link, dn_text: &str) -> Result<bool, Step> {
    Ok(crate::search::read_entry(
        link.session.as_mut(),
        dn_text,
        &["1.1".to_owned()],
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )?
    .is_some())
}

#[cfg(test)]
mod tests;

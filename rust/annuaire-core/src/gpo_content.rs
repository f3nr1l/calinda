// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Content of a GPO (J7.4, the content API of `annuaire.core.actions_gpo`): the files of its two
//! parts read on the write DC, and the changeset that writes them (ADR 0013).
//!
//! The editors of the content (administrative templates, raw registry, security settings,
//! preferences) all go through here: the GPO, `GPT.INI` and the wanted files read on the SYSVOL
//! of the PDC emulator in one batch of compounds; each editor gives the new content of its files
//! from what was read (its draft replayed on it); `write_contents` makes one changeset of it:
//! the files, `GPT.INI` with the version of each touched part raised, the object
//! (`versionNumber` and the list of extensions of each touched part) under the guard of
//! `uSNChanged`. Preview, journal, undo and resumption are those of every write.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

use annuaire_codecs::extensions::{self, Extension, Pair};
use annuaire_codecs::registry_pol::{self as rp, Entry};

use crate::changes::{Change, Changeset, Operation};
use crate::connection::{Connection, Link};
use crate::gpo::{self, Part};
use crate::gpo_write::{self as gw, GpoError, GpoRead, Step};
use crate::messages::{Catalog, Msg};
use crate::sysvol::{self, State};
use crate::sysvol_write::SysvolSession;

pub const REGISTRY_POL: &str = "Registry.pol";
pub const GPT_INI: &str = "GPT.INI";

/// The folder of a part in the folder of the GPO.
pub fn part_folder(part: Part) -> &'static str {
    match part {
        Part::Computer => "Machine",
        Part::User => "User",
    }
}

/// The attribute listing the extensions of a part.
pub fn extensions_attribute(part: Part) -> &'static str {
    match part {
        Part::Computer => "gPCMachineExtensionNames",
        Part::User => "gPCUserExtensionNames",
    }
}

/// The pair a `Registry.pol` declares (administrative templates), as the GPMC
/// (`extension_registre`).
pub fn registry_extension(part: Part) -> Pair {
    let tool = match part {
        Part::Computer => extensions::REGISTRY_TOOL_MACHINE,
        Part::User => extensions::REGISTRY_TOOL_USER,
    };
    (extensions::REGISTRY.to_owned(), tool.to_owned())
}

/// Version after a write of the content of `part`: the highest of the two halves (directory,
/// `GPT.INI`) plus one for this part, the other part kept as the directory carries it. After
/// 65535 back to 1 (never 0, which means « empty ») (`version_modifiee`).
pub fn modified_version(directory: i64, sysvol: Option<i64>, part: Part) -> i64 {
    let a = gpo::versions(directory);
    let mut current = a.of(part);
    if let Some(s) = sysvol {
        current = current.max(gpo::versions(s).of(part));
    }
    let next = if current < 0xFFFF { current + 1 } else { 1 };
    match part {
        Part::Computer => gpo::version_of(gpo::Versions {
            user: a.user,
            computer: next,
        }),
        Part::User => gpo::version_of(gpo::Versions {
            user: next,
            computer: a.computer,
        }),
    }
}

/// Files of a part of a GPO read on the write DC, with what is needed to write them again: the
/// GPO (version, extensions, descriptor), `GPT.INI`, and for each path read (files asked and
/// folders leading to them) its nature, its descriptor and its content (`ContenuLu`).
///
/// The paths of the files are relative to the folder of the part (`Machine` or `User`):
/// `Registry.pol`, `Microsoft\Windows NT\SecEdit\GptTmpl.inf`.
#[derive(Debug, Clone)]
pub struct ContentRead {
    pub gpo: GpoRead,
    pub part: Part,
    pub gpt_ini: Option<Vec<u8>>,
    /// By `sysvol::key` of the full path (relative to the share).
    pub states: Arc<HashMap<String, State>>,
}

impl ContentRead {
    pub fn root(&self) -> String {
        sysvol::join(&[&self.gpo.folder, part_folder(self.part)])
    }

    pub fn path(&self, relative: &str) -> String {
        sysvol::join(&[&self.root(), &relative.replace('/', "\\")])
    }

    pub fn state(&self, relative: &str) -> Result<&State, GpoError> {
        self.states
            .get(&sysvol::key(&self.path(relative)))
            .ok_or_else(|| GpoError::NotRead {
                path: relative.to_owned(),
            })
    }

    /// Content of the file; `None` if it does not exist.
    pub fn content(&self, relative: &str) -> Result<Option<&[u8]>, GpoError> {
        let state = self.state(relative)?;
        match state.nature {
            Some(true) => Err(GpoError::IsFolder {
                path: self.path(relative),
                dn: self.gpo.dn.clone(),
            }),
            Some(false) => Ok(Some(state.content.as_deref().unwrap_or_default())),
            None => Ok(None),
        }
    }

    pub fn extensions(&self) -> Vec<Extension> {
        extensions::decode(&self.gpo.text(extensions_attribute(self.part))).unwrap_or_default()
    }

    pub fn version(&self) -> i64 {
        self.gpo.text("versionNumber").trim().parse().unwrap_or(0)
    }
}

/// What a writer of content wants (`ModificationContenu`): new content of each file (relative
/// to the folder of the part; `None` deletes it; an unchanged file is ignored), pairs
/// (client-side extension, tool) to declare or to remove, remarks for the preview.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContentChange {
    pub files: Vec<(String, Option<Vec<u8>>)>,
    pub add_extensions: Vec<Pair>,
    pub remove_extensions: Vec<Pair>,
    pub remarks: Vec<String>,
}

/// Missing folders between the folder of the GPO (excluded) and `path` (excluded), from the
/// highest to the lowest.
fn parents_to_create(
    read: &ContentRead,
    path: &str,
    done: &HashSet<String>,
) -> Result<Vec<String>, GpoError> {
    let mut missing = Vec::new();
    let top = sysvol::key(&read.gpo.folder);
    let mut parent = sysvol::parent(path).to_owned();
    while !parent.is_empty()
        && sysvol::key(&parent).starts_with(&format!("{top}\\"))
        && sysvol::key(&parent) != top
    {
        match read.states.get(&sysvol::key(&parent)).map(|s| s.nature) {
            Some(Some(true)) => break,
            Some(Some(false)) => {
                return Err(GpoError::IsFile {
                    path: parent,
                    dn: read.gpo.dn.clone(),
                });
            }
            _ => {}
        }
        if !done.contains(&sysvol::key(&parent)) {
            missing.push(parent.clone());
        }
        parent = sysvol::parent(&parent).to_owned();
    }
    missing.reverse();
    Ok(missing)
}

fn file_operations(
    read: &ContentRead,
    change: &ContentChange,
    sd: &[u8],
    created: &mut HashSet<String>,
) -> Result<Vec<Operation>, GpoError> {
    let dn = &read.gpo.dn;
    let mut operations = Vec::new();
    for (relative, new) in &change.files {
        let path = read.path(relative);
        let old = read.content(relative)?;
        if new.as_deref() == old {
            continue;
        }
        match (new, old) {
            (None, old) => operations.push(Operation::DeleteFile {
                dn: dn.clone(),
                path,
                content: old.unwrap_or_default().to_vec(),
                descriptor: read.state(relative)?.descriptor.clone(),
            }),
            (Some(new), None) => {
                for folder in parents_to_create(read, &path, created)? {
                    created.insert(sysvol::key(&folder));
                    operations.push(Operation::CreateFolder {
                        dn: dn.clone(),
                        path: folder,
                        descriptor: Some(sd.to_vec()),
                    });
                }
                operations.push(Operation::WriteFile {
                    dn: dn.clone(),
                    path,
                    content: new.clone(),
                    old: None,
                    descriptor: Some(sd.to_vec()),
                });
            }
            (Some(new), Some(old)) => operations.push(Operation::WriteFile {
                dn: dn.clone(),
                path,
                content: new.clone(),
                old: Some(old.to_vec()),
                descriptor: None,
            }),
        }
    }
    Ok(operations)
}

fn extensions_change(
    read: &ContentRead,
    change: &ContentChange,
) -> Result<Option<Change>, GpoError> {
    let attribute = extensions_attribute(read.part);
    let current = read.extensions();
    let groups = extensions::with(&current, &change.add_extensions, &change.remove_extensions);
    if extensions::encode(&current) == extensions::encode(&groups) {
        return Ok(None); // same content: nothing to write again, even in another order
    }
    let before = read
        .gpo
        .values(attribute)
        .first()
        .cloned()
        .filter(|v| !v.is_empty());
    let after = (!groups.is_empty()).then(|| extensions::encode(&groups).into_bytes());
    if before == after {
        return Ok(None);
    }
    Ok(Some(Change::new(
        attribute,
        before.into_iter().collect(),
        after.into_iter().collect(),
    )?))
}

/// `write_contents` for one part (`ecrire_contenu`).
pub fn write_content(
    read: &ContentRead,
    change: &ContentChange,
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    write_contents(
        &BTreeMap::from([(order(read.part), (read.clone(), change.clone()))]),
        catalog,
    )
}

/// Computer part first, as Python iterates `Partie`.
pub fn order(part: Part) -> u8 {
    match part {
        Part::Computer => 0,
        Part::User => 1,
    }
}

/// Changeset of a write of the content of one or both parts of a GPO (pure), ADR 0013
/// (`ecrire_contenus`):
///
/// 1. the files, computer part then user part (created with their folders, replaced or
///    deleted; a file or a folder created gets the ACL of `sysvolreset`, as the rest of the
///    folder);
/// 2. `GPT.INI`, once, each touched part raised to its next version;
/// 3. the object, once: `versionNumber` (same value) and the list of extensions of each touched
///    part, under the guard of `uSNChanged`.
///
/// A part is touched if one of its files or its list of extensions changes. Guards: content read
/// of each file and of `GPT.INI`. Nothing to write: empty changeset. The reads come from one
/// reading (`read_contents`), keyed by `order(part)`.
pub fn write_contents(
    parts: &BTreeMap<u8, (ContentRead, ContentChange)>,
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let Some((first, _)) = parts.values().next() else {
        return Ok(Changeset::default());
    };
    let gpo = &first.gpo;
    let folder_present = first
        .states
        .get(&sysvol::key(&gpo.folder))
        .is_some_and(|s| s.nature == Some(true));
    if !folder_present {
        return Err(GpoError::FolderAbsent {
            name: gpo.name(),
            dn: gpo.dn.clone(),
        });
    }
    let sd = gw::file_bytes(gpo.descriptor()?)?;
    let mut operations = Vec::new();
    let mut created = HashSet::new();
    let mut extension_changes = Vec::new();
    let mut touched = Vec::new();
    for (read, change) in parts.values() {
        let files = file_operations(read, change, &sd, &mut created)?;
        let ext = extensions_change(read, change)?;
        let any = !files.is_empty() || ext.is_some();
        operations.extend(files);
        extension_changes.extend(ext);
        if any {
            touched.push(read.part);
        }
    }
    let editor_remarks: Vec<String> = parts
        .values()
        .flat_map(|(_, c)| c.remarks.iter().cloned())
        .collect();
    if touched.is_empty() {
        return Ok(Changeset {
            operations: Vec::new(),
            remarks: editor_remarks,
        });
    }

    let gpt_version = first
        .gpt_ini
        .as_deref()
        .and_then(|g| gpo::read_gpt_ini(g).version);
    let start = first.version();
    let mut version = start;
    for &part in &touched {
        version = modified_version(version, gpt_version, part);
    }
    let gpt_path = sysvol::join(&[&gpo.folder, GPT_INI]);
    operations.push(match &first.gpt_ini {
        None => Operation::WriteFile {
            dn: gpo.dn.clone(),
            path: gpt_path,
            content: format!("[General]\r\nVersion={version}\r\n").into_bytes(),
            old: None,
            descriptor: Some(sd.clone()),
        },
        Some(old) => Operation::WriteFile {
            dn: gpo.dn.clone(),
            path: gpt_path,
            content: gpo::gpt_ini_with_version(old, version),
            old: Some(old.clone()),
            descriptor: None,
        },
    });
    let mut changes = vec![Change::new(
        "versionNumber",
        gpo.values("versionNumber").to_vec(),
        vec![version.to_string().into_bytes()],
    )?];
    changes.extend(extension_changes);
    operations.push(Operation::modify(&gpo.dn, changes, Some(gpo.read.clone()))?);

    let mut remarks = Vec::new();
    let flags: i64 = gpo.text("flags").trim().parse().unwrap_or(0);
    for &part in &touched {
        remarks.push(catalog.text(&Msg::GpoContentVersion {
            part,
            name: gpo.name(),
            before: gpo::versions(start).of(part),
            after: gpo::versions(version).of(part),
        }));
        let disabled = match part {
            Part::Computer => gpo::COMPUTER_DISABLED,
            Part::User => gpo::USER_DISABLED,
        };
        if flags & disabled != 0 {
            remarks.push(catalog.text(&Msg::GpoPartDisabled { part }));
        }
    }
    if let Some(s) = gpt_version.filter(|&s| s != start) {
        remarks.push(catalog.text(&Msg::GpoVersionsDiffered {
            directory: start,
            sysvol: s,
        }));
    }
    remarks.extend(editor_remarks);
    Ok(Changeset {
        operations,
        remarks,
    })
}

/// Reads the GPO and, in one batch of compounds on the SYSVOL of the same DC, `GPT.INI` and, for
/// each part, the files `paths` (relative to the folder of the part) and the folders leading to
/// them (`lire_contenus`).
pub(crate) fn read_contents(
    link: &mut Link,
    session: &mut SysvolSession,
    dn: &str,
    paths: &[(Part, Vec<String>)],
) -> Result<Vec<ContentRead>, Step> {
    let gpo = gw::read_gpo(link, dn)?;
    let mut hints: Vec<(String, Option<bool>)> = Vec::new();
    let mut add = |path: String, nature: Option<bool>, replace: bool| {
        let key = sysvol::key(&path);
        match hints.iter_mut().find(|(p, _)| sysvol::key(p) == key) {
            Some(h) if replace => h.1 = nature,
            Some(_) => {}
            None => hints.push((path, nature)),
        }
    };
    add(gpo.folder.clone(), None, false);
    add(sysvol::join(&[&gpo.folder, GPT_INI]), Some(false), true);
    for (part, relatives) in paths {
        let root = sysvol::join(&[&gpo.folder, part_folder(*part)]);
        add(root.clone(), None, false);
        let root_key = sysvol::key(&root);
        for relative in relatives {
            let path = sysvol::join(&[&root, &relative.replace('/', "\\")]);
            let mut parent = sysvol::parent(&path).to_owned();
            while sysvol::key(&parent) != root_key
                && sysvol::key(&parent).starts_with(&format!("{root_key}\\"))
            {
                add(parent.clone(), None, false);
                parent = sysvol::parent(&parent).to_owned();
            }
            add(path, Some(false), true);
        }
    }
    let states = session.client()?.states(&hints)?;
    let by_key: HashMap<String, State> = states
        .into_iter()
        .map(|s| (sysvol::key(&s.path), s))
        .collect();
    let gpt = by_key
        .get(&sysvol::key(&sysvol::join(&[&gpo.folder, GPT_INI])))
        .filter(|s| s.nature == Some(false))
        .map(|s| s.content.clone().unwrap_or_default());
    let states = Arc::new(by_key);
    Ok(paths
        .iter()
        .map(|(part, _)| ContentRead {
            gpo: gpo.clone(),
            part: *part,
            gpt_ini: gpt.clone(),
            states: states.clone(),
        })
        .collect())
}

/// What an editor of content gives for a part: the files to read (relative to the folder of the
/// part) and the change made from what was read (`Travail`).
pub type Work = Arc<dyn Fn(&ContentRead) -> Result<ContentChange, GpoError> + Send + Sync>;

/// The common API of the content editors (J7): reads on the PDC emulator the GPO, `GPT.INI` and
/// the files of each part (one SMB batch), calls the change of each part (on the thread of the
/// connection, without network) with what was read, then returns `write_contents`: one
/// changeset for the files of both parts, `GPT.INI`, the version and the extensions
/// (`preparer_contenus`). With `domain`, on Samba, the account policy of a `GptTmpl.inf` written
/// for a GPO linked to the root goes to the domain object in the same changeset (ADR 0014,
/// `security_policy::complete_domain`). Blocking.
pub fn prepare_contents(
    connection: &Connection,
    dn: &str,
    works: Vec<(Part, Vec<String>, Work)>,
    domain: bool,
    catalog: Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let dn = dn.to_owned();
    gw::on_dc(connection, move |link, session| {
        let paths: Vec<(Part, Vec<String>)> =
            works.iter().map(|(p, f, _)| (*p, f.clone())).collect();
        let reads = read_contents(link, session, &dn, &paths)?;
        let mut parts = BTreeMap::new();
        for ((part, _, work), read) in works.iter().zip(reads) {
            let change = work(&read)?;
            parts.insert(order(*part), (read, change));
        }
        let changeset = write_contents(&parts, catalog.as_ref())?;
        if domain {
            crate::security_policy::complete_domain(link, session, &dn, changeset, catalog.as_ref())
        } else {
            Ok(changeset)
        }
    })
}

/// Read only, the files of both parts (to show the content of a GPO) (`lire_fichiers_gpo`).
/// Blocking.
pub fn read_files(
    connection: &Connection,
    dn: &str,
    paths: Vec<(Part, Vec<String>)>,
) -> Result<Vec<ContentRead>, GpoError> {
    let dn = dn.to_owned();
    gw::on_dc(connection, move |link, session| {
        read_contents(link, session, &dn, &paths)
    })
}

/// The entries of the `Registry.pol` of the part (none if it does not exist) (`registre`).
pub fn registry(read: &ContentRead) -> Result<Vec<Entry>, GpoError> {
    match read.content(REGISTRY_POL)? {
        Some(bytes) if !bytes.is_empty() => {
            rp::read(bytes).map_err(|e| GpoError::Invalid(e.to_string()))
        }
        _ => Ok(Vec::new()),
    }
}

/// `ContentChange` of the `Registry.pol`: the entries after `change`, encoded; the « Registry »
/// extension of the part declared (as the GPMC, it stays declared when the file has no entry
/// left) (`modifier_registre`).
pub fn modify_registry(
    read: &ContentRead,
    change: &dyn Fn(Vec<Entry>) -> Vec<Entry>,
) -> Result<ContentChange, GpoError> {
    let before = registry(read)?;
    let after = change(before.clone());
    if after == before {
        return Ok(ContentChange::default());
    }
    Ok(ContentChange {
        files: vec![(
            REGISTRY_POL.to_owned(),
            Some(rp::encode(&after).map_err(|e| GpoError::Invalid(e.to_string()))?),
        )],
        add_extensions: vec![registry_extension(read.part)],
        ..ContentChange::default()
    })
}

#[cfg(test)]
mod tests;

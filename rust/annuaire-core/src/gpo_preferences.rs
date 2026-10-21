// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Group Policy Preferences of a GPO (J7.6, `annuaire.core.preferences`): reading, draft,
//! writing.
//!
//! The files (`gpp`) are read and written through the content API of the GPOs (`gpo_content`):
//! on the PDC emulator, with the version of the part raised in the directory and `GPT.INI`, and
//! the list of extensions of the part kept up to date, in one changeset (preview, journal,
//! undo).
//!
//! **Draft.** What the administrator does on a family (add, change, remove, move an element) is
//! kept as operations naming the elements by their `uid`, and **replayed on the content read
//! again when writing** (`replay`): an element added meanwhile by the GPMC is kept; an element
//! the draft changes and that disappeared makes the write refused (`PreferenceGone`); an element
//! already removed is removed silently.
//!
//! Extensions: a family with at least one element declares its pair (client-side extension,
//! tool), as the GroupPolicy module of the GPMC (seen on 2026-10-14: no pair with the null
//! extension); when the last element goes, the file is deleted and the pair removed, with that
//! of the null extension the GPMC console adds.

use std::collections::HashMap;

use annuaire_codecs::Sid;
use annuaire_codecs::extensions::{self, Extension, Pair};

use crate::connection::{Connection, Failure};
use crate::gpo::Part;
use crate::gpo_content::{ContentChange, ContentRead};
use crate::gpo_write::GpoError;
use crate::gpp::{self, Document, Element, Family, PreferencesError, Target};
use crate::search::{self, Burst, BurstAnswer, Value};
use crate::session::Scope;

/// Families existing in the part (drives and shared printers: user only) (`familles`).
pub fn families(part: Part) -> Vec<Family> {
    let folder = crate::gpo_content::part_folder(part);
    Family::ALL
        .into_iter()
        .filter(|f| f.description().parts.contains(&folder))
        .collect()
}

/// A preferences file read: its content (`None`: absent), the document if it reads, else the
/// error (the file is then shown, not editable) (`Fichier`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct File {
    pub family: Family,
    pub content: Option<Vec<u8>>,
    pub document: Option<Document>,
    pub error: Option<PreferencesError>,
}

impl File {
    pub fn elements(&self) -> Vec<&Element> {
        self.document
            .as_ref()
            .map(Document::elements)
            .unwrap_or_default()
    }
}

/// The file of a family from its content (`None`: absent) (`fichier`).
pub fn file(family: Family, content: Option<&[u8]>) -> File {
    let Some(content) = content else {
        return File {
            family,
            content: None,
            document: None,
            error: None,
        };
    };
    match gpp::read(content, family) {
        Ok(d) => File {
            family,
            content: Some(content.to_vec()),
            document: Some(d),
            error: None,
        },
        Err(e) => File {
            family,
            content: Some(content.to_vec()),
            document: None,
            error: Some(e),
        },
    }
}

/// The preferences of a part of a GPO, read on the write DC (`Preferences`).
#[derive(Debug, Clone)]
pub struct Preferences {
    pub dn: String,
    pub name: String,
    pub part: Part,
    pub files: Vec<File>,
    pub extensions: Vec<Extension>,
}

impl Preferences {
    /// True if the list of extensions of the part declares that of the family.
    pub fn declared(&self, family: Family) -> bool {
        let d = family.description();
        extensions::pairs(&self.extensions).contains(&(d.cse.to_uppercase(), d.tool.to_uppercase()))
    }

    pub fn file(&self, family: Family) -> Option<&File> {
        self.files.iter().find(|f| f.family == family)
    }
}

/// `Preferences` from a reading of the content API (`depuis`).
pub fn from_read(read: &ContentRead) -> Result<Preferences, GpoError> {
    let mut files = Vec::new();
    for f in Family::ALL {
        files.push(file(f, read.content(&f.path())?));
    }
    Ok(Preferences {
        dn: read.gpo.dn.clone(),
        name: read.gpo.name(),
        part: read.part,
        files,
        extensions: read.extensions(),
    })
}

/// The paths of the four files, relative to the folder of a part.
pub fn paths() -> Vec<String> {
    Family::ALL.iter().map(|f| f.path()).collect()
}

// --- Draft --------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add(Element),
    Replace { uid: String, element: Element },
    Remove { uid: String },
    Shift { uid: String, offset: isize },
}

fn rank(document: &Document, uid: &str) -> Option<usize> {
    document.elements().iter().position(|e| e.uid() == uid)
}

/// The document after the operations of the draft, in order; refused if an element to change or
/// to move is no longer there (`appliquer`).
pub fn apply(mut document: Document, operations: &[Operation]) -> Result<Document, GpoError> {
    for op in operations {
        let uid = match op {
            Operation::Add(e) => {
                document = gpp::add(&document, e.clone());
                continue;
            }
            Operation::Replace { uid, .. }
            | Operation::Remove { uid }
            | Operation::Shift { uid, .. } => uid,
        };
        let Some(r) = rank(&document, uid) else {
            if matches!(op, Operation::Remove { .. }) {
                continue;
            }
            return Err(GpoError::PreferenceGone { uid: uid.clone() });
        };
        let gone = || GpoError::PreferenceGone { uid: uid.clone() };
        document = match op {
            Operation::Replace { element, .. } => {
                gpp::replace(&document, r, element.clone()).ok_or_else(gone)?
            }
            Operation::Remove { .. } => gpp::remove(&document, r).ok_or_else(gone)?,
            Operation::Shift { offset, .. } => {
                let n = document.elements().len();
                let wanted = isize::try_from(r).unwrap_or(0).saturating_add(*offset);
                let target = usize::try_from(wanted.max(0))
                    .unwrap_or(0)
                    .min(n.saturating_sub(1));
                let mut d = document;
                let mut i = r;
                while i != target {
                    let step: isize = if target > i { 1 } else { -1 };
                    d = gpp::shift(&d, i, step).ok_or_else(gone)?;
                    i = i.checked_add_signed(step).ok_or_else(gone)?;
                }
                d
            }
            Operation::Add(_) => document,
        };
    }
    Ok(document)
}

/// (document read, document after the draft); an unreadable file makes it refused.
fn documents(
    family: Family,
    current: Option<&[u8]>,
    operations: &[Operation],
) -> Result<(Option<Document>, Document), GpoError> {
    let before = match current {
        None => None,
        Some(bytes) => Some(
            gpp::read(bytes, family).map_err(|error| GpoError::Preferences {
                path: family.path(),
                error,
            })?,
        ),
    };
    let start = before.clone().unwrap_or_else(|| gpp::new_document(family));
    Ok((before, apply(start, operations)?))
}

/// New content of the file: the operations replayed on the content `current` (read again when
/// writing); `None` (file deleted) if no element is left (`rejouer`).
pub fn replay(
    family: Family,
    current: Option<&[u8]>,
    operations: &[Operation],
) -> Result<Option<Vec<u8>>, GpoError> {
    let (_, after) = documents(family, current, operations)?;
    Ok((!after.elements().is_empty()).then(|| gpp::write(&after)))
}

/// (pairs to declare, pairs to remove) whether the family keeps elements (`extensions`).
pub fn extension_pairs(family: Family, empty: bool) -> (Vec<Pair>, Vec<Pair>) {
    let d = family.description();
    let pair = (d.cse.to_owned(), d.tool.to_owned());
    if empty {
        (
            Vec::new(),
            vec![pair, (gpp::NULL_CSE.to_owned(), d.tool.to_owned())],
        )
    } else {
        (vec![pair], Vec::new())
    }
}

/// What the preview says of the change, element by element (by `uid`); the interface words
/// it (`remarques`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remark {
    Added(Vec<String>),
    Changed(Vec<String>),
    Removed(Vec<String>),
    Reordered,
    /// A stored password (MS14-025) removed from these elements.
    PasswordsRemoved(Vec<String>),
    /// No element left: the file is deleted.
    Emptied,
}

pub fn remarks(before: Option<&Document>, after: &Document) -> Vec<Remark> {
    let old: Vec<&Element> = before.map(Document::elements).unwrap_or_default();
    let new: Vec<&Element> = after.elements();
    // Python dictionaries by uid: the last element of a uid wins, at the place of the first.
    let by_uid = |list: &[&Element]| {
        let mut order: Vec<String> = Vec::new();
        let mut map: HashMap<String, Element> = HashMap::new();
        for e in list {
            if !map.contains_key(e.uid()) {
                order.push(e.uid().to_owned());
            }
            map.insert(e.uid().to_owned(), (*e).clone());
        }
        (order, map)
    };
    let (old_order, old_map) = by_uid(&old);
    let (new_order, new_map) = by_uid(&new);
    let name = |map: &HashMap<String, Element>, u: &String| {
        map.get(u).map(|e| e.name().to_owned()).unwrap_or_default()
    };
    let mut out = Vec::new();
    let added: Vec<String> = new_order
        .iter()
        .filter(|u| !old_map.contains_key(*u))
        .map(|u| name(&new_map, u))
        .collect();
    let removed: Vec<String> = old_order
        .iter()
        .filter(|u| !new_map.contains_key(*u))
        .map(|u| name(&old_map, u))
        .collect();
    let changed: Vec<String> = new_order
        .iter()
        .filter(|u| old_map.contains_key(*u) && new_map.get(*u).is_some_and(|e| e.raw.is_none()))
        .map(|u| name(&new_map, u))
        .collect();
    if !added.is_empty() {
        out.push(Remark::Added(added));
    }
    if !changed.is_empty() {
        out.push(Remark::Changed(changed));
    }
    if !removed.is_empty() {
        out.push(Remark::Removed(removed));
    }
    let common_new: Vec<&String> = new_order
        .iter()
        .filter(|u| old_map.contains_key(*u))
        .collect();
    let common_old: Vec<&String> = old_order
        .iter()
        .filter(|u| new_map.contains_key(*u))
        .collect();
    if common_old != common_new {
        out.push(Remark::Reordered);
    }
    let lost: Vec<String> = old_order
        .iter()
        .filter(|u| {
            old_map.get(*u).is_some_and(Element::has_password)
                && !new_map.get(*u).is_some_and(Element::has_password)
        })
        .map(|u| name(&old_map, u))
        .collect();
    if !lost.is_empty() {
        out.push(Remark::PasswordsRemoved(lost));
    }
    if after.elements().is_empty() && !old_order.is_empty() {
        out.push(Remark::Emptied);
    }
    out
}

/// What the content API must write: the draft replayed on the content read; `say` words the
/// remarks (`modification`).
pub fn change(
    read: &ContentRead,
    family: Family,
    operations: &[Operation],
    say: &dyn Fn(&[Remark]) -> Vec<String>,
) -> Result<ContentChange, GpoError> {
    let path = family.path();
    let (before, after) = documents(family, read.content(&path)?, operations)?;
    let new = (!after.elements().is_empty()).then(|| gpp::write(&after));
    let (add, remove) = extension_pairs(family, new.is_none());
    Ok(ContentChange {
        files: vec![(path, new)],
        add_extensions: add,
        remove_extensions: remove,
        remarks: say(&remarks(before.as_ref(), &after)),
    })
}

// --- Directory ----------------------------------------------------------------------------

/// NetBIOS name of the domain (`nETBIOSName` of its cross-reference in `CN=Partitions`), to
/// name a group or an account of the targeting as the console does: `LAB\GG-Essai`. The DNS
/// name of the domain in upper case, up to the first dot, if not found (`nom_netbios`).
/// Blocking.
pub fn netbios_name(connection: &Connection) -> Result<String, Failure> {
    let fallback = connection
        .profile()
        .domain
        .split('.')
        .next()
        .unwrap_or_default()
        .to_uppercase();
    connection.run(true, move |link| {
        let dse = link.state.root_dse.clone();
        let filter = search::and(&[
            search::eq("objectClass", Value::Text("crossRef")).unwrap_or_default(),
            search::eq("nCName", Value::Text(&dse.default_naming_context)).unwrap_or_default(),
        ])
        .unwrap_or_default();
        let mut burst = Burst::new();
        burst.search(
            link.session.as_mut(),
            &format!("CN=Partitions,{}", dse.configuration_naming_context),
            Scope::OneLevel,
            &filter,
            &["nETBIOSName".to_owned()],
            0,
            None,
        )?;
        let answers = burst.receive(link.session.as_mut(), Some(link.timeout))?;
        if let Some(BurstAnswer::Entries(entries)) = answers.first() {
            for e in entries {
                if let Some(v) = e.values("nETBIOSName").first() {
                    return Ok(String::from_utf8_lossy(v).into_owned());
                }
            }
        }
        Ok(fallback.clone())
    })
}

/// An object of the directory proposed to the targeting: group, user or OU (`Principal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub dn: String,
    pub name: String,
    pub account: String,
    pub sid: Option<String>,
}

pub const SEARCH_LIMIT: i32 = 200;

fn kind_filter(target: Target) -> String {
    match target {
        Target::Group => search::eq("objectClass", Value::Text("group")),
        Target::User => search::and(&[
            search::eq("objectCategory", Value::Text("person")).unwrap_or_default(),
            search::eq("objectClass", Value::Text("user")).unwrap_or_default(),
        ]),
        Target::Ou | Target::Computer => {
            search::eq("objectClass", Value::Text("organizationalUnit"))
        }
    }
    .unwrap_or_default()
}

/// Groups, users or OUs whose name or identifier starts with `text`, sorted by name (one
/// request). Empty if `text` is; `None` if there are more than `SEARCH_LIMIT` (be more
/// precise) (`chercher_principaux`). Blocking.
pub fn search_principals(
    connection: &Connection,
    target: Target,
    text: &str,
) -> Result<Option<Vec<Principal>>, Failure> {
    let text = text.trim().to_owned();
    if text.is_empty() {
        return Ok(Some(Vec::new()));
    }
    connection.run(true, move |link| {
        let names: Vec<String> = ["name", "sAMAccountName", "displayName"]
            .iter()
            .filter_map(|a| search::starts_with(a, &text).ok())
            .collect();
        let filter = search::and(&[kind_filter(target), search::or(&names).unwrap_or_default()])
            .unwrap_or_default();
        let mut burst = Burst::new();
        burst.search(
            link.session.as_mut(),
            &link.state.root_dse.default_naming_context.clone(),
            Scope::Subtree,
            &filter,
            &[
                "name".to_owned(),
                "sAMAccountName".to_owned(),
                "objectSid".to_owned(),
            ],
            SEARCH_LIMIT,
            None,
        )?;
        let answers = burst.receive(link.session.as_mut(), Some(link.timeout))?;
        let entries = match answers.into_iter().next() {
            Some(BurstAnswer::TooMany) => return Ok(None),
            Some(BurstAnswer::Entries(e)) => e,
            None => Vec::new(),
        };
        let mut found: Vec<Principal> = entries
            .iter()
            .map(|x| {
                let text = |a: &str| {
                    x.values(a)
                        .first()
                        .map(|v| String::from_utf8_lossy(v).into_owned())
                };
                Principal {
                    dn: x.dn.clone(),
                    name: text("name").unwrap_or_else(|| x.dn.clone()),
                    account: text("sAMAccountName").unwrap_or_default(),
                    sid: x
                        .values("objectSid")
                        .first()
                        .and_then(|v| Sid::decode(v).ok())
                        .map(|s| s.to_string()),
                }
            })
            .collect();
        found.sort_by_cached_key(|p| p.name.to_lowercase());
        Ok(Some(found))
    })
}

#[cfg(test)]
mod tests;

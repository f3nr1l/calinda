// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Deleted objects and their restoration (J9.1, ADR 0024).
//!
//! A deleted object leaves its place for `CN=Deleted Objects` of its partition, renamed
//! `name\nDEL:guid`, with `isDeleted` and `lastKnownParent`. Without the Recycle Bin it is a
//! tombstone: the DC keeps only the attributes of `searchFlags` bit 3 and a few of its own
//! (`objectSid`, `sAMAccountName`…). With the Recycle Bin (an optional feature of the forest,
//! `msDS-EnabledFeature` of `CN=Partitions`) it keeps everything, links and password
//! included, until `msDS-DeletedObjectLifetime`; it is then recycled (`isRecycled`), stripped
//! as a tombstone, and can no longer be brought back.
//!
//! The list is read with « show deleted » and « show recycled », and the extended DN for the
//! GUID of the last known parent. A restoration is one modification of the deleted object
//! (`isDeleted` removed, `distinguishedName` replaced: `Operation::Restore`), a deleted parent
//! restored first. What a DC does differs (constats of the ADR 0024):
//!
//! - Windows refuses to bring back a recycled object (`unwillingToPerform`), and recycles the
//!   tombstones already there when the Recycle Bin is enabled;
//! - Samba 4.22 marks every tombstone `isRecycled` without the Recycle Bin and brings it back
//!   all the same; with the Recycle Bin enabled it can bring back nothing (its
//!   `tombstone_reanimate` removes `isRecycled` unconditionally, refused on a deleted object
//!   that has none, and fails on the old tombstones).
//!
//! The undo of a deletion of the journal (`undo`) restores the objects still there instead of
//! recreating them (same `objectGUID` and `objectSid`); without the Recycle Bin it writes back
//! from the journal what the tombstone lost.

use std::collections::{HashMap, HashSet};

use annuaire_codecs::Guid;
use annuaire_codecs::time::{self, UtcTime};

use crate::changes::{
    self, Applied, AttributeMap, Change, ChangeError, Changeset, Operation, Read, Report,
    SENSITIVE, SYSTEM, dn_key,
};
use crate::connection::{Connection, Failure, Link};
use crate::dn::{self, Component};
use crate::error::{LdapError, code};
use crate::messages::{Catalog, Msg};
use crate::search::{self, Value as FilterValue};
use crate::session::{Control, Entry, Scope, SearchRequest};

pub const OID_SHOW_DELETED: &str = "1.2.840.113556.1.4.417";
pub const OID_SHOW_RECYCLED: &str = "1.2.840.113556.1.4.2064";
const OID_EXTENDED_DN: &str = "1.2.840.113556.1.4.529";
/// Well-known GUID of `CN=Deleted Objects` (`GUID_DELETED_OBJECTS_CONTAINER_W`).
pub const DELETED_OBJECTS_WKGUID: &str = "18e2ea80684f11d2b9aa00c04f79f805";
/// `CN=Recycle Bin Feature` of `CN=Optional Features`.
pub const RECYCLE_BIN_FEATURE: &str = "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a";

/// Attributes read on a deleted object, besides `*`.
const READ: [&str; 8] = [
    "*",
    "isDeleted",
    "isRecycled",
    "lastKnownParent",
    "msDS-LastKnownRDN",
    "whenChanged",
    "uSNChanged",
    "objectGUID",
];

/// Set again by the DC when it brings back a tombstone, as at a creation: not written back
/// from the journal (an « add » would find them there).
const DEFAULTED: [&str; 5] = [
    "accountexpires",
    "codepage",
    "countrycode",
    "admincount",
    "operatorcount",
];

/// « Show deleted » and « show recycled »: the controls of every read and write of a
/// deleted object.
pub fn deleted_controls() -> Vec<Control> {
    [OID_SHOW_DELETED, OID_SHOW_RECYCLED]
        .into_iter()
        .map(|oid| Control {
            oid: oid.into(),
            critical: true,
            value: None,
        })
        .collect()
}

/// Extended DN, text form: `<GUID=…>;<SID=…>;CN=…` (as `sync::extended_dn_control`).
fn extended_dn_control() -> Control {
    Control {
        oid: OID_EXTENDED_DN.into(),
        critical: false,
        value: Some(vec![0x30, 0x03, 0x02, 0x01, 0x01]),
    }
}

/// The GUID and the DN of an extended DN (as `store::split_extended_dn`).
fn split_extended_dn(text: &str) -> (Option<Guid>, &str) {
    let mut guid = None;
    let mut rest = text;
    while let Some(inner) = rest.strip_prefix('<') {
        let Some(end) = inner.find('>') else { break };
        if let Some(("GUID" | "guid", value)) = inner.get(..end).and_then(|i| i.split_once('=')) {
            guid = value.parse::<Guid>().ok();
        }
        rest = inner.get(end + 1..).unwrap_or("");
        rest = rest.strip_prefix(';').unwrap_or(rest);
    }
    (guid, rest)
}

/// An object under `CN=Deleted Objects`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedObject {
    /// Its DN under `CN=Deleted Objects`, as the DC gives it.
    pub dn: String,
    pub guid: Guid,
    /// Its name before the deletion (`msDS-LastKnownRDN`, else `name` before `\nDEL:`).
    pub name: String,
    /// Type of its RDN (`CN`, `OU`).
    pub rdn: String,
    /// The most derived of its classes.
    pub class: String,
    /// `whenChanged`: the deletion, as long as nothing touched it since.
    pub deleted: Option<UtcTime>,
    /// `lastKnownParent`: its DN now (under `Deleted Objects` if deleted too), and its GUID.
    pub parent: Option<String>,
    pub parent_guid: Option<Guid>,
    pub recycled: bool,
    /// What the DC kept, its own attributes left out.
    pub attributes: AttributeMap,
    pub read: Read,
}

impl DeletedObject {
    /// Names of the attributes kept.
    pub fn kept(&self) -> Vec<String> {
        self.attributes.iter().map(|(a, _)| a.clone()).collect()
    }

    pub fn values(&self, attribute: &str) -> &[Vec<u8>] {
        self.attributes
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attribute))
            .map_or(&[], |(_, v)| v.as_slice())
    }

    pub fn text(&self, attribute: &str) -> Option<String> {
        self.values(attribute)
            .first()
            .map(|v| String::from_utf8_lossy(v).into_owned())
    }

    /// A user or a computer: password and memberships matter.
    pub fn is_account(&self) -> bool {
        matches!(self.class.as_str(), "user" | "computer" | "inetorgperson")
    }

    /// Kind of object, for the filters of the list.
    pub fn kind(&self) -> Kind {
        match self.class.as_str() {
            "user" | "inetorgperson" => Kind::User,
            "computer" => Kind::Computer,
            "group" => Kind::Group,
            "organizationalunit" => Kind::Unit,
            "contact" => Kind::Contact,
            _ => Kind::Other,
        }
    }
}

/// Kind of a deleted object, as the list filters them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    User,
    Computer,
    Group,
    Unit,
    Contact,
    Other,
}

/// Why a deleted object cannot be brought back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unrestorable {
    /// Recycled: past `msDS-DeletedObjectLifetime`, or a tombstone of before the Recycle Bin.
    Recycled,
    /// Samba with the Recycle Bin enabled.
    SambaRecycleBin,
}

/// `CN=Deleted Objects` of the domain and what the forest does of a deletion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bin {
    /// The Recycle Bin is enabled in the forest.
    pub enabled: bool,
    /// The DC is a Samba DC.
    pub samba: bool,
    /// DN of `CN=Deleted Objects`.
    pub container: String,
    /// `tombstoneLifetime` and `msDS-DeletedObjectLifetime`, in days, if set.
    pub tombstone_days: Option<i64>,
    pub deleted_days: Option<i64>,
    /// From the most recent deletion.
    pub objects: Vec<DeletedObject>,
}

impl Bin {
    pub fn get(&self, guid: &Guid) -> Option<&DeletedObject> {
        self.objects.iter().find(|o| o.guid == *guid)
    }

    /// Why `object` cannot be brought back; None if it can.
    pub fn unrestorable(&self, object: &DeletedObject) -> Option<Unrestorable> {
        if self.samba && self.enabled {
            Some(Unrestorable::SambaRecycleBin)
        } else if self.enabled && object.recycled {
            Some(Unrestorable::Recycled)
        } else {
            None
        }
    }

    /// The deleted objects whose last known parent is `guid`.
    pub fn children(&self, guid: &Guid) -> impl Iterator<Item = &DeletedObject> {
        self.objects
            .iter()
            .filter(move |o| o.parent_guid.as_ref() == Some(guid))
    }
}

fn integer(entry: &Entry, attribute: &str) -> Option<i64> {
    entry
        .values(attribute)
        .first()
        .and_then(|v| std::str::from_utf8(v).ok()?.trim().parse().ok())
}

fn boolean(entry: &Entry, attribute: &str) -> bool {
    entry
        .values(attribute)
        .first()
        .is_some_and(|v| v.eq_ignore_ascii_case(b"TRUE"))
}

/// Name before the deletion: what precedes `\nDEL:` (or `\0ADEL:` not unescaped).
fn name_before(name: &str) -> String {
    let cut = name.find('\n').or_else(|| name.find("\\0A"));
    cut.map_or(name, |i| name.get(..i).unwrap_or(name))
        .to_owned()
}

/// A deleted object from its entry, read with the extended DN; None if it is not one.
pub fn deleted_from_entry(entry: &Entry, dc: &str) -> Option<DeletedObject> {
    let (guid, dn_text) = split_extended_dn(&entry.dn);
    let guid = guid.or_else(|| {
        entry
            .values("objectGUID")
            .first()
            .and_then(|g| Guid::decode(g).ok())
    })?;
    if !boolean(entry, "isDeleted") {
        return None;
    }
    let text = |a: &str| {
        entry
            .values(a)
            .first()
            .map(|v| String::from_utf8_lossy(v).into_owned())
    };
    let name = text("msDS-LastKnownRDN")
        .or_else(|| text("name").map(|n| name_before(&n)))
        .unwrap_or_default();
    let rdn = dn::split(dn_text)
        .ok()
        .and_then(|c| c.into_iter().next())
        .map_or_else(|| "CN".to_owned(), |c| c.attribute.to_uppercase());
    let class = entry
        .values("objectClass")
        .last()
        .map(|v| String::from_utf8_lossy(v).to_lowercase())
        .unwrap_or_default();
    let (parent_guid, parent) = match text("lastKnownParent") {
        Some(p) => {
            let (g, plain) = split_extended_dn(&p);
            (g, Some(plain.to_owned()))
        }
        None => (None, None),
    };
    let deleted = text("whenChanged").and_then(|t| time::decode_generalized_time(&t).ok());
    let attributes: AttributeMap = entry
        .attributes
        .iter()
        .filter(|(a, _)| {
            let lower = a.to_lowercase();
            !SYSTEM.contains(&lower.as_str())
                && !SENSITIVE.contains(&lower.as_str())
                && !matches!(lower.as_str(), "cn" | "ou" | "msds-lastknownrdn")
        })
        .cloned()
        .collect();
    Some(DeletedObject {
        dn: dn_text.to_owned(),
        guid,
        name,
        rdn,
        class,
        deleted,
        parent,
        parent_guid,
        recycled: boolean(entry, "isRecycled"),
        attributes,
        read: Read {
            dc: dc.to_owned(),
            usn: integer(entry, "uSNChanged").unwrap_or(0),
        },
    })
}

/// Recycle Bin, Samba, container and lifetimes, read on the thread of the connection.
fn read_frame(link: &mut Link) -> Result<Bin, LdapError> {
    let root = link.state.root_dse.clone();
    let configuration = root.configuration_naming_context.clone();
    let read = |link: &mut Link, dn_text: &str, names: &[&str]| {
        let names: Vec<String> = names.iter().map(|&n| n.to_owned()).collect();
        search::read_entry(
            link.session.as_mut(),
            dn_text,
            &names,
            "(objectClass=*)",
            None,
            Some(link.timeout),
        )
    };
    let partitions = read(
        link,
        &format!("CN=Partitions,{configuration}"),
        &["msDS-EnabledFeature"],
    )?;
    let enabled = partitions.is_some_and(|p| {
        p.values("msDS-EnabledFeature").iter().any(|v| {
            String::from_utf8_lossy(v)
                .to_lowercase()
                .starts_with("cn=recycle bin feature,")
        })
    });
    let service = read(
        link,
        &format!("CN=Directory Service,CN=Windows NT,CN=Services,{configuration}"),
        &["tombstoneLifetime", "msDS-DeletedObjectLifetime"],
    )?;
    let base = root.default_naming_context.clone();
    let container = format!("CN=Deleted Objects,{base}");
    Ok(Bin {
        enabled,
        samba: root.samba(),
        container,
        tombstone_days: service
            .as_ref()
            .and_then(|s| integer(s, "tombstoneLifetime")),
        deleted_days: service
            .as_ref()
            .and_then(|s| integer(s, "msDS-DeletedObjectLifetime")),
        objects: Vec::new(),
    })
}

fn search_deleted(
    link: &mut Link,
    bin: &Bin,
    filter: &str,
) -> Result<Vec<DeletedObject>, LdapError> {
    let mut controls = deleted_controls();
    controls.push(extended_dn_control());
    let entries = match crate::gpo::search_all(
        link,
        &bin.container,
        Scope::OneLevel,
        filter,
        &READ,
        &controls,
    ) {
        Err(e) if e.code == code::NO_SUCH_OBJECT && !e.foreign => Vec::new(),
        other => other?,
    };
    let dc = link.state.dc.clone();
    let mut objects: Vec<DeletedObject> = entries
        .iter()
        .filter_map(|e| deleted_from_entry(e, &dc))
        .collect();
    objects.sort_by(|a, b| b.deleted.cmp(&a.deleted).then_with(|| a.name.cmp(&b.name)));
    Ok(objects)
}

/// `CN=Deleted Objects` of the domain, every object in it (`lire_corbeille`). Blocking.
pub fn read_bin(connection: &Connection) -> Result<Bin, Failure> {
    connection.run(true, |link| {
        let mut bin = read_frame(link)?;
        bin.objects = search_deleted(link, &bin, "(isDeleted=TRUE)")?;
        Ok(bin)
    })
}

/// The deleted objects among `guids` (the others are not or no longer there). Blocking.
pub fn find(connection: &Connection, guids: &[Guid]) -> Result<Bin, Failure> {
    let guids = guids.to_vec();
    connection.run(true, move |link| {
        let mut bin = read_frame(link)?;
        for chunk in guids.chunks(50) {
            let clauses: Vec<String> = chunk
                .iter()
                .filter_map(|g| search::eq("objectGUID", FilterValue::Bytes(&g.encode())).ok())
                .collect();
            let filter = format!(
                "(&(isDeleted=TRUE){})",
                search::or(&clauses).unwrap_or_default()
            );
            bin.objects.extend(search_deleted(link, &bin, &filter)?);
        }
        Ok(bin)
    })
}

// --- Filters of the list (pure) -------------------------------------------------------------

/// What the list shows.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Searched, without case, in the name, the class, the last known parent and the values
    /// kept.
    pub text: String,
    pub kind: Option<Kind>,
    /// Deleted at this time or after.
    pub since: Option<UtcTime>,
}

pub fn matches(object: &DeletedObject, filter: &Filter) -> bool {
    if filter.kind.is_some_and(|k| k != object.kind()) {
        return false;
    }
    if let Some(since) = filter.since {
        if object.deleted.is_none_or(|d| d < since) {
            return false;
        }
    }
    let wanted = filter.text.trim().to_lowercase();
    if wanted.is_empty() {
        return true;
    }
    let found = |s: &str| s.to_lowercase().contains(&wanted);
    found(&object.name)
        || found(&object.class)
        || object.parent.as_deref().is_some_and(found)
        || object.attributes.iter().any(|(a, values)| {
            found(a)
                || values
                    .iter()
                    .any(|v| std::str::from_utf8(v).is_ok_and(found))
        })
}

// --- Restoration ---------------------------------------------------------------------------

/// What the user asks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Restoration {
    pub selected: Vec<Guid>,
    /// Another container than the last known parent, for the objects selected.
    pub target: Option<String>,
    /// Another name, for a single object selected.
    pub name: Option<String>,
    /// With the deleted objects that were under them.
    pub children: bool,
}

/// What prevents a restoration, before the preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    Unrestorable {
        name: String,
        why: Unrestorable,
    },
    /// The last known parent is deleted and cannot be brought back.
    ParentUnrestorable {
        name: String,
        parent: String,
    },
    /// No last known parent: a container is to be chosen.
    NoParent {
        name: String,
    },
    /// The container does not exist.
    ParentMissing {
        name: String,
        parent: String,
    },
    /// The DN is taken; `free`, a name that is not.
    NameTaken {
        dn: String,
        free: String,
    },
    /// Another account has the same `sAMAccountName`.
    AccountNameTaken {
        name: String,
        account: String,
        holder: String,
    },
    /// A DN the changeset cannot hold.
    Invalid(String),
}

/// An object to bring back, in the order of the changeset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Planned {
    pub guid: Guid,
    pub dn: String,
    /// Added because an object chosen was under it.
    pub as_parent: bool,
    /// Added as an object that was under one chosen.
    pub as_child: bool,
}

fn new_dn(object: &DeletedObject, name: &str, parent: &str) -> String {
    let mut components = vec![Component::new(object.rdn.clone(), name)];
    components.extend(dn::split(parent).unwrap_or_default());
    dn::compose(&components).unwrap_or_default()
}

/// Order and DN of the objects to bring back (pure): parents first, a deleted parent added
/// when it can be brought back. Problems: objects or parents that cannot be.
pub fn plan(bin: &Bin, choice: &Restoration) -> Result<Vec<Planned>, Vec<Problem>> {
    let mut wanted: Vec<(Guid, bool)> = choice.selected.iter().map(|g| (*g, false)).collect();
    if choice.children {
        let mut i = 0;
        while let Some((guid, _)) = wanted.get(i).copied() {
            for child in bin.children(&guid) {
                if !wanted.iter().any(|(g, _)| *g == child.guid)
                    && bin.unrestorable(child).is_none()
                {
                    wanted.push((child.guid, true));
                }
            }
            i += 1;
        }
    }
    let mut planner = Planner {
        bin,
        choice,
        wanted: wanted.clone(),
        planned: Vec::new(),
        problems: Vec::new(),
    };
    for (guid, as_child) in wanted {
        planner.place(guid, false, as_child, 0);
    }
    if planner.problems.is_empty() {
        Ok(planner.planned)
    } else {
        Err(planner.problems)
    }
}

struct Planner<'a> {
    bin: &'a Bin,
    choice: &'a Restoration,
    /// The objects asked, and whether each came as a child of another.
    wanted: Vec<(Guid, bool)>,
    planned: Vec<Planned>,
    problems: Vec<Problem>,
}

impl Planner<'_> {
    /// Places `guid` after its parent (depth first); its new DN, None if it cannot come back.
    fn place(
        &mut self,
        guid: Guid,
        as_parent: bool,
        as_child: bool,
        depth: usize,
    ) -> Option<String> {
        if let Some(p) = self.planned.iter().find(|p| p.guid == guid) {
            return Some(p.dn.clone());
        }
        let bin = self.bin;
        let object = bin.get(&guid)?;
        if depth > 64 {
            return None;
        }
        if let Some(why) = bin.unrestorable(object) {
            self.problems.push(Problem::Unrestorable {
                name: object.name.clone(),
                why,
            });
            return None;
        }
        let selected = self.choice.selected.contains(&guid);
        let parent = match (&self.choice.target, selected) {
            (Some(target), true) => target.clone(),
            _ => match (object.parent_guid.and_then(|g| bin.get(&g)), &object.parent) {
                (Some(parent), _) => {
                    if bin.unrestorable(parent).is_some() {
                        self.problems.push(Problem::ParentUnrestorable {
                            name: object.name.clone(),
                            parent: parent.name.clone(),
                        });
                        return None;
                    }
                    let asked = self.wanted.iter().find(|(g, _)| *g == parent.guid).copied();
                    let (as_parent, as_child) = asked.map_or((true, false), |(_, c)| (false, c));
                    self.place(parent.guid, as_parent, as_child, depth + 1)?
                }
                (None, Some(parent)) => parent.clone(),
                (None, None) => {
                    self.problems.push(Problem::NoParent {
                        name: object.name.clone(),
                    });
                    return None;
                }
            },
        };
        let name = match (
            &self.choice.name,
            selected && self.choice.selected.len() == 1,
        ) {
            (Some(n), true) if !n.trim().is_empty() => n.trim().to_owned(),
            _ => object.name.clone(),
        };
        let dn_text = new_dn(object, &name, &parent);
        self.planned.push(Planned {
            guid,
            dn: dn_text.clone(),
            as_parent,
            as_child,
        });
        Some(dn_text)
    }
}

/// A name of the form `name (n)` that the DN function says free.
fn free_name(object: &DeletedObject, wanted: &str, mut taken: impl FnMut(&str) -> bool) -> String {
    let parent = dn::parent(wanted).unwrap_or_default();
    let name = dn::split(wanted)
        .ok()
        .and_then(|c| c.into_iter().next())
        .map_or_else(|| object.name.clone(), |c| c.value);
    for n in 2..100 {
        let candidate = new_dn(object, &format!("{name} ({n})"), &parent);
        if !taken(&candidate) {
            return candidate;
        }
    }
    new_dn(object, &format!("{name} ({})", object.guid), &parent)
}

fn exists(link: &mut Link, dn_text: &str) -> Result<bool, LdapError> {
    Ok(search::read_entry(
        link.session.as_mut(),
        dn_text,
        &["1.1".to_owned()],
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )?
    .is_some())
}

/// The account of the domain named `sam`, if any.
fn holder(link: &mut Link, sam: &str) -> Result<Option<String>, LdapError> {
    let base = link.state.root_dse.default_naming_context.clone();
    let filter = search::eq("sAMAccountName", FilterValue::Text(sam)).unwrap_or_default();
    let request = SearchRequest {
        base,
        scope: Scope::Subtree,
        filter,
        attributes: vec!["1.1".into()],
        controls: Vec::new(),
        size_limit: 1,
    };
    match link.session.search_wait(request, Some(link.timeout)) {
        Ok(r) => Ok(r.into_entries().into_iter().next().map(|e| e.dn)),
        Err(e) if e.code == code::SIZELIMIT_EXCEEDED => Ok(Some(String::new())),
        Err(e) => Err(e),
    }
}

/// What the directory says of a plan: names taken, containers missing, account names used
/// by another account. Inside a job.
fn check(link: &mut Link, bin: &Bin, planned: &[Planned]) -> Result<Vec<Problem>, LdapError> {
    let mut problems = Vec::new();
    let ours: HashSet<String> = planned.iter().map(|p| key(&p.dn)).collect();
    let mut seen: HashSet<String> = HashSet::new();
    for p in planned {
        let Some(object) = bin.get(&p.guid) else {
            continue;
        };
        let parent = dn::parent(&p.dn).unwrap_or_default();
        if !ours.contains(&key(&parent)) && !exists(link, &parent)? {
            problems.push(Problem::ParentMissing {
                name: object.name.clone(),
                parent,
            });
            continue;
        }
        if !seen.insert(key(&p.dn)) || exists(link, &p.dn)? {
            let mut taken = |candidate: &str| {
                ours.contains(&key(candidate)) || exists(link, candidate).unwrap_or(true)
            };
            let free = free_name(object, &p.dn, &mut taken);
            problems.push(Problem::NameTaken {
                dn: p.dn.clone(),
                free,
            });
        }
        if let Some(sam) = object.text("sAMAccountName") {
            if let Some(found) = holder(link, &sam)? {
                problems.push(Problem::AccountNameTaken {
                    name: object.name.clone(),
                    account: sam,
                    holder: found,
                });
            }
        }
    }
    Ok(problems)
}

fn key(dn_text: &str) -> String {
    dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

/// What a restoration keeps and loses, said by the preview.
fn remarks(bin: &Bin, object: &DeletedObject, dn_text: &str) -> Vec<Msg> {
    let mut msgs = Vec::new();
    if bin.enabled {
        msgs.push(Msg::RestoredWhole {
            dn: dn_text.to_owned(),
        });
        if object.is_account() {
            msgs.push(Msg::RestoredPasswordKept {
                dn: dn_text.to_owned(),
            });
        }
    } else {
        let kept: Vec<String> = object
            .kept()
            .into_iter()
            .filter(|a| !a.eq_ignore_ascii_case("objectClass"))
            .collect();
        msgs.push(if kept.is_empty() {
            Msg::RestoredBare {
                dn: dn_text.to_owned(),
            }
        } else {
            Msg::RestoredStripped {
                dn: dn_text.to_owned(),
                kept: kept.join(", "),
            }
        });
        if object.is_account() {
            msgs.push(Msg::RestoredAccountLosses {
                dn: dn_text.to_owned(),
            });
        }
    }
    msgs
}

fn texts(msgs: &[Msg], catalog: &dyn Catalog) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for m in msgs {
        let t = catalog.text(m);
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

/// The changeset of a plan (pure): one restoration per object, what each keeps or loses.
pub fn changeset(
    bin: &Bin,
    planned: &[Planned],
    catalog: &dyn Catalog,
) -> Result<Changeset, ChangeError> {
    let mut operations = Vec::new();
    let mut msgs = Vec::new();
    for p in planned {
        let Some(object) = bin.get(&p.guid) else {
            continue;
        };
        operations.push(Operation::restore(
            &object.dn,
            object.guid,
            &p.dn,
            Some(object.read.clone()),
        )?);
        if p.as_parent {
            msgs.push(Msg::RestoredParentFirst { dn: p.dn.clone() });
        }
        msgs.extend(remarks(bin, object, &p.dn));
    }
    for p in planned {
        let left = bin
            .children(&p.guid)
            .filter(|c| !planned.iter().any(|q| q.guid == c.guid))
            .count();
        if left > 0 {
            msgs.push(Msg::RestoredChildrenLeft {
                dn: p.dn.clone(),
                n: left,
            });
        }
    }
    Ok(Changeset {
        operations,
        remarks: texts(&msgs, catalog),
    })
}

/// The changeset that brings back what `choice` asks, or what prevents it (`restaurer`).
/// Blocking: the names and containers are checked on the DC.
pub fn prepare(
    connection: &Connection,
    bin: &Bin,
    choice: &Restoration,
    catalog: &dyn Catalog,
) -> Result<Result<Changeset, Vec<Problem>>, Failure> {
    let planned = match plan(bin, choice) {
        Ok(p) => p,
        Err(problems) => return Ok(Err(problems)),
    };
    let (bin_copy, planned_copy) = (bin.clone(), planned.clone());
    let problems = connection.run(true, move |link| check(link, &bin_copy, &planned_copy))?;
    if !problems.is_empty() {
        return Ok(Err(problems));
    }
    Ok(changeset(bin, &planned, catalog).map_err(|e| vec![Problem::Invalid(e.to_string())]))
}

// --- Undo of a deletion of the journal ------------------------------------------------------

fn guid_of(before: &AttributeMap) -> Option<Guid> {
    before
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case("objectGUID"))
        .and_then(|(_, v)| v.first())
        .and_then(|g| Guid::decode(g).ok())
}

/// The `objectGUID` of the objects `report` deleted and left deleted (an entry of the
/// journal): what `find` looks for before offering their restoration.
pub fn deleted_guids(report: &Report) -> Vec<Guid> {
    deletions(report)
        .into_iter()
        .filter_map(|(_, before)| guid_of(before))
        .collect()
}

/// The deletions `report` left applied: (DN, values before).
fn deletions(report: &Report) -> Vec<(&str, &AttributeMap)> {
    let remaining = report.remaining_indices();
    report
        .applied
        .iter()
        .enumerate()
        .filter(|(i, _)| remaining.contains(i))
        .filter_map(|(_, a)| match (&a.operation, &a.before) {
            (Operation::Delete { dn, .. }, Some(before)) => Some((dn.as_str(), before)),
            _ => None,
        })
        .collect()
}

/// A value of `before` that names an object of the domain (`base`).
fn reference(value: &[u8], base: &str) -> Option<String> {
    let text = std::str::from_utf8(value).ok()?;
    let k = key(text);
    (k.ends_with(&key(base)) && dn::split(text).is_ok_and(|c| c.len() > 1)).then(|| text.to_owned())
}

/// What a tombstone lost and the journal has: `(attributes to add, groups to rejoin)`.
fn lost(
    before: &AttributeMap,
    object: &DeletedObject,
    base: &str,
    present: &HashSet<String>,
) -> (Vec<Change>, Vec<String>) {
    let mut changes = Vec::new();
    let mut groups = Vec::new();
    for (attribute, values) in before {
        let lower = attribute.to_lowercase();
        if lower == "memberof" {
            groups.extend(
                values
                    .iter()
                    .filter_map(|v| reference(v, base))
                    .filter(|g| present.contains(&key(g))),
            );
            continue;
        }
        if SYSTEM.contains(&lower.as_str())
            || SENSITIVE.contains(&lower.as_str())
            || DEFAULTED.contains(&lower.as_str())
            || matches!(lower.as_str(), "cn" | "ou" | "objectclass")
            || !object.values(attribute).is_empty()
        {
            continue;
        }
        let kept: Vec<Vec<u8>> = values
            .iter()
            .filter(|v| reference(v, base).is_none_or(|r| present.contains(&key(&r))))
            .cloned()
            .collect();
        if let (false, Ok(change)) = (kept.is_empty(), Change::new(attribute, Vec::new(), kept)) {
            changes.push(change);
        }
    }
    (changes, groups)
}

/// The inverse of `report` (an entry of the journal) where the objects it deleted that are
/// still under `Deleted Objects` are brought back instead of recreated; None if none can be.
/// Blocking: reads the deleted objects, and the objects their values name.
pub fn undo(
    connection: &Connection,
    report: &Report,
    journal: &[Report],
    catalog: &dyn Catalog,
) -> Result<Option<Changeset>, Failure> {
    let deleted = deletions(report);
    let guids = deleted_guids(report);
    if guids.is_empty() {
        return Ok(None);
    }
    let bin = find(connection, &guids)?;
    let revivable: HashMap<Guid, DeletedObject> = bin
        .objects
        .iter()
        .filter(|o| bin.unrestorable(o).is_none())
        .map(|o| (o.guid, o.clone()))
        .collect();
    if revivable.is_empty() {
        return Ok(None);
    }
    // The objects the values of the journal name, and those this undo brings back.
    let base = connection.run(true, |link| {
        Ok(link.state.root_dse.default_naming_context.clone())
    })?;
    let mut named: Vec<String> = Vec::new();
    for (_, before) in &deleted {
        for (_, values) in before.iter() {
            named.extend(values.iter().filter_map(|v| reference(v, &base)));
        }
    }
    named.sort();
    named.dedup();
    let mut present: HashSet<String> = connection.run(true, move |link| {
        let mut found = HashSet::new();
        for n in &named {
            if exists(link, n)? {
                found.insert(key(n));
            }
        }
        Ok(found)
    })?;
    present.extend(deleted.iter().map(|(dn_text, _)| key(dn_text)));
    let enabled = bin.enabled;
    let revive = |applied: &Applied| -> Option<changes::Revived> {
        let Operation::Delete { dn: dn_text, .. } = &applied.operation else {
            return None;
        };
        let before = applied.before.as_ref()?;
        let object = revivable.get(&guid_of(before)?)?;
        let restore =
            Operation::restore(&object.dn, object.guid, dn_text, Some(object.read.clone())).ok()?;
        let mut revived = changes::Revived {
            now: vec![restore],
            later: Vec::new(),
            remarks: vec![Msg::RestoredFromJournal {
                dn: dn_text.clone(),
            }],
        };
        if enabled {
            revived.remarks.push(Msg::RestoredWhole {
                dn: dn_text.clone(),
            });
            if object.is_account() {
                revived.remarks.push(Msg::RestoredPasswordKept {
                    dn: dn_text.clone(),
                });
            }
            return Some(revived);
        }
        let (attributes, groups) = lost(before, object, &base, &present);
        if !attributes.is_empty() {
            revived.later.push(Operation::Modify {
                dn: dn_text.clone(),
                changes: attributes,
                read: None,
            });
        }
        for group in groups {
            revived.later.push(Operation::Modify {
                dn: group,
                changes: vec![Change {
                    attribute: "member".into(),
                    removed: Vec::new(),
                    added: vec![dn_text.as_bytes().to_vec()],
                }],
                read: None,
            });
        }
        revived.remarks.push(Msg::RestoredRefilled {
            dn: dn_text.clone(),
        });
        if object.is_account() {
            revived.remarks.push(Msg::RestoredPasswordLost {
                dn: dn_text.clone(),
            });
        }
        Some(revived)
    };
    // A journal Calinda cannot read again: the plain inverse says why.
    let Ok(changeset) = changes::inverse_reviving(report, journal, catalog, &revive) else {
        return Ok(None);
    };
    let any = changeset
        .operations
        .iter()
        .any(|o| matches!(o, Operation::Restore { .. }));
    Ok(any.then_some(changeset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(name: &str, guid: u8, parent: Option<(&str, Option<u8>)>) -> DeletedObject {
        let mut bytes = [0u8; 16];
        bytes[0] = guid;
        let g = Guid::from_bytes(bytes);
        DeletedObject {
            dn: format!("CN={name}\\0ADEL:{g},CN=Deleted Objects,DC=lab,DC=test"),
            guid: g,
            name: name.into(),
            rdn: if name.starts_with('o') {
                "OU".into()
            } else {
                "CN".into()
            },
            class: if name.starts_with('o') {
                "organizationalunit".into()
            } else {
                "user".into()
            },
            deleted: None,
            parent: parent.map(|(p, _)| p.to_owned()),
            parent_guid: parent.and_then(|(_, g)| g).map(|g| {
                let mut b = [0u8; 16];
                b[0] = g;
                Guid::from_bytes(b)
            }),
            recycled: false,
            attributes: vec![("sAMAccountName".into(), vec![name.as_bytes().to_vec()])],
            read: Read {
                dc: "dc1".into(),
                usn: 7,
            },
        }
    }

    fn guid(n: u8) -> Guid {
        let mut b = [0u8; 16];
        b[0] = n;
        Guid::from_bytes(b)
    }

    fn bin(objects: Vec<DeletedObject>) -> Bin {
        Bin {
            container: "CN=Deleted Objects,DC=lab,DC=test".into(),
            objects,
            ..Bin::default()
        }
    }

    #[test]
    fn names_before_deletion() {
        assert_eq!(name_before("x1\nDEL:259ab55b"), "x1");
        assert_eq!(name_before("x1\\0ADEL:259ab55b"), "x1");
        assert_eq!(name_before("x1"), "x1");
    }

    #[test]
    fn deleted_parent_restored_first() {
        let b = bin(vec![
            object(
                "y1",
                2,
                Some(("OU=ox\\0ADEL:x,CN=Deleted Objects,DC=lab,DC=test", Some(1))),
            ),
            object("ox", 1, Some(("OU=Essais,DC=lab,DC=test", None))),
        ]);
        let planned = plan(
            &b,
            &Restoration {
                selected: vec![guid(2)],
                ..Restoration::default()
            },
        )
        .unwrap();
        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].dn, "OU=ox,OU=Essais,DC=lab,DC=test");
        assert!(planned[0].as_parent);
        assert_eq!(planned[1].dn, "CN=y1,OU=ox,OU=Essais,DC=lab,DC=test");
    }

    #[test]
    fn children_follow_their_unit() {
        let b = bin(vec![
            object("ox", 1, Some(("OU=Essais,DC=lab,DC=test", None))),
            object(
                "y1",
                2,
                Some(("OU=ox\\0ADEL:x,CN=Deleted Objects,DC=lab,DC=test", Some(1))),
            ),
            object(
                "oy",
                3,
                Some(("OU=ox\\0ADEL:x,CN=Deleted Objects,DC=lab,DC=test", Some(1))),
            ),
            object(
                "z1",
                4,
                Some(("OU=oy\\0ADEL:x,CN=Deleted Objects,DC=lab,DC=test", Some(3))),
            ),
        ]);
        let choice = Restoration {
            selected: vec![guid(1)],
            children: true,
            ..Restoration::default()
        };
        let planned = plan(&b, &choice).unwrap();
        let dns: Vec<&str> = planned.iter().map(|p| p.dn.as_str()).collect();
        assert_eq!(
            dns,
            [
                "OU=ox,OU=Essais,DC=lab,DC=test",
                "CN=y1,OU=ox,OU=Essais,DC=lab,DC=test",
                "OU=oy,OU=ox,OU=Essais,DC=lab,DC=test",
                "CN=z1,OU=oy,OU=ox,OU=Essais,DC=lab,DC=test",
            ]
        );
        assert!(planned[1].as_child);
        // Without the children: said by the preview.
        let alone = plan(
            &b,
            &Restoration {
                children: false,
                ..choice
            },
        )
        .unwrap();
        let c = changeset(&b, &alone, &crate::messages::English).unwrap();
        assert_eq!(c.operations.len(), 1);
        assert!(c.remarks.iter().any(|r| r.contains("2 deleted objects")));
    }

    #[test]
    fn another_container_and_name() {
        let b = bin(vec![object("x1", 1, Some(("OU=A,DC=lab,DC=test", None)))]);
        let planned = plan(
            &b,
            &Restoration {
                selected: vec![guid(1)],
                target: Some("OU=B,DC=lab,DC=test".into()),
                name: Some("x1 (2)".into()),
                children: false,
            },
        )
        .unwrap();
        assert_eq!(planned[0].dn, "CN=x1 (2),OU=B,DC=lab,DC=test");
        let c = changeset(&b, &planned, &crate::messages::English).unwrap();
        let Some(Operation::Restore { deleted, dn, .. }) = c.operations.first() else {
            panic!("a restoration expected");
        };
        assert_eq!(dn, "CN=x1 (2),OU=B,DC=lab,DC=test");
        assert!(deleted.contains("CN=Deleted Objects"));
        assert!(c.remarks.iter().any(|r| r.contains("sAMAccountName")));
    }

    #[test]
    fn what_cannot_come_back() {
        let mut parent = object("ox", 1, Some(("OU=Essais,DC=lab,DC=test", None)));
        parent.recycled = true;
        let mut b = bin(vec![
            parent,
            object(
                "y1",
                2,
                Some(("OU=ox\\0ADEL:x,CN=Deleted Objects,DC=lab,DC=test", Some(1))),
            ),
            object("x9", 3, None),
        ]);
        // Without the Recycle Bin, a recycled tombstone comes back (Samba marks them all).
        assert!(
            plan(
                &b,
                &Restoration {
                    selected: vec![guid(2)],
                    ..Default::default()
                }
            )
            .is_ok()
        );
        b.enabled = true;
        let problems = plan(
            &b,
            &Restoration {
                selected: vec![guid(2), guid(3)],
                ..Restoration::default()
            },
        )
        .unwrap_err();
        assert!(problems.contains(&Problem::ParentUnrestorable {
            name: "y1".into(),
            parent: "ox".into()
        }));
        assert!(problems.contains(&Problem::NoParent { name: "x9".into() }));
        b.samba = true;
        assert!(matches!(
            plan(
                &b,
                &Restoration {
                    selected: vec![guid(3)],
                    ..Default::default()
                }
            )
            .unwrap_err()[0],
            Problem::Unrestorable {
                why: Unrestorable::SambaRecycleBin,
                ..
            }
        ));
    }

    #[test]
    fn free_names() {
        let o = object("x1", 1, None);
        let taken = ["cn=x1 (2),ou=a,dc=lab,dc=test"];
        let free = free_name(&o, "CN=x1,OU=A,DC=lab,DC=test", |c| {
            taken.contains(&c.to_lowercase().as_str())
        });
        assert_eq!(free, "CN=x1 (3),OU=A,DC=lab,DC=test");
    }

    #[test]
    fn filters() {
        let mut o = object("Xavier Un", 1, Some(("OU=Essais,DC=lab,DC=test", None)));
        o.deleted = time::decode_generalized_time("20261029003947.0Z").ok();
        let f = |text: &str| Filter {
            text: text.into(),
            ..Filter::default()
        };
        assert!(matches(&o, &f("xavier")));
        assert!(matches(&o, &f("essais")));
        assert!(matches(&o, &f("samaccountname")));
        assert!(!matches(&o, &f("paris")));
        assert!(!matches(
            &o,
            &Filter {
                kind: Some(Kind::Group),
                ..Filter::default()
            }
        ));
        assert!(!matches(
            &o,
            &Filter {
                since: time::decode_generalized_time("20261030000000.0Z").ok(),
                ..Filter::default()
            }
        ));
    }

    #[test]
    fn lost_attributes_from_the_journal() {
        let o = object("x1", 1, None);
        let before: AttributeMap = vec![
            ("objectGUID".into(), vec![guid(1).encode()]),
            ("sAMAccountName".into(), vec![b"x1".to_vec()]),
            ("description".into(), vec![b"desc".to_vec()]),
            ("accountExpires".into(), vec![b"0".to_vec()]),
            (
                "manager".into(),
                vec![b"CN=Gone,OU=A,DC=lab,DC=test".to_vec()],
            ),
            (
                "memberOf".into(),
                vec![
                    b"CN=G1,OU=A,DC=lab,DC=test".to_vec(),
                    b"CN=G2,OU=A,DC=lab,DC=test".to_vec(),
                ],
            ),
        ];
        let present: HashSet<String> = ["cn=g1,ou=a,dc=lab,dc=test".to_owned()].into();
        let (changes, groups) = lost(&before, &o, "DC=lab,DC=test", &present);
        let names: Vec<&str> = changes.iter().map(|c| c.attribute.as_str()).collect();
        assert_eq!(names, ["description"]);
        assert_eq!(groups, ["CN=G1,OU=A,DC=lab,DC=test"]);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Membership of groups (J1.7, `annuaire.core.appartenance`): direct, primary group,
//! recursive.
//!
//! - **Direct**: `memberOf` of the object (linked attribute, computed by the DC from the
//!   `member` of the groups), read by ranges if it is long.
//! - **Primary group**: `primaryGroupID` gives the RID of a group of the domain. This
//!   membership is **neither in `memberOf` nor in the `member` of the group**: the group is
//!   found by its SID, SID of the domain + RID.
//! - **Recursive**: the `memberOf` are followed **level by level** from the direct groups and
//!   the primary group: one search per level of nesting, a set of the groups already seen
//!   that stops the cycles (Samba evaluates IN_CHAIN object by object: 20 to 26 s on the
//!   domain of the lab, against a fraction of a second here).
//!
//! Blocking functions: off the interface thread.

use std::collections::{HashMap, HashSet};

use annuaire_codecs::Sid;

use crate::connection::{Connection, Failure};
use crate::error::{LdapError, code};
use crate::model;
use crate::search::{self, RangesError, Search, SearchError, Value};
use crate::session::Scope;
use crate::source::{PAGE_SIZE, search_blocking};

/// Groups read per search during the walk by levels.
pub const BATCH: usize = 100;

const GROUPS: &str = "(objectClass=group)";

/// Groups of an object, by DN (`Appartenance`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Membership {
    /// `memberOf`, in the order of the server.
    pub direct: Vec<String>,
    /// Group named by `primaryGroupID`; None for an object that is not an account.
    pub primary: Option<String>,
    /// Every group, direct, primary and by nesting, sorted; None if not asked.
    pub recursive: Option<Vec<String>>,
}

impl Membership {
    /// Direct plus the primary group: what the « Member of » tab of RSAT shows.
    pub fn all_direct(&self) -> Vec<String> {
        let mut all = self.direct.clone();
        if let Some(primary) = &self.primary
            && !all.contains(primary)
        {
            all.push(primary.clone());
        }
        all
    }
}

/// Why the groups of an object could not be read.
#[derive(Debug, Clone)]
pub enum MembershipError {
    Failure(Failure),
    Search(SearchError),
    /// The object does not exist (its DN).
    Missing(String),
}

impl From<Failure> for MembershipError {
    fn from(f: Failure) -> Self {
        Self::Failure(f)
    }
}

impl From<SearchError> for MembershipError {
    fn from(e: SearchError) -> Self {
        Self::Search(e)
    }
}

/// Groups each DN of a level is a direct member of.
pub type Parents = HashMap<String, Vec<String>>;

/// Groups reached from `start` following `parents`, level by level (`fermeture`, pure).
/// `parents(level)` gives, for each DN of the level, the groups it is a direct member of.
/// Each group is visited once (DN compared without case): a cycle stops by itself. The DN
/// come in the order of discovery.
pub fn closure<E>(
    start: impl IntoIterator<Item = String>,
    parents: &mut dyn FnMut(&[String]) -> Result<Parents, E>,
) -> Result<Vec<String>, E> {
    let mut seen: HashSet<String> = HashSet::new();
    let mut found: Vec<String> = Vec::new();
    let mut level: Vec<String> = Vec::new();
    for dn in start {
        if seen.insert(dn.to_lowercase()) {
            found.push(dn.clone());
            level.push(dn);
        }
    }
    while !level.is_empty() {
        let read = parents(&level)?;
        let mut next = Vec::new();
        for dn in &level {
            for parent in read.get(dn).into_iter().flatten() {
                if seen.insert(parent.to_lowercase()) {
                    found.push(parent.clone());
                    next.push(parent.clone());
                }
            }
        }
        level = next;
    }
    Ok(found)
}

fn text(values: &[Vec<u8>]) -> Vec<String> {
    values
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect()
}

fn ranges_failure(error: RangesError) -> LdapError {
    match error {
        RangesError::Ldap(error) => error,
        RangesError::Range(error) => LdapError::new(code::DECODING_ERROR, error.to_string()),
    }
}

/// Every value of `attribute` of `dn`, by ranges (`lire_plages`). Blocking.
pub fn read_ranges(
    connection: &Connection,
    dn: &str,
    attribute: &str,
) -> Result<Vec<Vec<u8>>, Failure> {
    let (dn, attribute) = (dn.to_owned(), attribute.to_owned());
    connection.run(true, move |link| {
        search::read_ranges(
            link.session.as_mut(),
            &dn,
            &attribute,
            search::RANGE_SIZE,
            Some(link.timeout),
        )
        .map_err(ranges_failure)
    })
}

/// Entries of a subtree search under `base`, every page (blocking).
pub fn search_all(
    connection: &Connection,
    base: &str,
    filter: String,
    attributes: Vec<String>,
) -> Result<Vec<crate::session::Entry>, SearchError> {
    let search = Search {
        base: base.to_owned(),
        scope: Scope::Subtree,
        filter,
        attributes,
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls: Vec::new(),
    };
    let mut entries = Vec::new();
    search_blocking(connection, search, &mut |page| {
        entries.extend(page);
        true
    })?;
    Ok(entries)
}

fn group_by_sid(
    connection: &Connection,
    base: &str,
    sid: &Sid,
) -> Result<Option<String>, MembershipError> {
    let encoded = sid.encode();
    let filter = format!(
        "(&{GROUPS}{})",
        search::eq("objectSid", Value::Bytes(&encoded)).unwrap_or_default()
    );
    let found = search_all(connection, base, filter, vec!["1.1".into()])?;
    Ok(found.into_iter().next().map(|e| e.dn))
}

/// `parents` of `closure`: `memberOf` of a level of groups, by batches of `BATCH`.
fn member_of(
    connection: &Connection,
    base: &str,
    level: &[String],
) -> Result<Parents, MembershipError> {
    let mut read = HashMap::new();
    for batch in level.chunks(BATCH) {
        let by_lower: HashMap<String, &String> =
            batch.iter().map(|d| (d.to_lowercase(), d)).collect();
        let filters: Vec<String> = batch
            .iter()
            .filter_map(|dn| search::eq("distinguishedName", Value::Text(dn)).ok())
            .collect();
        let filter = search::or(&filters).unwrap_or_default();
        for entry in search_all(connection, base, filter, vec!["memberOf".into()])? {
            let dn = by_lower
                .get(&entry.dn.to_lowercase())
                .map_or_else(|| entry.dn.clone(), |d| (*d).clone());
            let ranged = entry
                .attributes
                .iter()
                .any(|(n, _)| n.to_lowercase().starts_with("memberof;range="));
            let groups = if ranged {
                text(&read_ranges(connection, &entry.dn, "memberOf")?)
            } else {
                text(entry.values("memberOf"))
            };
            read.insert(dn, groups);
        }
    }
    Ok(read)
}

/// Groups of the object `dn` (`groupes_de`); `Missing` if it does not exist. Blocking.
pub fn groups_of(
    connection: &Connection,
    dn: &str,
    recursive: bool,
) -> Result<Membership, MembershipError> {
    let (base, entry) = {
        let dn = dn.to_owned();
        connection.run(true, move |link| {
            let base = link.state.root_dse.default_naming_context.clone();
            let attributes: Vec<String> = ["objectClass", "objectSid", "primaryGroupID"]
                .iter()
                .map(|&a| a.to_owned())
                .collect();
            let entry = search::read_entry(
                link.session.as_mut(),
                &dn,
                &attributes,
                "(objectClass=*)",
                None,
                Some(link.timeout),
            )?;
            Ok((base, entry))
        })?
    };
    let Some(entry) = entry else {
        return Err(MembershipError::Missing(dn.to_owned()));
    };
    let direct = text(&read_ranges(connection, dn, "memberOf")?);
    let sid = model::object_from_entry(&entry)
        .ok()
        .and_then(|o| o.account().and_then(model::Account::primary_group_sid));
    let primary = match sid {
        Some(sid) => group_by_sid(connection, &base, &sid)?,
        None => None,
    };
    let recursive = if recursive {
        let mut start = direct.clone();
        start.extend(primary.clone());
        let mut all = closure(start, &mut |level| member_of(connection, &base, level))?;
        all.sort_by_key(|d| d.to_lowercase());
        Some(all)
    } else {
        None
    };
    Ok(Membership {
        direct,
        primary,
        recursive,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closure_stops_cycles() {
        let graph: HashMap<&str, Vec<&str>> = HashMap::from([
            ("A", vec!["B", "c"]),
            ("B", vec!["C"]),
            ("C", vec!["A", "D"]),
            ("D", vec![]),
        ]);
        let mut calls = 0;
        let found: Result<Vec<String>, ()> = closure(["A".to_owned()], &mut |level| {
            calls += 1;
            Ok(level
                .iter()
                .map(|dn| {
                    let up = dn.to_uppercase();
                    let parents = graph.get(up.as_str()).cloned().unwrap_or_default();
                    (dn.clone(), parents.into_iter().map(str::to_owned).collect())
                })
                .collect())
        });
        // « c » is « C » without case: seen once, in the order of discovery.
        assert_eq!(found.unwrap(), ["A", "B", "c", "D"]);
        assert_eq!(calls, 3);
    }

    #[test]
    fn primary_group_added_once() {
        let m = Membership {
            direct: vec!["CN=G,DC=x".into()],
            primary: Some("CN=Domain Users,DC=x".into()),
            recursive: None,
        };
        assert_eq!(m.all_direct(), ["CN=G,DC=x", "CN=Domain Users,DC=x"]);
        let same = Membership {
            primary: Some("CN=G,DC=x".into()),
            ..m
        };
        assert_eq!(same.all_direct(), ["CN=G,DC=x"]);
    }
}

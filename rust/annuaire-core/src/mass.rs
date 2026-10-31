// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Changes of many objects at once (J9.9, ADR 0026): on a selection (the table, the results of
//! a query, the members of a group), an attribute set, added to, removed from or cleared, a
//! group joined or left, accounts enabled, disabled, moved, given an expiry date or asked to
//! change their password at the next logon.
//!
//! The objects are read on the write DC (`read`, by bursts), each becomes an item of a change
//! in bulk (`bulk`) with its row of the preview (its value before and after); the objects
//! already in the state asked are left aside and counted. The builders are pure, apart from
//! `read` and `members`.

use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::time::NTTIME_NEVER;
use annuaire_codecs::uac::UserAccountControl;

use crate::actions::{ActionError, ReadObject};
use crate::bulk::{Item, Membership};
use crate::changes::{Change as AttributeChange, Operation, Read, Values, dn_key, parent_dn};
use crate::connection::{Connection, Failure};
use crate::dn;
use crate::error::{LdapError, code};
use crate::search::{Burst, BurstAnswer};
use crate::session::{Scope, SearchRequest};

/// What is done to every object of the selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// The attribute gets these values (those it had are removed).
    Set {
        attribute: String,
        values: Values,
    },
    /// These values are added (those already there left aside).
    Add {
        attribute: String,
        values: Values,
    },
    /// These values are removed (those not there left aside).
    Remove {
        attribute: String,
        values: Values,
    },
    /// Every value removed.
    Clear {
        attribute: String,
    },
    /// The group (its DN and version on the write DC) gains or loses the objects as members.
    Group {
        group: String,
        read: Read,
        join: bool,
    },
    Enable(bool),
    Move {
        parent: String,
    },
    /// `accountExpires`: the date (NT time, end of the day chosen) or never.
    Expire(Option<i64>),
    /// `pwdLastSet` 0 (change at the next logon) or -1 (not required).
    MustChange(bool),
}

impl Change {
    /// The attributes to read on each object, besides its version.
    pub fn attributes(&self) -> Vec<String> {
        let mut names = vec!["objectClass".to_owned()];
        names.push(
            match self {
                Self::Set { attribute, .. }
                | Self::Add { attribute, .. }
                | Self::Remove { attribute, .. }
                | Self::Clear { attribute } => attribute.as_str(),
                Self::Group { .. } => "memberOf",
                Self::Enable(_) => "userAccountControl",
                Self::Move { .. } => "name",
                Self::Expire(_) => "accountExpires",
                Self::MustChange(_) => "pwdLastSet",
            }
            .to_owned(),
        );
        names
    }

    /// The attribute the rows of the preview show.
    pub fn shown(&self) -> String {
        match self {
            Self::Move { .. } => "distinguishedName".into(),
            other => other.attributes().pop().unwrap_or_default(),
        }
    }
}

/// One object of the preview: what it holds before and after.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub dn: String,
    pub attribute: String,
    pub before: Values,
    pub after: Values,
}

/// What a change of the selection gives: the items to write and their rows, in the same order,
/// and the objects left aside (already as asked, or not accounts for an account change).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Planned {
    pub items: Vec<Item>,
    pub rows: Vec<Row>,
    pub unchanged: Vec<String>,
    pub not_accounts: Vec<String>,
}

fn same(a: &[u8], b: &[u8]) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn is_account(object: &ReadObject) -> bool {
    object
        .values("objectClass")
        .iter()
        .any(|c| same(c, b"user") || same(c, b"computer") || same(c, b"inetOrgPerson"))
}

fn number(values: &[Vec<u8>]) -> Option<i64> {
    values
        .first()
        .and_then(|v| integer::decode(v, Width::Bits64).ok())
}

/// The modification of one attribute, or None if nothing changes.
fn attribute_change(
    object: &ReadObject,
    attribute: &str,
    removed: Values,
    added: Values,
) -> Result<Option<(Operation, Row)>, ActionError> {
    if removed.is_empty() && added.is_empty() {
        return Ok(None);
    }
    let before = object.values(attribute);
    let mut after: Values = before
        .iter()
        .filter(|v| !removed.iter().any(|r| same(r, v)))
        .cloned()
        .collect();
    after.extend(added.iter().cloned());
    let op = Operation::modify(
        &object.dn,
        vec![AttributeChange::new(attribute, removed, added)?],
        Some(object.read.clone()),
    )?;
    Ok(Some((
        op,
        Row {
            dn: object.dn.clone(),
            attribute: attribute.to_owned(),
            before,
            after,
        },
    )))
}

/// Plans `change` on `objects` (read with `change.attributes()`).
pub fn plan(objects: &[ReadObject], change: &Change) -> Result<Planned, ActionError> {
    let mut planned = Planned::default();
    let account_change = matches!(
        change,
        Change::Enable(_) | Change::Expire(_) | Change::MustChange(_)
    );
    for o in objects {
        if account_change && !is_account(o) {
            planned.not_accounts.push(o.dn.clone());
            continue;
        }
        let made: Option<(Vec<Operation>, Vec<Membership>, Row)> = match change {
            Change::Set { attribute, values } => {
                let present = o.values(attribute);
                let removed: Values = present
                    .iter()
                    .filter(|p| !values.iter().any(|v| same(v, p)))
                    .cloned()
                    .collect();
                let added: Values = values
                    .iter()
                    .filter(|v| !present.iter().any(|p| same(p, v)))
                    .cloned()
                    .collect();
                attribute_change(o, attribute, removed, added)?
                    .map(|(op, row)| (vec![op], Vec::new(), row))
            }
            Change::Add { attribute, values } => {
                let present = o.values(attribute);
                let added: Values = values
                    .iter()
                    .filter(|v| !present.iter().any(|p| same(p, v)))
                    .cloned()
                    .collect();
                attribute_change(o, attribute, Vec::new(), added)?
                    .map(|(op, row)| (vec![op], Vec::new(), row))
            }
            Change::Remove { attribute, values } => {
                let present = o.values(attribute);
                let removed: Values = present
                    .iter()
                    .filter(|p| values.iter().any(|v| same(v, p)))
                    .cloned()
                    .collect();
                attribute_change(o, attribute, removed, Vec::new())?
                    .map(|(op, row)| (vec![op], Vec::new(), row))
            }
            Change::Clear { attribute } => {
                attribute_change(o, attribute, o.values(attribute), Vec::new())?
                    .map(|(op, row)| (vec![op], Vec::new(), row))
            }
            Change::Group { group, read, join } => {
                let k = dn_key(group)?;
                let member = o
                    .values("memberOf")
                    .iter()
                    .any(|g| dn_key(&String::from_utf8_lossy(g)).is_ok_and(|x| x == k));
                (member != *join).then(|| {
                    let before = o.values("memberOf");
                    let mut after = before.clone();
                    if *join {
                        after.push(group.as_bytes().to_vec());
                    } else {
                        after.retain(|g| dn_key(&String::from_utf8_lossy(g)).is_ok_and(|x| x != k));
                    }
                    (
                        Vec::new(),
                        vec![Membership {
                            group: group.clone(),
                            read: Some(read.clone()),
                            member: o.dn.clone(),
                            add: *join,
                        }],
                        Row {
                            dn: o.dn.clone(),
                            attribute: "memberOf".into(),
                            before,
                            after,
                        },
                    )
                })
            }
            Change::Enable(active) => {
                let present = number(&o.values("userAccountControl"))
                    .ok_or_else(|| ActionError::NoUserAccountControl(o.dn.clone()))?;
                let flag = i64::from(UserAccountControl::ACCOUNTDISABLE);
                let new = if *active {
                    present & !flag
                } else {
                    present | flag
                };
                let text = |n: i64| vec![n.to_string().into_bytes()];
                attribute_change(o, "userAccountControl", text(present), text(new))?
                    .filter(|_| new != present)
                    .map(|(op, row)| (vec![op], Vec::new(), row))
            }
            Change::Move { parent } => {
                let target = dn_key(parent)?;
                if dn_key(&parent_dn(&o.dn)?)? == target {
                    None
                } else {
                    let k = dn_key(&o.dn)?;
                    if k == target || target.ends_with(&format!(",{k}")) {
                        return Err(ActionError::UnderItself(o.dn.clone()));
                    }
                    let first = dn::split(&o.dn)
                        .map_err(|e| ActionError::Change(e.to_string()))?
                        .into_iter()
                        .next()
                        .ok_or(ActionError::EmptyName)?;
                    let op = Operation::rename(
                        &o.dn,
                        first,
                        Some(parent.clone()),
                        Some(o.read.clone()),
                    )?;
                    let after = op.dn_after()?;
                    Some((
                        vec![op],
                        Vec::new(),
                        Row {
                            dn: o.dn.clone(),
                            attribute: "distinguishedName".into(),
                            before: vec![o.dn.clone().into_bytes()],
                            after: vec![after.into_bytes()],
                        },
                    ))
                }
            }
            Change::Expire(at) => {
                let present = o.values("accountExpires");
                let wanted = at.unwrap_or(NTTIME_NEVER);
                let never = |n: Option<i64>| n.is_none_or(|n| n == 0 || n == NTTIME_NEVER);
                let unchanged = match at {
                    None => never(number(&present)),
                    Some(_) => number(&present) == Some(wanted),
                };
                if unchanged {
                    None
                } else {
                    attribute_change(
                        o,
                        "accountExpires",
                        present.into_iter().take(1).collect(),
                        vec![wanted.to_string().into_bytes()],
                    )?
                    .map(|(op, row)| (vec![op], Vec::new(), row))
                }
            }
            Change::MustChange(must) => {
                let present = o.values("pwdLastSet");
                let zero = number(&present) == Some(0);
                if zero == *must {
                    None
                } else {
                    let new = if *must { "0" } else { "-1" };
                    attribute_change(
                        o,
                        "pwdLastSet",
                        present.into_iter().take(1).collect(),
                        vec![new.as_bytes().to_vec()],
                    )?
                    .map(|(op, row)| (vec![op], Vec::new(), row))
                }
            }
        };
        match made {
            None => planned.unchanged.push(o.dn.clone()),
            Some((operations, memberships, row)) => {
                planned.items.push(Item {
                    label: o.dn.clone(),
                    operations,
                    memberships,
                });
                planned.rows.push(row);
            }
        }
    }
    Ok(planned)
}

fn usn(entry: &crate::session::Entry) -> Option<i64> {
    number(entry.values("uSNChanged"))
}

/// Reads `dns` on the write DC with `attributes` and their version, by bursts; those that no
/// longer exist are left out. Blocking.
pub fn read(
    connection: &Connection,
    dns: &[String],
    attributes: &[String],
) -> Result<Vec<ReadObject>, Failure> {
    let mut names = vec!["uSNChanged".to_owned()];
    names.extend(attributes.iter().cloned());
    let (dns, names) = (dns.to_vec(), names);
    connection.run(true, move |link| {
        let dc = link.state.dc.clone();
        let mut out = Vec::with_capacity(dns.len());
        for chunk in dns.chunks(crate::export::CHUNK) {
            let mut burst = Burst::new();
            for d in chunk {
                burst.search(
                    link.session.as_mut(),
                    d,
                    Scope::Base,
                    "(objectClass=*)",
                    &names,
                    0,
                    None,
                )?;
            }
            for answer in burst.receive(link.session.as_mut(), Some(link.timeout))? {
                let BurstAnswer::Entries(entries) = answer else {
                    continue;
                };
                for entry in entries {
                    let usn = usn(&entry)
                        .ok_or_else(|| LdapError::new(code::DECODING_ERROR, "uSNChanged absent"))?;
                    out.push(ReadObject {
                        dn: entry.dn,
                        attributes: entry.attributes,
                        read: Read {
                            dc: dc.clone(),
                            usn,
                        },
                    });
                }
            }
        }
        Ok(out)
    })
}

/// The range a `member;range=low-high` attribute covers: (low, high), high None for `*`.
fn range_of(name: &str) -> Option<(usize, Option<usize>)> {
    let (_, range) = name.split_once(";range=")?;
    let (low, high) = range.split_once('-')?;
    Some((low.parse().ok()?, high.parse().ok()))
}

/// The direct members of `group` (DN), read by ranges when the DC gives them so (beyond 1,500
/// values on Windows, MS-ADTS 3.1.1.3.1.3.3). Blocking.
pub fn members(connection: &Connection, group: &str) -> Result<Vec<String>, Failure> {
    let group = group.to_owned();
    connection.run(true, move |link| {
        let mut out = Vec::new();
        let mut low = 0usize;
        loop {
            let asked = if low == 0 {
                "member".to_owned()
            } else {
                format!("member;range={low}-*")
            };
            let request = SearchRequest {
                base: group.clone(),
                scope: Scope::Base,
                filter: "(objectClass=*)".into(),
                attributes: vec![asked],
                controls: Vec::new(),
                size_limit: 0,
            };
            let response = link.session.search_wait(request, Some(link.timeout))?;
            let Some(entry) = response.into_entries().into_iter().next() else {
                return Ok(out);
            };
            let mut next = None;
            for (name, values) in &entry.attributes {
                let lower = name.to_lowercase();
                if lower != "member" && !lower.starts_with("member;range=") {
                    continue;
                }
                out.extend(
                    values
                        .iter()
                        .map(|v| String::from_utf8_lossy(v).into_owned()),
                );
                if let Some((_, Some(high))) = range_of(&lower) {
                    next = Some(high + 1);
                }
            }
            match next {
                Some(n) if n > low => low = n,
                _ => return Ok(out),
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(dn: &str, attributes: &[(&str, &[&str])]) -> ReadObject {
        ReadObject {
            dn: dn.into(),
            attributes: attributes
                .iter()
                .map(|(a, vs)| {
                    (
                        (*a).to_owned(),
                        vs.iter().map(|v| v.as_bytes().to_vec()).collect(),
                    )
                })
                .collect(),
            read: Read {
                dc: "dc1".into(),
                usn: 5,
            },
        }
    }

    fn values(list: &[&str]) -> Values {
        list.iter().map(|v| v.as_bytes().to_vec()).collect()
    }

    #[test]
    fn attribute_set_added_removed_cleared() {
        let a = object("CN=a,OU=X,DC=x", &[("otherTelephone", &["01", "02"])]);
        let b = object("CN=b,OU=X,DC=x", &[]);
        let set = plan(
            &[a.clone(), b.clone()],
            &Change::Set {
                attribute: "otherTelephone".into(),
                values: values(&["02", "03"]),
            },
        )
        .unwrap();
        assert_eq!(set.items.len(), 2);
        let row = set.rows.first().unwrap();
        assert_eq!(row.before, values(&["01", "02"]));
        assert_eq!(row.after, values(&["02", "03"]));
        let Some(Operation::Modify { changes, .. }) = set.items.first().unwrap().operations.first()
        else {
            panic!("a modification expected");
        };
        assert_eq!(
            changes
                .first()
                .map(|c| (c.removed.clone(), c.added.clone())),
            Some((values(&["01"]), values(&["03"])))
        );
        let add = plan(
            std::slice::from_ref(&a),
            &Change::Add {
                attribute: "otherTelephone".into(),
                values: values(&["01"]),
            },
        )
        .unwrap();
        assert_eq!(add.unchanged, vec!["CN=a,OU=X,DC=x".to_owned()]);
        let remove = plan(
            &[a.clone(), b.clone()],
            &Change::Remove {
                attribute: "otherTelephone".into(),
                values: values(&["02"]),
            },
        )
        .unwrap();
        assert_eq!((remove.items.len(), remove.unchanged.len()), (1, 1));
        let clear = plan(
            &[a, b],
            &Change::Clear {
                attribute: "otherTelephone".into(),
            },
        )
        .unwrap();
        assert_eq!(clear.rows.first().map(|r| r.after.len()), Some(0));
    }

    #[test]
    fn accounts_groups_and_moves() {
        let user = object(
            "CN=u,OU=X,DC=x",
            &[
                ("objectClass", &["top", "user"]),
                ("userAccountControl", &["512"]),
                ("memberOf", &["CN=G,DC=x"]),
                ("pwdLastSet", &["133"]),
                ("accountExpires", &["9223372036854775807"]),
            ],
        );
        let group = object("CN=H,OU=X,DC=x", &[("objectClass", &["top", "group"])]);
        let disabled = plan(&[user.clone(), group.clone()], &Change::Enable(false)).unwrap();
        assert_eq!(disabled.not_accounts, vec!["CN=H,OU=X,DC=x".to_owned()]);
        assert_eq!(
            disabled.rows.first().map(|r| r.after.clone()),
            Some(values(&["514"]))
        );
        let read = Read {
            dc: "dc1".into(),
            usn: 9,
        };
        let join = plan(
            std::slice::from_ref(&user),
            &Change::Group {
                group: "cn=g,dc=x".into(),
                read: read.clone(),
                join: true,
            },
        )
        .unwrap();
        assert_eq!(join.unchanged.len(), 1);
        let leave = plan(
            std::slice::from_ref(&user),
            &Change::Group {
                group: "CN=G,DC=x".into(),
                read,
                join: false,
            },
        )
        .unwrap();
        let m = leave.items.first().unwrap().memberships.first().unwrap();
        assert!(!m.add && m.member == "CN=u,OU=X,DC=x");
        assert!(
            plan(std::slice::from_ref(&user), &Change::Expire(None))
                .unwrap()
                .items
                .is_empty()
        );
        assert_eq!(
            plan(
                std::slice::from_ref(&user),
                &Change::Expire(Some(134_116_992_000_000_000))
            )
            .unwrap()
            .items
            .len(),
            1
        );
        let must = plan(std::slice::from_ref(&user), &Change::MustChange(true)).unwrap();
        assert_eq!(
            must.rows.first().map(|r| r.after.clone()),
            Some(values(&["0"]))
        );
        let moved = plan(
            std::slice::from_ref(&user),
            &Change::Move {
                parent: "OU=Y,DC=x".into(),
            },
        )
        .unwrap();
        assert_eq!(
            moved.rows.first().map(|r| r.after.clone()),
            Some(values(&["CN=u,OU=Y,DC=x"]))
        );
        assert_eq!(
            plan(
                &[user],
                &Change::Move {
                    parent: "ou=x,dc=x".into()
                }
            )
            .unwrap()
            .unchanged
            .len(),
            1
        );
    }

    #[test]
    fn ranges() {
        assert_eq!(range_of("member;range=0-1499"), Some((0, Some(1499))));
        assert_eq!(range_of("member;range=1500-*"), Some((1500, None)));
        assert_eq!(range_of("member"), None);
    }
}

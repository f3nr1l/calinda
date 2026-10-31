// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Changes in bulk (J9.8, J9.9, ADR 0026): an import or a change of many objects written as a
//! **series of batches**. Each batch is a changeset of its own, written by `writer` with its
//! prior verification, its rollback and its journal (ADR 0006): « all or nothing » holds for
//! the batch, not beyond. The series names its batches (`changes::Series`), so that the history
//! shows them as one change and one undo takes them all.
//!
//! A change is made of **items** (one object: a row of the file, a selected account) and of
//! the memberships they bring; a batch takes `BATCH_SIZE` items, their operations in order,
//! then one modification per group for the members of the batch. The batches are written one
//! after the other; between two, the application can stop (`Control::stop`), and a batch that
//! does not end applied stops the series. What is written stays written: resuming writes the
//! batches left, without the items refused if asked; undoing writes the inverse of each batch
//! applied, the last first.
//!
//! An object changed by a batch (a group that gets members in each one) is expected by the
//! next batch in the version the previous one left (`Run::chain`), as within a changeset
//! (ADR 0006 § 2). Blocking, apart from the builders.

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::changes::{
    self, Change, ChangeError, Changeset, Issue, Operation, Read, Report, Series, dn_key,
};
use crate::connection::Connection;
use crate::journal::Journal;
use crate::profile::Profile;
use crate::writer::{self, ApplyError, Outcome, Problem, WriteCatalog};

/// Objects in one batch. A batch of creations with their checks is about 300 requests sent
/// together, its rollback a hundred writes: a few seconds on the local network (ADR 0026 § 2).
pub const BATCH_SIZE: usize = 100;

/// A group gains or loses a member with an item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Membership {
    pub group: String,
    /// The version of the group read on the write DC; None: not controlled.
    pub read: Option<Read>,
    pub member: String,
    pub add: bool,
}

/// One object of a change in bulk: its operations, and the groups it joins or leaves.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Item {
    /// What the reports name: the line of the file, the DN of the object.
    pub label: String,
    pub operations: Vec<Operation>,
    pub memberships: Vec<Membership>,
}

/// A batch: its changeset, and for each operation the items it serves (one for an
/// operation of an item, those of the batch for the members of a group).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Batch {
    pub changeset: Changeset,
    pub items: Vec<Vec<usize>>,
}

impl Batch {
    /// The items of the batch, in order.
    pub fn all_items(&self) -> Vec<usize> {
        let set: BTreeSet<usize> = self.items.iter().flatten().copied().collect();
        set.into_iter().collect()
    }
}

/// A group changed by a batch (in its first spelling): its version, the members added and
/// removed, the items they come from.
type GroupChange = (String, Option<Read>, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<usize>);

/// The batches of `items` (indices `chosen`, in order), `size` items each; the remarks go with
/// each batch.
pub fn batches(
    items: &[Item],
    chosen: &[usize],
    size: usize,
    remarks: &[String],
) -> Result<Vec<Batch>, ChangeError> {
    let mut out = Vec::new();
    for chunk in chosen.chunks(size.max(1)) {
        let mut operations = Vec::new();
        let mut served: Vec<Vec<usize>> = Vec::new();
        // Group (in its first spelling) → (version, members added, members removed, items).
        let mut groups: Vec<GroupChange> = Vec::new();
        for &i in chunk {
            let Some(item) = items.get(i) else { continue };
            for op in &item.operations {
                operations.push(op.clone());
                served.push(vec![i]);
            }
            for m in &item.memberships {
                let k = dn_key(&m.group)?;
                let at = match groups
                    .iter()
                    .position(|g| dn_key(&g.0).is_ok_and(|x| x == k))
                {
                    Some(at) => at,
                    None => {
                        groups.push((
                            m.group.clone(),
                            m.read.clone(),
                            Vec::new(),
                            Vec::new(),
                            Vec::new(),
                        ));
                        groups.len() - 1
                    }
                };
                if let Some(g) = groups.get_mut(at) {
                    let value = m.member.as_bytes().to_vec();
                    let list = if m.add { &mut g.2 } else { &mut g.3 };
                    if !list.contains(&value) {
                        list.push(value);
                    }
                    if !g.4.contains(&i) {
                        g.4.push(i);
                    }
                }
            }
        }
        for (group, read, added, removed, users) in groups {
            operations.push(Operation::modify(
                &group,
                vec![Change::new("member", removed, added)?],
                read,
            )?);
            served.push(users);
        }
        if !operations.is_empty() {
            out.push(Batch {
                changeset: Changeset {
                    operations,
                    remarks: remarks.to_vec(),
                },
                items: served,
            });
        }
    }
    Ok(out)
}

/// The items a refusal names: those of the operations of the problems (prior verification).
pub fn refused_by_problems(batch: &Batch, problems: &[Problem]) -> Vec<usize> {
    let set: BTreeSet<usize> = problems
        .iter()
        .filter_map(|p| batch.items.get(p.index))
        .flatten()
        .copied()
        .collect();
    set.into_iter().collect()
}

/// The items of the operation where the application of `report` failed (none if it did not).
pub fn refused_by_report(batch: &Batch, report: &Report) -> Vec<usize> {
    if report.error.is_none() || report.issue == Issue::Refused {
        return Vec::new();
    }
    batch
        .items
        .get(report.applied.len())
        .cloned()
        .unwrap_or_default()
}

// --- Application ------------------------------------------------------------------------------

/// Follows and stops a series from another thread: « Stop » asks to end after the batch being
/// written; the counters say where the series is.
#[derive(Debug, Default)]
pub struct Control {
    stop: AtomicBool,
    /// Batches ended (applied or not) in this run, and the batch being written (from 1).
    ended: AtomicUsize,
    current: AtomicUsize,
    /// Items written in this run.
    written: AtomicUsize,
    /// Stop once this many batches ended (0: no limit): the trials stop at a known place.
    limit: AtomicUsize,
}

impl Control {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    pub fn stopping(&self) -> bool {
        let limit = self.limit.load(Ordering::SeqCst);
        self.stop.load(Ordering::SeqCst)
            || (limit > 0 && self.ended.load(Ordering::SeqCst) >= limit)
    }

    /// Stop after `batches` more batches of this run.
    pub fn stop_after(&self, batches: usize) {
        self.limit.store(
            self.ended.load(Ordering::SeqCst) + batches,
            Ordering::SeqCst,
        );
    }

    /// (batches ended, batch being written, items written).
    pub fn progress(&self) -> (usize, usize, usize) {
        (
            self.ended.load(Ordering::SeqCst),
            self.current.load(Ordering::SeqCst),
            self.written.load(Ordering::SeqCst),
        )
    }
}

/// How a run of a series ended.
#[derive(Debug, Clone)]
pub enum End {
    /// Every batch applied.
    Finished,
    /// « Stop » between two batches.
    Stopped,
    /// A batch was refused by its verification, cancelled or left incomplete by its rollback:
    /// the series stops there (its report is the last of `outcomes`).
    Failed,
    /// Nothing written for that batch and no report (journal, DC unreachable).
    Error(ApplyError),
}

/// A series being written: its batches, the next one, and the versions the batches left.
#[derive(Debug, Clone)]
pub struct Run {
    pub id: String,
    pub title: String,
    pub batches: Vec<Batch>,
    /// The application each batch resumes (the batch undone, for an undo); empty: none.
    pub resumes: Vec<Option<String>>,
    /// Index of the next batch to write.
    pub next: usize,
    /// Rank of the next batch in the series (from 1): it goes on after a resume.
    pub rank: usize,
    /// One per batch tried, in order, over every run.
    pub outcomes: Vec<Outcome>,
    versions: HashMap<String, Option<Read>>,
}

impl Run {
    pub fn new(title: &str, batches: Vec<Batch>) -> Self {
        Self {
            id: writer::new_id(),
            title: title.to_owned(),
            batches,
            resumes: Vec::new(),
            next: 0,
            rank: 1,
            outcomes: Vec::new(),
            versions: HashMap::new(),
        }
    }

    /// Batches not written yet.
    pub fn left(&self) -> usize {
        self.batches.len().saturating_sub(self.next)
    }

    /// The version an earlier batch of the series left to an object this one touches again.
    fn chain(&self, changeset: &Changeset) -> Changeset {
        let operations = changeset
            .operations
            .iter()
            .map(|op| {
                let known = match op {
                    Operation::Modify { .. }
                    | Operation::Rename { .. }
                    | Operation::Delete { .. }
                    | Operation::Restore { .. } => dn_key(op.dn())
                        .ok()
                        .and_then(|k| self.versions.get(&k).cloned()),
                    _ => None,
                };
                match known {
                    Some(Some(read)) if op.read().is_some() => op.with_read(Some(read)),
                    _ => op.clone(),
                }
            })
            .collect();
        Changeset {
            operations,
            remarks: changeset.remarks.clone(),
        }
    }

    fn remember(&mut self, report: &Report) {
        for a in &report.applied {
            if !a.operation.is_ldap() {
                continue;
            }
            let version = match a.operation {
                Operation::Delete { .. } => None,
                _ => a.after.clone(),
            };
            if let Ok(k) = a.operation.dn_after().and_then(|d| dn_key(&d)) {
                self.versions.insert(k, version);
            }
        }
    }

    /// Writes the batches left, one after the other, until the end, a stop or a failure.
    pub fn write(
        &mut self,
        connection: &Connection,
        profile: &Profile,
        journal: &Arc<Journal>,
        catalog: &Arc<dyn WriteCatalog>,
        control: &Control,
    ) -> End {
        while self.next < self.batches.len() {
            if control.stopping() {
                return End::Stopped;
            }
            let Some(batch) = self.batches.get(self.next) else {
                break;
            };
            control.current.store(self.rank, Ordering::SeqCst);
            let changeset = self.chain(&batch.changeset);
            let total = self.rank + self.left() - 1;
            let series = Series {
                id: self.id.clone(),
                rank: self.rank,
                total,
                title: self.title.clone(),
            };
            let resumes = self.resumes.get(self.next).cloned().flatten();
            let items = batch.all_items().len();
            let result = writer::apply_in_series(
                connection,
                profile,
                &changeset,
                journal.clone(),
                catalog.clone(),
                resumes,
                None,
                Some(series),
            );
            control.ended.fetch_add(1, Ordering::SeqCst);
            let outcome = match result {
                Ok(outcome) => outcome,
                Err(e) => return End::Error(e),
            };
            let applied = outcome.report.issue == Issue::Applied;
            if applied {
                self.remember(&outcome.report);
                control.written.fetch_add(items, Ordering::SeqCst);
                self.next += 1;
                self.rank += 1;
            }
            self.outcomes.push(outcome);
            if !applied {
                return End::Failed;
            }
        }
        End::Finished
    }

    /// The batches left built again without `excluded` items, from the items of the change:
    /// a resume after a refusal. The batch that failed was rolled back: it is written again.
    pub fn without(
        &mut self,
        items: &[Item],
        excluded: &[usize],
        size: usize,
    ) -> Result<(), ChangeError> {
        let left: Vec<usize> = self
            .batches
            .get(self.next..)
            .unwrap_or_default()
            .iter()
            .flat_map(Batch::all_items)
            .filter(|i| !excluded.contains(i))
            .collect();
        let remarks = self
            .batches
            .first()
            .map(|b| b.changeset.remarks.clone())
            .unwrap_or_default();
        let rebuilt = batches(items, &left, size, &remarks)?;
        self.batches.truncate(self.next);
        self.batches.extend(rebuilt);
        Ok(())
    }

    /// The objects of the next batch that changed since they were read (the problems of
    /// version of its refusal), read again: the administrator writes over the change (a logon
    /// since the import, which the KDC wrote on the account). Blocking.
    pub fn refresh(
        &mut self,
        connection: &Connection,
        dns: &[String],
    ) -> Result<(), crate::connection::Failure> {
        let Some(batch) = self.batches.get_mut(self.next) else {
            return Ok(());
        };
        let keys: Vec<String> = dns.iter().filter_map(|d| dn_key(d).ok()).collect();
        for op in &mut batch.changeset.operations {
            if op.read().is_none() || !dn_key(op.dn()).is_ok_and(|k| keys.contains(&k)) {
                continue;
            }
            if let Some(read) = writer::read_version(connection, op.dn())? {
                *op = op.with_read(Some(read));
            }
        }
        Ok(())
    }

    /// The objects a refusal of version names (prior verification of the last batch tried).
    pub fn changed_since(&self) -> Vec<String> {
        self.outcomes
            .last()
            .map(|o| {
                o.problems
                    .iter()
                    .filter(|p| p.kind == writer::ProblemKind::Version)
                    .map(|p| p.dn.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Reports of the batches applied in this series.
    pub fn applied(&self) -> Vec<&Report> {
        self.outcomes
            .iter()
            .map(|o| &o.report)
            .filter(|r| r.issue == Issue::Applied)
            .collect()
    }
}

// --- Undo ---------------------------------------------------------------------------------------

/// The batches of the series `id` in the domain of which something stays applied, that no
/// application resumed, in their order of writing.
pub fn of_series<'a>(reports: &'a [Report], domain: &str, id: &str) -> Vec<&'a Report> {
    reports
        .iter()
        .filter(|r| {
            r.domain == domain
                && r.series.as_ref().is_some_and(|s| s.id == id)
                && r.resumed_by.is_none()
                && !r.remaining_indices().is_empty()
        })
        .collect()
}

/// The undo of a series: one batch per batch of it that stays applied, the last first, each
/// resuming the batch it undoes. `journal`: the reports of the journal (ADR 0006 § 5.1).
pub fn undo(
    reports: &[Report],
    domain: &str,
    id: &str,
    title: &str,
    catalog: &dyn crate::messages::Catalog,
) -> Result<Run, ChangeError> {
    let mut batches_out = Vec::new();
    let mut resumes = Vec::new();
    for report in of_series(reports, domain, id).into_iter().rev() {
        let inverse = changes::inverse(report, reports, catalog)?;
        if inverse.operations.is_empty() {
            continue;
        }
        let items = (0..inverse.operations.len()).map(|i| vec![i]).collect();
        batches_out.push(Batch {
            changeset: inverse,
            items,
        });
        resumes.push(Some(report.id.clone()));
    }
    let mut run = Run::new(title, batches_out);
    run.resumes = resumes;
    Ok(run)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(dn: &str) -> Operation {
        Operation::add(dn, vec![("objectClass".into(), vec![b"contact".to_vec()])]).unwrap()
    }

    fn item(n: usize, groups: &[&str]) -> Item {
        let dn = format!("CN=c{n},OU=X,DC=x");
        Item {
            label: format!("ligne {n}"),
            operations: vec![add(&dn)],
            memberships: groups
                .iter()
                .map(|g| Membership {
                    group: (*g).to_owned(),
                    read: Some(Read {
                        dc: "dc1".into(),
                        usn: 10,
                    }),
                    member: dn.clone(),
                    add: true,
                })
                .collect(),
        }
    }

    #[test]
    fn batches_and_their_groups() {
        let items: Vec<Item> = (0..5)
            .map(|n| {
                item(
                    n,
                    if n % 2 == 0 {
                        &["CN=G,DC=x", "cn=h,dc=x"]
                    } else {
                        &["CN=g,DC=X"]
                    },
                )
            })
            .collect();
        let made = batches(&items, &[0, 1, 2, 4], 3, &["r".into()]).unwrap();
        assert_eq!(made.len(), 2);
        let first = made.first().unwrap();
        // Three creations, then G (members 0, 1, 2) and H (0, 2).
        assert_eq!(first.changeset.operations.len(), 5);
        let Some(Operation::Modify { dn, changes, .. }) = first.changeset.operations.get(3) else {
            panic!("modification of G expected");
        };
        assert_eq!(dn, "CN=G,DC=x");
        assert_eq!(changes.first().map(|c| c.added.len()), Some(3));
        assert_eq!(first.items.get(3), Some(&vec![0, 1, 2]));
        assert_eq!(first.items.get(4), Some(&vec![0, 2]));
        assert_eq!(first.all_items(), vec![0, 1, 2]);
        assert_eq!(made.get(1).unwrap().all_items(), vec![4]);
        assert_eq!(first.changeset.remarks, vec!["r".to_owned()]);
    }

    #[test]
    fn refusals_named_by_their_items() {
        let items: Vec<Item> = (0..3).map(|n| item(n, &["CN=G,DC=x"])).collect();
        let made = batches(&items, &[0, 1, 2], 10, &[]).unwrap();
        let batch = made.first().unwrap();
        let problem = |index| Problem {
            index,
            dn: String::new(),
            kind: writer::ProblemKind::Exists,
            message: String::new(),
        };
        assert_eq!(refused_by_problems(batch, &[problem(1)]), vec![1]);
        assert_eq!(
            refused_by_problems(batch, &[problem(3), problem(0)]),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn versions_chained_from_batch_to_batch() {
        let items: Vec<Item> = (0..4).map(|n| item(n, &["CN=G,DC=x"])).collect();
        let made = batches(&items, &[0, 1, 2, 3], 2, &[]).unwrap();
        let mut run = Run::new("t", made);
        let first = run.batches.first().unwrap().changeset.clone();
        let applied = first
            .operations
            .iter()
            .map(|op| changes::Applied {
                operation: op.clone(),
                after: Some(Read {
                    dc: "dc1".into(),
                    usn: 42,
                }),
                before: None,
            })
            .collect();
        let report = Report {
            id: "a".into(),
            timestamp: String::new(),
            domain: "x".into(),
            dc: "dc1".into(),
            user: String::new(),
            changeset: first,
            applied,
            issue: Issue::Applied,
            error: None,
            rollback: None,
            origins: Vec::new(),
            rollback_applied: Vec::new(),
            rollback_error: None,
            doubtful: None,
            doubtful_rollback: None,
            resumes: None,
            resumed_by: None,
            series: None,
        };
        run.remember(&report);
        let second = run.chain(&run.batches.get(1).unwrap().changeset);
        let group = second.operations.last().unwrap();
        assert_eq!(group.read().map(|r| r.usn), Some(42));
        // A creation has no version to take.
        assert!(second.operations.first().unwrap().read().is_none());
    }

    #[test]
    fn resume_without_the_refused() {
        let items: Vec<Item> = (0..5).map(|n| item(n, &[])).collect();
        let made = batches(&items, &[0, 1, 2, 3, 4], 2, &[]).unwrap();
        let mut run = Run::new("t", made);
        run.next = 1;
        run.without(&items, &[2], 2).unwrap();
        let left: Vec<Vec<usize>> = run.batches.iter().map(Batch::all_items).collect();
        assert_eq!(left, vec![vec![0, 1], vec![3, 4]]);
    }
}

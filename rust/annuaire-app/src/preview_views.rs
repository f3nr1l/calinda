// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Preview of a changeset as a table object / attribute / before / after (J2.7,
//! `annuaire.vue.apercu`), and the report of an application in words
//! (`annuaire.core.ecriture.decrire`). A change of one value for another fits on one row
//! (before → after); otherwise each value removed is preceded by « − », each value added by
//! « + ». The secrets are hidden by `show_value`. The history: the entries of the local journal
//! for the open domain, and the change that Ctrl+Z undoes.

use std::collections::{HashMap, HashSet};

use annuaire_codecs::Sid;
use annuaire_codecs::sd::{Ace, SecurityDescriptor};
use annuaire_core::changes::{
    self, Applied, Changeset, Issue, Operation, Report, content_text, is_registry_pol, parent_dn,
    registry_lines, show_value, sysvol_path,
};
use annuaire_core::dn;
use annuaire_core::security::{self, SidName};
use annuaire_core::writer::Problem;

use crate::catalog::AppCatalog;
use crate::i18n::{fill, tr, tr_n};
use crate::security_views as sv;

/// A row of the table; `object` only on the first row of an operation (`LigneApercu`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreviewLine {
    pub object: String,
    pub action: String,
    pub attribute: String,
    pub before: String,
    pub after: String,
}

fn rdn(dn_text: &str) -> String {
    dn::split(dn_text)
        .ok()
        .and_then(|c| {
            c.first()
                .and_then(|f| dn::compose(std::slice::from_ref(f)).ok())
        })
        .unwrap_or_else(|| dn_text.to_owned())
}

fn same_rdn(dn_text: &str, new: &dn::Component) -> bool {
    dn::split(dn_text)
        .ok()
        .and_then(|c| c.first().cloned())
        .is_some_and(|old| {
            old.attribute.eq_ignore_ascii_case(&new.attribute) && old.value == new.value
        })
}

/// Short name of the operation (`action`).
pub fn action(op: &Operation) -> String {
    match op {
        Operation::CreateFolder { .. } => tr("Folder creation"),
        Operation::DeleteFolder { .. } => tr("Folder deletion"),
        Operation::WriteFile { old: None, .. } => tr("File creation"),
        Operation::WriteFile { .. } => tr("File replacement"),
        Operation::DeleteFile { .. } => tr("File deletion"),
        Operation::SetDescriptor { .. } => tr("Permissions"),
        Operation::Add { .. } => tr("Creation"),
        Operation::Modify { .. } => tr("Modification"),
        Operation::Delete { .. } => tr("Deletion"),
        Operation::Rename { parent: None, .. } => tr("Rename"),
        Operation::Rename { dn, rdn, .. } if same_rdn(dn, rdn) => tr("Move"),
        Operation::Rename { .. } => tr("Rename and move"),
    }
}

type Names = HashMap<Sid, SidName>;
type Detail = (String, String, String);

fn value(attribute: &str, v: &[u8]) -> String {
    show_value(attribute, v, &AppCatalog).unwrap_or_default()
}

/// An ACE of the preview: kind, sentence in clear and SDDL (`decrire_ace`).
pub fn describe_ace(ace: &Ace, names: Option<&Names>) -> String {
    let kind = if ace.is_deny() {
        tr("Deny")
    } else if ace.is_allow() {
        tr("Allow")
    } else {
        fill(
            &tr("Entry of type {t}"),
            &[("t", &ace.ace_type.to_string())],
        )
    };
    let text = fill(
        &tr("{genre}: {phrase} {sddl}"),
        &[
            ("genre", &kind),
            ("phrase", &sv::ace_sentence(ace, &[], None, names)),
            ("sddl", &sv::ace_sddl(ace, None)),
        ],
    );
    if ace.is_inherited() {
        format!("{text}{}", tr(" (inherited)"))
    } else {
        text
    }
}

/// ACEs removed and added; `before` None: descriptor set on a new item, all its ACEs shown
/// (`_details_sd`).
fn descriptor_details(
    attribute: &str,
    before: Option<&[u8]>,
    after: &[u8],
    names: &Names,
) -> Vec<Detail> {
    let old = before.map(SecurityDescriptor::decode);
    let new = SecurityDescriptor::decode(after);
    let (old, new) = match (old, new) {
        (Some(Err(_)), _) | (_, Err(_)) => {
            return vec![(
                attribute.to_owned(),
                before.map(|b| value(attribute, b)).unwrap_or_default(),
                value(attribute, after),
            )];
        }
        (old, Ok(new)) => (old.and_then(Result::ok), new),
    };
    let aces = |d: &SecurityDescriptor| -> Vec<Ace> {
        d.dacl.as_ref().map(|a| a.aces.clone()).unwrap_or_default()
    };
    let Some(old) = old else {
        return aces(&new)
            .iter()
            .map(|a| {
                (
                    attribute.to_owned(),
                    String::new(),
                    format!("+ {}", describe_ace(a, Some(names))),
                )
            })
            .collect();
    };
    let mut after_aces = aces(&new);
    let mut lines = Vec::new();
    for ace in aces(&old) {
        if let Some(position) = after_aces.iter().position(|a| *a == ace) {
            after_aces.remove(position);
        } else {
            lines.push((
                attribute.to_owned(),
                format!("− {}", describe_ace(&ace, Some(names))),
                String::new(),
            ));
        }
    }
    lines.extend(after_aces.iter().map(|a| {
        (
            attribute.to_owned(),
            String::new(),
            format!("+ {}", describe_ace(a, Some(names))),
        )
    }));
    if (old.owner, old.group) != (new.owner, new.group) {
        lines.push((attribute.to_owned(), tr("owner or group"), tr("modified")));
    }
    if lines.is_empty() {
        lines.push((attribute.to_owned(), tr("(unchanged)"), tr("(unchanged)")));
    }
    lines
}

fn registry_details(old: Option<&[u8]>, new: Option<&[u8]>) -> Option<Vec<Detail>> {
    let lines = registry_lines(old, new)?;
    let name = tr("registry");
    Some(
        lines
            .into_iter()
            .map(|x| {
                let rest: String = x.chars().skip(2).collect();
                if x.starts_with('−') {
                    (name.clone(), rest, String::new())
                } else {
                    (name.clone(), String::new(), rest)
                }
            })
            .collect(),
    )
}

fn sysvol_details(op: &Operation, names: &Names) -> Vec<Detail> {
    let sd = tr("permissions");
    match op {
        Operation::WriteFile {
            path,
            content,
            old,
            descriptor,
            ..
        } if is_registry_pol(path) => {
            if let Some(mut lines) = registry_details(old.as_deref(), Some(content)) {
                if old.is_none()
                    && let Some(d) = descriptor
                {
                    lines.extend(descriptor_details(&sd, None, d, names));
                }
                return lines;
            }
            write_file_details(content, old.as_deref(), descriptor.as_deref(), &sd, names)
        }
        Operation::DeleteFile { path, content, .. } if is_registry_pol(path) => {
            registry_details(Some(content), None).unwrap_or_else(|| {
                vec![(
                    tr("content"),
                    content_text(content, &AppCatalog),
                    tr("(deleted)"),
                )]
            })
        }
        Operation::CreateFolder { descriptor, .. } => descriptor
            .as_ref()
            .map(|d| descriptor_details(&sd, None, d, names))
            .unwrap_or_default(),
        Operation::DeleteFolder { path, .. } => vec![(tr("folder"), path.clone(), tr("(deleted)"))],
        Operation::WriteFile {
            content,
            old,
            descriptor,
            ..
        } => write_file_details(content, old.as_deref(), descriptor.as_deref(), &sd, names),
        Operation::DeleteFile { content, .. } => {
            vec![(
                tr("content"),
                content_text(content, &AppCatalog),
                tr("(deleted)"),
            )]
        }
        Operation::SetDescriptor { before, after, .. } => {
            descriptor_details(&sd, Some(before), after, names)
        }
        _ => Vec::new(),
    }
}

fn write_file_details(
    content: &[u8],
    old: Option<&[u8]>,
    descriptor: Option<&[u8]>,
    sd: &str,
    names: &Names,
) -> Vec<Detail> {
    match old {
        None => {
            let mut lines = vec![(
                tr("content"),
                String::new(),
                content_text(content, &AppCatalog),
            )];
            if let Some(d) = descriptor {
                lines.extend(descriptor_details(sd, None, d, names));
            }
            lines
        }
        Some(old) => vec![(
            tr("content"),
            content_text(old, &AppCatalog),
            content_text(content, &AppCatalog),
        )],
    }
}

fn dns_type(v: &[u8]) -> i64 {
    match (v.get(2), v.get(3)) {
        (Some(&a), Some(&b)) => i64::from(u16::from_le_bytes([a, b])),
        _ => -1,
    }
}

/// DNS records: one value removed and one added of the same type make a row before → after;
/// the others are shown alone (`_details_dns`).
fn dns_details(attribute: &str, removed: &[Vec<u8>], added: &[Vec<u8>]) -> Vec<Detail> {
    let mut left: Vec<&Vec<u8>> = added.iter().collect();
    let mut lines = Vec::new();
    let mut alone = Vec::new();
    for v in removed {
        match left.iter().position(|a| dns_type(a) == dns_type(v)) {
            None => alone.push((
                attribute.to_owned(),
                format!("− {}", value(attribute, v)),
                String::new(),
            )),
            Some(p) => {
                let pair = left.remove(p);
                lines.push((
                    attribute.to_owned(),
                    value(attribute, v),
                    value(attribute, pair),
                ));
            }
        }
    }
    alone.extend(left.iter().map(|v| {
        (
            attribute.to_owned(),
            String::new(),
            format!("+ {}", value(attribute, v)),
        )
    }));
    lines.extend(alone);
    lines
}

fn details(op: &Operation, names: &Names) -> Vec<Detail> {
    match op {
        Operation::Add { attributes, .. } => {
            let mut lines = Vec::new();
            for (a, values) in attributes {
                for v in values {
                    if a.eq_ignore_ascii_case("ntsecuritydescriptor") {
                        lines.extend(descriptor_details(a, None, v, names));
                    } else {
                        lines.push((a.clone(), String::new(), value(a, v)));
                    }
                }
            }
            lines
        }
        Operation::Modify { changes, .. } => {
            let mut lines = Vec::new();
            for c in changes {
                let lower = c.attribute.to_lowercase();
                if lower == "ntsecuritydescriptor"
                    && let (Some(before), Some(after)) = (c.removed.first(), c.added.first())
                {
                    lines.extend(descriptor_details(&c.attribute, Some(before), after, names));
                    continue;
                }
                if lower == "dnsrecord" {
                    lines.extend(dns_details(&c.attribute, &c.removed, &c.added));
                    continue;
                }
                if let ([before], [after]) = (c.removed.as_slice(), c.added.as_slice()) {
                    lines.push((
                        c.attribute.clone(),
                        value(&c.attribute, before),
                        value(&c.attribute, after),
                    ));
                    continue;
                }
                lines.extend(c.removed.iter().map(|v| {
                    (
                        c.attribute.clone(),
                        format!("− {}", value(&c.attribute, v)),
                        String::new(),
                    )
                }));
                lines.extend(c.added.iter().map(|v| {
                    (
                        c.attribute.clone(),
                        String::new(),
                        format!("+ {}", value(&c.attribute, v)),
                    )
                }));
            }
            lines
        }
        Operation::Rename {
            dn: old,
            rdn: new,
            parent,
            ..
        } => {
            let mut lines = Vec::new();
            if !same_rdn(old, new) {
                let new_dn = op.dn_after().unwrap_or_default();
                lines.push((tr("name (RDN)"), rdn(old), rdn(&new_dn)));
            }
            if let Some(parent) = parent {
                lines.push((
                    tr("location"),
                    parent_dn(old).unwrap_or_default(),
                    parent.clone(),
                ));
            }
            lines
        }
        Operation::Delete { dn, .. } => vec![(tr("object"), dn.clone(), tr("(deleted)"))],
        _ => sysvol_details(op, names),
    }
}

fn descriptors(op: &Operation) -> Vec<&[u8]> {
    match op {
        Operation::CreateFolder {
            descriptor: Some(d),
            ..
        }
        | Operation::WriteFile {
            descriptor: Some(d),
            ..
        } => vec![d],
        Operation::SetDescriptor { before, after, .. } => vec![before, after],
        Operation::Add { attributes, .. } => attributes
            .iter()
            .filter(|(a, _)| a.eq_ignore_ascii_case("ntsecuritydescriptor"))
            .flat_map(|(_, v)| v.iter().map(Vec::as_slice))
            .collect(),
        Operation::Modify { changes, .. } => changes
            .iter()
            .filter(|c| c.attribute.eq_ignore_ascii_case("ntsecuritydescriptor"))
            .flat_map(|c| c.removed.iter().chain(c.added.iter()).map(Vec::as_slice))
            .collect(),
        _ => Vec::new(),
    }
}

/// SIDs of the ACEs of the descriptors of the changeset, and those their conditions quote
/// (`sids_cites`).
pub fn quoted_sids(changeset: &Changeset) -> HashSet<Sid> {
    let mut sids = HashSet::new();
    for op in &changeset.operations {
        for raw in descriptors(op) {
            let Ok(sd) = SecurityDescriptor::decode(raw) else {
                continue;
            };
            for acl in [&sd.dacl, &sd.sacl].into_iter().flatten() {
                for ace in &acl.aces {
                    sids.extend(security::ace_sids(ace));
                }
            }
        }
    }
    sids
}

/// The table of the preview: one or more rows per operation, in order (`lignes_apercu`).
pub fn lines(changeset: &Changeset, names: Option<&Names>) -> Vec<PreviewLine> {
    let empty = Names::new();
    let names = names.unwrap_or(&empty);
    let mut out = Vec::new();
    for op in &changeset.operations {
        let mut found = details(op, names);
        if found.is_empty() {
            found.push(Default::default());
        }
        for (rank, (attribute, before, after)) in found.into_iter().enumerate() {
            let first = rank == 0;
            out.push(PreviewLine {
                object: if !first {
                    String::new()
                } else if op.is_sysvol() {
                    sysvol_path(op.path().unwrap_or_default())
                } else {
                    op.dn().to_owned()
                },
                action: if first { action(op) } else { String::new() },
                attribute,
                before,
                after,
            });
        }
    }
    out
}

/// One sentence: how many objects and operations (`resume`).
pub fn summary(changeset: &Changeset) -> String {
    let n = changeset.operations.len();
    let objects: HashSet<String> = changeset
        .operations
        .iter()
        .map(|o| o.dn().to_lowercase())
        .collect();
    fill(
        &tr_n(
            "{n} operation on {objets} object(s).",
            "{n} operations on {objets} object(s).",
            n as u64,
        ),
        &[
            ("n", &n.to_string()),
            ("objets", &objects.len().to_string()),
        ],
    )
}

fn read_of(op: &Operation) -> Option<bool> {
    match op {
        Operation::Modify { read, .. }
        | Operation::Rename { read, .. }
        | Operation::Delete { read, .. } => Some(read.is_some()),
        _ => None,
    }
}

/// What must be known before confirming: irreversible deletions, remarks (`avertissements`).
pub fn warnings(changeset: &Changeset) -> Vec<String> {
    let mut texts = Vec::new();
    if changeset
        .operations
        .iter()
        .any(|o| matches!(o, Operation::Delete { .. }))
    {
        texts.push(tr(
            "A deletion cannot be undone exactly: undoing recreates a new object (new objectGUID and objectSid, password and permissions not restored).",
        ));
    }
    if changeset
        .operations
        .iter()
        .any(|o| read_of(o) == Some(false))
    {
        texts.push(tr(
            "Some operations have no version check (object created in the meantime?).",
        ));
    }
    texts.extend(changeset.remarks.iter().cloned());
    texts
}

/// A problem of the prior verification, with the number of the operation (`texte_probleme`).
pub fn problem_text(problem: &Problem) -> String {
    fill(
        &tr("Operation {k} ({dn}): {message}"),
        &[
            ("k", &(problem.index + 1).to_string()),
            ("dn", &problem.dn),
            ("message", &problem.message),
        ],
    )
}

fn sysvol_title(op: &Operation) -> String {
    let path = format!("SYSVOL\\{}", op.path().unwrap_or_default());
    let template = match op {
        Operation::CreateFolder { .. } => tr("creation of folder {c}"),
        Operation::DeleteFolder { .. } => tr("deletion of folder {c}"),
        Operation::WriteFile { .. } => tr("writing of file {c}"),
        Operation::DeleteFile { .. } => tr("deletion of file {c}"),
        _ => tr("permissions of {c}"),
    };
    fill(&template, &[("c", &path)])
}

/// `_titre`.
fn title(op: &Operation) -> String {
    match op {
        Operation::Add { dn, .. } => fill(&tr("creation of {dn}"), &[("dn", dn)]),
        Operation::Modify { dn, .. } => fill(&tr("modification of {dn}"), &[("dn", dn)]),
        Operation::Rename { dn, .. } => fill(
            &tr("renaming of {dn} to {nouveau}"),
            &[("dn", dn), ("nouveau", &op.dn_after().unwrap_or_default())],
        ),
        Operation::Delete { dn, .. } => fill(&tr("deletion of {dn}"), &[("dn", dn)]),
        _ => sysvol_title(op),
    }
}

/// What to tell the user of the result, in clear (never a silent failure) (`decrire`).
pub fn describe(report: &Report, problems: &[Problem]) -> String {
    let n = report.changeset.operations.len();
    let mut lines: Vec<String> = Vec::new();
    match report.issue {
        Issue::Applied => {
            return fill(&tr("{n} operation(s) applied."), &[("n", &n.to_string())]);
        }
        Issue::Refused => {
            lines.push(
                report
                    .error
                    .as_ref()
                    .map_or_else(|| tr("Changeset refused."), |e| e.message.clone()),
            );
            if report
                .error
                .as_ref()
                .is_some_and(|e| e.class == "ErreurPrealable")
            {
                lines.extend(
                    problems
                        .iter()
                        .map(|p| format!("  - {}. {}", p.index + 1, p.message)),
                );
            }
            return lines.join("\n");
        }
        Issue::Interrupted => lines.push(fill(
            &tr("Application interrupted (abrupt stop) after {k} of {n} operation(s). The directory may be in an intermediate state: undo or complete it."),
            &[("k", &report.applied.len().to_string()), ("n", &n.to_string())],
        )),
        _ => {
            if let Some(error) = &report.error {
                lines.push(fill(
                    &tr("Failed at operation {k} of {n}: {message}"),
                    &[
                        ("k", &(report.applied.len() + 1).to_string()),
                        ("n", &n.to_string()),
                        ("message", &error.message),
                    ],
                ));
            }
        }
    }
    if report.issue == Issue::Cancelled {
        lines.push(fill(
            &tr("The {k} operation(s) already performed have been undone: the directory is back to its previous state."),
            &[("k", &report.applied.len().to_string())],
        ));
    }
    if let Some(error) = &report.rollback_error {
        lines.push(fill(
            &tr("Rollback failed: {message} Another administrator may have modified an object in the meantime."),
            &[("message", &error.message)],
        ));
    }
    let remaining: Vec<&Applied> = report
        .remaining_indices()
        .into_iter()
        .filter_map(|i| report.applied.get(i))
        .collect();
    if matches!(report.issue, Issue::Incomplete | Issue::Interrupted) && !remaining.is_empty() {
        lines.push(tr("Still applied:"));
        lines.extend(
            remaining
                .iter()
                .map(|a| format!("  - {}", title(&a.operation))),
        );
    }
    for doubtful in [&report.doubtful, &report.doubtful_rollback]
        .into_iter()
        .flatten()
    {
        lines.push(fill(
            &tr("Uncertain effect, to be checked in the directory: {op}."),
            &[("op", &title(&doubtful.operation))],
        ));
    }
    lines.join("\n")
}

/// The inverse of what a report left applied, to undo it; `journal`: the later applications,
/// whose versions the inverse expects (ADR 0006 § 5.1) (`inverse`).
pub fn inverse(report: &Report, journal: &[Report]) -> Option<Changeset> {
    changes::inverse(report, journal, &AppCatalog).ok()
}

/// Short title: the action and the object if there is only one, else the actions counted
/// (`titre_changeset`).
pub fn changeset_title(changeset: &Changeset) -> String {
    let ops = &changeset.operations;
    let Some(first) = ops.first() else {
        return tr("No change");
    };
    let objects: HashSet<String> = ops.iter().map(|o| o.dn().to_lowercase()).collect();
    if objects.len() == 1 {
        let mut actions: Vec<String> = Vec::new();
        for a in ops.iter().map(action) {
            if !actions.contains(&a) {
                actions.push(a);
            }
        }
        let name = dn::split(first.dn())
            .ok()
            .and_then(|c| c.first().map(|c| c.value.clone()))
            .unwrap_or_else(|| first.dn().to_owned());
        return fill(
            &tr("{actions}: {nom}"),
            &[("actions", &actions.join(", ")), ("nom", &name)],
        );
    }
    let mut counts: Vec<(String, usize)> = Vec::new();
    for a in ops.iter().map(action) {
        match counts.iter_mut().find(|(k, _)| *k == a) {
            Some((_, n)) => *n += 1,
            None => counts.push((a, 1)),
        }
    }
    counts
        .iter()
        .map(|(a, n)| format!("{a} ({n})"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// An application of the journal, as the history shows it (`EntreeHistorique`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub id: String,
    pub title: String,
    pub subtitle: String,
    pub detail: String,
    /// Something stays applied and no application resumed it yet.
    pub undoable: bool,
}

fn issue_label(issue: Issue) -> String {
    match issue {
        Issue::Applied => tr("Applied"),
        Issue::Refused => tr("Refused"),
        Issue::Cancelled => tr("Failed, undone"),
        Issue::Incomplete => tr("Incomplete"),
        Issue::Interrupted => tr("Interrupted"),
    }
}

/// The applications of the journal for this domain, from the most recent to the oldest
/// (`entrees_historique`).
pub fn history_entries(reports: &[Report], domain: &str) -> Vec<HistoryEntry> {
    reports
        .iter()
        .rev()
        .filter(|r| r.domain == domain)
        .map(|report| {
            let when = gtk::glib::DateTime::from_iso8601(&report.timestamp, None)
                .ok()
                .map(|d| crate::views::format_unix(d.to_unix()))
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| report.timestamp.clone());
            let mut state = issue_label(report.issue);
            if report.resumed_by.is_some() {
                state = fill(&tr("{etat}, undone or resumed since"), &[("etat", &state)]);
            } else if report.resumes.is_some() {
                state = fill(&tr("{etat} (undo or resume)"), &[("etat", &state)]);
            }
            let user = report
                .user
                .strip_prefix("u:")
                .unwrap_or(&report.user)
                .to_owned();
            let subtitle = [when, state, user, report.dc.clone()]
                .into_iter()
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
            let mut detail = changes::preview(&report.changeset, &AppCatalog).unwrap_or_default();
            if report.issue != Issue::Applied {
                detail = format!("{}\n\n{detail}", describe(report, &[]));
            }
            HistoryEntry {
                id: report.id.clone(),
                title: changeset_title(&report.changeset),
                subtitle,
                detail,
                undoable: !report.remaining_indices().is_empty() && report.resumed_by.is_none(),
            }
        })
        .collect()
}

/// The change that Ctrl+Z undoes: the most recent of the domain of which something stays
/// applied, that no application resumed, and that is not itself an undo or a resume. Two
/// Ctrl+Z thus undo the last two changes, instead of restoring the first; the history can undo
/// an undo (`derniere_annulable`).
pub fn last_undoable<'a>(reports: &'a [Report], domain: &str) -> Option<&'a Report> {
    reports.iter().rev().find(|r| {
        r.domain == domain
            && r.resumes.is_none()
            && r.resumed_by.is_none()
            && !r.remaining_indices().is_empty()
    })
}

#[cfg(test)]
mod tests {
    use annuaire_core::changes::{Change, Read};

    use super::*;

    #[test]
    fn rows_of_a_modification() {
        let op = Operation::modify(
            "CN=a,DC=x",
            vec![
                Change::new("description", vec![b"old".to_vec()], vec![b"new".to_vec()]).unwrap(),
                Change::new(
                    "otherTelephone",
                    Vec::new(),
                    vec![b"1".to_vec(), b"2".to_vec()],
                )
                .unwrap(),
            ],
            Some(Read {
                dc: "dc1".into(),
                usn: 4,
            }),
        )
        .unwrap();
        let changeset = Changeset {
            operations: vec![op],
            remarks: Vec::new(),
        };
        let rows = lines(&changeset, None);
        let [first, second, third] = rows.as_slice() else {
            panic!("three rows expected");
        };
        assert_eq!(first.object, "CN=a,DC=x");
        assert_eq!(first.action, "Modification");
        assert_eq!(second.object, "");
        assert!(third.after.starts_with("+ "));
        assert_eq!(summary(&changeset), "1 operation on 1 object(s).");
        assert!(warnings(&changeset).is_empty());
    }
}

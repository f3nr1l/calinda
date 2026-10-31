// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the « Deleted Objects » window (J9.1, ADR 0024): what the forest does of a
//! deletion, a row of the list, what a deleted object kept, why it cannot come back, what
//! prevents a restoration.

use annuaire_core::changes::show_value;
use annuaire_core::recycle::{Bin, DeletedObject, Kind, Problem, Unrestorable};

use crate::catalog::AppCatalog;
use crate::i18n::{fill, tr, tr_n};
use crate::sheet_views::date_text;

/// The kinds offered by the filter, in its order (the first: every kind).
pub const KINDS: [Option<Kind>; 7] = [
    None,
    Some(Kind::User),
    Some(Kind::Group),
    Some(Kind::Computer),
    Some(Kind::Unit),
    Some(Kind::Contact),
    Some(Kind::Other),
];

pub fn kind_label(kind: Option<Kind>) -> String {
    match kind {
        None => tr("All kinds"),
        Some(Kind::User) => tr("Users"),
        Some(Kind::Group) => tr("Groups"),
        Some(Kind::Computer) => tr("Computers"),
        Some(Kind::Unit) => tr("Organizational units"),
        Some(Kind::Contact) => tr("Contacts"),
        Some(Kind::Other) => tr("Other objects"),
    }
}

/// The periods offered by the filter, in days (the first: any date).
pub const PERIODS: [Option<i64>; 4] = [None, Some(1), Some(7), Some(30)];

pub fn period_label(days: Option<i64>) -> String {
    match days {
        None => tr("Any date"),
        Some(1) => tr("Last 24 hours"),
        Some(n) => fill(&tr("Last {n} days"), &[("n", &n.to_string())]),
    }
}

/// What the forest does of a deletion: the banner of the window.
pub fn state_text(bin: &Bin) -> String {
    let tombstone = bin.tombstone_days.unwrap_or(180).to_string();
    if bin.enabled && bin.samba {
        tr(
            "The Recycle Bin is enabled, but Samba cannot restore an object deleted since then: its reanimation is refused by the domain controller.",
        )
    } else if bin.enabled {
        let deleted = bin
            .deleted_days
            .or(bin.tombstone_days)
            .unwrap_or(180)
            .to_string();
        fill(
            &tr(
                "The Recycle Bin is enabled: a deleted object keeps its attributes, its links and its password for {jours} days, then it is recycled and can no longer be restored.",
            ),
            &[("jours", &deleted)],
        )
    } else {
        fill(
            &tr(
                "The Recycle Bin is not enabled: a deleted object keeps only a few attributes (its account name and its SID, among others) for {jours} days. Restored, an account comes back without its password, its groups and its other attributes.",
            ),
            &[("jours", &tombstone)],
        )
    }
}

/// The name of the class, as the list shows it.
fn class_label(object: &DeletedObject) -> String {
    match object.kind() {
        Kind::User => tr("User"),
        Kind::Group => tr("Group"),
        Kind::Computer => tr("Computer"),
        Kind::Unit => tr("Organizational unit"),
        Kind::Contact => tr("Contact"),
        Kind::Other => object.class.clone(),
    }
}

/// The last known parent: its name if deleted too, its DN otherwise.
pub fn parent_text(bin: &Bin, object: &DeletedObject) -> String {
    match (object.parent_guid.and_then(|g| bin.get(&g)), &object.parent) {
        (Some(parent), _) => fill(&tr("{nom} (deleted)"), &[("nom", &parent.name)]),
        (None, Some(dn)) => dn.clone(),
        (None, None) => tr("unknown"),
    }
}

/// Subtitle of a row: class, date of the deletion, last known parent.
pub fn row_subtitle(bin: &Bin, object: &DeletedObject) -> String {
    fill(
        &tr("{classe} · deleted {date} · from {parent}"),
        &[
            ("classe", &class_label(object)),
            ("date", &date_text(object.deleted)),
            ("parent", &parent_text(bin, object)),
        ],
    )
}

pub fn unrestorable_text(why: Unrestorable) -> String {
    match why {
        Unrestorable::Recycled => tr("Recycled: it can no longer be restored."),
        Unrestorable::SambaRecycleBin => {
            tr("Samba cannot restore it while the Recycle Bin is enabled.")
        }
    }
}

/// What the object kept, one attribute per line, its values as the preview shows them.
pub fn kept_text(object: &DeletedObject) -> String {
    let mut lines: Vec<String> = object
        .attributes
        .iter()
        .map(|(attribute, values)| {
            let shown: Vec<String> = values
                .iter()
                .take(5)
                .map(|v| show_value(attribute, v, &AppCatalog).unwrap_or_default())
                .collect();
            let more = values.len().saturating_sub(5);
            let mut line = format!("{attribute}: {}", shown.join(", "));
            if more > 0 {
                line.push_str(&fill(&tr(" and {k} more"), &[("k", &more.to_string())]));
            }
            line
        })
        .collect();
    lines.sort_by_key(|l| l.to_lowercase());
    lines.join("\n")
}

/// The count under the list.
pub fn count_text(shown: usize, matching: usize, total: usize) -> String {
    if shown < matching {
        fill(
            &tr("{montres} shown of {n} matching ({total} deleted objects): refine the filter."),
            &[
                ("montres", &shown.to_string()),
                ("n", &matching.to_string()),
                ("total", &total.to_string()),
            ],
        )
    } else {
        fill(
            &tr_n(
                "{n} object of {total}",
                "{n} objects of {total}",
                matching as u64,
            ),
            &[("n", &matching.to_string()), ("total", &total.to_string())],
        )
    }
}

/// What prevents a restoration, in a sentence.
pub fn problem_text(problem: &Problem) -> String {
    match problem {
        Problem::Unrestorable { name, why } => fill(
            &tr("“{nom}”: {raison}"),
            &[("nom", name), ("raison", &unrestorable_text(*why))],
        ),
        Problem::ParentUnrestorable { name, parent } => fill(
            &tr(
                "“{nom}”: its last parent, “{parent}”, is deleted and can no longer be restored; choose another container.",
            ),
            &[("nom", name), ("parent", parent)],
        ),
        Problem::NoParent { name } => fill(
            &tr("“{nom}”: no last known parent; choose a container."),
            &[("nom", name)],
        ),
        Problem::ParentMissing { name, parent } => fill(
            &tr("“{nom}”: the container {parent} does not exist."),
            &[("nom", name), ("parent", parent)],
        ),
        Problem::NameTaken { dn, free } => fill(
            &tr("{dn} exists already. Free name: {libre}."),
            &[("dn", dn), ("libre", free)],
        ),
        Problem::AccountNameTaken {
            name,
            account,
            holder,
        } => fill(
            &tr(
                "“{nom}”: the account name {compte} is used by {titulaire}; rename or delete that account first.",
            ),
            &[("nom", name), ("compte", account), ("titulaire", holder)],
        ),
        Problem::Invalid(text) => text.clone(),
    }
}

/// The name of a free DN, for the field « Name ».
pub fn free_name(free: &str) -> String {
    annuaire_core::dn::split(free)
        .ok()
        .and_then(|c| c.into_iter().next())
        .map(|c| c.value)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_name_of_a_dn() {
        assert_eq!(free_name("CN=rc-pc (2),OU=A,DC=lab,DC=test"), "rc-pc (2)");
        assert_eq!(free_name("CN=Dupont\\, Jean (2),DC=x"), "Dupont, Jean (2)");
    }

    #[test]
    fn counts() {
        assert!(count_text(500, 4000, 4400).contains("refine"));
        assert!(count_text(3, 3, 4400).contains("4400"));
    }
}

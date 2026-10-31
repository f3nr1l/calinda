// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the import, of the export and of the changes in bulk (J9.8, J9.9, ADR 0026),
//! without GTK widgets: the report of a line of the file, the row of an object in the preview,
//! what the progress and the end of a series say, the labels of the attributes the import
//! recognises (those of the sheet, in English and in the language of the interface).

use std::collections::HashMap;

use annuaire_codecs::time;
use annuaire_core::bulk::Batch;
use annuaire_core::dn;
use annuaire_core::home_folder::Refusal;
use annuaire_core::import::{self, Kind, Line, Note, Problem, Unique};
use annuaire_core::mass::{Change, Row};
use gtk::glib;

use crate::account_views as av;
use crate::i18n::{fill, tr, tr_marked, tr_n};
use crate::preview_views::PreviewLine;

/// Marks a message of a table for `xgettext` (keyword `N_` of the GLib preset); translated
/// when shown (`tr_marked`).
#[allow(non_snake_case)]
const fn N_(text: &'static str) -> &'static str {
    text
}

/// Attributes of the sheet and their labels there (`fiche.blp`): the import recognises a
/// column by these, in English or translated.
pub const LABELS: [(&str, &str); 26] = [
    ("description", N_("Description")),
    ("givenName", N_("First name")),
    ("initials", N_("Initials")),
    ("displayName", N_("Display name")),
    ("physicalDeliveryOfficeName", N_("Office")),
    ("mail", N_("Email")),
    ("telephoneNumber", N_("Telephone")),
    ("mobile", N_("Mobile")),
    ("wWWHomePage", N_("Web page")),
    ("streetAddress", N_("Address")),
    ("postalCode", N_("ZIP/Postal code")),
    ("l", N_("City")),
    ("st", N_("State/province")),
    ("title", N_("Job title")),
    ("department", N_("Department")),
    ("company", N_("Company")),
    ("info", N_("Notes")),
    ("dNSHostName", N_("DNS name")),
    ("location", N_("Physical location")),
    ("userPrincipalName", N_("User logon name (UPN)")),
    ("sAMAccountName", N_("Logon name (pre-Windows 2000)")),
    ("profilePath", N_("Profile path")),
    ("scriptPath", N_("Logon script")),
    ("homeDrive", N_("Home folder drive")),
    ("homeDirectory", N_("Home folder")),
    ("sn", N_("Last name")),
];

/// Label in lower case → LDAP name, in English and translated.
pub fn labels() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for (attribute, label) in LABELS {
        map.insert(label.to_lowercase(), attribute.to_owned());
        map.insert(tr_marked(label).to_lowercase(), attribute.to_owned());
    }
    map
}

pub fn kind_label(kind: Kind) -> String {
    match kind {
        Kind::User => tr("User"),
        Kind::Group => tr("Group"),
        Kind::Contact => tr("Contact"),
        Kind::Computer => tr("Computer"),
    }
}

fn unique_label(what: Unique) -> String {
    match what {
        Unique::Dn => tr("the distinguished name"),
        Unique::Identifier => tr("the logon name (sAMAccountName)"),
        Unique::Upn => tr("the user logon name (UPN)"),
    }
}

fn folder_refusal(refusal: &Refusal) -> String {
    match refusal {
        Refusal::ShareMissing => tr("the share does not exist"),
        Refusal::ParentMissing { parent } => fill(
            &tr("the folder “{dossier}” does not exist"),
            &[("dossier", parent)],
        ),
        Refusal::NotAFolder => tr("a file has the name of the folder"),
    }
}

/// What is wrong with a line of the file.
pub fn problem(p: &Problem) -> String {
    match p {
        Problem::UnknownKind(kind) => fill(
            &tr("unknown type “{type}”: user, group, contact or computer"),
            &[("type", kind)],
        ),
        Problem::NoName => tr("no name"),
        Problem::NoIdentifier => tr("no logon name (sAMAccountName)"),
        Problem::Action(e) => av::action_error(e),
        Problem::InvalidPath(path) => fill(&tr("invalid container “{dn}”"), &[("dn", path)]),
        Problem::PathMissing(path) => {
            fill(&tr("the container “{dn}” does not exist"), &[("dn", path)])
        }
        Problem::UnknownColumn(name) => fill(
            &tr("column “{colonne}”: unknown to the import and to the schema"),
            &[("colonne", name)],
        ),
        Problem::NotWritable(a) => fill(
            &tr("{attribut} is written by the domain controller, not by an import"),
            &[("attribut", a)],
        ),
        Problem::NotAllowed { attribute, class } => fill(
            &tr("the class {classe} does not allow {attribut}"),
            &[("classe", class), ("attribut", attribute)],
        ),
        Problem::Value { attribute, message } => fill(
            &tr("{attribut}: {message}"),
            &[("attribut", attribute), ("message", message)],
        ),
        Problem::SeveralValues(a) => {
            fill(&tr("{attribut} takes a single value"), &[("attribut", a)])
        }
        Problem::NotForKind(column) => fill(
            &tr("the column {colonne} is for groups only"),
            &[("colonne", column)],
        ),
        Problem::InvalidFlag { column, value } => fill(
            &tr("“{valeur}” is not a value of {colonne}"),
            &[("valeur", value), ("colonne", column)],
        ),
        Problem::DuplicateInFile { what, value, line } => fill(
            &tr("{quoi} “{valeur}” is already on line {ligne}"),
            &[
                ("quoi", &unique_label(*what)),
                ("valeur", value),
                ("ligne", &line.to_string()),
            ],
        ),
        Problem::InDirectory { what, value, dn } => fill(
            &tr("{quoi} “{valeur}” is already used by {dn}"),
            &[
                ("quoi", &unique_label(*what)),
                ("valeur", value),
                ("dn", dn),
            ],
        ),
        Problem::GroupMissing(group) => fill(
            &tr("the group “{groupe}” does not exist"),
            &[("groupe", group)],
        ),
        Problem::NoPassword => tr("an enabled account requires an initial password"),
        Problem::PasswordTooShort { minimum } => fill(
            &tr("the password is shorter than the {n} characters of the domain policy"),
            &[("n", &minimum.to_string())],
        ),
        Problem::PasswordNotComplex => tr(
            "the password does not meet the complexity of the domain (three kinds of characters, not the logon name)",
        ),
        Problem::HomeFolder { unc, refusal } => fill(
            &tr("home folder {chemin}: {raison}"),
            &[("chemin", unc), ("raison", &folder_refusal(refusal))],
        ),
        Problem::HomeFolderServer { server, message } => fill(
            &tr("the file server {serveur} cannot be read: {message}"),
            &[("serveur", server), ("message", message)],
        ),
    }
}

pub fn note(n: &Note) -> String {
    match n {
        Note::PasswordGenerated => tr("password generated"),
        Note::HomeFolderExists(unc) => fill(
            &tr("home folder {chemin} already there, left as it is"),
            &[("chemin", unc)],
        ),
        Note::HomeFolderCreated(unc) => {
            fill(&tr("home folder {chemin} created"), &[("chemin", unc)])
        }
    }
}

/// A line of the report of the import, as a row of the preview table.
pub fn line_view(line: &Line) -> PreviewLine {
    let refused = !line.problems.is_empty();
    let details: Vec<String> = if refused {
        line.problems.iter().map(problem).collect()
    } else {
        line.notes.iter().map(note).collect()
    };
    PreviewLine {
        object: fill(
            &tr("Line {n}: {nom}"),
            &[("n", &line.line.to_string()), ("nom", &line.name)],
        ),
        action: if refused {
            tr("refused")
        } else {
            tr("to create")
        },
        attribute: line.kind.map(kind_label).unwrap_or_default(),
        before: line.dn.clone(),
        after: details.join(" ; "),
    }
}

/// The summary of the check of a file.
pub fn check_summary(lines: usize, items: usize, refused: usize, generated: usize) -> String {
    let mut text = fill(
        &tr_n(
            "{n} line read: {ok} to import, {refus} refused.",
            "{n} lines read: {ok} to import, {refus} refused.",
            lines as u64,
        ),
        &[
            ("n", &lines.to_string()),
            ("ok", &items.to_string()),
            ("refus", &refused.to_string()),
        ],
    );
    if generated > 0 {
        text.push(' ');
        text.push_str(&fill(
            &tr_n(
                "{n} password generated: the file of the passwords is written before the import.",
                "{n} passwords generated: the file of the passwords is written before the import.",
                generated as u64,
            ),
            &[("n", &generated.to_string())],
        ));
    }
    text
}

/// Why a file cannot be checked.
pub fn import_error(error: &import::ImportError, domain: &str) -> String {
    match error {
        import::ImportError::Csv(e) => match e {
            annuaire_codecs::csv::CsvError::NotUtf8 { offset } => fill(
                &tr(
                    "The file is not in UTF-8 (byte {n}). Save it as “CSV UTF-8” from the spreadsheet.",
                ),
                &[("n", &offset.to_string())],
            ),
            annuaire_codecs::csv::CsvError::UnclosedQuote { line } => fill(
                &tr("A quote opened on line {n} is never closed."),
                &[("n", &line.to_string())],
            ),
            annuaire_codecs::csv::CsvError::AfterQuote { line } => fill(
                &tr("Text after a closing quote on line {n}."),
                &[("n", &line.to_string())],
            ),
        },
        import::ImportError::Empty => tr("The file has no line after its header."),
        import::ImportError::Failure(f) => crate::errors::failure_problem(f, domain).message,
    }
}

// --- Series ------------------------------------------------------------------------------

/// The local date of a time read in the directory, as the attribute editor reads it back.
pub fn local_date(utc: time::UtcTime) -> String {
    glib::DateTime::from_unix_local(utc.unix_seconds())
        .and_then(|d| d.format(&tr("%d/%m/%Y %H:%M:%S")))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// The summary of the batches of a series.
pub fn batches_summary(batches: &[Batch]) -> String {
    let objects: usize = batches.iter().map(|b| b.all_items().len()).sum();
    fill(
        &tr_n(
            "Written in {lots} batch of {taille} objects at most ({n} objects); each batch is applied all or nothing, and the series can be stopped between two batches.",
            "Written in {lots} batches of {taille} objects at most ({n} objects); each batch is applied all or nothing, and the series can be stopped between two batches.",
            batches.len() as u64,
        ),
        &[
            ("lots", &batches.len().to_string()),
            ("taille", &annuaire_core::bulk::BATCH_SIZE.to_string()),
            ("n", &objects.to_string()),
        ],
    )
}

/// The bar of progress.
pub fn progress_text(batch: usize, total: usize, written: usize) -> String {
    fill(
        &tr("Batch {lot} of {total}, {n} objects written"),
        &[
            ("lot", &batch.to_string()),
            ("total", &total.to_string()),
            ("n", &written.to_string()),
        ],
    )
}

/// The objects a refusal names, by their labels.
pub fn refused_text(labels: &[String]) -> String {
    fill(
        &tr_n(
            "Refused: {liste}",
            "Refused ({n}): {liste}",
            labels.len() as u64,
        ),
        &[
            ("n", &labels.len().to_string()),
            ("liste", &labels.join(" ; ")),
        ],
    )
}

// --- Changes of a selection (J9.9) ------------------------------------------------------

fn rdn(dn_text: &str) -> String {
    dn::split(dn_text)
        .ok()
        .and_then(|c| c.into_iter().next())
        .map_or_else(|| dn_text.to_owned(), |c| c.value)
}

fn parent(dn_text: &str) -> String {
    annuaire_core::changes::parent_dn(dn_text).unwrap_or_else(|_| dn_text.to_owned())
}

/// The values of `attribute` as the preview shows them.
pub fn values_text(attribute: &str, values: &[Vec<u8>]) -> String {
    let number = || {
        values
            .first()
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|t| t.trim().parse::<i64>().ok())
    };
    match attribute.to_lowercase().as_str() {
        "useraccountcontrol" => match number() {
            Some(n) if n & 2 != 0 => tr("disabled"),
            Some(_) => tr("enabled"),
            None => String::new(),
        },
        "accountexpires" => match number() {
            None | Some(0) => tr("never"),
            Some(n) if n == time::NTTIME_NEVER => tr("never"),
            Some(n) => time::nttime_to_utc(n)
                .ok()
                .flatten()
                .map(local_date)
                .unwrap_or_else(|| n.to_string()),
        },
        "pwdlastset" => match number() {
            Some(0) => tr("change required at the next logon"),
            Some(_) => tr("not required"),
            None => String::new(),
        },
        "memberof" => values
            .iter()
            .map(|v| rdn(&String::from_utf8_lossy(v)))
            .collect::<Vec<_>>()
            .join(" ; "),
        "distinguishedname" => values
            .first()
            .map(|v| parent(&String::from_utf8_lossy(v)))
            .unwrap_or_default(),
        _ => values
            .iter()
            .map(|v| {
                std::str::from_utf8(v)
                    .map(str::to_owned)
                    .unwrap_or_else(|_| annuaire_core::schema::hex(v))
            })
            .collect::<Vec<_>>()
            .join(" ; "),
    }
}

fn shown_attribute(attribute: &str) -> String {
    match attribute.to_lowercase().as_str() {
        "useraccountcontrol" => tr("State"),
        "accountexpires" => tr("Account expires"),
        "pwdlastset" => tr("Password change"),
        "memberof" => tr("Member Of"),
        "distinguishedname" => tr("Location"),
        _ => attribute.to_owned(),
    }
}

/// An object of the selection, as a row of the preview.
pub fn row_view(row: &Row) -> PreviewLine {
    PreviewLine {
        object: rdn(&row.dn),
        action: parent(&row.dn),
        attribute: shown_attribute(&row.attribute),
        before: values_text(&row.attribute, &row.before),
        after: values_text(&row.attribute, &row.after),
    }
}

/// What the dialog of the changes in bulk offers, in the order of its list.
pub const CHANGES: [&str; 12] = [
    "poser",
    "ajouter",
    "retirer",
    "vider",
    "rejoindre",
    "quitter",
    "activer",
    "desactiver",
    "deplacer",
    "expiration",
    "changer-mot-de-passe",
    "ne-plus-exiger",
];

pub fn change_labels() -> Vec<String> {
    vec![
        tr("Set an attribute"),
        tr("Add values to an attribute"),
        tr("Remove values from an attribute"),
        tr("Clear an attribute"),
        tr("Add to a group"),
        tr("Remove from a group"),
        tr("Enable the accounts"),
        tr("Disable the accounts"),
        tr("Move"),
        tr("Account expiration"),
        tr("User must change password at next logon"),
        tr("Password change not required at next logon"),
    ]
}

/// Which fields a change needs: (attribute, values, group, target container, date).
pub fn fields_of(change: &str) -> (bool, bool, bool, bool, bool) {
    match change {
        "poser" | "ajouter" | "retirer" => (true, true, false, false, false),
        "vider" => (true, false, false, false, false),
        "rejoindre" | "quitter" => (false, false, true, false, false),
        "deplacer" => (false, false, false, true, false),
        "expiration" => (false, false, false, false, true),
        _ => (false, false, false, false, false),
    }
}

/// The values typed for an attribute, separated by `|`.
pub fn split_values(text: &str) -> Vec<String> {
    text.split('|')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .collect()
}

/// The end of the day `DD/MM/YYYY` in local time, as ADUC sets `accountExpires` (the account
/// expires at the end of that day); None for an empty text (never). Err: not a date.
pub fn expiry(text: &str) -> Result<Option<i64>, String> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(None);
    }
    let parts: Vec<&str> = text.split('/').collect();
    let [d, m, y] = parts.as_slice() else {
        return Err(tr("Date expected: DD/MM/YYYY, or empty for never."));
    };
    let (Ok(d), Ok(m), Ok(y)) = (d.parse::<i32>(), m.parse::<i32>(), y.parse::<i32>()) else {
        return Err(tr("Date expected: DD/MM/YYYY, or empty for never."));
    };
    let next = glib::DateTime::new(&glib::TimeZone::local(), y, m, d, 0, 0, 0.0)
        .and_then(|day| day.add_days(1))
        .map_err(|_| tr("Impossible date."))?;
    time::unix_to_nttime(next.to_unix())
        .map(Some)
        .map_err(|_| tr("Impossible date."))
}

/// The summary of a planned change.
pub fn change_summary(changed: usize, unchanged: usize, not_accounts: usize) -> String {
    let mut parts = vec![fill(
        &tr_n(
            "{n} object will be changed.",
            "{n} objects will be changed.",
            changed as u64,
        ),
        &[("n", &changed.to_string())],
    )];
    if unchanged > 0 {
        parts.push(fill(
            &tr_n(
                "{n} object is already as asked: left aside.",
                "{n} objects are already as asked: left aside.",
                unchanged as u64,
            ),
            &[("n", &unchanged.to_string())],
        ));
    }
    if not_accounts > 0 {
        parts.push(fill(
            &tr_n(
                "{n} object is not an account: left aside.",
                "{n} objects are not accounts: left aside.",
                not_accounts as u64,
            ),
            &[("n", &not_accounts.to_string())],
        ));
    }
    parts.join(" ")
}

/// A change from the choice of the dialog; Err: the message to show.
#[allow(clippy::too_many_arguments)]
pub fn change_of(
    choice: &str,
    attribute: &str,
    values: Vec<Vec<u8>>,
    group: Option<(String, annuaire_core::changes::Read)>,
    target: &str,
    date: Option<i64>,
) -> Result<Change, String> {
    let attribute = attribute.trim().to_owned();
    let needs = fields_of(choice);
    if needs.0 && attribute.is_empty() {
        return Err(tr("Name the attribute."));
    }
    if needs.1 && values.is_empty() {
        return Err(tr("Give at least one value."));
    }
    Ok(match choice {
        "poser" => Change::Set { attribute, values },
        "ajouter" => Change::Add { attribute, values },
        "retirer" => Change::Remove { attribute, values },
        "vider" => Change::Clear { attribute },
        "rejoindre" | "quitter" => {
            let (group, read) = group.ok_or_else(|| tr("Choose the group."))?;
            Change::Group {
                group,
                read,
                join: choice == "rejoindre",
            }
        }
        "activer" => Change::Enable(true),
        "desactiver" => Change::Enable(false),
        "deplacer" => {
            if target.trim().is_empty() {
                return Err(tr("Give the destination container."));
            }
            Change::Move {
                parent: target.trim().to_owned(),
            }
        }
        "expiration" => Change::Expire(date),
        "changer-mot-de-passe" => Change::MustChange(true),
        _ => Change::MustChange(false),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_in_both_languages() {
        assert!(labels().contains_key("first name"));
        assert_eq!(
            labels().get("home folder").map(String::as_str),
            Some("homeDirectory")
        );
    }

    #[test]
    fn rows_of_the_preview() {
        let row = Row {
            dn: "CN=Élise Martin,OU=Paris,DC=lab,DC=test".into(),
            attribute: "userAccountControl".into(),
            before: vec![b"512".to_vec()],
            after: vec![b"514".to_vec()],
        };
        let view = row_view(&row);
        assert_eq!(view.object, "Élise Martin");
        assert_eq!(view.action, "OU=Paris,DC=lab,DC=test");
        assert_eq!(
            (view.before.as_str(), view.after.as_str()),
            ("enabled", "disabled")
        );
        assert_eq!(values_text("accountExpires", &[b"0".to_vec()]), "never");
        assert_eq!(
            values_text(
                "memberOf",
                &[b"CN=G1,DC=x".to_vec(), b"CN=G2,DC=x".to_vec()]
            ),
            "G1 ; G2"
        );
    }

    #[test]
    fn inputs_of_the_dialog() {
        assert_eq!(split_values(" a | b ||c "), vec!["a", "b", "c"]);
        assert_eq!(expiry(""), Ok(None));
        assert!(expiry("31/02/2026").is_err());
        assert!(expiry("lundi").is_err());
        assert!(expiry("31/12/2026").unwrap().is_some());
        assert!(change_of("poser", "", vec![], None, "", None).is_err());
        assert!(matches!(
            change_of("deplacer", "", vec![], None, "OU=X,DC=x", None),
            Ok(Change::Move { .. })
        ));
        assert_eq!(fields_of("vider"), (true, false, false, false, false));
        assert_eq!(CHANGES.len(), change_labels().len());
    }
}

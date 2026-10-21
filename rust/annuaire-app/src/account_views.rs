// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Logic of the dialogs of the actions on the accounts (J2.6, `annuaire.vue.comptes`), without
//! GTK: values proposed, input checks, texts of the confirmation; and the messages of the
//! errors of `annuaire_core::actions`.

use annuaire_core::actions::ActionError;
use annuaire_core::dn;
use annuaire_core::model::Kind;
use gtk::glib;
use gtk::glib::Unichar;

use crate::i18n::{fill, tr, tr_n};

pub const SAM_LENGTH: usize = 20;
const FORBIDDEN: &str = "\"/\\[]:;|=,+*?<>@";

fn forbidden(c: char) -> bool {
    c.is_whitespace() || FORBIDDEN.contains(c)
}

/// Without accents nor ligatures (`sans_accents`).
pub fn without_accents(text: &str) -> String {
    let translated: String = text
        .chars()
        .map(|c| match c {
            'œ' => "oe".to_owned(),
            'Œ' => "OE".to_owned(),
            'æ' => "ae".to_owned(),
            'Æ' => "AE".to_owned(),
            'ß' => "ss".to_owned(),
            other => other.to_string(),
        })
        .collect();
    glib::normalize(&translated, glib::NormalizeMode::All)
        .chars()
        .filter(|c| c.combining_class() == 0)
        .collect()
}

pub fn full_name(given: &str, surname: &str) -> String {
    [given.trim(), surname.trim()]
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `prenom.nom` in lower case, without accents nor forbidden characters, 20 characters at most
/// (`identifiant_propose`).
pub fn proposed_identifier(given: &str, surname: &str) -> String {
    let pieces: Vec<String> = [given, surname]
        .iter()
        .filter(|p| !p.trim().is_empty())
        .map(|p| {
            without_accents(p)
                .to_lowercase()
                .chars()
                .filter(|&c| !forbidden(c) && c.is_ascii())
                .collect::<String>()
        })
        .filter(|m| !m.is_empty())
        .collect();
    let joined: String = pieces.join(".").chars().take(SAM_LENGTH).collect();
    joined.trim_end_matches('.').to_owned()
}

pub fn proposed_upn(identifier: &str, domain: &str) -> String {
    if identifier.is_empty() {
        String::new()
    } else {
        format!("{identifier}@{domain}")
    }
}

pub fn identifier_problem(identifier: &str) -> Option<String> {
    if identifier.is_empty() {
        return Some(tr("The logon name is required."));
    }
    if identifier.chars().count() > SAM_LENGTH {
        return Some(fill(
            &tr("The logon name is longer than {n} characters."),
            &[("n", &SAM_LENGTH.to_string())],
        ));
    }
    if identifier.chars().any(forbidden) {
        return Some(tr(
            "The logon name contains a forbidden character (space or \" / \\ [ ] : ; | = , + * ? < > @).",
        ));
    }
    None
}

/// Local check; the policy of the domain is applied by the DC (`probleme_mot_de_passe`).
pub fn password_problem(password: &str, confirmation: &str, required: bool) -> Option<String> {
    if password.is_empty() && confirmation.is_empty() {
        return required.then(|| tr("An enabled account requires an initial password."));
    }
    (password != confirmation).then(|| tr("The two passwords differ."))
}

pub fn name_problem(name: &str) -> Option<String> {
    name.trim().is_empty().then(|| tr("The name is required."))
}

/// Readable location: the names from the nearest to the farthest, separated by « ‹ »
/// (`libelle_parent`).
pub fn parent_label(dn_text: &str) -> String {
    let names: Vec<String> = dn::split(dn_text)
        .unwrap_or_default()
        .into_iter()
        .filter(|c| {
            c.attribute.eq_ignore_ascii_case("OU") || c.attribute.eq_ignore_ascii_case("CN")
        })
        .map(|c| c.value)
        .collect();
    if names.is_empty() {
        dn_text.to_owned()
    } else {
        names.join(" ‹ ")
    }
}

pub fn can_protect(kinds: &[String]) -> bool {
    matches!(kinds, [only] if only == Kind::Ou.name())
}

/// Enable, disable, unlock, password: users and computers (`comptes_seulement`).
pub fn accounts_only(kinds: &[String]) -> bool {
    !kinds.is_empty()
        && kinds
            .iter()
            .all(|k| k == Kind::User.name() || k == Kind::Computer.name())
}

/// (title, body, text to type) of the reinforced confirmation of a deletion
/// (`confirmation_suppression`).
pub fn delete_confirmation(names: &[String]) -> (String, String, String) {
    let n = names.len();
    let (title, expected, instruction) = if n == 1 {
        let name = names.first().cloned().unwrap_or_default();
        (
            fill(&tr("Delete “{nom}”?"), &[("nom", &name)]),
            name,
            tr("Type the name of the object to confirm."),
        )
    } else {
        (
            fill(
                &tr_n("Delete {n} object?", "Delete {n} objects?", n as u64),
                &[("n", &n.to_string())],
            ),
            n.to_string(),
            fill(
                &tr("Type the number of objects ({n}) to confirm."),
                &[("n", &n.to_string())],
            ),
        )
    };
    let mut shown = names.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    if n > 5 {
        shown.push_str(&fill(&tr(" and {k} more"), &[("k", &(n - 5).to_string())]));
    }
    let body = [
        shown,
        tr("A deletion cannot be undone exactly: undoing recreates new objects (new SIDs and GUIDs; passwords and permissions lost)."),
        instruction,
    ]
    .join("\n\n");
    (title, body, expected)
}

/// Message of an action that cannot be built.
pub fn action_error(error: &ActionError) -> String {
    match error {
        ActionError::EmptyPassword => tr("empty password"),
        ActionError::EmptyName => tr("empty name"),
        ActionError::ActiveWithoutPassword => tr("an enabled account requires an initial password"),
        ActionError::InvalidIdentifier(i) => fill(
            &tr("invalid account name (sAMAccountName): {identifiant}"),
            &[("identifiant", &format!("'{i}'"))],
        ),
        ActionError::UnreadableDescriptor(dn) => {
            fill(&tr("unreadable security descriptor: {dn}"), &[("dn", dn)])
        }
        ActionError::NoUserAccountControl(dn) => {
            fill(&tr("no userAccountControl: {dn}"), &[("dn", dn)])
        }
        ActionError::UnderItself(dn) => {
            fill(&tr("“{dn}” cannot be moved under itself."), &[("dn", dn)])
        }
        ActionError::NoTemplate => tr("no delegation template chosen"),
        ActionError::InheritedRemoval => {
            tr("An inherited permission is removed on the object it is inherited from.")
        }
        ActionError::Change(text) => crate::codec_texts::codec_message(text),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposals() {
        assert_eq!(proposed_identifier("Léa", "Hervé"), "lea.herve");
        assert_eq!(
            proposed_identifier("Jean-Æric", "O'Neil Œuvre"),
            "jean-aeric.o'neiloeu"
        );
        assert_eq!(full_name(" Léa ", "Hervé"), "Léa Hervé");
        assert_eq!(proposed_upn("lea.herve", "lab.test"), "lea.herve@lab.test");
        assert_eq!(
            parent_label("OU=Paris,OU=Labo,DC=lab,DC=test"),
            "Paris ‹ Labo"
        );
    }

    #[test]
    fn checks() {
        assert!(identifier_problem("a b").is_some());
        assert!(identifier_problem("abcdefghijklmnopqrstu").is_some());
        assert!(identifier_problem("lea.herve").is_none());
        assert!(password_problem("", "", true).is_some());
        assert!(password_problem("", "", false).is_none());
        assert!(password_problem("a", "b", false).is_some());
        let (_, _, expected) = delete_confirmation(&["a".into(), "b".into()]);
        assert_eq!(expected, "2");
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the fine-grained password policies (PSO, `annuaire.vue.pso`): durations in clear
//! and as typed, summary of a PSO, what it targets.
//!
//! The AD durations (hundreds of nanoseconds, negative) show in days, hours, minutes and
//! seconds, and are typed alike: « 42 d », « 1 d 12 h », « 30 min », « 90 s », « never ». A
//! number alone takes the unit of the setting (days for the ages of the password, minutes for
//! the lockout), as in the GPMC. A field left unchanged keeps the value read, even if it was
//! not a whole number of seconds.

use annuaire_codecs::uac::Scope;
use annuaire_core::dn;
use annuaire_core::model::Object;
use annuaire_core::pso::{self as p, Problem, PsoError, PsoRead, Settings};

use crate::i18n::{fill, tr, tr_ctx, tr_n};

const SECOND: i64 = p::SECOND;

/// Units recognised when typing, in French and in English, whatever the language
/// (`UNITES_SAISIE`).
fn unit(text: &str) -> Option<i64> {
    Some(match text {
        "j" | "jour" | "jours" | "d" | "day" | "days" => p::DAY,
        "h" | "heure" | "heures" | "hour" | "hours" => p::HOUR,
        "min" | "mn" | "minute" | "minutes" | "m" => p::MINUTE,
        "s" | "sec" | "seconde" | "secondes" | "second" | "seconds" => SECOND,
        _ => return None,
    })
}

const NEVER_WORDS: [&str; 6] = [
    "jamais",
    "never",
    "aucune",
    "none",
    "illimitée",
    "unlimited",
];

/// Unit of a number typed alone (`UNITE_PAR_DEFAUT`).
fn default_unit(name: &str) -> i64 {
    match name {
        "age_minimal" | "age_maximal" => p::DAY,
        "duree_verrouillage" | "fenetre_verrouillage" => p::MINUTE,
        _ => SECOND,
    }
}

/// (number, unit) of the days, hours, minutes and seconds of a duration (positive)
/// (`_morceaux`).
fn pieces(duration: i128) -> Vec<(i128, i64)> {
    let mut rest = duration / i128::from(SECOND);
    let mut out = Vec::new();
    for u in [p::DAY, p::HOUR, p::MINUTE, SECOND] {
        let size = i128::from(u / SECOND);
        let n = rest / size;
        rest %= size;
        if n != 0 {
            out.push((n, u));
        }
    }
    out
}

/// `round(x, 3)` as Python prints it.
fn seconds_text(value: i64) -> String {
    let x = -(value as f64) / SECOND as f64;
    let rounded = (x * 1000.0).round() / 1000.0;
    let text = format!("{rounded}");
    if text.contains('.') {
        text
    } else {
        format!("{text}.0")
    }
}

/// The short form, the one the field reads back: « 1 d 12 h », « 30 min », « never »
/// (`duree_saisie`).
pub fn duration_input(value: i64) -> String {
    if value == p::NEVER {
        return tr("never");
    }
    if value == 0 {
        return "0".into();
    }
    let short = |u: i64| match u {
        p::DAY => tr("d"),
        p::HOUR => tr("h"),
        p::MINUTE => tr("min"),
        _ => tr("s"),
    };
    let found = pieces(-i128::from(value));
    if found.is_empty() {
        return fill(&tr("{n} s"), &[("n", &seconds_text(value))]);
    }
    found
        .iter()
        .map(|(n, u)| format!("{n} {}", short(*u)))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A duration in words; « never » said by the setting `name`. A maximum age of zero means
/// « never expires » (`duree_en_clair`).
pub fn duration_text(value: i64, name: &str) -> String {
    if value == p::NEVER || (value == 0 && name == "age_maximal") {
        return match name {
            "age_maximal" => tr("Never expires"),
            "duree_verrouillage" => tr("Until an administrator unlocks it"),
            _ => tr("Never"),
        };
    }
    if value == 0 {
        return if name == "age_minimal" {
            tr("None (changes allowed at any time)")
        } else {
            tr_ctx("feminine", "None")
        };
    }
    let found = pieces(-i128::from(value));
    if found.is_empty() {
        return fill(&tr("{n} s"), &[("n", &seconds_text(value))]);
    }
    found
        .iter()
        .map(|(n, u)| {
            let count = u64::try_from(*n).unwrap_or(u64::MAX);
            let template = match *u {
                p::DAY => tr_n("{n} day", "{n} days", count),
                p::HOUR => tr_n("{n} hour", "{n} hours", count),
                p::MINUTE => tr_n("{n} minute", "{n} minutes", count),
                _ => tr_n("{n} second", "{n} seconds", count),
            };
            fill(&template, &[("n", &n.to_string())])
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The AD duration of a field, or a clear message if it does not read (`duree_depuis_saisie`).
pub fn duration_from_input(text: &str, name: &str) -> Result<i64, String> {
    let clean = text.trim().to_lowercase();
    if clean.is_empty() {
        return Err(tr("Empty duration."));
    }
    if NEVER_WORDS.contains(&clean.as_str()) {
        return Ok(p::NEVER);
    }
    let unreadable = || {
        fill(
            &tr("Unreadable duration: “{texte}” (examples: 42 d, 1 d 12 h, 30 min)."),
            &[("texte", text.trim())],
        )
    };
    let chars: Vec<char> = clean.chars().collect();
    let mut total = 0.0_f64;
    let mut i = 0;
    while i < chars.len() {
        while chars.get(i).is_some_and(|c| c.is_whitespace()) {
            i += 1;
        }
        let start = i;
        while chars.get(i).is_some_and(char::is_ascii_digit) {
            i += 1;
        }
        if i == start {
            return Err(unreadable());
        }
        if chars.get(i).is_some_and(|c| *c == '.' || *c == ',')
            && chars.get(i + 1).is_some_and(char::is_ascii_digit)
        {
            i += 1;
            while chars.get(i).is_some_and(char::is_ascii_digit) {
                i += 1;
            }
        }
        let number: String = chars
            .get(start..i)
            .unwrap_or_default()
            .iter()
            .collect::<String>()
            .replace(',', ".");
        while chars.get(i).is_some_and(|c| c.is_whitespace()) {
            i += 1;
        }
        let unit_start = i;
        while chars
            .get(i)
            .is_some_and(|c| !c.is_ascii_digit() && !c.is_whitespace() && *c != '.' && *c != ',')
        {
            i += 1;
        }
        let word: String = chars
            .get(unit_start..i)
            .unwrap_or_default()
            .iter()
            .collect();
        let factor = if word.is_empty() {
            default_unit(name)
        } else {
            unit(&word).ok_or_else(|| {
                fill(
                    &tr("Unknown unit: “{unite}” (d, h, min, s)."),
                    &[("unite", &word)],
                )
            })?
        };
        let value: f64 = number.parse().map_err(|_| unreadable())?;
        total += value * factor as f64;
    }
    let value = -total.round();
    if value < (p::NEVER as f64) + 1.0 {
        return Err(tr("Duration too long."));
    }
    Ok(value as i64)
}

// --- Summaries ------------------------------------------------------------------------------------

/// The name of a target: its first RDN (`nom_cible`).
pub fn target_name(dn_text: &str) -> String {
    dn::split(dn_text)
        .ok()
        .and_then(|c| c.first().map(|c| c.value.clone()))
        .unwrap_or_else(|| dn_text.to_owned())
}

/// Why a PSO would have no effect on this object; empty if it applies to it (user account,
/// global security group) (`sans_effet`).
pub fn without_effect(object: &Object) -> String {
    match object {
        Object::Group { group_type, .. } => match group_type {
            Some(t) if t.scope == Some(Scope::Global) && t.security => String::new(),
            _ => tr("no effect: not a global security group"),
        },
        Object::User { .. } => String::new(),
        _ => tr("no effect: not a user account"),
    }
}

pub fn targets_text(targets: &[String]) -> String {
    if targets.is_empty() {
        return tr("Applies to nobody");
    }
    fill(
        &tr("Applies to: {cibles}"),
        &[(
            "cibles",
            &targets
                .iter()
                .map(|d| target_name(d))
                .collect::<Vec<_>>()
                .join(", "),
        )],
    )
}

/// One line: length, complexity, maximum age, lockout (`resume`).
pub fn summary(settings: &Settings) -> String {
    let n = u64::try_from(settings.min_length).unwrap_or(0);
    let mut pieces = vec![
        fill(
            &tr_n("at least {n} character", "at least {n} characters", n),
            &[("n", &settings.min_length.to_string())],
        ),
        if settings.complexity {
            tr("complexity required")
        } else {
            tr("no complexity")
        },
        fill(
            &tr("history of {n}"),
            &[("n", &settings.history.to_string())],
        ),
        fill(
            &tr("expiration: {d}"),
            &[("d", &duration_text(settings.max_age, "age_maximal"))],
        ),
    ];
    if settings.lockout_threshold != 0 {
        pieces.push(fill(
            &tr("locked out after {n} failures ({d})"),
            &[
                ("n", &settings.lockout_threshold.to_string()),
                (
                    "d",
                    &duration_text(settings.lockout_duration, "duree_verrouillage"),
                ),
            ],
        ));
    } else {
        pieces.push(tr("never locked out"));
    }
    if settings.reversible {
        pieces.push(tr("reversible encryption"));
    }
    pieces.join(" · ")
}

pub fn title(pso: &PsoRead) -> String {
    fill(
        &tr("{nom} (precedence {n})"),
        &[
            ("nom", &pso.name),
            ("n", &pso.settings.precedence.to_string()),
        ],
    )
}

/// Title of a field (`TITRES`).
pub fn field_title(name: &str) -> String {
    match name {
        "priorite" => tr("Priority"),
        "longueur_minimale" => tr("Minimum password length"),
        "historique" => tr("Enforce password history"),
        "complexite" => tr("Password must meet complexity requirements"),
        "chiffrement_reversible" => tr("Store passwords using reversible encryption"),
        "age_minimal" => tr("Minimum password age"),
        "age_maximal" => tr("Maximum password age"),
        "seuil_verrouillage" => tr("Account lockout threshold"),
        "duree_verrouillage" => tr("Account lockout duration"),
        _ => tr("Reset account lockout counter after"),
    }
}

/// What the common preview says besides the diff (`remarques`).
pub fn remarks(without_effect_on: &[String]) -> Vec<String> {
    let mut out = vec![tr(
        "The fine-grained password policy replaces the domain policy for the accounts it applies to; among several policies, the lowest precedence wins, and a policy linked to the account itself wins over those of its groups.",
    )];
    if !without_effect_on.is_empty() {
        out.push(fill(
            &tr(
                "No effect on {cibles}: a fine-grained password policy only applies to user accounts and global security groups.",
            ),
            &[("cibles", &without_effect_on.join(", "))],
        ));
    }
    out
}

/// A check of the settings said plainly (`problemes`).
pub fn problem_text(problem: &Problem) -> String {
    match problem {
        Problem::OutOfRange {
            field,
            value,
            minimum,
            maximum,
        } => fill(
            &tr("{champ}: {n} is out of range ({mini} to {maxi})."),
            &[
                ("champ", &field_title(field)),
                ("n", &value.to_string()),
                ("mini", &minimum.to_string()),
                ("maxi", &maximum.to_string()),
            ],
        ),
        Problem::InvalidDuration { field, value } => fill(
            &tr("{champ}: invalid duration ({n})."),
            &[("champ", &field_title(field)), ("n", &value.to_string())],
        ),
        Problem::MinAgeNotBelowMax => {
            tr("The minimum password age must be less than the maximum password age.")
        }
        Problem::WindowLongerThanDuration => {
            tr("The lockout counter reset cannot be longer than the lockout duration.")
        }
    }
}

pub fn pso_error_text(error: &PsoError) -> String {
    match error {
        PsoError::EmptyName => tr("The policy name is empty."),
        PsoError::NameTooLong => tr("The policy name is longer than 64 characters."),
        PsoError::Problems(found) => found.iter().map(problem_text).collect::<Vec<_>>().join(" "),
        PsoError::Invalid(detail) => crate::codec_texts::codec_message(detail),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations() {
        assert_eq!(duration_input(-42 * p::DAY), "42 d");
        assert_eq!(duration_input(-(p::DAY + 12 * p::HOUR)), "1 d 12 h");
        assert_eq!(duration_input(p::NEVER), "never");
        assert_eq!(duration_input(-5_000_000), "0.5 s");
        assert_eq!(
            duration_text(-30 * p::MINUTE, "duree_verrouillage"),
            "30 minutes"
        );
        assert_eq!(duration_text(0, "age_maximal"), "Never expires");
        assert_eq!(duration_from_input("42", "age_maximal"), Ok(-42 * p::DAY));
        assert_eq!(
            duration_from_input("30", "duree_verrouillage"),
            Ok(-30 * p::MINUTE)
        );
        assert_eq!(
            duration_from_input("1 j 12 h", "age_maximal"),
            Ok(-(p::DAY + 12 * p::HOUR))
        );
        assert_eq!(
            duration_from_input("1,5 h", "x"),
            Ok(-(p::HOUR + 30 * p::MINUTE))
        );
        assert_eq!(duration_from_input(" jamais ", "x"), Ok(p::NEVER));
        assert!(duration_from_input("", "x").is_err());
        assert!(duration_from_input("3 lunes", "x").is_err());
        assert!(duration_from_input("abc", "x").is_err());
    }

    #[test]
    fn texts() {
        let s = Settings::default();
        assert_eq!(
            summary(&s),
            "at least 7 characters · complexity required · history of 24 · expiration: 42 days · never locked out"
        );
        assert_eq!(targets_text(&["CN=G,DC=x".into()]), "Applies to: G");
    }
}

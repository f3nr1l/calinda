// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the home screen and of the status bars (`annuaire.vue.textes`): profiles,
//! ticket. Pure, apart from the catalogue and the local time zone.

use std::time::{SystemTime, UNIX_EPOCH};

use annuaire_codecs::time::UtcTime;
use annuaire_core::cache::{SyncPhase, SyncState};
use annuaire_core::kerberos::Ticket;
use annuaire_core::profile::{Mode, Profile, ProfileError};
use annuaire_core::sync::Reason;
use gtk::glib;

use crate::i18n::{fill, tr};

pub fn mode_label(mode: Mode) -> String {
    match mode {
        Mode::Sealed => tr("GSSAPI signed and sealed"),
        Mode::Ldaps => tr("LDAPS"),
        Mode::StartTls => tr("StartTLS"),
    }
}

/// What must always be seen (plan, 0.1): read-only, or writes allowed.
pub fn access_label(profile: &Profile) -> String {
    if profile.read_only {
        tr("Read-only")
    } else {
        tr("Writes allowed")
    }
}

pub fn describe_profile(profile: &Profile) -> String {
    let mut parts = vec![access_label(profile), mode_label(profile.mode)];
    if let Some(dc) = &profile.preferred_dc {
        parts.push(fill(&tr("Preferred DC: {dc}"), &[("dc", dc)]));
    }
    parts.join(" · ")
}

/// Local date and time, to the minute (`formater_date`); empty without a date.
pub fn format_date(date: Option<SystemTime>) -> String {
    let Some(date) = date else {
        return String::new();
    };
    let seconds = match date.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
    };
    format_unix(seconds)
}

fn format_unix(seconds: i64) -> String {
    glib::DateTime::from_unix_local(seconds)
        .and_then(|d| d.format(&tr("%d/%m/%Y %H:%M")))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

pub fn describe_ticket(ticket: Option<&Ticket>) -> String {
    match ticket {
        None => tr("No valid ticket in the session cache"),
        Some(Ticket {
            principal,
            end: None,
        }) => fill(
            &tr("{principal}, with no time limit"),
            &[("principal", principal)],
        ),
        Some(Ticket {
            principal,
            end: Some(end),
        }) => fill(
            &tr("{principal}, valid until {fin}"),
            &[("principal", principal), ("fin", &format_date(Some(*end)))],
        ),
    }
}

/// Why the local copy is made anew entirely (`libelle_motif`).
pub fn reason_label(reason: Option<Reason>) -> String {
    match reason {
        None => String::new(),
        Some(Reason::First) => tr("first copy"),
        Some(Reason::OtherDc) => {
            tr("the controller of the copy is not responding: copy redone on another one")
        }
        Some(Reason::Restoration) => tr("the controller of the copy has been restored"),
        Some(Reason::Old) => tr("copy older than the deleted object lifetime"),
        Some(Reason::Schema) => tr("the directory schema has changed"),
    }
}

/// Date of the copy that served the display (`decrire_fraicheur`).
pub fn describe_freshness(date: UtcTime) -> String {
    fill(
        &tr("Local copy of {date}"),
        &[("date", &format_unix(date.unix_seconds()))],
    )
}

/// Status bar: (text, tooltip) (`decrire_copie`). `date`: date of the local copy that
/// served the display, None if it was read on the DC; `state`: state of the copy, None
/// without a local copy; `error`: message of a failed synchronization. A datum of the copy
/// is always dated, never shown as fresh (criterion JC).
pub fn describe_copy(
    date: Option<UtcTime>,
    state: Option<&SyncState>,
    error: &str,
) -> (String, String) {
    let phase = state.map(|s| s.phase);
    let tooltip = match state {
        Some(_) if !error.is_empty() => error.to_owned(),
        Some(s) if s.phase != SyncPhase::UpToDate => reason_label(s.reason),
        _ => String::new(),
    };
    let Some(date) = date else {
        let text = match state {
            Some(s) if s.phase == SyncPhase::Preparing => {
                tr("Read on the DC; local copy being prepared…")
            }
            Some(s) if s.phase == SyncPhase::Failed && s.date.is_none() => {
                tr("Read on the DC; local copy not possible")
            }
            _ => String::new(),
        };
        return (text, tooltip);
    };
    let copy = describe_freshness(date);
    let text = match phase {
        Some(SyncPhase::Synchronizing) => fill(&tr("{copie}, synchronizing…"), &[("copie", &copy)]),
        Some(SyncPhase::Resynchronizing) => {
            fill(&tr("{copie}, full resynchronization…"), &[("copie", &copy)])
        }
        Some(SyncPhase::Failed) => {
            fill(&tr("{copie}, synchronization failed"), &[("copie", &copy)])
        }
        _ => copy,
    };
    (text, tooltip)
}

/// Message of an invalid profile (`ProfilDomaine.__post_init__`, `profil_depuis_dict`).
pub fn profile_error(error: &ProfileError) -> String {
    match error {
        ProfileError::InvalidDomain(d) => fill(
            &tr("invalid domain name: {domaine}"),
            &[("domaine", &format!("'{d}'"))],
        ),
        ProfileError::InvalidDc(dc) => {
            fill(&tr("invalid DC name: {dc}"), &[("dc", &format!("'{dc}'"))])
        }
        ProfileError::TlsWithoutCa => tr("TLS mode requires the certificate of the domain CA"),
        ProfileError::NoDomain => tr("profile without a domain"),
        ProfileError::NotText(key) => fill(&tr("field {cle}: string expected"), &[("cle", key)]),
        ProfileError::NotBool(key) if key == "lecture-seule" => {
            tr("read-only field: boolean expected")
        }
        ProfileError::NotBool(key) if key == "smb2-signature-seule" => {
            tr("smb2-signature-seule field: boolean expected")
        }
        ProfileError::NotBool(_) => tr("cache field: boolean expected"),
        ProfileError::UnknownMode(mode) => format!("mode: {mode}"),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn profile_description() {
        let mut p = Profile::new("lab.test");
        assert_eq!(describe_profile(&p), "Read-only · GSSAPI signed and sealed");
        p.read_only = false;
        p.preferred_dc = Some("dc1.lab.test".into());
        assert_eq!(
            describe_profile(&p),
            "Writes allowed · GSSAPI signed and sealed · Preferred DC: dc1.lab.test"
        );
    }

    #[test]
    fn ticket_description() {
        assert_eq!(
            describe_ticket(None),
            "No valid ticket in the session cache"
        );
        let mut t = Ticket {
            principal: "Administrator@LAB.TEST".into(),
            end: None,
        };
        assert_eq!(
            describe_ticket(Some(&t)),
            "Administrator@LAB.TEST, with no time limit"
        );
        t.end = Some(UNIX_EPOCH + Duration::from_secs(86_400 * 365));
        let text = describe_ticket(Some(&t));
        assert!(
            text.starts_with("Administrator@LAB.TEST, valid until "),
            "{text}"
        );
        // dd/mm/YYYY HH:MM, in the local time zone.
        let date = text.rsplit("until ").next().unwrap_or_default();
        assert_eq!(date.len(), 16, "{date}");
        assert_eq!(format_date(None), "");
    }

    #[test]
    fn profile_errors() {
        assert_eq!(
            profile_error(&ProfileError::InvalidDomain("LAB".into())),
            "invalid domain name: 'LAB'"
        );
        assert_eq!(
            profile_error(&ProfileError::NotBool("cache".into())),
            "cache field: boolean expected"
        );
    }
}

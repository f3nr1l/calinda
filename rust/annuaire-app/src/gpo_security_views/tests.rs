// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the « Security Settings » pages and draft (`test_vue_gpo_securite.py`); the texts
//! are those of the source language (no catalogue in the tests).

#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;

use annuaire_core::security_policy::{AccountScope, DomainPolicy};

use super::*;

const GROUP: &str = "S-1-5-21-1-2-3-1105";

fn domain() -> DomainPolicy {
    sp::domain_policy(&[
        ("minPwdLength".into(), Some(b"7".to_vec())),
        ("pwdProperties".into(), Some(b"1".to_vec())),
    ])
}

fn security(reach: Reach, samba: bool, prior: &[&str]) -> SecurityRead {
    SecurityRead {
        dn: "CN={X},CN=Policies,CN=System,DC=lab,DC=test".into(),
        name: "Essai".into(),
        inf: Inf::new_gpmc(),
        exists: false,
        scope: AccountScope {
            reach,
            prior: Vec::new(),
        },
        domain: domain(),
        samba,
        prior_names: prior.iter().map(|x| (*x).to_owned()).collect(),
        psos: Vec::new(),
    }
}

fn setting(key: &str) -> &'static sp::SettingDef {
    sp::setting(key).unwrap()
}

#[test]
fn value_texts() {
    assert_eq!(
        value_text(setting("MinimumPasswordLength"), None),
        "Not Defined"
    );
    assert_eq!(
        value_text(setting("MinimumPasswordLength"), Some(12)),
        "12 characters"
    );
    assert_eq!(
        value_text(setting("MaximumPasswordAge"), Some(-1)),
        "Never expires"
    );
    assert!(value_text(setting("MaximumPasswordAge"), Some(0)).contains("ignored by Windows"));
    assert_eq!(
        value_text(setting("PasswordComplexity"), Some(1)),
        "Enabled"
    );
    assert_eq!(
        value_text(setting("LockoutDuration"), Some(-1)),
        "Until an administrator unlocks it"
    );
}

#[test]
fn setting_rows_with_domain() {
    let inf = sp::set(&Inf::new_gpmc(), setting("MinimumPasswordLength"), Some(12)).unwrap();
    let rows = setting_rows(Page::Password, &inf, Some(&domain()));
    let length = rows
        .iter()
        .find(|x| x.setting.key == "MinimumPasswordLength")
        .unwrap();
    assert_eq!(
        (length.text.as_str(), length.domain.as_str()),
        ("12 characters", "7 characters")
    );
    let keys: Vec<&str> = setting_rows(Page::Lockout, &inf, None)
        .iter()
        .map(|x| x.setting.key)
        .collect();
    assert_eq!(
        keys,
        ["LockoutBadCount", "LockoutDuration", "ResetLockoutCount"]
    );
}

#[test]
fn banners() {
    assert!(!accounts_banner(&security(Reach::Domain, true, &[])).alert);
    assert!(
        accounts_banner(&security(Reach::Domain, true, &[]))
            .text
            .contains("samba-tool")
    );
    assert!(
        accounts_banner(&security(Reach::Domain, false, &[]))
            .text
            .contains("PDC emulator")
    );
    assert!(
        accounts_banner(&security(Reach::Domain, true, &["Prior"]))
            .text
            .contains("Prior")
    );
    let ou = accounts_banner(&security(Reach::Elsewhere, true, &[]));
    assert!(ou.alert && ou.text.contains("local accounts") && ou.text.contains("PSO"));
    assert!(accounts_banner(&security(Reach::Unlinked, true, &[])).alert);
}

#[test]
fn names_of_the_entries() {
    let sid: Sid = GROUP.parse().unwrap();
    let names: Names = HashMap::from([(
        sid,
        SidName {
            sid,
            name: "GG-Helpdesk".into(),
            dn: String::new(),
            classes: Vec::new(),
        },
    )]);
    assert_eq!(
        entry_name(&format!("*{GROUP}"), Some(&names)),
        "GG-Helpdesk"
    );
    let admins = entry_name("*S-1-5-32-544", None);
    assert_ne!(admins, "*S-1-5-32-544");
    assert_eq!(entry_name("*S-1-5-80-0", None), "All Services");
    assert_eq!(entry_name("Invité", None), "Invité");
    assert_eq!(entry_name("*S-pas-un-sid", None), "*S-pas-un-sid");
    assert_eq!(names_list(None, None), "Not Defined");
    assert_eq!(names_list(Some(&[]), None), "Nobody");
    assert_eq!(
        names_list(Some(&["*S-1-5-32-544".into(), "Invité".into()]), None),
        format!("{admins}, Invité")
    );
}

#[test]
fn rights_and_groups() {
    let inf = Inf::new_gpmc()
        .set_right(
            "SeDenyInteractiveLogonRight",
            Some(&["*S-1-5-32-546".into()]),
        )
        .set_right("SeDroitInconnu", Some(&["*S-1-1-0".into()]))
        .set_group("*S-1-5-32-544", &[format!("*{GROUP}")], &[]);
    let rows = right_rows(&inf);
    assert_eq!(rows.len(), sp::RIGHTS.len() + 1);
    let deny = rows
        .iter()
        .find(|x| x.name == "SeDenyInteractiveLogonRight")
        .unwrap();
    assert_eq!(
        deny.entries.as_deref(),
        Some(&["*S-1-5-32-546".to_owned()][..])
    );
    assert!(deny.title.starts_with("Deny"), "{}", deny.title);
    assert_eq!(rows.last().unwrap().name, "SeDroitInconnu");
    let wanted: HashSet<Sid> = ["S-1-5-32-546", "S-1-1-0", "S-1-5-32-544", GROUP]
        .iter()
        .map(|x| x.parse().unwrap())
        .collect();
    assert_eq!(sids(&inf), wanted);
    let groups = inf.restricted_groups();
    assert_eq!(groups.len(), 1);
    assert_eq!(names_list(groups[0].member_of.as_deref(), None), "Nobody");
    assert_eq!(
        entry_name(&groups[0].group, None),
        entry_name("*S-1-5-32-544", None)
    );
}

#[test]
fn draft_replayed_on_the_content_read_again() {
    let mut draft = Draft::default();
    assert!(draft.is_empty());
    draft.set_setting("MinimumPasswordLength", Some(12), None);
    draft.set_right("SeBackupPrivilege", Some(Vec::new()), None);
    draft.set_group(
        "*S-1-5-32-544",
        Some((vec![format!("*{GROUP}")], Vec::new())),
        None,
    );
    // Meanwhile someone defined another setting: it is kept.
    let again = sp::set(&Inf::new_gpmc(), setting("LockoutBadCount"), Some(5)).unwrap();
    let inf = draft.apply(&again).unwrap();
    assert_eq!(sp::value(&inf, setting("LockoutBadCount")), Some(5));
    assert_eq!(sp::value(&inf, setting("MinimumPasswordLength")), Some(12));
    assert_eq!(inf.right("SeBackupPrivilege"), Some(Vec::new()));
    assert_eq!(
        inf.restricted_groups()[0].members.as_deref(),
        Some(&[format!("*{GROUP}")][..])
    );
    // Back to what is read: out of the draft.
    draft.set_setting("MinimumPasswordLength", None, None);
    assert_eq!(draft.len(), 2);
    let lines = preview_lines(&draft, &inf, None);
    assert_eq!(lines.len(), 2);
    assert_eq!(
        page_summary(SecurityPage::Lockout, &again),
        "1 item defined"
    );
    assert_eq!(
        page_summary(SecurityPage::Rights, &again),
        "Nothing defined"
    );
}

#[test]
fn pso_summary() {
    let pso = PsoSummary {
        dn: "CN=Admins,CN=Password Settings Container,CN=System,DC=lab,DC=test".into(),
        name: "Admins".into(),
        precedence: 10,
        values: BTreeMap::from([
            ("MinimumPasswordLength".into(), 16),
            ("PasswordComplexity".into(), 1),
        ]),
        applies_to: vec!["CN=Domain Admins,CN=Users,DC=lab,DC=test".into()],
    };
    let (title, summary) = pso_text(&pso, &HashMap::new());
    assert_eq!(title, "Admins (precedence 10)");
    assert!(summary.contains("16 characters") && summary.contains("Domain Admins"));
}

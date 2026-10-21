// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Meaning of the security settings of a GPO (`test_strategie_securite.py`): settings, domain
//! object, scope.

use super::*;

const DOMAIN: &str = "DC=lab,DC=test";

/// Attributes of the domain object of LAB.TEST as Samba provisions them.
fn lab() -> Vec<(String, Option<Vec<u8>>)> {
    [
        ("minPwdLength", "7"),
        ("pwdHistoryLength", "24"),
        ("minPwdAge", "-864000000000"),
        ("maxPwdAge", "-36288000000000"),
        ("pwdProperties", "1"),
        ("lockoutThreshold", "0"),
        ("lockoutDuration", "-18000000000"),
        ("lockOutObservationWindow", "-18000000000"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), Some(v.as_bytes().to_vec())))
    .collect()
}

fn with(
    attributes: &[(String, Option<Vec<u8>>)],
    name: &str,
    v: &str,
) -> Vec<(String, Option<Vec<u8>>)> {
    let mut out = attributes.to_vec();
    for (k, value) in &mut out {
        if k == name {
            *value = Some(v.as_bytes().to_vec());
        }
    }
    out
}

fn inf(values: &[(&str, i64)]) -> Inf {
    let mut inf = Inf::new_gpmc();
    for (k, n) in values {
        inf = inf.set_integer(gt::SYSTEM_ACCESS, k, Some(*n));
    }
    inf
}

fn change(attribute: &str, before: &[&str], after: &str) -> Change {
    Change::new(
        attribute,
        before.iter().map(|b| b.as_bytes().to_vec()).collect(),
        vec![after.as_bytes().to_vec()],
    )
    .unwrap()
}

#[test]
fn domain_policy_of_lab() {
    let p = domain_policy(&lab());
    let wanted: BTreeMap<String, i64> = [
        ("MinimumPasswordLength", 7),
        ("PasswordHistorySize", 24),
        ("LockoutBadCount", 0),
        ("MinimumPasswordAge", 1),
        ("MaximumPasswordAge", 42),
        ("LockoutDuration", 30),
        ("ResetLockoutCount", 30),
        ("PasswordComplexity", 1),
        ("ClearTextPassword", 0),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), *v))
    .collect();
    assert_eq!(p.values, wanted);
}

#[test]
fn policy_never() {
    let p = domain_policy(&[
        ("maxPwdAge".into(), Some(b"-9223372036854775808".to_vec())),
        ("pwdProperties".into(), Some(b"16".to_vec())),
    ]);
    assert_eq!(p.values["MaximumPasswordAge"], -1);
    assert_eq!(p.values["PasswordComplexity"], 0);
    assert_eq!(p.values["ClearTextPassword"], 1);
}

#[test]
fn changes_as_samba_tool() {
    let i = inf(&[
        ("MinimumPasswordLength", 12),
        ("LockoutBadCount", 5),
        ("LockoutDuration", 15),
        ("ResetLockoutCount", 15),
        ("PasswordComplexity", 1),
    ]);
    assert_eq!(
        domain_changes(&i, &lab()).unwrap(),
        [
            change("minPwdLength", &["7"], "12"),
            change("lockoutThreshold", &["0"], "5"),
            change("lockoutDuration", &["-18000000000"], "-9000000000"),
            change("lockOutObservationWindow", &["-18000000000"], "-9000000000"),
        ]
    );
}

#[test]
fn changes_never_and_bits() {
    let i = inf(&[
        ("MaximumPasswordAge", -1),
        ("LockoutDuration", -1),
        ("ClearTextPassword", 0),
        ("PasswordComplexity", 0),
    ]);
    let attributes = with(&lab(), "pwdProperties", "5");
    assert_eq!(
        domain_changes(&i, &attributes).unwrap(),
        [
            change("maxPwdAge", &["-36288000000000"], "-9223372036854775808"),
            change("pwdProperties", &["5"], "4"),
            change("lockoutDuration", &["-18000000000"], "-9223372036854775808"),
        ]
    );
    assert!(domain_changes(&inf(&[]), &lab()).unwrap().is_empty());
    // As the Windows PDC emulator: MaximumPasswordAge = 0 changes nothing.
    assert!(
        domain_changes(&inf(&[("MaximumPasswordAge", 0)]), &lab())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn attribute_absent() {
    assert_eq!(
        domain_changes(&inf(&[("LockoutBadCount", 3)]), &[]).unwrap(),
        [change("lockoutThreshold", &[], "3")]
    );
}

#[test]
fn bounds_and_problems() {
    let r = setting("MinimumPasswordLength").unwrap();
    assert!(set(&Inf::new_gpmc(), r, Some(15)).is_err());
    let d = setting("LockoutDuration").unwrap();
    assert_eq!(
        value(&set(&Inf::new_gpmc(), d, Some(-1)).unwrap(), d),
        Some(-1)
    );
    assert!(
        !problems(&inf(&[
            ("MinimumPasswordAge", 42),
            ("MaximumPasswordAge", 42)
        ]))
        .is_empty()
    );
    assert!(
        problems(&inf(&[
            ("MinimumPasswordAge", 42),
            ("MaximumPasswordAge", -1)
        ]))
        .is_empty()
    );
    assert!(!problems(&inf(&[("LockoutDuration", 10), ("ResetLockoutCount", 30)])).is_empty());
    assert!(problems(&inf(&[("LockoutDuration", -1), ("ResetLockoutCount", 30)])).is_empty());
}

#[test]
fn known_rights() {
    assert!(known_right("sesystemtimeprivilege").is_some());
    let names: std::collections::HashSet<String> =
        RIGHTS.iter().map(|r| r.name.to_lowercase()).collect();
    assert_eq!(names.len(), RIGHTS.len());
    assert!(known_right("SeInconnu").is_none());
}

fn guid(n: u32) -> String {
    format!("{{00000000-0000-0000-0000-{n:012}}}")
}

fn link(n: u32, options: u32) -> String {
    format!(
        "[LDAP://CN={},CN=Policies,CN=System,{DOMAIN};{options}]",
        guid(n)
    )
}

#[test]
fn reach() {
    // String: 1, 2 (disabled), 3; link order: 3 (first), 2, 1.
    let root = GpLink::parse(&format!("{}{}{}", link(1, 0), link(2, 1), link(3, 0)));
    let ou = [GpLink::parse(&link(4, 0))];
    assert_eq!(
        scope(&root, &ou, &guid(3)),
        AccountScope {
            reach: Reach::Domain,
            prior: vec![]
        }
    );
    assert_eq!(
        scope(&root, &ou, &guid(1).to_lowercase()),
        AccountScope {
            reach: Reach::Domain,
            prior: vec![guid(3)]
        }
    );
    assert_eq!(scope(&root, &ou, &guid(2)).reach, Reach::Unlinked);
    assert_eq!(scope(&root, &ou, &guid(4)).reach, Reach::Elsewhere);
}

#[test]
fn prior_masked() {
    let i = inf(&[("MinimumPasswordLength", 12), ("LockoutBadCount", 5)]);
    let prior = inf(&[("MinimumPasswordLength", 8)]);
    let (rest, aside) = mask_prior(&i, &[prior]);
    assert_eq!(
        domain_changes(&rest, &lab()).unwrap(),
        [change("lockoutThreshold", &["0"], "5")]
    );
    assert_eq!(aside, ["MinimumPasswordLength"]);
}

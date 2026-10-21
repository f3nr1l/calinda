// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The draft of the preferences replayed on the file read again (`test_preferences.py`, pure
//! part).

use super::*;
use crate::gpp::{Common, EditableFilter, Filter};

const INSTANT: i64 = 1_792_011_909;

fn drive(letter: &str, path: &str, uid: &str) -> Element {
    gpp::new_element(
        Family::Drives,
        &format!("{letter}:"),
        &format!("{letter}:"),
        &[
            ("action".into(), "U".into()),
            ("path".into(), path.into()),
            ("letter".into(), letter.into()),
        ],
        &Common::default(),
        &[Filter::Editable(EditableFilter::new(
            Target::Group,
            &[("name", "LAB\\GG-Essai"), ("sid", "S-1-5-21-1-2-3-1105")],
        ))],
        uid,
        INSTANT,
        &[],
    )
}

fn names(bytes: &[u8]) -> Vec<String> {
    gpp::read(bytes, Family::Drives)
        .unwrap()
        .elements()
        .iter()
        .map(|e| e.name().to_owned())
        .collect()
}

#[test]
fn families_by_part() {
    assert_eq!(
        families(Part::Computer),
        [Family::Shortcuts, Family::Registry]
    );
    assert_eq!(families(Part::User), Family::ALL);
}

#[test]
fn add_change_remove_replayed() {
    let h = drive("H", "\\\\srv\\a", "{A}");
    let first = replay(Family::Drives, None, &[Operation::Add(h.clone())])
        .unwrap()
        .unwrap();
    assert_eq!(
        first,
        gpp::write(&gpp::add(&gpp::new_document(Family::Drives), h))
    );
    // Meanwhile another tool added an element: it is kept.
    let s = drive("S", "\\\\srv\\b", "{B}");
    let with_s = replay(Family::Drives, Some(&first), &[Operation::Add(s)])
        .unwrap()
        .unwrap();
    let t = drive("T", "\\\\srv\\c", "{C}");
    let ops = [
        Operation::Add(t),
        Operation::Shift {
            uid: "{C}".into(),
            offset: -5,
        },
        Operation::Remove { uid: "{Z}".into() },
    ];
    let after = replay(Family::Drives, Some(&with_s), &ops)
        .unwrap()
        .unwrap();
    assert_eq!(names(&after), ["T:", "H:", "S:"]);
    // The element changed by the draft disappeared: refused.
    let changed = drive("H", "\\\\srv\\x", "{Z}");
    assert!(matches!(
        replay(
            Family::Drives,
            Some(&with_s),
            &[Operation::Replace {
                uid: "{Z}".into(),
                element: changed
            }]
        ),
        Err(GpoError::PreferenceGone { .. })
    ));
    // Last element gone: no file.
    let ops = [
        Operation::Remove { uid: "{A}".into() },
        Operation::Remove { uid: "{B}".into() },
    ];
    assert_eq!(replay(Family::Drives, Some(&with_s), &ops).unwrap(), None);
    // An unreadable file makes the write refused.
    assert!(matches!(
        replay(Family::Drives, Some(b"<Printers/>"), &[]),
        Err(GpoError::Preferences { .. })
    ));
}

#[test]
fn remarks_of_the_preview() {
    let h = drive("H", "\\\\srv\\a", "{A}");
    let s = drive("S", "\\\\srv\\b", "{B}");
    let doc = gpp::read(
        &gpp::write(&gpp::add(
            &gpp::add(&gpp::new_document(Family::Drives), h.clone()),
            s,
        )),
        Family::Drives,
    )
    .unwrap();
    let changed = gpp::modify_element(
        doc.elements()[0],
        "H:",
        "H:",
        &[("path".into(), "\\\\srv\\z".into())],
        &Common::default(),
        &[],
        INSTANT,
        None,
    );
    let after = apply(
        doc.clone(),
        &[
            Operation::Replace {
                uid: "{A}".into(),
                element: changed,
            },
            Operation::Shift {
                uid: "{B}".into(),
                offset: -1,
            },
            Operation::Add(drive("K", "\\\\srv\\k", "{K}")),
        ],
    )
    .unwrap();
    assert_eq!(
        remarks(Some(&doc), &after),
        [
            Remark::Added(vec!["K:".into()]),
            Remark::Changed(vec!["H:".into()]),
            Remark::Reordered,
        ]
    );
    let empty = apply(
        doc.clone(),
        &[
            Operation::Remove { uid: "{A}".into() },
            Operation::Remove { uid: "{B}".into() },
        ],
    )
    .unwrap();
    assert_eq!(
        remarks(Some(&doc), &empty),
        [
            Remark::Removed(vec!["H:".into(), "S:".into()]),
            Remark::Emptied
        ]
    );
}

#[test]
fn extensions_of_a_family() {
    let d = Family::Drives.description();
    assert_eq!(
        extension_pairs(Family::Drives, false),
        (vec![(d.cse.to_owned(), d.tool.to_owned())], vec![])
    );
    let (add, remove) = extension_pairs(Family::Drives, true);
    assert!(add.is_empty());
    assert_eq!(remove[1], (gpp::NULL_CSE.to_owned(), d.tool.to_owned()));
}

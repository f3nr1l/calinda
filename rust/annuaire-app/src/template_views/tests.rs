// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Raw registry input and draft (`test_strategies.py`, second half).

use super::*;

fn dword(key: &str, name: &str, v: u32) -> Entry {
    Entry {
        key: key.into(),
        value_name: name.into(),
        rtype: rp::REG_DWORD,
        data: v.to_le_bytes().to_vec(),
    }
}

fn sz(key: &str, name: &str, v: &str, rtype: u32) -> Entry {
    Entry {
        key: key.into(),
        value_name: name.into(),
        rtype,
        data: v
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect(),
    }
}

fn raw(key: &str, name: &str, rtype: u32, data: Vec<u8>) -> Entry {
    Entry {
        key: key.into(),
        value_name: name.into(),
        rtype,
        data,
    }
}

fn form(rtype: u32, data: &str, decimal: bool) -> RawForm {
    RawForm {
        key: " K ".into(),
        name: "V".into(),
        rtype,
        data: data.into(),
        decimal,
        ..RawForm::default()
    }
}

#[test]
fn removal_line_said() {
    let text = removal_line(Part::Computer, &dword("Software\\X", "Y", 1));
    assert!(
        text.contains("HKLM\\Software\\X\\Y") && text.contains("removed"),
        "{text}"
    );
}

#[test]
fn raw_input_by_type() {
    let utf16 = |t: &str| {
        t.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    for (rtype, text, decimal, wanted) in [
        (rp::REG_SZ, "a b", true, sz("K", "V", "a b", rp::REG_SZ)),
        (
            rp::REG_EXPAND_SZ,
            "%SystemRoot%\\x",
            true,
            sz("K", "V", "%SystemRoot%\\x", rp::REG_EXPAND_SZ),
        ),
        (
            rp::REG_DWORD,
            "4294967295",
            true,
            dword("K", "V", 0xFFFF_FFFF),
        ),
        (rp::REG_DWORD, "ff", false, dword("K", "V", 255)),
        (
            rp::REG_QWORD,
            "1",
            true,
            raw("K", "V", rp::REG_QWORD, 1u64.to_le_bytes().to_vec()),
        ),
        (
            rp::REG_MULTI_SZ,
            "a\nb\n",
            true,
            raw("K", "V", rp::REG_MULTI_SZ, utf16("a\0b\0\0")),
        ),
        (
            rp::REG_BINARY,
            "01 ab\n2C",
            true,
            raw("K", "V", rp::REG_BINARY, vec![1, 0xab, 0x2c]),
        ),
    ] {
        let f = form(rtype, text, decimal);
        assert!(validate_raw(&f).is_empty(), "{text}");
        assert_eq!(raw_entry(&f).unwrap(), wanted, "{text}");
        // An entry of the file reads back in the dialog and is made again identically.
        let again = raw_form(Some(&wanted)).unwrap();
        assert_eq!(raw_entry(&again).unwrap(), wanted);
    }
}

#[test]
fn raw_input_refused() {
    let errors = |change: &dyn Fn(&mut RawForm)| {
        let mut f = RawForm {
            key: "Software\\X".into(),
            name: "V".into(),
            data: "1".into(),
            ..RawForm::default()
        };
        change(&mut f);
        validate_raw(&f).into_keys().collect::<Vec<_>>()
    };
    assert_eq!(errors(&|f| f.key = String::new()), ["cle"]);
    assert_eq!(errors(&|f| f.key = "HKLM\\Software\\X".into()), ["cle"]);
    assert_eq!(errors(&|f| f.key = "HKEY_CURRENT_USER\\X".into()), ["cle"]);
    assert_eq!(errors(&|f| f.key = "Software\\\\X".into()), ["cle"]);
    assert_eq!(errors(&|f| f.key = "\\Software".into()), ["cle"]);
    assert!(errors(&|f| f.key = "HKLMachin".into()).is_empty());
    assert_eq!(errors(&|f| f.name = "**del.V".into()), ["nom"]);
    assert_eq!(
        errors(&|f| {
            f.action = RawAction::Delete;
            f.name = String::new();
        }),
        ["nom"]
    );
    assert!(
        errors(&|f| {
            f.action = RawAction::DeleteAll;
            f.name = String::new();
            f.data = "x".into();
        })
        .is_empty()
    );
    let typed = |rtype: u32, data: &str, decimal: bool| {
        errors(&move |f: &mut RawForm| {
            f.rtype = rtype;
            f.data = data.into();
            f.decimal = decimal;
        })
    };
    assert_eq!(typed(rp::REG_DWORD, "4294967296", true), ["donnees"]);
    assert_eq!(typed(rp::REG_DWORD, "-1", true), ["donnees"]);
    assert_eq!(typed(rp::REG_DWORD, "12g", false), ["donnees"]);
    assert_eq!(typed(rp::REG_QWORD, "", true), ["donnees"]);
    assert_eq!(typed(rp::REG_BINARY, "abc", true), ["donnees"]);
    assert_eq!(typed(rp::REG_MULTI_SZ, "a\n\nb", true), ["donnees"]);
    assert_eq!(typed(rp::REG_SZ, "a\0b", true), ["donnees"]);
    assert!(raw_entry(&RawForm::default()).is_err());
}

#[test]
fn raw_input_markers() {
    let delete = raw_entry(&RawForm {
        action: RawAction::Delete,
        key: "K".into(),
        name: "V".into(),
        ..RawForm::default()
    })
    .unwrap();
    assert_eq!(
        delete,
        raw("K", "**del.V", rp::REG_SZ, rp::DEL_DATA.to_vec())
    );
    let all = raw_entry(&RawForm {
        action: RawAction::DeleteAll,
        key: "K".into(),
        name: "ignored".into(),
        ..RawForm::default()
    })
    .unwrap();
    assert_eq!(all.value_name, "**delvals.");
    assert_eq!(all.special(), Some(Special::DelVals));
    assert_eq!(
        raw_form(Some(&delete)),
        Some(RawForm {
            action: RawAction::Delete,
            key: "K".into(),
            name: "V".into(),
            ..RawForm::default()
        })
    );
    // The form of the GPMC (`**delVals.`, empty data) reads too.
    let gpmc = raw("K", "**delVals.", rp::REG_SZ, vec![0, 0]);
    assert_eq!(
        raw_form(Some(&gpmc)),
        Some(RawForm {
            action: RawAction::DeleteAll,
            key: "K".into(),
            ..RawForm::default()
        })
    );
    // What the dialog cannot make again identically does not open in it.
    let utf16 = |t: &str| {
        t.encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<u8>>()
    };
    assert!(raw_form(Some(&raw("K", "**DeleteKeys", rp::REG_SZ, utf16("a\0\0")))).is_none());
    assert!(
        raw_form(Some(&raw(
            "K",
            "V",
            rp::REG_DWORD_BIG_ENDIAN,
            vec![0, 0, 0, 1]
        )))
        .is_none()
    );
    assert!(raw_form(Some(&raw("K", "V", rp::REG_SZ, utf16("a\0b\0")))).is_none());
    assert!(raw_form(Some(&raw("K", "V", rp::REG_DWORD, vec![1]))).is_none());
}

#[test]
fn decimal_switch() {
    assert_eq!(convert_integer("255", false), "FF");
    assert_eq!(convert_integer("ff", true), "255");
    assert_eq!(convert_integer("zz", true), "zz");
}

#[test]
fn raw_draft_replayed() {
    let (a, b, c) = (dword("K", "A", 1), dword("K", "B", 2), dword("L", "C", 3));
    let file = vec![a.clone(), b.clone(), c.clone()];
    let (b2, d) = (dword("K", "B", 20), sz("K", "D", "x", rp::REG_SZ));
    let result = apply_raw(
        &file,
        std::slice::from_ref(&a),
        &[(Some(b.clone()), b2.clone()), (None, d.clone())],
    );
    // B changed in its place; D set after the last entry of its key, as the GPMC.
    assert_eq!(result, [b2.clone(), d.clone(), c.clone()]);
    // File changed meanwhile (B removed by the GPMC): the change is set anyway.
    assert_eq!(
        apply_raw(
            std::slice::from_ref(&c),
            &[],
            &[(Some(b.clone()), b2.clone())]
        ),
        [c.clone(), b2.clone()]
    );
    // Disabling a value set: `**del.` takes its place.
    let del = raw("K", "**del.B", rp::REG_SZ, rp::DEL_DATA.to_vec());
    assert_eq!(
        apply_raw(&file, &[], &[(Some(b.clone()), del.clone())]),
        [a, del, c]
    );
    assert!(addition_line(Part::User, None, &d).contains("added"));
    let text = addition_line(Part::Computer, Some(&b), &b2);
    assert!(
        text.contains("HKLM\\K\\B") && text.contains("changed") && text.contains("DWORD 20"),
        "{text}"
    );
}

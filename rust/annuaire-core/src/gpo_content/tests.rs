// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The changeset of a write of the content (`test_gpo_contenu.py`, pure part): files,
//! `GPT.INI`, `versionNumber` and extensions in one changeset.

use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::sddl;

use super::*;
use crate::changes::Read;
use crate::messages::English;

const GUID: &str = "{11111111-2222-3333-4444-555555555555}";
const DN: &str = "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=lab,DC=test";
const KEY: &str = "Software\\Policies\\Annuaire\\Essai";
const SECEDIT: &str = "Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf";

fn folder() -> String {
    gw::gpo_folder("lab.test", GUID)
}

fn machine() -> String {
    format!("{}\\Machine", folder())
}

fn descriptor() -> Vec<u8> {
    let domain: annuaire_codecs::Sid = "S-1-5-21-1094140757-505220614-2701386893".parse().unwrap();
    let sd: SecurityDescriptor = sddl::sd_from_sddl(
        "O:DAG:DAD:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPLCLORC;;;AU)",
        Some(&domain),
        true,
    )
    .unwrap();
    sd.encode().unwrap()
}

fn gpo(version: &str, flags: &str, machine_extensions: Option<&str>) -> GpoRead {
    let mut attributes: Vec<(String, Vec<Vec<u8>>)> = vec![
        ("displayName".into(), vec![b"Essai".to_vec()]),
        ("versionNumber".into(), vec![version.as_bytes().to_vec()]),
        ("flags".into(), vec![flags.as_bytes().to_vec()]),
        ("nTSecurityDescriptor".into(), vec![descriptor()]),
    ];
    if let Some(e) = machine_extensions {
        attributes.push((
            "gPCMachineExtensionNames".into(),
            vec![e.as_bytes().to_vec()],
        ));
    }
    GpoRead {
        dn: DN.into(),
        attributes,
        read: Read {
            dc: "dc1.lab.test".into(),
            usn: 42,
        },
        folder: folder(),
    }
}

fn state(path: &str, nature: Option<bool>, content: Option<&[u8]>) -> (String, State) {
    (
        sysvol::key(path),
        State {
            path: path.to_owned(),
            nature,
            descriptor: Some(b"sd".to_vec()),
            content: content.map(<[u8]>::to_vec),
            children: None,
        },
    )
}

fn read(gpo: GpoRead, part: Part, states: Vec<(String, State)>) -> ContentRead {
    ContentRead {
        gpo,
        part,
        gpt_ini: Some(b"[General]\r\nVersion=0\r\n".to_vec()),
        states: Arc::new(states.into_iter().collect()),
    }
}

fn base(extra: Vec<(String, State)>) -> Vec<(String, State)> {
    let mut states = vec![
        state(&folder(), Some(true), None),
        state(&machine(), Some(true), None),
        state(&format!("{}\\User", folder()), Some(true), None),
        state(&format!("{}\\Machine\\Registry.pol", folder()), None, None),
        state(&format!("{}\\User\\Registry.pol", folder()), None, None),
    ];
    states.extend(extra);
    states
}

fn entry(name: &str, v: u32) -> Entry {
    Entry {
        key: KEY.into(),
        value_name: name.into(),
        rtype: rp::REG_DWORD,
        data: v.to_le_bytes().to_vec(),
    }
}

fn set(entries: Vec<Entry>) -> impl Fn(Vec<Entry>) -> Vec<Entry> {
    move |mut current| {
        for e in &entries {
            current = rp::set(&current, e.clone());
        }
        current
    }
}

#[test]
fn modified_versions() {
    let (c, u) = (Part::Computer, Part::User);
    assert_eq!(modified_version(0, None, c), 1);
    assert_eq!(modified_version(0, Some(0), u), 1 << 16);
    assert_eq!(
        modified_version((3 << 16) | 5, Some((1 << 16) | 9), c),
        (3 << 16) | 10
    );
    assert_eq!(
        modified_version((3 << 16) | 5, Some((8 << 16) | 9), u),
        (9 << 16) | 5
    );
    assert_eq!(modified_version(0xFFFF, None, c), 1);
}

#[test]
fn registry_written_with_version_and_extension() {
    let r = read(gpo("0", "0", None), Part::Computer, base(Vec::new()));
    let new = entry("Valeur", 1);
    let change = modify_registry(&r, &set(vec![new.clone()])).unwrap();
    let cs = write_content(&r, &change, &English).unwrap();
    let [pol, gpt, object] = cs.operations.as_slice() else {
        panic!("{:?}", cs.operations)
    };
    let Operation::WriteFile {
        path,
        content,
        old,
        descriptor,
        ..
    } = pol
    else {
        panic!()
    };
    assert_eq!(path, &format!("{}\\Registry.pol", machine()));
    assert!(old.is_none() && *content == rp::encode(&[new]).unwrap());
    assert_eq!(
        descriptor.as_ref().unwrap(),
        &gw::file_bytes(&descriptor_bytes()).unwrap()
    );
    let Operation::WriteFile { content, old, .. } = gpt else {
        panic!()
    };
    assert_eq!(old.as_deref(), Some(&b"[General]\r\nVersion=0\r\n"[..]));
    assert_eq!(content, b"[General]\r\nVersion=1\r\n");
    let Operation::Modify {
        changes,
        read: Some(read),
        ..
    } = object
    else {
        panic!()
    };
    assert_eq!(read.usn, 42);
    let added: Vec<(&str, &[Vec<u8>])> = changes
        .iter()
        .map(|c| (c.attribute.as_str(), c.added.as_slice()))
        .collect();
    let ext = format!(
        "[{}{}]",
        extensions::REGISTRY,
        extensions::REGISTRY_TOOL_MACHINE
    );
    assert_eq!(
        added,
        [
            ("versionNumber", &[b"1".to_vec()][..]),
            ("gPCMachineExtensionNames", &[ext.into_bytes()][..]),
        ]
    );
    assert!(cs.remarks.iter().any(|r| r.contains("version 0 → 1")));
}

fn descriptor_bytes() -> Vec<u8> {
    descriptor()
}

#[test]
fn second_value_replaces_the_file_and_keeps_the_extension() {
    let first = rp::encode(&[entry("A", 1)]).unwrap();
    let ext = format!(
        "[{}{}]",
        extensions::REGISTRY,
        extensions::REGISTRY_TOOL_MACHINE
    );
    let r = read(
        gpo("1", "0", Some(&ext)),
        Part::Computer,
        base(vec![state(
            &format!("{}\\Registry.pol", machine()),
            Some(false),
            Some(&first),
        )]),
    );
    let change = modify_registry(&r, &set(vec![entry("B", 2)])).unwrap();
    let cs = write_content(&r, &change, &English).unwrap();
    let Operation::WriteFile { old, .. } = &cs.operations[0] else {
        panic!()
    };
    assert_eq!(old.as_deref(), Some(first.as_slice()));
    let Some(Operation::Modify { changes, .. }) = cs.operations.last() else {
        panic!()
    };
    let names: Vec<&str> = changes.iter().map(|c| c.attribute.as_str()).collect();
    assert_eq!(names, ["versionNumber"]);
}

#[test]
fn both_parts_in_one_changeset() {
    let states = base(Vec::new());
    let g = gpo("0", "0", None);
    let mut parts = BTreeMap::new();
    for part in [Part::User, Part::Computer] {
        let r = read(g.clone(), part, states.clone());
        let c = modify_registry(&r, &set(vec![entry("V", 1)])).unwrap();
        parts.insert(order(part), (r, c));
    }
    let cs = write_contents(&parts, &English).unwrap();
    let kinds: Vec<bool> = cs
        .operations
        .iter()
        .map(|o| matches!(o, Operation::WriteFile { .. }))
        .collect();
    assert_eq!(kinds, [true, true, true, false]);
    let Operation::WriteFile { path, .. } = &cs.operations[0] else {
        panic!()
    };
    assert!(path.contains("\\Machine\\"));
    let Some(Operation::Modify { changes, .. }) = cs.operations.last() else {
        panic!()
    };
    let names: Vec<&str> = changes.iter().map(|c| c.attribute.as_str()).collect();
    assert_eq!(
        names,
        [
            "versionNumber",
            "gPCMachineExtensionNames",
            "gPCUserExtensionNames"
        ]
    );
    assert_eq!(changes[0].added, [b"65537".to_vec()]);
}

#[test]
fn nothing_to_write() {
    let r = read(gpo("0", "0", None), Part::Computer, base(Vec::new()));
    let change = modify_registry(&r, &|x| x).unwrap();
    assert!(
        write_content(&r, &change, &English)
            .unwrap()
            .operations
            .is_empty()
    );
    let r = read(
        gpo("0", "0", None),
        Part::Computer,
        base(vec![state(&format!("{}\\a.ini", machine()), None, None)]),
    );
    let change = ContentChange {
        files: vec![("a.ini".into(), None)],
        ..ContentChange::default()
    };
    assert!(
        write_content(&r, &change, &English)
            .unwrap()
            .operations
            .is_empty()
    );
}

#[test]
fn folders_created_and_file_deleted() {
    let inf: Vec<u8> = "\u{feff}[Unicode]\r\nUnicode=yes\r\n"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let secedit: Pair = (
        "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}".into(),
        "{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}".into(),
    );
    let path = format!("{}\\{SECEDIT}", machine());
    let mut states = vec![
        state(&folder(), Some(true), None),
        state(&machine(), None, None),
        state(&format!("{}\\Microsoft", machine()), None, None),
        state(&format!("{}\\Microsoft\\Windows NT", machine()), None, None),
        state(
            &format!("{}\\Microsoft\\Windows NT\\SecEdit", machine()),
            None,
            None,
        ),
        state(&path, None, None),
    ];
    let r = read(gpo("0", "0", None), Part::Computer, states.clone());
    assert_eq!(r.content(SECEDIT).unwrap(), None);
    let change = ContentChange {
        files: vec![(SECEDIT.into(), Some(inf.clone()))],
        add_extensions: vec![secedit.clone()],
        ..ContentChange::default()
    };
    let cs = write_content(&r, &change, &English).unwrap();
    let created: Vec<&str> = cs
        .operations
        .iter()
        .filter_map(|o| match o {
            Operation::CreateFolder { path, .. } => Some(path.as_str()),
            _ => None,
        })
        .collect();
    let m = machine();
    assert_eq!(
        created,
        [
            m.clone(),
            format!("{m}\\Microsoft"),
            format!("{m}\\Microsoft\\Windows NT"),
            format!("{m}\\Microsoft\\Windows NT\\SecEdit"),
        ]
    );
    // Then deleted: the last pair of the part goes.
    states.retain(|(k, _)| *k != sysvol::key(&path));
    states.push(state(&path, Some(false), Some(&inf)));
    let ext = extensions::encode(&extensions::with(&[], std::slice::from_ref(&secedit), &[]));
    let r = read(gpo("2", "0", Some(&ext)), Part::Computer, states);
    let change = ContentChange {
        files: vec![(SECEDIT.into(), None)],
        remove_extensions: vec![secedit],
        ..ContentChange::default()
    };
    let cs = write_content(&r, &change, &English).unwrap();
    let Operation::DeleteFile {
        content,
        descriptor,
        ..
    } = &cs.operations[0]
    else {
        panic!()
    };
    assert!(*content == inf && descriptor.is_some());
    let Some(Operation::Modify { changes, .. }) = cs.operations.last() else {
        panic!()
    };
    assert!(changes[1].added.is_empty() && changes[1].attribute == "gPCMachineExtensionNames");
}

#[test]
fn diverging_versions_and_disabled_part() {
    let mut r = read(gpo("0", "2", None), Part::Computer, base(Vec::new()));
    r.gpt_ini = Some(b"[General]\r\nVersion=7\r\ndisplayName=Nouvel \xe9\r\n".to_vec());
    let change = modify_registry(&r, &set(vec![entry("V", 1)])).unwrap();
    let cs = write_content(&r, &change, &English).unwrap();
    let Operation::WriteFile { content, .. } = &cs.operations[1] else {
        panic!()
    };
    assert_eq!(
        content,
        b"[General]\r\nVersion=8\r\ndisplayName=Nouvel \xe9\r\n"
    );
    assert!(cs.remarks.iter().any(|r| r.contains("differed")));
    assert!(cs.remarks.iter().any(|r| r.contains("disabled")));
}

#[test]
fn folder_of_the_gpo_absent() {
    let r = read(
        gpo("0", "0", None),
        Part::Computer,
        vec![state(&folder(), None, None)],
    );
    let change = ContentChange {
        files: vec![("x".into(), Some(b"x".to_vec()))],
        ..ContentChange::default()
    };
    assert!(matches!(
        write_content(&r, &change, &English),
        Err(GpoError::FolderAbsent { .. })
    ));
    assert!(matches!(
        r.content("autre.ini"),
        Err(GpoError::NotRead { .. })
    ));
}

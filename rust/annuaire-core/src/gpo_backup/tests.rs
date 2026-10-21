// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Backups and restorations of a GPO, without network (`test_gpo_ecriture.py`, J5.6).

use super::*;
use crate::messages::English;

const GUID: &str = "{11111111-2222-3333-4444-555555555555}";
const BASE: &str = "DC=lab,DC=test";

fn sd(owner: &str) -> Vec<u8> {
    sddl::sd_from_sddl(
        &format!("O:{owner}G:{owner}D:P(A;CI;LCRPLORC;;;AU)"),
        None,
        false,
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn backup() -> Backup {
    Backup {
        date: "2026-10-16T12:34:56Z".into(),
        domain: "lab.test".into(),
        dc: "dc1.lab.test".into(),
        guid: GUID.into(),
        dn: gpo_dn(BASE, GUID),
        name: "Fond d'écran / Paris".into(),
        attributes: vec![
            (
                "displayName".into(),
                vec![b"Fond d'\xc3\xa9cran / Paris".to_vec()],
            ),
            ("versionNumber".into(), vec![b"65538".to_vec()]),
            ("flags".into(), vec![b"0".to_vec()]),
        ],
        descriptor: sd("BA"),
        objects: vec![
            (
                "CN=Machine".into(),
                vec![("objectClass".into(), vec![b"container".to_vec()])],
            ),
            (
                "CN=User".into(),
                vec![("objectClass".into(), vec![b"container".to_vec()])],
            ),
        ],
        elements: vec![
            SavedElement {
                path: String::new(),
                directory: true,
                descriptor: Some(sd("SY")),
                content: None,
            },
            SavedElement {
                path: "GPT.INI".into(),
                directory: false,
                descriptor: Some(sd("SY")),
                content: Some(b"[General]\r\nVersion=65538\r\n".to_vec()),
            },
            SavedElement {
                path: "Machine".into(),
                directory: true,
                descriptor: Some(sd("SY")),
                content: None,
            },
            SavedElement {
                path: "Machine\\Registry.pol".into(),
                directory: false,
                descriptor: Some(sd("SY")),
                content: Some(b"PReg\x01\x00\x00\x00machine".to_vec()),
            },
        ],
        links: vec![SavedLink {
            container: "OU=Paris,DC=lab,DC=test".into(),
            order: 1,
            options: 2,
        }],
    }
}

fn temporary() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("annuaire-sauvegarde-{}", new_guid()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn versions_names_and_dates() {
    assert_eq!(next_version(0, 0), (1 << 16) | 1);
    assert_eq!(next_version((2 << 16) | 9, (5 << 16) | 1), (6 << 16) | 10);
    assert_eq!(
        file_name(&backup()),
        format!("20261016T123456Z_Fond-d-écran-Paris_{GUID}.tar.gz")
    );
    assert_eq!(unix_seconds("1970-01-02T00:00:01Z"), 86_401);
    assert_eq!(unix_seconds("2026-10-16T12:34:56Z"), 1_792_154_096);
    assert!(now().ends_with('Z'));
}

#[test]
fn archive_round_trip_and_checks() {
    let dir = temporary();
    let saved = backup();
    let path = write_archive(&saved, &dir).unwrap();
    assert_eq!(list_archives(&dir), std::slice::from_ref(&path));
    assert!(matches!(
        write_archive(&saved, &dir),
        Err(BackupError::ArchiveExists(_))
    ));
    use std::os::unix::fs::PermissionsExt as _;
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(read_archive(&path).unwrap(), saved);

    // An altered file is refused.
    let mut altered = saved.clone();
    altered.elements[3].content = Some(b"PReg other".to_vec());
    let bytes = archive_bytes(&altered).unwrap();
    let original = archive_bytes(&saved).unwrap();
    let mut doc_from_saved = {
        let mut a = tar::Archive::new(flate2::read::GzDecoder::new(&original[..]));
        let mut entry = a.entries().unwrap().next().unwrap().unwrap();
        let mut text = Vec::new();
        entry.read_to_end(&mut text).unwrap();
        text
    };
    // The manifest of the original with the content of the altered one.
    let mut rebuilt = tar::Builder::new(flate2::write::GzEncoder::new(
        Vec::new(),
        flate2::Compression::default(),
    ));
    let mut a = tar::Archive::new(flate2::read::GzDecoder::new(&bytes[..]));
    for (i, entry) in a.entries().unwrap().enumerate() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        let mut data = Vec::new();
        entry.read_to_end(&mut data).unwrap();
        if i == 0 {
            data = std::mem::take(&mut doc_from_saved);
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(data.len() as u64);
        header.set_mode(0o600);
        rebuilt.append_data(&mut header, &name, &data[..]).unwrap();
    }
    let forged = dir.join("forged_{X}.tar.gz");
    std::fs::write(&forged, rebuilt.into_inner().unwrap().finish().unwrap()).unwrap();
    assert!(matches!(
        read_archive(&forged),
        Err(BackupError::UnexpectedSize(_) | BackupError::Altered(_))
    ));
    std::fs::write(&forged, b"not an archive").unwrap();
    assert!(matches!(
        read_archive(&forged),
        Err(BackupError::Unreadable(_))
    ));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn restoration_of_an_absent_gpo_and_a_copy() {
    let saved = backup();
    let same = restore_absent(&saved, BASE, None, None, &English).unwrap();
    let paths: Vec<String> = same
        .operations
        .iter()
        .map(|op| op.path().map_or_else(|| op.dn().to_owned(), str::to_owned))
        .collect();
    let root = "lab.test\\Policies\\{11111111-2222-3333-4444-555555555555}";
    assert_eq!(
        paths,
        [
            gpo_dn(BASE, GUID),
            format!("CN=Machine,{}", gpo_dn(BASE, GUID)),
            format!("CN=User,{}", gpo_dn(BASE, GUID)),
            root.to_owned(),
            format!("{root}\\Machine"),
            format!("{root}\\GPT.INI"),
            format!("{root}\\Machine\\Registry.pol"),
        ]
    );
    assert_eq!(same.remarks.len(), 2);
    let Operation::CreateFolder { descriptor, .. } = &same.operations[3] else {
        panic!("folder expected");
    };
    assert_eq!(descriptor.as_deref(), Some(&sd("SY")[..]));

    let copy = restore_absent(&saved, BASE, Some("{AB}"), Some("Copie"), &English).unwrap();
    let Operation::Add { dn, attributes } = &copy.operations[0] else {
        panic!("add expected");
    };
    assert_eq!(dn, &gpo_dn(BASE, "{AB}"));
    assert!(attributes.contains(&("displayName".into(), vec![b"Copie".to_vec()])));
    let Operation::CreateFolder { descriptor, .. } = &copy.operations[3] else {
        panic!("folder expected");
    };
    // A copy: the ACL computed from the descriptor of the GPO.
    assert_eq!(
        descriptor.as_deref(),
        Some(&gpo_write::file_bytes(&saved.descriptor).unwrap()[..])
    );
}

#[test]
fn restoration_of_an_existing_gpo() {
    let saved = backup();
    let root = "lab.test\\Policies\\{11111111-2222-3333-4444-555555555555}".to_owned();
    let read = Read {
        dc: "dc1".into(),
        usn: 7,
    };
    let gpo = GpoRead {
        dn: gpo_dn(BASE, GUID),
        attributes: vec![
            ("displayName".into(), vec![b"Autre nom".to_vec()]),
            ("versionNumber".into(), vec![b"131075".to_vec()]),
            ("flags".into(), vec![b"0".to_vec()]),
            (SD.into(), vec![sd("BA")]),
        ],
        read: read.clone(),
        folder: root.clone(),
    };
    let element = |path: &str, directory: bool, content: Option<&[u8]>| Element {
        path: if path.is_empty() {
            root.clone()
        } else {
            format!("{root}\\{path}")
        },
        directory,
        size: 0,
        content: content.map(<[u8]>::to_vec),
        descriptor: Some(sd("SY")),
    };
    let present = [
        element("", true, None),
        element("GPT.INI", false, Some(b"[General]\r\nVersion=131075\r\n")),
        element("Machine", true, None),
        element("User", true, None),
        element("User\\extra.ini", false, Some(b"x")),
    ];
    let objects = vec![(
        format!("CN=Machine,{}", gpo_dn(BASE, GUID)),
        read.clone(),
        Vec::new(),
    )];
    let cs = restore_existing(&saved, &gpo, &objects, &present, &English).unwrap();
    // Version above both: user max(2, 1) + 1, computer max(3, 2) + 1.
    let version = (3 << 16) | 4;
    let Operation::Modify { changes, .. } = &cs.operations[0] else {
        panic!("modification expected");
    };
    let names: Vec<&str> = changes.iter().map(|c| c.attribute.as_str()).collect();
    assert_eq!(names, ["displayName", "versionNumber"]);
    assert_eq!(changes[1].added, [version.to_string().into_bytes()]);
    assert_eq!(cs.operations.len(), 6, "{:?}", cs.operations);
    assert!(matches!(&cs.operations[1], Operation::Add { dn, .. } if dn.starts_with("CN=User,")));
    assert!(
        matches!(&cs.operations[2], Operation::DeleteFile { path, .. } if path.ends_with("extra.ini"))
    );
    assert!(
        matches!(&cs.operations[3], Operation::DeleteFolder { path, .. } if path.ends_with("\\User"))
    );
    let Operation::WriteFile { content, old, .. } = &cs.operations[4] else {
        panic!("GPT.INI expected");
    };
    assert_eq!(
        content,
        format!("[General]\r\nVersion={version}\r\n").as_bytes()
    );
    assert!(old.is_some());
    assert!(
        matches!(&cs.operations[5], Operation::WriteFile { path, old: None, .. } if path.ends_with("Registry.pol"))
    );
    assert!(cs.remarks[0].contains(&version.to_string()));
}

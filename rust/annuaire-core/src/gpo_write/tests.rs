// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The pure part of the writes on the GPOs (`test_gpo_ecriture.py`): `dsacl2fsacl` against
//! the vectors of Samba, the descriptor of a creation, the filtering, the links.

use std::path::PathBuf;

use serde_json::Value;

use super::*;
use crate::messages::English;

const DOMAIN_SID: &str = "S-1-5-21-1094140757-505220614-2701386893";
/// `defaultSecurityDescriptor` of `groupPolicyContainer` on the lab (Samba 4.22).
const DEFAULT: &str = "D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)\
(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)\
(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)";
/// Descriptor (without SACL) of the GPOs of the lab, created by the GPMC or by samba-tool.
const SD_GPO_LAB: &str = "O:DAG:DAD:P(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;EA)\
(A;CIIO;CCDCLCSWRPWPDTLOSDRCWDWO;;;CO)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)\
(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;SY)(A;CI;LCRPLORC;;;AU)\
(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)";
const BASE: &str = "DC=lab,DC=test";
const OU: &str = "OU=Liee,DC=lab,DC=test";

fn domain() -> Sid {
    DOMAIN_SID.parse().unwrap()
}

fn to_sddl(sd: &SecurityDescriptor) -> String {
    sddl::sd_to_sddl(sd, Some(&domain())).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn paths() {
    assert_eq!(gpo_folder("LAB.test", "{abc}"), "lab.test\\Policies\\{ABC}");
    let unc = unc_path("lab.test", "{abc}");
    assert_eq!(unc, "\\\\lab.test\\SysVol\\lab.test\\Policies\\{ABC}");
    assert_eq!(from_unc(&unc).as_deref(), Some("lab.test\\Policies\\{ABC}"));
    assert_eq!(
        from_unc("\\\\dc1.lab.test\\sysvol\\lab.test\\Policies\\{X}\\").as_deref(),
        Some("lab.test\\Policies\\{X}")
    );
    assert_eq!(from_unc("\\\\lab.test\\NETLOGON\\x"), None);
    let guid = new_guid();
    assert!(gpo::is_folder_guid(&guid), "{guid}");
    assert_eq!(guid, guid.to_uppercase());
    assert_eq!(guid_of(&gpo_dn(BASE, "{abc}")), "{ABC}");
}

#[test]
fn file_descriptor_as_samba() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/vecteurs/fsacl.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = doc["vecteurs"].as_array().unwrap();
    assert!(!vectors.is_empty());
    for v in vectors {
        let sd = SecurityDescriptor::decode(&hex(v["hex"].as_str().unwrap())).unwrap();
        let expected = &v["attendu"];
        assert_eq!(to_sddl(&sd), expected["sddl"].as_str().unwrap());
        let Some(dacl_hex) = expected["fichier_dacl_hex"].as_str() else {
            assert!(matches!(file_descriptor(&sd), Err(GpoError::NoPermission)));
            continue;
        };
        let file = file_descriptor(&sd).unwrap();
        assert_eq!(to_sddl(&file), expected["fichier_sddl"].as_str().unwrap());
        let raw = file.encode().unwrap();
        let offset = u32::from_le_bytes(raw[16..20].try_into().unwrap()) as usize;
        let tail: String = raw[offset..].iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(tail, dacl_hex, "{}", v["id"]);
    }
}

#[test]
fn masks_and_creation_descriptor() {
    let full = sddl::mask_from_sddl("CCDCLCSWRPWPDTLOSDRCWDWO").unwrap();
    assert_eq!(file_mask(full), 0x1F_01FF);
    assert_eq!(
        file_mask(sddl::mask_from_sddl("LCRPLORC").unwrap()),
        0x12_00A9
    );
    assert_eq!(file_mask(sd::ADS_RIGHT_DS_CONTROL_ACCESS), 0);
    let sd = creation_descriptor(DEFAULT, &domain()).unwrap();
    assert_eq!(to_sddl(&sd), SD_GPO_LAB);
}

#[test]
fn creation() {
    let cs = create(
        BASE,
        &domain(),
        DEFAULT,
        "  Essai  ",
        Some("{11111111-2222-3333-4444-555555555555}"),
        &English,
    )
    .unwrap();
    let kinds: Vec<String> = cs
        .operations
        .iter()
        .map(|op| format!("{} {}", op.dn(), op.path().unwrap_or_default()))
        .collect();
    let gpo = "CN={11111111-2222-3333-4444-555555555555},CN=Policies,CN=System,DC=lab,DC=test";
    let folder = "lab.test\\Policies\\{11111111-2222-3333-4444-555555555555}";
    assert_eq!(
        kinds,
        [
            format!("{gpo} "),
            format!("CN=User,{gpo} "),
            format!("CN=Machine,{gpo} "),
            format!("{gpo} {folder}"),
            format!("{gpo} {folder}\\Machine"),
            format!("{gpo} {folder}\\User"),
            format!("{gpo} {folder}\\GPT.INI"),
        ]
    );
    let Operation::Add { attributes, .. } = &cs.operations[0] else {
        panic!("add expected");
    };
    let get = |a: &str| attributes.iter().find(|(x, _)| x == a).unwrap().1[0].clone();
    assert_eq!(get("displayName"), b"Essai");
    assert_eq!(
        get("gPCFileSysPath"),
        b"\\\\lab.test\\SysVol\\lab.test\\Policies\\{11111111-2222-3333-4444-555555555555}"
    );
    let Operation::WriteFile {
        content,
        descriptor,
        ..
    } = &cs.operations[6]
    else {
        panic!("file expected");
    };
    assert_eq!(content, NEW_GPT_INI);
    let file_sd = SecurityDescriptor::decode(descriptor.as_ref().unwrap()).unwrap();
    assert!(to_sddl(&file_sd).starts_with("O:DAG:DAD:P"));
    assert!(matches!(
        create(BASE, &domain(), DEFAULT, " ", None, &English),
        Err(GpoError::EmptyName)
    ));
    assert_eq!(cs.remarks.len(), 1);
}

#[test]
fn filtering_read_and_written() {
    let lab = sddl::sd_from_sddl(SD_GPO_LAB, Some(&domain()), false).unwrap();
    assert_eq!(applying(&lab), [authenticated_users()]);
    let deny = Ace::object(
        sd::ACCESS_DENIED_OBJECT,
        sd::ADS_RIGHT_DS_CONTROL_ACCESS,
        &authenticated_users(),
        0,
        Some(gpo::right_apply()),
        None,
    )
    .unwrap();
    assert!(applying(&lab.add_aces(&[deny]).unwrap()).is_empty());

    let raw = lab.encode().unwrap();
    let gpo_dn = gpo_dn(BASE, "{11111111-2222-3333-4444-555555555555}");
    let gpo = GpoRead {
        dn: gpo_dn.clone(),
        attributes: vec![(SD.into(), vec![raw.clone()])],
        read: Read {
            dc: "dc1.lab.test".into(),
            usn: 42,
        },
        folder: "lab.test\\Policies\\{11111111-2222-3333-4444-555555555555}".into(),
    };
    let folder_sd = file_bytes(&raw).unwrap();
    let elements = vec![
        Element {
            path: gpo.folder.clone(),
            directory: true,
            size: 0,
            content: None,
            descriptor: Some(folder_sd.clone()),
        },
        Element {
            path: format!("{}\\GPT.INI", gpo.folder),
            directory: false,
            size: 22,
            content: None,
            descriptor: Some(b"other".to_vec()),
        },
    ];
    let group: Sid = format!("{DOMAIN_SID}-1105").parse().unwrap();
    let cs = filter(
        &gpo,
        &elements,
        &[group],
        &[authenticated_users()],
        &English,
    )
    .unwrap();
    // The object, then the ACL of both elements (their descriptor changes with the object).
    assert_eq!(cs.operations.len(), 3);
    assert!(
        matches!(&cs.operations[1], Operation::SetDescriptor { path, .. } if *path == gpo.folder)
    );
    assert_eq!(
        cs.remarks,
        [English.text(&Msg::GpoAuthenticatedUsersCannotRead)]
    );
    // Nothing to do: an empty changeset.
    assert!(
        filter(&gpo, &elements, &[authenticated_users()], &[], &English)
            .unwrap()
            .operations
            .is_empty()
    );
    let nobody = filter(&gpo, &elements, &[], &[authenticated_users()], &English).unwrap();
    assert_eq!(nobody.remarks.len(), 2);
}

const GPO_A: &str =
    "CN={AAAAAAAA-0000-0000-0000-000000000001},CN=Policies,CN=System,DC=lab,DC=test";
const GPO_B: &str =
    "CN={BBBBBBBB-0000-0000-0000-000000000002},CN=Policies,CN=System,DC=lab,DC=test";
const GPO_C: &str =
    "CN={CCCCCCCC-0000-0000-0000-000000000003},CN=Policies,CN=System,DC=lab,DC=test";

fn container(gplink: Option<&str>, gpoptions: Option<&str>) -> ContainerRead {
    ContainerRead {
        dn: OU.into(),
        gplink: gplink.map(|t| t.as_bytes().to_vec()),
        gpoptions: gpoptions.map(|t| t.as_bytes().to_vec()),
        read: Read {
            dc: "dc1.lab.test".into(),
            usn: 42,
        },
    }
}

/// The value written by a one-operation changeset (None: cleared).
fn after(cs: &Changeset) -> Option<String> {
    let [Operation::Modify { changes, read, .. }] = cs.operations.as_slice() else {
        panic!("one modification expected: {cs:?}");
    };
    assert_eq!(read.as_ref().map(|r| r.usn), Some(42));
    let [c] = changes.as_slice() else {
        panic!("one change expected");
    };
    c.added
        .first()
        .map(|v| String::from_utf8(v.clone()).unwrap())
}

#[test]
fn link_and_unlink() {
    let empty = container(None, None);
    let cs = modify_links(&empty, &link_gpo(GPO_A, 0)).unwrap();
    assert_eq!(after(&cs).unwrap(), format!("[LDAP://{GPO_A};0]"));
    let one = container(Some(&format!("[LDAP://{GPO_A};0]")), None);
    assert!(matches!(
        modify_links(&one, &link_gpo(&GPO_A.to_lowercase(), 0)),
        Err(GpoError::AlreadyLinked)
    ));
    let two = modify_links(&one, &link_gpo(GPO_B, 0)).unwrap();
    assert_eq!(
        after(&two).unwrap(),
        format!("[LDAP://{GPO_B};0][LDAP://{GPO_A};0]")
    );
    let cleared = modify_links(&one, &unlink(GPO_A)).unwrap();
    assert_eq!(after(&cleared), None);
    assert!(
        modify_links(&one, &unlink(GPO_B))
            .unwrap()
            .operations
            .is_empty()
    );
}

#[test]
fn order_options_inheritance() {
    let three = container(
        Some(&format!(
            "[LDAP://{GPO_C};0][LDAP://{GPO_B};0][LDAP://{GPO_A};0]"
        )),
        None,
    );
    // GPMC order: A (1), B (2), C (3).
    assert_eq!(
        after(&modify_links(&three, &move_down(GPO_A)).unwrap()).unwrap(),
        format!("[LDAP://{GPO_C};0][LDAP://{GPO_A};0][LDAP://{GPO_B};0]")
    );
    assert_eq!(
        after(&modify_links(&three, &move_up(GPO_C)).unwrap()).unwrap(),
        format!("[LDAP://{GPO_B};0][LDAP://{GPO_C};0][LDAP://{GPO_A};0]")
    );
    assert!(
        modify_links(&three, &move_up(GPO_A))
            .unwrap()
            .operations
            .is_empty()
    );
    assert!(
        modify_links(&three, &move_down(GPO_C))
            .unwrap()
            .operations
            .is_empty()
    );
    assert_eq!(
        after(&modify_links(&three, &move_link(GPO_C, 1)).unwrap()).unwrap(),
        format!("[LDAP://{GPO_B};0][LDAP://{GPO_A};0][LDAP://{GPO_C};0]")
    );
    let options = modify_links(&three, &link_options(GPO_B, Some(true), Some(true))).unwrap();
    assert!(
        after(&options)
            .unwrap()
            .contains(&format!("[LDAP://{GPO_B};3]"))
    );
    assert!(matches!(
        modify_links(
            &container(None, None),
            &link_options(GPO_B, None, Some(true))
        ),
        Err(GpoError::NoLongerLinked)
    ));
    assert_eq!(
        after(&block_inheritance(&container(None, None), true).unwrap()).as_deref(),
        Some("1")
    );
    assert_eq!(
        after(&block_inheritance(&container(None, Some("1")), false).unwrap()).as_deref(),
        Some("0")
    );
    assert!(
        block_inheritance(&container(None, Some("0")), false)
            .unwrap()
            .operations
            .is_empty()
    );
}

#[test]
fn deletion_removes_the_links() {
    let linked = container(
        Some(&format!(
            "[LDAP://{GPO_A};0][LDAP://{GPO_B};2][LDAP://{};1]",
            GPO_A.to_lowercase()
        )),
        None,
    );
    let op = without_link(&linked, "{AAAAAAAA-0000-0000-0000-000000000001}")
        .unwrap()
        .unwrap();
    let Operation::Modify { changes, .. } = op else {
        panic!("modification expected");
    };
    assert_eq!(
        changes[0].added,
        [format!("[LDAP://{GPO_B};2]").into_bytes()]
    );
    assert!(
        without_link(
            &container(Some(&format!("[LDAP://{GPO_B};0]")), None),
            "{AAAAAAAA-0000-0000-0000-000000000001}"
        )
        .unwrap()
        .is_none()
    );
}

#[test]
fn orphans_and_folder_deletion() {
    let root = "lab.test\\Policies\\{AAAAAAAA-0000-0000-0000-000000000001}";
    let element = |path: &str, directory: bool| Element {
        path: path.to_owned(),
        directory,
        size: 0,
        content: (!directory).then(|| b"x".to_vec()),
        descriptor: Some(b"sd".to_vec()),
    };
    let found = vec![
        element(root, true),
        element(&format!("{root}\\Machine"), true),
        element(&format!("{root}\\Machine\\Registry.pol"), false),
        element(&format!("{root}\\GPT.INI"), false),
    ];
    let ops = folder_deletion("CN=x", &found);
    let paths: Vec<&str> = ops.iter().filter_map(Operation::path).collect();
    assert_eq!(paths[0], format!("{root}\\Machine\\Registry.pol"));
    assert_eq!(*paths.last().unwrap(), root);
    let cs = remove_orphans(BASE, &[found.clone(), Vec::new()], &English);
    assert_eq!(cs.operations.len(), 4);
    assert_eq!(cs.operations[0].dn(), GPO_A);
    assert!(cs.remarks[0].contains("{AAAAAAAA-0000-0000-0000-000000000001}"));
    let one = delete_orphan(
        BASE,
        "{aaaaaaaa-0000-0000-0000-000000000001}",
        &found,
        "dc1",
        2,
        &English,
    )
    .unwrap();
    assert_eq!(one.remarks.len(), 2);
    assert!(matches!(
        delete_orphan(BASE, "{A}", &[], "dc1", 0, &English),
        Err(GpoError::OrphanGone { .. })
    ));
}

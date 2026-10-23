// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The SYSVOL part of the writer against the fake SMB server (`test_gpo_ecriture.py`, the
//! cases of `ecriture_sysvol`).

use std::sync::Mutex;

use annuaire_codecs::Sid;
use annuaire_codecs::sd::{self, Acl, SecurityDescriptor};

use super::*;
use crate::changes::ErrorRecord;
use crate::error::LdapError;
use crate::messages::{Catalog, English, Msg};
use crate::smb::fake_server::{DEFAULT_SD, FakeAuth, FakeServer, Fs};
use crate::smb::{Client, Options};

#[derive(Debug)]
struct Texts;

impl Catalog for Texts {
    fn text(&self, msg: &Msg) -> String {
        English.text(msg)
    }
}

impl WriteCatalog for Texts {
    fn write_text(&self, msg: &WriteMsg) -> String {
        format!("{msg:?}")
    }
    fn ldap_error(&self, error: &LdapError, _dc: &str) -> ErrorRecord {
        record("ErreurLDAP", error.to_string(), "")
    }
}

/// A session on the fake server: the opener hands over the client connected beforehand.
fn session(fs: Fs) -> (FakeServer, SysvolSession) {
    let server = FakeServer::start(16, fs);
    let options = Options {
        port: server.port,
        ..Options::default()
    };
    let client = Client::connect(
        "127.0.0.1",
        sysvol::SHARE,
        &options,
        &mut FakeAuth::default(),
    )
    .expect("fake server");
    let ready = Mutex::new(Some(Session::from_client("127.0.0.1", client)));
    let opener: Opener = Arc::new(move |_dc: &str| {
        ready
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| SysvolError::status(status::ACCESS_DENIED, "second session"))
    });
    (server, SysvolSession::new(opener, "127.0.0.1"))
}

fn sid(text: &str) -> Sid {
    text.parse().unwrap()
}

fn descriptor(owner: &str, aces: &[sd::Ace], control: u16) -> Vec<u8> {
    SecurityDescriptor {
        revision: sd::REVISION,
        control: control | sd::SE_SELF_RELATIVE | sd::SE_DACL_PRESENT,
        owner: Some(sid(owner)),
        group: Some(sid(owner)),
        sacl: None,
        dacl: Some(Acl {
            revision: sd::ACL_REVISION,
            aces: aces.to_vec(),
        }),
    }
    .encode()
    .unwrap()
}

fn ace(who: &str, mask: u32) -> sd::Ace {
    sd::Ace::simple(sd::ACCESS_ALLOWED, mask, &sid(who), 0).unwrap()
}

#[test]
fn descriptors_compared_by_content() {
    let a = ace("S-1-5-11", 0x1200a9);
    let b = ace("S-1-5-18", 0x1f01ff);
    let one = descriptor("S-1-5-32-544", &[a.clone(), b.clone()], 0);
    // A repeated ACE and the « automatically inherited » bit do not count.
    let repeated = descriptor(
        "S-1-5-32-544",
        &[a.clone(), b.clone(), a.clone()],
        sd::SE_DACL_AUTO_INHERITED,
    );
    assert!(same_descriptor(Some(&one), Some(&repeated)));
    let protected = descriptor(
        "S-1-5-32-544",
        &[a.clone(), b.clone()],
        sd::SE_DACL_PROTECTED,
    );
    assert!(!same_descriptor(Some(&one), Some(&protected)));
    let other_owner = descriptor("S-1-5-18", &[a.clone(), b.clone()], 0);
    assert!(!same_descriptor(Some(&one), Some(&other_owner)));
    let other_order = descriptor("S-1-5-32-544", &[b, a], 0);
    assert!(!same_descriptor(Some(&one), Some(&other_order)));
    assert!(same_descriptor(None, None));
    assert!(!same_descriptor(Some(&one), None));
    // Undecodable: compared byte for byte.
    assert!(same_descriptor(Some(b"x"), Some(b"x")));
    assert_eq!(information(&one, &protected), sysvol::INFO_DACL);
    assert_eq!(
        information(&one, &other_owner),
        sysvol::INFO_OWNER | sysvol::INFO_GROUP
    );
    // Nothing changes: the DACL is written again.
    assert_eq!(information(&one, &one), sysvol::INFO_DACL);
    assert_eq!(information(b"x", &one), sysvol::INFO_OGD);
}

const GPO: &str = "d\\Policies\\{A}";
const INI: &str = "d\\Policies\\{A}\\GPT.INI";
const DN: &str = "CN={A},CN=Policies,CN=System,DC=d";

fn lab() -> Fs {
    Fs::with(&[
        ("d", None),
        ("d\\Policies", None),
        (GPO, None),
        (INI, Some(&b"[General]\r\nVersion=0\r\n"[..])),
        ("d\\Policies\\{A}\\Machine", None),
        ("d\\Policies\\{A}\\User", None),
    ])
}

fn create_folder(path: &str, sd: Option<&[u8]>) -> Operation {
    Operation::CreateFolder {
        dn: DN.into(),
        path: path.into(),
        descriptor: sd.map(<[u8]>::to_vec),
    }
}

fn write_file(path: &str, content: &[u8], old: Option<&[u8]>) -> Operation {
    Operation::WriteFile {
        dn: DN.into(),
        path: path.into(),
        content: content.to_vec(),
        old: old.map(<[u8]>::to_vec),
        descriptor: None,
    }
}

type Found = Vec<(usize, String, ProblemKind, WriteMsg)>;

fn verify(session: &mut SysvolSession, operations: &[Operation]) -> Found {
    let mut found = Vec::new();
    let mut view = View::new(session);
    let refs: Vec<&Operation> = operations.iter().collect();
    view.preload(&refs).unwrap();
    for (i, op) in operations.iter().enumerate() {
        check(&mut view, i, op, &mut |i, shown, kind, msg| {
            found.push((i, shown.to_owned(), kind, msg));
        })
        .unwrap();
    }
    found
}

#[test]
fn prior_verification() {
    let (server, mut session) = session(lab());
    // A folder, a file inside, a change of GPT.INI from its present content: nothing to say.
    let fine = [
        create_folder("d\\Policies\\{N}", None),
        write_file("d\\Policies\\{N}\\GPT.INI", b"v", None),
        write_file(
            INI,
            b"[General]\r\nVersion=1\r\n",
            Some(b"[General]\r\nVersion=0\r\n"),
        ),
    ];
    assert!(verify(&mut session, &fine).is_empty());
    let kinds = |found: Found| found.into_iter().map(|f| (f.0, f.2)).collect::<Vec<_>>();
    let wrong = [
        create_folder(GPO, None),                      // exists
        write_file("d\\Absent\\f", b"", None),         // no parent
        write_file(INI, b"x", Some(b"other content")), // changed since the preview
        Operation::DeleteFolder {
            dn: DN.into(),
            path: GPO.into(),
            descriptor: None,
        }, // not empty
        Operation::DeleteFile {
            dn: DN.into(),
            path: "d\\Policies\\{A}\\Machine".into(),
            content: Vec::new(),
            descriptor: None,
        }, // a folder
        Operation::SetDescriptor {
            dn: DN.into(),
            path: "d\\Policies\\{Z}".into(),
            before: Vec::new(),
            after: Vec::new(),
        }, // absent
    ];
    // Each alone: in one changeset, the effect of the first ones changes the next ones.
    let found: Vec<(usize, ProblemKind)> = wrong
        .iter()
        .enumerate()
        .flat_map(|(i, op)| {
            kinds(verify(&mut session, std::slice::from_ref(op)))
                .into_iter()
                .map(move |(_, k)| (i, k))
        })
        .collect();
    assert_eq!(
        found,
        [
            (0, ProblemKind::Exists),
            (1, ProblemKind::Target),
            (2, ProblemKind::Version),
            (3, ProblemKind::NotLeaf),
            (4, ProblemKind::Values),
            (4, ProblemKind::Version), // a folder has no content
            (5, ProblemKind::Missing),
        ]
    );
    // Emptied by the changeset first: the folder can go.
    let emptied = [
        Operation::DeleteFile {
            dn: DN.into(),
            path: INI.into(),
            content: b"[General]\r\nVersion=0\r\n".to_vec(),
            descriptor: Some(DEFAULT_SD.to_vec()),
        },
        Operation::DeleteFolder {
            dn: DN.into(),
            path: "d\\Policies\\{A}\\Machine".into(),
            descriptor: None,
        },
        Operation::DeleteFolder {
            dn: DN.into(),
            path: "d\\Policies\\{A}\\User".into(),
            descriptor: None,
        },
        Operation::DeleteFolder {
            dn: DN.into(),
            path: GPO.into(),
            descriptor: Some(DEFAULT_SD.to_vec()),
        },
    ];
    assert!(verify(&mut session, &emptied).is_empty());
    let shown = verify(&mut session, &wrong[..1]);
    assert_eq!(shown[0].1, "SYSVOL\\d\\Policies\\{A}");
    session.close();
    server.join();
}

#[test]
fn writes_guards_and_ascertaining() {
    let (server, mut session) = session(lab());
    let catalog = Texts;
    let new = "d\\Policies\\{N}";
    let ini = "d\\Policies\\{N}\\GPT.INI";
    // Creation with a descriptor, the guard of the next operation read in the same batch.
    let then = [(ini.to_owned(), Some(false))];
    let states = apply(
        &mut session,
        &create_folder(new, Some(b"SD of N")),
        None,
        &then,
        &catalog,
    )
    .unwrap();
    assert_eq!(states.len(), 1);
    assert_eq!(states[0].nature, None);
    apply(
        &mut session,
        &write_file(ini, b"v0", None),
        None,
        &[],
        &catalog,
    )
    .unwrap();
    // A replacement guarded by the old content.
    apply(
        &mut session,
        &write_file(ini, b"v1", Some(b"v0")),
        None,
        &[],
        &catalog,
    )
    .unwrap();
    match apply(
        &mut session,
        &write_file(ini, b"v2", Some(b"v0")),
        None,
        &[],
        &catalog,
    ) {
        Err(StepError::Conflict(r)) => assert_eq!(r.class, "ErreurConflit"),
        other => panic!("conflict expected: {other:?}"),
    }
    // A creation over an existing element: the server refuses, nothing was done.
    match apply(
        &mut session,
        &write_file(ini, b"x", None),
        None,
        &[],
        &catalog,
    ) {
        Err(StepError::Conflict(r)) => assert!(r.message.contains("SysvolChangedReadAgain")),
        other => panic!("conflict expected: {other:?}"),
    }
    let set = Operation::SetDescriptor {
        dn: DN.into(),
        path: ini.into(),
        before: DEFAULT_SD.to_vec(),
        after: b"new SD".to_vec(),
    };
    apply(&mut session, &set, None, &[], &catalog).unwrap();
    assert_eq!(ascertain(&mut session, &set).unwrap(), Some(true));
    assert_eq!(
        ascertain(&mut session, &write_file(ini, b"v1", Some(b"v0"))).unwrap(),
        Some(true)
    );
    assert_eq!(
        ascertain(&mut session, &write_file(ini, b"v0", Some(b"v1"))).unwrap(),
        Some(false)
    );
    assert_eq!(
        ascertain(&mut session, &write_file(ini, b"v9", Some(b"v8"))).unwrap(),
        None
    );
    let delete = Operation::DeleteFile {
        dn: DN.into(),
        path: ini.into(),
        content: b"v1".to_vec(),
        descriptor: Some(b"new SD".to_vec()),
    };
    apply(&mut session, &delete, None, &[], &catalog).unwrap();
    assert_eq!(ascertain(&mut session, &delete).unwrap(), Some(true));
    let folder = Operation::DeleteFolder {
        dn: DN.into(),
        path: new.into(),
        descriptor: Some(b"SD of N".to_vec()),
    };
    apply(&mut session, &folder, None, &[], &catalog).unwrap();
    assert_eq!(
        ascertain(&mut session, &create_folder(new, None)).unwrap(),
        Some(false)
    );
    session.close();
    assert!(server.fs.lock().unwrap().get(new).is_none());
    server.join();
}

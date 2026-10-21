// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `sd`, `sddl` and `condition` against the shared vectors (`sd`, `sddl`, `sddlwin`,
//! `fsacl`, `sddl_conditionnel`, `sddl_conditionnel_windows`), and the cases of
//! `tests/unitaires/test_codecs_sd.py` and `test_codecs_condition.py`.

#![allow(clippy::indexing_slicing)]

mod common;

use annuaire_codecs::condition::{self, ConditionError, Node};
use annuaire_codecs::sd::*;
use annuaire_codecs::sddl::{self, SddlError, sd_from_sddl, sd_to_sddl};
use annuaire_codecs::{Guid, Sid};
use common::{to_hex, vectors};
use serde_json::Value;

fn sid(text: &str) -> Sid {
    text.parse().unwrap()
}

fn guid(text: &str) -> Guid {
    text.parse().unwrap()
}

/// The domain of the lab (`dc1.lab.test`).
fn lab() -> Sid {
    sid("S-1-5-21-1094140757-505220614-2701386893")
}

fn text_of(s: Option<Sid>) -> Value {
    s.map_or(Value::Null, |s| Value::String(s.to_string()))
}

fn decode(bytes: &[u8]) -> SecurityDescriptor {
    SecurityDescriptor::decode(bytes).unwrap()
}

fn encode(sd: &SecurityDescriptor) -> Vec<u8> {
    sd.encode().unwrap()
}

fn aces(sd: &SecurityDescriptor) -> Vec<Ace> {
    [&sd.dacl, &sd.sacl]
        .into_iter()
        .flatten()
        .flat_map(|a| a.aces.clone())
        .collect()
}

#[test]
fn round_trip_and_structure() {
    for v in vectors("sd") {
        let sd = decode(&v.bytes);
        assert_eq!(encode(&sd), v.bytes, "{}", v.id);
        let e = &v.expected["structure"];
        assert_eq!(sd.revision, e["revision"], "{}", v.id);
        assert_eq!(sd.control, e["controle"], "{}", v.id);
        assert_eq!(text_of(sd.owner), e["proprietaire"], "{}", v.id);
        assert_eq!(text_of(sd.group), e["groupe"], "{}", v.id);
        for (name, acl) in [("dacl", &sd.dacl), ("sacl", &sd.sacl)] {
            let Some(acl) = acl else {
                assert!(e[name].is_null(), "{}", v.id);
                continue;
            };
            assert_eq!(acl.revision, e[name]["revision"], "{}", v.id);
            let expected = e[name]["aces"].as_array().unwrap();
            assert_eq!(acl.aces.len(), expected.len(), "{}", v.id);
            for (a, x) in acl.aces.iter().zip(expected) {
                assert_eq!(a.ace_type, x["type"], "{}", v.id);
                assert_eq!(a.flags, x["drapeaux"], "{}", v.id);
                assert_eq!(a.mask(), x["masque"], "{}", v.id);
                assert_eq!(text_of(a.sid()), x["sid"], "{}", v.id);
            }
        }
    }
}

#[test]
fn sddl_of_real_descriptors() {
    let domain = lab();
    for v in vectors("sd") {
        let sd = decode(&v.bytes);
        let text = sd_to_sddl(&sd, Some(&domain)).unwrap();
        assert_eq!(text, v.expected["sddl"], "{}", v.id);
        if let Some(tool) = v.expected["sddl_samba_tool"].as_str() {
            assert_eq!(text, tool.trim().lines().last().unwrap(), "{}", v.id);
        }
        // Read back: same content (the control loses the "defaulted" bits).
        let back = sd_from_sddl(&text, Some(&domain), false).unwrap();
        assert_eq!(sd_to_sddl(&back, Some(&domain)).unwrap(), text);
        assert_eq!((back.owner, back.group), (sd.owner, sd.group));
        assert_eq!(back.dacl.map(|a| a.aces), sd.dacl.map(|a| a.aces));
    }
}

#[test]
fn sddl_built_by_samba() {
    let domain = lab();
    let all = vectors("sddl");
    assert_eq!(all.len(), 144);
    for v in all {
        let sd = decode(&v.bytes);
        assert_eq!(encode(&sd), v.bytes, "{}", v.id);
        let e = &v.expected;
        assert_eq!(
            sd_to_sddl(&sd, Some(&domain)).unwrap(),
            e["sddl"],
            "{}",
            v.id
        );
        assert_eq!(
            sd_to_sddl(&sd, None).unwrap(),
            e["sddl_sans_domaine"],
            "{}",
            v.id
        );
        let back = sd_from_sddl(e["sddl"].as_str().unwrap(), Some(&domain), false).unwrap();
        assert_eq!(to_hex(&encode(&back)), e["relu_hex"], "{}", v.id);
    }
}

#[test]
fn sddl_from_windows() {
    for v in vectors("sddlwin") {
        let e = &v.expected;
        let domain = sid(e["sid_domaine"].as_str().unwrap());
        let sd = decode(&v.bytes);
        // Windows stores SACL and DACL before owner and group: same content, other bytes.
        let offsets: Vec<u32> = [4, 8, 12, 16]
            .iter()
            .map(|&i| u32::from_le_bytes(v.bytes[i..i + 4].try_into().unwrap()))
            .collect();
        assert!(
            offsets[3] < offsets[0] && offsets[0] < offsets[1],
            "{}",
            v.id
        );
        assert_ne!(encode(&sd), v.bytes);
        assert_eq!(decode(&encode(&sd)), sd);
        assert_eq!(
            sd_to_sddl(&sd, Some(&domain)).unwrap(),
            e["sddl"],
            "{}",
            v.id
        );
        // Win32's form keeps the binary order of the ACEs: read back, the same descriptor.
        let back = sd_from_sddl(e["sddl_windows"].as_str().unwrap(), Some(&domain), false).unwrap();
        assert_eq!(
            sd_to_sddl(&back, Some(&domain)).unwrap(),
            e["sddl"],
            "{}",
            v.id
        );
        assert_eq!((back.owner, back.group), (sd.owner, sd.group));
        // Get-Acl's (.NET) reorders and merges ACEs: it is read, without being faithful.
        if let Some(get_acl) = e["sddl_get_acl"].as_str() {
            let console = sd_from_sddl(get_acl, Some(&domain), false).unwrap();
            assert_eq!((console.owner, console.group), (sd.owner, sd.group));
        }
    }
}

#[test]
fn file_acls() {
    let domain = lab();
    for v in vectors("fsacl") {
        let sd = decode(&v.bytes);
        assert_eq!(encode(&sd), v.bytes, "{}", v.id);
        assert_eq!(
            sd_to_sddl(&sd, Some(&domain)).unwrap(),
            v.expected["sddl"],
            "{}",
            v.id
        );
        if let Some(file) = v.expected["fichier_sddl"].as_str() {
            let back = sd_from_sddl(file, Some(&domain), false).unwrap();
            assert_eq!(sd_to_sddl(&back, Some(&domain)).unwrap(), file, "{}", v.id);
        }
    }
}

#[test]
fn conditional_aces_like_samba() {
    let domain = sid("S-1-5-21-1-2-3");
    let all = vectors("sddl_conditionnel");
    assert_eq!(all.len(), 57);
    for v in all {
        let sd = decode(&v.bytes);
        assert_eq!(encode(&sd), v.bytes, "{}", v.id);
        let expected = v.expected["sddl"].as_str().unwrap();
        assert_eq!(
            sd_to_sddl(&sd, Some(&domain)).unwrap(),
            expected,
            "{}",
            v.id
        );
        // Samba's writing and the original text give Samba's bytes back.
        for text in [expected, v.raw["description"].as_str().unwrap()] {
            let back = sd_from_sddl(text, Some(&domain), true).unwrap();
            assert_eq!(encode(&back), v.bytes, "{text}");
        }
    }
}

#[test]
fn conditional_aces_from_windows() {
    let all = vectors("sddl_conditionnel_windows");
    assert_eq!(all.len(), 105);
    for v in all {
        let domain = sid(v.expected["sid_domaine"].as_str().unwrap());
        let expected = aces(&decode(&v.bytes));
        let texts = [
            v.raw["description"].as_str(),
            v.expected["sddl_windows"].as_str(),
        ];
        for text in texts.map(Option::unwrap) {
            assert_eq!(
                aces(&sd_from_sddl(text, Some(&domain), false).unwrap()),
                expected,
                "{text}"
            );
        }
        let written = sd_to_sddl(&decode(&v.bytes), Some(&domain)).unwrap();
        assert_eq!(
            aces(&sd_from_sddl(&written, Some(&domain), false).unwrap()),
            expected
        );
    }
}

#[test]
fn windows_and_samba_agree() {
    // Same text, same ACEs, except the two known differences of resource attributes.
    let samba: Vec<(String, Vec<u8>)> = vectors("sddl_conditionnel")
        .into_iter()
        .flat_map(|v| {
            let d = v.raw["description"].as_str().unwrap().to_owned();
            let s = v.expected["sddl"].as_str().unwrap().to_owned();
            [(d, v.bytes.clone()), (s, v.bytes)]
        })
        .collect();
    let mut common = 0;
    for v in vectors("sddl_conditionnel_windows") {
        let description = v.raw["description"].as_str().unwrap();
        let Some((_, bytes)) = samba.iter().find(|(t, _)| t == description) else {
            continue;
        };
        let (a, b) = (aces(&decode(bytes)), aces(&decode(&v.bytes)));
        if description.contains(",TB,") || description.contains(",TD,") {
            assert_ne!(a, b);
            continue;
        }
        assert_eq!(a, b, "{description}");
        common += 1;
    }
    assert!(common > 80);
}

fn first_sd(prefix: &str) -> Vec<u8> {
    vectors("sd")
        .into_iter()
        .find(|v| v.id == prefix)
        .unwrap()
        .bytes
}

#[test]
fn protect_then_unprotect() {
    let bytes = first_sd("sd-ou-labo");
    let sd = decode(&bytes);
    assert!(!sd.is_protected());
    let protected = sd.protect().unwrap();
    assert!(protected.is_protected());
    assert_eq!(protected.protect().unwrap(), protected);
    assert_eq!(protected.dacl.as_ref().unwrap().aces[0], protection_ace());
    let back = decode(&encode(&protected));
    assert_eq!(back, protected);
    assert_eq!(
        back.dacl.unwrap().aces[0].sid().unwrap().to_string(),
        "S-1-1-0"
    );
    assert_eq!(protection_ace().mask(), 0x10040);
    assert_eq!(encode(&protected.unprotect()), bytes);
}

#[test]
fn malformed() {
    let bytes = first_sd("sd-ou-labo");
    let mut wrong_revision = bytes.clone();
    wrong_revision[0] = 2;
    for bad in [&[][..], &bytes[..10], &wrong_revision, &bytes[..200]] {
        assert!(SecurityDescriptor::decode(bad).is_err());
    }
    assert!(Ace::simple(ACCESS_ALLOWED_OBJECT, 1, &everyone(), 0).is_err());
}

const USER: &str = "bf967aba-0de6-11d0-a285-00aa003049e2";
const RESET: &str = "00299570-246d-11d0-a768-00aa006e0529";

#[test]
fn object_ace() {
    let account = sid("S-1-5-21-1094140757-505220614-2701386893-1105");
    let flags = CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
    let ace = Ace::object(
        ACCESS_ALLOWED_OBJECT,
        ADS_RIGHT_DS_CONTROL_ACCESS,
        &account,
        flags,
        Some(guid(RESET)),
        Some(guid(USER)),
    )
    .unwrap();
    assert_eq!(ace.object_type(), Some(guid(RESET)));
    assert_eq!(ace.inherited_object_type(), Some(guid(USER)));
    assert_eq!((ace.sid(), ace.mask()), (Some(account), 0x100));
    let text = sddl::ace_to_sddl(&ace, Some(&lab())).unwrap();
    assert_eq!(
        text,
        format!("(OA;CIIO;CR;{RESET};{USER};S-1-5-21-1094140757-505220614-2701386893-1105)")
    );
    assert_eq!(
        sddl::ace_from_sddl(&text, Some(&lab()), false).unwrap(),
        ace
    );
    let inherited_only = Ace::object(
        ACCESS_ALLOWED_OBJECT,
        0xF01FF,
        &account,
        0xA,
        None,
        Some(guid(USER)),
    )
    .unwrap();
    assert_eq!(inherited_only.object_type(), None);
    assert_eq!(inherited_only.inherited_object_type(), Some(guid(USER)));
    assert!(
        sddl::ace_to_sddl(&inherited_only, None)
            .unwrap()
            .starts_with("(OA;CIIO;CCDCLCSWRPWPDTLOCRSDRCWDWO;;bf967aba")
    );
    assert!(Ace::object(ACCESS_ALLOWED, 1, &account, 0, None, None).is_err());
}

#[test]
fn callback_ace_kept_raw() {
    let mut sd = decode(&first_sd("sd-ou-labo"));
    let data = b"artx\x00\x00\x00\x00";
    let mut body = 0x10u32.to_le_bytes().to_vec();
    body.extend(everyone().encode());
    body.extend(data);
    let callback = Ace {
        ace_type: ACCESS_ALLOWED_CALLBACK,
        flags: 0,
        body,
    };
    sd.dacl.as_mut().unwrap().aces.push(callback);
    let back = decode(&encode(&sd));
    assert_eq!(back, sd);
    let last = back.dacl.as_ref().unwrap().aces.last().unwrap().clone();
    assert_eq!((last.sid(), last.data()), (Some(everyone()), &data[..]));
    assert!(matches!(
        sd_to_sddl(&back, None),
        Err(SddlError::Unrepresentable(_))
    ));
    let unknown = Ace {
        ace_type: 42,
        flags: 0,
        body: vec![1, 2, 3, 4, 5],
    };
    assert!(unknown.sid().is_none() && !unknown.is_readable());
    sd.dacl = Some(Acl {
        revision: 4,
        aces: vec![unknown.clone()],
    });
    assert_eq!(decode(&encode(&sd)).dacl.unwrap().aces, vec![unknown]);
}

#[test]
fn masks_and_generic_rights() {
    assert_eq!(sddl::mask_to_sddl(0), "");
    assert_eq!(sddl::mask_to_sddl(0x1F01FF), "FA");
    assert_eq!(sddl::mask_to_sddl(0xF01FF), "CCDCLCSWRPWPDTLOCRSDRCWDWO");
    assert_eq!(sddl::mask_to_sddl(0x1200A9), "0x1200a9");
    assert_eq!(sddl::mask_from_sddl("0x1200A9").unwrap(), 0x1200A9);
    assert_eq!(sddl::mask_from_sddl("GA").unwrap(), GENERIC_ALL);
    assert_eq!(sddl::mask_from_sddl("0x1_0000_0001").unwrap(), 1);
    assert_eq!(translate_generic(GENERIC_ALL), DS_FULL_CONTROL);
    assert_eq!(translate_generic(GENERIC_READ | 0x20), 0x20094 | 0x20);
}

#[test]
fn invalid_sddl() {
    for text in [
        "X:BA",
        "O:BAO:BA",
        "D:(A;;CC;;;WD",
        "D:(A;;CC;;WD)",
        "D:(Q;;CC;;;WD)",
        "D:(A;ZZ;CC;;;WD)",
        "D:(A;;QQ;;;WD)",
        "D:(A;;CCD;;;WD)",
        "D:(A;;CC;;;S-1-x)",
        "D:(A;;CC;bf967aba-0de6-11d0-a285-00aa003049e2;;WD)",
        "D:(OA;;CC;pas-un-guid;;WD)",
        "D:XX(A;;CC;;;WD)",
        "D:(A;;CC;;;WD)texte",
        "O:DA",
        "texte",
        // Conditional ACEs.
        "D:(XA;;FA;;;WD)",
        "D:(A;;FA;;;WD;(Member_of {SID(BA)}))",
        "D:(XA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;WD;(Member_of {SID(BA)}))",
        "D:(XA;;FA;;;WD;(Member_of {SID(BA)})",
        "S:(RA;;;;;WD;(\"Project\",TZ,0x0,\"A\"))",
        "S:(RA;;;;;WD;(Project,TS,0x0,\"A\"))",
        "S:(RA;;;;;WD;(\"Project\",TS,0x0,A))",
        "S:(RA;;;;;WD;(\"Project\",TX,0x0,0g))",
        "S:(RA;;;;;WD;(\"Project\",TS))",
        "D:(XA;;FA;;;AU;(Member_of {SID(DA)}))",
    ] {
        assert!(
            matches!(sd_from_sddl(text, None, false), Err(SddlError::Invalid(_))),
            "{text}"
        );
    }
    // A quote outside an ACE only toggles the quote state, as in Python.
    assert!(sd_from_sddl("D:(A;;CC;;;WD)\"\"", None, false).is_ok());
}

#[test]
fn ace_order_when_adding_and_removing() {
    let bytes = first_sd("sd-ou-r-et-d");
    let sd = decode(&bytes);
    let account = sid("S-1-5-21-1094140757-505220614-2701386893-1105");
    let allow = Ace::object(
        ACCESS_ALLOWED_OBJECT,
        0x100,
        &account,
        0xA,
        Some(guid(RESET)),
        None,
    )
    .unwrap();
    let deny = Ace::simple(ACCESS_DENIED, 0x10000, &account, 0).unwrap();
    let new = sd
        .add_aces(&[allow.clone(), deny.clone(), allow.clone()])
        .unwrap();
    let list = &new.dacl.as_ref().unwrap().aces;
    assert_eq!(list[0], deny);
    assert_eq!(list.iter().filter(|a| **a == allow).count(), 1);
    let explicit = sd
        .dacl
        .as_ref()
        .unwrap()
        .aces
        .iter()
        .filter(|a| !a.is_inherited())
        .count();
    // The allow comes after the original explicit ACEs, before the first inherited one.
    let at = list.iter().position(|a| *a == allow).unwrap();
    assert_eq!(at, explicit + 1);
    assert!(list[at + 1..].iter().all(Ace::is_inherited));
    assert_eq!(encode(&new.remove_aces(&[allow, deny])), bytes);
    let inherited = Ace::simple(ACCESS_ALLOWED, 1, &account, INHERITED_ACE).unwrap();
    assert!(sd.add_aces(&[inherited]).is_err());
}

// --- conditions -----------------------------------------------------------------------------

fn parse(text: &str) -> Node {
    condition::condition_from_sddl(text, None).unwrap()
}

fn user(name: &str) -> Node {
    Node::Attribute {
        scope: 0xF9,
        name: name.into(),
    }
}

#[test]
fn domain_sid_in_a_condition() {
    // `SID(DA)` (which crashes Samba 4.22) is written as the full SID: the same bytes.
    let domain = sid("S-1-5-21-1-2-3");
    let short = sd_from_sddl(
        "D:(XD;;FA;;;AU;(Member_of {SID(DA)}))",
        Some(&domain),
        false,
    );
    let long = "D:(XD;;FA;;;AU;(Member_of {SID(S-1-5-21-1-2-3-512)}))";
    assert_eq!(
        short.clone().unwrap(),
        sd_from_sddl(long, Some(&domain), false).unwrap()
    );
    assert_eq!(sd_to_sddl(&short.unwrap(), Some(&domain)).unwrap(), long);
    assert_eq!(
        condition::domain_abbreviations("(Member_of {SID(DA), SID(du), SID(BA)})"),
        ["DA", "DU"]
    );
    assert!(condition::domain_abbreviations("(@USER.a == \"SID(DA)\")").is_empty());
}

#[test]
fn integers_like_samba() {
    for (value, sign, base, text) in [
        (-1, 3, 1, "01777777777777777777777"),
        (-1, 3, 3, "0xffffffffffffffff"),
        (0, 3, 1, "00"),
        (0, 3, 2, "0"),
        (8, 3, 1, "010"),
        (0, 2, 2, "-0"),
        (0, 1, 2, "+0"),
    ] {
        assert_eq!(condition::integer_to_sddl(value, sign, base).unwrap(), text);
        let node = Node::Integer {
            value,
            sign,
            base,
            token: 4,
        };
        let expected = Node::Operation {
            code: 0x80,
            operands: vec![user("a"), node],
        };
        assert_eq!(parse(&format!("(@USER.a == {text})")), expected);
    }
    // Samba writes a negative decimal without noted sign as "-1"; read back, the sign is noted.
    assert_eq!(condition::integer_to_sddl(-1, 3, 2).unwrap(), "-1");
    let minus_one = Node::Integer {
        value: -1,
        sign: 3,
        base: 2,
        token: 4,
    };
    assert_eq!(
        parse("(@USER.a == 18446744073709551615)"),
        Node::Operation {
            code: 0x80,
            operands: vec![user("a"), minus_one]
        }
    );
    assert!(condition::integer_to_sddl(5, 2, 2).is_err());
    assert!(condition::integer_to_sddl(-5, 1, 2).is_err());
}

#[test]
fn precedence_and_free_forms() {
    let node = parse("((@User.a == 1) || (@User.b == 2) && (@User.c == 3))");
    assert_eq!(
        condition::node_to_sddl(&node).unwrap(),
        "((@USER.a == 1) || ((@USER.b == 2) && (@USER.c == 3)))"
    );
    assert_eq!(
        parse("(member_of{SID(BA)})"),
        parse("(Member_of {SID(BA)})")
    );
    let local = Node::Attribute {
        scope: 0xF8,
        name: "Title".into(),
    };
    assert_eq!(
        parse("( Exists  Title )"),
        Node::Operation {
            code: 0x87,
            operands: vec![local]
        }
    );
    assert_eq!(
        to_hex(&condition::encode_condition(&parse("(!(@User.a))")).unwrap()),
        "61727478f9020000006100a2"
    );
}

#[test]
fn malformed_condition_text() {
    for text in [
        "@USER.a == 1",
        "(@USER.a == 1",
        "(@USER.a == 1))",
        "(@USER.a == \"x)",
        "(@USER.a == #012)",
        "(@USER.a == 0x)",
        "(@USER.a == 99999999999999999999)",
        "(@User.a == -9223372036854775809)",
        "(@Truc.a == 1)",
        "(@USER. == 1)",
        "(Member_of)",
        "(Contains @USER.a)",
        "(@USER.a == {1, 2)",
        "(@USER.a == {1 2})",
        "(Member_of {SID(XX)})",
        "(@USER.a == 1 ; 2)",
        "(@USER.a == 1) (@USER.b == 2)",
    ] {
        assert!(
            matches!(
                condition::condition_from_sddl(text, None),
                Err(ConditionError::Invalid { .. })
            ),
            "{text}"
        );
    }
}

#[test]
fn malformed_condition_bytes() {
    for data in [
        &b""[..],
        b"xxxx",
        b"artx\x80",
        b"artx\x10\xff\x00\x00\x00",
        b"artx\x42",
    ] {
        assert!(condition::read_condition(data).is_err());
    }
}

#[test]
fn blanks_kept_in_conditions() {
    let sd = sd_from_sddl(
        " D: ( XA ; ; FR ; ; ; WD ; (@User.Project  Contains {\"a b\", \"c\"}) ) ",
        None,
        false,
    );
    assert_eq!(
        sd_to_sddl(&sd.unwrap(), None).unwrap(),
        "D:(XA;;FR;;;WD;(@USER.Project Contains {\"a b\", \"c\"}))"
    );
}

#[test]
fn deep_nesting_is_refused_not_overflowed() {
    let deep = |n: usize| format!("({}@USER.a{})", "(".repeat(n), ")".repeat(n));
    assert!(condition::condition_from_sddl(&deep(100), None).is_ok());
    assert!(condition::condition_from_sddl(&deep(200), None).is_err());
    assert!(condition::condition_from_sddl(&deep(100_000), None).is_err());
    let chain = format!("({})", vec!["(@USER.a == 1)"; 5000].join(" || "));
    assert!(condition::condition_from_sddl(&chain, None).is_err());
    let mut data = b"artx\xf9\x02\x00\x00\x00a\x00".to_vec();
    data.extend(vec![0xA2; 100_000]);
    assert!(condition::read_condition(&data).is_err());
    assert!(condition::condition_to_sddl(&data[..11 + 499]).is_ok());
    assert!(condition::condition_to_sddl(&data[..11 + 500]).is_err());
}

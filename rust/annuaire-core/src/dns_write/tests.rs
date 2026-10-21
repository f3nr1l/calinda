// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS writing (J3.4): inputs, changesets built from the nodes read, tombstones, SOA,
//! inverse and conflicts (`tests/unitaires/test_actions_dns.py`, without the fake directory:
//! the reads are given).

use super::*;
use crate::dns::Partition;
use crate::messages::English;
use annuaire_codecs::dns_property::ZoneSettings;

const CONTAINER: &str = "CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=test";
const SERIAL: u32 = 57;
const DC: &str = "dc1.lab.test";

fn zone(name: &str) -> Zone {
    Zone {
        dn: format!("DC={name},{CONTAINER}"),
        name: name.into(),
        partition: Partition::Domain,
        settings: ZoneSettings::default(),
        modified: None,
    }
}

fn forward() -> Zone {
    zone("lab.test")
}

fn reverse() -> Zone {
    zone("1.168.192.in-addr.arpa")
}

fn soa(serial: u32, zone: &str) -> Vec<u8> {
    let mut r = Record::new(
        dns_record::SOA,
        RecordData::Soa {
            serial,
            refresh: 900,
            retry: 600,
            expire: 86400,
            minimum: 3600,
            primary_server: format!("dc1.{zone}"),
            responsible: format!("hostmaster.{zone}"),
        },
    );
    r.serial = serial;
    r.ttl = 3600;
    r.encode().unwrap()
}

fn data(rtype: u16, text: &str) -> RecordData {
    if rtype == dns_record::NS {
        RecordData::Name(text.into())
    } else {
        read_input(rtype, text).unwrap()
    }
}

fn rec(rtype: u16, text: &str, serial: u32, ttl: u32, rank: u8) -> Vec<u8> {
    let mut r = Record::new(rtype, data(rtype, text));
    r.serial = serial;
    r.ttl = ttl;
    r.rank = rank;
    r.encode().unwrap()
}

fn a(text: &str, serial: u32) -> Vec<u8> {
    rec(dns_record::A, text, serial, 900, RANK_ZONE)
}

fn node(z: &Zone, name: &str) -> String {
    node_dn(&z.dn, name)
}

fn entry(dn_text: &str, usn: i64, records: Vec<Vec<u8>>, extra: &[(&str, &[u8])]) -> Entry {
    let mut attributes = vec![
        ("uSNChanged".to_owned(), vec![usn.to_string().into_bytes()]),
        (DNS_RECORD.to_owned(), records),
    ];
    for (n, v) in extra {
        attributes.push(((*n).to_owned(), vec![v.to_vec()]));
    }
    Entry {
        dn: dn_text.into(),
        attributes,
    }
}

fn root(z: &Zone, serial: u32, writable: bool) -> Entry {
    let mut e = entry(
        &node(z, ROOT),
        100,
        vec![
            soa(serial, &z.name),
            rec(dns_record::NS, "dc1.lab.test", 1, 900, RANK_ZONE),
        ],
        &[],
    );
    if writable {
        e.attributes.push((
            "allowedAttributesEffective".into(),
            vec![b"dnsRecord".to_vec(), b"dNSTombstoned".to_vec()],
        ));
    }
    e
}

/// The lab of the Python tests: `hote` (A 192.0.2.1), `alias` (CNAME hote), two zones.
fn world() -> Reads {
    let (z, r) = (forward(), reverse());
    let mut reads = Reads::new();
    for e in [
        root(&z, SERIAL, true),
        root(&r, SERIAL, true),
        entry(&node(&z, "hote"), 200, vec![a("192.0.2.1", 3)], &[]),
        entry(
            &node(&z, "alias"),
            201,
            vec![rec(
                dns_record::CNAME,
                "hote.lab.test",
                SERIAL + 1,
                900,
                RANK_ZONE,
            )],
            &[],
        ),
    ] {
        reads.insert(key(&e.dn), Some(e));
    }
    reads
}

fn build(reads: &Reads, requests: &[Request]) -> Result<Changeset, DnsError> {
    build_from(requests, reads, DC, Some(1), &English)
}

fn add(z: &Zone, name: &str, rtype: u16, text: &str) -> Request {
    Request::Add {
        zone: z.clone(),
        name: name.into(),
        rtype,
        data: data(rtype, text),
        ttl: DEFAULT_TTL,
    }
}

fn change(attribute: &str, removed: Vec<Vec<u8>>, added: Vec<Vec<u8>>) -> Change {
    Change::new(attribute, removed, added).unwrap()
}

fn read(usn: i64) -> Option<Read> {
    Some(Read { dc: DC.into(), usn })
}

#[test]
fn names() {
    assert_eq!(
        verify_name("_ldap._tcp.dc._msdcs", false).unwrap(),
        "_ldap._tcp.dc._msdcs"
    );
    assert_eq!(
        verify_name("hote.lab.test.", false).unwrap(),
        "hote.lab.test"
    );
    assert_eq!(verify_name("*.web", true).unwrap(), "*.web");
    let long = "x".repeat(64);
    for wrong in [
        "",
        "a..b",
        "-a",
        "a-",
        "é",
        "a b",
        long.as_str(),
        "a.*",
        "*",
    ] {
        assert!(verify_name(wrong, false).is_err(), "{wrong}");
    }
    assert_eq!(
        relative_name("lab.test", " "),
        Err(DnsError::EmptyNameUseAt)
    );
    assert_eq!(relative_name("lab.test", "@").unwrap(), "@");
    assert_eq!(relative_name("lab.test", "lab.test.").unwrap(), "@");
    assert_eq!(relative_name("lab.test", "Hote").unwrap(), "Hote");
    assert_eq!(relative_name("lab.test", "hote.lab.test").unwrap(), "hote");
    assert_eq!(relative_name("lab.test", "hote.LAB.test.").unwrap(), "hote");
    assert!(matches!(
        relative_name("lab.test", "hote.autre.test."),
        Err(DnsError::NotInZone { .. })
    ));
}

#[test]
fn inputs() {
    assert_eq!(
        read_input(dns_record::A, " 192.0.2.10 ").unwrap(),
        RecordData::Address("192.0.2.10".parse().unwrap())
    );
    assert_eq!(
        read_input(dns_record::MX, "10 mx.lab.test.").unwrap(),
        RecordData::Mx {
            preference: 10,
            target: "mx.lab.test".into()
        }
    );
    assert_eq!(
        read_input(dns_record::SRV, "0 100 389 dc1.lab.test").unwrap(),
        RecordData::Srv {
            priority: 0,
            weight: 100,
            port: 389,
            target: "dc1.lab.test".into()
        }
    );
    assert_eq!(
        read_input(dns_record::TXT, r#""essai j3" "deux \"x\"""#).unwrap(),
        RecordData::Txt(vec!["essai j3".into(), "deux \"x\"".into()])
    );
    assert_eq!(
        read_input(dns_record::TXT, "une seule chaîne").unwrap(),
        RecordData::Txt(vec!["une seule chaîne".into()])
    );
    let RecordData::Txt(long) = read_input(dns_record::TXT, &"é".repeat(200)).unwrap() else {
        panic!("TXT");
    };
    assert_eq!(long.iter().map(String::len).collect::<Vec<_>>(), [254, 146]);
    for (rtype, text) in [
        (dns_record::A, "2001:db8::1"),
        (dns_record::AAAA, "192.0.2.1"),
        (dns_record::A, "192.0.2"),
        (dns_record::MX, "70000 mx"),
        (dns_record::MX, "mx"),
        (dns_record::SRV, "0 0 65536 x"),
        (dns_record::CNAME, "a..b"),
        (dns_record::TXT, "\"non fermé"),
        (dns_record::TXT, ""),
        (dns_record::NS, "dc1.lab.test"),
    ] {
        assert!(read_input(rtype, text).is_err(), "{rtype} {text}");
    }
    assert_eq!(
        read_input(dns_record::MX, "70000 mx"),
        Err(DnsError::OutOfRange {
            field: Field::Priority,
            value: 70000,
            max: 0xFFFF
        })
    );
    assert!(verify_ttl(-1).is_err());
}

#[test]
fn reverse_zones() {
    let mut wider = zone("168.192.in-addr.arpa");
    wider.dn = "x".into();
    let zones = [forward(), reverse(), wider];
    let (z, name) = reverse_zone(&zones, "192.168.1.10".parse().unwrap()).unwrap();
    assert_eq!(
        (z.name.as_str(), name.as_str()),
        ("1.168.192.in-addr.arpa", "10")
    );
    assert!(reverse_zone(&zones, "192.168.2.7".parse().unwrap()).is_some());
    assert!(reverse_zone(&zones, "10.0.0.1".parse().unwrap()).is_none());
    assert_eq!(
        reverse_pointer("2001:db8::1".parse().unwrap()),
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    );
}

#[test]
fn value_as_samba_tool() {
    // samba-tool's header (ADR 0003, 2): version 5, rank ZONE, flags 0, static.
    let v = encode(
        dns_record::A,
        data(dns_record::A, "192.0.2.10"),
        58,
        DEFAULT_TTL,
    )
    .unwrap();
    let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        concat!(
            "0400010005f000003a000000",
            "00000384",
            "00000000",
            "00000000",
            "c000020a"
        )
    );
}

#[test]
fn new_name() {
    let z = forward();
    let cs = build(&world(), &[add(&z, "essai", dns_record::A, "192.0.2.10")]).unwrap();
    assert_eq!(
        cs.operations,
        [
            Operation::Modify {
                dn: node(&z, ROOT),
                changes: vec![change(
                    DNS_RECORD,
                    vec![soa(SERIAL, "lab.test")],
                    vec![soa(SERIAL + 1, "lab.test")]
                )],
                read: read(100),
            },
            Operation::Add {
                dn: node(&z, "essai"),
                attributes: vec![
                    (
                        "objectClass".into(),
                        vec![b"top".to_vec(), b"dnsNode".to_vec()]
                    ),
                    (DNS_RECORD.into(), vec![a("192.0.2.10", SERIAL + 1)]),
                ],
            },
        ]
    );
    assert!(cs.remarks.iter().any(|m| m.contains("57 → 58")));
    assert!(cs.remarks[0].starts_with("Zone lab.test: "));
}

#[test]
fn modification_reads_the_value_again() {
    let z = forward();
    let old = a("192.0.2.1", 3);
    let modify = |shown: Vec<u8>, ttl| Request::Modify {
        zone: z.clone(),
        name: "hote".into(),
        old: shown,
        rtype: dns_record::A,
        data: data(dns_record::A, "192.0.2.2"),
        ttl,
    };
    let cs = build(&world(), &[modify(old.clone(), 1200)]).unwrap();
    let new = rec(dns_record::A, "192.0.2.2", SERIAL + 1, 1200, RANK_ZONE);
    assert_eq!(
        cs.operations[1],
        Operation::Modify {
            dn: node(&z, "hote"),
            changes: vec![change(DNS_RECORD, vec![old.clone()], vec![new.clone()])],
            read: read(200),
        }
    );
    // Shown with another TTL: the value of the DC goes.
    let shown = rec(dns_record::A, "192.0.2.1", 2, 60, RANK_ZONE);
    let delete = Request::Delete {
        zone: z.clone(),
        name: "hote".into(),
        value: shown,
    };
    let cs = build(&world(), &[delete]).unwrap();
    let Operation::Modify { changes, .. } = &cs.operations[1] else {
        panic!("modify");
    };
    assert_eq!(changes[0].removed, std::slice::from_ref(&old));
    let gone = Request::Delete {
        zone: z.clone(),
        name: "hote".into(),
        value: a("192.0.2.99", 3),
    };
    assert!(matches!(
        build(&world(), &[gone]),
        Err(DnsError::RecordGone { .. })
    ));
    // Same data and TTL: nothing to do.
    let mut reads = world();
    reads.insert(
        key(&node(&z, "hote")),
        Some(entry(&node(&z, "hote"), 200, vec![new.clone()], &[])),
    );
    assert_eq!(build(&reads, &[modify(new, 1200)]), Err(DnsError::NoChange));
}

#[test]
fn unreadable_node_refused() {
    let z = forward();
    let mut reads = world();
    reads.insert(
        key(&node(&z, "hote")),
        Some(Entry {
            dn: node(&z, "hote"),
            attributes: Vec::new(),
        }),
    );
    assert!(matches!(
        build(&reads, &[add(&z, "hote", dns_record::A, "192.0.2.2")]),
        Err(DnsError::UnreadableNode { .. })
    ));
}

#[test]
fn last_record_makes_a_tombstone_then_back_in_service() {
    let z = forward();
    let value = a("192.0.2.1", 3);
    let cs = build(
        &world(),
        &[Request::Delete {
            zone: z.clone(),
            name: "hote".into(),
            value: value.clone(),
        }],
    )
    .unwrap();
    let Operation::Modify { changes, .. } = &cs.operations[1] else {
        panic!("modify");
    };
    let tomb = tombstone_value(SERIAL + 1, Some(1));
    assert_eq!(
        changes,
        &[
            change(DNS_RECORD, vec![value], vec![tomb.clone()]),
            change(TOMBSTONED, vec![], vec![b"TRUE".to_vec()]),
        ]
    );
    let t = Record::decode(&tomb).unwrap();
    assert_eq!(
        (t.rtype, t.rank, t.ttl, t.serial, t.timestamp),
        (0, 0, 0, SERIAL + 1, 0)
    );
    assert!(cs.remarks.iter().any(|m| m.contains("tombstone")));
    // The node in tombstone, a new record: values of type 0 removed, FALSE.
    let mut reads = world();
    reads.insert(
        key(&node(&z, "hote")),
        Some(entry(
            &node(&z, "hote"),
            300,
            vec![tomb.clone()],
            &[(TOMBSTONED, b"TRUE")],
        )),
    );
    let cs = build(&reads, &[add(&z, "hote", dns_record::A, "192.0.2.5")]).unwrap();
    assert_eq!(
        cs.operations[1],
        Operation::Modify {
            dn: node(&z, "hote"),
            changes: vec![
                change(DNS_RECORD, vec![tomb], vec![a("192.0.2.5", SERIAL + 1)]),
                change(TOMBSTONED, vec![b"TRUE".to_vec()], vec![b"FALSE".to_vec()]),
            ],
            read: read(300),
        }
    );
    // Purge: deletion of the object, no SOA; refused on a live node or a missing one.
    let purge = |name: &str| Request::Purge {
        zone: z.clone(),
        name: name.into(),
    };
    let cs = build(&reads, &[purge("hote")]).unwrap();
    assert_eq!(
        cs.operations,
        [Operation::Delete {
            dn: node(&z, "hote"),
            read: read(300),
            guards: Vec::new()
        }]
    );
    assert!(matches!(
        build(&reads, &[purge("alias")]),
        Err(DnsError::NoLongerTombstone { .. })
    ));
    assert!(matches!(
        build(&reads, &[purge("absent")]),
        Err(DnsError::NoLongerExists { .. })
    ));
}

#[test]
fn every_value_counts() {
    // An NS of rank NS_GLUE keeps the node alive; a value of unknown rank is never written.
    let z = forward();
    let glue = rec(dns_record::NS, "dc1.lab.test", SERIAL + 1, 900, 0x82);
    let odd = rec(dns_record::A, "192.0.2.77", SERIAL + 1, 900, 0x13);
    let keep = a("192.0.2.7", SERIAL + 1);
    let mut reads = world();
    reads.insert(
        key(&node(&z, "_msdcs")),
        Some(entry(
            &node(&z, "_msdcs"),
            400,
            vec![glue.clone(), keep.clone(), odd.clone()],
            &[],
        )),
    );
    let delete = |value: &Vec<u8>| Request::Delete {
        zone: z.clone(),
        name: "_msdcs".into(),
        value: value.clone(),
    };
    let cs = build(&reads, &[delete(&keep)]).unwrap();
    let Operation::Modify { changes, .. } = &cs.operations[1] else {
        panic!("modify");
    };
    assert_eq!(changes, &[change(DNS_RECORD, vec![keep], vec![])]);
    assert!(!modifiable(&odd, &WRITTEN_TYPES) && !modifiable(&glue, &WRITTEN_TYPES));
    assert!(matches!(
        build(&reads, &[delete(&odd)]),
        Err(DnsError::NotModifiable { .. })
    ));
}

#[test]
fn cname_alone() {
    let z = forward();
    let w = world();
    assert!(matches!(
        build(&w, &[add(&z, "hote", dns_record::CNAME, "x.lab.test")]),
        Err(DnsError::CnameNotAlone { .. })
    ));
    assert!(matches!(
        build(&w, &[add(&z, "alias", dns_record::A, "192.0.2.3")]),
        Err(DnsError::IsAlias { .. })
    ));
    assert!(matches!(
        build(&w, &[add(&z, ROOT, dns_record::CNAME, "x.lab.test")]),
        Err(DnsError::CnameNotAlone { .. })
    ));
    let mut again = add(&z, "hote", dns_record::A, "192.0.2.1");
    if let Request::Add { ttl, .. } = &mut again {
        *ttl = 60;
    }
    assert!(matches!(
        build(&w, &[again]),
        Err(DnsError::AlreadyThere { .. })
    ));
}

#[test]
fn root_merged_with_the_soa_and_two_zones() {
    let (z, r) = (forward(), reverse());
    let cs = build(&world(), &[add(&z, ROOT, dns_record::MX, "10 mx.lab.test")]).unwrap();
    assert_eq!(
        cs.operations,
        [Operation::Modify {
            dn: node(&z, ROOT),
            changes: vec![change(
                DNS_RECORD,
                vec![soa(SERIAL, "lab.test")],
                vec![
                    soa(SERIAL + 1, "lab.test"),
                    rec(dns_record::MX, "10 mx.lab.test", SERIAL + 1, 900, RANK_ZONE)
                ]
            )],
            read: read(100),
        }]
    );
    let cs = build(
        &world(),
        &[
            add(&z, "web", dns_record::A, "192.168.1.10"),
            add(&r, "10", dns_record::PTR, "web.lab.test"),
        ],
    )
    .unwrap();
    let dns: Vec<&str> = cs.operations.iter().map(Operation::dn).collect();
    assert_eq!(
        dns,
        [
            node(&z, ROOT),
            node(&r, ROOT),
            node(&z, "web"),
            node(&r, "10")
        ]
    );
}

#[test]
fn account_without_right_on_the_soa() {
    let z = forward();
    let mut reads = world();
    reads.insert(key(&node(&z, ROOT)), Some(root(&z, SERIAL, false)));
    let cs = build(&reads, &[add(&z, "poste", dns_record::A, "192.0.2.20")]).unwrap();
    assert_eq!(
        cs.operations,
        [Operation::Add {
            dn: node(&z, "poste"),
            attributes: vec![
                (
                    "objectClass".into(),
                    vec![b"top".to_vec(), b"dnsNode".to_vec()]
                ),
                (DNS_RECORD.into(), vec![a("192.0.2.20", SERIAL)]),
            ],
        }]
    );
    assert!(
        cs.remarks
            .iter()
            .any(|m| m.contains("without incrementing"))
    );
}

#[test]
fn ns_removed_and_added_not_modified() {
    let z = forward();
    let old = rec(dns_record::NS, "dc1.lab.test", 1, 900, RANK_ZONE);
    let cs = build(
        &world(),
        &[
            add(&z, ROOT, dns_record::NS, "dc2.lab.test"),
            Request::Delete {
                zone: z.clone(),
                name: ROOT.into(),
                value: old.clone(),
            },
        ],
    )
    .unwrap();
    let new = rec(dns_record::NS, "dc2.lab.test", SERIAL + 1, 900, RANK_ZONE);
    assert_eq!(
        cs.operations,
        [Operation::Modify {
            dn: node(&z, ROOT),
            changes: vec![change(
                DNS_RECORD,
                vec![soa(SERIAL, "lab.test"), old],
                vec![soa(SERIAL + 1, "lab.test"), new.clone()]
            )],
            read: read(100),
        }]
    );
    assert!(!modifiable(&new, &WRITTEN_TYPES) && modifiable(&new, &FIX_TYPES));
}

#[test]
fn equivalents() {
    let z = forward();
    let modify = |before: u32, after: u32| Operation::Modify {
        dn: node(&z, ROOT),
        changes: vec![change(
            DNS_RECORD,
            vec![soa(before, "lab.test")],
            vec![soa(after, "lab.test")],
        )],
        read: None,
    };
    let created = |value: Vec<u8>| Operation::Add {
        dn: node(&z, "a"),
        attributes: vec![(DNS_RECORD.into(), vec![value])],
    };
    let set = |ops: Vec<Operation>| Changeset {
        operations: ops,
        remarks: Vec::new(),
    };
    let x = set(vec![modify(1, 2), created(a("192.0.2.1", 2))]);
    let y = set(vec![modify(4, 5), created(a("192.0.2.1", 5))]);
    let w = set(vec![modify(4, 5), created(soa(3, "lab.test"))]);
    assert!(equivalent(&x, &y) && !equivalent(&x, &w));
    let tomb = |serial, nttime| Operation::Modify {
        dn: "DC=a,DC=z,CN=MicrosoftDNS,DC=x".into(),
        changes: vec![change(
            DNS_RECORD,
            vec![],
            vec![tombstone_value(serial, Some(nttime))],
        )],
        read: None,
    };
    assert!(equivalent(&set(vec![tomb(2, 1)]), &set(vec![tomb(9, 99)])));
}

#[test]
fn rollback_raises_the_soa_again() {
    let z = forward();
    let cs = build(
        &world(),
        &[
            add(&z, "hote", dns_record::A, "192.0.2.9"),
            add(&z, "neuf", dns_record::A, "192.0.2.10"),
        ],
    )
    .unwrap();
    // The SOA and « hote » written, « neuf » refused: the inverse of the first two.
    let inverse = Changeset {
        operations: cs.operations[..2]
            .iter()
            .rev()
            .map(|op| match op {
                Operation::Modify { dn, changes, read } => Operation::Modify {
                    dn: dn.clone(),
                    changes: changes.iter().map(Change::inverse).collect(),
                    read: read.clone(),
                },
                other => other.clone(),
            })
            .collect(),
        remarks: Vec::new(),
    };
    let rollback = soa_on_rollback(inverse, &English);
    let Operation::Modify { changes, .. } = &rollback.operations[1] else {
        panic!("modify");
    };
    assert_eq!(
        changes,
        &[change(
            DNS_RECORD,
            vec![soa(SERIAL + 1, "lab.test")],
            vec![soa(SERIAL + 2, "lab.test")]
        )]
    );
    assert!(
        rollback
            .remarks
            .iter()
            .any(|m| m.contains("incremented again"))
    );
    // Without effect outside DNS, nor on a rollback without SOA.
    let outside = Changeset {
        operations: vec![Operation::Modify {
            dn: "CN=x,DC=lab,DC=test".into(),
            changes: vec![change(
                "description",
                vec![b"a".to_vec()],
                vec![b"b".to_vec()],
            )],
            read: None,
        }],
        remarks: Vec::new(),
    };
    assert_eq!(soa_on_rollback(outside.clone(), &English), outside);
    let plain = Changeset {
        operations: vec![Operation::Modify {
            dn: node(&z, "hote"),
            changes: vec![change(DNS_RECORD, vec![a("192.0.2.9", 1)], vec![])],
            read: None,
        }],
        remarks: Vec::new(),
    };
    assert_eq!(soa_on_rollback(plain.clone(), &English), plain);
    assert!(touches_dns(&plain) && !touches_dns(&outside));
}

#[test]
fn soa_taken_out_and_merged_again() {
    let z = forward();
    let with = Operation::Modify {
        dn: node(&z, ROOT),
        changes: vec![change(
            DNS_RECORD,
            vec![soa(58, "lab.test"), a("192.0.2.1", 1)],
            vec![soa(57, "lab.test")],
        )],
        read: None,
    };
    let rest = without_soa(&with).unwrap().unwrap();
    assert_eq!(
        rest,
        Operation::Modify {
            dn: node(&z, ROOT),
            changes: vec![change(DNS_RECORD, vec![a("192.0.2.1", 1)], vec![])],
            read: None,
        }
    );
    let soa_only = Operation::Modify {
        dn: node(&z, ROOT),
        changes: vec![change(
            DNS_RECORD,
            vec![soa(58, "lab.test")],
            vec![soa(57, "lab.test")],
        )],
        read: None,
    };
    assert_eq!(without_soa(&soa_only).unwrap(), None);
    let merged = merge(
        rest,
        change(
            DNS_RECORD,
            vec![soa(58, "lab.test")],
            vec![soa(59, "lab.test")],
        ),
        read(5),
    )
    .unwrap();
    assert_eq!(
        merged,
        Operation::Modify {
            dn: node(&z, ROOT),
            changes: vec![change(
                DNS_RECORD,
                vec![soa(58, "lab.test"), a("192.0.2.1", 1)],
                vec![soa(59, "lab.test")]
            )],
            read: read(5),
        }
    );
    assert_eq!(soa_prefix(&English), "Zone ");
}

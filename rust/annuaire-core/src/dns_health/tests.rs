// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS health (J3.5): each rule, as a true positive and a true negative, on a synthetic
//! healthy domain to which each test adds a defect (`tests/unitaires/test_sante_dns.py`).

use super::*;
use crate::dns_write::{read_input, tombstone_value};
use annuaire_codecs::dns_property::ZoneSettings;
use annuaire_codecs::time::Civil;

const DOMAIN: &str = "exemple.test";
const BASE: &str = "DC=exemple,DC=test";
const GUID1: &str = "11111111-2222-3333-4444-555555555555";
const GUID2: &str = "66666666-7777-8888-9999-000000000000";

fn now() -> UtcTime {
    UtcTime::from_civil(Civil {
        year: 2026,
        month: 10,
        day: 14,
        hour: 12,
        minute: 0,
        second: 0,
        fraction: 0,
    })
    .unwrap()
}

fn days_ago(days: f64) -> UtcTime {
    #[allow(clippy::cast_possible_truncation)]
    now().add_seconds(-((days * 86_400.0) as i64)).unwrap()
}

fn zone(name: &str, partition: Partition) -> Zone {
    Zone {
        dn: format!("DC={name},CN=MicrosoftDNS,DC={},{BASE}", partition.value()),
        name: name.into(),
        partition,
        settings: ZoneSettings::default(),
        modified: None,
    }
}

fn direct() -> Zone {
    zone(DOMAIN, Partition::Domain)
}
fn msdcs() -> Zone {
    zone(&format!("_msdcs.{DOMAIN}"), Partition::Forest)
}
fn reverse() -> Zone {
    zone("2.0.192.in-addr.arpa", Partition::Domain)
}

/// A record; dynamic (refreshed `days` ago) if `days` is given.
fn rec(rtype: u16, text: &str, days: Option<f64>) -> Vec<u8> {
    let data = match rtype {
        dns_record::NS | dns_record::CNAME | dns_record::PTR => RecordData::Name(text.into()),
        dns_record::SOA => RecordData::Soa {
            serial: 1,
            refresh: 900,
            retry: 600,
            expire: 86400,
            minimum: 3600,
            primary_server: format!("dc1.{DOMAIN}"),
            responsible: format!("hostmaster.{DOMAIN}"),
        },
        _ => read_input(rtype, text).unwrap(),
    };
    let mut r = Record::new(rtype, data);
    r.serial = 1;
    r.ttl = 900;
    r.timestamp = days.map_or(0, |d| {
        u32::try_from(dns_record::utc_to_hours(days_ago(d))).unwrap()
    });
    r.encode().unwrap()
}

fn soa_naming(server: &str) -> Vec<u8> {
    let mut r = Record::new(
        dns_record::SOA,
        RecordData::Soa {
            serial: 1310,
            refresh: 900,
            retry: 600,
            expire: 86400,
            minimum: 3600,
            primary_server: server.into(),
            responsible: format!("hostmaster.{DOMAIN}"),
        },
    );
    r.serial = 1310;
    r.ttl = 3600;
    r.encode().unwrap()
}

fn grave(days: f64) -> Vec<u8> {
    let t = time::utc_to_nttime(days_ago(days)).unwrap();
    tombstone_value(1, Some(u64::try_from(t).unwrap()))
}

fn node(z: &Zone, name: &str, values: Vec<Vec<u8>>, tombstone: bool) -> Node {
    Node {
        dn: dns::node_dn(&z.dn, name),
        name: name.into(),
        zone: z.name.clone(),
        values,
        tombstone,
        modified: None,
        unreadable: false,
    }
}

fn a(address: &str) -> Vec<u8> {
    rec(dns_record::A, address, None)
}

fn healthy() -> DnsState {
    let (d, m, r) = (direct(), msdcs(), reverse());
    let root = vec![
        rec(dns_record::SOA, "", None),
        rec(dns_record::NS, &format!("dc1.{DOMAIN}"), None),
        rec(dns_record::NS, &format!("dc2.{DOMAIN}"), None),
    ];
    let addresses = vec![a("192.0.2.1"), a("192.0.2.2")];
    let srv = |port: &str, dc: &str| {
        rec(
            dns_record::SRV,
            &format!("0 100 {port} {dc}.{DOMAIN}"),
            None,
        )
    };
    let mut nodes = HashMap::new();
    nodes.insert(
        d.dn.clone(),
        vec![
            node(&d, "@", [root.clone(), addresses.clone()].concat(), false),
            node(&d, "DomainDnsZones", addresses.clone(), false),
            node(&d, "ForestDnsZones", addresses.clone(), false),
            node(&d, "dc1", vec![a("192.0.2.1")], false),
            node(&d, "DC2", vec![a("192.0.2.2")], false),
            node(
                &d,
                "_msdcs",
                vec![rec(dns_record::NS, &format!("dc1.{DOMAIN}"), None)],
                false,
            ),
            node(
                &d,
                "_ldap._tcp",
                vec![srv("389", "dc1"), srv("389", "dc2")],
                false,
            ),
            node(
                &d,
                "_kerberos._tcp.Default-First-Site-Name._sites",
                vec![srv("88", "dc1")],
                false,
            ),
            node(
                &d,
                "poste1",
                vec![rec(dns_record::A, "198.51.100.50", Some(2.0))],
                false,
            ),
            node(&d, "srv1", vec![a("192.0.2.60")], false),
            node(&d, "imprimante", vec![a("192.0.2.70")], false),
            node(
                &d,
                "www",
                vec![rec(dns_record::CNAME, &format!("srv1.{DOMAIN}"), None)],
                false,
            ),
            node(
                &d,
                "externe",
                vec![rec(dns_record::CNAME, "www.example.org", None)],
                false,
            ),
            node(
                &d,
                "courrier",
                vec![rec(dns_record::MX, &format!("10 srv1.{DOMAIN}"), None)],
                false,
            ),
        ],
    );
    nodes.insert(
        m.dn.clone(),
        vec![
            node(
                &m,
                "@",
                vec![
                    rec(dns_record::SOA, "", None),
                    rec(dns_record::NS, &format!("dc1.{DOMAIN}"), None),
                ],
                false,
            ),
            node(&m, "gc", addresses, false),
            node(&m, "_ldap._tcp.dc", vec![srv("389", "dc1")], false),
            node(
                &m,
                GUID1,
                vec![rec(dns_record::CNAME, &format!("dc1.{DOMAIN}"), None)],
                false,
            ),
            node(
                &m,
                GUID2,
                vec![rec(dns_record::CNAME, &format!("dc2.{DOMAIN}"), None)],
                false,
            ),
        ],
    );
    nodes.insert(
        r.dn.clone(),
        vec![
            // As samba-tool zonecreate: the NS is the name of the domain.
            node(
                &r,
                "@",
                vec![
                    rec(dns_record::SOA, "", None),
                    rec(dns_record::NS, DOMAIN, None),
                ],
                false,
            ),
            node(
                &r,
                "1",
                vec![rec(dns_record::PTR, &format!("dc1.{DOMAIN}"), None)],
                false,
            ),
            node(
                &r,
                "2",
                vec![rec(dns_record::PTR, &format!("dc2.{DOMAIN}"), None)],
                false,
            ),
            node(
                &r,
                "60",
                vec![rec(dns_record::PTR, &format!("srv1.{DOMAIN}"), None)],
                false,
            ),
        ],
    );
    let controller = |n: &str, guid: &str| Controller {
        name: format!("{n}.{DOMAIN}"),
        guid: guid.into(),
        site: "Default-First-Site-Name".into(),
        catalog: true,
    };
    DnsState {
        domain: DOMAIN.into(),
        forest: DOMAIN.into(),
        zones: vec![r, d, m],
        nodes,
        controllers: vec![controller("dc1", GUID1), controller("dc2", GUID2)],
        computers: ["dc1", "dc2", "poste1", "srv1"]
            .iter()
            .map(|x| format!("{x}.{DOMAIN}"))
            .collect(),
        sites: ["default-first-site-name".to_owned()].into(),
        ..DnsState::default()
    }
}

/// The state with these values besides under `name` (node created if needed).
fn with(
    mut state: DnsState,
    z: &Zone,
    name: &str,
    values: Vec<Vec<u8>>,
    tombstone: bool,
) -> DnsState {
    let list = state.nodes.entry(z.dn.clone()).or_default();
    match list.iter_mut().find(|n| n.name.eq_ignore_ascii_case(name)) {
        Some(n) => {
            n.values.extend(values);
            n.tombstone = tombstone;
        }
        None => list.push(node(z, name, values, tombstone)),
    }
    if !state.zones.contains(z) {
        state.zones.push(z.clone());
    }
    state
}

fn without(mut state: DnsState, z: &Zone, name: &str, value: &[u8]) -> DnsState {
    for n in state.nodes.get_mut(&z.dn).unwrap() {
        if n.name.eq_ignore_ascii_case(name) {
            n.values.retain(|v| v != value);
        }
    }
    state
}

fn diagnosis(state: &DnsState) -> Diagnosis {
    diagnose(state, Settings::default(), Some(now()))
}

fn rules(d: &Diagnosis) -> Vec<(&'static str, String)> {
    let mut out: Vec<(&'static str, String)> = d
        .anomalies
        .iter()
        .map(|x| (x.rule.value(), x.targets[0].fqdn().to_lowercase()))
        .collect();
    out.sort();
    out
}

fn only(d: &Diagnosis) -> &Anomaly {
    assert_eq!(
        d.anomalies.len(),
        1,
        "{:?}",
        d.anomalies.iter().map(|x| &x.title).collect::<Vec<_>>()
    );
    &d.anomalies[0]
}

fn deletion(z: &Zone, name: &str, value: Vec<u8>) -> Request {
    Request::Delete {
        zone: z.clone(),
        name: name.into(),
        value,
    }
}

#[test]
fn healthy_domain() {
    let d = diagnosis(&healthy());
    assert!(
        d.anomalies.is_empty() && d.remarks.is_empty(),
        "{:?}",
        d.anomalies
    );
    assert_eq!((d.zones, d.nodes), (3, 23));
}

#[test]
fn a_record_belongs_to_one_anomaly() {
    let mut state = healthy();
    for k in 0..5 {
        state = with(
            state,
            &direct(),
            &format!("vieux{k}"),
            vec![rec(
                dns_record::A,
                &format!("198.51.100.{}", k + 1),
                Some(400.0),
            )],
            false,
        );
        state = with(
            state,
            &reverse(),
            &(100 + k).to_string(),
            vec![rec(
                dns_record::PTR,
                &format!("vieux{k}.{DOMAIN}"),
                Some(400.0),
            )],
            false,
        );
    }
    let d = diagnosis(&state);
    let keys: Vec<_> = d
        .anomalies
        .iter()
        .flat_map(|x| x.targets.iter().map(Target::key))
        .collect();
    let unique: HashSet<_> = keys.iter().cloned().collect();
    assert_eq!(keys.len(), unique.len());
    assert!(d.anomalies.iter().all(|x| x.rule == Rule::VanishedHost));
}

#[test]
fn ns_to_an_old_dc() {
    let old = rec(dns_record::NS, &format!("vieux-dc.{DOMAIN}"), None);
    let d = diagnosis(&with(healthy(), &direct(), "@", vec![old.clone()], false));
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::NsOutsideDc, Severity::Critical)
    );
    let Explanation::NsNotDc { target, dcs, .. } = &x.explanation else {
        panic!("explanation");
    };
    assert_eq!(target, "vieux-dc.exemple.test");
    assert_eq!(dcs, &["dc1.exemple.test", "dc2.exemple.test"]);
    assert_eq!(
        x.fix.as_ref().unwrap().requests,
        [deletion(&direct(), "@", old)]
    );
    assert_eq!(
        x.fix.as_ref().unwrap().label,
        FixLabel::RemoveNs {
            target: "vieux-dc.exemple.test".into()
        }
    );
}

#[test]
fn ns_of_the_domain_name_counts_as_dc() {
    let state = with(
        healthy(),
        &direct(),
        "mixte",
        vec![a("192.0.2.1"), a("192.0.2.99")],
        false,
    );
    let state = with(
        state,
        &reverse(),
        "@",
        vec![rec(dns_record::NS, &format!("mixte.{DOMAIN}"), None)],
        false,
    );
    assert_eq!(
        rules(&diagnosis(&state)),
        [("ns-hors-dc", "2.0.192.in-addr.arpa".into())]
    );
}

#[test]
fn every_ns_wrong_one_fix_naming_the_dcs() {
    let m = msdcs();
    let state = without(
        healthy(),
        &m,
        "@",
        &rec(dns_record::NS, &format!("dc1.{DOMAIN}"), None),
    );
    let state = with(
        state,
        &m,
        "@",
        vec![
            rec(dns_record::NS, &format!("vieux-dc.{DOMAIN}"), None),
            rec(dns_record::NS, &format!("autre.{DOMAIN}"), None),
        ],
        false,
    );
    let d = diagnosis(&state);
    assert_eq!(
        d.anomalies.iter().map(|x| x.rule).collect::<Vec<_>>(),
        [Rule::NsOutsideDc; 2]
    );
    let fix = d.anomalies[0].fix.clone().unwrap();
    assert_eq!(d.anomalies[1].fix.as_ref(), Some(&fix));
    let added: Vec<&RecordData> = fix
        .requests
        .iter()
        .filter_map(|r| match r {
            Request::Add { data, .. } => Some(data),
            _ => None,
        })
        .collect();
    assert_eq!(
        added,
        [
            &RecordData::Name(format!("dc1.{DOMAIN}")),
            &RecordData::Name(format!("dc2.{DOMAIN}"))
        ]
    );
    assert_eq!(requests(&d.anomalies).len(), 4);
}

#[test]
fn ns_of_an_internal_windows_zone_as_information() {
    let anchors = zone("..TrustAnchors", Partition::Forest);
    let state = with(
        healthy(),
        &anchors,
        "@",
        vec![
            rec(dns_record::SOA, "", None),
            rec(dns_record::NS, &format!("vieux-dc.{DOMAIN}"), None),
        ],
        false,
    );
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::NsOutsideDc, Severity::Information)
    );
    assert!(
        matches!(&x.explanation, Explanation::NsNotDc { internal_zone: Some(z), .. } if z == "..TrustAnchors")
    );
}

#[test]
fn without_controller_nothing_judged_and_said() {
    let mut state = with(
        healthy(),
        &direct(),
        "@",
        vec![rec(dns_record::NS, "x.example.org", None)],
        false,
    );
    state.controllers.clear();
    let d = diagnosis(&state);
    assert!(d.anomalies.is_empty());
    assert_eq!(d.remarks.first(), Some(&HealthRemark::NoControllers));
}

#[test]
fn srv_of_the_locator_to_a_removed_dc() {
    let (d, m) = (direct(), msdcs());
    let guid_name = format!("_ldap._tcp.{GUID1}.domains");
    for (z, name) in [
        (&d, "_ldap._tcp"),
        (&d, "_kerberos._udp"),
        (&d, "_ldap._tcp.ForestDnsZones"),
        (
            &d,
            "_ldap._tcp.Default-First-Site-Name._sites.DomainDnsZones",
        ),
        (&m, "_ldap._tcp.pdc"),
        (&m, "_kerberos._tcp.Default-First-Site-Name._sites.dc"),
        (&m, guid_name.as_str()),
    ] {
        let value = rec(
            dns_record::SRV,
            &format!("0 100 389 vieux-dc.{DOMAIN}"),
            None,
        );
        let diag = diagnosis(&with(healthy(), z, name, vec![value.clone()], false));
        let x = only(&diag);
        assert_eq!(
            (x.rule, x.severity),
            (Rule::RemovedDc, Severity::Critical),
            "{name}"
        );
        assert_eq!(x.fix.as_ref().unwrap().requests, [deletion(z, name, value)]);
    }
}

#[test]
fn srv_of_a_missing_site_and_outside_the_locator() {
    let state = with(
        healthy(),
        &direct(),
        "_ldap._tcp.lyon._sites",
        vec![rec(dns_record::SRV, "0 100 389 dc-lyon.x.y", None)],
        false,
    );
    let d = diagnosis(&state);
    assert!(
        matches!(&only(&d).explanation, Explanation::SrvNotDc { missing_site: Some(s), .. } if s == "lyon")
    );
    let state = with(
        healthy(),
        &direct(),
        "_sip._tls",
        vec![rec(
            dns_record::SRV,
            &format!("0 100 443 srv1.{DOMAIN}"),
            None,
        )],
        false,
    );
    let state = with(
        state,
        &direct(),
        "_ldap._tcp.annuaire",
        vec![rec(
            dns_record::SRV,
            &format!("0 100 389 srv1.{DOMAIN}"),
            None,
        )],
        false,
    );
    assert!(diagnosis(&state).anomalies.is_empty());
}

#[test]
fn replication_cname_of_a_removed_dc() {
    let guid = "abcdefab-cdef-abcd-efab-cdefabcdefab";
    let d = diagnosis(&with(
        healthy(),
        &msdcs(),
        guid,
        vec![rec(dns_record::CNAME, &format!("vieux-dc.{DOMAIN}"), None)],
        false,
    ));
    let x = only(&d);
    assert_eq!(x.rule, Rule::RemovedDc);
    assert!(matches!(
        x.explanation,
        Explanation::ReplicationCname { .. }
    ));
}

#[test]
fn a_of_the_root_outside_the_dcs() {
    let (d, m) = (direct(), msdcs());
    for (z, name) in [(&d, "@"), (&d, "ForestDnsZones"), (&m, "gc")] {
        let value = a("192.0.2.146");
        let diag = diagnosis(&with(healthy(), z, name, vec![value.clone()], false));
        let x = only(&diag);
        assert_eq!((x.rule, x.severity), (Rule::AOutsideDc, Severity::Critical));
        assert_eq!(x.fix.as_ref().unwrap().requests, [deletion(z, name, value)]);
    }
    let mut state = healthy();
    state.controllers[1].catalog = false;
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.targets[0].name.as_str()),
        (Rule::AOutsideDc, "gc")
    );
    assert!(matches!(
        x.explanation,
        Explanation::ANotDc { catalog: true, .. }
    ));
}

#[test]
fn dc_missing_from_the_root() {
    let state = without(healthy(), &direct(), "DomainDnsZones", &a("192.0.2.2"));
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!((x.rule, x.severity), (Rule::MissingDc, Severity::Warning));
    assert_eq!(
        x.fix.as_ref().unwrap().requests,
        [Request::Add {
            zone: direct(),
            name: "DomainDnsZones".into(),
            rtype: dns_record::A,
            data: RecordData::Address("192.0.2.2".parse().unwrap()),
            ttl: DEFAULT_TTL,
        }]
    );
}

#[test]
fn addresses_of_the_dcs_from_the_resolver() {
    let mut state = healthy();
    let d = direct();
    state
        .nodes
        .get_mut(&d.dn)
        .unwrap()
        .retain(|n| !["dc1", "dc2"].contains(&n.name.to_lowercase().as_str()));
    state
        .unreadable
        .insert(d.dn.clone(), ["dc1".to_owned(), "dc2".to_owned()].into());
    state
        .resolved
        .insert(format!("dc1.{DOMAIN}"), ["192.0.2.1".to_owned()].into());
    state
        .resolved
        .insert(format!("dc2.{DOMAIN}"), ["192.0.2.2".to_owned()].into());
    let state = with(state, &d, "@", vec![a("192.0.2.146")], false);
    let diag = diagnosis(&state);
    assert_eq!(rules(&diag), [("a-hors-dc", DOMAIN.to_owned())]);
    assert!(
        diag.remarks
            .iter()
            .any(|r| matches!(r, HealthRemark::Resolved { .. }))
    );
    assert!(diag.remarks.contains(&HealthRemark::Unreadable { n: 2 }));
}

#[test]
fn vanished_host_with_its_ptr() {
    let state = with(
        healthy(),
        &direct(),
        "ancien-pc",
        vec![rec(dns_record::A, "192.0.2.150", Some(90.0))],
        false,
    );
    let state = with(
        state,
        &reverse(),
        "150",
        vec![rec(
            dns_record::PTR,
            &format!("ancien-pc.{DOMAIN}"),
            Some(90.0),
        )],
        false,
    );
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::VanishedHost, Severity::Warning)
    );
    assert_eq!(
        x.targets.iter().map(|t| t.zone.clone()).collect::<Vec<_>>(),
        [direct(), reverse()]
    );
    assert!(matches!(x.explanation, Explanation::Host { ptrs: 1, .. }));
    assert_eq!(x.fix.as_ref().unwrap().requests.len(), 2);
    // Static without account: only on demand, as information.
    let d = diagnose(
        &healthy(),
        Settings {
            statics: true,
            ..Settings::default()
        },
        Some(now()),
    );
    let x = only(&d);
    assert_eq!(
        (x.severity, x.targets[0].name.as_str()),
        (Severity::Information, "imprimante")
    );
    // Dynamic A of an existing computer.
    let state = with(
        healthy(),
        &direct(),
        "poste1",
        vec![rec(dns_record::A, "198.51.100.51", Some(3.0))],
        false,
    );
    assert!(diagnosis(&state).anomalies.is_empty());
}

#[test]
fn ptr_rules() {
    let value = rec(dns_record::PTR, &format!("ancien-srv01.{DOMAIN}"), None);
    let d = diagnosis(&with(
        healthy(),
        &reverse(),
        "200",
        vec![value.clone()],
        false,
    ));
    let x = only(&d);
    assert_eq!(x.rule, Rule::PtrWithoutName);
    assert!(matches!(&x.title, Title::PtrToNothing { name, .. } if name == "192.0.2.200"));
    assert_eq!(
        x.fix.as_ref().unwrap().requests,
        [deletion(&reverse(), "200", value)]
    );
    let d = diagnosis(&with(
        healthy(),
        &reverse(),
        "61",
        vec![rec(dns_record::PTR, &format!("srv1.{DOMAIN}"), None)],
        false,
    ));
    let x = only(&d);
    assert_eq!(x.rule, Rule::InconsistentPtr);
    assert!(
        matches!(&x.explanation, Explanation::PtrOtherAddress { theirs, .. } if theirs == &["192.0.2.60"])
    );
    let d = diagnosis(&with(
        healthy(),
        &reverse(),
        "80",
        vec![rec(dns_record::PTR, "hote.example.org", None)],
        false,
    ));
    assert!(d.anomalies.is_empty());
    for (full, expected) in [
        ("10.1.168.192.in-addr.arpa", Some("192.168.1.10")),
        ("1.168.192.in-addr.arpa", None),
        (
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa",
            Some("4321:0:1:2:3:4:567:89ab"),
        ),
        ("x.1.168.192.in-addr.arpa", None),
    ] {
        assert_eq!(
            address_of_ptr(full).map(|a| a.to_string()).as_deref(),
            expected
        );
    }
}

#[test]
fn missing_targets() {
    for (rtype, text) in [
        (dns_record::CNAME, format!("srv-intranet-old.{DOMAIN}")),
        (dns_record::SRV, format!("0 100 443 lync.{DOMAIN}")),
        (dns_record::MX, format!("10 mail.{DOMAIN}")),
    ] {
        let d = diagnosis(&with(
            healthy(),
            &direct(),
            "service",
            vec![rec(rtype, &text, None)],
            false,
        ));
        let x = only(&d);
        assert_eq!(
            (x.rule, x.severity),
            (Rule::MissingTarget, Severity::Warning)
        );
    }
    let state = with(
        healthy(),
        &direct(),
        "alias2",
        vec![rec(dns_record::CNAME, &format!("www.{DOMAIN}"), None)],
        false,
    );
    let state = with(
        state,
        &direct(),
        "mx2",
        vec![rec(dns_record::MX, "10 mx.example.org", None)],
        false,
    );
    let mut state = with(
        state,
        &direct(),
        "cache",
        vec![rec(dns_record::CNAME, &format!("secret.{DOMAIN}"), None)],
        false,
    );
    state
        .unreadable
        .insert(direct().dn, ["secret".to_owned()].into());
    let d = diagnosis(&state);
    assert_eq!(
        d.anomalies.iter().map(|x| x.rule).collect::<Vec<_>>(),
        Vec::<Rule>::new()
    );
}

#[test]
fn not_refreshed() {
    let state = with(
        healthy(),
        &direct(),
        "poste1",
        vec![rec(dns_record::A, "198.51.100.52", Some(200.0))],
        false,
    );
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(x.rule, Rule::NotRefreshed);
    assert!(matches!(&x.title, Title::NotRefreshed { days: 200, .. }));
    assert!(matches!(
        &x.explanation,
        Explanation::NotRefreshed {
            aging: Aging::Disabled,
            ..
        }
    ));
    let d = diagnose(
        &state,
        Settings {
            days: 365,
            ..Settings::default()
        },
        Some(now()),
    );
    assert!(d.anomalies.is_empty());
    // Aging of the zone at 7 + 300 days: 200 days is still normal.
    let mut aged = direct();
    aged.settings.aging = Some(true);
    aged.settings.no_refresh_interval = Some(168);
    aged.settings.refresh_interval = Some(7200);
    let mut state = healthy();
    for z in &mut state.zones {
        if z.dn == aged.dn {
            *z = aged.clone();
        }
    }
    let state = with(
        state,
        &aged,
        "poste1",
        vec![rec(dns_record::A, "198.51.100.52", Some(200.0))],
        false,
    );
    assert!(diagnosis(&state).anomalies.is_empty());
    let state = with(
        state,
        &aged,
        "poste1",
        vec![rec(dns_record::A, "198.51.100.53", Some(320.0))],
        false,
    );
    let d = diagnosis(&state);
    assert!(matches!(
        &only(&d).explanation,
        Explanation::NotRefreshed {
            aging: Aging::Enabled { days: 307 },
            ..
        }
    ));
}

#[test]
fn not_refreshed_machine_in_service() {
    let state = with(
        healthy(),
        &direct(),
        "nas",
        vec![rec(dns_record::A, "192.0.2.47", Some(3000.0))],
        false,
    );
    let mut state = with(
        state,
        &reverse(),
        "47",
        vec![rec(dns_record::PTR, &format!("nas.{DOMAIN}"), Some(3000.0))],
        false,
    );
    state.computers.insert(format!("nas.{DOMAIN}"));
    state
        .activity
        .insert(format!("nas.{DOMAIN}"), days_ago(8.0));
    let d = diagnosis(&state);
    assert_eq!(
        rules(&d),
        [
            ("non-rafraichi", format!("47.{}", reverse().name)),
            ("non-rafraichi", format!("nas.{DOMAIN}")),
        ]
    );
    for x in &d.anomalies {
        assert_eq!(x.severity, Severity::Information);
        assert!(x.fix.is_none());
        assert!(
            matches!(&x.explanation, Explanation::InService { seen, .. } if seen == "2026-10-06")
        );
    }
    assert!(requests(&d.anomalies).is_empty());
    for activity in [Some(days_ago(400.0)), None] {
        let mut s = state.clone();
        s.activity.clear();
        if let Some(date) = activity {
            s.activity.insert(format!("nas.{DOMAIN}"), date);
        }
        let d = diagnosis(&s);
        assert_eq!(
            d.anomalies
                .iter()
                .map(|x| (x.severity, x.fix.is_some()))
                .collect::<Vec<_>>(),
            [(Severity::Warning, true); 2]
        );
    }
}

#[test]
fn activity_of_a_computer() {
    let entry = |uac: i64, last: i64, password: i64| Entry {
        dn: format!("CN=NAS,CN=Computers,{BASE}"),
        attributes: vec![
            (
                "userAccountControl".into(),
                vec![uac.to_string().into_bytes()],
            ),
            (
                "lastLogonTimestamp".into(),
                vec![last.to_string().into_bytes()],
            ),
            ("pwdLastSet".into(), vec![password.to_string().into_bytes()]),
        ],
    };
    let (old, recent) = (133_000_000_000_000_000, 134_000_000_000_000_000);
    let date = activity_of(&entry(4096, old, recent)).unwrap();
    assert_eq!(
        (day(date), date.civil().hour, date.civil().minute),
        ("2025-08-18".into(), 14, 13)
    );
    assert_eq!(
        activity_of(&entry(4096, recent, 0)),
        activity_of(&entry(4096, 0, recent))
    );
    assert_eq!(activity_of(&entry(4096 | 2, recent, recent)), None);
    assert_eq!(activity_of(&entry(4096, 0, 0)), None);
}

#[test]
fn names_held_by_the_dcs_never_not_refreshed() {
    let state = with(
        healthy(),
        &direct(),
        "@",
        vec![rec(dns_record::A, "192.0.2.1", Some(400.0))],
        false,
    );
    let state = with(
        state,
        &direct(),
        "_ldap._tcp",
        vec![rec(
            dns_record::SRV,
            &format!("0 0 389 dc1.{DOMAIN}"),
            Some(400.0),
        )],
        false,
    );
    let state = with(
        state,
        &msdcs(),
        "gc",
        vec![rec(dns_record::A, "192.0.2.2", Some(400.0))],
        false,
    );
    assert!(diagnosis(&state).anomalies.is_empty());
}

#[test]
fn without_ptr() {
    let state = without(
        healthy(),
        &reverse(),
        "2",
        &rec(dns_record::PTR, &format!("dc2.{DOMAIN}"), None),
    );
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::WithoutPtr, Severity::Information)
    );
    assert_eq!(
        x.fix.as_ref().unwrap().requests,
        [Request::Add {
            zone: reverse(),
            name: "2".into(),
            rtype: dns_record::PTR,
            data: RecordData::Name(format!("DC2.{DOMAIN}")),
            ttl: DEFAULT_TTL,
        }]
    );
    let state = with(
        healthy(),
        &direct(),
        "poste1",
        vec![rec(dns_record::A, "192.0.2.51", Some(1.0))],
        false,
    );
    assert!(diagnosis(&state).anomalies.is_empty());
    let state = without(
        healthy(),
        &reverse(),
        "60",
        &rec(dns_record::PTR, &format!("srv1.{DOMAIN}"), None),
    );
    assert_eq!(
        rules(&diagnosis(&state)),
        [("sans-ptr", format!("srv1.{DOMAIN}"))]
    );
}

#[test]
fn old_tombstone_and_its_purge() {
    let state = with(healthy(), &direct(), "parti", vec![grave(30.0)], true);
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::OldTombstone, Severity::Information)
    );
    assert!(x.targets[0].value.is_none());
    assert_eq!(
        x.fix.as_ref().unwrap().requests,
        [Request::Purge {
            zone: direct(),
            name: "parti".into()
        }]
    );
    assert!(
        diagnosis(&with(
            healthy(),
            &direct(),
            "recent",
            vec![grave(3.0)],
            true
        ))
        .anomalies
        .is_empty()
    );
    let d = diagnose(
        &state,
        Settings {
            tombstone_days: 60,
            ..Settings::default()
        },
        Some(now()),
    );
    assert!(d.anomalies.is_empty());
}

#[test]
fn soa_naming_a_removed_dc() {
    let base = without(healthy(), &reverse(), "@", &rec(dns_record::SOA, "", None));
    let state = with(
        base.clone(),
        &reverse(),
        "@",
        vec![soa_naming(&format!("ancien-dc.{DOMAIN}"))],
        false,
    );
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::SoaOutsideDc, Severity::Information)
    );
    assert!(x.fix.is_none() && x.targets[0].fqdn() == reverse().name);
    for server in [
        DOMAIN.to_owned(),
        format!("DC2.{DOMAIN}."),
        format!("dc1.{DOMAIN}"),
    ] {
        let state = with(
            base.clone(),
            &reverse(),
            "@",
            vec![soa_naming(&server)],
            false,
        );
        assert!(diagnosis(&state).anomalies.is_empty(), "{server}");
    }
}

#[test]
fn duplicate_zones() {
    let legacy = zone(DOMAIN, Partition::Legacy);
    let mut state = healthy();
    state.zones.push(legacy.clone());
    let d = diagnosis(&state);
    let x = only(&d);
    assert_eq!(
        (x.rule, x.severity),
        (Rule::DuplicateZone, Severity::Critical)
    );
    assert!(x.fix.is_none());
    let mut state = healthy();
    state.zones.push(zone("RootDNSServers", Partition::Domain));
    state.zones.push(zone("RootDNSServers", Partition::Legacy));
    assert!(diagnosis(&state).anomalies.is_empty());
    let mut state = healthy();
    state.zones.push(zone("RootDNSServers", Partition::Domain));
    state.zones.push(zone("RootDNSServers", Partition::Forest));
    let d = diagnosis(&state);
    assert_eq!(
        (only(&d).rule, only(&d).severity),
        (Rule::DuplicateZone, Severity::Information)
    );
}

#[test]
fn order_by_severity() {
    let state = with(healthy(), &direct(), "parti", vec![grave(30.0)], true);
    let state = with(
        state,
        &direct(),
        "@",
        vec![rec(dns_record::NS, &format!("vieux-dc.{DOMAIN}"), None)],
        false,
    );
    let state = with(
        state,
        &direct(),
        "intranet",
        vec![rec(dns_record::CNAME, &format!("absent.{DOMAIN}"), None)],
        false,
    );
    let severities: Vec<Severity> = diagnosis(&state)
        .anomalies
        .iter()
        .map(|x| x.severity)
        .collect();
    assert_eq!(
        severities,
        [Severity::Critical, Severity::Warning, Severity::Information]
    );
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The file servers offered by the « Shares » window (ADR 0023 § 2, J8.2, J8.7).
//!
//! A computer of the directory is offered when it has a DNS name and either is a domain
//! controller, or declares a server system (`operatingSystem` contains « Server »), or shows a
//! mark of a file service: an explicit `cifs/` service principal name, or an account joined by
//! a client (`RestrictedKrbHost/` principal, which Windows, `net ads join` and adcli register)
//! that declares no system. Every Windows machine writes its system when it joins and keeps it
//! current; Linux machines joined by realmd declare theirs; the joined accounts left without one
//! are, in practice, Samba members and the appliances built on Samba, which are file servers.
//! The `HOST/` and `RestrictedKrbHost/` principals alone say nothing: a Windows workstation has
//! both, and `cifs/` is an alias of `HOST/` that nobody needs to register.
//!
//! The directory does the filtering (one paged search, the matches only); [`classify`] applies
//! the same criterion to the entries read, to rank them, and [`offered`] orders the list:
//! domain controllers, servers, the other file servers, then the servers remembered in the
//! profile that the directory did not offer.

/// The servers of the directory, as an LDAP filter (see the module).
pub const FILTER: &str = "(&(objectCategory=computer)(dNSHostName=*)(|\
(userAccountControl:1.2.840.113556.1.4.803:=8192)\
(operatingSystem=*Server*)\
(servicePrincipalName=cifs/*)\
(&(servicePrincipalName=RestrictedKrbHost/*)(!(operatingSystem=*)))))";

/// The attributes [`classify`] reads.
pub const ATTRIBUTES: [&str; 4] = [
    "dNSHostName",
    "operatingSystem",
    "userAccountControl",
    "servicePrincipalName",
];

/// `SERVER_TRUST_ACCOUNT` of `userAccountControl`: a domain controller.
const SERVER_TRUST_ACCOUNT: u32 = 0x2000;

/// Why a server is offered, in the order of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A domain controller.
    DomainController,
    /// A computer whose system is a server system.
    Server,
    /// A mark of a file service: `cifs/` principal, or joined without a system declared.
    FileService,
    /// Remembered in the profile, not offered by the directory.
    Remembered,
}

/// A file server offered: its DNS name (lower case), its system as declared (may be empty).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    pub name: String,
    pub system: String,
    pub kind: Kind,
}

/// The service class of a principal name (`cifs` of `cifs/fs1.lab.test`), lower case.
fn service_class(spn: &str) -> String {
    spn.split('/')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// The place of a computer in the list, from what the directory says of it; `None` when the
/// criterion of [`FILTER`] does not hold (or when it has no DNS name).
pub fn classify(
    dns_host_name: &str,
    operating_system: &str,
    user_account_control: u32,
    service_principal_names: &[String],
) -> Option<Offered> {
    let name = dns_host_name.trim().trim_end_matches('.').to_lowercase();
    if name.is_empty() {
        return None;
    }
    let has = |class: &str| {
        service_principal_names
            .iter()
            .any(|spn| service_class(spn) == class)
    };
    let kind = if user_account_control & SERVER_TRUST_ACCOUNT != 0 {
        Kind::DomainController
    } else if operating_system.to_lowercase().contains("server") {
        Kind::Server
    } else if has("cifs") || (operating_system.is_empty() && has("restrictedkrbhost")) {
        Kind::FileService
    } else {
        return None;
    };
    Some(Offered {
        name,
        system: operating_system.to_owned(),
        kind,
    })
}

/// The list offered: the servers of the directory by kind then name, each name once, then the
/// servers of the profile (`remembered`, in their order) the directory did not offer.
pub fn offered(mut found: Vec<Offered>, remembered: &[String]) -> Vec<Offered> {
    found.sort_by(|a, b| (a.kind, &a.name).cmp(&(b.kind, &b.name)));
    let mut seen = std::collections::HashSet::new();
    found.retain(|o| seen.insert(o.name.clone()));
    for name in remembered {
        let name = name.trim().to_lowercase();
        if !name.is_empty() && !found.iter().any(|o| o.name == name) {
            found.push(Offered {
                name,
                system: String::new(),
                kind: Kind::Remembered,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spns(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    /// What the lab directories hold (LAB.TEST and WIN.TEST, 2026-10-22).
    fn lab() -> Vec<(&'static str, &'static str, u32, Vec<String>)> {
        vec![
            // Samba DC with a system, Samba DC without one, Windows DC.
            (
                "dc1.lab.test",
                "Samba-4.22.11-Debian-4.22.11+dfsg-0+deb13u1",
                532_480,
                spns(&["HOST/DC1", "ldap/dc1.lab.test", "RestrictedKrbHost/DC1"]),
            ),
            (
                "dc2.lab.test",
                "",
                532_480,
                spns(&["HOST/DC2", "RestrictedKrbHost/dc2.lab.test"]),
            ),
            (
                "WDC1.win.test",
                "Windows Server 2025 Standard Evaluation",
                532_480,
                spns(&["HOST/WDC1", "DNS/WDC1.win.test", "RestrictedKrbHost/WDC1"]),
            ),
            // Samba member joined by `net ads join`: no system.
            (
                "fs1.lab.test",
                "",
                4096,
                spns(&[
                    "HOST/FS1.lab.test",
                    "RestrictedKrbHost/FS1.lab.test",
                    "HOST/FS1",
                    "RestrictedKrbHost/FS1",
                ]),
            ),
            // The joined Windows workstation: the same principals, a system.
            (
                "annuaire-poste1.lab.test",
                "Version d’évaluation de Windows 11 Entreprise",
                4096,
                spns(&[
                    "HOST/annuaire-poste1.lab.test",
                    "RestrictedKrbHost/annuaire-poste1.lab.test",
                    "HOST/ANNUAIRE-POSTE1",
                    "RestrictedKrbHost/ANNUAIRE-POSTE1",
                ]),
            ),
            // Fictitious computers: a server, workstations with or without a system.
            (
                "par-srv02.lab.test",
                "Windows Server 2022 Standard",
                4096,
                spns(&["HOST/PAR-SRV02", "HOST/par-srv02.lab.test"]),
            ),
            (
                "par-pc0668.lab.test",
                "Windows 11 Entreprise",
                4096,
                spns(&["HOST/PAR-PC0668", "HOST/par-pc0668.lab.test"]),
            ),
            (
                "lil-pc0209.lab.test",
                "Ubuntu",
                4096,
                spns(&["HOST/LIL-PC0209", "HOST/lil-pc0209.lab.test"]),
            ),
            (
                "par-pc0004.lab.test",
                "",
                4096,
                spns(&["HOST/PAR-PC0004", "HOST/par-pc0004.lab.test"]),
            ),
            (
                "pc-nan-dir-1.win.test",
                "Windows 11 Entreprise",
                4096,
                vec![],
            ),
            (
                "srv-paris.win.test",
                "Windows Server 2022 Standard",
                4096,
                vec![],
            ),
            // No DNS name: never offered.
            ("", "Windows Server 2012 R2 Standard", 4098, vec![]),
        ]
    }

    fn classified() -> Vec<Offered> {
        lab()
            .into_iter()
            .filter_map(|(n, s, u, p)| classify(n, s, u, &p))
            .collect()
    }

    #[test]
    fn the_lab_gives_dcs_servers_and_fs1_not_the_workstations() {
        let list = offered(classified(), &[]);
        let names: Vec<(&str, Kind)> = list.iter().map(|o| (o.name.as_str(), o.kind)).collect();
        assert_eq!(
            names,
            [
                ("dc1.lab.test", Kind::DomainController),
                ("dc2.lab.test", Kind::DomainController),
                ("wdc1.win.test", Kind::DomainController),
                ("par-srv02.lab.test", Kind::Server),
                ("srv-paris.win.test", Kind::Server),
                ("fs1.lab.test", Kind::FileService),
            ]
        );
    }

    #[test]
    fn an_explicit_cifs_principal_is_a_file_service() {
        let o = classify(
            "nas.lab.test",
            "Windows 11 Entreprise",
            4096,
            &spns(&["HOST/NAS", "CIFS/nas.lab.test"]),
        )
        .expect("offered");
        assert_eq!(o.kind, Kind::FileService);
        assert_eq!(o.system, "Windows 11 Entreprise");
        // `cifsx/` is another class; the host of a principal does not count.
        assert!(classify("pc.lab.test", "", 4096, &spns(&["cifsx/pc", "HOST/cifs"])).is_none());
    }

    #[test]
    fn the_server_system_is_matched_without_case() {
        let o = classify("x.lab.test.", "windows SERVER 2019", 4096, &[]).expect("offered");
        assert_eq!((o.name.as_str(), o.kind), ("x.lab.test", Kind::Server));
    }

    #[test]
    fn remembered_servers_come_last_once() {
        let list = offered(
            classified(),
            &[
                "Saisi.lab.test".to_owned(),
                "fs1.lab.test".to_owned(),
                "dc1.lab.test".to_owned(),
                " ".to_owned(),
                "autre.lab.test".to_owned(),
            ],
        );
        let tail: Vec<(&str, Kind)> = list
            .iter()
            .skip(6)
            .map(|o| (o.name.as_str(), o.kind))
            .collect();
        assert_eq!(
            tail,
            [
                ("saisi.lab.test", Kind::Remembered),
                ("autre.lab.test", Kind::Remembered),
            ]
        );
        // fs1 and dc1 keep the place the directory gives them.
        assert_eq!(list.iter().filter(|o| o.name == "fs1.lab.test").count(), 1);
        assert_eq!(list[0].name, "dc1.lab.test");
    }

    #[test]
    fn a_name_found_twice_is_offered_once() {
        let twice = vec![
            classify("dc1.lab.test", "", 532_480, &[]).expect("dc"),
            classify("DC1.lab.test", "", 532_480, &[]).expect("dc"),
        ];
        assert_eq!(offered(twice, &[]).len(), 1);
    }

    /// The filter names what `classify` reads, with each mark of the criterion.
    #[test]
    fn the_filter_holds_each_mark() {
        for part in [
            "(objectCategory=computer)",
            "(dNSHostName=*)",
            "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
            "(operatingSystem=*Server*)",
            "(servicePrincipalName=cifs/*)",
            "(&(servicePrincipalName=RestrictedKrbHost/*)(!(operatingSystem=*)))",
        ] {
            assert!(FILTER.contains(part), "{part}");
        }
        assert_eq!(FILTER.matches('(').count(), FILTER.matches(')').count());
    }
}

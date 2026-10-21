// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS health (J3.5, `annuaire.vue.sante_dns` and the sentences of
//! `annuaire.core.sante_dns`) put in rows and sentences, without GTK: the table of the
//! anomalies, the summary of the diagnosis, the details of the anomaly chosen. The core
//! names titles, explanations, fixes and remarks; they are said here.

use annuaire_codecs::time::UtcTime;
use annuaire_core::changes::dns_record_text;
use annuaire_core::dns_health::{
    Aging, Anomaly, Diagnosis, Explanation, FixLabel, HealthRemark, Rule, Severity, Target, Title,
};

use crate::catalog::AppCatalog;
use crate::dns_views::format_time;
use crate::i18n::{fill, tr, tr_ctx, tr_n};

pub fn icon(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "dialog-error-symbolic",
        Severity::Warning => "dialog-warning-symbolic",
        Severity::Information => "dialog-information-symbolic",
    }
}

pub fn severity_label(severity: Severity) -> String {
    match severity {
        Severity::Information => tr_ctx("severity", "Information"),
        Severity::Warning => tr("Warning"),
        Severity::Critical => tr("Critical"),
    }
}

/// `libelle_regle`.
pub fn rule_label(rule: Rule) -> String {
    match rule {
        Rule::NsOutsideDc => tr("NS outside the DCs"),
        Rule::RemovedDc => tr("Removed DC"),
        Rule::AOutsideDc => tr("A outside the DCs"),
        Rule::MissingDc => tr("Missing DC"),
        Rule::VanishedHost => tr("Vanished machine"),
        Rule::PtrWithoutName => tr("PTR without a name"),
        Rule::InconsistentPtr => tr("Inconsistent PTR"),
        Rule::MissingTarget => tr("Missing target"),
        Rule::NotRefreshed => tr("Not refreshed"),
        Rule::WithoutPtr => tr("Without PTR"),
        Rule::OldTombstone => tr("Old tombstone"),
        Rule::SoaOutsideDc => tr("SOA outside DCs"),
        Rule::DuplicateZone => tr("Duplicate zone"),
    }
}

/// Names sorted, or « none » (`_liste`).
fn list(names: &[String]) -> String {
    if names.is_empty() {
        tr("none")
    } else {
        names.join(", ")
    }
}

pub fn title(t: &Title) -> String {
    match t {
        Title::NsNotDc { target } => fill(
            &tr("NS to {cible}, which is not a DC"),
            &[("cible", target)],
        ),
        Title::SrvNotDc { name, target } => fill(
            &tr("SRV {nom} to {cible}, which is not a DC"),
            &[("nom", name), ("cible", target)],
        ),
        Title::ReplicationCname { target } => fill(
            &tr("Replication CNAME of a removed DC ({cible})"),
            &[("cible", target)],
        ),
        Title::ANotDc { name, address } => fill(
            &tr("{nom} points to {adresse}, which is not a DC"),
            &[("nom", name), ("adresse", address)],
        ),
        Title::DcMissingFrom { dc, name } => {
            fill(&tr("{dc} missing from {nom}"), &[("dc", dc), ("nom", name)])
        }
        Title::HostWithoutAccount { name } => fill(
            &tr("{nom}: machine without a computer account"),
            &[("nom", name)],
        ),
        Title::StaticWithoutAccount { name } => fill(
            &tr("{nom}: static record without a computer account"),
            &[("nom", name)],
        ),
        Title::PtrToNothing { name, target } => fill(
            &tr("PTR {nom} to {cible}, which does not exist"),
            &[("nom", name), ("cible", target)],
        ),
        Title::PtrOtherAddress { address, target } => fill(
            &tr("PTR {adresse} to {cible}, which has another address"),
            &[("adresse", address), ("cible", target)],
        ),
        Title::TargetMissing {
            rtype,
            name,
            target,
        } => fill(
            &tr("{type} {nom} to {cible}, which does not exist"),
            &[("type", rtype), ("nom", name), ("cible", target)],
        ),
        Title::NotRefreshed { name, days } => fill(
            &tr("{nom}: not refreshed for {jours} days"),
            &[("nom", name), ("jours", &days.to_string())],
        ),
        Title::NotRefreshedInService { name, days } => fill(
            &tr("{nom}: not refreshed for {jours} days, machine in service"),
            &[("nom", name), ("jours", &days.to_string())],
        ),
        Title::WithoutPtr { name, address } => fill(
            &tr("{nom} ({adresse}) without PTR"),
            &[("nom", name), ("adresse", address)],
        ),
        Title::SoaNotDc { zone, server } => fill(
            &tr("SOA of {zone}: primary server {serveur}, which is not a DC"),
            &[("zone", zone), ("serveur", server)],
        ),
        Title::DuplicateZone { zone, n } => fill(
            &tr("Zone {zone} present in {n} locations"),
            &[("zone", zone), ("n", &n.to_string())],
        ),
        Title::OldTombstone { name, days } => fill(
            &tr("{nom}: deleted (tombstone) for {jours} days"),
            &[("nom", name), ("jours", &days.to_string())],
        ),
    }
}

#[allow(clippy::too_many_lines)]
pub fn explanation(e: &Explanation) -> String {
    match e {
        Explanation::NsNotDc {
            name,
            target,
            dcs,
            only_server,
            internal_zone,
        } => {
            let mut text = fill(
                &tr(
                    "{nom} names {cible} as a name server, but {cible} is not a domain controller (current DCs: {dcs}). Resolvers and secondary servers will query it for nothing, and dynamic updates may be sent to it.",
                ),
                &[("nom", name), ("cible", target), ("dcs", &list(dcs))],
            );
            if *only_server {
                text.push(' ');
                text += &tr("This is the only server of this delegation: fix it by hand.");
            }
            if let Some(zone) = internal_zone {
                text.push(' ');
                text += &fill(
                    &tr(
                        "{zone} is an internal zone of the Windows DNS server (DNSSEC trust anchors), which Samba does not serve: no effect as long as no Windows DC comes back.",
                    ),
                    &[("zone", zone)],
                );
            }
            text
        }
        Explanation::SrvNotDc {
            target,
            dcs,
            missing_site,
        } => {
            let site = missing_site.as_ref().map_or_else(String::new, |s| {
                format!(
                    " {}",
                    fill(
                        &tr("The site “{site}” does not exist either."),
                        &[("site", s)]
                    )
                )
            });
            fill(
                &tr(
                    "This DC locator record sends computers to {cible}, which is not (or no longer) a domain controller (current DCs: {dcs}). Computers that pick it wait for an answer that never comes: slow logons, Kerberos failures.{site}",
                ),
                &[("cible", target), ("dcs", &list(dcs)), ("site", &site)],
            )
        }
        Explanation::ReplicationCname { name, target } => fill(
            &tr(
                "{nom} is the replication alias of a domain controller whose “NTDS Settings” object no longer exists (no nTDSDSA has this GUID). It is a leftover of the DC {cible}, removed from the directory.",
            ),
            &[("nom", name), ("cible", target)],
        ),
        Explanation::ANotDc {
            name,
            catalog,
            allowed,
            address,
        } => {
            let what = if *catalog {
                tr("global catalog")
            } else {
                tr("domain controller")
            };
            fill(
                &tr(
                    "{nom} must point only to {quoi}s (addresses: {permises}). {adresse} is not one: computers that read Group Policy, the DNS partitions or the catalog through this name end up every other time on a machine that does not respond.",
                ),
                &[
                    ("nom", name),
                    ("quoi", &what),
                    ("permises", &list(allowed)),
                    ("adresse", address),
                ],
            )
        }
        Explanation::DcMissing {
            dc,
            addresses,
            name,
        } => fill(
            &tr(
                "No address of the DC {dc} ({adresses}) appears under {nom}: computers do not find it through this name. The DC normally adds it itself (samba_dnsupdate, netlogon).",
            ),
            &[("dc", dc), ("adresses", &list(addresses)), ("nom", name)],
        ),
        Explanation::Host { name, date, ptrs } => {
            let ptr = if *ptrs > 0 {
                fill(
                    &tr_n(
                        "The PTR record pointing to it goes with it.",
                        "The {n} PTR records pointing to it go with it.",
                        *ptrs as u64,
                    ),
                    &[("n", &ptrs.to_string())],
                )
            } else {
                String::new()
            };
            fill(
                &tr(
                    "{nom} was registered dynamically by a machine (last refreshed on {date}), but no computer account in the directory has this name: the machine was removed from the domain or deleted. If its address is reassigned, this name will lead to another machine. {ptr}",
                ),
                &[("nom", name), ("date", date), ("ptr", &ptr)],
            )
            .trim()
            .to_owned()
        }
        Explanation::Static { name } => fill(
            &tr(
                "{nom} was written by hand and matches no computer account. This is normal for a printer or a device outside the domain; otherwise, it is a leftover.",
            ),
            &[("nom", name)],
        ),
        Explanation::PtrToNothing { address, target } => fill(
            &tr(
                "Reverse lookup of {adresse} gives {cible}, but this name has neither A nor AAAA in its zone: a leftover of a vanished machine. Logs and tools that resolve addresses will show a wrong name.",
            ),
            &[("adresse", address), ("cible", target)],
        ),
        Explanation::PtrOtherAddress {
            address,
            target,
            theirs,
        } => fill(
            &tr(
                "Reverse lookup of {adresse} gives {cible}, but {cible} has the address {siennes}. The PTR probably dates from an old address of the machine.",
            ),
            &[
                ("adresse", address),
                ("cible", target),
                ("siennes", &list(theirs)),
            ],
        ),
        Explanation::TargetMissing {
            name,
            target,
            address,
        } => {
            let suffix = if *address {
                tr(" (A or AAAA)")
            } else {
                String::new()
            };
            fill(
                &tr(
                    "{nom} points to {cible}, which has no record in its zone{adresse}: anything going through this name fails. Delete it, or recreate the target if the service still exists elsewhere.",
                ),
                &[("nom", name), ("cible", target), ("adresse", &suffix)],
            )
        }
        Explanation::NotRefreshed {
            name,
            date,
            threshold,
            aging,
        } => {
            let phrase = match aging {
                Aging::Enabled { days } => fill(
                    &tr(
                        "Aging is enabled on the zone ({jours} days): the server's scavenging should remove it; if it is still there, scavenging is not running.",
                    ),
                    &[("jours", &days.to_string())],
                ),
                Aging::Disabled => tr("Aging is disabled on the zone: nothing will remove it."),
            };
            fill(
                &tr(
                    "The machine that registered {nom} has not refreshed it since {date} (threshold: {seuil} days). It has probably been off for a long time, or has changed its name; if it comes back, it will register again. {phrase}",
                ),
                &[
                    ("nom", name),
                    ("date", date),
                    ("seuil", &threshold.to_string()),
                    ("phrase", &phrase),
                ],
            )
        }
        Explanation::InService {
            machine,
            name,
            date,
            seen,
        } => fill(
            &tr(
                "{machine} has not refreshed {nom} since {date}, but its computer account is active (last activity on {vue}): this is a device that writes its name only once (NAS, Samba server, non-Windows system). The name is still in use, do not delete it. If aging is enabled on the zone some day, scavenging will remove it: rewriting it as a static record protects it.",
            ),
            &[
                ("machine", machine),
                ("nom", name),
                ("date", date),
                ("vue", seen),
            ],
        ),
        Explanation::WithoutPtr {
            zone,
            address,
            name,
        } => fill(
            &tr(
                "The reverse zone {zone} exists, but no PTR of {adresse} leads to {nom}: reverse lookup of this address fails or gives another name. Mostly a problem for a server.",
            ),
            &[("zone", zone), ("adresse", address), ("nom", name)],
        ),
        Explanation::SoaNotDc { zone, server, dcs } => fill(
            &tr(
                "The stored SOA of {zone} names {serveur} as primary server, but {serveur} is not a domain controller (current DCs: {dcs}): it is left over from a removed DC. Samba answers with its own name, whatever the record says; but the DNS window, a copy of the zone or a Windows DC added later read the stored value. Fix it by hand, keeping the next serial number: for example samba-tool dns update <DC> {zone} @ SOA “old” “new”.",
            ),
            &[("zone", zone), ("serveur", server), ("dcs", &list(dcs))],
        ),
        Explanation::DuplicateZone {
            zone,
            places,
            root_hints,
        } => {
            let template = if *root_hints {
                tr(
                    "The root hints (Internet root servers) are stored in several locations ({lieux}): a leftover from an older version of Windows, with no effect as long as DNS goes through forwarders. The oldest copy can be deleted by hand.",
                )
            } else {
                tr(
                    "The zone {zone} exists in several locations ({lieux}). The server serves only one of them, and which one is undefined: the records of the other are ignored, or served by another DC. Compare both copies, keep the one in DomainDnsZones or ForestDnsZones, and delete the other by hand.",
                )
            };
            fill(&template, &[("zone", zone), ("lieux", &list(places))])
        }
        Explanation::OldTombstone {
            name,
            date,
            threshold,
        } => fill(
            &tr(
                "The last record of {nom} was removed on {date}; the object stays in the directory, marked as deleted. Windows purges it after {seuil} days; Samba only if DNS scavenging is enabled. Purging deletes the object (the name no longer has any data).",
            ),
            &[
                ("nom", name),
                ("date", date),
                ("seuil", &threshold.to_string()),
            ],
        ),
    }
}

pub fn fix_label(label: &FixLabel) -> String {
    match label {
        FixLabel::Delete { n } => fill(
            &tr_n("Delete this record", "Delete these {n} records", *n as u64),
            &[("n", &n.to_string())],
        ),
        FixLabel::ReplaceNs { zone, dcs } => fill(
            &tr("Replace the NS records of {zone} with the DCs ({dcs})"),
            &[("zone", zone), ("dcs", &list(dcs))],
        ),
        FixLabel::RemoveNs { target } => fill(&tr("Remove the NS {cible}"), &[("cible", target)]),
        FixLabel::AddAddress { address, name } => fill(
            &tr("Add {adresse} to {nom}"),
            &[("adresse", address), ("nom", name)],
        ),
        FixLabel::AddPtr { address, name } => fill(
            &tr("Add the PTR {adresse} → {nom}"),
            &[("adresse", address), ("nom", name)],
        ),
        FixLabel::Purge => tr("Purge the node"),
    }
}

pub fn remark(r: &HealthRemark) -> String {
    match r {
        HealthRemark::Resolved { dcs } => fill(
            &tr(
                "Addresses of {dcs} taken from this computer's resolver: their DNS node cannot be read with this account.",
            ),
            &[("dcs", &list(dcs))],
        ),
        HealthRemark::Unreadable { n } => fill(
            &tr_n(
                "{n} DNS name cannot be read with this account (permissions): it is never considered missing. An administrator account sees everything.",
                "{n} DNS names cannot be read with this account (permissions): they are never considered missing. An administrator account sees everything.",
                *n as u64,
            ),
            &[("n", &n.to_string())],
        ),
        HealthRemark::NoControllers => tr(
            "No domain controller (nTDSDSA object) read: NS, SRV and A records of the DCs not checked.",
        ),
        HealthRemark::NoDcAddresses => {
            tr("DC addresses not found in the zones: A records of the root not checked.")
        }
    }
}

/// A row of the table (`LigneAnomalie`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyLine {
    pub severity: String,
    pub icon: String,
    pub rule: String,
    pub title: String,
    /// Label of the fix, or what to do by hand.
    pub fix: String,
    pub fixable: bool,
    pub accessible: String,
    pub anomaly: Anomaly,
}

/// `ligne`.
pub fn line(anomaly: &Anomaly) -> AnomalyLine {
    let severity = severity_label(anomaly.severity);
    let rule = rule_label(anomaly.rule);
    let title = title(&anomaly.title);
    AnomalyLine {
        icon: icon(anomaly.severity).to_owned(),
        fix: anomaly
            .fix
            .as_ref()
            .map_or_else(|| tr("to fix by hand"), |f| fix_label(&f.label)),
        fixable: anomaly.fix.is_some(),
        accessible: fill(
            &tr("{gravite}, {regle}: {titre}"),
            &[("gravite", &severity), ("regle", &rule), ("titre", &title)],
        ),
        severity,
        rule,
        title,
        anomaly: anomaly.clone(),
    }
}

/// « 57 issues: 2 critical, 52 warnings, 3 information. » (or none) (`resume`).
pub fn summary(d: &Diagnosis) -> String {
    let total = d.anomalies.len();
    let (zones, nodes) = (d.zones.to_string(), d.nodes.to_string());
    let text = if total == 0 {
        fill(
            &tr("No issues in {zones} zones ({noeuds} names)."),
            &[("zones", &zones), ("noeuds", &nodes)],
        )
    } else {
        let mut parts = Vec::new();
        for severity in [Severity::Critical, Severity::Warning, Severity::Information] {
            let n = d.of_severity(severity);
            if n == 0 {
                continue;
            }
            let template = match (severity, n == 1) {
                (Severity::Critical, true) => tr("{n} critical"),
                (Severity::Critical, false) => tr_ctx("plural", "{n} critical"),
                (Severity::Warning, true) => tr("{n} warning"),
                (Severity::Warning, false) => tr("{n} warnings"),
                (Severity::Information, true) => tr("{n} information"),
                (Severity::Information, false) => tr_ctx("plural", "{n} information"),
            };
            parts.push(fill(&template, &[("n", &n.to_string())]));
        }
        fill(
            &tr_n(
                "{n} issue: {detail}, in {zones} zones ({noeuds} names).",
                "{n} issues: {detail}, in {zones} zones ({noeuds} names).",
                total as u64,
            ),
            &[
                ("n", &total.to_string()),
                ("detail", &parts.join(", ")),
                ("zones", &zones),
                ("noeuds", &nodes),
            ],
        )
    };
    std::iter::once(text)
        .chain(d.remarks.iter().map(remark))
        .collect::<Vec<_>>()
        .join(" ")
}

/// `decrire_lecture`.
pub fn read_text(dc: &str, date: Option<UtcTime>) -> String {
    match date {
        None => fill(&tr("Read on {dc}"), &[("dc", dc)]),
        Some(date) => fill(
            &tr("Read on {dc} on {date}"),
            &[("dc", dc), ("date", &format_time(date))],
        ),
    }
}

/// `texte_vise`.
pub fn target_text(target: &Target) -> String {
    let Some(value) = &target.value else {
        return fill(&tr("{nom} (whole node)"), &[("nom", &target.fqdn())]);
    };
    let text = dns_record_text(value, &AppCatalog)
        .ok()
        .flatten()
        .unwrap_or_else(|| tr("unreadable value"));
    fill(
        &tr("{nom}: {valeur}"),
        &[("nom", &target.fqdn()), ("valeur", &text)],
    )
}

/// The details of the anomaly chosen: explanation, records targeted, fix (`details`).
pub fn details(anomaly: &Anomaly) -> String {
    let targets: Vec<String> = anomaly
        .targets
        .iter()
        .map(|t| format!("• {}", target_text(t)))
        .collect();
    let fix = match &anomaly.fix {
        Some(f) => fill(
            &tr("Proposed fix: {libelle}. It goes through the preview."),
            &[("libelle", &fix_label(&f.label))],
        ),
        None => tr("No automatic fix: to be done by hand."),
    };
    let heading = tr_n(
        "Targeted record:",
        "Targeted records:",
        anomaly.targets.len() as u64,
    );
    format!(
        "{}\n\n{heading}\n{}\n\n{fix}",
        explanation(&anomaly.explanation),
        targets.join("\n")
    )
}

/// `libelle_corriger`.
pub fn fix_button(anomalies: &[Anomaly]) -> String {
    let n = anomalies.iter().filter(|a| a.fix.is_some()).count();
    if n <= 1 {
        tr("Fix…")
    } else {
        fill(&tr("Fix the {n} Issues…"), &[("n", &n.to_string())])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use annuaire_core::dns::{Partition, Zone};
    use annuaire_core::dns_health::Fix;
    use annuaire_core::dns_write::Request;

    #[test]
    fn rows_summary_and_details() {
        let zone = Zone {
            dn: "DC=lab.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=lab,DC=test".into(),
            name: "lab.test".into(),
            partition: Partition::Domain,
            settings: Default::default(),
            modified: None,
        };
        let anomaly = Anomaly {
            rule: Rule::OldTombstone,
            severity: Severity::Information,
            title: Title::OldTombstone {
                name: "parti.lab.test".into(),
                days: 30,
            },
            explanation: Explanation::OldTombstone {
                name: "parti.lab.test".into(),
                date: "2026-09-14".into(),
                threshold: 14,
            },
            targets: vec![Target {
                zone: zone.clone(),
                name: "parti".into(),
                value: None,
            }],
            fix: Some(Fix {
                label: FixLabel::Purge,
                requests: vec![Request::Purge {
                    zone,
                    name: "parti".into(),
                }],
            }),
        };
        let l = line(&anomaly);
        assert_eq!(l.title, "parti.lab.test: deleted (tombstone) for 30 days");
        assert_eq!(l.fix, "Purge the node");
        assert_eq!(
            l.accessible,
            "Information, Old tombstone: parti.lab.test: deleted (tombstone) for 30 days"
        );
        let text = details(&anomaly);
        assert!(text.contains("Targeted record:\n• parti.lab.test (whole node)"));
        assert!(text.ends_with("Proposed fix: Purge the node. It goes through the preview."));
        let diagnosis = Diagnosis {
            anomalies: vec![anomaly.clone(), anomaly.clone()],
            settings: Default::default(),
            now: annuaire_codecs::time::NT_EPOCH,
            zones: 3,
            nodes: 23,
            records: 40,
            remarks: vec![HealthRemark::NoDcAddresses],
        };
        assert_eq!(
            summary(&diagnosis),
            "2 issues: 2 information, in 3 zones (23 names). DC addresses not found in the zones: A records of the root not checked."
        );
        assert_eq!(fix_button(&diagnosis.anomalies), "Fix the 2 Issues…");
        assert_eq!(
            explanation(&Explanation::Host {
                name: "x".into(),
                date: "?".into(),
                ptrs: 0
            }),
            "x was registered dynamically by a machine (last refreshed on ?), but no computer account in the directory has this name: the machine was removed from the domain or deleted. If its address is reassigned, this name will lead to another machine."
        );
    }
}

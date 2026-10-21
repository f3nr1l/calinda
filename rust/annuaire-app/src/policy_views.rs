// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the resultant policy (J5.7, `annuaire.vue.gpo`, the part of the « Policy » tab
//! of the sheet): rows by priority, then filtered, then ignored links; summary, location,
//! loopback. The rest of `vue.gpo` comes with the window of the group policies (R4.8).

use annuaire_core::dn;
use annuaire_core::gpo::{
    Container, Loopback, LoopbackMode, Part, Reason, Remark, ResultantPolicy,
};

use crate::i18n::{fill, tr, tr_n};

pub fn part_label(part: Part) -> String {
    match part {
        Part::Computer => tr("Computer Configuration"),
        Part::User => tr("User Configuration"),
    }
}

pub fn reason_label(reason: Reason) -> String {
    match reason {
        Reason::Applied => tr("Applied"),
        Reason::LinkDisabled => tr("Link disabled"),
        Reason::InheritanceBlocked => tr("Inheritance blocked"),
        Reason::NotFound => tr("GPO not found or unreadable"),
        Reason::OtherDomain => tr("GPO from another domain, not evaluated"),
        Reason::Security => tr("Denied (security filtering)"),
        Reason::Disabled => tr("Disabled (GPO part)"),
        Reason::Empty => tr("Not applied (empty)"),
    }
}

pub fn loopback_label(mode: Loopback) -> String {
    match mode {
        Loopback::None => tr("no loopback processing"),
        Loopback::Merge => tr("loopback processing, merge mode"),
        Loopback::Replace => tr("loopback processing, replace mode"),
    }
}

/// `str.capitalize`: the first letter in upper case, the rest in lower case.
pub fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first
            .to_uppercase()
            .chain(chars.flat_map(char::to_lowercase))
            .collect()
    })
}

pub fn remark_text(remark: &Remark) -> String {
    match remark {
        Remark::SitesLinked => tr(
            "Some GPOs are linked to sites: they are not evaluated (the computer's site is not known here).",
        ),
        Remark::WmiNotEvaluated => {
            tr("WMI filters not evaluated: a GPO that has one may not apply.")
        }
        Remark::Loopback {
            mode,
            gpo,
            computer,
        } => fill(
            &tr("{mode}: setting of the GPO “{gpo}”, applied to {ordinateur}."),
            &[
                ("mode", &capitalize(&loopback_label(*mode))),
                ("gpo", gpo),
                ("ordinateur", computer),
            ],
        ),
    }
}

/// A row of the « Policy » tab (`LigneStrategie`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLine {
    /// Priority, or `–` for a GPO not applied.
    pub priority: Option<usize>,
    pub name: String,
    pub link: String,
    pub state: String,
    pub remark: String,
    pub alert: bool,
}

fn place(container: &Container, dns_name: &str) -> String {
    if container.class == "domainDNS" {
        dns_name.to_owned()
    } else {
        container.name.clone()
    }
}

/// Applied by priority, then filtered, then ignored links (`lignes_strategie`).
pub fn lines(policy: &ResultantPolicy, dns_name: &str) -> Vec<PolicyLine> {
    let mut out = Vec::new();
    for line in &policy.applied {
        let mut remark = Vec::new();
        if line.link.enforced() {
            remark.push(tr("enforced link"));
        }
        if line.wmi_not_evaluated {
            remark.push(fill(
                &tr("WMI filter “{nom}” not evaluated"),
                &[("nom", &line.wmi_name)],
            ));
        }
        out.push(PolicyLine {
            priority: Some(line.priority),
            name: line.name(),
            link: place(&line.container, dns_name),
            state: reason_label(line.reason),
            remark: remark.join(", "),
            alert: line.wmi_not_evaluated,
        });
    }
    for line in policy.discarded.iter().chain(policy.ignored.iter()) {
        out.push(PolicyLine {
            priority: None,
            name: line.name(),
            link: place(&line.container, dns_name),
            state: reason_label(line.reason),
            remark: if line.link.enforced() {
                tr("enforced link")
            } else {
                String::new()
            },
            alert: line.reason == Reason::NotFound,
        });
    }
    out
}

/// The path of the account, from the root of the domain to its container
/// (`lab.test/Labo/Paris`) (`emplacement`).
pub fn location(policy: &ResultantPolicy, dns_name: &str) -> String {
    let mut pieces = vec![dns_name.to_owned()];
    pieces.extend(
        dn::split(&policy.location)
            .unwrap_or_default()
            .iter()
            .rev()
            .filter(|c| !c.attribute.eq_ignore_ascii_case("dc"))
            .map(|c| c.value.clone()),
    );
    pieces.join("/")
}

/// `resume_strategie`.
pub fn summary(policy: &ResultantPolicy, dns_name: &str) -> String {
    let n = policy.applied.len();
    let part = part_label(policy.part).to_lowercase();
    let text = if n > 0 {
        fill(
            &tr_n(
                "{n} GPO applied to the {partie}.",
                "{n} GPOs applied to the {partie}.",
                n as u64,
            ),
            &[("n", &n.to_string()), ("partie", &part)],
        )
    } else {
        fill(&tr("No GPO applied to the {partie}."), &[("partie", &part)])
    };
    format!(
        "{text} {}",
        fill(
            &tr("Location: {lieu}."),
            &[("lieu", &location(policy, dns_name))]
        )
    )
}

/// The loopback mode of a computer and the GPO that sets it (`texte_boucle`).
pub fn loopback_text(mode: &LoopbackMode) -> String {
    match &mode.gpo {
        None => tr("No loopback processing (no applied GPO configures it)."),
        Some(gpo) => fill(
            &tr("{mode} (set by “{gpo}”)."),
            &[
                ("mode", &capitalize(&loopback_label(mode.mode))),
                ("gpo", &gpo.name),
            ],
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capitalized_as_python() {
        assert_eq!(
            capitalize("loopback processing, MERGE mode"),
            "Loopback processing, merge mode"
        );
        assert_eq!(capitalize(""), "");
    }
}

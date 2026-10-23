// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts of the « Effective Access » dialog (ADR 0023 § 6, J8.5): for an account or a group
//! and a folder or file of a share, each right as the « Effective Access » tab of Windows lists
//! it, granted or not, and what decides it: the entry of the share and the entry of the NTFS
//! permissions that grant it, or the one that denies it, or that none grants it. No widget
//! here: the dialog (`access`) shows these lines, the tests check them.

use annuaire_codecs::sd::{Ace, SecurityDescriptor};
use annuaire_core::effective_access::{
    Decision, Effective, Evaluation, FILE_ALL_ACCESS, LocalGroups, NotEvaluated, Source, right,
};

use crate::i18n::{fill, tr};
use crate::security_views::sid_name;
use crate::share_views::{self as shv, Names};

/// Which side keeps a right from the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    Share,
    Ntfs,
    Both,
}

/// One line of the list: a right (or Full control), granted or not, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightLine {
    /// The bits of the right (several for Full control).
    pub mask: u32,
    pub name: String,
    pub granted: bool,
    /// Who keeps it from the account, when not granted.
    pub limit: Option<Limit>,
    /// What decides, in words: the share, then the NTFS permissions.
    pub reasons: Vec<String>,
}

/// The rights in the order of the « Effective Access » tab of Windows, Full control first.
pub fn listed_rights() -> [u32; 15] {
    [
        FILE_ALL_ACCESS,
        right::EXECUTE,
        right::READ_DATA,
        right::READ_ATTRIBUTES,
        right::READ_EA,
        right::WRITE_DATA,
        right::APPEND_DATA,
        right::WRITE_ATTRIBUTES,
        right::WRITE_EA,
        right::DELETE_CHILD,
        right::DELETE,
        right::READ_CONTROL,
        right::WRITE_DAC,
        right::WRITE_OWNER,
        right::SYNCHRONIZE,
    ]
}

fn right_name(mask: u32, folder: bool) -> String {
    match mask {
        FILE_ALL_ACCESS => tr("Full control"),
        right::SYNCHRONIZE => tr("Synchronize"),
        bit => shv::fine_right_text(bit, folder),
    }
}

fn ace_at(descriptor: &SecurityDescriptor, index: usize) -> Option<&Ace> {
    descriptor.dacl.as_ref()?.aces.get(index)
}

/// What decided one right on one side, in words; `None` when nothing decided it (no entry).
fn decision_text(
    decision: Option<&Decision>,
    descriptor: &SecurityDescriptor,
    sentence: &dyn Fn(&Ace) -> String,
) -> Option<String> {
    let d = decision?;
    Some(match d.source {
        Source::Ace(i) => ace_at(descriptor, i).map_or_else(|| format!("#{i}"), sentence),
        Source::Owner => tr("implicit rights of the owner"),
        Source::NoDacl => tr("no list of permissions: everything is allowed"),
    })
}

/// The reasons of one side for the bits of `mask`: the first bit not granted (its denial, or
/// that no entry grants it), else what grants the first bit.
fn side_reason(
    label: &str,
    evaluation: &Evaluation,
    descriptor: &SecurityDescriptor,
    mask: u32,
    sentence: &dyn Fn(&Ace) -> String,
) -> String {
    let missing = (0..32)
        .map(|i| 1u32 << i)
        .find(|b| mask & b != 0 && evaluation.granted & b == 0);
    let text = match missing {
        Some(bit) => match evaluation.decision(bit) {
            Some(d) if !d.allowed => fill(
                &tr("denied by {entree}"),
                &[(
                    "entree",
                    &decision_text(Some(d), descriptor, sentence).unwrap_or_default(),
                )],
            ),
            _ => tr("no entry grants it"),
        },
        None => {
            let first = (0..32).map(|i| 1u32 << i).find(|b| mask & b != 0);
            let found =
                first.and_then(|b| decision_text(evaluation.decision(b), descriptor, sentence));
            fill(
                &tr("granted by {entree}"),
                &[("entree", &found.unwrap_or_default())],
            )
        }
    };
    fill(
        &tr("{cote}: {raison}"),
        &[("cote", label), ("raison", &text)],
    )
}

/// Each right of the list, granted or not, with what decides it.
pub fn right_lines(e: &Effective, folder: bool, names: &Names) -> Vec<RightLine> {
    let file_sentence = |a: &Ace| shv::file_ace_sentence(a, folder, Some(names));
    let share_sentence = |a: &Ace| shv::share_ace_sentence(a, Some(names));
    listed_rights()
        .into_iter()
        .map(|mask| {
            let ntfs = e.folder.granted & mask == mask;
            let share = e.share.as_ref().is_none_or(|s| s.granted & mask == mask);
            let mut reasons = Vec::new();
            match (&e.share, &e.share_descriptor) {
                (Some(s), Some(d)) => {
                    reasons.push(side_reason(&tr("share"), s, d, mask, &share_sentence));
                }
                _ => reasons.push(fill(
                    &tr("{cote}: {raison}"),
                    &[
                        ("cote", &tr("share")),
                        ("raison", &tr("no permissions set, everything is allowed")),
                    ],
                )),
            }
            reasons.push(side_reason(
                &tr("NTFS"),
                &e.folder,
                &e.folder_descriptor,
                mask,
                &file_sentence,
            ));
            RightLine {
                mask,
                name: right_name(mask, folder),
                granted: ntfs && share,
                limit: match (share, ntfs) {
                    (true, true) => None,
                    (false, true) => Some(Limit::Share),
                    (true, false) => Some(Limit::Ntfs),
                    (false, false) => Some(Limit::Both),
                },
                reasons,
            }
        })
        .collect()
}

pub fn limit_text(limit: Option<Limit>) -> String {
    match limit {
        None => tr("Granted"),
        Some(Limit::Share) => tr("Not granted: limited by the share"),
        Some(Limit::Ntfs) => tr("Not granted: limited by the NTFS permissions"),
        Some(Limit::Both) => tr("Not granted: limited by the share and the NTFS permissions"),
    }
}

/// The access in one sentence: the basic permission it amounts to, through the share and by
/// NTFS.
pub fn summary(e: &Effective, folder: bool) -> String {
    let level = |mask: u32| {
        if mask == 0 {
            tr("nothing")
        } else {
            shv::file_right_text(mask, folder)
        }
    };
    fill(
        &tr("{acces} (share: {partage}; NTFS: {ntfs})"),
        &[
            ("acces", &level(e.granted)),
            (
                "partage",
                &e.share
                    .as_ref()
                    .map_or_else(|| tr("everything"), |s| level(s.granted)),
            ),
            ("ntfs", &level(e.folder.granted)),
        ],
    )
}

/// What the result leaves out, in words: local groups not asked, conditional entries, central
/// policy, integrity label, and the privileges, always.
pub fn notes(e: &Effective) -> Vec<String> {
    let mut out = Vec::new();
    if let LocalGroups::NotEvaluated(why) = &e.token.local_groups {
        out.push(fill(
            &tr("The local groups of the server could not be read ({raison}): an access given to one of them is not counted."),
            &[("raison", why)],
        ));
    }
    let mut kinds = e.folder.not_evaluated();
    if let Some(s) = &e.share {
        for k in s.not_evaluated() {
            if !kinds.contains(&k) {
                kinds.push(k);
            }
        }
    }
    for kind in kinds {
        out.push(match kind {
            NotEvaluated::ConditionalAces => tr(
                "Conditional entries apply to this account: their condition is not evaluated.",
            ),
            NotEvaluated::CentralPolicy => tr(
                "A central access policy applies to this element: it is not evaluated.",
            ),
            NotEvaluated::IntegrityLabel => {
                tr("An integrity label applies to this element: it is not evaluated.")
            }
            NotEvaluated::Privileges => tr(
                "Privileges (backup, restore, taking ownership) are not counted: an account that holds one may do more.",
            ),
        });
    }
    out
}

/// The identities of the token, named: the account, its groups of the directory, the local
/// groups of the server, the identities of a network logon.
pub fn identities(e: &Effective, names: &Names) -> Vec<String> {
    e.token
        .sids()
        .iter()
        .map(|s| {
            let name = sid_name(s, Some(names));
            if name == s.to_string() {
                name
            } else {
                format!("{name} ({s})")
            }
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use annuaire_codecs::Sid;
    use annuaire_codecs::sddl;
    use annuaire_core::effective_access::{Token, effective};

    const USER: &str = "S-1-5-21-1-2-3-1104";
    const GROUP: &str = "S-1-5-21-1-2-3-1200";

    fn sd(text: &str) -> SecurityDescriptor {
        sddl::sd_from_sddl(text, None, false).unwrap()
    }

    fn token() -> Token {
        let s = |t: &str| t.parse::<Sid>().unwrap();
        Token::new(s(USER), false, vec![s(GROUP)])
            .with_local_groups(LocalGroups::Evaluated(Vec::new()))
    }

    fn line(lines: &[RightLine], mask: u32) -> &RightLine {
        lines.iter().find(|l| l.mask == mask).unwrap()
    }

    #[test]
    fn rights_and_their_reasons() {
        // Share: Everyone Change. NTFS: the group may modify, writing denied to the user.
        let share = sd("D:(A;;0x1301bf;;;WD)");
        let folder = sd(&format!(
            "O:BAD:(D;;0x2;;;{USER})(A;OICI;0x1301bf;;;{GROUP})(A;OICI;FA;;;BA)"
        ));
        let e = effective(Some(share), folder, token());
        let lines = right_lines(&e, true, &Names::new());
        assert_eq!(lines.len(), 15);
        let read = line(&lines, right::READ_DATA);
        assert!(read.granted && read.limit.is_none());
        assert!(
            read.reasons[0].starts_with("share: granted by"),
            "{:?}",
            read.reasons
        );
        assert!(read.reasons[1].contains("granted by"), "{:?}", read.reasons);
        let write = line(&lines, right::WRITE_DATA);
        assert_eq!(write.limit, Some(Limit::Ntfs));
        assert!(
            write.reasons[1].contains("denied by"),
            "{:?}",
            write.reasons
        );
        let dac = line(&lines, right::WRITE_DAC);
        // Neither Change of the share nor Modify of the folder holds it.
        assert_eq!(dac.limit, Some(Limit::Both));
        assert!(
            dac.reasons[1].ends_with("no entry grants it"),
            "{:?}",
            dac.reasons
        );
        let full = line(&lines, FILE_ALL_ACCESS);
        assert!(!full.granted);
        assert_eq!(full.name, "Full control");
        assert!(
            summary(&e, true).contains("share:"),
            "{}",
            summary(&e, true)
        );
        // Privileges are always said.
        assert!(notes(&e).iter().any(|n| n.contains("Privileges")));
    }

    #[test]
    fn owner_and_no_share_descriptor() {
        let folder = sd(&format!("O:{USER}D:(A;;0x1200a9;;;{GROUP})"));
        let e = effective(None, folder, token());
        let lines = right_lines(&e, false, &Names::new());
        let dac = line(&lines, right::WRITE_DAC);
        assert!(dac.granted);
        assert!(
            dac.reasons[0].contains("everything is allowed"),
            "{:?}",
            dac.reasons
        );
        assert!(dac.reasons[1].contains("owner"), "{:?}", dac.reasons);
        assert_eq!(limit_text(None), "Granted");
    }

    #[test]
    fn local_groups_not_read_are_said() {
        let t = token().with_local_groups(LocalGroups::NotEvaluated("refus".into()));
        let e = effective(None, sd("D:(A;;FA;;;WD)"), t);
        assert!(notes(&e)[0].contains("refus"));
        assert!(
            identities(&e, &Names::new())
                .iter()
                .any(|i| i.contains(USER))
        );
    }
}

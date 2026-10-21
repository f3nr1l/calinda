// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Security Settings » pages of the GPO editor (J7.5, `annuaire.vue.gpo_securite`), without
//! GTK: texts of the four pages (password policy, lockout policy, user rights assignment,
//! restricted groups), warning on the scope of the account policy, names in clear of the
//! principals, and `Draft`: the changes made in a page, replayed on the content read again on
//! the DC when writing (`security_policy::prepare_security`).

use std::collections::{HashMap, HashSet};

use annuaire_codecs::Sid;
use annuaire_codecs::gpt_tmpl::{self as gt, Inf};
use annuaire_core::security::SidName;
use annuaire_core::security_policy::{
    self as sp, Kind, Page, PsoSummary, Reach, SecurityProblem, SecurityRead, SettingDef,
};

use crate::i18n::{fill, tr, tr_marked, tr_n};
use crate::security_views::{known_sid, sid_name};

type Names = HashMap<Sid, SidName>;

/// Marks a message for the catalogue; translated when shown.
#[allow(non_snake_case)]
const fn N_(text: &'static str) -> &'static str {
    text
}

/// Title, explanation, unit and « never » text of each setting of `[System Access]`.
pub const SETTING_TEXTS: [(&str, &str, &str, &str, &str); 9] = [
    (
        "PasswordHistorySize",
        N_("Enforce password history"),
        N_(
            "Number of previous passwords a user cannot reuse. 0 allows going straight back to the old password; 24 is the Windows domain default.",
        ),
        N_("passwords remembered"),
        "",
    ),
    (
        "MaximumPasswordAge",
        N_("Maximum password age"),
        N_(
            "After this time, the user must change the password at the next sign-in. Current guidance prefers a long password that does not expire over forced changes.",
        ),
        N_("days"),
        N_("Never expires"),
    ),
    (
        "MinimumPasswordAge",
        N_("Minimum password age"),
        N_(
            "Time before a user may change the password again; prevents cycling through the history to get the old one back. Must stay below the maximum password age. 0: changes allowed at any time.",
        ),
        N_("days"),
        "",
    ),
    (
        "MinimumPasswordLength",
        N_("Minimum password length"),
        N_(
            "Minimum number of characters in a password. 0 accepts an empty password. The GPMC limits this setting to 14; beyond that, use a fine-grained password policy (PSO).",
        ),
        N_("characters"),
        "",
    ),
    (
        "PasswordComplexity",
        N_("Password must meet complexity requirements"),
        N_(
            "The password does not contain the account name or parts of the full name longer than two characters, and mixes three of four categories: uppercase, lowercase, digits, special characters.",
        ),
        "",
        "",
    ),
    (
        "ClearTextPassword",
        N_("Store passwords using reversible encryption"),
        N_(
            "Keeps passwords in a form that can be turned back into plain text. Only needed by old protocols (CHAP, Digest authentication); leave it disabled.",
        ),
        "",
        "",
    ),
    (
        "LockoutBadCount",
        N_("Account lockout threshold"),
        N_(
            "Number of failed sign-ins that lock the account. 0: the account is never locked, which allows unlimited password guessing. Windows 11 suggests 10.",
        ),
        N_("invalid sign-in attempts"),
        "",
    ),
    (
        "LockoutDuration",
        N_("Account lockout duration"),
        N_(
            "How long a locked account stays locked before unlocking by itself. “Until unlocked”: an administrator must unlock it. Must be at least the counter reset time. No effect if the threshold is 0.",
        ),
        N_("minutes"),
        N_("Until an administrator unlocks it"),
    ),
    (
        "ResetLockoutCount",
        N_("Reset account lockout counter after"),
        N_(
            "Time after a failure after which the failure counter goes back to zero. Cannot exceed the lockout duration. No effect if the threshold is 0.",
        ),
        N_("minutes"),
        "",
    ),
];
/// Title and explanation of each right, in the order of `security_policy::RIGHTS`.
pub const RIGHT_TEXTS: [(&str, &str, &str); 45] = [
    (
        "SeTrustedCredManAccessPrivilege",
        N_("Access Credential Manager as a trusted caller"),
        N_("Used to back up and restore Credential Manager; grant it to no one."),
    ),
    (
        "SeNetworkLogonRight",
        N_("Access this computer from the network"),
        N_("Sign in to the machine over the network: file shares, printing, RPC."),
    ),
    (
        "SeTcbPrivilege",
        N_("Act as part of the operating system"),
        N_("Impersonate any user without authentication; grant it to no one."),
    ),
    (
        "SeMachineAccountPrivilege",
        N_("Add workstations to domain"),
        N_(
            "Join computers to the domain (ten at most per user, per ms-DS-MachineAccountQuota). Only meaningful on domain controllers.",
        ),
    ),
    (
        "SeIncreaseQuotaPrivilege",
        N_("Adjust memory quotas for a process"),
        N_("Change the maximum memory of a process; for service accounts and administrators."),
    ),
    (
        "SeInteractiveLogonRight",
        N_("Allow log on locally"),
        N_(
            "Sign in at the machine's keyboard. Removing it from Users prevents any sign-in on a workstation.",
        ),
    ),
    (
        "SeRemoteInteractiveLogonRight",
        N_("Allow log on through Remote Desktop Services"),
        N_("Sign in through Remote Desktop (RDP)."),
    ),
    (
        "SeBackupPrivilege",
        N_("Back up files and directories"),
        N_("Read any file regardless of permissions, for backups."),
    ),
    (
        "SeChangeNotifyPrivilege",
        N_("Bypass traverse checking"),
        N_(
            "Traverse folders without the right to list them; needed for normal operation, leave it to Everyone.",
        ),
    ),
    (
        "SeSystemtimePrivilege",
        N_("Change the system time"),
        N_("Change the machine's clock; a skew of more than five minutes breaks Kerberos."),
    ),
    (
        "SeTimeZonePrivilege",
        N_("Change the time zone"),
        N_("Change the machine's time zone (no effect on Kerberos)."),
    ),
    (
        "SeCreatePagefilePrivilege",
        N_("Create a pagefile"),
        N_("Create or enlarge the page file."),
    ),
    (
        "SeCreateTokenPrivilege",
        N_("Create a token object"),
        N_("Forge arbitrary access tokens; grant it to no one."),
    ),
    (
        "SeCreateGlobalPrivilege",
        N_("Create global objects"),
        N_("Create objects shared between sessions; for services and administrators."),
    ),
    (
        "SeCreatePermanentPrivilege",
        N_("Create permanent shared objects"),
        N_("Create permanent kernel objects; grant it to no one."),
    ),
    (
        "SeCreateSymbolicLinkPrivilege",
        N_("Create symbolic links"),
        N_("Create symbolic links in the file system."),
    ),
    (
        "SeDebugPrivilege",
        N_("Debug programs"),
        N_("Open any process, system ones included: amounts to full control of the machine."),
    ),
    (
        "SeDenyNetworkLogonRight",
        N_("Deny access to this computer from the network"),
        N_("Denies network access; overrides the right to access."),
    ),
    (
        "SeDenyBatchLogonRight",
        N_("Deny log on as a batch job"),
        N_("Prevents scheduled tasks from running under these accounts."),
    ),
    (
        "SeDenyServiceLogonRight",
        N_("Deny log on as a service"),
        N_("Prevents services from running under these accounts."),
    ),
    (
        "SeDenyInteractiveLogonRight",
        N_("Deny log on locally"),
        N_("Denies sign-in at the keyboard; overrides the right to sign in."),
    ),
    (
        "SeDenyRemoteInteractiveLogonRight",
        N_("Deny log on through Remote Desktop Services"),
        N_("Denies Remote Desktop; overrides the right to use it."),
    ),
    (
        "SeEnableDelegationPrivilege",
        N_("Enable computer and user accounts to be trusted for delegation"),
        N_(
            "Mark an account as trusted for Kerberos delegation; only meaningful on domain controllers.",
        ),
    ),
    (
        "SeRemoteShutdownPrivilege",
        N_("Force shutdown from a remote system"),
        N_("Shut the machine down over the network."),
    ),
    (
        "SeAuditPrivilege",
        N_("Generate security audits"),
        N_("Write to the security log; for service accounts."),
    ),
    (
        "SeImpersonatePrivilege",
        N_("Impersonate a client after authentication"),
        N_("Act as a connected client; for services."),
    ),
    (
        "SeIncreaseWorkingSetPrivilege",
        N_("Increase a process working set"),
        N_("Increase the resident memory of a process."),
    ),
    (
        "SeIncreaseBasePriorityPrivilege",
        N_("Increase scheduling priority"),
        N_("Give a process a higher priority."),
    ),
    (
        "SeLoadDriverPrivilege",
        N_("Load and unload device drivers"),
        N_("Load code into the kernel: amounts to full control of the machine."),
    ),
    (
        "SeLockMemoryPrivilege",
        N_("Lock pages in memory"),
        N_("Keep a process's memory out of the page file (databases)."),
    ),
    (
        "SeBatchLogonRight",
        N_("Log on as a batch job"),
        N_("Run scheduled tasks under these accounts."),
    ),
    (
        "SeServiceLogonRight",
        N_("Log on as a service"),
        N_("Run services under these accounts."),
    ),
    (
        "SeSecurityPrivilege",
        N_("Manage auditing and security log"),
        N_("Set object auditing and read or clear the security log."),
    ),
    (
        "SeRelabelPrivilege",
        N_("Modify an object label"),
        N_("Change the integrity level of an object; grant it to no one."),
    ),
    (
        "SeSystemEnvironmentPrivilege",
        N_("Modify firmware environment values"),
        N_("Change firmware (UEFI) variables."),
    ),
    (
        "SeManageVolumePrivilege",
        N_("Perform volume maintenance tasks"),
        N_("Defragment or check a volume; allows reading raw disk data."),
    ),
    (
        "SeProfileSingleProcessPrivilege",
        N_("Profile single process"),
        N_("Measure the performance of a process."),
    ),
    (
        "SeSystemProfilePrivilege",
        N_("Profile system performance"),
        N_("Measure system performance."),
    ),
    (
        "SeUndockPrivilege",
        N_("Remove computer from docking station"),
        N_("Undock a laptop without signing in."),
    ),
    (
        "SeAssignPrimaryTokenPrivilege",
        N_("Replace a process level token"),
        N_("Start a process under another token; for service accounts."),
    ),
    (
        "SeRestorePrivilege",
        N_("Restore files and directories"),
        N_("Write any file regardless of permissions, and change its owner."),
    ),
    (
        "SeShutdownPrivilege",
        N_("Shut down the system"),
        N_("Shut the machine down from a session on it."),
    ),
    (
        "SeSyncAgentPrivilege",
        N_("Synchronize directory service data"),
        N_(
            "Read the whole directory regardless of permissions; only meaningful on domain controllers.",
        ),
    ),
    (
        "SeTakeOwnershipPrivilege",
        N_("Take ownership of files or other objects"),
        N_("Become the owner of any object, and so change its permissions."),
    ),
    (
        "SeDelegateSessionUserImpersonatePrivilege",
        N_("Obtain an impersonation token for another user in the same session"),
        N_("Get the token of another user in the same session."),
    ),
];

/// The four pages: password, lockout, rights, groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityPage {
    Password,
    Lockout,
    Rights,
    Groups,
}

impl SecurityPage {
    pub const ALL: [Self; 4] = [Self::Password, Self::Lockout, Self::Rights, Self::Groups];

    pub fn title(self) -> String {
        match self {
            Self::Password => tr("Password Policy"),
            Self::Lockout => tr("Account Lockout Policy"),
            Self::Rights => tr("User Rights Assignment"),
            Self::Groups => tr("Restricted Groups"),
        }
    }

    /// Place of the page under « Computer Configuration › Policies » (`CHEMINS`).
    pub fn path(self) -> String {
        match self {
            Self::Password | Self::Lockout => {
                tr("Windows Settings › Security Settings › Account Policies")
            }
            Self::Rights => tr("Windows Settings › Security Settings › Local Policies"),
            Self::Groups => tr("Windows Settings › Security Settings"),
        }
    }

    pub fn settings_page(self) -> Option<Page> {
        match self {
            Self::Password => Some(Page::Password),
            Self::Lockout => Some(Page::Lockout),
            _ => None,
        }
    }
}

type SettingTexts = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

fn texts(key: &str) -> Option<&'static SettingTexts> {
    SETTING_TEXTS.iter().find(|t| t.0.eq_ignore_ascii_case(key))
}

/// Title of a setting, in the language of the interface (as the GPMC editor).
pub fn setting_title(key: &str) -> String {
    texts(key).map_or_else(|| key.to_owned(), |t| tr_marked(t.1))
}

pub fn setting_explanation(key: &str) -> String {
    texts(key).map_or_else(String::new, |t| tr_marked(t.2))
}

/// The unit of a setting (« days »…), empty for a boolean.
pub fn setting_unit(key: &str) -> String {
    texts(key)
        .filter(|t| !t.3.is_empty())
        .map_or_else(String::new, |t| tr_marked(t.3))
}

pub fn never_text(key: &str) -> String {
    texts(key)
        .filter(|t| !t.4.is_empty())
        .map_or_else(String::new, |t| tr_marked(t.4))
}

/// Title and explanation of a right; `None` for a right unknown to the tool.
pub fn right_texts(name: &str) -> Option<(String, String)> {
    RIGHT_TEXTS
        .iter()
        .find(|t| t.0.eq_ignore_ascii_case(name))
        .map(|t| (tr_marked(t.1), tr_marked(t.2)))
}

/// Well-known SIDs of the user rights the table of the security does not name (`AUTRES_SID`).
fn other_sid(text: &str) -> Option<String> {
    Some(match text {
        "S-1-5-80-0" => tr("All Services"),
        "S-1-5-90-0" => tr("Window Manager"),
        "S-1-5-83-0" => tr("Virtual Machines"),
        "S-1-5-113" => tr("Local account"),
        "S-1-5-114" => tr("Local account and member of Administrators group"),
        _ => return None,
    })
}

/// Principals proposed without a search (absent from the directory or groups of `Builtin`)
/// (`PRINCIPAUX_CONNUS`).
pub const KNOWN_PRINCIPALS: [&str; 17] = [
    "S-1-1-0",
    "S-1-5-11",
    "S-1-5-32-544",
    "S-1-5-32-545",
    "S-1-5-32-546",
    "S-1-5-32-551",
    "S-1-5-32-555",
    "S-1-5-32-556",
    "S-1-5-32-558",
    "S-1-5-32-559",
    "S-1-5-32-562",
    "S-1-5-32-573",
    "S-1-5-19",
    "S-1-5-20",
    "S-1-5-6",
    "S-1-5-113",
    "S-1-5-114",
];

// --- Principals ---------------------------------------------------------------------------

/// SID of an entry `*S-…`; `None` for an account name (or a malformed SID) (`sid_entree`).
pub fn entry_sid(entry: &str) -> Option<Sid> {
    gt::sid_of(entry)?.parse().ok()
}

/// Name in clear of an entry of a right or of a restricted group: name of the object of the
/// directory, name of a well-known SID, or the text as is (local account name) (`nom_entree`).
pub fn entry_name(entry: &str, names: Option<&Names>) -> String {
    let Some(sid) = entry_sid(entry) else {
        return entry.to_owned();
    };
    let text = sid.to_string();
    if known_sid(&text).is_none()
        && !names.is_some_and(|n| n.contains_key(&sid))
        && let Some(name) = other_sid(&text)
    {
        return name;
    }
    sid_name(&sid, names)
}

/// Every SID the rights and the restricted groups cite (to be named) (`sids`).
pub fn sids(inf: &Inf) -> HashSet<Sid> {
    let mut entries: Vec<String> = inf.rights().into_iter().flat_map(|(_, v)| v).collect();
    for g in inf.restricted_groups() {
        entries.push(g.group.clone());
        entries.extend(g.members.clone().unwrap_or_default());
        entries.extend(g.member_of.clone().unwrap_or_default());
    }
    entries.iter().filter_map(|e| entry_sid(e)).collect()
}

/// The entry of a SID (`*S-…`).
pub fn entry(sid: &Sid) -> String {
    gt::sid_entry(&sid.to_string())
}

/// « Not Defined », « Nobody », or the names (`liste_noms`).
pub fn names_list(entries: Option<&[String]>, names: Option<&Names>) -> String {
    match entries {
        None => tr("Not Defined"),
        Some([]) => tr("Nobody"),
        Some(list) => list
            .iter()
            .map(|e| entry_name(e, names))
            .collect::<Vec<_>>()
            .join(&tr(", ")),
    }
}

// --- Account settings ---------------------------------------------------------------------

/// The value of a setting in clear (`texte_valeur`).
pub fn value_text(r: &SettingDef, n: Option<i64>) -> String {
    let Some(n) = n else {
        return tr("Not Defined");
    };
    if r.kind == Kind::Boolean {
        return if n != 0 {
            tr("Enabled")
        } else {
            tr("Disabled")
        };
    }
    if r.never == Some(n) {
        return never_text(r.key);
    }
    if r.key == "MaximumPasswordAge" && n == 0 {
        return tr("0 days (ignored by Windows: “never expires” is written -1)");
    }
    if r.key == "LockoutDuration" && n == 0 {
        return tr("Until an administrator unlocks it");
    }
    quantity(r.key, n)
}

/// « 1 day », « 42 days »: the unit agreeing with the number (`_quantite`).
fn quantity(key: &str, n: i64) -> String {
    let count = n.unsigned_abs();
    let text = match key {
        "MaximumPasswordAge" | "MinimumPasswordAge" => tr_n("{n} day", "{n} days", count),
        "MinimumPasswordLength" => tr_n("{n} character", "{n} characters", count),
        "LockoutDuration" | "ResetLockoutCount" => tr_n("{n} minute", "{n} minutes", count),
        "LockoutBadCount" => tr_n(
            "{n} invalid sign-in attempt",
            "{n} invalid sign-in attempts",
            count,
        ),
        "PasswordHistorySize" => tr_n("{n} password remembered", "{n} passwords remembered", count),
        _ => return format!("{n} {}", setting_unit(key)),
    };
    fill(&text, &[("n", &n.to_string())])
}

/// A row of the password or lockout page (`LigneReglage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingRow {
    pub setting: &'static SettingDef,
    pub value: Option<i64>,
    pub text: String,
    /// Value applied by the domain object (empty if it does not carry it).
    pub domain: String,
}

impl SettingRow {
    pub fn title(&self) -> String {
        setting_title(self.setting.key)
    }

    pub fn explanation(&self) -> String {
        setting_explanation(self.setting.key)
    }
}

pub fn setting_rows(page: Page, inf: &Inf, domain: Option<&sp::DomainPolicy>) -> Vec<SettingRow> {
    sp::settings(page)
        .map(|r| {
            let value = sp::value(inf, r);
            let effective = domain.and_then(|d| d.of(r));
            SettingRow {
                setting: r,
                value,
                text: value_text(r, value),
                domain: effective.map_or_else(String::new, |e| value_text(r, Some(e))),
            }
        })
        .collect()
}

/// Banner of the account pages (`Bandeau`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    pub title: String,
    pub text: String,
    pub alert: bool,
}

/// What the account policy of this GPO is worth, according to where it is linked and the DC
/// (`bandeau_comptes`).
pub fn accounts_banner(security: &SecurityRead) -> Banner {
    match security.scope.reach {
        Reach::Domain => {
            let mut text = if security.samba {
                tr(
                    "Linked to the root of the domain: it applies to all domain accounts. Samba does not read the GPO for this: when saving, the tool also writes the defined values to the domain object (like samba-tool domain passwordsettings set), in the same write.",
                )
            } else {
                tr(
                    "Linked to the root of the domain: it applies to all domain accounts. The PDC emulator carries it over to the domain object at its next refresh.",
                )
            };
            if !security.prior_names.is_empty() {
                text.push(' ');
                text.push_str(&fill(
                    &tr(
                        "A higher-precedence GPO is also linked to the domain ({noms}): where it defines a setting, its value applies.",
                    ),
                    &[("noms", &security.prior_names.join(", "))],
                ));
            }
            Banner {
                title: tr("Domain policy"),
                text,
                alert: false,
            }
        }
        Reach::Elsewhere => Banner {
            title: tr("No effect on domain accounts"),
            text: tr(
                "A password or lockout policy applies to domain accounts only from a GPO linked to the root of the domain. Linked to an OU, it only governs the local accounts of the computers in the OU. For a policy specific to some users, use a fine-grained password policy (PSO).",
            ),
            alert: true,
        },
        Reach::Unlinked => Banner {
            title: tr("Unlinked GPO"),
            text: tr(
                "This GPO is not linked anywhere: its settings do not apply. Linked to the root of the domain, its account policy would apply to all domain accounts.",
            ),
            alert: true,
        },
    }
}

/// Title and summary of a fine-grained policy (`texte_pso`).
pub fn pso_text(pso: &PsoSummary, names: &HashMap<String, String>) -> (String, String) {
    let mut pieces = Vec::new();
    for key in [
        "MinimumPasswordLength",
        "PasswordComplexity",
        "LockoutBadCount",
    ] {
        if let (Some(v), Some(r)) = (pso.values.get(key), sp::setting(key)) {
            pieces.push(format!(
                "{} : {}",
                setting_title(key),
                value_text(r, Some(*v))
            ));
        }
    }
    let targets: Vec<String> = pso
        .applies_to
        .iter()
        .map(|dn| {
            names.get(dn).cloned().unwrap_or_else(|| {
                let first = dn.split(',').next().unwrap_or_default();
                first.split_once('=').map_or(first, |(_, v)| v).to_owned()
            })
        })
        .collect();
    let targets = if targets.is_empty() {
        tr("no one")
    } else {
        targets.join(", ")
    };
    pieces.push(fill(&tr("applies to: {cibles}"), &[("cibles", &targets)]));
    let title = fill(
        &tr("{nom} (precedence {n})"),
        &[("nom", &pso.name), ("n", &pso.precedence.to_string())],
    );
    (title, pieces.join(" ; "))
}

// --- Rights and groups --------------------------------------------------------------------

/// A row of the rights page (`LigneDroit`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RightRow {
    pub name: String,
    pub title: String,
    pub explanation: String,
    pub sensitive: bool,
    pub entries: Option<Vec<String>>,
}

/// The known rights in the order of the Windows editor (alphabetical by title), then those of
/// the file the tool does not know (`lignes_droits`).
pub fn right_rows(inf: &Inf) -> Vec<RightRow> {
    let mut defined: Vec<(String, Vec<String>)> = inf.rights();
    let mut known: Vec<(&sp::Right, String, String)> = sp::RIGHTS
        .iter()
        .map(|r| {
            let (title, explanation) = right_texts(r.name).unwrap_or_default();
            (r, title, explanation)
        })
        .collect();
    known.sort_by_cached_key(|(_, title, _)| title.to_lowercase());
    let mut out = Vec::new();
    for (r, title, explanation) in known {
        let found = defined
            .iter()
            .position(|(k, _)| k.eq_ignore_ascii_case(r.name))
            .map(|i| defined.remove(i).1);
        out.push(RightRow {
            name: r.name.to_owned(),
            title,
            explanation,
            sensitive: r.sensitive,
            entries: found,
        });
    }
    for (key, v) in defined {
        out.push(RightRow {
            name: key.clone(),
            title: key,
            explanation: tr("Right unknown to the tool, kept as is."),
            sensitive: false,
            entries: Some(v),
        });
    }
    out
}

/// The members imposed on a restricted group; an empty list empties the group
/// (`texte_membres`).
pub fn members_text(entries: Option<&[String]>, names: Option<&Names>) -> String {
    if entries.is_some_and(<[String]>::is_empty) {
        return tr("None: the group is emptied on each computer");
    }
    names_list(entries, names)
}

pub fn rights_warning() -> String {
    tr(
        "A right defined here replaces the whole list on the computer: accounts that had it and are not listed here lose it. Leaving it “Not Defined” keeps the computer's list.",
    )
}

pub fn groups_warning() -> String {
    tr(
        "“Members” replaces the whole membership of the group on the computer: members missing from the list are removed each time it applies. “Member of” adds the group to the listed groups without removing anything.",
    )
}

/// A refusal said plainly.
pub fn problem_text(problem: &SecurityProblem) -> String {
    match problem {
        SecurityProblem::OutOfBounds { key, n, min, max } => fill(
            &tr("“{titre}”: {n} is out of range ({mini} to {maxi})."),
            &[
                ("titre", &setting_title(key)),
                ("n", &n.to_string()),
                ("mini", &min.to_string()),
                ("maxi", &max.to_string()),
            ],
        ),
        SecurityProblem::MinimumAge { min, max } => fill(
            &tr(
                "The minimum password age ({mini} d) must be lower than the maximum password age ({maxi} d).",
            ),
            &[("mini", &min.to_string()), ("maxi", &max.to_string())],
        ),
        SecurityProblem::ResetWindow { window, duration } => fill(
            &tr(
                "The failure counter resets after {fenetre} min, longer than the lockout duration ({duree} min): the GPMC refuses this.",
            ),
            &[
                ("fenetre", &window.to_string()),
                ("duree", &duration.to_string()),
            ],
        ),
    }
}

/// What a page defines, for the list of the pages (`resume_page`).
pub fn page_summary(page: SecurityPage, inf: &Inf) -> String {
    let n = match page {
        SecurityPage::Rights => inf.rights().len(),
        SecurityPage::Groups => inf.restricted_groups().len(),
        SecurityPage::Password | SecurityPage::Lockout => page.settings_page().map_or(0, |p| {
            sp::settings(p)
                .filter(|r| sp::value(inf, r).is_some())
                .count()
        }),
    };
    if n == 0 {
        return tr("Nothing defined");
    }
    fill(
        &tr_n(
            "{n} item defined",
            "{n} items defined",
            u64::try_from(n).unwrap_or(u64::MAX),
        ),
        &[("n", &n.to_string())],
    )
}

/// What the draft changes, in clear, for the common preview (`_lignes_apercu`).
pub fn preview_lines(draft: &Draft, after: &Inf, names: Option<&Names>) -> Vec<String> {
    let mut lines: Vec<String> = draft
        .settings
        .iter()
        .filter_map(|(key, n)| {
            let r = sp::setting(key)?;
            Some(format!("{} : {}", setting_title(key), value_text(r, *n)))
        })
        .collect();
    for (name, entries) in &draft.rights {
        let title = right_texts(name).map_or_else(|| name.clone(), |(t, _)| t);
        lines.push(format!(
            "{title} : {}",
            names_list(entries.as_deref(), names)
        ));
    }
    let groups = after.restricted_groups();
    for (group, _) in &draft.groups {
        let name = entry_name(group, names);
        match groups.iter().find(|g| g.group.eq_ignore_ascii_case(group)) {
            None => lines.push(fill(&tr("Restricted group {g}: removed"), &[("g", &name)])),
            Some(x) => lines.push(fill(
                &tr("Restricted group {g}: members {m}; member of {d}"),
                &[
                    ("g", &name),
                    ("m", &members_text(x.members.as_deref(), names)),
                    ("d", &names_list(x.member_of.as_deref(), names)),
                ],
            )),
        }
    }
    lines
}

// --- Draft --------------------------------------------------------------------------------

/// The lists of a restricted group: members, member of.
pub type GroupLists = (Vec<String>, Vec<String>);

fn put<V>(list: &mut Vec<(String, V)>, key: &str, value: V) {
    match list.iter_mut().find(|(k, _)| k == key) {
        Some(slot) => slot.1 = value,
        None => list.push((key.to_owned(), value)),
    }
}

/// Changes made in the pages, replayed on the content read again on the DC, each kind in the
/// order typed (`Brouillon`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Draft {
    pub settings: Vec<(String, Option<i64>)>,
    pub rights: Vec<(String, Option<Vec<String>>)>,
    /// Group → (members, member of); `None`: group removed.
    pub groups: Vec<(String, Option<GroupLists>)>,
}

impl Draft {
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty() && self.rights.is_empty() && self.groups.is_empty()
    }

    pub fn len(&self) -> usize {
        self.settings.len() + self.rights.len() + self.groups.len()
    }

    /// The setting `key` changed, or back to `origin` (out of the draft).
    pub fn set_setting(&mut self, key: &str, n: Option<i64>, origin: Option<i64>) {
        if n == origin {
            self.settings.retain(|(k, _)| k != key);
        } else {
            put(&mut self.settings, key, n);
        }
    }

    pub fn set_right(
        &mut self,
        name: &str,
        entries: Option<Vec<String>>,
        origin: Option<Vec<String>>,
    ) {
        if entries == origin {
            self.rights.retain(|(k, _)| k != name);
        } else {
            put(&mut self.rights, name, entries);
        }
    }

    pub fn set_group(
        &mut self,
        group: &str,
        lists: Option<GroupLists>,
        origin: Option<GroupLists>,
    ) {
        if lists == origin {
            self.groups.retain(|(k, _)| k != group);
        } else {
            put(&mut self.groups, group, lists);
        }
    }

    pub fn forget_group(&mut self, group: &str) {
        self.groups.retain(|(k, _)| k != group);
    }

    /// Settings, then rights, then groups (`appliquer`).
    pub fn apply(&self, inf: &Inf) -> Result<Inf, SecurityProblem> {
        let mut inf = inf.clone();
        for (key, n) in &self.settings {
            if let Some(r) = sp::setting(key) {
                inf = sp::set(&inf, r, *n)?;
            }
        }
        for (name, entries) in &self.rights {
            inf = inf.set_right(name, entries.as_deref());
        }
        for (group, lists) in &self.groups {
            inf = match lists {
                None => inf.remove_group(group),
                Some((members, member_of)) => inf.set_group(group, members, member_of),
            };
        }
        Ok(inf)
    }
}

#[cfg(test)]
mod tests;

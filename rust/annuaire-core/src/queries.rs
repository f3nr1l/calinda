// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Global search and saved queries (J2.3, `annuaire.core.recherche`): filters and
//! selections, without network. The search bar combines three criteria: a text looked for
//! in the name, the logon name, the display name, the UPN, the mail and the description; a
//! kind of object; a state of account. The saved queries are ready filters, combined with
//! the same kind and state. Two queries are not only a filter: "inactive for N days" and
//! "never logged on" judge the last activity on every DC (`activity`), and "locked out"
//! depends on the lockout duration of the domain and on the time.

use annuaire_codecs::time;
use annuaire_codecs::uac::UserAccountControl;

use crate::model::{DomainPolicy, Object, is_inactive};
use crate::search::{OID_BIT_AND, OID_IN_CHAIN, escape_filter};

/// Attributes where the typed text is looked for (substring, without case).
pub const TEXT_ATTRIBUTES: [&str; 6] = [
    "name",
    "sAMAccountName",
    "displayName",
    "userPrincipalName",
    "mail",
    "description",
];

pub const USERS: &str = "(&(objectCategory=person)(objectClass=user))";
pub const COMPUTERS: &str = "(objectCategory=computer)";
/// Domain controllers and read-only ones (which keep their own `lastLogon` too).
pub const DCS: &str = "(&(objectCategory=computer)(|(userAccountControl:1.2.840.113556.1.4.803:=8192)(userAccountControl:1.2.840.113556.1.4.803:=67108864)))";

/// Kind of object looked for (`TypeCherche`), in the order of the drop-down list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    All,
    User,
    Computer,
    Group,
    Contact,
    Ou,
}

impl Kind {
    pub const ALL: [Self; 6] = [
        Self::All,
        Self::User,
        Self::Computer,
        Self::Group,
        Self::Contact,
        Self::Ou,
    ];

    /// Value of `TypeCherche`, kept in the saved searches.
    pub fn name(self) -> &'static str {
        match self {
            Self::All => "tous",
            Self::User => "utilisateur",
            Self::Computer => "ordinateur",
            Self::Group => "groupe",
            Self::Contact => "contact",
            Self::Ou => "ou",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.name() == name)
    }

    /// Filter of the kind; None for every kind.
    pub fn filter(self) -> Option<String> {
        match self {
            Self::All => None,
            Self::User => Some(USERS.into()),
            Self::Computer => Some(COMPUTERS.into()),
            Self::Group => Some("(objectCategory=group)".into()),
            Self::Contact => Some("(&(objectCategory=person)(objectClass=contact))".into()),
            Self::Ou => Some("(objectCategory=organizationalUnit)".into()),
        }
    }
}

/// State of account looked for (`EtatCherche`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    All,
    Enabled,
    Disabled,
}

impl State {
    pub const ALL: [Self; 3] = [Self::All, Self::Enabled, Self::Disabled];

    pub fn name(self) -> &'static str {
        match self {
            Self::All => "tous",
            Self::Enabled => "actif",
            Self::Disabled => "desactive",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.name() == name)
    }

    /// Filter of the state; None for all. Enabled or disabled only applies to users and
    /// computers: a group is neither.
    pub fn filter(self) -> Option<String> {
        match self {
            Self::All => None,
            Self::Enabled => Some(enabled()),
            Self::Disabled => Some(disabled()),
        }
    }
}

/// Users and computers (those with a state and a last activity).
pub fn accounts() -> String {
    format!("(|{USERS}{COMPUTERS})")
}

fn uac_bit(flag: u32) -> String {
    format!("(userAccountControl:{OID_BIT_AND}:={flag})")
}

pub fn disabled() -> String {
    format!(
        "(&{}{})",
        accounts(),
        uac_bit(UserAccountControl::ACCOUNTDISABLE)
    )
}

pub fn enabled() -> String {
    format!(
        "(&{}(!{}))",
        accounts(),
        uac_bit(UserAccountControl::ACCOUNTDISABLE)
    )
}

pub fn password_never_expires() -> String {
    format!(
        "(&{}{})",
        accounts(),
        uac_bit(UserAccountControl::DONT_EXPIRE_PASSWD)
    )
}

/// BUILTIN\Administrators: its name changes with the language of the domain, not its SID.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";
const DOMAIN_ADMINS_RID: u32 = 512;
const ENTERPRISE_ADMINS_RID: u32 = 519;

/// Members, direct or nested, of BUILTIN\Administrators; by IN_CHAIN, slow on the DC (more
/// than 20 s on Samba with 20,000 accounts). An account is not in the `member` of its
/// primary group: those of the two administrator groups are added.
pub fn administrators() -> String {
    format!(
        "(|(memberOf:{OID_IN_CHAIN}:=<SID={ADMINISTRATORS_SID}>)\
         (primaryGroupID={DOMAIN_ADMINS_RID})(primaryGroupID={ENTERPRISE_ADMINS_RID}))"
    )
}

/// Objects renamed by the replication after a collision of names: `<name>\nCNF:<GUID>`.
pub const CONFLICTS: &str = "(name=*\\0aCNF:*)";

/// Candidates "never logged on": no `lastLogonTimestamp`; the survey of activity decides.
pub fn without_replicated_logon() -> String {
    format!("(&{}(!(lastLogonTimestamp=*)))", accounts())
}

/// Words of the input, in order, without duplicates (`mots`).
pub fn words(input: &str) -> Vec<&str> {
    let mut words: Vec<&str> = Vec::new();
    for word in input.split_whitespace() {
        if !words.contains(&word) {
            words.push(word);
        }
    }
    words
}

/// Each word must be in one of [`TEXT_ATTRIBUTES`]; None without a word. Special
/// characters are escaped: a typed `*` is an asterisk, not a wildcard.
pub fn text_filter(input: &str) -> Option<String> {
    let terms: Vec<String> = words(input)
        .into_iter()
        .map(|word| {
            let escaped = escape_filter(word);
            let alternatives: String = TEXT_ATTRIBUTES
                .iter()
                .map(|a| format!("({a}=*{escaped}*)"))
                .collect();
            format!("(|{alternatives})")
        })
        .collect();
    match terms.as_slice() {
        [] => None,
        [one] => Some(one.clone()),
        _ => Some(format!("(&{})", terms.concat())),
    }
}

/// Conjunction of the filters given; every object if none (`combiner`).
pub fn combine(filters: &[Option<String>]) -> String {
    let present: Vec<&String> = filters.iter().flatten().collect();
    match present.as_slice() {
        [] => "(objectClass=*)".into(),
        [one] => (*one).clone(),
        many => format!("(&{})", many.iter().map(|f| f.as_str()).collect::<String>()),
    }
}

/// Filter of the search bar.
pub fn search_filter(input: &str, kind: Kind, state: State) -> String {
    combine(&[text_filter(input), kind.filter(), state.filter()])
}

/// Smallest `lockoutTime` of an account still locked out at `now` (NTTIME), with the rule of
/// `Account::locked`: set, and an infinite duration or an end to come.
pub fn lockout_threshold(policy: &DomainPolicy, now: i64) -> i64 {
    if policy.lockout_duration == time::DURATION_NEVER {
        return 1;
    }
    // A negative duration: now + duration is the instant "duration" ago.
    now.saturating_add(policy.lockout_duration)
        .saturating_add(1)
        .max(1)
}

pub fn locked(policy: &DomainPolicy, now: i64) -> String {
    format!(
        "(&{}(lockoutTime>={}))",
        accounts(),
        lockout_threshold(policy, now)
    )
}

/// Ready queries (plan, J2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Query {
    Inactive,
    Disabled,
    Locked,
    PasswordNeverExpires,
    Administrators,
    NeverLoggedOn,
    Conflicts,
}

/// How a query runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Execution {
    /// A filter, by a search.
    Filter,
    /// A filter that depends on the policy of the domain and on the time.
    Policy,
    /// A survey of the activity on every DC, then a selection.
    Activity,
}

impl Query {
    pub const ALL: [Self; 7] = [
        Self::Inactive,
        Self::Disabled,
        Self::Locked,
        Self::PasswordNeverExpires,
        Self::Administrators,
        Self::NeverLoggedOn,
        Self::Conflicts,
    ];

    /// Value of `Requete` (target of `recherche.requete`, saved searches).
    pub fn name(self) -> &'static str {
        match self {
            Self::Inactive => "inactifs",
            Self::Disabled => "desactives",
            Self::Locked => "verrouilles",
            Self::PasswordNeverExpires => "mot-de-passe-permanent",
            Self::Administrators => "administrateurs",
            Self::NeverLoggedOn => "jamais-connectes",
            Self::Conflicts => "conflits",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|q| q.name() == name)
    }

    pub fn execution(self) -> Execution {
        match self {
            Self::Inactive | Self::NeverLoggedOn => Execution::Activity,
            Self::Locked => Execution::Policy,
            _ => Execution::Filter,
        }
    }

    /// The DC computes it slowly (IN_CHAIN), unless a synchronized local copy answers.
    pub fn slow(self, copy: bool) -> bool {
        self == Self::Administrators && !copy
    }

    /// LDAP filter of the query, restricted to the kind and state chosen (`filtre_requete`).
    /// For an activity query, the filter of the survey; `Locked` needs the policy and the
    /// time (NTTIME), None otherwise.
    pub fn filter(
        self,
        kind: Kind,
        state: State,
        policy: Option<(&DomainPolicy, i64)>,
    ) -> Option<String> {
        let base = match self {
            Self::Locked => {
                let (policy, now) = policy?;
                locked(policy, now)
            }
            Self::Disabled => disabled(),
            Self::PasswordNeverExpires => password_never_expires(),
            Self::Administrators => administrators(),
            Self::Conflicts => CONFLICTS.into(),
            Self::Inactive => accounts(),
            Self::NeverLoggedOn => without_replicated_logon(),
        };
        if self == Self::Inactive && matches!(kind, Kind::User | Kind::Computer) {
            // The very filter of `activite.filtre_comptes`, so of the command line.
            return Some(combine(&[kind.filter(), state.filter()]));
        }
        Some(combine(&[Some(base), kind.filter(), state.filter()]))
    }
}

/// An account of a survey and its last activity on every DC.
pub type Surveyed = (Object, crate::model::LastActivity);

/// "Inactive for `days` days": no activity since `now` − `days` (`inactifs`).
pub fn select_inactive(accounts: Vec<Surveyed>, threshold: i64) -> Vec<Surveyed> {
    accounts
        .into_iter()
        .filter(|(object, activity)| {
            let created = object
                .common()
                .created
                .and_then(|c| time::utc_to_nttime(c).ok());
            is_inactive(activity, created, threshold)
        })
        .collect()
}

/// "Never logged on": no activity at all on any DC.
pub fn select_never(accounts: Vec<Surveyed>) -> Vec<Surveyed> {
    accounts
        .into_iter()
        .filter(|(_, a)| a.nttime == 0)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_as_python() {
        // Values of `core.recherche` (test_recherche.py).
        assert_eq!(search_filter("", Kind::All, State::All), "(objectClass=*)");
        assert_eq!(
            text_filter("du*").unwrap(),
            "(|(name=*du\\2a*)(sAMAccountName=*du\\2a*)(displayName=*du\\2a*)\
             (userPrincipalName=*du\\2a*)(mail=*du\\2a*)(description=*du\\2a*))"
        );
        assert_eq!(words("a b a  c"), ["a", "b", "c"]);
        assert_eq!(
            search_filter("", Kind::Group, State::All),
            "(objectCategory=group)"
        );
        assert_eq!(
            disabled(),
            "(&(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))\
             (userAccountControl:1.2.840.113556.1.4.803:=2))"
        );
        assert!(
            administrators().contains("(memberOf:1.2.840.113556.1.4.1941:=<SID=S-1-5-32-544>)")
        );
        assert_eq!(
            Query::Inactive
                .filter(Kind::User, State::Enabled, None)
                .unwrap(),
            format!("(&{USERS}{})", enabled())
        );
        assert_eq!(Query::Locked.filter(Kind::All, State::All, None), None);
        // Printed by `filtre_recherche("du* x", UTILISATEUR, ACTIF)`.
        assert_eq!(
            search_filter("du* x", Kind::User, State::Enabled),
            "(&(&(|(name=*du\\2a*)(sAMAccountName=*du\\2a*)(displayName=*du\\2a*)\
             (userPrincipalName=*du\\2a*)(mail=*du\\2a*)(description=*du\\2a*))\
             (|(name=*x*)(sAMAccountName=*x*)(displayName=*x*)(userPrincipalName=*x*)(mail=*x*)\
             (description=*x*)))(&(objectCategory=person)(objectClass=user))\
             (&(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))\
             (!(userAccountControl:1.2.840.113556.1.4.803:=2))))"
        );
        assert_eq!(
            without_replicated_logon(),
            "(&(|(&(objectCategory=person)(objectClass=user))(objectCategory=computer))\
             (!(lastLogonTimestamp=*)))"
        );
    }

    #[test]
    fn lockout() {
        let mut policy = DomainPolicy {
            lockout_duration: -18_000_000_000, // 30 min
            lockout_threshold: 5,
            max_password_age: 0,
        };
        assert_eq!(lockout_threshold(&policy, 100_000_000_000), 82_000_000_001);
        assert_eq!(lockout_threshold(&policy, 1), 1);
        policy.lockout_duration = time::DURATION_NEVER;
        assert_eq!(lockout_threshold(&policy, 100), 1);
    }

    #[test]
    fn names() {
        for q in Query::ALL {
            assert_eq!(Query::from_name(q.name()), Some(q));
        }
        assert_eq!(Kind::from_name("ou"), Some(Kind::Ou));
        assert_eq!(State::from_name("desactive"), Some(State::Disabled));
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Effective access of an account (or a group) to a folder of a share (ADR 0023 § 6): what
//! the descriptor of the share grants, what the descriptor of the folder grants, their
//! intersection, and for each right the ACE that decides it.
//!
//! The token is built as a network logon would: the SID of the account, its `tokenGroups`
//! read in the directory, Everyone, Authenticated Users, NETWORK, This Organization and
//! Authentication authority asserted identity (a Kerberos network logon in the same forest),
//! then the local groups of the server through SAMR (its account domain, then `Builtin`, as
//! the server does: see `samr::Samr::local_groups`). On a member server, the `Builtin` aliases
//! of `tokenGroups` (those of the DCs) are left out for the server's own (J8.7, `server_token`);
//! when the server does not answer SAMR,
//! the evaluation says so and goes on without them. For a group
//! given in place of an account: the group and the security groups that hold it, directly or
//! not, as for any of its members.
//!
//! The evaluation is the access check of MS-DTYP 2.5.3.2 asked for `MAXIMUM_ALLOWED`: ACEs
//! in their order, inherited ones included, inherit-only ones skipped; READ_CONTROL and
//! WRITE_DAC to the owner unless an `OWNER RIGHTS` ACE (S-1-3-4) applies; no DACL grants
//! everything, an empty DACL nothing. Generic rights are translated by the table of files.
//! Conditional ACEs (callback), central access policies and integrity labels are not
//! evaluated: they are reported ([`Evaluation::not_evaluated`]). Privileges (backup, restore,
//! taking ownership) are never part of it, and the result always says so.

use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::{Sid, sd::SdError};

use crate::connection::{Connection, Failure, Link};
use crate::error::{LdapError, code};
use crate::samr::Samr;
use crate::search::{self, OID_BIT_AND, OID_IN_CHAIN};
use crate::session::{Scope, SearchRequest};
use crate::smb::client::Options;
use crate::srvsvc::{self, Srvsvc};
use crate::sysvol::{self, Protection, Session, SysvolError};

/// Rights of a file or a folder (MS-DTYP 2.4.3, MS-SMB2 2.2.13.1).
pub mod right {
    pub const READ_DATA: u32 = 0x0000_0001;
    pub const WRITE_DATA: u32 = 0x0000_0002;
    pub const APPEND_DATA: u32 = 0x0000_0004;
    pub const READ_EA: u32 = 0x0000_0008;
    pub const WRITE_EA: u32 = 0x0000_0010;
    pub const EXECUTE: u32 = 0x0000_0020;
    pub const DELETE_CHILD: u32 = 0x0000_0040;
    pub const READ_ATTRIBUTES: u32 = 0x0000_0080;
    pub const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
    pub const DELETE: u32 = 0x0001_0000;
    pub const READ_CONTROL: u32 = 0x0002_0000;
    pub const WRITE_DAC: u32 = 0x0004_0000;
    pub const WRITE_OWNER: u32 = 0x0008_0000;
    pub const SYNCHRONIZE: u32 = 0x0010_0000;
}

/// `FILE_ALL_ACCESS`: every right an access check of a file can grant, the bits reported.
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;

/// Generic rights replaced by the rights of files they stand for; what is left outside
/// `FILE_ALL_ACCESS` (`ACCESS_SYSTEM_SECURITY`, `MAXIMUM_ALLOWED`) is not granted by a DACL.
pub fn map_generic(mask: u32) -> u32 {
    let mut out = mask & FILE_ALL_ACCESS;
    for (generic, specific) in [
        (sd::GENERIC_ALL, FILE_ALL_ACCESS),
        (sd::GENERIC_READ, FILE_GENERIC_READ),
        (sd::GENERIC_WRITE, FILE_GENERIC_WRITE),
        (sd::GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
    ] {
        if mask & generic != 0 {
            out |= specific;
        }
    }
    out
}

fn well_known(text: &str) -> Sid {
    text.parse().unwrap_or_else(|_| sd::everyone())
}

/// Everyone, Authenticated Users, NETWORK, This Organization and Authentication authority
/// asserted identity: in the token of a Kerberos network logon (an SMB session) of an
/// account of the same forest, as Windows builds it.
pub fn network_sids() -> [Sid; 5] {
    [
        sd::everyone(),
        well_known("S-1-5-11"),
        well_known("S-1-5-2"),
        well_known("S-1-5-15"),
        well_known("S-1-18-1"),
    ]
}

/// `OWNER RIGHTS`, S-1-3-4.
pub fn owner_rights() -> Sid {
    well_known("S-1-3-4")
}

/// Local groups of the server in the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalGroups {
    /// Asked of the server by SAMR: the aliases found (possibly none).
    Evaluated(Vec<Sid>),
    /// The server did not answer or refused: why.
    NotEvaluated(String),
}

/// The SIDs an access check compares with the ACEs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The account, or the group given in place of one.
    pub principal: Sid,
    pub is_group: bool,
    /// Groups read in the directory (`tokenGroups`, or the groups holding a group).
    pub directory_groups: Vec<Sid>,
    pub local_groups: LocalGroups,
    sids: Vec<Sid>,
}

impl Token {
    /// The principal, its groups of the directory and the identities of a network logon;
    /// local groups not asked yet.
    pub fn new(principal: Sid, is_group: bool, directory_groups: Vec<Sid>) -> Self {
        let mut token = Self {
            principal,
            is_group,
            directory_groups,
            local_groups: LocalGroups::NotEvaluated(String::new()),
            sids: Vec::new(),
        };
        token.rebuild();
        token
    }

    pub fn with_local_groups(mut self, local: LocalGroups) -> Self {
        self.local_groups = local;
        self.rebuild();
        self
    }

    fn rebuild(&mut self) {
        let mut sids = vec![self.principal];
        let local = match &self.local_groups {
            LocalGroups::Evaluated(l) => l.as_slice(),
            LocalGroups::NotEvaluated(_) => &[],
        };
        for s in self
            .directory_groups
            .iter()
            .chain(network_sids().iter())
            .chain(local)
        {
            if !sids.contains(s) {
                sids.push(*s);
            }
        }
        self.sids = sids;
    }

    /// Every SID of the token, the principal first.
    pub fn sids(&self) -> &[Sid] {
        &self.sids
    }

    pub fn contains(&self, sid: &Sid) -> bool {
        self.sids.contains(sid)
    }

    /// The token on a member server: the `Builtin` aliases of the directory groups, those of
    /// the DCs that `tokenGroups` gives, left out; the server adds its own by SAMR.
    pub fn without_builtin(mut self) -> Self {
        let builtin = crate::samr::builtin();
        self.directory_groups
            .retain(|g| g.domain().ok() != Some(builtin));
        self.rebuild();
        self
    }

    /// The SIDs sent to SAMR: the principal and its groups of the directory, plus the
    /// identities of a network logon (an alias may hold Everyone or Authenticated Users).
    pub fn without_local(&self) -> Vec<Sid> {
        let mut out = vec![self.principal];
        for s in self.directory_groups.iter().chain(network_sids().iter()) {
            if !out.contains(s) {
                out.push(*s);
            }
        }
        out
    }
}

/// Where a right comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The ACE of this index in the DACL.
    Ace(usize),
    /// Implicit rights of the owner (READ_CONTROL, WRITE_DAC).
    Owner,
    /// The descriptor has no DACL: everything is allowed.
    NoDacl,
}

/// The first answer given for one right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// One bit of `FILE_ALL_ACCESS`.
    pub right: u32,
    pub allowed: bool,
    pub source: Source,
}

/// Why an ACE was not evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// A conditional ACE (callback) whose SID is in the token: its condition was not
    /// evaluated, the right may be granted or denied by it.
    Conditional,
    /// An object ACE with an object type, which a file has no use for.
    Object,
}

/// What a DACL grants to a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Rights granted (`MAXIMUM_ALLOWED`), in `FILE_ALL_ACCESS`.
    pub granted: u32,
    /// Rights denied by an ACE before any grant.
    pub denied: u32,
    /// For each right decided, in the order of the bits, what decided it.
    pub decisions: Vec<Decision>,
    /// ACEs not evaluated (index, reason).
    pub skipped: Vec<(usize, Skipped)>,
    /// The descriptor names a central access policy (SACL), not evaluated.
    pub central_policy: bool,
    /// The SACL holds an integrity label (`SYSTEM_MANDATORY_LABEL`), not evaluated.
    pub integrity_label: bool,
}

/// What an evaluation leaves out, for the interface to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotEvaluated {
    /// Conditional ACEs whose SID is in the token.
    ConditionalAces,
    /// A central access policy named by the SACL.
    CentralPolicy,
    /// An integrity label in the SACL.
    IntegrityLabel,
    /// Privileges (backup, restore, taking ownership…): never evaluated, whatever the
    /// descriptor; an account that holds one may do more than the result says.
    Privileges,
}

impl Evaluation {
    /// What decided `right`, if anything did.
    pub fn decision(&self, right: u32) -> Option<&Decision> {
        self.decisions.iter().find(|d| d.right == right)
    }

    /// Something of this descriptor was left out: the result may be wrong. Privileges, left
    /// out of every evaluation, do not count here.
    pub fn partial(&self) -> bool {
        !self.skipped.is_empty() || self.central_policy || self.integrity_label
    }

    /// What this evaluation left out, privileges always last.
    pub fn not_evaluated(&self) -> Vec<NotEvaluated> {
        let mut out = Vec::new();
        if self
            .skipped
            .iter()
            .any(|(_, why)| *why == Skipped::Conditional)
        {
            out.push(NotEvaluated::ConditionalAces);
        }
        if self.central_policy {
            out.push(NotEvaluated::CentralPolicy);
        }
        if self.integrity_label {
            out.push(NotEvaluated::IntegrityLabel);
        }
        out.push(NotEvaluated::Privileges);
        out
    }
}

fn bits(mask: u32) -> impl Iterator<Item = u32> {
    (0..32).map(|i| 1u32 << i).filter(move |b| mask & b != 0)
}

fn in_sacl(descriptor: &SecurityDescriptor, ace_type: u8) -> bool {
    descriptor
        .sacl
        .as_ref()
        .is_some_and(|sacl| sacl.aces.iter().any(|a| a.ace_type == ace_type))
}

/// The access check of MS-DTYP 2.5.3.2 for `MAXIMUM_ALLOWED`.
pub fn evaluate(descriptor: &SecurityDescriptor, token: &Token) -> Evaluation {
    let mut e = Evaluation {
        granted: 0,
        denied: 0,
        decisions: Vec::new(),
        skipped: Vec::new(),
        central_policy: in_sacl(descriptor, sd::SYSTEM_SCOPED_POLICY_ID),
        integrity_label: in_sacl(descriptor, sd::SYSTEM_MANDATORY_LABEL),
    };
    let dacl = match &descriptor.dacl {
        Some(dacl) if descriptor.control & sd::SE_DACL_PRESENT != 0 => dacl,
        _ => {
            grant(&mut e, FILE_ALL_ACCESS, Source::NoDacl);
            return e;
        }
    };
    let effective = |a: &&Ace| a.flags & sd::INHERIT_ONLY_ACE == 0;
    let owner = descriptor.owner.is_some_and(|o| token.contains(&o));
    let owner_rights = owner_rights();
    if owner
        && !dacl
            .aces
            .iter()
            .filter(effective)
            .any(|a| a.sid() == Some(owner_rights))
    {
        grant(
            &mut e,
            right::READ_CONTROL | right::WRITE_DAC,
            Source::Owner,
        );
    }
    for (index, ace) in dacl.aces.iter().enumerate() {
        if ace.flags & sd::INHERIT_ONLY_ACE != 0 || !(ace.is_allow() || ace.is_deny()) {
            continue;
        }
        let Some(sid) = ace.sid() else { continue };
        let applies = token.contains(&sid) || (owner && sid == owner_rights);
        if !applies {
            continue;
        }
        if matches!(
            ace.ace_type,
            sd::ACCESS_ALLOWED_CALLBACK
                | sd::ACCESS_DENIED_CALLBACK
                | sd::ACCESS_ALLOWED_CALLBACK_OBJECT
                | sd::ACCESS_DENIED_CALLBACK_OBJECT
        ) {
            e.skipped.push((index, Skipped::Conditional));
            continue;
        }
        if ace.is_object() && ace.object_type().is_some() {
            e.skipped.push((index, Skipped::Object));
            continue;
        }
        let mask = map_generic(ace.mask());
        if ace.is_allow() {
            grant(&mut e, mask, Source::Ace(index));
        } else {
            let new = mask & !e.granted & !e.denied;
            e.denied |= new;
            for right in bits(new) {
                e.decisions.push(Decision {
                    right,
                    allowed: false,
                    source: Source::Ace(index),
                });
            }
        }
    }
    e.decisions.sort_by_key(|d| d.right);
    e
}

fn grant(e: &mut Evaluation, mask: u32, source: Source) {
    let new = mask & !e.granted & !e.denied;
    e.granted |= new;
    for right in bits(new) {
        e.decisions.push(Decision {
            right,
            allowed: true,
            source,
        });
    }
}

/// Effective access through a share to one of its folders.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    pub token: Token,
    /// Descriptor of the share; None: the share has none, everything is allowed by it.
    pub share_descriptor: Option<SecurityDescriptor>,
    pub folder_descriptor: SecurityDescriptor,
    /// What the share grants; None without descriptor.
    pub share: Option<Evaluation>,
    pub folder: Evaluation,
    /// Intersection of the two.
    pub granted: u32,
}

impl Effective {
    /// Rights the folder grants and the share does not.
    pub fn limited_by_share(&self) -> u32 {
        self.folder.granted & !self.granted
    }

    /// Something was left out (local groups, conditional ACEs, central policy, label);
    /// privileges, always left out, do not count (see [`Evaluation::not_evaluated`]).
    pub fn partial(&self) -> bool {
        matches!(self.token.local_groups, LocalGroups::NotEvaluated(_))
            || self.folder.partial()
            || self.share.as_ref().is_some_and(Evaluation::partial)
    }
}

/// The share and the folder evaluated, and their intersection. Pure.
pub fn effective(
    share: Option<SecurityDescriptor>,
    folder: SecurityDescriptor,
    token: Token,
) -> Effective {
    let share_evaluation = share.as_ref().map(|d| evaluate(d, &token));
    let folder_evaluation = evaluate(&folder, &token);
    let granted = folder_evaluation.granted
        & share_evaluation
            .as_ref()
            .map_or(FILE_ALL_ACCESS, |e| e.granted);
    Effective {
        token,
        share_descriptor: share,
        folder_descriptor: folder,
        share: share_evaluation,
        folder: folder_evaluation,
        granted,
    }
}

// -- Reading --------------------------------------------------------------------------------

/// What went wrong in a reading.
#[derive(Debug, Clone)]
pub enum Error {
    /// The directory (connection or search).
    Directory(Failure),
    /// The object is absent or has no SID.
    NoPrincipal(String),
    /// `srvsvc` (descriptor of the share).
    Share(srvsvc::Error),
    /// The session on the share, or the descriptor of the folder.
    Folder(SysvolError),
    /// The folder does not exist.
    NoFolder(String),
    /// A descriptor that cannot be decoded.
    Descriptor(SdError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Directory(e) => write!(f, "{e:?}"),
            Self::NoPrincipal(dn) => write!(f, "{dn}: no such account or group"),
            Self::Share(e) => write!(f, "{e}"),
            Self::Folder(e) => write!(f, "{e}"),
            Self::NoFolder(p) => write!(f, "{p}: no such folder"),
            Self::Descriptor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// `groupType` of a security group (`GROUP_TYPE_SECURITY_ENABLED`).
const SECURITY_ENABLED: &str = "2147483648";

/// On the thread of the connection: the token of an account (`tokenGroups`), or of a group
/// (the security groups holding it, through the IN_CHAIN rule: Samba gives no `tokenGroups`
/// to a group). Local groups not asked yet.
pub fn read_token_data(link: &mut Link, dn: &str) -> std::result::Result<Token, LdapError> {
    let attributes: Vec<String> = ["objectClass", "objectSid", "tokenGroups"]
        .iter()
        .map(|&a| a.to_owned())
        .collect();
    let entry = search::read_entry(
        link.session.as_mut(),
        dn,
        &attributes,
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )?
    .ok_or_else(|| LdapError::new(code::NO_SUCH_OBJECT, "objet introuvable"))?;
    let sid = entry
        .values("objectSid")
        .first()
        .and_then(|v| Sid::decode(v).ok())
        .ok_or_else(|| LdapError::new(code::NO_SUCH_ATTRIBUTE, "objectSid"))?;
    let is_group = entry
        .values("objectClass")
        .iter()
        .any(|c| c.eq_ignore_ascii_case(b"group"));
    let mut groups: Vec<Sid> = Vec::new();
    if is_group {
        let filter = format!(
            "(&(objectClass=group)(groupType:{OID_BIT_AND}:={SECURITY_ENABLED})(member:{OID_IN_CHAIN}:={}))",
            search::escape_filter(&entry.dn)
        );
        let request = SearchRequest {
            base: link.state.root_dse.default_naming_context.clone(),
            scope: Scope::Subtree,
            filter: filter.clone(),
            attributes: vec!["objectSid".to_owned()],
            controls: Vec::new(),
            size_limit: 0,
        };
        let timeout = link.timeout_for(&filter);
        for e in link
            .session
            .search_wait(request, Some(timeout))?
            .into_entries()
        {
            if let Some(s) = e
                .values("objectSid")
                .first()
                .and_then(|v| Sid::decode(v).ok())
            {
                groups.push(s);
            }
        }
    } else {
        groups.extend(
            entry
                .values("tokenGroups")
                .iter()
                .filter_map(|v| Sid::decode(v).ok()),
        );
    }
    groups.retain(|g| *g != sid);
    Ok(Token::new(sid, is_group, groups))
}

/// The token of an account or a group of the directory, local groups not asked. Blocking.
pub fn read_token(connection: &Connection, dn: &str) -> Result<Token> {
    let dn_text = dn.to_owned();
    connection
        .run(true, move |link| read_token_data(link, &dn_text))
        .map_err(|f| match &f {
            Failure::Ldap { error, .. } if error.code == code::NO_SUCH_OBJECT => {
                Error::NoPrincipal(dn.to_owned())
            }
            Failure::Ldap { error, .. } if error.code == code::NO_SUCH_ATTRIBUTE => {
                Error::NoPrincipal(dn.to_owned())
            }
            _ => Error::Directory(f),
        })
}

/// Is the server whose account domains are `account_domains` a member server for this token?
/// On a DC, the account domain is a domain of the directory, and the token holds a group of it
/// (Domain Users at least, or the group given); a member server has a domain of its own, which
/// no SID of the directory belongs to.
pub fn member_server(account_domains: &[Sid], token: &Token) -> bool {
    !token
        .without_local()
        .iter()
        .filter_map(|s| s.domain().ok())
        .any(|d| account_domains.contains(&d))
}

/// The token as `server` builds it: its local groups by SAMR added. On a member server, the
/// `Builtin` aliases read in the directory (`tokenGroups` gives those of the DCs) are replaced
/// by those of the server itself; on a DC, they are its own and stay. Never an error: a refusal
/// or a failure leaves the local groups `NotEvaluated`. Blocking.
pub fn server_token(server: &str, options: &Options, token: Token) -> Token {
    let result = Samr::open(server, options).and_then(|mut service| {
        let found = service.account_domains().and_then(|domains| {
            let member = member_server(&domains, &token);
            let token = if member {
                token.clone().without_builtin()
            } else {
                token.clone()
            };
            service
                .local_groups_of(&domains, &token.without_local())
                .map(|groups| (token, groups))
        });
        service.close();
        found
    });
    match result {
        Ok((token, groups)) => token.with_local_groups(LocalGroups::Evaluated(groups)),
        Err(e) => token.with_local_groups(LocalGroups::NotEvaluated(e.to_string())),
    }
}

/// Where the access is asked: a share of a server, and a folder of that share (`""` for its
/// root, `\` between names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub server: String,
    pub share: String,
    pub path: String,
}

/// Parts of the descriptor of a folder read beyond owner, group and DACL, both readable with
/// READ_CONTROL: the integrity label (`LABEL_SECURITY_INFORMATION`) and the central access
/// policy (`SCOPE_SECURITY_INFORMATION`), in the SACL.
const INFO_LABEL: u32 = 0x10;
const INFO_SCOPE: u32 = 0x40;

/// Descriptor of the folder: with its label and central policy if the server gives them,
/// otherwise owner, group and DACL.
fn folder_descriptor(session: &mut Session, path: &str) -> Result<Vec<u8>> {
    let paths = [path.to_owned()];
    let info = sysvol::INFO_OGD | INFO_LABEL | INFO_SCOPE;
    let read = match session.read_descriptors(&paths, info) {
        Ok(r) => r,
        Err(e) if e.ntstatus().is_some() => session
            .read_descriptors(&paths, sysvol::INFO_OGD)
            .map_err(Error::Folder)?,
        Err(e) => return Err(Error::Folder(e)),
    };
    read.into_iter()
        .next()
        .flatten()
        .ok_or_else(|| Error::NoFolder(path.to_owned()))
}

/// Effective access of the account or group `dn` to `target`: its token (directory, then
/// SAMR), the descriptor of the share (`srvsvc`), the descriptor of the folder (SMB), then
/// [`effective`]. Blocking.
pub fn read(
    connection: &Connection,
    dn: &str,
    target: &Target,
    protection: Protection,
    timeout: std::time::Duration,
) -> Result<Effective> {
    let options = protection.options(timeout);
    let token = server_token(&target.server, &options, read_token(connection, dn)?);

    let mut service = Srvsvc::open(&target.server, &options).map_err(Error::Share)?;
    let share = service.share(&target.share);
    service.close();
    let share_descriptor = share
        .map_err(Error::Share)?
        .descriptor
        .map(|d| SecurityDescriptor::decode(&d))
        .transpose()
        .map_err(Error::Descriptor)?;

    let mut session = Session::open_share(&target.server, &target.share, protection, timeout)
        .map_err(Error::Folder)?;
    let folder = folder_descriptor(&mut session, &target.path);
    session.close();
    let folder_descriptor = SecurityDescriptor::decode(&folder?).map_err(Error::Descriptor)?;

    Ok(effective(share_descriptor, folder_descriptor, token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use annuaire_codecs::sd::Acl;

    fn s(text: &str) -> Sid {
        text.parse().unwrap()
    }

    const USER: &str = "S-1-5-21-1-2-3-1104";
    const GROUP: &str = "S-1-5-21-1-2-3-1200";
    const OTHER: &str = "S-1-5-21-1-2-3-1300";

    fn token() -> Token {
        Token::new(s(USER), false, vec![s(GROUP)])
    }

    fn ace(kind: u8, mask: u32, sid: &str, flags: u8) -> Ace {
        Ace::simple(kind, mask, &s(sid), flags).unwrap()
    }

    fn descriptor(owner: Option<&str>, aces: Option<Vec<Ace>>) -> SecurityDescriptor {
        SecurityDescriptor {
            revision: 1,
            control: sd::SE_SELF_RELATIVE
                | if aces.is_some() {
                    sd::SE_DACL_PRESENT
                } else {
                    0
                },
            owner: owner.map(s),
            group: None,
            sacl: None,
            dacl: aces.map(|aces| Acl { revision: 2, aces }),
        }
    }

    #[test]
    fn generic_rights_are_those_of_files() {
        assert_eq!(map_generic(sd::GENERIC_ALL), FILE_ALL_ACCESS);
        assert_eq!(map_generic(sd::GENERIC_READ), FILE_GENERIC_READ);
        assert_eq!(
            map_generic(sd::GENERIC_READ | sd::GENERIC_EXECUTE | right::DELETE),
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE | right::DELETE
        );
        assert_eq!(map_generic(sd::ACCESS_SYSTEM_SECURITY), 0);
    }

    #[test]
    fn token_has_the_identities_of_a_network_logon() {
        let t = token();
        assert_eq!(t.sids()[0], s(USER));
        for sid in [
            "S-1-1-0", "S-1-5-11", "S-1-5-2", "S-1-5-15", "S-1-18-1", GROUP,
        ] {
            assert!(t.contains(&s(sid)), "{sid}");
        }
        assert!(!t.contains(&s("S-1-5-32-545")));
        let t = t.with_local_groups(LocalGroups::Evaluated(vec![s("S-1-5-32-545")]));
        assert!(t.contains(&s("S-1-5-32-545")));
        assert_eq!(t.without_local().len(), 7);
    }

    #[test]
    fn builtin_of_the_dcs_left_out_on_a_member_server() {
        let domain = "S-1-5-21-1-2-3";
        let t = Token::new(
            s(&format!("{domain}-1105")),
            false,
            vec![
                s(&format!("{domain}-513")),
                s("S-1-5-32-551"),
                s("S-1-5-32-545"),
            ],
        );
        // A DC serves the domain of the directory: its Builtin is the one of tokenGroups.
        assert!(!member_server(&[s(domain)], &t));
        // A member server has an account domain of its own.
        let member = [s("S-1-5-21-9-9-9")];
        assert!(member_server(&member, &t));
        let m = t.clone().without_builtin();
        assert!(!m.contains(&s("S-1-5-32-551")) && !m.contains(&s("S-1-5-32-545")));
        assert!(m.contains(&s(&format!("{domain}-513"))));
        assert!(!m.without_local().contains(&s("S-1-5-32-551")));
        let m = m.with_local_groups(LocalGroups::Evaluated(vec![s("S-1-5-32-545")]));
        assert!(m.contains(&s("S-1-5-32-545")) && !m.contains(&s("S-1-5-32-551")));
    }

    #[test]
    fn no_dacl_grants_everything_and_empty_dacl_nothing() {
        let e = evaluate(&descriptor(None, None), &token());
        assert_eq!(e.granted, FILE_ALL_ACCESS);
        assert!(e.decisions.iter().all(|d| d.source == Source::NoDacl));
        let e = evaluate(&descriptor(Some(OTHER), Some(vec![])), &token());
        assert_eq!((e.granted, e.denied), (0, 0));
        assert!(e.decisions.is_empty());
    }

    #[test]
    fn deny_before_allow_wins_and_allow_before_deny_too() {
        // Canonical order: the explicit denial first.
        let d = descriptor(
            Some(OTHER),
            Some(vec![
                ace(sd::ACCESS_DENIED, right::WRITE_DATA, GROUP, 0),
                ace(
                    sd::ACCESS_ALLOWED,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    USER,
                    0,
                ),
            ]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(e.denied, right::WRITE_DATA);
        assert_eq!(
            e.granted,
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !right::WRITE_DATA
        );
        assert_eq!(
            e.decision(right::WRITE_DATA),
            Some(&Decision {
                right: right::WRITE_DATA,
                allowed: false,
                source: Source::Ace(0)
            })
        );
        assert_eq!(e.decision(right::READ_DATA).unwrap().source, Source::Ace(1));
        // A grant before a denial (not canonical): the grant stays.
        let d = descriptor(
            Some(OTHER),
            Some(vec![
                ace(sd::ACCESS_ALLOWED, FILE_GENERIC_WRITE, USER, 0),
                ace(sd::ACCESS_DENIED, right::WRITE_DATA, GROUP, 0),
            ]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, FILE_GENERIC_WRITE);
        assert_eq!(e.denied, 0);
    }

    #[test]
    fn inherited_aces_count_inherit_only_ones_do_not() {
        let d = descriptor(
            Some(OTHER),
            Some(vec![
                ace(
                    sd::ACCESS_DENIED,
                    FILE_ALL_ACCESS,
                    USER,
                    sd::INHERIT_ONLY_ACE | sd::OBJECT_INHERIT_ACE,
                ),
                ace(
                    sd::ACCESS_ALLOWED,
                    sd::GENERIC_READ,
                    GROUP,
                    sd::INHERITED_ACE | sd::CONTAINER_INHERIT_ACE,
                ),
                ace(sd::ACCESS_ALLOWED, FILE_ALL_ACCESS, OTHER, 0),
            ]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, FILE_GENERIC_READ);
        assert_eq!(e.denied, 0);
        assert!(
            e.decisions
                .iter()
                .all(|dec| dec.allowed && dec.source == Source::Ace(1))
        );
    }

    #[test]
    fn owner_has_read_control_and_write_dac_unless_owner_rights() {
        let d = descriptor(Some(USER), Some(vec![]));
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, right::READ_CONTROL | right::WRITE_DAC);
        assert!(e.decisions.iter().all(|dec| dec.source == Source::Owner));
        // Owner through a group of the token.
        let d = descriptor(
            Some(GROUP),
            Some(vec![ace(sd::ACCESS_ALLOWED, FILE_GENERIC_READ, OTHER, 0)]),
        );
        assert_eq!(
            evaluate(&d, &token()).granted,
            right::READ_CONTROL | right::WRITE_DAC
        );
        // OWNER RIGHTS replaces the implicit rights.
        let d = descriptor(
            Some(USER),
            Some(vec![ace(
                sd::ACCESS_ALLOWED,
                right::READ_DATA,
                "S-1-3-4",
                0,
            )]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, right::READ_DATA);
        // Not the owner: OWNER RIGHTS does not apply.
        let d = descriptor(
            Some(OTHER),
            Some(vec![ace(
                sd::ACCESS_ALLOWED,
                right::READ_DATA,
                "S-1-3-4",
                0,
            )]),
        );
        assert_eq!(evaluate(&d, &token()).granted, 0);
        // An inherit-only OWNER RIGHTS ACE leaves the implicit rights.
        let d = descriptor(
            Some(USER),
            Some(vec![ace(
                sd::ACCESS_ALLOWED,
                right::READ_DATA,
                "S-1-3-4",
                sd::INHERIT_ONLY_ACE | sd::CONTAINER_INHERIT_ACE,
            )]),
        );
        assert_eq!(
            evaluate(&d, &token()).granted,
            right::READ_CONTROL | right::WRITE_DAC
        );
        // A denial for the owner: the implicit rights come first, as in MS-DTYP.
        let d = descriptor(
            Some(USER),
            Some(vec![ace(sd::ACCESS_DENIED, right::WRITE_DAC, USER, 0)]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, right::READ_CONTROL | right::WRITE_DAC);
        assert_eq!(e.denied, 0);
    }

    #[test]
    fn well_known_identities_match() {
        let d = descriptor(
            Some(OTHER),
            Some(vec![
                ace(sd::ACCESS_ALLOWED, right::READ_DATA, "S-1-1-0", 0),
                ace(sd::ACCESS_ALLOWED, right::WRITE_DATA, "S-1-5-11", 0),
                ace(sd::ACCESS_ALLOWED, right::APPEND_DATA, "S-1-5-2", 0),
                ace(sd::ACCESS_ALLOWED, right::DELETE, "S-1-5-4", 0), // INTERACTIVE
                ace(sd::ACCESS_ALLOWED, right::WRITE_OWNER, "S-1-3-0", 0), // CREATOR OWNER
            ]),
        );
        assert_eq!(
            evaluate(&d, &token()).granted,
            right::READ_DATA | right::WRITE_DATA | right::APPEND_DATA
        );
    }

    #[test]
    fn conditional_aces_are_reported_not_evaluated() {
        let mut conditional = ace(sd::ACCESS_ALLOWED, FILE_ALL_ACCESS, USER, 0);
        conditional.ace_type = sd::ACCESS_ALLOWED_CALLBACK;
        conditional.body.extend_from_slice(b"artx\0\0\0\0");
        let mut foreign = ace(sd::ACCESS_DENIED, FILE_ALL_ACCESS, OTHER, 0);
        foreign.ace_type = sd::ACCESS_DENIED_CALLBACK;
        let d = descriptor(
            Some(OTHER),
            Some(vec![
                foreign,
                conditional,
                ace(sd::ACCESS_ALLOWED, right::READ_DATA, GROUP, 0),
            ]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, right::READ_DATA);
        assert_eq!(e.skipped, [(1, Skipped::Conditional)]);
        assert!(e.partial());
    }

    #[test]
    fn central_policy_is_reported() {
        let mut d = descriptor(Some(OTHER), Some(vec![]));
        let mut scoped = ace(sd::SYSTEM_AUDIT, 0, "S-1-17-1", 0);
        scoped.ace_type = sd::SYSTEM_SCOPED_POLICY_ID;
        d.sacl = Some(Acl {
            revision: 2,
            aces: vec![scoped],
        });
        let e = evaluate(&d, &token());
        assert!(e.central_policy && e.partial());
        assert_eq!(
            e.not_evaluated(),
            [NotEvaluated::CentralPolicy, NotEvaluated::Privileges]
        );
    }

    #[test]
    fn integrity_label_and_privileges_are_reported() {
        let mut d = descriptor(Some(OTHER), Some(vec![]));
        // Low integrity, no write up (`ML;;NW;;;LW`).
        let mut label = ace(sd::SYSTEM_AUDIT, 1, "S-1-16-4096", 0);
        label.ace_type = sd::SYSTEM_MANDATORY_LABEL;
        d.sacl = Some(Acl {
            revision: 2,
            aces: vec![label],
        });
        let e = evaluate(&d, &token());
        assert!(e.integrity_label && e.partial());
        assert_eq!(
            e.not_evaluated(),
            [NotEvaluated::IntegrityLabel, NotEvaluated::Privileges]
        );
        // Without anything left out of the descriptor, privileges are still named.
        let e = evaluate(&descriptor(Some(OTHER), Some(vec![])), &token());
        assert!(!e.partial());
        assert_eq!(e.not_evaluated(), [NotEvaluated::Privileges]);
    }

    #[test]
    fn this_organization_and_asserted_identity_decide() {
        // Read for This Organization, writing denied to the asserted identity.
        let d = descriptor(
            Some(OTHER),
            Some(vec![
                ace(sd::ACCESS_DENIED, right::WRITE_DATA, "S-1-18-1", 0),
                ace(
                    sd::ACCESS_ALLOWED,
                    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                    "S-1-5-15",
                    0,
                ),
            ]),
        );
        let e = evaluate(&d, &token());
        assert_eq!(
            e.granted,
            (FILE_GENERIC_READ | FILE_GENERIC_WRITE) & !right::WRITE_DATA
        );
        assert_eq!(
            e.decision(right::WRITE_DATA),
            Some(&Decision {
                right: right::WRITE_DATA,
                allowed: false,
                source: Source::Ace(0)
            })
        );
        assert_eq!(e.decision(right::READ_DATA).unwrap().source, Source::Ace(1));
    }

    #[test]
    fn share_and_folder_intersect() {
        // Share: read for Everyone; folder: modify for the group.
        let share = descriptor(
            Some("S-1-5-32-544"),
            Some(vec![ace(sd::ACCESS_ALLOWED, 0x0012_00A9, "S-1-1-0", 0)]),
        );
        let folder = descriptor(
            Some(OTHER),
            Some(vec![ace(sd::ACCESS_ALLOWED, 0x0013_01BF, GROUP, 0)]),
        );
        let t = token().with_local_groups(LocalGroups::Evaluated(vec![]));
        let r = effective(Some(share), folder.clone(), t.clone());
        assert_eq!(r.granted, 0x0012_00A9);
        assert_eq!(r.limited_by_share(), 0x0013_01BF & !0x0012_00A9);
        assert!(!r.partial());
        // A share without descriptor allows everything.
        let r = effective(None, folder, t);
        assert_eq!(r.granted, 0x0013_01BF);
        assert_eq!(r.limited_by_share(), 0);
        // Local groups not evaluated: partial.
        let r = effective(None, descriptor(None, None), token());
        assert!(r.partial());
    }

    #[test]
    fn real_descriptor_of_samba() {
        // As smbcacls shows it on fs1: owner Domain Admins, Administrators full, a group
        // modify inherited to folders and files, Everyone nothing.
        let d = annuaire_codecs::sddl::sd_from_sddl(
            "O:S-1-5-21-1-2-3-512G:S-1-5-21-1-2-3-513D:P(A;OICI;FA;;;BA)(D;;WD;;;S-1-5-21-1-2-3-1200)(A;OICIID;0x1301bf;;;S-1-5-21-1-2-3-1200)",
            None,
            false,
        )
        .unwrap();
        let e = evaluate(&d, &token());
        assert_eq!(e.granted, 0x0013_01BF & !right::WRITE_DAC);
        assert_eq!(e.denied, right::WRITE_DAC);
        let t = token().with_local_groups(LocalGroups::Evaluated(vec![s("S-1-5-32-544")]));
        assert_eq!(evaluate(&d, &t).granted, FILE_ALL_ACCESS);
    }
}

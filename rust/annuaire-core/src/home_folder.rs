// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The home folder of an account, as the « Profile » tab of « Active Directory Users and
//! Computers » makes it (ADR 0027): `%username%` replaced by the `sAMAccountName` of the
//! account in `homeDirectory` and `profilePath` (the value written is the expanded one), and,
//! when a drive is connected to a UNC path, the folder created on its share if it does not
//! exist, with the permissions ADUC gives it.
//!
//! The permissions, read on a folder made by ADUC (`icacls`): full control for the account and
//! for `BUILTIN\Administrators`, each in two explicit ACEs (one for the folder itself, one
//! inherit-only for subfolders and files, generic rights: what Windows makes of an ACE
//! `GENERIC_ALL` with `OI|CI`), then the entries inherited from the parent, kept. The folder is
//! created without a descriptor, so that the server gives it its inherited entries itself;
//! the explicit ACEs are written next (`share_write`, `Operation::CreateShareFolder`). A
//! folder that already exists keeps its permissions: ADUC only warns, and so does Calinda. A
//! missing share or parent is refused: no share is ever created.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, PoisonError};

use annuaire_codecs::sd::{self, Ace, Acl, SecurityDescriptor};
use annuaire_codecs::sid::Sid;

use crate::changes::Operation;
use crate::connection::{Connection, Failure};
use crate::error::LdapError;
use crate::ntfs;
use crate::search;
use crate::session::{Scope, SearchRequest};
use crate::sysvol::{self, Protection, Session, SysvolError};

/// The variable ADUC replaces, whatever its case.
pub const USERNAME: &str = "%username%";

/// `STATUS_BAD_NETWORK_NAME`: the share does not exist (tree connect).
pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;

const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// `text` with every `%username%` (any case) replaced by `sam`.
pub fn expand_username(text: &str, sam: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut out = String::with_capacity(text.len());
    let mut rest = 0;
    while let Some(found) = lower.get(rest..).and_then(|l| l.find(USERNAME)) {
        let at = rest + found;
        out.push_str(text.get(rest..at).unwrap_or_default());
        out.push_str(sam);
        rest = at + USERNAME.len();
    }
    out.push_str(text.get(rest..).unwrap_or_default());
    out
}

/// A folder named by a UNC path: server, share, path in the share (`\` between components).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unc {
    pub server: String,
    pub share: String,
    pub path: String,
}

impl Unc {
    /// `\\server\share\folder[\…]`; `None` for anything else, the root of a share included
    /// (there is no folder to create), and for a component `.` or `..`.
    pub fn parse(text: &str) -> Option<Self> {
        let rest = text.trim().strip_prefix("\\\\")?;
        let parts: Vec<&str> = rest.trim_end_matches('\\').split('\\').collect();
        let valid = |p: &&str| !p.is_empty() && *p != "." && *p != ".." && !p.contains('/');
        if parts.len() < 3 || !parts.iter().all(valid) {
            return None;
        }
        let (server, share, path) = (parts.first()?, parts.get(1)?, parts.get(2..)?);
        Some(Self {
            server: (*server).to_owned(),
            share: (*share).to_owned(),
            path: path.join("\\"),
        })
    }
}

/// `BUILTIN\Administrators`, S-1-5-32-544.
pub fn administrators() -> Sid {
    Sid::new(5, &[32, 544]).expect("S-1-5-32-544 is a valid SID")
}

/// The explicit ACEs of a home folder: full control for `account`, then for the
/// administrators, on the folder (`FA`) and, inherit-only, on its subfolders and files (`GA`).
pub fn explicit_aces(account: &Sid) -> Vec<Ace> {
    let inherit = sd::OBJECT_INHERIT_ACE | sd::CONTAINER_INHERIT_ACE | sd::INHERIT_ONLY_ACE;
    let mut aces = Vec::new();
    for sid in [*account, administrators()] {
        for (mask, flags) in [(FILE_ALL_ACCESS, 0), (sd::GENERIC_ALL, inherit)] {
            if let Ok(ace) = Ace::simple(sd::ACCESS_ALLOWED, mask, &sid, flags) {
                aces.push(ace);
            }
        }
    }
    aces
}

/// The descriptor carried by the operation: the explicit ACEs alone, no owner (the server
/// makes the creator the owner, as for a folder made by ADUC).
pub fn descriptor(account: &Sid) -> Vec<u8> {
    SecurityDescriptor {
        revision: sd::REVISION,
        control: sd::SE_SELF_RELATIVE | sd::SE_DACL_PRESENT | sd::SE_DACL_AUTO_INHERITED,
        owner: None,
        group: None,
        sacl: None,
        dacl: Some(Acl {
            revision: sd::ACL_REVISION,
            aces: explicit_aces(account),
        }),
    }
    .encode()
    .unwrap_or_default()
}

/// `op` (a `CreateShareFolder` for an account created by the same changeset) with the
/// explicit ACEs of `sid`, as it is written.
pub fn for_sid(op: &Operation, sid: &Sid) -> Operation {
    let mut op = op.clone();
    if let Operation::CreateShareFolder {
        descriptor,
        account_dn,
        ..
    } = &mut op
    {
        *descriptor = self::descriptor(sid);
        *account_dn = None;
    }
    op
}

/// The descriptor written on the folder just created: the explicit ACEs of `explicit` before
/// the entries the server gave it (`created`), owner and group as created, inheritance on.
pub fn composed(created: &[u8], explicit: &[u8]) -> Option<Vec<u8>> {
    let created = SecurityDescriptor::decode(created).ok()?;
    let explicit = SecurityDescriptor::decode(explicit).ok()?;
    let mut written = ntfs::composed(
        &created,
        &ntfs::explicit_aces(&explicit),
        &ntfs::inherited_of(&created),
        false,
    );
    written.owner = None;
    written.group = None;
    written.encode().ok()
}

/// What a folder to create finds on its share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Found {
    /// Absent, its parent there: it can be created.
    Absent,
    /// Already there, as a folder: its permissions are not touched.
    Exists,
}

/// Why a folder cannot be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The share does not exist.
    ShareMissing,
    /// The parent folder does not exist (or is a file): `parent`, relative to the share.
    ParentMissing { parent: String },
    /// A file has the name of the folder.
    NotAFolder,
}

/// The state of `path` on the share of `session`: absent with its parent, or a folder already.
pub fn inspect(session: &mut Session, path: &str) -> sysvol::Result<Result<Found, Refusal>> {
    let parent = sysvol::parent(path);
    if !parent.is_empty() && session.nature(parent)? != Some(true) {
        return Ok(Err(Refusal::ParentMissing {
            parent: parent.to_owned(),
        }));
    }
    Ok(match session.nature(path)? {
        None => Ok(Found::Absent),
        Some(true) => Ok(Found::Exists),
        Some(false) => Err(Refusal::NotAFolder),
    })
}

/// Opens the session of `\\server\share`; `Ok(None)` when the share does not exist.
pub fn open(server: &str, share: &str, protection: Protection) -> sysvol::Result<Option<Session>> {
    match Session::open_share(server, share, protection, crate::sysvol_write::DELAY) {
        Ok(session) => Ok(Some(session)),
        Err(e) if e.ntstatus() == Some(BAD_NETWORK_NAME) => Ok(None),
        Err(e) => Err(e),
    }
}

// --- In the directory ----------------------------------------------------------------------------

/// What the home folder of an account needs from the directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub sam: String,
    pub sid: Sid,
    /// `DOMAIN\sam` when the domain is known, as the preview names the account.
    pub name: String,
    pub home_drive: String,
    pub home_directory: String,
}

fn text(entry: &crate::session::Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

/// The account `dn`: `None` if it does not exist or is not an account (no SID or no name).
pub fn read_account(connection: &Connection, dn: &str) -> Result<Option<Account>, Failure> {
    let dn = dn.to_owned();
    connection.run(true, move |link| {
        let attributes = ["sAMAccountName", "objectSid", "homeDrive", "homeDirectory"]
            .map(str::to_owned)
            .to_vec();
        let Some(entry) = search::read_entry(
            link.session.as_mut(),
            &dn,
            &attributes,
            "(objectClass=*)",
            None,
            Some(link.timeout),
        )?
        else {
            return Ok(None);
        };
        let sam = text(&entry, "sAMAccountName");
        let sid = entry
            .values("objectSid")
            .first()
            .and_then(|v| Sid::decode(v).ok());
        let Some(sid) = sid.filter(|_| !sam.is_empty()) else {
            return Ok(None);
        };
        let netbios = netbios_name(link)?;
        let name = account_name(
            netbios.as_deref(),
            &link.state.root_dse.default_naming_context,
            &sam,
        );
        Ok(Some(Account {
            sam,
            sid,
            name,
            home_drive: text(&entry, "homeDrive"),
            home_directory: text(&entry, "homeDirectory"),
        }))
    })
}

/// The NetBIOS names of the domains already read (`nETBIOSName`), by naming context: the name
/// of a domain does not change, it is read once.
fn netbios_cache() -> &'static Mutex<HashMap<String, Option<String>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<String>>>> = OnceLock::new();
    CACHE.get_or_init(Mutex::default)
}

/// The filter of the `crossRef` of the domain `naming_context` under `CN=Partitions`.
pub fn crossref_filter(naming_context: &str) -> String {
    format!(
        "(&(objectClass=crossRef)(nCName={})(nETBIOSName=*))",
        search::escape_filter(naming_context)
    )
}

/// The NetBIOS name of the domain of the connection, from its `crossRef` in the configuration
/// partition (`CN=Partitions`); `None` if the directory does not give it.
fn netbios_name(link: &mut crate::Link) -> Result<Option<String>, LdapError> {
    let root = &link.state.root_dse;
    let key = root.default_naming_context.to_lowercase();
    if let Some(known) = netbios_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&key)
    {
        return Ok(known.clone());
    }
    let request = SearchRequest {
        base: format!("CN=Partitions,{}", root.configuration_naming_context),
        scope: Scope::OneLevel,
        filter: crossref_filter(&root.default_naming_context),
        attributes: vec!["nETBIOSName".into()],
        controls: Vec::new(),
        size_limit: 0,
    };
    let found = link
        .session
        .search_wait(request, Some(link.timeout))?
        .into_entries()
        .into_iter()
        .map(|e| text(&e, "nETBIOSName"))
        .find(|n| !n.is_empty());
    netbios_cache()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, found.clone());
    Ok(found)
}

/// `DOMAIN\sam`, as the preview names the account: the NetBIOS name of the domain, or without
/// it the first label of its naming context in upper case (the usual case).
pub fn account_name(netbios: Option<&str>, naming_context: &str, sam: &str) -> String {
    let domain = netbios
        .map(str::to_owned)
        .filter(|n| !n.is_empty())
        .or_else(|| {
            naming_context
                .split(',')
                .next()
                .and_then(|c| c.split_once('='))
                .map(|(_, v)| v.to_uppercase())
        })
        .unwrap_or_default();
    if domain.is_empty() {
        sam.to_owned()
    } else {
        format!("{domain}\\{sam}")
    }
}

/// The DNS name of the file server named `server` in a UNC path (`SRV-FICHIERS`): the
/// `dNSHostName` of the computer of that name in the directory, which the Kerberos ticket and
/// the connection need; a name with a dot, or one the directory does not know, as it is.
/// With the protection of the profile for the SMB sessions.
pub fn server_of(connection: &Connection, server: &str) -> Result<(String, Protection), Failure> {
    let name = server.to_owned();
    connection.run(true, move |link| {
        let protection = link.sysvol;
        if name.contains('.') {
            return Ok((name.to_lowercase(), protection));
        }
        let request = SearchRequest {
            base: link.state.root_dse.default_naming_context.clone(),
            scope: Scope::Subtree,
            filter: format!(
                "(&(objectCategory=computer)(sAMAccountName={}$))",
                search::escape_filter(&name)
            ),
            attributes: vec!["dNSHostName".into()],
            controls: Vec::new(),
            size_limit: 2,
        };
        let found = match link.session.search_wait(request, Some(link.timeout)) {
            Ok(response) => response
                .into_entries()
                .into_iter()
                .map(|e| text(&e, "dNSHostName"))
                .find(|n| !n.is_empty()),
            Err(LdapError { code, .. }) if code == crate::error::code::SIZELIMIT_EXCEEDED => None,
            Err(e) => return Err(e),
        };
        Ok((
            found
                .unwrap_or(name.clone())
                .trim_end_matches('.')
                .to_lowercase(),
            protection,
        ))
    })
}

/// What saving the home folder of an account comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The folder to create, as an operation of the changeset.
    Create(Box<Operation>),
    /// The folder exists: left as it is, said in the preview (`unc` as written).
    Exists { unc: String },
}

/// Why the home folder cannot be planned.
#[derive(Debug, Clone)]
pub enum PlanError {
    Failure(Failure),
    /// The share or the parent is missing, or a file has the name: `unc` as written.
    Refused {
        unc: String,
        refusal: Refusal,
    },
    /// The file server could not be read.
    Server {
        server: String,
        error: SysvolError,
    },
}

/// The home folder `directory` (expanded) of `account`: to create, there already, or refused.
/// `None` when `directory` is not a folder under a share (nothing for Calinda to do, as for
/// ADUC with a local path). Blocking: one LDAP search and one SMB session.
pub fn plan(
    connection: &Connection,
    account: &Account,
    directory: &str,
) -> Result<Option<Plan>, PlanError> {
    planned(connection, directory, |server, unc| {
        Operation::create_share_folder(
            server,
            &unc.share,
            &unc.path,
            descriptor(&account.sid),
            &account.name,
        )
    })
}

/// The same for an account the changeset creates (`dn`, `sam`): its SID is read at the
/// write (`Operation::create_share_folder_for`).
pub fn plan_new(
    connection: &Connection,
    dn: &str,
    sam: &str,
    directory: &str,
) -> Result<Option<Plan>, PlanError> {
    let (netbios, context) = connection
        .run(true, |link| {
            Ok((
                netbios_name(link)?,
                link.state.root_dse.default_naming_context.clone(),
            ))
        })
        .map_err(PlanError::Failure)?;
    let name = account_name(netbios.as_deref(), &context, sam);
    planned(connection, directory, |server, unc| {
        Operation::create_share_folder_for(server, &unc.share, &unc.path, dn, &name)
    })
}

/// A home folder to plan for an account the changeset creates: its DN, its
/// `sAMAccountName`, its folder (expanded).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFolder {
    pub dn: String,
    pub sam: String,
    pub directory: String,
}

/// (server, share) in lower case → the folders asked on that share.
type ShareFolders = ((String, String), Vec<(usize, Unc)>);

/// `plan_new` for many accounts (the import, ADR 0026): one search per server and one SMB
/// session per share, instead of one of each per account. One answer per folder, in order.
pub fn plan_new_many(
    connection: &Connection,
    folders: &[NewFolder],
) -> Result<Vec<Result<Option<Plan>, PlanError>>, Failure> {
    let (netbios, context) = connection.run(true, |link| {
        Ok((
            netbios_name(link)?,
            link.state.root_dse.default_naming_context.clone(),
        ))
    })?;
    let mut servers: HashMap<String, (String, Protection)> = HashMap::new();
    let mut out: Vec<Option<Result<Option<Plan>, PlanError>>> = vec![None; folders.len()];
    // (server, share) → folders of that share.
    let mut shares: Vec<ShareFolders> = Vec::new();
    for (i, folder) in folders.iter().enumerate() {
        let Some(unc) = Unc::parse(&folder.directory) else {
            if let Some(slot) = out.get_mut(i) {
                *slot = Some(Ok(None));
            }
            continue;
        };
        let name = unc.server.to_lowercase();
        if !servers.contains_key(&name) {
            servers.insert(name.clone(), server_of(connection, &unc.server)?);
        }
        let k = (name, unc.share.to_lowercase());
        match shares.iter_mut().find(|(s, _)| *s == k) {
            Some((_, list)) => list.push((i, unc)),
            None => shares.push((k, vec![(i, unc)])),
        }
    }
    for ((name, _), list) in shares {
        let Some((server, protection)) = servers.get(&name).cloned() else {
            continue;
        };
        let share = list
            .first()
            .map(|(_, u)| u.share.clone())
            .unwrap_or_default();
        let written = |i: usize| {
            folders
                .get(i)
                .map(|f| f.directory.trim().to_owned())
                .unwrap_or_default()
        };
        let mut set = |i: usize, value: Result<Option<Plan>, PlanError>| {
            if let Some(slot) = out.get_mut(i) {
                *slot = Some(value);
            }
        };
        let mut session = match open(&server, &share, protection) {
            Ok(Some(session)) => session,
            Ok(None) => {
                for (i, _) in &list {
                    set(
                        *i,
                        Err(PlanError::Refused {
                            unc: written(*i),
                            refusal: Refusal::ShareMissing,
                        }),
                    );
                }
                continue;
            }
            Err(error) => {
                for (i, _) in &list {
                    set(
                        *i,
                        Err(PlanError::Server {
                            server: server.clone(),
                            error: error.clone(),
                        }),
                    );
                }
                continue;
            }
        };
        for (i, unc) in &list {
            let Some(folder) = folders.get(*i) else {
                continue;
            };
            let value = match inspect(&mut session, &unc.path) {
                Err(error) => Err(PlanError::Server {
                    server: server.clone(),
                    error,
                }),
                Ok(Err(refusal)) => Err(PlanError::Refused {
                    unc: written(*i),
                    refusal,
                }),
                Ok(Ok(Found::Exists)) => Ok(Some(Plan::Exists { unc: written(*i) })),
                Ok(Ok(Found::Absent)) => Ok(Some(Plan::Create(Box::new(
                    Operation::create_share_folder_for(
                        &server,
                        &unc.share,
                        &unc.path,
                        &folder.dn,
                        &account_name(netbios.as_deref(), &context, &folder.sam),
                    ),
                )))),
            };
            set(*i, value);
        }
        session.close();
    }
    Ok(out.into_iter().map(|o| o.unwrap_or(Ok(None))).collect())
}

fn planned(
    connection: &Connection,
    directory: &str,
    operation: impl FnOnce(&str, &Unc) -> Operation,
) -> Result<Option<Plan>, PlanError> {
    let Some(unc) = Unc::parse(directory) else {
        return Ok(None);
    };
    let written = directory.trim().to_owned();
    let (server, protection) = server_of(connection, &unc.server).map_err(PlanError::Failure)?;
    let failed = |error: SysvolError| PlanError::Server {
        server: server.clone(),
        error,
    };
    let refused = |refusal: Refusal| PlanError::Refused {
        unc: written.clone(),
        refusal,
    };
    let Some(mut session) = open(&server, &unc.share, protection).map_err(failed)? else {
        return Err(refused(Refusal::ShareMissing));
    };
    let found = inspect(&mut session, &unc.path);
    session.close();
    match found.map_err(failed)? {
        Err(refusal) => Err(refused(refusal)),
        Ok(Found::Exists) => Ok(Some(Plan::Exists { unc: written })),
        Ok(Found::Absent) => Ok(Some(Plan::Create(Box::new(operation(&server, &unc))))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use annuaire_codecs::sddl;

    #[test]
    fn username_expanded_whatever_its_case() {
        assert_eq!(
            expand_username("\\\\SRV-FICHIERS\\Home\\%username%", "a.martin"),
            "\\\\SRV-FICHIERS\\Home\\a.martin"
        );
        assert_eq!(
            expand_username("\\\\srv\\Profils\\%UserName%\\%USERNAME%.v6", "élise"),
            "\\\\srv\\Profils\\élise\\élise.v6"
        );
        assert_eq!(
            expand_username("\\\\srv\\Home\\fixe", "x"),
            "\\\\srv\\Home\\fixe"
        );
        assert_eq!(expand_username("%username", "x"), "%username");
        assert_eq!(expand_username("", "x"), "");
    }

    #[test]
    fn netbios_name_of_the_domain() {
        assert_eq!(
            crossref_filter("DC=lab,DC=test"),
            "(&(objectClass=crossRef)(nCName=DC=lab,DC=test)(nETBIOSName=*))"
        );
        // The name of the crossRef, even when it is not the first DNS label.
        assert_eq!(
            account_name(Some("LAB"), "DC=lab,DC=test", "a.martin"),
            "LAB\\a.martin"
        );
        assert_eq!(
            account_name(None, "DC=lab,DC=test", "a.martin"),
            "LAB\\a.martin"
        );
        assert_eq!(account_name(Some(""), "", "a.martin"), "a.martin");
    }

    #[test]
    fn unc_paths() {
        assert_eq!(
            Unc::parse(" \\\\SRV-FICHIERS\\Home\\a.martin\\ "),
            Some(Unc {
                server: "SRV-FICHIERS".into(),
                share: "Home".into(),
                path: "a.martin".into(),
            })
        );
        assert_eq!(
            Unc::parse("\\\\fs1.lab.test\\Commun\\Personnel\\é.dupont").map(|u| u.path),
            Some("Personnel\\é.dupont".into())
        );
        // The root of a share, a local path, a relative or odd one: nothing to create.
        for text in [
            "\\\\srv\\Home",
            "\\\\srv\\Home\\",
            "H:\\Home\\x",
            "\\srv\\Home\\x",
            "\\\\srv\\\\x",
            "\\\\srv\\Home\\..\\x",
            "\\\\srv\\Home\\a/b",
            "",
        ] {
            assert_eq!(Unc::parse(text), None, "{text}");
        }
    }

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    fn sddl_of(bytes: &[u8]) -> String {
        sddl::sd_to_sddl(&SecurityDescriptor::decode(bytes).unwrap(), None).unwrap()
    }

    #[test]
    fn the_dacl_of_aduc() {
        let user = sid("S-1-5-21-1-2-3-1105");
        // LAB\a.martin:(F) ; (OI)(CI)(IO)(F) ; BUILTIN\Administrateurs:(F) ; (OI)(CI)(IO)(F)
        assert_eq!(
            sddl_of(&descriptor(&user)),
            "D:AI(A;;FA;;;S-1-5-21-1-2-3-1105)(A;OICIIO;GA;;;S-1-5-21-1-2-3-1105)\
             (A;;FA;;;BA)(A;OICIIO;GA;;;BA)"
        );
    }

    fn encoded(text: &str) -> Vec<u8> {
        sddl::sd_from_sddl(text, None, false)
            .unwrap()
            .encode()
            .unwrap()
    }

    #[test]
    fn written_after_the_inherited_entries_of_the_server() {
        let user = sid("S-1-5-21-1-2-3-1105");
        // What the server gave the folder at its creation: the entries of the parent.
        let created = encoded(
            "O:S-1-5-21-1-2-3-500G:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;ID;0x1200a9;;;AU)",
        );
        let written = composed(&created, &descriptor(&user)).unwrap();
        assert_eq!(
            sddl_of(&written),
            "D:ARAI(A;;FA;;;S-1-5-21-1-2-3-1105)(A;OICIIO;GA;;;S-1-5-21-1-2-3-1105)\
             (A;;FA;;;BA)(A;OICIIO;GA;;;BA)\
             (A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;ID;0x1200a9;;;AU)"
        );
        // Not protected: the inheritance stays on.
        let d = SecurityDescriptor::decode(&written).unwrap();
        assert!(!ntfs::is_protected(&d));
        // A server that keeps generic rights mapped (Samba) reads back the same permissions.
        let read = encoded(
            "O:S-1-5-21-1-2-3-500G:SYD:AI(A;;FA;;;S-1-5-21-1-2-3-1105)(A;OICIIO;FA;;;S-1-5-21-1-2-3-1105)\
             (A;;FA;;;BA)(A;OICIIO;FA;;;BA)\
             (A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;ID;0x1200a9;;;AU)",
        );
        assert!(crate::share_write::same_file_descriptor(
            Some(&read),
            Some(&written)
        ));
    }

    #[test]
    fn journaled_and_undone() {
        let op = Operation::create_share_folder(
            "fs1.lab.test",
            "Home",
            "a.martin",
            descriptor(&sid("S-1-5-21-1-2-3-1105")),
            "LAB\\a.martin",
        );
        assert_eq!(op.dn(), "\\\\fs1.lab.test\\Home\\a.martin");
        assert!(op.is_file_share() && !op.is_ldap());
        let json = crate::changes::operation_to_json(&op).unwrap();
        assert_eq!(json["type"], "creer_dossier_partage");
        assert_eq!(crate::changes::operation_from_json(&json).unwrap(), op);
        let undo = crate::changes::inverse_sysvol(&op);
        assert!(matches!(undo, Operation::DeleteShareFolder { .. }));
        let json = crate::changes::operation_to_json(&undo).unwrap();
        assert_eq!(json["type"], "supprimer_dossier_partage");
        assert_eq!(crate::changes::operation_from_json(&json).unwrap(), undo);
        assert_eq!(crate::changes::inverse_sysvol(&undo), op);
    }

    #[test]
    fn an_account_created_by_the_same_changeset() {
        let dn = "CN=Alice Martin,OU=Personnel,DC=lab,DC=test";
        let op = Operation::create_share_folder_for(
            "fs1.lab.test",
            "Home",
            "a.martin",
            dn,
            "LAB\\a.martin",
        );
        let json = crate::changes::operation_to_json(&op).unwrap();
        assert_eq!(json["compte_dn"], dn);
        assert_eq!(crate::changes::operation_from_json(&json).unwrap(), op);
        let undo = crate::changes::inverse_sysvol(&op);
        let json = crate::changes::operation_to_json(&undo).unwrap();
        assert_eq!(crate::changes::operation_from_json(&json).unwrap(), undo);
        // At the write: the ACEs of the SID given by the DC.
        let user = sid("S-1-5-21-1-2-3-1105");
        let Operation::CreateShareFolder {
            descriptor: d,
            account_dn,
            ..
        } = for_sid(&op, &user)
        else {
            panic!("not a creation");
        };
        assert_eq!(d, descriptor(&user));
        assert_eq!(account_dn, None);
    }
}

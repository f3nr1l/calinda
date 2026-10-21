// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Writes on the group policies (J5.3 to J5.5), as changesets (ADR 0012,
//! `annuaire.core.actions_gpo`).
//!
//! Links (J5.3): `gPLink` and `gPOptions` of the containers (domain, OU, site), written whole
//! by the codec `gplink` (exact round trip); the guard is `uSNChanged` of the container, the
//! inverse puts the original value back.
//!
//! A GPO has two halves: the object `groupPolicyContainer` of the directory
//! (`CN={GUID},CN=Policies,CN=System,<domain>`) and its folder of the SYSVOL
//! (`<domain>\Policies\{GUID}`). As the GPMC, both are written on the same DC, the PDC
//! emulator by default; a changeset thus mixes LDAP and SYSVOL operations, applied in order,
//! journaled and undone alike.
//!
//! No function writes: each reads the state on the write connection (and the SYSVOL of the
//! same DC), then returns a `Changeset` for the common preview. The remarks are said by the
//! catalogue of the interface (`Msg`), the errors are values (`GpoError`).
//!
//! ACL of the folder: those `samba-tool ntacl sysvolreset` would set, computed as
//! `dsacl2fsacl` (samba/ntacls.py) from the descriptor of the object — simple and object
//! allow ACEs only (but « Pre-Windows 2000 Compatible Access »), `OI|CI` flags added (and `IO`
//! for CREATOR OWNER), mask translated by `ldapmask2filemask`, owner, group and control flags
//! copied — and set on the folder **and each of its elements** (`set_dir_acl`: the same
//! descriptor everywhere). `sysvolcheck` compares exactly that. SET_INFO propagating nothing,
//! each element has its operation.

use std::collections::HashSet;
use std::io::Read as _;

use annuaire_codecs::gplink::{self, GpLink};
use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::sd::{self, Ace, Acl, SecurityDescriptor};
use annuaire_codecs::sddl;
use annuaire_codecs::{Guid, Sid};

use crate::changes::{AttributeMap, Change, ChangeError, Changeset, Operation, Read, dn_key};
use crate::connection::{Connection, Failure, Link};
use crate::dn::{self, Component};
use crate::error::{LdapError, code};
use crate::gpo::{self, FilterRight};
use crate::messages::{Catalog, Msg};
use crate::search::{self, SD_WITHOUT_SACL};
use crate::session::{Entry, Scope};
use crate::sysvol::{self, Element, SysvolError};
use crate::sysvol_write::{self, SysvolSession};
use crate::writer::WriteMsg;

pub const GPO_CLASS: &str = "groupPolicyContainer";
pub const SD: &str = "nTSecurityDescriptor";
pub const DOMAIN_ADMINS_RID: u32 = 512;
pub const FUNCTIONALITY_VERSION: &[u8] = b"2";
/// `GPT.INI` of a new GPO (as `samba-tool gpo create`).
pub const NEW_GPT_INI: &[u8] = b"[General]\r\nVersion=0\r\n";

pub const GPO_ATTRIBUTES: [&str; 9] = [
    "cn",
    "displayName",
    "gPCFileSysPath",
    "flags",
    "versionNumber",
    "gPCFunctionalityVersion",
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "gPCWQLFilter",
];

fn sid(text: &str) -> Sid {
    text.parse().expect("well-known SID")
}

/// Pre-Windows 2000 Compatible Access.
fn pre_w2k() -> Sid {
    sid("S-1-5-32-554")
}

fn creator_owner() -> Sid {
    sid("S-1-3-0")
}

pub fn authenticated_users() -> Sid {
    sid("S-1-5-11")
}

// --- Errors -------------------------------------------------------------------------------------

/// Why a changeset of the group policies could not be prepared; the interface says it.
#[derive(Debug, Clone)]
pub enum GpoError {
    Failure(Failure),
    Sysvol(SysvolError),
    /// The write connection is not on the PDC emulator (`hors_pdc`).
    OffPdc(WriteMsg),
    EmptyName,
    /// The descriptor of the GPO grants no permission: the folder would be open to all.
    NoPermission,
    DomainSidUnreadable,
    DefaultDescriptorUnreadable,
    DescriptorUnreadable {
        dn: String,
    },
    /// The GPO does not exist (a conflict: read it again).
    Missing {
        dn: String,
    },
    NotAGpo {
        dn: String,
    },
    ContainerMissing {
        dn: String,
    },
    AlreadyLinked,
    NoLongerLinked,
    OrderOutOfRange {
        order: usize,
        n: usize,
    },
    OrphanGone {
        name: String,
        dc: String,
    },
    NotOrphan {
        name: String,
        dn: String,
    },
    InvalidFolderName {
        name: String,
    },
    /// Content of a GPO (R4.9): a file that was not read (`fichier de GPO non lu`).
    NotRead {
        path: String,
    },
    /// A folder where a file is expected, and the reverse.
    IsFolder {
        path: String,
        dn: String,
    },
    IsFile {
        path: String,
        dn: String,
    },
    /// The folder of the GPO is missing from the SYSVOL of this DC.
    FolderAbsent {
        name: String,
        dn: String,
    },
    /// The domain object cannot be read (security settings).
    DomainUnreadable {
        dn: String,
    },
    /// Security settings refused (bounds, inconsistent policy).
    #[cfg(feature = "gpo-content")]
    Security(Vec<crate::security_policy::SecurityProblem>),
    /// A preferences file that cannot be read: writing it is refused.
    #[cfg(feature = "gpo-content")]
    Preferences {
        path: String,
        error: crate::gpp::PreferencesError,
    },
    /// An element changed in the draft is no longer in the file (removed by another tool).
    #[cfg(feature = "gpo-content")]
    PreferenceGone {
        uid: String,
    },
    /// A descriptor or a changeset that could not be built (codec).
    Invalid(String),
    /// A backup archive that could not be written or read.
    #[cfg(feature = "gpo-backup")]
    Backup(crate::gpo_backup::BackupError),
}

impl From<ChangeError> for GpoError {
    fn from(e: ChangeError) -> Self {
        Self::Invalid(e.to_string())
    }
}

impl From<sd::SdError> for GpoError {
    fn from(e: sd::SdError) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// An error of a step on the thread of the connection: LDAP (the connection decides) or not.
#[derive(Debug)]
pub(crate) enum Step {
    Ldap(LdapError),
    Gpo(GpoError),
}

impl From<LdapError> for Step {
    fn from(e: LdapError) -> Self {
        Self::Ldap(e)
    }
}

impl From<GpoError> for Step {
    fn from(e: GpoError) -> Self {
        Self::Gpo(e)
    }
}

impl From<SysvolError> for Step {
    fn from(e: SysvolError) -> Self {
        Self::Gpo(GpoError::Sysvol(e))
    }
}

impl From<ChangeError> for Step {
    fn from(e: ChangeError) -> Self {
        Self::Gpo(e.into())
    }
}

impl From<sd::SdError> for Step {
    fn from(e: sd::SdError) -> Self {
        Self::Gpo(e.into())
    }
}

/// Runs `work` on the thread of the connection; a `Step::Gpo` comes back as an error value.
pub(crate) fn run<T, F>(connection: &Connection, mut work: F) -> Result<T, GpoError>
where
    T: Send + 'static,
    F: FnMut(&mut Link) -> Result<T, Step> + Send + 'static,
{
    connection
        .run(true, move |link| match work(link) {
            Ok(v) => Ok(Ok(v)),
            Err(Step::Ldap(e)) => Err(e),
            Err(Step::Gpo(g)) => Ok(Err(g)),
        })
        .map_err(GpoError::Failure)?
}

// --- Names and paths ----------------------------------------------------------------------------

pub fn gpo_container(base: &str) -> String {
    format!("CN=Policies,CN=System,{base}")
}

pub fn gpo_dn(base: &str, guid: &str) -> String {
    let rdn = dn::compose(&[Component {
        attribute: "CN".into(),
        value: guid.to_uppercase(),
    }])
    .unwrap_or_else(|_| format!("CN={}", guid.to_uppercase()));
    format!("{rdn},{}", gpo_container(base))
}

/// `{GUID}` of a GPO from its DN (the `cn`, not the `objectGUID`) (`guid_de`).
pub fn guid_of(dn_text: &str) -> String {
    dn::split(dn_text)
        .ok()
        .and_then(|c| c.first().map(|c| c.value.to_uppercase()))
        .unwrap_or_default()
}

/// A new GUID, `{…}` in upper case (`nouveau_guid`).
pub fn new_guid() -> String {
    let mut bytes = [0u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .is_err()
    {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        bytes = nanos.to_le_bytes();
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02X}")).collect();
    let part = |a: usize, b: usize| hex.get(a..b).unwrap_or_default();
    format!(
        "{{{}-{}-{}-{}-{}}}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

/// `DC=lab,DC=test` → `lab.test` (`domaine_dns`).
pub fn domain_dns(base: &str) -> String {
    gpo::dns_name(base).to_lowercase()
}

/// Folder of a GPO, relative to the share: `lab.test\Policies\{GUID}` (`dossier_gpo`).
pub fn gpo_folder(domain: &str, guid: &str) -> String {
    sysvol::join(&[&domain.to_lowercase(), "Policies", &guid.to_uppercase()])
}

/// Value of `gPCFileSysPath` as the GPMC writes it (`chemin_unc`).
pub fn unc_path(domain: &str, guid: &str) -> String {
    let d = domain.to_lowercase();
    format!("\\\\{d}\\SysVol\\{d}\\Policies\\{}", guid.to_uppercase())
}

/// Path relative to the share from `gPCFileSysPath` (`\\<domain or DC>\SysVol\…`); the server
/// named is ignored: the chosen DC is always read (ADR 0002, point 4) (`depuis_unc`).
pub fn from_unc(value: &str) -> Option<String> {
    let value = value.replace('/', "\\");
    let pieces: Vec<&str> = value.split('\\').filter(|p| !p.is_empty()).collect();
    if pieces.len() < 3 || !pieces.get(1)?.eq_ignore_ascii_case(sysvol::SHARE) {
        return None;
    }
    Some(sysvol::join(pieces.get(2..)?))
}

fn file_name(path: &str) -> &str {
    path.rsplit_once('\\').map_or(path, |(_, n)| n)
}

// --- ACL of the SYSVOL folder: dsacl2fsacl -------------------------------------------------------

const FILE_READ_DATA: u32 = 0x0001;
const FILE_WRITE_DATA: u32 = 0x0002;
const FILE_APPEND_DATA: u32 = 0x0004;
const FILE_READ_EA: u32 = 0x0008;
const FILE_WRITE_EA: u32 = 0x0010;
const FILE_EXECUTE: u32 = 0x0020;
const FILE_DELETE_CHILD: u32 = 0x0040;
const FILE_READ_ATTRIBUTES: u32 = 0x0080;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
const STANDARD_RIGHTS_ALL: u32 = 0x001F_0000;

/// `ldapmask2filemask`: rights of the directory → rights of a file (`masque_fichier`).
pub fn file_mask(mask: u32) -> u32 {
    let mut file = mask & STANDARD_RIGHTS_ALL;
    if mask & sd::ADS_RIGHT_DS_READ_PROP != 0 && mask & sd::ADS_RIGHT_ACTRL_DS_LIST != 0 {
        file |=
            sd::SYNCHRONIZE | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_EXECUTE;
    }
    if mask & sd::ADS_RIGHT_DS_WRITE_PROP != 0 {
        file |= sd::SYNCHRONIZE
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES;
    }
    if mask & sd::ADS_RIGHT_DS_CREATE_CHILD != 0 {
        file |= FILE_APPEND_DATA | FILE_WRITE_DATA;
    }
    if mask & sd::ADS_RIGHT_DS_DELETE_CHILD != 0 {
        file |= FILE_DELETE_CHILD;
    }
    file
}

const DACL_BITS: u16 = sd::SE_DACL_PRESENT
    | sd::SE_DACL_DEFAULTED
    | sd::SE_DACL_AUTO_INHERIT_REQ
    | sd::SE_DACL_AUTO_INHERITED
    | sd::SE_DACL_PROTECTED;

fn with_mask(ace: &Ace, mask: u32, flags: u8) -> Ace {
    let mut body = mask.to_le_bytes().to_vec();
    body.extend(ace.body.get(4..).unwrap_or_default());
    Ace {
        ace_type: ace.ace_type,
        flags,
        body,
    }
}

/// `dsacl2fsacl`: the descriptor of a folder of a GPO from the one of the object
/// (`descripteur_fichier`).
pub fn file_descriptor(descriptor: &SecurityDescriptor) -> Result<SecurityDescriptor, GpoError> {
    let mut aces = Vec::new();
    let mut object = false;
    for ace in descriptor.dacl.iter().flat_map(|d| d.aces.iter()) {
        if ![sd::ACCESS_ALLOWED, sd::ACCESS_ALLOWED_OBJECT].contains(&ace.ace_type)
            || ace.sid() == Some(pre_w2k())
        {
            continue;
        }
        let mut flags = ace.flags | sd::OBJECT_INHERIT_ACE | sd::CONTAINER_INHERIT_ACE;
        if ace.sid() == Some(creator_owner()) {
            flags |= sd::INHERIT_ONLY_ACE;
        }
        aces.push(with_mask(ace, file_mask(ace.mask()), flags));
        object = object || ace.is_object();
    }
    if aces.is_empty() {
        // Samba would then write a descriptor without a DACL: everyone would have every right.
        return Err(GpoError::NoPermission);
    }
    Ok(SecurityDescriptor {
        revision: sd::REVISION,
        control: (descriptor.control & DACL_BITS) | sd::SE_DACL_PRESENT | sd::SE_SELF_RELATIVE,
        owner: descriptor.owner,
        group: descriptor.group,
        sacl: None,
        dacl: Some(Acl {
            revision: if object {
                sd::ACL_REVISION_DS
            } else {
                sd::ACL_REVISION
            },
            aces,
        }),
    })
}

/// The bytes of the folder descriptor from those of the object (`octets_fichier`).
pub fn file_bytes(object_descriptor: &[u8]) -> Result<Vec<u8>, GpoError> {
    let descriptor = SecurityDescriptor::decode(object_descriptor)?;
    Ok(file_descriptor(&descriptor)?.encode()?)
}

// --- Descriptor of a new GPO ----------------------------------------------------------------------

/// The descriptor a DC gives to a GPO created by an administrator of the domain
/// (`descripteur_creation`).
///
/// `default`: `defaultSecurityDescriptor` of the class `groupPolicyContainer`. Owner and
/// group: Domain Admins. An inheritable ACE of CREATOR OWNER becomes, as at any creation, a
/// « child objects only » ACE (`IO`) followed by the same for the owner, without inheritance
/// (MS-DTYP 2.5.3.4.1). The DACL being protected, nothing is inherited from the container.
/// Seen identical on the GPOs of the GPMC and of `samba-tool gpo create`.
pub fn creation_descriptor(
    default: &str,
    domain_sid: &Sid,
) -> Result<SecurityDescriptor, GpoError> {
    let base = sddl::sd_from_sddl(default, Some(domain_sid), false)
        .map_err(|e| GpoError::Invalid(e.to_string()))?;
    let owner = domain_sid
        .with_rid(DOMAIN_ADMINS_RID)
        .map_err(|e| GpoError::Invalid(e.to_string()))?;
    let mut aces = Vec::new();
    for ace in base.dacl.iter().flat_map(|d| d.aces.iter()) {
        let inheritable = ace.flags & (sd::CONTAINER_INHERIT_ACE | sd::OBJECT_INHERIT_ACE) != 0;
        let sid = ace.sid();
        if sid == Some(creator_owner()) && inheritable && ace.flags & sd::INHERIT_ONLY_ACE == 0 {
            let mut io = ace.clone();
            io.flags |= sd::INHERIT_ONLY_ACE;
            aces.push(io);
            let length = sid.map_or(0, |s| s.binary_len());
            let mut body = ace
                .body
                .get(..ace.body.len().saturating_sub(length))
                .unwrap_or_default()
                .to_vec();
            owner.write_to(&mut body);
            let flags = ace.flags
                & !(sd::CONTAINER_INHERIT_ACE
                    | sd::OBJECT_INHERIT_ACE
                    | sd::NO_PROPAGATE_INHERIT_ACE);
            aces.push(Ace {
                ace_type: ace.ace_type,
                flags,
                body,
            });
        } else {
            aces.push(ace.clone());
        }
    }
    Ok(SecurityDescriptor {
        revision: sd::REVISION,
        control: (base.control & DACL_BITS) | sd::SE_DACL_PRESENT | sd::SE_SELF_RELATIVE,
        owner: Some(owner),
        group: Some(owner),
        sacl: None,
        dacl: Some(Acl {
            revision: base.dacl.as_ref().map_or(sd::ACL_REVISION, |d| d.revision),
            aces,
        }),
    })
}

// --- Reads on the write DC --------------------------------------------------------------------------

const ALL: &str = "(objectClass=*)";

fn read_entry(
    link: &mut Link,
    dn_text: &str,
    attributes: &[&str],
    sd_flags: Option<i64>,
) -> Result<Option<Entry>, LdapError> {
    let attributes: Vec<String> = attributes.iter().map(|&a| a.to_owned()).collect();
    search::read_entry(
        link.session.as_mut(),
        dn_text,
        &attributes,
        ALL,
        sd_flags,
        Some(link.timeout),
    )
}

/// A complete paged search on the thread of the connection (`chercher`).
pub(crate) fn search(
    link: &mut Link,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<Entry>, LdapError> {
    gpo::search_all(link, base, scope, filter, attributes, &[])
}

fn usn_of(entry: &Entry) -> i64 {
    entry
        .values("uSNChanged")
        .first()
        .and_then(|v| integer::decode(v, Width::Bits64).ok())
        .unwrap_or(0)
}

fn version_read(link: &Link, entry: &Entry) -> Read {
    Read {
        dc: link.state.dc.clone(),
        usn: usn_of(entry),
    }
}

fn domain_sid(link: &mut Link) -> Result<Sid, Step> {
    let base = link.state.root_dse.default_naming_context.clone();
    let entry = read_entry(link, &base, &["objectSid"], None)?;
    entry
        .as_ref()
        .and_then(|e| e.values("objectSid").first().cloned())
        .and_then(|v| Sid::decode(&v).ok())
        .ok_or(Step::Gpo(GpoError::DomainSidUnreadable))
}

fn default_gpo_descriptor(link: &mut Link) -> Result<String, Step> {
    let schema = link.state.root_dse.schema_naming_context.clone();
    let filter = format!("(&(objectClass=classSchema)(lDAPDisplayName={GPO_CLASS}))");
    let entries = search(
        link,
        &schema,
        Scope::OneLevel,
        &filter,
        &["defaultSecurityDescriptor"],
    )?;
    entries
        .first()
        .and_then(|e| e.values("defaultSecurityDescriptor").first().cloned())
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .ok_or(Step::Gpo(GpoError::DefaultDescriptorUnreadable))
}

/// A GPO read on the write DC (`GpoLue`): the object (with its descriptor without SACL) and its
/// version, the path of its folder relative to the SYSVOL share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpoRead {
    pub dn: String,
    pub attributes: AttributeMap,
    pub read: Read,
    pub folder: String,
}

impl GpoRead {
    pub fn values(&self, attribute: &str) -> &[Vec<u8>] {
        self.attributes
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attribute))
            .map_or(&[], |(_, v)| v.as_slice())
    }

    pub fn text(&self, attribute: &str) -> String {
        self.values(attribute)
            .first()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default()
    }

    pub fn guid(&self) -> String {
        guid_of(&self.dn)
    }

    pub fn name(&self) -> String {
        let name = self.text("displayName");
        if name.is_empty() { self.guid() } else { name }
    }

    pub fn descriptor(&self) -> Result<&[u8], GpoError> {
        self.values(SD)
            .first()
            .map(Vec::as_slice)
            .ok_or_else(|| GpoError::DescriptorUnreadable {
                dn: self.dn.clone(),
            })
    }
}

/// Reads the GPO `dn` (attributes, descriptor without SACL, version) (`lire_gpo`).
pub(crate) fn read_gpo(link: &mut Link, dn_text: &str) -> Result<GpoRead, Step> {
    let mut attributes = vec!["uSNChanged", "objectClass", SD];
    attributes.extend(GPO_ATTRIBUTES);
    let Some(entry) = read_entry(link, dn_text, &attributes, Some(SD_WITHOUT_SACL))? else {
        return Err(GpoError::Missing {
            dn: dn_text.to_owned(),
        }
        .into());
    };
    let is_gpo = entry
        .values("objectClass")
        .iter()
        .any(|v| v.eq_ignore_ascii_case(GPO_CLASS.as_bytes()));
    if !is_gpo {
        return Err(GpoError::NotAGpo {
            dn: dn_text.to_owned(),
        }
        .into());
    }
    let base = link.state.root_dse.default_naming_context.clone();
    let folder = entry
        .values("gPCFileSysPath")
        .first()
        .and_then(|v| from_unc(&String::from_utf8_lossy(v)))
        .filter(|f| !f.is_empty())
        .unwrap_or_else(|| gpo_folder(&domain_dns(&base), &guid_of(&entry.dn)));
    Ok(GpoRead {
        dn: entry.dn.clone(),
        read: version_read(link, &entry),
        attributes: entry.attributes.clone(),
        folder,
    })
}

/// A GPO is read and written on the PDC emulator (`_au_pdc`).
fn at_pdc(link: &mut Link, imposed: bool) -> Result<(), Step> {
    match sysvol_write::off_pdc(link, imposed, None)? {
        Some(reason) => Err(GpoError::OffPdc(reason).into()),
        None => Ok(()),
    }
}

/// Runs `work` on the thread of the write connection, with a session on the SYSVOL of the same
/// DC, closed afterwards (`sur_dc`).
pub(crate) fn on_dc<T, F>(connection: &Connection, mut work: F) -> Result<T, GpoError>
where
    T: Send + 'static,
    F: FnMut(&mut Link, &mut SysvolSession) -> Result<T, Step> + Send + 'static,
{
    let imposed = connection.profile().write_dc.is_some();
    run(connection, move |link| {
        at_pdc(link, imposed)?;
        let mut session = SysvolSession::new(sysvol_write::opener(link.sysvol), &link.state.dc);
        let result = work(link, &mut session);
        session.close();
        result
    })
}

// --- J5.4: creation --------------------------------------------------------------------------------

fn bytes(text: &str) -> Vec<Vec<u8>> {
    vec![text.as_bytes().to_vec()]
}

/// Changeset of the creation of an empty GPO (pure) (`creer`).
///
/// Directory: the object with the attributes the GPMC writes (`displayName`,
/// `gPCFileSysPath`, `versionNumber` 0, `flags` 0, `gPCFunctionalityVersion` 2) and the default
/// descriptor of the class, then its containers `CN=User` and `CN=Machine`. SYSVOL: the folder
/// `{GUID}`, `Machine`, `User` and `GPT.INI` (`Version=0`), each with the ACL `sysvolreset`
/// would give it.
pub fn create(
    base: &str,
    domain_sid: &Sid,
    default: &str,
    name: &str,
    guid: Option<&str>,
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(GpoError::EmptyName);
    }
    let guid = guid.map_or_else(new_guid, str::to_uppercase);
    let domain = domain_dns(base);
    let dn_text = gpo_dn(base, &guid);
    let object_sd = creation_descriptor(default, domain_sid)?;
    let folder_sd = file_descriptor(&object_sd)?.encode()?;
    let folder = gpo_folder(&domain, &guid);
    let operations = vec![
        Operation::add(
            &dn_text,
            vec![
                ("objectClass".into(), bytes(GPO_CLASS)),
                ("cn".into(), bytes(&guid)),
                ("displayName".into(), bytes(name)),
                ("gPCFileSysPath".into(), bytes(&unc_path(&domain, &guid))),
                ("versionNumber".into(), bytes("0")),
                ("flags".into(), bytes("0")),
                (
                    "gPCFunctionalityVersion".into(),
                    vec![FUNCTIONALITY_VERSION.to_vec()],
                ),
                (SD.into(), vec![object_sd.encode()?]),
            ],
        )?,
        Operation::add(
            &format!("CN=User,{dn_text}"),
            vec![
                ("objectClass".into(), bytes("container")),
                ("cn".into(), bytes("User")),
            ],
        )?,
        Operation::add(
            &format!("CN=Machine,{dn_text}"),
            vec![
                ("objectClass".into(), bytes("container")),
                ("cn".into(), bytes("Machine")),
            ],
        )?,
        create_folder(&dn_text, &folder, Some(&folder_sd)),
        create_folder(
            &dn_text,
            &sysvol::join(&[&folder, "Machine"]),
            Some(&folder_sd),
        ),
        create_folder(
            &dn_text,
            &sysvol::join(&[&folder, "User"]),
            Some(&folder_sd),
        ),
        Operation::WriteFile {
            dn: dn_text.clone(),
            path: sysvol::join(&[&folder, "GPT.INI"]),
            content: NEW_GPT_INI.to_vec(),
            old: None,
            descriptor: Some(folder_sd.clone()),
        },
    ];
    Ok(Changeset {
        operations,
        remarks: vec![catalog.text(&Msg::GpoCreated {
            name: name.to_owned(),
            guid,
        })],
    })
}

fn create_folder(dn_text: &str, path: &str, descriptor: Option<&[u8]>) -> Operation {
    Operation::CreateFolder {
        dn: dn_text.to_owned(),
        path: path.to_owned(),
        descriptor: descriptor.map(<[u8]>::to_vec),
    }
}

/// Reads the SID of the domain and the default descriptor of the GPOs, then returns `create`
/// (`preparer_creation`). Blocking.
pub fn prepare_creation(
    connection: &Connection,
    name: &str,
    guid: Option<&str>,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let imposed = connection.profile().write_dc.is_some();
    let (name, guid) = (name.to_owned(), guid.map(str::to_owned));
    run(connection, move |link| {
        at_pdc(link, imposed)?;
        let base = link.state.root_dse.default_naming_context.clone();
        let sid = domain_sid(link)?;
        let default = default_gpo_descriptor(link)?;
        Ok(create(
            &base,
            &sid,
            &default,
            &name,
            guid.as_deref(),
            catalog.as_ref(),
        )?)
    })
}

// --- Reading of the folder: elements and their ACL ----------------------------------------------------

/// Survey of the folder; empty if it does not exist (`_elements`).
pub(crate) fn elements(
    session: &mut SysvolSession,
    folder: &str,
    contents: bool,
) -> Result<Vec<Element>, SysvolError> {
    match session.client()?.survey(folder, contents, true) {
        Err(e) if e.ntstatus().is_some_and(sysvol::absent) => Ok(Vec::new()),
        other => other,
    }
}

/// Operations that give `folder_sd` to each element of the folder that does not have it
/// (`acl_dossier`).
pub fn folder_acl(dn_text: &str, elements: &[Element], folder_sd: &[u8]) -> Vec<Operation> {
    elements
        .iter()
        .filter_map(|e| {
            let before = e.descriptor.as_ref()?;
            (!sysvol_write::same_descriptor(Some(before), Some(folder_sd))).then(|| {
                Operation::SetDescriptor {
                    dn: dn_text.to_owned(),
                    path: e.path.clone(),
                    before: before.clone(),
                    after: folder_sd.to_vec(),
                }
            })
        })
        .collect()
}

/// Aligns the ACL of the folder of the GPO on its descriptor (`sysvolreset` of a GPO)
/// (`preparer_alignement`). Blocking.
pub fn prepare_alignment(
    connection: &Connection,
    dn_text: &str,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let dn_text = dn_text.to_owned();
    on_dc(connection, move |link, session| {
        let gpo = read_gpo(link, &dn_text)?;
        let folder_sd = file_bytes(gpo.descriptor()?)?;
        let operations = folder_acl(
            &dn_text,
            &elements(session, &gpo.folder, false)?,
            &folder_sd,
        );
        let remarks = if operations.is_empty() {
            Vec::new()
        } else {
            vec![catalog.text(&Msg::GpoAclReset {
                name: gpo.name(),
                n: operations.len(),
            })]
        };
        Ok(Changeset {
            operations,
            remarks,
        })
    })
}

// --- J5.5: security filtering -------------------------------------------------------------------

/// Reading, as the ACE of the Authenticated Users of the default descriptor (`LCRPLORC`).
pub const READ_GPO: u32 = sd::ADS_RIGHT_ACTRL_DS_LIST
    | sd::ADS_RIGHT_DS_READ_PROP
    | sd::ADS_RIGHT_DS_LIST_OBJECT
    | sd::READ_CONTROL;

/// The two ACEs the GPMC writes to « apply to » a group or an account: reading, and the
/// extended right « Apply group policy », inheritable (`CI`) as those of the default
/// descriptor (`aces_filtrage`).
pub fn filtering_aces(sid: &Sid) -> Result<[Ace; 2], GpoError> {
    let apply: Guid = gpo::right_apply();
    Ok([
        Ace::simple(sd::ACCESS_ALLOWED, READ_GPO, sid, sd::CONTAINER_INHERIT_ACE)?,
        Ace::object(
            sd::ACCESS_ALLOWED_OBJECT,
            sd::ADS_RIGHT_DS_CONTROL_ACCESS,
            sid,
            sd::CONTAINER_INHERIT_ACE,
            Some(apply),
            None,
        )?,
    ])
}

/// Accounts and groups the GPO applies to (reading and application, without denial): what
/// the GPMC shows under « Security Filtering » (`appliquent`).
pub fn applying(descriptor: &SecurityDescriptor) -> Vec<Sid> {
    gpo::filtering(Some(descriptor))
        .into_iter()
        .filter(|f| f.applies())
        .map(|f| f.sid)
        .collect()
}

/// Changeset of the filtering (pure) (`filtrer`): ACEs added or removed on the object, then
/// the ACL of each element of the folder computed again as `sysvolreset` (GPMC: the object
/// and the folder). Removing an account removes its explicit reading and application ACEs
/// that have the form of `filtering_aces` (a broader delegation stays).
pub fn filter(
    gpo: &GpoRead,
    elements: &[Element],
    add: &[Sid],
    remove: &[Sid],
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let raw = gpo.descriptor()?;
    let old = SecurityDescriptor::decode(raw)?;
    let mut new = old.clone();
    for sid in remove {
        new = new.remove_aces(&filtering_aces(sid)?);
    }
    for sid in add {
        new = new.add_aces(&filtering_aces(sid)?)?;
    }
    if new == old {
        return Ok(Changeset::default());
    }
    let encoded = new.encode()?;
    let mut operations = vec![Operation::modify(
        &gpo.dn,
        vec![Change::new(SD, vec![raw.to_vec()], vec![encoded.clone()])?],
        Some(gpo.read.clone()),
    )?];
    operations.extend(folder_acl(&gpo.dn, elements, &file_bytes(&encoded)?));
    let mut remarks = Vec::new();
    if applying(&new).is_empty() {
        remarks.push(catalog.text(&Msg::GpoNobodyApplies));
    }
    if !gpo::access(Some(&new), &HashSet::from([authenticated_users()])).read {
        remarks.push(catalog.text(&Msg::GpoAuthenticatedUsersCannotRead));
    }
    Ok(Changeset {
        operations,
        remarks,
    })
}

/// Reads the GPO and its folder on the write DC, then returns `filter`
/// (`preparer_filtrage`). Blocking.
pub fn prepare_filtering(
    connection: &Connection,
    dn_text: &str,
    add: Vec<Sid>,
    remove: Vec<Sid>,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let dn_text = dn_text.to_owned();
    on_dc(connection, move |link, session| {
        let gpo = read_gpo(link, &dn_text)?;
        let found = elements(session, &gpo.folder, false)?;
        Ok(filter(&gpo, &found, &add, &remove, catalog.as_ref())?)
    })
}

/// The filtering of a GPO as the dialog shows it: accounts and groups it applies to.
pub fn filter_rights(gpo: &gpo::Gpo) -> Vec<FilterRight> {
    gpo::filtering(gpo.descriptor.as_ref())
        .into_iter()
        .filter(|f| f.applies())
        .collect()
}

// --- J5.4: deletion ----------------------------------------------------------------------------

/// Objects under the GPO (`CN=User`, `CN=Machine` and what the extensions put there), the
/// deepest first (`_sous_objets`).
fn sub_objects(link: &mut Link, dn_text: &str) -> Result<Vec<(String, Read)>, LdapError> {
    let key = dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase());
    let mut entries: Vec<Entry> = search(link, dn_text, Scope::Subtree, ALL, &["uSNChanged"])?
        .into_iter()
        .filter(|e| dn_key(&e.dn).unwrap_or_else(|_| e.dn.to_lowercase()) != key)
        .collect();
    entries.sort_by_key(|e| std::cmp::Reverse(dn::split(&e.dn).map_or(0, |c| c.len())));
    Ok(entries
        .iter()
        .map(|e| (e.dn.clone(), version_read(link, e)))
        .collect())
}

fn depth(path: &str) -> usize {
    path.matches('\\').count()
}

/// Files and folders surveyed, the deepest first, each with its content and descriptor (the
/// inverse creates them again identically) (`suppression_dossier`).
pub fn folder_deletion(dn_text: &str, elements: &[Element]) -> Vec<Operation> {
    let mut sorted: Vec<&Element> = elements.iter().collect();
    sorted.sort_by_key(|e| std::cmp::Reverse(depth(&e.path)));
    sorted
        .into_iter()
        .map(|e| {
            if e.directory {
                Operation::DeleteFolder {
                    dn: dn_text.to_owned(),
                    path: e.path.clone(),
                    descriptor: e.descriptor.clone(),
                }
            } else {
                Operation::DeleteFile {
                    dn: dn_text.to_owned(),
                    path: e.path.clone(),
                    content: e.content.clone().unwrap_or_default(),
                    descriptor: e.descriptor.clone(),
                }
            }
        })
        .collect()
}

/// Changeset of the deletion (pure) (`supprimer`): the links first (`links`, one `Modify` of
/// `gPLink` per container), then the objects under the GPO and the GPO, then the content of
/// the folder, the deepest files and folders first. Each file goes with its content and
/// descriptor, each object with its attributes: the inverse creates the GPO again under the
/// same GUID, its filtering included (only the `objectGUID` change).
pub fn delete(
    gpo: &GpoRead,
    sub: &[(String, Read)],
    links: Vec<Operation>,
    elements: &[Element],
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    let n_links = links.len();
    let mut operations = links;
    for (dn_text, read) in sub {
        operations.push(Operation::delete(dn_text, Some(read.clone()), Vec::new())?);
    }
    operations.push(Operation::delete(
        &gpo.dn,
        Some(gpo.read.clone()),
        vec![SD.to_owned()],
    )?);
    operations.extend(folder_deletion(&gpo.dn, elements));
    let mut remarks = vec![catalog.text(&Msg::GpoDeleted {
        name: gpo.name(),
        guid: gpo.guid(),
        links: n_links,
        items: elements.len(),
    })];
    if elements.is_empty() {
        remarks.push(catalog.text(&Msg::GpoFolderAbsent));
    }
    Ok(Changeset {
        operations,
        remarks,
    })
}

// --- J5.3: links --------------------------------------------------------------------------------

/// Domain, OU or site read on the write DC (`ConteneurLu`): raw `gPLink` and `gPOptions`,
/// version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerRead {
    pub dn: String,
    pub gplink: Option<Vec<u8>>,
    pub gpoptions: Option<Vec<u8>>,
    pub read: Read,
}

impl ContainerRead {
    pub fn links(&self) -> GpLink {
        self.gplink.as_deref().map_or_else(GpLink::default, |v| {
            GpLink::decode(v).unwrap_or_else(|_| GpLink::parse(&String::from_utf8_lossy(v)))
        })
    }

    pub fn inheritance_blocked(&self) -> bool {
        self.gpoptions
            .as_deref()
            .and_then(|v| gplink::decode_gpoptions(v).ok())
            .is_some_and(gplink::inheritance_blocked)
    }

    fn from_entry(link: &Link, entry: &Entry) -> Self {
        Self {
            dn: entry.dn.clone(),
            gplink: entry.values("gPLink").first().cloned(),
            gpoptions: entry.values("gPOptions").first().cloned(),
            read: version_read(link, entry),
        }
    }
}

pub(crate) fn read_container(link: &mut Link, dn_text: &str) -> Result<ContainerRead, Step> {
    let Some(entry) = read_entry(link, dn_text, &["uSNChanged", "gPLink", "gPOptions"], None)?
    else {
        return Err(GpoError::ContainerMissing {
            dn: dn_text.to_owned(),
        }
        .into());
    };
    Ok(ContainerRead::from_entry(link, &entry))
}

/// A single value replaced (removed then added), set or cleared (`_changement`).
fn change(
    attribute: &str,
    before: Option<&[u8]>,
    after: Option<&[u8]>,
) -> Result<Option<Change>, GpoError> {
    if before == after {
        return Ok(None);
    }
    let list = |v: Option<&[u8]>| v.filter(|v| !v.is_empty()).map(|v| vec![v.to_vec()]);
    Ok(Some(Change::new(
        attribute,
        list(before).unwrap_or_default(),
        list(after).unwrap_or_default(),
    )?))
}

/// A modification of the links of a container (`lier`, `delier`, `options_lien`…).
pub type LinkChange = Box<dyn Fn(&GpLink) -> Result<GpLink, GpoError> + Send + Sync>;

/// Changeset that gives `gPLink` the value `modification(present links)` (pure)
/// (`modifier_liens`). A string without any element left clears the attribute (as
/// `samba-tool gpo dellink`).
pub fn modify_links(
    container: &ContainerRead,
    modification: &LinkChange,
) -> Result<Changeset, GpoError> {
    let new = modification(&container.links())?;
    let encoded = (!new.elements.is_empty()).then(|| new.encode());
    let Some(c) = change("gPLink", container.gplink.as_deref(), encoded.as_deref())? else {
        return Ok(Changeset::default());
    };
    Ok(Changeset {
        operations: vec![Operation::modify(
            &container.dn,
            vec![c],
            Some(container.read.clone()),
        )?],
        remarks: Vec::new(),
    })
}

/// `gPOptions` = 1 blocks the inheritance, 0 restores it (as the GPMC, which keeps the
/// attribute) (`bloquer_heritage`).
pub fn block_inheritance(container: &ContainerRead, block: bool) -> Result<Changeset, GpoError> {
    if container.inheritance_blocked() == block {
        return Ok(Changeset::default());
    }
    let present = container
        .gpoptions
        .as_deref()
        .and_then(|v| gplink::decode_gpoptions(v).ok())
        .unwrap_or(0);
    let wanted = if block {
        present | gplink::INHERITANCE_BLOCKED
    } else {
        present & !gplink::INHERITANCE_BLOCKED
    };
    let text = wanted.to_string();
    let Some(c) = change(
        "gPOptions",
        container.gpoptions.as_deref(),
        Some(text.as_bytes()),
    )?
    else {
        return Ok(Changeset::default());
    };
    Ok(Changeset {
        operations: vec![Operation::modify(
            &container.dn,
            vec![c],
            Some(container.read.clone()),
        )?],
        remarks: Vec::new(),
    })
}

/// Link the GPO to the container: one more link, at the last rank (as the GPMC). Refused if
/// it is already linked there (`lier`).
pub fn link_gpo(gpo_dn: &str, options: u64) -> LinkChange {
    let gpo_dn = gpo_dn.to_owned();
    Box::new(move |links: &GpLink| {
        if !links.find(&gpo_dn).is_empty() {
            return Err(GpoError::AlreadyLinked);
        }
        Ok(links.link(&gpo_dn, options))
    })
}

fn position(links: &GpLink, gpo_dn: &str) -> Result<usize, GpoError> {
    links
        .find(gpo_dn)
        .first()
        .copied()
        .ok_or(GpoError::NoLongerLinked)
}

/// Remove every link of the container to this GPO (`delier`).
pub fn unlink(gpo_dn: &str) -> LinkChange {
    let gpo_dn = gpo_dn.to_owned();
    Box::new(move |links: &GpLink| {
        let mut out = links.clone();
        for p in links.find(&gpo_dn).into_iter().rev() {
            out = out
                .unlink(p)
                .map_err(|e| GpoError::Invalid(e.to_string()))?;
        }
        Ok(out)
    })
}

/// Enable or disable the link, enforce it or not; None: unchanged (`options_lien`).
pub fn link_options(gpo_dn: &str, disabled: Option<bool>, enforced: Option<bool>) -> LinkChange {
    let gpo_dn = gpo_dn.to_owned();
    Box::new(move |links: &GpLink| {
        let p = position(links, &gpo_dn)?;
        let mut options = links.links().nth(p).map_or(0, |l| l.options);
        for (wanted, bit) in [(disabled, gplink::DISABLED), (enforced, gplink::ENFORCED)] {
            match wanted {
                Some(true) => options |= bit,
                Some(false) => options &= !bit,
                None => {}
            }
        }
        links
            .with_options(p, options)
            .map_err(|e| GpoError::Invalid(e.to_string()))
    })
}

/// Put the link at the order `order` of the GPMC (1 = highest precedence) (`deplacer_lien`).
fn move_to(links: &GpLink, gpo_dn: &str, order: usize) -> Result<GpLink, GpoError> {
    let p = position(links, gpo_dn)?;
    let n = links.links().count();
    if !(1..=n).contains(&order) {
        return Err(GpoError::OrderOutOfRange { order, n });
    }
    links
        .move_link(p, n - order)
        .map_err(|e| GpoError::Invalid(e.to_string()))
}

pub fn move_link(gpo_dn: &str, order: usize) -> LinkChange {
    let gpo_dn = gpo_dn.to_owned();
    Box::new(move |links: &GpLink| move_to(links, &gpo_dn, order))
}

/// One rank of precedence more (link order − 1); no effect at the first rank (`monter`).
pub fn move_up(gpo_dn: &str) -> LinkChange {
    let gpo_dn = gpo_dn.to_owned();
    Box::new(move |links: &GpLink| {
        let order = links.link_order(position(links, &gpo_dn)?);
        if order > 1 {
            move_to(links, &gpo_dn, order - 1)
        } else {
            Ok(links.clone())
        }
    })
}

/// One rank of precedence less (link order + 1); no effect at the last rank (`descendre`).
pub fn move_down(gpo_dn: &str) -> LinkChange {
    let gpo_dn = gpo_dn.to_owned();
    Box::new(move |links: &GpLink| {
        let order = links.link_order(position(links, &gpo_dn)?);
        if order < links.links().count() {
            move_to(links, &gpo_dn, order + 1)
        } else {
            Ok(links.clone())
        }
    })
}

/// Reads the container on the write DC, then returns `modify_links` (`preparer_liens`).
/// Blocking.
pub fn prepare_links(
    connection: &Connection,
    container: &str,
    modification: LinkChange,
) -> Result<Changeset, GpoError> {
    let container = container.to_owned();
    run(connection, move |link| {
        let read = read_container(link, &container)?;
        Ok(modify_links(&read, &modification)?)
    })
}

/// `preparer_heritage`. Blocking.
pub fn prepare_inheritance(
    connection: &Connection,
    container: &str,
    block: bool,
) -> Result<Changeset, GpoError> {
    let container = container.to_owned();
    run(connection, move |link| {
        let read = read_container(link, &container)?;
        Ok(block_inheritance(&read, block)?)
    })
}

// --- J5.4: deletion, read on the write DC ------------------------------------------------------

/// Domain, OUs and sites whose `gPLink` quotes this GPO (filter by substring, then the codec
/// decides: a mention outside a link does not count) (`conteneurs_lies`).
pub fn linked_containers(link: &mut Link, guid: &str) -> Result<Vec<ContainerRead>, LdapError> {
    let root = link.state.root_dse.clone();
    let guid = guid.to_uppercase();
    let filter = format!("(gPLink=*{guid}*)");
    let mut bases = vec![root.default_naming_context.clone()];
    if !root.configuration_naming_context.is_empty() {
        bases.push(format!("CN=Sites,{}", root.configuration_naming_context));
    }
    let mut found = Vec::new();
    for base in bases {
        let entries = match search(
            link,
            &base,
            Scope::Subtree,
            &filter,
            &["uSNChanged", "gPLink", "gPOptions"],
        ) {
            Err(e) if e.code == code::NO_SUCH_OBJECT => continue,
            other => other?,
        };
        for entry in entries {
            let container = ContainerRead::from_entry(link, &entry);
            if container
                .links()
                .links()
                .any(|l| l.guid().as_deref() == Some(guid.as_str()))
            {
                found.push(container);
            }
        }
    }
    Ok(found)
}

fn without_link(container: &ContainerRead, guid: &str) -> Result<Option<Operation>, GpoError> {
    let guid = guid.to_uppercase();
    let modification: LinkChange = Box::new(move |links: &GpLink| {
        let mut out = links.clone();
        let positions: Vec<usize> = links
            .links()
            .enumerate()
            .filter(|(_, l)| l.guid().as_deref() == Some(guid.as_str()))
            .map(|(i, _)| i)
            .collect();
        for p in positions.into_iter().rev() {
            out = out
                .unlink(p)
                .map_err(|e| GpoError::Invalid(e.to_string()))?;
        }
        Ok(out)
    });
    Ok(modify_links(container, &modification)?
        .operations
        .into_iter()
        .next())
}

/// Reads the GPO, its objects, the containers that link it and its whole folder (contents and
/// descriptors) on the write DC, then returns `delete` (`preparer_suppression`). Blocking.
pub fn prepare_deletion(
    connection: &Connection,
    dn_text: &str,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    let dn_text = dn_text.to_owned();
    on_dc(connection, move |link, session| {
        let gpo = read_gpo(link, &dn_text)?;
        let mut links = Vec::new();
        for container in linked_containers(link, &gpo.guid())? {
            if let Some(op) = without_link(&container, &gpo.guid())? {
                links.push(op);
            }
        }
        let sub = sub_objects(link, &gpo.dn)?;
        let found = elements(session, &gpo.folder, true)?;
        Ok(delete(&gpo, &sub, links, &found, catalog.as_ref())?)
    })
}

// --- SYSVOL folders without a GPO, all together ---------------------------------------------------

/// GUIDs (upper case) the GPOs of the directory designate, read on the write DC in the whole
/// domain: their `cn` and the last element of their `gPCFileSysPath` (`guids_gpo`).
fn gpo_guids(link: &mut Link) -> Result<HashSet<String>, LdapError> {
    let base = link.state.root_dse.default_naming_context.clone();
    let filter = format!("(objectClass={GPO_CLASS})");
    let entries = search(link, &base, Scope::Subtree, &filter, &["gPCFileSysPath"])?;
    let mut guids: HashSet<String> = entries.iter().map(|e| guid_of(&e.dn)).collect();
    for e in &entries {
        for value in e.values("gPCFileSysPath") {
            let text = String::from_utf8_lossy(value).replace('/', "\\");
            let name = file_name(&text);
            if gpo::is_folder_guid(name) {
                guids.insert(name.to_uppercase());
            }
        }
    }
    Ok(guids)
}

/// Changeset that removes `{GUID}` folders of the SYSVOL without an object in the directory
/// (pure) (`retirer_orphelins`): files and folders from the deepest to the folder itself,
/// content and ACL kept for the inverse. `dn` of the operations: the one the GPO would have.
pub fn remove_orphans(base: &str, folders: &[Vec<Element>], catalog: &dyn Catalog) -> Changeset {
    let mut operations = Vec::new();
    let mut names = Vec::new();
    for found in folders {
        let Some(root) = found.iter().min_by_key(|e| depth(&e.path)) else {
            continue;
        };
        let guid = file_name(&root.path).to_uppercase();
        operations.extend(folder_deletion(&gpo_dn(base, &guid), found));
        names.push(guid);
    }
    if operations.is_empty() {
        return Changeset::default();
    }
    Changeset {
        operations,
        remarks: vec![catalog.text(&Msg::GpoOrphansRemoved {
            list: names.join(", "),
        })],
    }
}

/// Reads the GPOs of the directory and the `Policies` folder of the SYSVOL of the PDC
/// emulator, then returns `remove_orphans` for the `{GUID}` folders no GPO designates
/// (`preparer_retrait_orphelins`). Blocking.
pub fn prepare_orphans_removal(
    connection: &Connection,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    on_dc(connection, move |link, session| {
        let base = link.state.root_dse.default_naming_context.clone();
        let known = gpo_guids(link)?;
        let policies = sysvol::join(&[&domain_dns(&base), "Policies"]);
        let client = session.client()?;
        let orphans: Vec<String> = client
            .list(&policies)?
            .into_iter()
            .filter(|c| {
                let name = file_name(c);
                gpo::is_folder_guid(name) && !known.contains(&name.to_uppercase())
            })
            .collect();
        let mut folders = Vec::new();
        for c in orphans {
            folders.push(client.survey(&c, true, true)?);
        }
        Ok(remove_orphans(&base, &folders, catalog.as_ref()))
    })
}

// --- One folder of the SYSVOL without a GPO (orphan), chosen in the window --------------------------

/// DNs of the GPO objects that carry this GUID, by their name (`cn`) or their path
/// (`gPCFileSysPath`), in the whole domain: a folder is an orphan only if the list is empty
/// (`gpos_du_guid`).
fn gpos_of_guid(link: &mut Link, guid: &str) -> Result<Vec<String>, LdapError> {
    let base = link.state.root_dse.default_naming_context.clone();
    let escaped = search::escape_filter(guid);
    let filter =
        format!("(&(objectClass={GPO_CLASS})(|(cn={escaped})(gPCFileSysPath=*{escaped}*)))");
    Ok(search(link, &base, Scope::Subtree, &filter, &["1.1"])?
        .into_iter()
        .map(|e| e.dn)
        .collect())
}

/// Changeset of the deletion of an orphan folder (pure) (`supprimer_orphelin`): all its
/// content then itself, each element with its content and descriptor, as the SYSVOL half of
/// `delete`. The operations carry the DN the GPO would have (the preview files them under it).
pub fn delete_orphan(
    base: &str,
    name: &str,
    elements: &[Element],
    dc: &str,
    links: usize,
    catalog: &dyn Catalog,
) -> Result<Changeset, GpoError> {
    if elements.is_empty() {
        return Err(GpoError::OrphanGone {
            name: name.to_owned(),
            dc: dc.to_owned(),
        });
    }
    let mut remarks = vec![catalog.text(&Msg::GpoOrphanDeleted {
        name: name.to_owned(),
        dc: dc.to_owned(),
        items: elements.len(),
    })];
    if links > 0 {
        remarks.push(catalog.text(&Msg::GpoOrphanLinks { n: links }));
    }
    Ok(Changeset {
        operations: folder_deletion(&gpo_dn(base, name), elements),
        remarks,
    })
}

/// Reads again on the write DC that no GPO object carries the GUID of the folder `name` (its
/// written name, `{GUID}`), surveys the folder in the SYSVOL of the same DC, then returns
/// `delete_orphan` (`preparer_suppression_orphelin`). Blocking.
pub fn prepare_orphan_deletion(
    connection: &Connection,
    name: &str,
    catalog: std::sync::Arc<dyn Catalog + Send + Sync>,
) -> Result<Changeset, GpoError> {
    if !gpo::is_folder_guid(name) {
        return Err(GpoError::InvalidFolderName {
            name: name.to_owned(),
        });
    }
    let name = name.to_owned();
    on_dc(connection, move |link, session| {
        let guid = name.to_uppercase();
        if let Some(dn_text) = gpos_of_guid(link, &guid)?.into_iter().next() {
            return Err(GpoError::NotOrphan {
                name: name.clone(),
                dn: dn_text,
            }
            .into());
        }
        let base = link.state.root_dse.default_naming_context.clone();
        let folder = sysvol::join(&[&domain_dns(&base), "Policies", &name]);
        let links = linked_containers(link, &guid)?.len();
        let found = elements(session, &folder, true)?;
        let dc = link.state.dc.clone();
        Ok(delete_orphan(
            &base,
            &name,
            &found,
            &dc,
            links,
            catalog.as_ref(),
        )?)
    })
}

#[cfg(test)]
mod tests;

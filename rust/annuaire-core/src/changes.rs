// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Changesets: the model of the writes to the directory (plan, 0.1; ADR 0006).
//!
//! Port of `annuaire/core/changes.py`: operations, their preview (secrets hidden), their
//! inverse and the journaled form. A modification never uses "replace": it removes the
//! values read and adds the new ones in the same request, so that the server itself refuses
//! a value to remove that is gone or a value to add that is already there.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use annuaire_codecs::dns_record::{self, Record};
use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::registry_pol::{self, RegValue};
use annuaire_codecs::sd::SecurityDescriptor;
use annuaire_codecs::uac::UserAccountControl;
use annuaire_codecs::{Guid, Sid, sddl, time};
use serde_json::{Map, Value, json};

use crate::dn::{self, Component, DnError};
use crate::messages::{Catalog, Msg};
pub use crate::propagation::Direction;
use crate::search::{FilterError, verify_attribute};

pub const JOURNAL_VERSION: i64 = 1;
/// Value of a secret read back from the journal (data, not a message).
pub const MASKED_VALUE: &str = "<masqué>";

/// Secrets: values never shown nor journaled, so never restored by an inverse.
pub const SENSITIVE: [&str; 21] = [
    "unicodepwd",
    "userpassword",
    "cleartextpassword",
    "dbcspwd",
    "lmpwdhistory",
    "ntpwdhistory",
    "supplementalcredentials",
    "currentvalue",
    "priorvalue",
    "trustauthincoming",
    "trustauthoutgoing",
    "initialauthincoming",
    "initialauthoutgoing",
    "msds-managedpassword",
    "ms-mcs-admpwd",
    "mslaps-password",
    "mslaps-encryptedpassword",
    "mslaps-encryptedpasswordhistory",
    "mslaps-encrypteddsrmpassword",
    "msfve-recoverypassword",
    "msfve-keypackage",
];

/// Attributes kept by the DC (identity, replication, back links, logon state): never copied
/// when a deleted object is recreated, ignored when comparing an object before and after.
pub const SYSTEM: [&str; 30] = [
    "objectguid",
    "objectsid",
    "distinguishedname",
    "name",
    "instancetype",
    "objectcategory",
    "ntsecuritydescriptor",
    "whencreated",
    "whenchanged",
    "usncreated",
    "usnchanged",
    "dscorepropagationdata",
    "replpropertymetadata",
    "iscriticalsystemobject",
    "systemflags",
    "isdeleted",
    "isrecycled",
    "lastknownparent",
    "msds-lastknownrdn",
    "memberof",
    "samaccounttype",
    "primarygroupid",
    "pwdlastset",
    "badpwdcount",
    "badpasswordtime",
    "lastlogon",
    "lastlogoff",
    "lastlogontimestamp",
    "logoncount",
    "lockouttime",
];

/// Large integers that are FILETIME dates (`syntaxes.ATTRIBUTS_DATE`).
pub const DATE_ATTRIBUTES: [&str; 13] = [
    "accountexpires",
    "pwdlastset",
    "lastlogon",
    "lastlogontimestamp",
    "lastlogoff",
    "badpasswordtime",
    "lockouttime",
    "msds-lastsuccessfulinteractivelogontime",
    "msds-lastfailedinteractivelogontime",
    "msds-userpasswordexpirytimecomputed",
    "creationtime",
    "msds-cached-membership-time-stamp",
    "dscorepropagationdata",
];

pub fn is_sensitive(attribute: &str) -> bool {
    SENSITIVE.contains(&attribute.to_lowercase().as_str())
}

pub type Values = Vec<Vec<u8>>;
/// Attributes in their order, as a Python dict keeps them.
pub type AttributeMap = Vec<(String, Values)>;

/// Why an operation, a changeset or a journaled form is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeError {
    Filter(FilterError),
    Dn(DnError),
    EmptyDn,
    EmptyChange(String),
    Duplicate(String),
    RemovedAndAdded(String),
    AddWithoutAttributes,
    MissingValues(String),
    ModifyWithoutChange,
    RenameWithoutEffect,
    /// A value that the preview cannot show (tombstone after the year 9999…).
    Unshowable(String),
    /// The journaled form cannot be read.
    Journal(String),
    /// No continuation after a failure, a rollback or a doubtful operation.
    NoContinuation,
}

impl fmt::Display for ChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filter(e) => e.fmt(f),
            Self::Dn(e) => e.fmt(f),
            Self::EmptyDn => f.write_str("empty DN"),
            Self::EmptyChange(a) => write!(f, "empty change on {a}"),
            Self::Duplicate(a) => write!(f, "duplicate value on {a}"),
            Self::RemovedAndAdded(a) => write!(f, "value both removed and added on {a}"),
            Self::AddWithoutAttributes => f.write_str("creation without attribute"),
            Self::MissingValues(a) => write!(f, "missing or non-binary values for {a}"),
            Self::ModifyWithoutChange => f.write_str("modification without change"),
            Self::RenameWithoutEffect => f.write_str("rename without effect"),
            Self::Unshowable(e) => write!(f, "value not shown: {e}"),
            Self::Journal(e) => write!(f, "journaled form: {e}"),
            Self::NoContinuation => {
                f.write_str("no continuation: failure, rollback or doubtful operation")
            }
        }
    }
}

impl std::error::Error for ChangeError {}

impl From<DnError> for ChangeError {
    fn from(e: DnError) -> Self {
        Self::Dn(e)
    }
}

impl From<FilterError> for ChangeError {
    fn from(e: FilterError) -> Self {
        Self::Filter(e)
    }
}

/// Comparable form of a DN.
pub fn dn_key(dn: &str) -> Result<String, ChangeError> {
    Ok(dn::key(dn)?)
}

pub fn parent_dn(dn: &str) -> Result<String, ChangeError> {
    Ok(dn::parent(dn)?)
}

fn check_dn(dn: &str) -> Result<(), ChangeError> {
    if dn::split(dn)?.is_empty() {
        return Err(ChangeError::EmptyDn);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Operations

/// Version of an object read before the preview: `uSNChanged` on a given DC.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Read {
    pub dc: String,
    pub usn: i64,
}

/// Change of one attribute: values to remove, values to add.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub attribute: String,
    pub removed: Values,
    pub added: Values,
}

impl Change {
    /// Checked as `Changement.__post_init__`.
    pub fn new(attribute: &str, removed: Values, added: Values) -> Result<Self, ChangeError> {
        verify_attribute(attribute)?;
        if removed.is_empty() && added.is_empty() {
            return Err(ChangeError::EmptyChange(attribute.into()));
        }
        if !is_sensitive(attribute) {
            for values in [&removed, &added] {
                let mut sorted: Vec<&Vec<u8>> = values.iter().collect();
                sorted.sort();
                sorted.dedup();
                if sorted.len() != values.len() {
                    return Err(ChangeError::Duplicate(attribute.into()));
                }
            }
            if removed.iter().any(|v| added.contains(v)) {
                return Err(ChangeError::RemovedAndAdded(attribute.into()));
            }
        }
        Ok(Self {
            attribute: attribute.into(),
            removed,
            added,
        })
    }

    pub fn inverse(&self) -> Self {
        Self {
            attribute: self.attribute.clone(),
            removed: self.added.clone(),
            added: self.removed.clone(),
        }
    }

    /// Adding a class: placed before the attributes it allows (ADR 0006, 5.2).
    pub fn adds_class(&self) -> bool {
        self.attribute.eq_ignore_ascii_case("objectclass") && !self.added.is_empty()
    }
}

/// A share of a file server as a changeset writes it (ADR 0023 § 3): `SHARE_INFO_502` and
/// the flags of `SHARE_INFO_1005`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareSpec {
    pub name: String,
    /// Local path on the server, as the server gives it (`C:\Partages\Commun`).
    pub path: String,
    pub remark: String,
    /// Maximum connections; `u32::MAX` for no limit.
    pub max_uses: u32,
    /// Self-relative descriptor of the share; absent: the default of the server.
    pub descriptor: Option<Vec<u8>>,
    pub flags: u32,
    /// The values of the key of the share in the registry configuration of Samba
    /// (`HKLM\Software\Samba\smbconf\<share>`, ADR 0023 § 9), as read before the operation,
    /// in their order; `None` for a share that has no key (Windows, smb.conf). The fields above
    /// say what the parameters Calinda changes become; the others are only put back by the
    /// undo of a deletion.
    pub registry: Option<Vec<(String, String)>>,
}

/// An operation of a changeset: four on LDAP, five on the SYSVOL (ADR 0012), four on the
/// shares of a file server (ADR 0023).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operation {
    Add {
        dn: String,
        attributes: AttributeMap,
    },
    Modify {
        dn: String,
        changes: Vec<Change>,
        read: Option<Read>,
    },
    Rename {
        dn: String,
        rdn: Component,
        parent: Option<String>,
        read: Option<Read>,
    },
    Delete {
        dn: String,
        read: Option<Read>,
        guards: Vec<String>,
    },
    CreateFolder {
        dn: String,
        path: String,
        descriptor: Option<Vec<u8>>,
    },
    DeleteFolder {
        dn: String,
        path: String,
        descriptor: Option<Vec<u8>>,
    },
    WriteFile {
        dn: String,
        path: String,
        content: Vec<u8>,
        old: Option<Vec<u8>>,
        descriptor: Option<Vec<u8>>,
    },
    DeleteFile {
        dn: String,
        path: String,
        content: Vec<u8>,
        descriptor: Option<Vec<u8>>,
    },
    SetDescriptor {
        dn: String,
        path: String,
        before: Vec<u8>,
        after: Vec<u8>,
    },
    /// `unc`: `\\server\share`, what the preview and the journal name.
    AddShare {
        unc: String,
        server: String,
        share: ShareSpec,
    },
    ChangeShare {
        unc: String,
        server: String,
        before: ShareSpec,
        after: ShareSpec,
    },
    DeleteShare {
        unc: String,
        server: String,
        share: ShareSpec,
    },
    /// NTFS descriptor of a file or folder of a share; `path` relative to the share, empty for
    /// its root. `unc`: `\\server\share\path`.
    SetFileDescriptor {
        unc: String,
        server: String,
        share: String,
        path: String,
        before: Vec<u8>,
        after: Vec<u8>,
    },
    /// Inheritance propagated under the folder `path` of a share (ADR 0023 § 5): its
    /// descendants recomputed (`Compute`), or their descriptors written back from the backup
    /// `backup` (`Undo`, `Redo`). One operation for the whole tree: what each element had and
    /// got is in the backup, not in the journal. `count`: elements counted under the folder
    /// before the confirmation. `parts`: the DACL recomputed, the owner replaced (J8.7).
    PropagateInheritance {
        unc: String,
        server: String,
        share: String,
        path: String,
        replace: bool,
        parts: crate::propagation::Parts,
        backup: String,
        direction: Direction,
        count: usize,
    },
}

/// `\\server\share`, then the path in the share if any.
pub fn unc(server: &str, share: &str, path: &str) -> String {
    let mut text = format!("\\\\{server}\\{share}");
    if !path.is_empty() {
        text.push('\\');
        text.push_str(path);
    }
    text
}

impl Operation {
    pub fn add_share(server: &str, share: ShareSpec) -> Self {
        Self::AddShare {
            unc: unc(server, &share.name, ""),
            server: server.into(),
            share,
        }
    }

    /// `after` keeps the registry values read with `before`: they are what the change starts
    /// from, and what its undo goes back to.
    pub fn change_share(server: &str, before: ShareSpec, mut after: ShareSpec) -> Self {
        after.registry.clone_from(&before.registry);
        Self::ChangeShare {
            unc: unc(server, &after.name, ""),
            server: server.into(),
            before,
            after,
        }
    }

    pub fn delete_share(server: &str, share: ShareSpec) -> Self {
        Self::DeleteShare {
            unc: unc(server, &share.name, ""),
            server: server.into(),
            share,
        }
    }

    pub fn set_file_descriptor(
        server: &str,
        share: &str,
        path: &str,
        before: Vec<u8>,
        after: Vec<u8>,
    ) -> Self {
        Self::SetFileDescriptor {
            unc: unc(server, share, path),
            server: server.into(),
            share: share.into(),
            path: path.into(),
            before,
            after,
        }
    }

    /// Inheritance propagated under `path` (`Direction::Compute`), saved in the backup
    /// `backup` (`propagation::backup_path`).
    pub fn propagate_inheritance(
        server: &str,
        share: &str,
        path: &str,
        replace: bool,
        backup: &str,
        count: usize,
    ) -> Self {
        Self::propagate_parts(
            server,
            share,
            path,
            replace,
            crate::propagation::Parts::default(),
            backup,
            count,
        )
    }

    /// A propagation of `parts` under `path` (J8.7: the owner, with or without the DACL).
    pub fn propagate_parts(
        server: &str,
        share: &str,
        path: &str,
        replace: bool,
        parts: crate::propagation::Parts,
        backup: &str,
        count: usize,
    ) -> Self {
        Self::PropagateInheritance {
            unc: unc(server, share, path),
            server: server.into(),
            share: share.into(),
            path: path.into(),
            replace,
            parts,
            backup: backup.into(),
            direction: Direction::Compute,
            count,
        }
    }

    /// An operation on a file server, not on the domain (ADR 0023).
    pub fn is_file_share(&self) -> bool {
        matches!(
            self,
            Self::AddShare { .. }
                | Self::ChangeShare { .. }
                | Self::DeleteShare { .. }
                | Self::SetFileDescriptor { .. }
                | Self::PropagateInheritance { .. }
        )
    }

    /// An operation on the directory: neither the SYSVOL nor a file server.
    pub fn is_ldap(&self) -> bool {
        !self.is_sysvol() && !self.is_file_share()
    }

    /// The file server of an operation on shares.
    pub fn server(&self) -> Option<&str> {
        match self {
            Self::AddShare { server, .. }
            | Self::ChangeShare { server, .. }
            | Self::DeleteShare { server, .. }
            | Self::SetFileDescriptor { server, .. }
            | Self::PropagateInheritance { server, .. } => Some(server),
            _ => None,
        }
    }

    pub fn add(dn: &str, attributes: AttributeMap) -> Result<Self, ChangeError> {
        check_dn(dn)?;
        if attributes.is_empty() {
            return Err(ChangeError::AddWithoutAttributes);
        }
        for (attribute, values) in &attributes {
            verify_attribute(attribute)?;
            if values.is_empty() {
                return Err(ChangeError::MissingValues(attribute.clone()));
            }
        }
        Ok(Self::Add {
            dn: dn.into(),
            attributes,
        })
    }

    pub fn modify(dn: &str, changes: Vec<Change>, read: Option<Read>) -> Result<Self, ChangeError> {
        check_dn(dn)?;
        if changes.is_empty() {
            return Err(ChangeError::ModifyWithoutChange);
        }
        Ok(Self::Modify {
            dn: dn.into(),
            changes,
            read,
        })
    }

    pub fn rename(
        dn: &str,
        rdn: Component,
        parent: Option<String>,
        read: Option<Read>,
    ) -> Result<Self, ChangeError> {
        check_dn(dn)?;
        dn::compose(std::slice::from_ref(&rdn))?;
        if let Some(p) = &parent {
            check_dn(p)?;
        }
        let op = Self::Rename {
            dn: dn.into(),
            rdn,
            parent,
            read,
        };
        if dn_key(&op.dn_after()?)? == dn_key(dn)? {
            return Err(ChangeError::RenameWithoutEffect);
        }
        Ok(op)
    }

    pub fn delete(dn: &str, read: Option<Read>, guards: Vec<String>) -> Result<Self, ChangeError> {
        check_dn(dn)?;
        for guard in &guards {
            verify_attribute(guard)?;
        }
        Ok(Self::Delete {
            dn: dn.into(),
            read,
            guards,
        })
    }

    pub fn dn(&self) -> &str {
        match self {
            Self::Add { dn, .. }
            | Self::Modify { dn, .. }
            | Self::Rename { dn, .. }
            | Self::Delete { dn, .. }
            | Self::CreateFolder { dn, .. }
            | Self::DeleteFolder { dn, .. }
            | Self::WriteFile { dn, .. }
            | Self::DeleteFile { dn, .. }
            | Self::SetDescriptor { dn, .. } => dn,
            // Not a DN: what names the share or the file, as the preview shows it.
            Self::AddShare { unc, .. }
            | Self::ChangeShare { unc, .. }
            | Self::DeleteShare { unc, .. }
            | Self::SetFileDescriptor { unc, .. }
            | Self::PropagateInheritance { unc, .. } => unc,
        }
    }

    pub fn is_sysvol(&self) -> bool {
        matches!(
            self,
            Self::CreateFolder { .. }
                | Self::DeleteFolder { .. }
                | Self::WriteFile { .. }
                | Self::DeleteFile { .. }
                | Self::SetDescriptor { .. }
        )
    }

    /// Path relative to the SYSVOL share, for a SYSVOL operation.
    pub fn path(&self) -> Option<&str> {
        match self {
            Self::CreateFolder { path, .. }
            | Self::DeleteFolder { path, .. }
            | Self::WriteFile { path, .. }
            | Self::DeleteFile { path, .. }
            | Self::SetDescriptor { path, .. } => Some(path),
            _ => None,
        }
    }

    /// DN after a rename (`Renommer.nouveau_dn`), the DN otherwise.
    pub fn dn_after(&self) -> Result<String, ChangeError> {
        match self {
            Self::Rename {
                dn, rdn, parent, ..
            } => {
                let parent = match parent {
                    Some(p) => p.clone(),
                    None => parent_dn(dn)?,
                };
                let rdn = dn::compose(std::slice::from_ref(rdn))?;
                Ok(if parent.is_empty() {
                    rdn
                } else {
                    format!("{rdn},{parent}")
                })
            }
            other => Ok(other.dn().to_owned()),
        }
    }

    fn read(&self) -> Option<&Read> {
        match self {
            Self::Modify { read, .. } | Self::Rename { read, .. } | Self::Delete { read, .. } => {
                read.as_ref()
            }
            _ => None,
        }
    }

    fn with_read(&self, new: Option<Read>) -> Self {
        let mut op = self.clone();
        if let Self::Modify { read, .. } | Self::Rename { read, .. } | Self::Delete { read, .. } =
            &mut op
        {
            *read = new;
        }
        op
    }
}

/// An ordered sequence of operations, with what the preview must say besides.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Changeset {
    pub operations: Vec<Operation>,
    pub remarks: Vec<String>,
}

impl Changeset {
    pub fn touches_sysvol(&self) -> bool {
        self.operations.iter().any(Operation::is_sysvol)
    }

    pub fn touches_shares(&self) -> bool {
        self.operations.iter().any(Operation::is_file_share)
    }
}

// ---------------------------------------------------------------------------
// Preview

/// The value as text, if it is UTF-8 without control character (but tab, LF, CR).
pub fn text_value(value: &[u8]) -> Option<&str> {
    let text = std::str::from_utf8(value).ok()?;
    let control =
        |c: char| ((c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r')) || c as u32 == 0x7F;
    (!text.chars().any(control)).then_some(text)
}

fn date_text(text: &str, catalog: &dyn Catalog) -> Result<String, ChangeError> {
    // `int()` of Python: optional sign, ASCII digits, surrounding spaces allowed.
    let Ok(n) = text.trim().parse::<i128>() else {
        return Ok(String::new());
    };
    if n == 0 || n == i128::from(time::NTTIME_NEVER) {
        return Ok(catalog.text(&Msg::Never));
    }
    if n < 0 {
        return Ok(String::new());
    }
    let n = i64::try_from(n).map_err(|_| ChangeError::Unshowable(text.into()))?;
    let date = time::nttime_to_utc(n).map_err(|e| ChangeError::Unshowable(e.to_string()))?;
    Ok(date.map_or_else(String::new, |d| {
        let c = d.civil();
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02} UTC",
            c.year, c.month, c.day, c.hour, c.minute
        )
    }))
}

/// `dnsRecord` in clear (`A 192.0.2.10 (TTL 900, serial 58)`); None if its header is
/// unreadable.
pub fn dns_record_text(value: &[u8], catalog: &dyn Catalog) -> Result<Option<String>, ChangeError> {
    let Ok(record) = Record::decode(value) else {
        return Ok(None);
    };
    let mut details = vec![
        catalog.text(&Msg::Ttl { ttl: record.ttl }),
        catalog.text(&Msg::Serial {
            serial: record.serial,
        }),
    ];
    if record.rank != dns_record::RANK_ZONE {
        details.push(catalog.text(&Msg::Rank {
            rank: record.rank_name(),
        }));
    }
    if !record.is_static() {
        details.push(catalog.text(&Msg::Dynamic));
    }
    let data = record
        .data_text()
        .map_err(|e| ChangeError::Unshowable(e.to_string()))?;
    Ok(Some(format!(
        "{} {data} ({})",
        record.type_name(),
        details.join(", ")
    )))
}

/// Descriptor as SDDL (Samba's form), or hexadecimal if unreadable. The domain is taken
/// from the owner or the group: `DA` rather than `S-1-5-21-…-512`.
pub fn descriptor_text(value: &[u8], catalog: &dyn Catalog) -> Result<String, ChangeError> {
    let Ok(sd) = SecurityDescriptor::decode(value) else {
        return show_value("", value, catalog);
    };
    let domain = [sd.owner, sd.group]
        .into_iter()
        .flatten()
        .find(Sid::is_domain_sid)
        .and_then(|s| s.domain().ok());
    sddl::sd_to_sddl(&sd, domain.as_ref()).map_err(|e| ChangeError::Unshowable(e.to_string()))
}

/// Readable form of a value for the preview; hidden for a secret.
pub fn show_value(
    attribute: &str,
    value: &[u8],
    catalog: &dyn Catalog,
) -> Result<String, ChangeError> {
    if is_sensitive(attribute) {
        return Ok(catalog.text(&Msg::Masked));
    }
    let lower = attribute.to_lowercase();
    if lower == "dnsrecord" {
        if let Some(text) = dns_record_text(value, catalog)? {
            return Ok(text);
        }
    }
    if lower == "ntsecuritydescriptor" {
        return descriptor_text(value, catalog);
    }
    if lower == "objectsid" {
        if let Ok(sid) = Sid::decode(value) {
            return Ok(sid.to_string());
        }
    }
    if lower == "objectguid" {
        if let Ok(guid) = Guid::decode(value) {
            return Ok(guid.to_string());
        }
    }
    let text = text_value(value);
    if let Some(text) = text {
        if DATE_ATTRIBUTES.contains(&lower.as_str()) {
            let date = date_text(text, catalog)?;
            if !date.is_empty() {
                return Ok(catalog.text(&Msg::QuotedWithDate {
                    text: text.into(),
                    date,
                }));
            }
        }
        let escaped = text
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t");
        return Ok(catalog.text(&Msg::Quoted { text: escaped }));
    }
    let start: String = value.iter().take(32).map(|b| format!("{b:02x}")).collect();
    let more = if value.len() > 32 { "…" } else { "" };
    Ok(catalog.text(&Msg::Hex {
        bytes: start,
        more: more.into(),
        n: value.len(),
    }))
}

/// Content of a file for the preview: the text if short, its size otherwise.
pub fn content_text(content: &[u8], catalog: &dyn Catalog) -> String {
    let mut text = text_value(content).map(str::to_owned);
    if text.is_none() && (content.starts_with(b"\xff\xfe") || content.starts_with(b"\xfe\xff")) {
        text = decode_utf16_bom(content);
    }
    match text {
        Some(t) if t.chars().count() <= 200 => catalog.text(&Msg::Quoted {
            text: t.replace('\r', "").replace('\n', "\\n"),
        }),
        _ => catalog.text(&Msg::Bytes { n: content.len() }),
    }
}

/// `bytes.decode("utf-16")` of Python: BOM read, then strict decoding.
fn decode_utf16_bom(content: &[u8]) -> Option<String> {
    let (big, rest) = match content {
        [0xFF, 0xFE, rest @ ..] => (false, rest),
        [0xFE, 0xFF, rest @ ..] => (true, rest),
        _ => return None,
    };
    if rest.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = rest
        .chunks_exact(2)
        .map(|p| match p {
            [a, b] if big => u16::from_be_bytes([*a, *b]),
            [a, b] => u16::from_le_bytes([*a, *b]),
            _ => 0,
        })
        .collect();
    String::from_utf16(&units).ok()
}

fn registry_entry_text(e: &registry_pol::Entry) -> String {
    let shown = match e.interpret() {
        Ok(RegValue::Integer(n)) => n.to_string(),
        Ok(RegValue::Text(t)) => t,
        Ok(RegValue::Texts(t)) => t.join("; "),
        Ok(RegValue::Bytes(b)) => b.iter().map(|x| format!("{x:02x}")).collect(),
        Err(_) => e.data.iter().map(|x| format!("{x:02x}")).collect(),
    };
    format!("[{}] {} = {shown} ({})", e.key, e.value_name, e.type_name())
}

/// Entries of a `Registry.pol` removed (−) and added (+); None if unreadable.
pub fn registry_lines(old: Option<&[u8]>, new: Option<&[u8]>) -> Option<Vec<String>> {
    let read = |bytes: Option<&[u8]>| match bytes {
        Some(b) if !b.is_empty() => registry_pol::read(b).ok(),
        _ => Some(Vec::new()),
    };
    let (before, after) = (read(old)?, read(new)?);
    let mut lines: Vec<String> = before
        .iter()
        .filter(|e| !after.contains(e))
        .map(|e| format!("− {}", registry_entry_text(e)))
        .collect();
    lines.extend(
        after
            .iter()
            .filter(|e| !before.contains(e))
            .map(|e| format!("+ {}", registry_entry_text(e))),
    );
    Some(lines)
}

pub fn is_registry_pol(path: &str) -> bool {
    path.rsplit('\\')
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case("registry.pol"))
}

pub fn sysvol_path(path: &str) -> String {
    format!("SYSVOL\\{path}")
}

fn change_lines(c: &Change, catalog: &dyn Catalog) -> Result<Vec<String>, ChangeError> {
    let show = |v: &Vec<u8>| show_value(&c.attribute, v, catalog);
    if let ([before], [after]) = (c.removed.as_slice(), c.added.as_slice()) {
        return Ok(vec![catalog.text(&Msg::Replace {
            attribute: c.attribute.clone(),
            before: show(before)?,
            after: show(after)?,
        })]);
    }
    let mut lines = Vec::new();
    for v in &c.removed {
        lines.push(catalog.text(&Msg::Removed {
            attribute: c.attribute.clone(),
            value: show(v)?,
        }));
    }
    for v in &c.added {
        lines.push(catalog.text(&Msg::Added {
            attribute: c.attribute.clone(),
            value: show(v)?,
        }));
    }
    Ok(lines)
}

fn file_details(path: &str, old: Option<&[u8]>, new: Option<&[u8]>) -> Option<Vec<String>> {
    if !is_registry_pol(path) {
        return None;
    }
    registry_lines(old, new)
}

fn sysvol_lines(
    op: &Operation,
    catalog: &dyn Catalog,
) -> Result<(String, Vec<String>), ChangeError> {
    let path = sysvol_path(op.path().unwrap_or_default());
    Ok(match op {
        Operation::CreateFolder { descriptor, .. } => (
            catalog.text(&Msg::CreateFolder { path }),
            match descriptor {
                Some(d) => vec![descriptor_text(d, catalog)?],
                None => Vec::new(),
            },
        ),
        Operation::DeleteFolder { .. } => (catalog.text(&Msg::DeleteFolder { path }), Vec::new()),
        Operation::WriteFile {
            path: p,
            content,
            old: None,
            descriptor,
            ..
        } => {
            let mut details = file_details(p, None, Some(content))
                .unwrap_or_else(|| vec![content_text(content, catalog)]);
            if let Some(d) = descriptor {
                details.push(descriptor_text(d, catalog)?);
            }
            (catalog.text(&Msg::CreateFile { path }), details)
        }
        Operation::WriteFile {
            path: p,
            content,
            old: Some(old),
            ..
        } => {
            let details = file_details(p, Some(old), Some(content)).unwrap_or_else(|| {
                vec![format!(
                    "{} → {}",
                    content_text(old, catalog),
                    content_text(content, catalog)
                )]
            });
            (catalog.text(&Msg::ReplaceFile { path }), details)
        }
        Operation::DeleteFile {
            path: p, content, ..
        } => {
            let details = file_details(p, Some(content), None)
                .unwrap_or_else(|| vec![content_text(content, catalog)]);
            (catalog.text(&Msg::DeleteFile { path }), details)
        }
        Operation::SetDescriptor { before, after, .. } => (
            catalog.text(&Msg::SetPermissions { path }),
            vec![
                format!("− {}", descriptor_text(before, catalog)?),
                format!("+ {}", descriptor_text(after, catalog)?),
            ],
        ),
        _ => unreachable!("LDAP operations are handled by operation_lines"),
    })
}

fn share_spec_lines(share: &ShareSpec, catalog: &dyn Catalog) -> Result<Vec<String>, ChangeError> {
    let mut lines = vec![
        catalog.text(&Msg::SharePath {
            path: share.path.clone(),
        }),
        catalog.text(&Msg::ShareRemark {
            remark: share.remark.clone(),
        }),
    ];
    if share.max_uses != u32::MAX {
        lines.push(catalog.text(&Msg::ShareMaxUses { n: share.max_uses }));
    }
    if share.flags != 0 {
        lines.push(catalog.text(&Msg::ShareFlags { flags: share.flags }));
    }
    if let Some(d) = &share.descriptor {
        lines.push(descriptor_text(d, catalog)?);
    }
    Ok(lines)
}

fn share_lines(
    op: &Operation,
    catalog: &dyn Catalog,
) -> Result<(String, Vec<String>), ChangeError> {
    let target = op.dn().to_owned();
    Ok(match op {
        Operation::AddShare { share, .. } => (
            catalog.text(&Msg::AddShare { unc: target }),
            share_spec_lines(share, catalog)?,
        ),
        Operation::DeleteShare { share, .. } => {
            let mut details = vec![catalog.text(&Msg::DeleteShareKeepsFolder)];
            details.extend(share_spec_lines(share, catalog)?);
            (catalog.text(&Msg::DeleteShare { unc: target }), details)
        }
        Operation::ChangeShare { before, after, .. } => {
            let old = share_spec_lines(before, catalog)?;
            let new = share_spec_lines(after, catalog)?;
            let mut details: Vec<String> = old
                .iter()
                .filter(|l| !new.contains(l))
                .map(|l| format!("− {l}"))
                .collect();
            details.extend(
                new.iter()
                    .filter(|l| !old.contains(l))
                    .map(|l| format!("+ {l}")),
            );
            (catalog.text(&Msg::ChangeShare { unc: target }), details)
        }
        Operation::SetFileDescriptor { before, after, .. } => (
            catalog.text(&Msg::SetPermissions { path: target }),
            vec![
                format!("− {}", descriptor_text(before, catalog)?),
                format!("+ {}", descriptor_text(after, catalog)?),
            ],
        ),
        Operation::PropagateInheritance {
            replace,
            parts,
            backup,
            direction,
            count,
            ..
        } => {
            let file = crate::propagation::backup_path(backup, None)
                .display()
                .to_string();
            match direction {
                Direction::Compute => {
                    let mut details = vec![catalog.text(&Msg::PropagationCount { n: *count })];
                    if let Some(owner) = &parts.owner {
                        details.push(catalog.text(&Msg::PropagationOwner {
                            owner: owner.to_string(),
                        }));
                    }
                    if *replace && parts.dacl {
                        details.push(catalog.text(&Msg::PropagationReplace));
                    }
                    if let Some(replace) = parts.sacl {
                        details.push(catalog.text(&Msg::PropagationAudit { replace }));
                    }
                    details.push(catalog.text(&Msg::PropagationBackup { file }));
                    let title = if parts.dacl {
                        Msg::Propagate { path: target }
                    } else if parts.sacl.is_some() {
                        Msg::PropagateAudit { path: target }
                    } else {
                        Msg::PropagateOwner { path: target }
                    };
                    (catalog.text(&title), details)
                }
                Direction::Undo | Direction::Redo => (
                    catalog.text(&Msg::PropagationRewrite {
                        path: target,
                        undo: *direction == Direction::Undo,
                    }),
                    vec![catalog.text(&Msg::PropagationBackup { file })],
                ),
            }
        }
        _ => unreachable!("only operations on shares"),
    })
}

fn operation_lines(
    op: &Operation,
    catalog: &dyn Catalog,
) -> Result<(String, Vec<String>), ChangeError> {
    if op.is_sysvol() {
        return sysvol_lines(op, catalog);
    }
    if op.is_file_share() {
        return share_lines(op, catalog);
    }
    let no_check = || -> Vec<String> {
        if op.read().is_none() {
            vec![catalog.text(&Msg::NoVersionCheck)]
        } else {
            Vec::new()
        }
    };
    Ok(match op {
        Operation::Add { dn, attributes } => {
            let mut details = Vec::new();
            for (a, values) in attributes {
                let shown = values
                    .iter()
                    .map(|v| show_value(a, v, catalog))
                    .collect::<Result<Vec<_>, _>>()?;
                details.push(format!("{a} = {}", shown.join(", ")));
            }
            (catalog.text(&Msg::Create { dn: dn.clone() }), details)
        }
        Operation::Modify { dn, changes, .. } => {
            let mut details = Vec::new();
            for c in changes {
                details.extend(change_lines(c, catalog)?);
            }
            details.extend(no_check());
            (catalog.text(&Msg::Modify { dn: dn.clone() }), details)
        }
        Operation::Rename { dn, .. } => (
            catalog.text(&Msg::Rename {
                dn: dn.clone(),
                new_dn: op.dn_after()?,
            }),
            no_check(),
        ),
        _ => {
            let mut details = vec![catalog.text(&Msg::DeleteIrreversible)];
            details.extend(no_check());
            (
                catalog.text(&Msg::Delete {
                    dn: op.dn().to_owned(),
                }),
                details,
            )
        }
    })
}

/// Text of the preview (exact LDAP diff, secrets hidden): also the "dry run".
pub fn preview(changeset: &Changeset, catalog: &dyn Catalog) -> Result<String, ChangeError> {
    if changeset.operations.is_empty() {
        return Ok(catalog.text(&Msg::NoChange));
    }
    let mut lines = Vec::new();
    for (number, op) in changeset.operations.iter().enumerate() {
        let (title, details) = operation_lines(op, catalog)?;
        lines.push(format!("{}. {title}", number + 1));
        lines.extend(details.into_iter().map(|d| format!("     {d}")));
    }
    if !changeset.remarks.is_empty() {
        lines.push(catalog.text(&Msg::Remarks));
        lines.extend(changeset.remarks.iter().map(|r| format!("  - {r}")));
    }
    Ok(lines.join("\n"))
}

// ---------------------------------------------------------------------------
// Report of an application

/// What became of a changeset (`Issue`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Issue {
    Applied,
    Refused,
    Cancelled,
    Incomplete,
    Interrupted,
}

impl Issue {
    pub fn name(self) -> &'static str {
        match self {
            Self::Applied => "applique",
            Self::Refused => "refuse",
            Self::Cancelled => "annule",
            Self::Incomplete => "incomplet",
            Self::Interrupted => "interrompu",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        [
            Self::Applied,
            Self::Refused,
            Self::Cancelled,
            Self::Incomplete,
            Self::Interrupted,
        ]
        .into_iter()
        .find(|i| i.name() == name)
    }
}

/// An applied operation: its version read back, and the complete state read before a
/// deletion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    pub operation: Operation,
    pub after: Option<Read>,
    pub before: Option<AttributeMap>,
}

/// An error kept in a report: class name, message for the user, technical detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorRecord {
    pub class: String,
    pub message: String,
    pub detail: String,
}

/// Result of an application, as journaled (`Bilan`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub id: String,
    pub timestamp: String,
    pub domain: String,
    pub dc: String,
    pub user: String,
    pub changeset: Changeset,
    pub applied: Vec<Applied>,
    pub issue: Issue,
    pub error: Option<ErrorRecord>,
    pub rollback: Option<Changeset>,
    pub origins: Vec<usize>,
    pub rollback_applied: Vec<Applied>,
    pub rollback_error: Option<ErrorRecord>,
    pub doubtful: Option<Applied>,
    pub doubtful_rollback: Option<Applied>,
    pub resumes: Option<String>,
    pub resumed_by: Option<String>,
}

impl Report {
    /// Indices of the applied operations that the rollback did not (entirely) undo.
    pub fn remaining_indices(&self) -> Vec<usize> {
        let done = self.rollback_applied.len();
        let undone: Vec<usize> = self
            .origins
            .iter()
            .copied()
            .filter(|&i| {
                self.origins
                    .iter()
                    .enumerate()
                    .filter(|&(_, &o)| o == i)
                    .all(|(j, _)| j < done)
            })
            .collect();
        (0..self.applied.len())
            .filter(|i| !undone.contains(i))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Inverse

fn versions_left(applied: &[&Applied]) -> Result<HashMap<String, Option<Read>>, ChangeError> {
    let mut versions = HashMap::new();
    for a in applied {
        if !a.operation.is_ldap() {
            continue;
        }
        let version = if matches!(a.operation, Operation::Delete { .. }) {
            None
        } else {
            a.after.clone()
        };
        versions.insert(dn_key(&a.operation.dn_after()?)?, version);
    }
    Ok(versions)
}

/// Exact inverse of a SYSVOL operation: the state before is in the operation.
pub fn inverse_sysvol(op: &Operation) -> Operation {
    match op.clone() {
        Operation::CreateFolder {
            dn,
            path,
            descriptor,
        } => Operation::DeleteFolder {
            dn,
            path,
            descriptor,
        },
        Operation::DeleteFolder {
            dn,
            path,
            descriptor,
        } => Operation::CreateFolder {
            dn,
            path,
            descriptor,
        },
        Operation::WriteFile {
            dn,
            path,
            content,
            old: None,
            descriptor,
        } => Operation::DeleteFile {
            dn,
            path,
            content,
            descriptor,
        },
        Operation::WriteFile {
            dn,
            path,
            content,
            old: Some(old),
            ..
        } => Operation::WriteFile {
            dn,
            path,
            content: old,
            old: Some(content),
            descriptor: None,
        },
        Operation::DeleteFile {
            dn,
            path,
            content,
            descriptor,
        } => Operation::WriteFile {
            dn,
            path,
            content,
            old: None,
            descriptor,
        },
        Operation::SetDescriptor {
            dn,
            path,
            before,
            after,
        } => Operation::SetDescriptor {
            dn,
            path,
            before: after,
            after: before,
        },
        Operation::AddShare { unc, server, share } => Operation::DeleteShare { unc, server, share },
        Operation::DeleteShare { unc, server, share } => Operation::AddShare { unc, server, share },
        Operation::ChangeShare {
            unc,
            server,
            before,
            after,
        } => Operation::ChangeShare {
            unc,
            server,
            before: after,
            after: before,
        },
        Operation::SetFileDescriptor {
            unc,
            server,
            share,
            path,
            before,
            after,
        } => Operation::SetFileDescriptor {
            unc,
            server,
            share,
            path,
            before: after,
            after: before,
        },
        Operation::PropagateInheritance {
            unc,
            server,
            share,
            path,
            replace,
            parts,
            backup,
            direction,
            count,
        } => Operation::PropagateInheritance {
            unc,
            server,
            share,
            path,
            replace,
            parts,
            backup,
            direction: direction.inverse(),
            count,
        },
        other => other,
    }
}

/// The DC accepts only 0 or -1 in `pwdLastSet`: an old date is restored as -1.
fn inverse_pwdlastset(c: &Change, remarks: &mut Vec<Msg>) -> Change {
    let mut old: Values = c
        .removed
        .iter()
        .map(|v| {
            if v.as_slice() == b"0" || v.as_slice() == b"-1" {
                v.clone()
            } else {
                b"-1".to_vec()
            }
        })
        .collect();
    if old != c.removed {
        remarks.push(Msg::PwdLastSetNow);
    }
    if old.is_empty() || old == c.added {
        old = vec![b"-1".to_vec()];
    }
    Change {
        attribute: c.attribute.clone(),
        removed: c.added.clone(),
        added: old,
    }
}

fn values_of<'a>(attributes: &'a AttributeMap, name: &str) -> &'a [Vec<u8>] {
    attributes
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(name))
        .map_or(&[], |(_, v)| v.as_slice())
}

fn name_of(attributes: &AttributeMap, name: &str) -> String {
    attributes
        .iter()
        .find(|(a, _)| a.eq_ignore_ascii_case(name))
        .map_or_else(|| name.to_owned(), |(a, _)| a.clone())
}

/// Approximate inverse of a deletion: a new object, same non-system attributes (and the
/// system attributes of `guards`).
fn recreate(
    dn: &str,
    before: &AttributeMap,
    guards: &[String],
    remarks: &mut Vec<Msg>,
) -> Result<Vec<Operation>, ChangeError> {
    let guards: Vec<String> = guards.iter().map(|g| g.to_lowercase()).collect();
    if guards.iter().any(|g| g == "ntsecuritydescriptor") {
        remarks.push(Msg::RecreatedWithPermissions { dn: dn.into() });
    } else {
        remarks.push(Msg::RecreatedNew { dn: dn.into() });
    }
    let mut attributes: AttributeMap = Vec::new();
    for (attribute, values) in before {
        let lower = attribute.to_lowercase();
        if SYSTEM.contains(&lower.as_str()) && !guards.contains(&lower) {
            continue;
        }
        if SENSITIVE.contains(&lower.as_str()) {
            remarks.push(Msg::SecretNotJournaled {
                attribute: attribute.clone(),
            });
            continue;
        }
        attributes.push((attribute.clone(), values.clone()));
    }
    let classes: Vec<Vec<u8>> = values_of(before, "objectClass")
        .iter()
        .map(|v| v.to_ascii_lowercase())
        .collect();
    let uac = values_of(before, "userAccountControl");
    let account = classes.iter().any(|c| c == b"user" || c == b"computer");
    if let (Some(first), true) = (uac.first(), account) {
        let value = integer::decode(first, Width::Bits32)
            .map_err(|e| ChangeError::Journal(e.to_string()))?;
        let flags = value as u32;
        if flags & UserAccountControl::ACCOUNTDISABLE == 0 {
            let disabled = (flags | UserAccountControl::ACCOUNTDISABLE) as i32;
            let encoded = integer::encode(i64::from(disabled), Width::Bits32)
                .map_err(|e| ChangeError::Journal(e.to_string()))?;
            let name = name_of(before, "userAccountControl");
            match attributes.iter_mut().find(|(a, _)| *a == name) {
                Some((_, v)) => *v = vec![encoded],
                None => attributes.push((name, vec![encoded])),
            }
            remarks.push(Msg::RecreatedDisabled { dn: dn.into() });
        }
    }
    let mut operations = vec![Operation::Add {
        dn: dn.into(),
        attributes,
    }];
    for group in values_of(before, "memberOf") {
        let group = String::from_utf8(group.clone())
            .map_err(|_| ChangeError::Journal("memberOf: invalid UTF-8".into()))?;
        operations.push(Operation::Modify {
            dn: group,
            changes: vec![Change {
                attribute: "member".into(),
                removed: Vec::new(),
                added: vec![dn.as_bytes().to_vec()],
            }],
            read: None,
        });
    }
    Ok(operations)
}

fn inverse_one(
    op: &Operation,
    after: Option<Read>,
    remarks: &mut Vec<Msg>,
) -> Result<Vec<Operation>, ChangeError> {
    match op {
        Operation::Add { dn, .. } => Ok(vec![Operation::Delete {
            dn: dn.clone(),
            read: after,
            guards: Vec::new(),
        }]),
        Operation::Modify { dn, changes, .. } => {
            let mut inverse: Vec<Change> = Vec::new();
            for c in changes.iter().rev() {
                if is_sensitive(&c.attribute) {
                    remarks.push(Msg::SecretNotRestored {
                        attribute: c.attribute.clone(),
                    });
                } else if c.attribute.eq_ignore_ascii_case("pwdlastset") {
                    inverse.push(inverse_pwdlastset(c, remarks));
                } else {
                    inverse.push(c.inverse());
                }
            }
            // Stable: the classes added go first (ADR 0006, 5.2).
            inverse.sort_by_key(|c| !c.adds_class());
            Ok(if inverse.is_empty() {
                Vec::new()
            } else {
                vec![Operation::Modify {
                    dn: dn.clone(),
                    changes: inverse,
                    read: after,
                }]
            })
        }
        Operation::Rename { dn, parent, .. } => {
            let old_rdn = dn::split(dn)?
                .into_iter()
                .next()
                .ok_or(ChangeError::EmptyDn)?;
            let old_parent = match parent {
                None => None,
                Some(_) => Some(parent_dn(dn)?),
            };
            Ok(vec![Operation::Rename {
                dn: op.dn_after()?,
                rdn: old_rdn,
                parent: old_parent,
                read: after,
            }])
        }
        _ => Ok(Vec::new()),
    }
}

/// Inverse of applied operations (original index, operation), and for each inverse
/// operation the index of the one it undoes. Every inverse operation on one object carries
/// the last known version (`known`, otherwise the one left by the last operation).
pub fn invert(
    applied: &[(usize, &Applied)],
    known: Option<&HashMap<String, Option<Read>>>,
    catalog: &dyn Catalog,
) -> Result<(Changeset, Vec<usize>), ChangeError> {
    let mut operations = Vec::new();
    let mut origins = Vec::new();
    let mut remarks: Vec<Msg> = Vec::new();
    let mut last: HashMap<String, Option<Read>> = known.cloned().unwrap_or_default();
    for &(index, a) in applied.iter().rev() {
        let op = &a.operation;
        let inverses = if !op.is_ldap() {
            vec![inverse_sysvol(op)]
        } else if let Operation::Delete { dn, guards, .. } = op {
            last.insert(dn_key(dn)?, None); // recreated: no version to check
            recreate(
                dn,
                a.before.as_ref().unwrap_or(&Vec::new()),
                guards,
                &mut remarks,
            )?
        } else {
            let version = match last.get(&dn_key(&op.dn_after()?)?) {
                Some(v) => v.clone(),
                None => a.after.clone(),
            };
            last.insert(dn_key(op.dn())?, version.clone());
            inverse_one(op, version, &mut remarks)?
        };
        origins.extend(std::iter::repeat_n(index, inverses.len()));
        operations.extend(inverses);
    }
    let mut texts: Vec<String> = Vec::new();
    for remark in &remarks {
        let text = catalog.text(remark);
        if !texts.contains(&text) {
            texts.push(text);
        }
    }
    Ok((
        Changeset {
            operations,
            remarks: texts,
        },
        origins,
    ))
}

/// Changeset that undoes what `report` left applied. `journal`: the reports of the journal,
/// to undo one after the other several changes of one object (`versions_returned`).
pub fn inverse(
    report: &Report,
    journal: &[Report],
    catalog: &dyn Catalog,
) -> Result<Changeset, ChangeError> {
    let remaining: Vec<(usize, &Applied)> = report
        .remaining_indices()
        .into_iter()
        .filter_map(|i| report.applied.get(i).map(|a| (i, a)))
        .collect();
    let rollback: Vec<&Applied> = report.rollback_applied.iter().collect();
    let mut known = versions_left(&rollback)?;
    for (key, version) in versions_returned(report, journal)? {
        known.insert(key, Some(version));
    }
    Ok(invert(&remaining, Some(&known), catalog)?.0)
}

struct Follow {
    dn: String,
    version: Option<Read>,
    valid: bool,
    net: BTreeMap<(String, Vec<u8>), i64>,
}

impl Follow {
    fn targets(&self, op: &Operation) -> Result<bool, ChangeError> {
        Ok(op.is_ldap() && dn_key(op.dn())? == dn_key(&self.dn)?)
    }
}

fn follow_operation(
    follows: &mut BTreeMap<String, Follow>,
    op: &Operation,
    after: Option<&Read>,
) -> Result<(), ChangeError> {
    for follow in follows.values_mut() {
        if !follow.valid || !follow.targets(op)? {
            continue;
        }
        match op {
            Operation::Modify { changes, .. } => {
                for c in changes {
                    for (values, sign) in [(&c.removed, -1), (&c.added, 1)] {
                        for v in values {
                            *follow
                                .net
                                .entry((c.attribute.to_lowercase(), v.clone()))
                                .or_insert(0) += sign;
                        }
                    }
                }
            }
            Operation::Rename { .. } => follow.dn = op.dn_after()?,
            _ => {
                follow.valid = false;
                continue;
            }
        }
        if after.is_none() {
            follow.valid = false;
        }
        follow.version = after.cloned();
    }
    Ok(())
}

/// Versions of the objects `report` left applied, when the later applications of the
/// journal (same domain) touched them without changing anything in the end
/// (ADR 0006, 5.1).
pub fn versions_returned(
    report: &Report,
    journal: &[Report],
) -> Result<BTreeMap<String, Read>, ChangeError> {
    let mut later: Vec<&Report> = Vec::new();
    for r in journal {
        if r.id == report.id {
            later.clear();
        } else if r.domain == report.domain {
            later.push(r);
        }
    }
    if !journal.iter().any(|r| r.id == report.id) {
        return Ok(BTreeMap::new());
    }
    let mut follows: BTreeMap<String, Follow> = BTreeMap::new();
    for i in report.remaining_indices() {
        let Some(a) = report.applied.get(i) else {
            continue;
        };
        if a.operation.is_ldap() && !matches!(a.operation, Operation::Delete { .. }) {
            let key = dn_key(&a.operation.dn_after()?)?;
            follows.insert(
                key.clone(),
                Follow {
                    dn: key,
                    version: None,
                    valid: true,
                    net: BTreeMap::new(),
                },
            );
        }
    }
    for r in later {
        for a in r.applied.iter().chain(&r.rollback_applied) {
            follow_operation(&mut follows, &a.operation, a.after.as_ref())?;
        }
        for doubtful in [&r.doubtful, &r.doubtful_rollback].into_iter().flatten() {
            for follow in follows.values_mut() {
                if follow.targets(&doubtful.operation)? {
                    follow.valid = false;
                }
            }
        }
    }
    let mut versions = BTreeMap::new();
    for (key, follow) in follows {
        if follow.valid && dn_key(&follow.dn)? == key && follow.net.values().all(|&n| n == 0) {
            if let Some(version) = follow.version {
                versions.insert(key, version);
            }
        }
    }
    Ok(versions)
}

/// Operations of the changeset not done yet, to finish an interrupted application; the
/// versions of the objects already touched are those the done part left.
pub fn continuation(report: &Report) -> Result<Changeset, ChangeError> {
    if report.error.is_some() || report.rollback.is_some() || report.doubtful.is_some() {
        return Err(ChangeError::NoContinuation);
    }
    let applied: Vec<&Applied> = report.applied.iter().collect();
    let left = versions_left(&applied)?;
    let mut operations = Vec::new();
    for op in report
        .changeset
        .operations
        .iter()
        .skip(report.applied.len())
    {
        let replaced = match op {
            Operation::Modify { .. } | Operation::Rename { .. } | Operation::Delete { .. }
                if op.read().is_some() =>
            {
                left.get(&dn_key(op.dn())?).map(|v| op.with_read(v.clone()))
            }
            _ => None,
        };
        operations.push(replaced.unwrap_or_else(|| op.clone()));
    }
    Ok(Changeset {
        operations,
        remarks: report.changeset.remarks.clone(),
    })
}

/// The propagation cut by a stop of the application in `interrupted` (its doubtful
/// operation), if `settled` (the same report, ascertained) found it applied, as after « Stop »
/// (ADR 0023 § 8).
pub fn cut_propagation<'a>(interrupted: &'a Report, settled: &Report) -> Option<&'a Operation> {
    let cut = interrupted.doubtful.as_ref()?;
    let done = settled.doubtful.is_none() && settled.applied.len() == interrupted.applied.len() + 1;
    (done && matches!(cut.operation, Operation::PropagateInheritance { .. }))
        .then_some(&cut.operation)
}

/// What completes an application cut by a stop (`settled`, ascertained from `interrupted`):
/// the propagation that was under way started again, then the operations not done
/// (`continuation`). A computation starts again with a backup of its own and writes only what
/// is not yet as it must be; a rewrite starts again from the same backup and passes what it
/// already wrote.
pub fn completion(interrupted: &Report, settled: &Report) -> Result<Changeset, ChangeError> {
    let mut rest = continuation(settled)?;
    if let Some(cut) = cut_propagation(interrupted, settled) {
        let mut again = cut.clone();
        if let Operation::PropagateInheritance {
            backup,
            direction: Direction::Compute,
            ..
        } = &mut again
        {
            *backup = crate::propagation::new_id();
        }
        rest.operations.insert(0, again);
    }
    Ok(rest)
}

// ---------------------------------------------------------------------------
// Journaled form (JSON): a value is a string if it is UTF-8 text, otherwise
// {"base64": …}; a value of a secret attribute is {"masque": true}.

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                let index = ((n >> shift) & 0x3F) as usize;
                out.push(char::from(BASE64.get(index).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// `base64.b64decode(…, validate=True)`: only the alphabet, padding at the end.
pub fn base64_decode(text: &str) -> Result<Vec<u8>, ChangeError> {
    let bad = || ChangeError::Journal(format!("invalid base64: {text:?}"));
    let bytes = text.as_bytes();
    if bytes.len() % 4 != 0 {
        return Err(bad());
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let chunks: Vec<&[u8]> = bytes.chunks(4).collect();
    for (k, chunk) in chunks.iter().enumerate() {
        let padding = chunk.iter().rev().take_while(|&&c| c == b'=').count();
        if padding > 2 || (padding > 0 && k + 1 != chunks.len()) {
            return Err(bad());
        }
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            let value = if i >= 4 - padding {
                0
            } else {
                BASE64.iter().position(|&a| a == c).ok_or_else(bad)? as u32
            };
            n = (n << 6) | value;
        }
        let decoded = n.to_be_bytes();
        out.extend_from_slice(decoded.get(1..4 - padding).unwrap_or_default());
    }
    Ok(out)
}

fn value_to_json(attribute: &str, value: &[u8]) -> Value {
    if is_sensitive(attribute) {
        return json!({"masque": true});
    }
    match text_value(value) {
        Some(text) => Value::String(text.into()),
        None => json!({"base64": base64_encode(value)}),
    }
}

fn value_from_json(value: &Value) -> Result<Vec<u8>, ChangeError> {
    match value {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        Value::Object(map) => {
            if let Some(Value::String(b)) = map.get("base64") {
                return base64_decode(b);
            }
            if map.get("masque") == Some(&Value::Bool(true)) {
                return Ok(MASKED_VALUE.as_bytes().to_vec());
            }
            Err(ChangeError::Journal(format!("unreadable value: {value}")))
        }
        other => Err(ChangeError::Journal(format!("unreadable value: {other}"))),
    }
}

pub fn attributes_to_json(attributes: &AttributeMap) -> Value {
    Value::Object(
        attributes
            .iter()
            .map(|(a, values)| {
                (
                    a.clone(),
                    Value::Array(values.iter().map(|v| value_to_json(a, v)).collect()),
                )
            })
            .collect(),
    )
}

pub fn attributes_from_json(value: &Value) -> Result<AttributeMap, ChangeError> {
    let Value::Object(map) = value else {
        return Err(ChangeError::Journal("attributes: object expected".into()));
    };
    map.iter()
        .map(|(a, values)| {
            let values = array(values)?
                .iter()
                .map(value_from_json)
                .collect::<Result<Values, _>>()?;
            Ok((a.clone(), values))
        })
        .collect()
}

fn array(value: &Value) -> Result<&Vec<Value>, ChangeError> {
    match value {
        Value::Array(a) => Ok(a),
        other => Err(ChangeError::Journal(format!("array expected: {other}"))),
    }
}

fn field<'a>(map: &'a Map<String, Value>, key: &str) -> Result<&'a Value, ChangeError> {
    map.get(key)
        .ok_or_else(|| ChangeError::Journal(format!("missing key {key:?}")))
}

/// `str(x)` of Python for the scalars of the journal.
fn text_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => other.to_string(),
    }
}

fn int_of(value: &Value) -> Result<i64, ChangeError> {
    match value {
        Value::Number(n) => n
            .as_i64()
            .ok_or_else(|| ChangeError::Journal(format!("integer expected: {n}"))),
        Value::String(s) => s
            .trim()
            .parse()
            .map_err(|_| ChangeError::Journal(format!("integer expected: {s:?}"))),
        Value::Bool(b) => Ok(i64::from(*b)),
        other => Err(ChangeError::Journal(format!("integer expected: {other}"))),
    }
}

pub fn read_to_json(read: Option<&Read>) -> Value {
    read.map_or(Value::Null, |r| json!({"dc": r.dc, "usn": r.usn}))
}

pub fn read_from_json(value: Option<&Value>) -> Result<Option<Read>, ChangeError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(map)) => Ok(Some(Read {
            dc: text_of(field(map, "dc")?),
            usn: int_of(field(map, "usn")?)?,
        })),
        Some(other) => Err(ChangeError::Journal(format!("version expected: {other}"))),
    }
}

fn bytes_to_json(bytes: Option<&[u8]>) -> Value {
    bytes.map_or(Value::Null, |b| Value::String(base64_encode(b)))
}

fn bytes_from_json(value: Option<&Value>) -> Result<Option<Vec<u8>>, ChangeError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(v) => base64_decode(&text_of(v)).map(Some),
    }
}

fn required_bytes(value: Option<&Value>) -> Result<Vec<u8>, ChangeError> {
    bytes_from_json(value)?.ok_or_else(|| ChangeError::Journal("missing journaled value".into()))
}

pub fn operation_to_json(op: &Operation) -> Result<Value, ChangeError> {
    let mut d = Map::new();
    match op {
        Operation::Add { dn, attributes } => {
            d.insert("type".into(), "ajouter".into());
            d.insert("dn".into(), dn.clone().into());
            d.insert("attributs".into(), attributes_to_json(attributes));
        }
        Operation::Modify { dn, changes, read } => {
            d.insert("type".into(), "modifier".into());
            d.insert("dn".into(), dn.clone().into());
            d.insert("lecture".into(), read_to_json(read.as_ref()));
            let changes: Vec<Value> = changes
                .iter()
                .map(|c| {
                    json!({
                        "attribut": c.attribute,
                        "retirees": c.removed.iter().map(|v| value_to_json(&c.attribute, v)).collect::<Vec<_>>(),
                        "ajoutees": c.added.iter().map(|v| value_to_json(&c.attribute, v)).collect::<Vec<_>>(),
                    })
                })
                .collect();
            d.insert("changements".into(), Value::Array(changes));
        }
        Operation::Rename {
            dn,
            rdn,
            parent,
            read,
        } => {
            d.insert("type".into(), "renommer".into());
            d.insert("dn".into(), dn.clone().into());
            d.insert("rdn".into(), dn::compose(std::slice::from_ref(rdn))?.into());
            d.insert(
                "parent".into(),
                parent.clone().map_or(Value::Null, Value::String),
            );
            d.insert("lecture".into(), read_to_json(read.as_ref()));
        }
        Operation::Delete { dn, read, guards } => {
            d.insert("type".into(), "supprimer".into());
            d.insert("dn".into(), dn.clone().into());
            d.insert("lecture".into(), read_to_json(read.as_ref()));
            if !guards.is_empty() {
                d.insert(
                    "gardes".into(),
                    Value::Array(guards.iter().cloned().map(Value::String).collect()),
                );
            }
        }
        other if other.is_file_share() => return Ok(share_to_json(other)),
        sysvol => return Ok(sysvol_to_json(sysvol)),
    }
    Ok(Value::Object(d))
}

fn share_spec_to_json(share: &ShareSpec) -> Value {
    let mut value = json!({
        "nom": share.name,
        "chemin": share.path,
        "commentaire": share.remark,
        "max": share.max_uses,
        "descripteur": bytes_to_json(share.descriptor.as_deref()),
        "drapeaux": share.flags,
    });
    // J8.7: absent for a share without a registry key, as before.
    if let (Some(values), Value::Object(d)) = (&share.registry, &mut value) {
        d.insert(
            "registre".into(),
            Value::Array(values.iter().map(|(n, v)| json!([n, v])).collect()),
        );
    }
    value
}

fn registry_from_json(value: Option<&Value>) -> Result<Option<Vec<(String, String)>>, ChangeError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let bad = || ChangeError::Journal("share: registry".into());
    let mut values = Vec::new();
    for pair in value.as_array().ok_or_else(bad)? {
        match pair.as_array().map(Vec::as_slice) {
            Some([Value::String(n), Value::String(v)]) => values.push((n.clone(), v.clone())),
            _ => return Err(bad()),
        }
    }
    Ok(Some(values))
}

fn share_spec_from_json(value: Option<&Value>) -> Result<ShareSpec, ChangeError> {
    let Some(Value::Object(d)) = value else {
        return Err(ChangeError::Journal("share: object expected".into()));
    };
    let number = |key: &str| -> Result<u32, ChangeError> {
        field(d, key)?
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .ok_or_else(|| ChangeError::Journal(format!("share: {key} is not a number")))
    };
    Ok(ShareSpec {
        name: text_of(field(d, "nom")?),
        path: text_of(field(d, "chemin")?),
        remark: text_of(field(d, "commentaire")?),
        max_uses: number("max")?,
        descriptor: bytes_from_json(d.get("descripteur"))?,
        flags: number("drapeaux")?,
        registry: registry_from_json(d.get("registre"))?,
    })
}

/// Journaled form of an operation on shares; descriptors in base64.
pub fn share_to_json(op: &Operation) -> Value {
    let mut d = Map::new();
    d.insert("dn".into(), op.dn().to_owned().into());
    d.insert("serveur".into(), op.server().unwrap_or_default().into());
    match op {
        Operation::AddShare { share, .. } => {
            d.insert("type".into(), "creer_partage".into());
            d.insert("partage".into(), share_spec_to_json(share));
        }
        Operation::DeleteShare { share, .. } => {
            d.insert("type".into(), "supprimer_partage".into());
            d.insert("partage".into(), share_spec_to_json(share));
        }
        Operation::ChangeShare { before, after, .. } => {
            d.insert("type".into(), "modifier_partage".into());
            d.insert("avant".into(), share_spec_to_json(before));
            d.insert("apres".into(), share_spec_to_json(after));
        }
        Operation::SetFileDescriptor {
            share,
            path,
            before,
            after,
            ..
        } => {
            d.insert("type".into(), "poser_descripteur_fichier".into());
            d.insert("partage".into(), share.clone().into());
            d.insert("chemin".into(), path.clone().into());
            d.insert("avant".into(), bytes_to_json(Some(before)));
            d.insert("apres".into(), bytes_to_json(Some(after)));
        }
        Operation::PropagateInheritance {
            share,
            path,
            replace,
            parts,
            backup,
            direction,
            count,
            ..
        } => {
            d.insert("type".into(), "propager_heritage".into());
            d.insert("partage".into(), share.clone().into());
            d.insert("chemin".into(), path.clone().into());
            d.insert("remplacer".into(), (*replace).into());
            parts.to_json(&mut d);
            d.insert("sauvegarde".into(), backup.clone().into());
            d.insert("sens".into(), direction.name().into());
            d.insert("elements".into(), (*count).into());
        }
        _ => {}
    }
    Value::Object(d)
}

fn share_from_json(d: &Map<String, Value>, kind: &str) -> Result<Operation, ChangeError> {
    let server = text_of(field(d, "serveur")?);
    Ok(match kind {
        "creer_partage" => Operation::add_share(&server, share_spec_from_json(d.get("partage"))?),
        "supprimer_partage" => {
            Operation::delete_share(&server, share_spec_from_json(d.get("partage"))?)
        }
        "modifier_partage" => Operation::change_share(
            &server,
            share_spec_from_json(d.get("avant"))?,
            share_spec_from_json(d.get("apres"))?,
        ),
        "propager_heritage" => {
            let backup = text_of(field(d, "sauvegarde")?);
            if !crate::propagation::valid_id(&backup) {
                return Err(ChangeError::Journal(format!("backup: {backup:?}")));
            }
            let direction = crate::propagation::Direction::of_name(&text_of(field(d, "sens")?))
                .ok_or_else(|| ChangeError::Journal("propagation: direction".into()))?;
            let share = text_of(field(d, "partage")?);
            let path = text_of(field(d, "chemin")?);
            let parts = crate::propagation::Parts::from_json(&Value::Object(d.clone()))
                .ok_or_else(|| ChangeError::Journal("propagation: owner".into()))?;
            Operation::PropagateInheritance {
                unc: unc(&server, &share, &path),
                server,
                share,
                path,
                replace: field(d, "remplacer")?.as_bool().unwrap_or(false),
                parts,
                backup,
                direction,
                count: field(d, "elements")?
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .unwrap_or(0),
            }
        }
        _ => Operation::set_file_descriptor(
            &server,
            &text_of(field(d, "partage")?),
            &text_of(field(d, "chemin")?),
            required_bytes(d.get("avant"))?,
            required_bytes(d.get("apres"))?,
        ),
    })
}

/// Journaled form of a SYSVOL operation; contents and descriptors in base64.
pub fn sysvol_to_json(op: &Operation) -> Value {
    let mut d = Map::new();
    d.insert("dn".into(), op.dn().to_owned().into());
    d.insert(
        "chemin".into(),
        op.path().unwrap_or_default().to_owned().into(),
    );
    match op {
        Operation::CreateFolder { descriptor, .. } | Operation::DeleteFolder { descriptor, .. } => {
            let kind = if matches!(op, Operation::CreateFolder { .. }) {
                "creer_dossier"
            } else {
                "supprimer_dossier"
            };
            d.insert("type".into(), kind.into());
            d.insert("descripteur".into(), bytes_to_json(descriptor.as_deref()));
        }
        Operation::WriteFile {
            content,
            old,
            descriptor,
            ..
        } => {
            d.insert("type".into(), "ecrire_fichier".into());
            d.insert("contenu".into(), bytes_to_json(Some(content)));
            d.insert("ancien".into(), bytes_to_json(old.as_deref()));
            d.insert("descripteur".into(), bytes_to_json(descriptor.as_deref()));
        }
        Operation::DeleteFile {
            content,
            descriptor,
            ..
        } => {
            d.insert("type".into(), "supprimer_fichier".into());
            d.insert("contenu".into(), bytes_to_json(Some(content)));
            d.insert("descripteur".into(), bytes_to_json(descriptor.as_deref()));
        }
        Operation::SetDescriptor { before, after, .. } => {
            d.insert("type".into(), "poser_descripteur".into());
            d.insert("avant".into(), bytes_to_json(Some(before)));
            d.insert("apres".into(), bytes_to_json(Some(after)));
        }
        _ => {}
    }
    Value::Object(d)
}

fn sysvol_from_json(d: &Map<String, Value>) -> Result<Operation, ChangeError> {
    let dn = text_of(field(d, "dn")?);
    let path = text_of(field(d, "chemin")?);
    let kind = d.get("type").map(text_of).unwrap_or_default();
    Ok(match kind.as_str() {
        "creer_dossier" => Operation::CreateFolder {
            dn,
            path,
            descriptor: bytes_from_json(d.get("descripteur"))?,
        },
        "supprimer_dossier" => Operation::DeleteFolder {
            dn,
            path,
            descriptor: bytes_from_json(d.get("descripteur"))?,
        },
        "ecrire_fichier" => Operation::WriteFile {
            dn,
            path,
            content: required_bytes(d.get("contenu"))?,
            old: bytes_from_json(d.get("ancien"))?,
            descriptor: bytes_from_json(d.get("descripteur"))?,
        },
        "supprimer_fichier" => Operation::DeleteFile {
            dn,
            path,
            content: required_bytes(d.get("contenu"))?,
            descriptor: bytes_from_json(d.get("descripteur"))?,
        },
        "poser_descripteur" => Operation::SetDescriptor {
            dn,
            path,
            before: required_bytes(d.get("avant"))?,
            after: required_bytes(d.get("apres"))?,
        },
        other => {
            return Err(ChangeError::Journal(format!(
                "unknown operation type: {other:?}"
            )));
        }
    })
}

/// Inverse of [`operation_to_json`]; a masked value comes back as `<masqué>`.
pub fn operation_from_json(value: &Value) -> Result<Operation, ChangeError> {
    let Value::Object(d) = value else {
        return Err(ChangeError::Journal("operation: object expected".into()));
    };
    let kind = d.get("type").map(text_of).unwrap_or_default();
    let dn = text_of(field(d, "dn")?);
    match kind.as_str() {
        "ajouter" => Operation::add(&dn, attributes_from_json(field(d, "attributs")?)?),
        "modifier" => {
            let read = read_from_json(d.get("lecture"))?;
            let mut changes = Vec::new();
            for c in array(field(d, "changements")?)? {
                let Value::Object(c) = c else {
                    return Err(ChangeError::Journal("change: object expected".into()));
                };
                let removed = array(field(c, "retirees")?)?
                    .iter()
                    .map(value_from_json)
                    .collect::<Result<Values, _>>()?;
                let added = array(field(c, "ajoutees")?)?
                    .iter()
                    .map(value_from_json)
                    .collect::<Result<Values, _>>()?;
                changes.push(Change::new(
                    &text_of(field(c, "attribut")?),
                    removed,
                    added,
                )?);
            }
            Operation::modify(&dn, changes, read)
        }
        "renommer" => {
            let read = read_from_json(d.get("lecture"))?;
            let rdn_text = text_of(field(d, "rdn")?);
            let mut parts = dn::split(&rdn_text)?;
            if parts.len() != 1 {
                return Err(ChangeError::Journal(format!(
                    "one RDN expected: {rdn_text:?}"
                )));
            }
            let rdn = parts.remove(0);
            let parent = match d.get("parent") {
                None | Some(Value::Null) => None,
                Some(p) => Some(text_of(p)),
            };
            Operation::rename(&dn, rdn, parent, read)
        }
        "supprimer" => {
            let read = read_from_json(d.get("lecture"))?;
            let guards = match d.get("gardes") {
                None => Vec::new(),
                Some(g) => array(g)?.iter().map(text_of).collect(),
            };
            Operation::delete(&dn, read, guards)
        }
        "creer_partage"
        | "supprimer_partage"
        | "modifier_partage"
        | "poser_descripteur_fichier"
        | "propager_heritage" => share_from_json(d, &kind),
        _ => sysvol_from_json(d),
    }
}

pub fn changeset_to_json(changeset: &Changeset) -> Result<Value, ChangeError> {
    Ok(json!({
        "operations": changeset.operations.iter().map(operation_to_json).collect::<Result<Vec<_>, _>>()?,
        "remarques": changeset.remarks,
    }))
}

pub fn changeset_from_json(value: &Value) -> Result<Changeset, ChangeError> {
    let Value::Object(d) = value else {
        return Err(ChangeError::Journal("changeset: object expected".into()));
    };
    Ok(Changeset {
        operations: array(field(d, "operations")?)?
            .iter()
            .map(operation_from_json)
            .collect::<Result<_, _>>()?,
        remarks: match d.get("remarques") {
            None => Vec::new(),
            Some(r) => array(r)?.iter().map(text_of).collect(),
        },
    })
}

pub fn error_to_json(error: Option<&ErrorRecord>) -> Value {
    error.map_or(
        Value::Null,
        |e| json!({"classe": e.class, "message": e.message, "detail": e.detail}),
    )
}

pub fn error_from_json(value: Option<&Value>) -> Result<Option<ErrorRecord>, ChangeError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(m)) if m.is_empty() => Ok(None),
        Some(Value::Object(m)) => Ok(Some(ErrorRecord {
            class: "ErreurAnnuaire".into(),
            message: text_of(field(m, "message")?),
            detail: text_of(field(m, "detail")?),
        })),
        Some(other) => Err(ChangeError::Journal(format!("error expected: {other}"))),
    }
}

pub fn applied_to_json(a: &Applied) -> Value {
    let mut d = Map::new();
    d.insert("apres".into(), read_to_json(a.after.as_ref()));
    if let Some(before) = &a.before {
        d.insert("avant".into(), attributes_to_json(before));
    }
    Value::Object(d)
}

pub fn applied_from_json(op: &Operation, value: &Value) -> Result<Applied, ChangeError> {
    let Value::Object(d) = value else {
        return Err(ChangeError::Journal("applied: object expected".into()));
    };
    let before = match d.get("avant") {
        None | Some(Value::Null) => None,
        Some(a) => Some(attributes_from_json(a)?),
    };
    Ok(Applied {
        operation: op.clone(),
        after: read_from_json(d.get("apres"))?,
        before,
    })
}

/// The "bilan" record of the journal, complete by itself.
pub fn report_to_json(report: &Report) -> Result<Value, ChangeError> {
    let mut d = Map::new();
    d.insert("version".into(), JOURNAL_VERSION.into());
    d.insert("id".into(), report.id.clone().into());
    d.insert("etape".into(), "bilan".into());
    d.insert("horodatage".into(), report.timestamp.clone().into());
    d.insert("domaine".into(), report.domain.clone().into());
    d.insert("dc".into(), report.dc.clone().into());
    d.insert("utilisateur".into(), report.user.clone().into());
    d.insert(
        "reprend".into(),
        report.resumes.clone().map_or(Value::Null, Value::String),
    );
    d.insert("changeset".into(), changeset_to_json(&report.changeset)?);
    d.insert("issue".into(), report.issue.name().into());
    d.insert(
        "appliquees".into(),
        Value::Array(report.applied.iter().map(applied_to_json).collect()),
    );
    d.insert("erreur".into(), error_to_json(report.error.as_ref()));
    d.insert(
        "retour".into(),
        match &report.rollback {
            None => Value::Null,
            Some(c) => changeset_to_json(c)?,
        },
    );
    d.insert(
        "origines".into(),
        Value::Array(report.origins.iter().map(|&o| o.into()).collect()),
    );
    d.insert(
        "retour_appliquees".into(),
        Value::Array(
            report
                .rollback_applied
                .iter()
                .map(applied_to_json)
                .collect(),
        ),
    );
    d.insert(
        "erreur_retour".into(),
        error_to_json(report.rollback_error.as_ref()),
    );
    d.insert(
        "douteuse".into(),
        report
            .doubtful
            .as_ref()
            .map_or(Value::Null, applied_to_json),
    );
    d.insert(
        "douteuse_retour".into(),
        report
            .doubtful_rollback
            .as_ref()
            .map_or(Value::Null, applied_to_json),
    );
    Ok(Value::Object(d))
}

/// Inverse of [`report_to_json`].
pub fn report_from_json(value: &Value) -> Result<Report, ChangeError> {
    let Value::Object(d) = value else {
        return Err(ChangeError::Journal("report: object expected".into()));
    };
    if d.get("version") != Some(&Value::from(JOURNAL_VERSION)) {
        return Err(ChangeError::Journal(format!(
            "unknown journal version: {:?}",
            d.get("version")
        )));
    }
    let changeset = changeset_from_json(field(d, "changeset")?)?;
    let rollback = match d.get("retour") {
        None | Some(Value::Null) => None,
        Some(r) => Some(changeset_from_json(r)?),
    };
    let applied = changeset
        .operations
        .iter()
        .zip(array(field(d, "appliquees")?)?)
        .map(|(op, a)| applied_from_json(op, a))
        .collect::<Result<Vec<_>, _>>()?;
    let rollback_ops: &[Operation] = rollback.as_ref().map_or(&[], |r| &r.operations);
    let rollback_applied = rollback_ops
        .iter()
        .zip(array(field(d, "retour_appliquees")?)?)
        .map(|(op, a)| applied_from_json(op, a))
        .collect::<Result<Vec<_>, _>>()?;
    let doubtful = match d.get("douteuse") {
        None | Some(Value::Null) => None,
        Some(a) => {
            let op = changeset
                .operations
                .get(applied.len())
                .ok_or_else(|| ChangeError::Journal("doubtful operation out of range".into()))?;
            Some(applied_from_json(op, a)?)
        }
    };
    let doubtful_rollback = match (d.get("douteuse_retour"), &rollback) {
        (None | Some(Value::Null), _) | (_, None) => None,
        (Some(a), Some(r)) => {
            let op = r.operations.get(rollback_applied.len()).ok_or_else(|| {
                ChangeError::Journal("doubtful rollback operation out of range".into())
            })?;
            Some(applied_from_json(op, a)?)
        }
    };
    let issue_name = text_of(field(d, "issue")?);
    Ok(Report {
        id: text_of(field(d, "id")?),
        timestamp: text_of(field(d, "horodatage")?),
        domain: text_of(field(d, "domaine")?),
        dc: text_of(field(d, "dc")?),
        user: text_of(field(d, "utilisateur")?),
        changeset,
        applied,
        issue: Issue::from_name(&issue_name)
            .ok_or_else(|| ChangeError::Journal(format!("unknown issue: {issue_name:?}")))?,
        error: error_from_json(d.get("erreur"))?,
        rollback,
        origins: match d.get("origines") {
            None => Vec::new(),
            Some(o) => array(o)?
                .iter()
                .map(|v| int_of(v).map(|n| usize::try_from(n).unwrap_or(usize::MAX)))
                .collect::<Result<_, _>>()?,
        },
        rollback_applied,
        rollback_error: error_from_json(d.get("erreur_retour"))?,
        doubtful,
        doubtful_rollback,
        resumes: match d.get("reprend") {
            None | Some(Value::Null) => None,
            Some(r) => Some(text_of(r)),
        },
        resumed_by: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::messages::English;

    const OU: &str = "OU=Labo,DC=lab,DC=test";

    fn bytes(values: &[&str]) -> Values {
        values.iter().map(|v| v.as_bytes().to_vec()).collect()
    }

    #[test]
    fn changes_are_checked() {
        assert!(Change::new("description", vec![], vec![]).is_err());
        assert!(Change::new("description", bytes(&["a"]), bytes(&["a"])).is_err());
        assert!(Change::new("member", vec![], bytes(&["x", "x"])).is_err());
        assert!(Change::new("nom invalide", vec![], bytes(&["x"])).is_err());
        assert!(Change::new("unicodePwd", vec![], bytes(&["x", "x"])).is_ok());
        let renamed =
            Operation::rename(&format!("CN=a,{OU}"), Component::new("CN", "a"), None, None);
        assert_eq!(renamed, Err(ChangeError::RenameWithoutEffect));
    }

    #[test]
    fn preview_in_english() {
        let read = Some(Read {
            dc: "dc1.lab.test".into(),
            usn: 5,
        });
        let changeset = Changeset {
            operations: vec![
                Operation::add(
                    &format!("CN=Neuf,{OU}"),
                    vec![("objectClass".into(), bytes(&["contact"]))],
                )
                .unwrap(),
                Operation::modify(
                    &format!("CN=Jean Dupont,{OU}"),
                    vec![
                        Change::new("description", bytes(&["avant"]), bytes(&["après"])).unwrap(),
                        Change::new("unicodePwd", vec![], vec![b"\"\0s\0\"\0".to_vec()]).unwrap(),
                        Change::new(
                            "objectSid",
                            vec![],
                            vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]],
                        )
                        .unwrap(),
                        Change::new("jpegPhoto", vec![], vec![(0u8..40).collect()]).unwrap(),
                    ],
                    read.clone(),
                )
                .unwrap(),
                Operation::rename(
                    &format!("CN=Jean Dupont,{OU}"),
                    Component::new("CN", "Dupont, Jean"),
                    Some("OU=Autre,DC=lab,DC=test".into()),
                    None,
                )
                .unwrap(),
                Operation::delete(&format!("CN=GG,{OU}"), read, vec![]).unwrap(),
            ],
            remarks: vec!["a remark".into()],
        };
        let text = preview(&changeset, &English).unwrap();
        assert!(text.contains(&format!("1. Create CN=Neuf,{OU}")));
        assert!(text.contains("description: “avant” → “après”"));
        assert!(text.contains("unicodePwd: + <hidden>"));
        assert!(text.contains("objectSid: + S-1-5-18"));
        assert!(text.contains("jpegPhoto: + 0x000102") && text.contains("(40 bytes)"));
        assert!(text.contains("→ CN=Dupont\\, Jean,OU=Autre,DC=lab,DC=test"));
        assert!(text.contains("(no version check)"));
        assert!(text.ends_with("  - a remark"));
        assert_eq!(
            preview(&Changeset::default(), &English).unwrap(),
            "No change."
        );
    }

    #[test]
    fn base64_like_python() {
        for (raw, encoded) in [
            (&b""[..], ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"\xff\xfe\x00", "//4A"),
        ] {
            assert_eq!(base64_encode(raw), encoded);
            assert_eq!(base64_decode(encoded).unwrap(), raw);
        }
        assert!(base64_decode("Zg=").is_err());
        assert!(base64_decode("Z=g=").is_err());
        assert!(base64_decode("Zm9v\n").is_err());
    }

    #[test]
    fn journaled_form_round_trip() {
        let op = Operation::modify(
            &format!("CN=a,{OU}"),
            vec![
                Change::new("description", bytes(&["x"]), vec![vec![0xFF]]).unwrap(),
                Change::new("unicodePwd", vec![], bytes(&["secret"])).unwrap(),
            ],
            Some(Read {
                dc: "dc1".into(),
                usn: 7,
            }),
        )
        .unwrap();
        let json = operation_to_json(&op).unwrap();
        assert_eq!(
            json.to_string(),
            r#"{"type":"modifier","dn":"CN=a,OU=Labo,DC=lab,DC=test","lecture":{"dc":"dc1","usn":7},"changements":[{"attribut":"description","retirees":["x"],"ajoutees":[{"base64":"/w=="}]},{"attribut":"unicodePwd","retirees":[],"ajoutees":[{"masque":true}]}]}"#
        );
        let back = operation_from_json(&json).unwrap();
        let Operation::Modify { changes, .. } = &back else {
            panic!()
        };
        assert_eq!(changes[1].added, vec![MASKED_VALUE.as_bytes().to_vec()]);
    }

    #[test]
    fn propagation_cut_by_a_stop_is_completed() {
        let descriptor = Operation::set_file_descriptor(
            "fs1.lab.test",
            "Commun",
            "Compta",
            b"avant".to_vec(),
            b"apres".to_vec(),
        );
        let propagation = Operation::propagate_inheritance(
            "fs1.lab.test",
            "Commun",
            "Compta",
            false,
            "20261023080000-0a1b2c3d",
            40,
        );
        let applied = |op: &Operation| Applied {
            operation: op.clone(),
            after: None,
            before: None,
        };
        let interrupted = Report {
            id: "a1".into(),
            timestamp: String::new(),
            domain: "lab.test".into(),
            dc: "dc1".into(),
            user: String::new(),
            changeset: Changeset {
                operations: vec![descriptor.clone(), propagation.clone()],
                remarks: Vec::new(),
            },
            applied: vec![applied(&descriptor)],
            issue: Issue::Interrupted,
            error: None,
            rollback: None,
            origins: Vec::new(),
            rollback_applied: Vec::new(),
            rollback_error: None,
            doubtful: Some(applied(&propagation)),
            doubtful_rollback: None,
            resumes: None,
            resumed_by: None,
        };
        // Still doubtful: nothing to complete.
        assert!(completion(&interrupted, &interrupted).is_err());
        assert!(cut_propagation(&interrupted, &interrupted).is_none());
        // Its backup found: applied, and started again with a backup of its own.
        let mut settled = interrupted.clone();
        settled.applied.push(applied(&propagation));
        settled.doubtful = None;
        assert_eq!(cut_propagation(&interrupted, &settled), Some(&propagation));
        let again = completion(&interrupted, &settled).unwrap();
        let [
            Operation::PropagateInheritance {
                backup, direction, ..
            },
        ] = again.operations.as_slice()
        else {
            panic!("{again:?}")
        };
        assert_eq!(*direction, Direction::Compute);
        assert_ne!(backup, "20261023080000-0a1b2c3d");
        assert!(crate::propagation::valid_id(backup));
        // No backup: not applied, the continuation proposes it as it was.
        let mut not_started = interrupted.clone();
        not_started.doubtful = None;
        assert!(cut_propagation(&interrupted, &not_started).is_none());
        assert_eq!(
            completion(&interrupted, &not_started).unwrap().operations,
            vec![propagation.clone()]
        );
        // A rewrite starts again from its own backup.
        let undo = inverse_sysvol(&propagation);
        let mut rewriting = interrupted.clone();
        rewriting.changeset.operations = vec![undo.clone()];
        rewriting.applied.clear();
        rewriting.doubtful = Some(applied(&undo));
        let mut settled = rewriting.clone();
        settled.applied.push(applied(&undo));
        settled.doubtful = None;
        assert_eq!(
            completion(&rewriting, &settled).unwrap().operations,
            vec![undo]
        );
    }

    #[test]
    fn share_journaled_with_its_registry_values() {
        let before = ShareSpec {
            name: "Essai".into(),
            path: "C:\\srv\\essai".into(),
            remark: "x".into(),
            max_uses: u32::MAX,
            descriptor: None,
            flags: 0,
            registry: Some(vec![
                ("path".into(), "/srv/essai".into()),
                ("vfs objects".into(), "acl_xattr".into()),
            ]),
        };
        let after = ShareSpec {
            max_uses: 5,
            registry: None,
            ..before.clone()
        };
        let op = Operation::change_share("fs1.lab.test", before.clone(), after);
        // The change starts from the values read with « before ».
        let Operation::ChangeShare { after, .. } = &op else {
            panic!()
        };
        assert_eq!(after.registry, before.registry);
        let json = operation_to_json(&op).unwrap();
        assert_eq!(
            json["avant"]["registre"],
            json!([["path", "/srv/essai"], ["vfs objects", "acl_xattr"]])
        );
        assert_eq!(operation_from_json(&json).unwrap(), op);
        // Without a key, the form of J8.6.
        let plain = Operation::delete_share(
            "wdc1.win.test",
            ShareSpec {
                registry: None,
                ..before
            },
        );
        let json = operation_to_json(&plain).unwrap();
        assert!(json["partage"].get("registre").is_none());
        assert_eq!(operation_from_json(&json).unwrap(), plain);
        let mut bad = json.clone();
        bad["partage"]["registre"] = json!([["path"]]);
        assert!(operation_from_json(&bad).is_err());
    }

    #[test]
    fn propagation_journaled_and_inverted() {
        let op = Operation::propagate_inheritance(
            "fs1.lab.test",
            "Commun",
            "Compta\\2026",
            true,
            "20261022120000-0a1b2c3d",
            3012,
        );
        assert_eq!(op.dn(), "\\\\fs1.lab.test\\Commun\\Compta\\2026");
        assert!(op.is_file_share() && !op.is_ldap() && !op.is_sysvol());
        let json = operation_to_json(&op).unwrap();
        assert_eq!(json["type"], "propager_heritage");
        assert_eq!(json["sens"], "calcul");
        assert_eq!(operation_from_json(&json).unwrap(), op);
        // Its inverse writes the backup back, the inverse of that writes it again.
        let changeset = Changeset {
            operations: vec![op.clone()],
            remarks: Vec::new(),
        };
        let undo = [inverse_sysvol(&op)];
        let Operation::PropagateInheritance { direction, .. } = &undo[0] else {
            panic!()
        };
        assert_eq!(*direction, Direction::Undo);
        let json = operation_to_json(&undo[0]).unwrap();
        assert_eq!(json["sens"], "annulation");
        assert_eq!(operation_from_json(&json).unwrap(), undo[0]);
        // A backup name that is not a file of the folder is refused.
        let mut bad = operation_to_json(&op).unwrap();
        bad["sauvegarde"] = "../../.bashrc".into();
        assert!(operation_from_json(&bad).is_err());
        let text = preview(&changeset, &English).unwrap();
        assert!(text.contains("Propagate the inheritance under"), "{text}");
        assert!(text.contains("3012 elements"), "{text}");
        assert!(text.contains("replaced by the inherited ones"), "{text}");
        // A journal of J8.4 has neither « droits » nor « proprietaire »: the DACL alone.
        assert!(json.get("droits").is_none() && json.get("proprietaire").is_none());
        // The owner replaced, the DACL left (J8.7): journaled and read back.
        let owner: Sid = "S-1-5-32-544".parse().unwrap();
        let op = Operation::propagate_parts(
            "fs1.lab.test",
            "Commun",
            "Compta",
            false,
            crate::propagation::Parts {
                dacl: false,
                sacl: None,
                owner: Some(owner),
            },
            "20261023120000-0a1b2c3d",
            12,
        );
        let json = operation_to_json(&op).unwrap();
        assert_eq!(json["droits"], false);
        assert_eq!(json["proprietaire"], "S-1-5-32-544");
        assert_eq!(operation_from_json(&json).unwrap(), op);
        let undo = inverse_sysvol(&op);
        assert!(
            matches!(&undo, Operation::PropagateInheritance { parts, .. } if parts.owner == Some(owner))
        );
        let mut bad = json.clone();
        bad["proprietaire"] = "pas un SID".into();
        assert!(operation_from_json(&bad).is_err());
        let text = preview(
            &Changeset {
                operations: vec![op],
                remarks: Vec::new(),
            },
            &English,
        )
        .unwrap();
        assert!(text.contains("Replace the owner under"), "{text}");
        assert!(text.contains("S-1-5-32-544"), "{text}");
        // The auditing entries alone, « replace » on (J8.7).
        let op = Operation::propagate_parts(
            "fs1.lab.test",
            "Commun",
            "Compta",
            false,
            crate::propagation::Parts {
                dacl: false,
                sacl: Some(true),
                owner: None,
            },
            "20261023120000-0a1b2c3e",
            12,
        );
        let json = operation_to_json(&op).unwrap();
        assert_eq!(
            (json["audit"].clone(), json["remplacer_audit"].clone()),
            (true.into(), true.into())
        );
        assert_eq!(operation_from_json(&json).unwrap(), op);
        let text = preview(
            &Changeset {
                operations: vec![op],
                remarks: Vec::new(),
            },
            &English,
        )
        .unwrap();
        assert!(
            text.contains("Propagate the auditing entries under"),
            "{text}"
        );
    }

    #[test]
    fn inverse_of_a_modification_and_a_rename() {
        let dn = format!("CN=a,{OU}");
        let read = |usn| {
            Some(Read {
                dc: "dc1".into(),
                usn,
            })
        };
        let applied = [
            Applied {
                operation: Operation::modify(
                    &dn,
                    vec![
                        Change::new("description", bytes(&["x"]), bytes(&["y"])).unwrap(),
                        Change::new("objectClass", vec![], bytes(&["aux"])).unwrap(),
                        Change::new("pwdLastSet", bytes(&["132000000000000000"]), bytes(&["0"]))
                            .unwrap(),
                    ],
                    read(1),
                )
                .unwrap(),
                after: read(2),
                before: None,
            },
            Applied {
                operation: Operation::rename(&dn, Component::new("CN", "b"), None, read(2))
                    .unwrap(),
                after: read(3),
                before: None,
            },
        ];
        let pairs: Vec<(usize, &Applied)> = applied.iter().enumerate().collect();
        let (changeset, origins) = invert(&pairs, None, &English).unwrap();
        assert_eq!(origins, [1, 0]);
        let Operation::Rename {
            dn: renamed,
            rdn,
            read: r,
            ..
        } = &changeset.operations[0]
        else {
            panic!()
        };
        assert_eq!(
            (renamed.as_str(), rdn.value.as_str()),
            (format!("CN=b,{OU}").as_str(), "a")
        );
        assert_eq!(r, &read(3));
        let Operation::Modify {
            changes, read: r, ..
        } = &changeset.operations[1]
        else {
            panic!()
        };
        assert_eq!(r, &read(3)); // the last known version of the object
        assert_eq!(changes[0].attribute, "pwdLastSet");
        assert_eq!(changes[0].added, bytes(&["-1"]));
        assert_eq!(changes[1].attribute, "objectClass");
        assert_eq!(changeset.remarks.len(), 1);
    }
}

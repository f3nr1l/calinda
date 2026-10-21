// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Group policies in reading (`annuaire.core.gpo`): what the directory says of the GPOs of a
//! domain, its inventory with the SYSVOL of the PDC and the comparison of the SYSVOL of the
//! other DCs (J5.2), and the resultant policy of an account (J5.7), with the loopback
//! processing. The writes are in `gpo_write`, the backups in `gpo_backup`.
//!
//! **Where it is read (ADR 0012).** Everything is read on the write DC (the PDC emulator, as
//! the GPMC), by its connection, never in the local copy.
//!
//! **Security filtering.** A GPO applies to an account if its DACL grants it the reading
//! (`RP`) and the extended right « Apply group policy » (`CR` on
//! `edacfd8f-ffb3-11d1-b41d-00a0c968f939`), without a denial that comes first (MS-GPOL
//! 3.2.5.1.6). `access` evaluates the DACL as `AccessCheck`.
//!
//! **Resultant policy (MS-GPOL 3.2.5.1.5, « LSDOU »).** Links of the domain, then of the OUs
//! from the highest to the nearest; in a container, the `gPLink` chain in order (the last
//! link, order 1, comes last and wins). An OU that blocks inheritance discards the links of
//! the containers above it, except the enforced links; the enforced links come after all the
//! others, those of the highest container last. A disabled link does not count. Then, for
//! each GPO kept: not found, refused by the security filtering, part disabled (`flags`),
//! empty for this part (version 0), or applied; a WMI filter is not evaluated (said as such).
//! The site links are not evaluated: the policy says so if there are some in the forest.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use annuaire_codecs::gplink::{self, GpLink, Link};
use annuaire_codecs::integer::{self, Width};
use annuaire_codecs::registry_pol::{self, RegValue};
use annuaire_codecs::sd::{self, SecurityDescriptor};
use annuaire_codecs::time::{self, UtcTime};
use annuaire_codecs::{Guid, Sid};

use crate::connection::{Connection, Failure, Link as LdapLink};
use crate::dn;
use crate::error::{LdapError, code};
use crate::queries;
use crate::search::{self, SD_WITHOUT_SACL};
use crate::session::{Control, Entry, Scope, SearchRequest};
use crate::sysvol;

// flags of a GPO (MS-GPOL 2.2.4).
pub const USER_DISABLED: i64 = 0x1;
pub const COMPUTER_DISABLED: i64 = 0x2;

/// Extended right « Apply group policy » (Apply-Group-Policy).
pub fn right_apply() -> Guid {
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
        .parse()
        .unwrap_or(Guid::from_bytes([0; 16]))
}

fn well_known(text: &str) -> Option<Sid> {
    text.parse().ok()
}

pub const GPO_ATTRIBUTES: [&str; 12] = [
    "cn",
    "displayName",
    "flags",
    "versionNumber",
    "gPCFileSysPath",
    "gPCMachineExtensionNames",
    "gPCUserExtensionNames",
    "gPCWQLFilter",
    "gPCFunctionalityVersion",
    "whenCreated",
    "whenChanged",
    "nTSecurityDescriptor",
];
pub const CONTAINER_ATTRIBUTES: [&str; 4] = ["objectClass", "name", "gPLink", "gPOptions"];
pub const GPO_FILTER: &str = "(objectClass=groupPolicyContainer)";
pub const CONTAINERS_FILTER: &str = "(|(objectClass=domainDNS)(objectClass=organizationalUnit))";
pub const LINKS_FILTER: &str = "(gPLink=*)";

/// Which part of a GPO (`Partie`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Part {
    Computer,
    User,
}

/// Versions of the two parts of `versionNumber` (user in the 16 high bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Versions {
    pub user: i64,
    pub computer: i64,
}

impl Versions {
    pub fn of(self, part: Part) -> i64 {
        match part {
            Part::Computer => self.computer,
            Part::User => self.user,
        }
    }
}

pub fn versions(version: i64) -> Versions {
    let v = version & 0xFFFF_FFFF;
    Versions {
        user: v >> 16,
        computer: v & 0xFFFF,
    }
}

/// Versions of the two parts → `versionNumber` (user in the 16 high bits) (`version_de`).
pub fn version_of(v: Versions) -> i64 {
    ((v.user & 0xFFFF) << 16) | (v.computer & 0xFFFF)
}

// --- GPT.INI ------------------------------------------------------------------------------------

/// Why `GPT.INI` gives no version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GptError {
    /// No `Version=` in `[General]`.
    NoVersion,
    /// `Version=` is not a number: the text read.
    Unreadable(String),
}

/// `GPT.INI` read (`GptIni`): `version` None if absent or unreadable (`error` says why).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptIni {
    pub version: Option<i64>,
    pub name: Option<String>,
    pub error: Option<GptError>,
}

/// Windows-1252 as Python decodes it with « replace »: five bytes have no character.
fn cp1252(bytes: &[u8]) -> String {
    const HIGH: [char; 32] = [
        '€', '\u{FFFD}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{FFFD}', 'Ž',
        '\u{FFFD}', '\u{FFFD}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ',
        '\u{FFFD}', 'ž', 'Ÿ',
    ];
    bytes
        .iter()
        .map(|&b| match b {
            0x80..=0x9F => HIGH
                .get(usize::from(b - 0x80))
                .copied()
                .unwrap_or('\u{FFFD}'),
            _ => char::from(b),
        })
        .collect()
}

/// ANSI (Windows-1252), UTF-8 or UTF-16 with a BOM, as Python decodes it.
fn decode_ini(bytes: &[u8]) -> String {
    let utf16 = |little: bool| -> String {
        let units: Vec<u16> = bytes
            .get(2..)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|c| match c {
                [a, b] if little => u16::from_le_bytes([*a, *b]),
                [a, b] => u16::from_be_bytes([*a, *b]),
                _ => 0,
            })
            .collect();
        String::from_utf16_lossy(&units)
    };
    match bytes {
        [0xFF, 0xFE, ..] => utf16(true),
        [0xFE, 0xFF, ..] => utf16(false),
        _ => {
            let body = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
            match std::str::from_utf8(body) {
                Ok(text) => text.to_owned(),
                Err(_) => cp1252(bytes),
            }
        }
    }
}

/// Section `[General]`, keys without case, spaces allowed around `=` (Samba writes
/// `Version = 65540`, Windows `Version=65540`); ANSI, UTF-8 or UTF-16 with a BOM
/// (`lire_gpt_ini`).
pub fn read_gpt_ini(bytes: &[u8]) -> GptIni {
    let text = decode_ini(bytes);
    let mut section = String::new();
    let mut keys: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') && line.len() >= 2 {
            section = line
                .get(1..line.len() - 1)
                .unwrap_or_default()
                .trim()
                .to_lowercase();
            continue;
        }
        if section == "general"
            && let Some((key, value)) = line.split_once('=')
        {
            let key = key.trim().to_lowercase();
            if !keys.iter().any(|(k, _)| *k == key) {
                keys.push((key, value.trim().to_owned()));
            }
        }
    }
    let get = |k: &str| keys.iter().find(|(x, _)| x == k).map(|(_, v)| v.clone());
    let name = get("displayname");
    match get("version") {
        None => GptIni {
            version: None,
            name,
            error: Some(GptError::NoVersion),
        },
        Some(v) => match v.replace('_', "").parse::<i64>() {
            Ok(n) => GptIni {
                version: Some(n),
                name,
                error: None,
            },
            Err(_) => GptIni {
                version: None,
                name,
                error: Some(GptError::Unreadable(v)),
            },
        },
    }
}

/// The first line `Version = <digits>` (any case, blanks around), as the pattern of Python:
/// (start, end) of the digits in `chars`.
fn version_digits(chars: &[char]) -> Option<(usize, usize)> {
    let mut start = 0;
    while start <= chars.len() {
        let end = chars
            .get(start..)
            .and_then(|rest| rest.iter().position(|&c| c == '\n'))
            .map_or(chars.len(), |p| start + p);
        let line = chars.get(start..end).unwrap_or_default();
        let mut i = line.iter().take_while(|c| c.is_whitespace()).count();
        let word: String = line.get(i..i + 7).unwrap_or_default().iter().collect();
        if word.eq_ignore_ascii_case("version") {
            i += 7;
            i += line
                .get(i..)
                .unwrap_or_default()
                .iter()
                .take_while(|c| c.is_whitespace())
                .count();
            if line.get(i) == Some(&'=') {
                i += 1;
                i += line
                    .get(i..)
                    .unwrap_or_default()
                    .iter()
                    .take_while(|c| c.is_whitespace())
                    .count();
                let digits = line
                    .get(i..)
                    .unwrap_or_default()
                    .iter()
                    .take_while(|c| c.is_ascii_digit())
                    .count();
                let rest = line.get(i + digits..).unwrap_or_default();
                if digits > 0 && rest.iter().all(|c| c.is_whitespace()) {
                    return Some((start + i, start + i + digits));
                }
            }
        }
        start = end + 1;
    }
    None
}

/// `GPT.INI` with `Version=` changed and the rest kept byte for byte (ANSI or UTF-8; UTF-16
/// with its BOM); added at the head of `[General]` if missing (`gpt_ini_avec_version`).
pub fn gpt_ini_with_version(content: &[u8], version: i64) -> Vec<u8> {
    let little = content.starts_with(&[0xFF, 0xFE]);
    let utf16 = little || content.starts_with(&[0xFE, 0xFF]);
    let chars: Vec<char> = if utf16 {
        let units: Vec<u16> = content
            .get(2..)
            .unwrap_or_default()
            .chunks_exact(2)
            .map(|c| match c {
                [a, b] if little => u16::from_le_bytes([*a, *b]),
                [a, b] => u16::from_be_bytes([*a, *b]),
                _ => 0,
            })
            .collect();
        String::from_utf16_lossy(&units).chars().collect()
    } else {
        content.iter().map(|&b| char::from(b)).collect()
    };
    let text: String = match version_digits(&chars) {
        Some((a, b)) => {
            let mut t: String = chars.get(..a).unwrap_or_default().iter().collect();
            t.push_str(&version.to_string());
            t.extend(chars.get(b..).unwrap_or_default());
            t
        }
        None => {
            let whole: String = chars.iter().collect();
            format!(
                "[General]\r\nVersion={version}\r\n{}",
                whole.replacen("[General]\r\n", "", 1)
            )
        }
    };
    if utf16 {
        let mut out = content.get(..2).unwrap_or_default().to_vec();
        for unit in text.encode_utf16() {
            out.extend(if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        out
    } else {
        // Latin-1: one byte per character, as read.
        text.chars()
            .map(|c| u8::try_from(u32::from(c)).unwrap_or(b'?'))
            .collect()
    }
}

/// The directory half of a GPO. `guid`: the `cn` (`{…}` in upper case), key of the links.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gpo {
    pub dn: String,
    pub guid: String,
    pub name: String,
    pub flags: i64,
    pub version: i64,
    pub path: String,
    pub computer_extensions: String,
    pub user_extensions: String,
    pub wmi_filter: String,
    pub created: Option<UtcTime>,
    pub modified: Option<UtcTime>,
    pub descriptor: Option<SecurityDescriptor>,
}

impl Gpo {
    pub fn versions(&self) -> Versions {
        versions(self.version)
    }

    pub fn disabled(&self, part: Part) -> bool {
        match part {
            Part::Computer => self.flags & COMPUTER_DISABLED != 0,
            Part::User => self.flags & USER_DISABLED != 0,
        }
    }

    /// `gPCWQLFilter` = `[domain;{GUID};0]`: the GUID (`{…}` in upper case).
    pub fn wmi_guid(&self) -> Option<String> {
        let text = &self.wmi_filter;
        let start = text.find('{')?;
        let candidate = text.get(start..start + 38)?;
        let well_formed = candidate.ends_with('}')
            && candidate
                .get(1..37)
                .is_some_and(|g| g.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
        well_formed.then(|| candidate.to_uppercase())
    }
}

/// Domain, OU or site, with its links. `class`: `domainDNS`, `organizationalUnit`, `site`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Container {
    pub dn: String,
    pub name: String,
    pub class: String,
    pub gplink: GpLink,
    pub gpoptions: i64,
}

impl Container {
    pub fn inheritance_blocked(&self) -> bool {
        gplink::inheritance_blocked(self.gpoptions)
    }
}

fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

fn number(entry: &Entry, attribute: &str) -> i64 {
    entry
        .values(attribute)
        .first()
        .and_then(|v| integer::decode(v, Width::Bits32).ok())
        .unwrap_or(0)
}

fn date(entry: &Entry, attribute: &str) -> Option<UtcTime> {
    let value = entry.values(attribute).first()?;
    time::decode_generalized_time(std::str::from_utf8(value).ok()?).ok()
}

pub fn name_from_dn(dn_text: &str) -> String {
    dn::split(dn_text)
        .ok()
        .and_then(|c| c.first().map(|c| c.value.clone()))
        .unwrap_or_else(|| dn_text.to_owned())
}

/// Tolerant decoding: an unreadable attribute takes its default value (`gpo_depuis_entree`).
pub fn gpo_from_entry(entry: &Entry) -> Gpo {
    let cn = text(entry, "cn");
    let guid = if cn.is_empty() {
        name_from_dn(&entry.dn)
    } else {
        cn
    }
    .to_uppercase();
    let name = text(entry, "displayName");
    Gpo {
        dn: entry.dn.clone(),
        name: if name.is_empty() { guid.clone() } else { name },
        flags: number(entry, "flags"),
        version: number(entry, "versionNumber"),
        path: text(entry, "gPCFileSysPath"),
        computer_extensions: text(entry, "gPCMachineExtensionNames"),
        user_extensions: text(entry, "gPCUserExtensionNames"),
        wmi_filter: text(entry, "gPCWQLFilter"),
        created: date(entry, "whenCreated"),
        modified: date(entry, "whenChanged"),
        descriptor: entry
            .values("nTSecurityDescriptor")
            .first()
            .and_then(|v| SecurityDescriptor::decode(v).ok()),
        guid,
    }
}

pub fn container_from_entry(entry: &Entry) -> Container {
    let classes: Vec<String> = entry
        .values("objectClass")
        .iter()
        .map(|v| String::from_utf8_lossy(v).to_lowercase())
        .collect();
    let has = |c: &str| classes.iter().any(|x| x == c);
    let class = if has("domaindns") {
        "domainDNS"
    } else if has("organizationalunit") {
        "organizationalUnit"
    } else if has("site") {
        "site"
    } else {
        "container"
    };
    let gplink = entry
        .values("gPLink")
        .first()
        .map_or_else(GpLink::default, |v| {
            GpLink::decode(v).unwrap_or_else(|_| GpLink::parse(&String::from_utf8_lossy(v)))
        });
    let name = text(entry, "name");
    Container {
        dn: entry.dn.clone(),
        name: if name.is_empty() {
            name_from_dn(&entry.dn)
        } else {
            name
        },
        class: class.to_owned(),
        gplink,
        gpoptions: number(entry, "gPOptions"),
    }
}

// --- Security filtering --------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Access {
    pub read: bool,
    pub apply: bool,
}

impl Access {
    pub fn applies(self) -> bool {
        self.read && self.apply
    }
}

/// Does the ACE quote this right (for this object type if there is one)?
fn counts_for(ace: &sd::Ace, right: u32, object_type: Option<&Guid>) -> bool {
    let mask = sd::translate_generic(ace.mask());
    if mask & right == 0 {
        return false;
    }
    match (ace.is_object(), ace.object_type()) {
        (true, Some(t)) => object_type == Some(&t),
        _ => true,
    }
}

/// Reading (`RP` on the whole object) and application (`CR` « Apply group policy ») granted to
/// the token `sids`, as `AccessCheck`: first decisive ACE (`acces`).
pub fn access(descriptor: Option<&SecurityDescriptor>, sids: &HashSet<Sid>) -> Access {
    let Some(descriptor) = descriptor else {
        // Unreadable descriptor: unknown, and an account that does not read the DACL does not
        // read the GPO either.
        return Access {
            read: false,
            apply: false,
        };
    };
    let Some(dacl) = &descriptor.dacl else {
        // No DACL: everything is allowed (MS-DTYP 2.4.6).
        return Access {
            read: true,
            apply: true,
        };
    };
    let apply_right = right_apply();
    let (mut read, mut apply): (Option<bool>, Option<bool>) = (None, None);
    for ace in &dacl.aces {
        if !ace.is_readable() || !ace.sid().is_some_and(|s| sids.contains(&s)) {
            continue;
        }
        if ace.flags & sd::INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if !(ace.is_deny() || ace.is_allow()) {
            continue;
        }
        if read.is_none() && counts_for(ace, sd::ADS_RIGHT_DS_READ_PROP, None) {
            read = Some(!ace.is_deny());
        }
        if apply.is_none() && counts_for(ace, sd::ADS_RIGHT_DS_CONTROL_ACCESS, Some(&apply_right)) {
            apply = Some(!ace.is_deny());
        }
        if read.is_some() && apply.is_some() {
            break;
        }
    }
    Access {
        read: read.unwrap_or(false),
        apply: apply.unwrap_or(false),
    }
}

/// SIDs the access check of the client sees: the account, its groups, and the identities
/// Windows adds to any session (plus Interactive for a user) (`jeton`).
pub fn token(sid: &Sid, groups: &[Sid], part: Part) -> HashSet<Sid> {
    let mut out: HashSet<Sid> = groups.iter().copied().collect();
    out.insert(*sid);
    for added in ["S-1-1-0", "S-1-5-11", "S-1-5-15"] {
        out.extend(well_known(added));
    }
    if part == Part::User {
        out.extend(well_known("S-1-5-4"));
    }
    out
}

/// What the DACL grants or denies to a SID, for the security filtering (`DroitFiltrage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterRight {
    pub sid: Sid,
    pub read: bool,
    pub apply: bool,
    /// A denial of reading or application: the SID is excluded from the GPO.
    pub deny: bool,
}

impl FilterRight {
    pub fn applies(self) -> bool {
        self.read && self.apply && !self.deny
    }
}

/// The SIDs quoted by ACEs of reading or application, with what they give them taken alone
/// (the « Filtering » tab of the GPMC shows only those that have both); in the order of their
/// first ACE (`filtrage`).
pub fn filtering(descriptor: Option<&SecurityDescriptor>) -> Vec<FilterRight> {
    let Some(dacl) = descriptor.and_then(|d| d.dacl.as_ref()) else {
        return Vec::new();
    };
    let apply_right = right_apply();
    let quotes = |ace: &sd::Ace| {
        counts_for(ace, sd::ADS_RIGHT_DS_READ_PROP, None)
            || counts_for(ace, sd::ADS_RIGHT_DS_CONTROL_ACCESS, Some(&apply_right))
    };
    let mut order: Vec<Sid> = Vec::new();
    for ace in &dacl.aces {
        let Some(sid) = ace.sid().filter(|_| ace.is_readable()) else {
            continue;
        };
        if order.contains(&sid) || ace.flags & sd::INHERIT_ONLY_ACE != 0 {
            continue;
        }
        if quotes(ace) {
            order.push(sid);
        }
    }
    order
        .into_iter()
        .map(|sid| {
            let a = access(descriptor, &HashSet::from([sid]));
            let deny = dacl.aces.iter().any(|ace| {
                ace.is_readable()
                    && ace.is_deny()
                    && ace.sid() == Some(sid)
                    && ace.flags & sd::INHERIT_ONLY_ACE == 0
                    && quotes(ace)
            });
            FilterRight {
                sid,
                read: a.read,
                apply: a.apply,
                deny,
            }
        })
        .collect()
}

// --- SYSVOL: comparison -----------------------------------------------------------------------

/// The folder of a GPO on a DC (`SysvolGpo`): `present` false if missing; `gpt` None if
/// GPT.INI is missing or unreadable; `files`: paths relative to the folder → size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysvolGpo {
    pub guid: String,
    pub present: bool,
    pub gpt: Option<GptIni>,
    pub files: Vec<(String, u64)>,
    pub unreadable: Vec<String>,
}

impl SysvolGpo {
    fn absent(guid: &str) -> Self {
        Self {
            guid: guid.to_uppercase(),
            present: false,
            gpt: None,
            files: Vec::new(),
            unreadable: Vec::new(),
        }
    }
}

/// Why the SYSVOL of a DC could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SysvolReadError {
    /// No `Policies` folder in the SYSVOL of the DC.
    NoPolicies,
    Sysvol(sysvol::SysvolError),
}

/// The SYSVOL of a DC read for the inventory (`SysvolDc`): the `{GUID}` folders of
/// `Policies`, by GUID in upper case. `error`: DC unreadable (nothing else is sure).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysvolDc {
    pub dc: String,
    pub folders: HashMap<String, SysvolGpo>,
    pub error: Option<SysvolReadError>,
    pub round_trips: u64,
    /// GUID in upper case → name of the folder as written (original case).
    pub names: HashMap<String, String>,
}

impl SysvolDc {
    fn failed(dc: &str, error: SysvolReadError) -> Self {
        Self {
            dc: dc.to_owned(),
            folders: HashMap::new(),
            error: Some(error),
            round_trips: 0,
            names: HashMap::new(),
        }
    }

    /// The folder of a GPO (absent: `present` false); None if the DC was not read.
    pub fn folder(&self, guid: &str) -> Option<SysvolGpo> {
        if self.error.is_some() {
            return None;
        }
        Some(
            self.folders
                .get(&guid.to_uppercase())
                .cloned()
                .unwrap_or_else(|| SysvolGpo::absent(guid)),
        )
    }

    /// `{GUID}` folders without a GPO object in the directory, under their written name,
    /// sorted (`orphelins`).
    pub fn orphans<'a>(&self, guids: impl IntoIterator<Item = &'a String>) -> Vec<String> {
        let known: HashSet<String> = guids.into_iter().map(|g| g.to_uppercase()).collect();
        let mut out: Vec<String> = self
            .folders
            .keys()
            .filter(|g| !known.contains(*g))
            .map(|g| self.names.get(g).cloned().unwrap_or_else(|| g.clone()))
            .collect();
        out.sort();
        out
    }
}

/// A deviation between the two halves of a GPO, or between a DC and the PDC, said by the
/// interface (`ecarts_versions`, `comparer_dossiers`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Deviation {
    FolderMissing,
    GptMissing,
    GptUnreadable(GptError),
    /// Directory and GPT.INI versions differ.
    Versions {
        directory: Versions,
        sysvol: Versions,
    },
    AbsentOn {
        dc: String,
    },
    OnlyOn {
        dc: String,
    },
    GptVersionOn {
        dc: String,
        found: Option<i64>,
        reference: Option<i64>,
    },
    /// Files missing on `dc`: their number and the first three.
    MissingFiles {
        dc: String,
        n: usize,
        first: Vec<String>,
    },
    ExtraFiles {
        dc: String,
        n: usize,
        first: Vec<String>,
    },
    OtherSize {
        dc: String,
        n: usize,
        first: Vec<String>,
    },
    /// A deviation of the GPO named `name` (comparison of a DC).
    Of {
        name: String,
        deviation: Box<Deviation>,
    },
    /// The folders without a GPO differ from those of the PDC.
    OrphansDiffer {
        names: Vec<String>,
    },
    /// The DC could not be read.
    Unreadable(SysvolReadError),
}

/// Deviations between the directory half and the SYSVOL half of a GPO (empty: none)
/// (`ecarts_versions`).
pub fn version_deviations(gpo: &Gpo, folder: Option<&SysvolGpo>) -> Vec<Deviation> {
    let Some(folder) = folder else {
        return Vec::new();
    };
    if !folder.present {
        return vec![Deviation::FolderMissing];
    }
    let Some(gpt) = &folder.gpt else {
        return vec![Deviation::GptMissing];
    };
    match gpt.version {
        None => vec![Deviation::GptUnreadable(
            gpt.error.clone().unwrap_or(GptError::NoVersion),
        )],
        Some(v) if v != gpo.version => vec![Deviation::Versions {
            directory: gpo.versions(),
            sysvol: versions(v),
        }],
        Some(_) => Vec::new(),
    }
}

fn first_three(mut list: Vec<String>) -> (usize, Vec<String>) {
    list.sort();
    let n = list.len();
    list.truncate(3);
    (n, list)
}

/// Differences of the folder of a GPO on `dc` from the PDC: presence, version of GPT.INI,
/// files missing, extra or of another size (names without case) (`comparer_dossiers`).
pub fn compare_folders(reference: &SysvolGpo, other: &SysvolGpo, dc: &str) -> Vec<Deviation> {
    if !reference.present && !other.present {
        return Vec::new();
    }
    if !other.present {
        return vec![Deviation::AbsentOn { dc: dc.to_owned() }];
    }
    if !reference.present {
        return vec![Deviation::OnlyOn { dc: dc.to_owned() }];
    }
    let mut out = Vec::new();
    let version = |f: &SysvolGpo| f.gpt.as_ref().and_then(|g| g.version);
    let (vr, va) = (version(reference), version(other));
    if vr != va {
        out.push(Deviation::GptVersionOn {
            dc: dc.to_owned(),
            found: va,
            reference: vr,
        });
    }
    let index = |f: &SysvolGpo| -> HashMap<String, (String, u64)> {
        f.files
            .iter()
            .map(|(k, t)| (k.to_lowercase(), (k.clone(), *t)))
            .collect()
    };
    let (r, a) = (index(reference), index(other));
    let missing: Vec<String> = r
        .iter()
        .filter(|(k, _)| !a.contains_key(*k))
        .map(|(_, (n, _))| n.clone())
        .collect();
    let extra: Vec<String> = a
        .iter()
        .filter(|(k, _)| !r.contains_key(*k))
        .map(|(_, (n, _))| n.clone())
        .collect();
    let sizes: Vec<String> = r
        .iter()
        .filter(|(k, (_, t))| a.get(*k).is_some_and(|(_, u)| u != t))
        .map(|(_, (n, _))| n.clone())
        .collect();
    let dc = dc.to_owned();
    if !missing.is_empty() {
        let (n, first) = first_three(missing);
        out.push(Deviation::MissingFiles {
            dc: dc.clone(),
            n,
            first,
        });
    }
    if !extra.is_empty() {
        let (n, first) = first_three(extra);
        out.push(Deviation::ExtraFiles {
            dc: dc.clone(),
            n,
            first,
        });
    }
    if !sizes.is_empty() {
        let (n, first) = first_three(sizes);
        out.push(Deviation::OtherSize { dc, n, first });
    }
    out
}

/// Is the name the one of a folder of a GPO, `{GUID}` (any case) (`est_guid_de_dossier`)?
pub fn is_folder_guid(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.len() != 38 || bytes.first() != Some(&b'{') || bytes.last() != Some(&b'}') {
        return false;
    }
    bytes
        .get(1..37)
        .unwrap_or_default()
        .iter()
        .enumerate()
        .all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                *b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

/// Pure: walk of `<domain>\Policies` and contents of GPT.INI (key: GUID in upper case) →
/// `SysvolDc`. Only the folders named `{GUID}` count (`sysvol_depuis_parcours`).
pub fn sysvol_from_walk(
    dc: &str,
    tree: &sysvol::Tree,
    gpt: &HashMap<String, Option<Vec<u8>>>,
    round_trips: u64,
) -> SysvolDc {
    if !tree.present {
        return SysvolDc::failed(dc, SysvolReadError::NoPolicies);
    }
    let mut by_gpo: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    let mut names: HashMap<String, String> = HashMap::new();
    for entry in &tree.entries {
        let (head, rest) = entry.path.split_once('\\').unwrap_or((&entry.path, ""));
        let k = head.to_uppercase();
        if rest.is_empty() {
            if entry.directory && is_folder_guid(head) {
                names.insert(k.clone(), head.to_owned());
                by_gpo.entry(k).or_default();
            }
            continue;
        }
        if !entry.directory && names.contains_key(&k) {
            by_gpo
                .entry(k)
                .or_default()
                .push((rest.to_owned(), entry.size));
        }
    }
    let mut unreadable: HashMap<String, Vec<String>> = HashMap::new();
    for path in &tree.unreadable {
        let (head, rest) = path.split_once('\\').unwrap_or((path, ""));
        let shown = if rest.is_empty() { head } else { rest };
        unreadable
            .entry(head.to_uppercase())
            .or_default()
            .push(shown.to_owned());
    }
    let folders = names
        .keys()
        .map(|guid| {
            let folder = SysvolGpo {
                guid: guid.clone(),
                present: true,
                gpt: gpt.get(guid).cloned().flatten().map(|b| read_gpt_ini(&b)),
                files: by_gpo.remove(guid).unwrap_or_default(),
                unreadable: unreadable.remove(guid).unwrap_or_default(),
            };
            (guid.clone(), folder)
        })
        .collect();
    SysvolDc {
        dc: dc.to_owned(),
        folders,
        error: None,
        round_trips,
        names,
    }
}

/// Blocking (a thread apart): `\\<dc>\SYSVOL\<domain>\Policies` walked entirely, then the
/// GPT.INI of each `{GUID}` folder, in compound requests (ADR 0002). Does not depend on the
/// directory: read at the same time as it. An error is kept in `SysvolDc.error`
/// (`lire_sysvol_au_mieux`).
pub fn read_sysvol(opener: &crate::sysvol_write::Opener, dc: &str, domain: &str) -> SysvolDc {
    let root = format!("{domain}\\Policies");
    let mut session = match opener(dc) {
        Ok(s) => s,
        Err(e) => return SysvolDc::failed(dc, SysvolReadError::Sysvol(e)),
    };
    let read = (|| -> sysvol::Result<SysvolDc> {
        let tree = session
            .walk(std::slice::from_ref(&root))?
            .into_iter()
            .next()
            .unwrap_or(sysvol::Tree {
                root: root.clone(),
                present: false,
                entries: Vec::new(),
                unreadable: Vec::new(),
            });
        let mut gpt_files: Vec<(String, String)> = Vec::new();
        for entry in &tree.entries {
            if let Some((head, rest)) = entry.path.split_once('\\')
                && !entry.directory
                && rest.eq_ignore_ascii_case("gpt.ini")
                && is_folder_guid(head)
            {
                gpt_files.push((head.to_uppercase(), format!("{root}\\{}", entry.path)));
            }
        }
        let paths: Vec<String> = gpt_files.iter().map(|(_, p)| p.clone()).collect();
        let contents = if paths.is_empty() {
            Vec::new()
        } else {
            session.read(&paths)?
        };
        let gpt: HashMap<String, Option<Vec<u8>>> = gpt_files
            .into_iter()
            .map(|(g, _)| g)
            .zip(contents)
            .collect();
        Ok(sysvol_from_walk(dc, &tree, &gpt, session.round_trips()))
    })();
    session.close();
    read.unwrap_or_else(|e| SysvolDc::failed(dc, SysvolReadError::Sysvol(e)))
}

// --- What the directory says of the GPOs -----------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WmiFilter {
    pub guid: String,
    pub name: String,
    pub query: String,
}

/// What the directory says of the GPOs of a domain, read in one operation (`AnnuaireGpo`).
#[derive(Debug, Clone)]
pub struct GpoDirectory {
    /// DN of the domain.
    pub domain: String,
    pub dns_name: String,
    /// By GUID (`{…}` in upper case).
    pub gpos: HashMap<String, Gpo>,
    /// Domain and every OU, in the order of the tree (parent before children).
    pub containers: Vec<Container>,
    pub linked_sites: Vec<Container>,
    pub wmi_filters: HashMap<String, WmiFilter>,
    pub dcs: Vec<String>,
    /// DC that answered.
    pub dc: String,
    /// Names of the SIDs quoted by the DACLs of the GPOs (filtering); empty when read without.
    pub names: HashMap<Sid, crate::security::SidName>,
}

impl GpoDirectory {
    pub fn gpo_of_link(&self, link: &Link) -> Option<&Gpo> {
        link.guid().and_then(|g| self.gpos.get(&g))
    }
}

pub fn dns_name(domain_dn: &str) -> String {
    dn::split(domain_dn)
        .unwrap_or_default()
        .iter()
        .filter(|c| c.attribute.eq_ignore_ascii_case("dc"))
        .map(|c| c.value.as_str())
        .collect::<Vec<_>>()
        .join(".")
}

fn depth(dn_text: &str) -> usize {
    dn::split(dn_text).map_or(0, |c| c.len())
}

/// A complete paged search **on the thread of the connection** (one operation)
/// (`_chercher_tout`).
pub(crate) fn search_all(
    link: &mut LdapLink,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
    controls: &[Control],
) -> Result<Vec<Entry>, LdapError> {
    let mut entries = Vec::new();
    let mut cookie: Vec<u8> = Vec::new();
    loop {
        let mut all_controls = vec![search::paged_control(crate::source::PAGE_SIZE, &cookie)];
        all_controls.extend(controls.iter().cloned());
        let request = SearchRequest {
            base: base.to_owned(),
            scope,
            filter: filter.to_owned(),
            attributes: attributes.iter().map(|&a| a.to_owned()).collect(),
            controls: all_controls,
            size_limit: 0,
        };
        let response = link.session.search_wait(request, Some(link.timeout))?;
        cookie = search::paged_cookie(&response);
        entries.extend(response.into_entries());
        if cookie.is_empty() {
            return Ok(entries);
        }
    }
}

fn absent_is_empty(read: Result<Vec<Entry>, LdapError>) -> Result<Vec<Entry>, LdapError> {
    match read {
        Err(e) if e.code == code::NO_SUCH_OBJECT && !e.foreign => Ok(Vec::new()),
        other => other,
    }
}

/// On the thread of the connection: GPOs (descriptor included), domain and OUs with their
/// links, linked sites, WMI filters, DCs of the domain (`lire_annuaire_gpo`, without the
/// names of the SIDs).
pub fn read_gpo_directory(link: &mut LdapLink) -> Result<GpoDirectory, LdapError> {
    let root = link.state.root_dse.clone();
    let domain = root.default_naming_context.clone();
    let sd_control = search::sd_flags_control(SD_WITHOUT_SACL);
    let mut gpos = HashMap::new();
    for entry in search_all(
        link,
        &format!("CN=Policies,CN=System,{domain}"),
        Scope::OneLevel,
        GPO_FILTER,
        &GPO_ATTRIBUTES,
        &[sd_control],
    )? {
        let gpo = gpo_from_entry(&entry);
        gpos.insert(gpo.guid.clone(), gpo);
    }
    let mut containers: Vec<Container> = search_all(
        link,
        &domain,
        Scope::Subtree,
        CONTAINERS_FILTER,
        &CONTAINER_ATTRIBUTES,
        &[],
    )?
    .iter()
    .map(container_from_entry)
    .collect();
    containers.sort_by_cached_key(|c| {
        dn::split(&c.dn)
            .unwrap_or_default()
            .iter()
            .rev()
            .map(|x| x.value.to_lowercase())
            .collect::<Vec<_>>()
    });
    let linked_sites = absent_is_empty(search_all(
        link,
        &format!("CN=Sites,{}", root.configuration_naming_context),
        Scope::OneLevel,
        LINKS_FILTER,
        &CONTAINER_ATTRIBUTES,
        &[],
    ))?
    .iter()
    .map(container_from_entry)
    .collect();
    let mut wmi_filters = HashMap::new();
    for e in absent_is_empty(search_all(
        link,
        &format!("CN=SOM,CN=WMIPolicy,CN=System,{domain}"),
        Scope::OneLevel,
        "(objectClass=msWMI-Som)",
        &["msWMI-ID", "msWMI-Name", "msWMI-Parm2"],
        &[],
    ))? {
        let guid = text(&e, "msWMI-ID").to_uppercase();
        if !guid.is_empty() {
            wmi_filters.insert(
                guid.clone(),
                WmiFilter {
                    guid,
                    name: text(&e, "msWMI-Name"),
                    query: text(&e, "msWMI-Parm2"),
                },
            );
        }
    }
    let mut dcs: Vec<String> = search_all(
        link,
        &domain,
        Scope::Subtree,
        queries::DCS,
        &["dNSHostName"],
        &[],
    )?
    .iter()
    .map(|e| text(e, "dNSHostName").to_lowercase())
    .filter(|n| !n.is_empty())
    .collect();
    dcs.sort();
    dcs.dedup();
    Ok(GpoDirectory {
        dns_name: dns_name(&domain),
        domain,
        gpos,
        containers,
        linked_sites,
        wmi_filters,
        dcs,
        dc: link.state.dc.clone(),
        names: HashMap::new(),
    })
}

/// `read_gpo_directory` with the names of the SIDs of the filtering (`lire_annuaire_gpo`).
pub fn read_gpo_directory_named(link: &mut LdapLink) -> Result<GpoDirectory, LdapError> {
    let mut directory = read_gpo_directory(link)?;
    let sids: HashSet<Sid> = directory
        .gpos
        .values()
        .flat_map(|g| filtering(g.descriptor.as_ref()))
        .map(|f| f.sid)
        .collect();
    directory.names = crate::security::resolve_sids(link, &directory.domain, &sids)?;
    Ok(directory)
}

/// What the directory says of the GPOs, on the connection (the PDC emulator for the write
/// connection) (`lire_annuaire`). Blocking.
pub fn read_directory(connection: &Connection) -> Result<GpoDirectory, Failure> {
    connection.run(true, read_gpo_directory_named)
}

/// The SYSVOL of the DC of the connection (the PDC for the write connection)
/// (`lire_sysvol_pdc`). Blocking.
pub fn read_pdc_sysvol(connection: &Connection) -> Result<SysvolDc, Failure> {
    let (dc, domain, protection) = connection.run(true, |link| {
        Ok((
            link.state.dc.clone(),
            link.state.root_dse.default_naming_context.clone(),
            link.sysvol,
        ))
    })?;
    Ok(read_sysvol(
        &crate::sysvol_write::opener(protection),
        &dc,
        &dns_name(&domain),
    ))
}

/// The SYSVOL of each other DC of the domain, read at the same time (a thread per DC)
/// (`comparer_dcs`). Blocking.
pub fn compare_dcs(
    directory: &GpoDirectory,
    pdc: &str,
    protection: sysvol::Protection,
) -> Vec<SysvolDc> {
    let opener = crate::sysvol_write::opener(protection);
    let others: Vec<&String> = directory
        .dcs
        .iter()
        .filter(|dc| !dc.eq_ignore_ascii_case(pdc))
        .collect();
    std::thread::scope(|scope| {
        let handles: Vec<_> = others
            .iter()
            .map(|dc| {
                let opener = &opener;
                scope.spawn(move || read_sysvol(opener, dc, &directory.dns_name))
            })
            .collect();
        handles
            .into_iter()
            .zip(others.iter())
            .map(|(h, dc)| {
                h.join().unwrap_or_else(|_| {
                    SysvolDc::failed(
                        dc,
                        SysvolReadError::Sysvol(sysvol::SysvolError::status(0, "")),
                    )
                })
            })
            .collect()
    })
}

// --- Inventory ----------------------------------------------------------------------------------

/// Directory, SYSVOL of the DC that answered (the PDC), and of the other DCs once read
/// (`Inventaire`).
#[derive(Debug, Clone)]
pub struct Inventory {
    pub directory: GpoDirectory,
    pub sysvol: SysvolDc,
    pub others: Vec<SysvolDc>,
}

impl Inventory {
    /// Alerts of a GPO: directory / SYSVOL versions, then the SYSVOL of the other DCs
    /// (`ecarts`).
    pub fn deviations(&self, guid: &str) -> Vec<Deviation> {
        let Some(gpo) = self.directory.gpos.get(guid) else {
            return Vec::new();
        };
        let reference = self.sysvol.folder(guid);
        let mut alerts = version_deviations(gpo, reference.as_ref());
        for other in &self.others {
            if let (Some(r), Some(f)) = (&reference, other.folder(guid)) {
                alerts.extend(compare_folders(r, &f, &other.dc));
            }
        }
        alerts
    }

    /// `{GUID}` folders of the SYSVOL of the PDC without a GPO object in the directory
    /// (written names) (`orphelins`). The directory and the SYSVOL are read at the same time:
    /// a GPO created between the two may look orphaned; the deletion reads the directory
    /// again.
    pub fn orphans(&self) -> Vec<String> {
        if self.sysvol.error.is_some() {
            return Vec::new();
        }
        self.sysvol.orphans(self.directory.gpos.keys())
    }

    fn by_name(&self) -> Vec<&Gpo> {
        let mut gpos: Vec<&Gpo> = self.directory.gpos.values().collect();
        gpos.sort_by_cached_key(|g| g.name.to_lowercase());
        gpos
    }

    /// GUIDs of the GPOs whose folder is missing in the SYSVOL of the PDC, by name
    /// (`sans_dossier`).
    pub fn without_folder(&self) -> Vec<String> {
        if self.sysvol.error.is_some() {
            return Vec::new();
        }
        self.by_name()
            .into_iter()
            .filter(|g| !self.sysvol.folders.get(&g.guid).is_some_and(|f| f.present))
            .map(|g| g.guid.clone())
            .collect()
    }

    /// Summary of the comparison of a DC with the PDC, orphan folders included (`ecarts_dc`).
    pub fn dc_deviations(&self, other: &SysvolDc) -> Vec<Deviation> {
        if let Some(e) = &other.error {
            return vec![Deviation::Unreadable(e.clone())];
        }
        let mut alerts = Vec::new();
        for gpo in self.by_name() {
            if let (Some(r), Some(f)) = (self.sysvol.folder(&gpo.guid), other.folder(&gpo.guid)) {
                for d in compare_folders(&r, &f, &other.dc) {
                    alerts.push(Deviation::Of {
                        name: gpo.name.clone(),
                        deviation: Box::new(d),
                    });
                }
            }
        }
        let here: HashSet<String> = self
            .sysvol
            .orphans(self.directory.gpos.keys())
            .into_iter()
            .collect();
        let there: HashSet<String> = other
            .orphans(self.directory.gpos.keys())
            .into_iter()
            .collect();
        if self.sysvol.error.is_none() && here != there {
            let mut names: Vec<String> = here.symmetric_difference(&there).cloned().collect();
            names.sort_by_cached_key(|n| n.to_lowercase());
            alerts.push(Deviation::OrphansDiffer { names });
        }
        alerts
    }
}

// --- Resultant policy --------------------------------------------------------------------------

/// Fate of a link in the resultant policy (`Motif`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    Applied,
    LinkDisabled,
    InheritanceBlocked,
    NotFound,
    OtherDomain,
    Security,
    Disabled,
    Empty,
}

/// A link met on the path of the account and what it becomes (`LigneRsop`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsopLine {
    pub link: Link,
    pub container: Container,
    pub gpo: Option<Gpo>,
    pub reason: Reason,
    /// 1 = wins over all the others; 0 for a GPO not applied.
    pub priority: usize,
    pub wmi_not_evaluated: bool,
    pub wmi_name: String,
}

impl RsopLine {
    fn new(link: &Link, container: &Container, gpo: Option<&Gpo>, reason: Reason) -> Self {
        Self {
            link: link.clone(),
            container: container.clone(),
            gpo: gpo.cloned(),
            reason,
            priority: 0,
            wmi_not_evaluated: false,
            wmi_name: String::new(),
        }
    }

    pub fn name(&self) -> String {
        match &self.gpo {
            Some(gpo) => gpo.name.clone(),
            None => self.link.guid().unwrap_or_else(|| self.link.dn.clone()),
        }
    }

    fn key(&self) -> String {
        self.link
            .guid()
            .unwrap_or_else(|| self.link.dn.to_lowercase())
    }
}

/// Loopback mode of a computer (`Boucle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loopback {
    None,
    Merge,
    Replace,
}

/// A remark of the resultant policy, said by the interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Remark {
    /// GPOs are linked to sites: not evaluated.
    SitesLinked,
    /// WMI filters not evaluated.
    WmiNotEvaluated,
    /// The loopback processing of `computer`, set by the GPO named `gpo`.
    Loopback {
        mode: Loopback,
        gpo: String,
        computer: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultantPolicy {
    pub part: Part,
    /// DN of the account or of the computer.
    pub account: String,
    /// DN of its container.
    pub location: String,
    /// By priority: the first wins.
    pub applied: Vec<RsopLine>,
    /// GPOs filtered out (security, disabled, empty, not found), in the order of processing.
    pub discarded: Vec<RsopLine>,
    /// Links that do not enter the list: disabled, inheritance blocked.
    pub ignored: Vec<RsopLine>,
    pub remarks: Vec<Remark>,
}

/// DN of the containers of the domain up to the parent of `dn`, from the domain to the parent
/// (`chemin_conteneurs`).
pub fn container_path(dn_text: &str, domain: &str) -> Vec<String> {
    let Ok(components) = dn::split(dn_text) else {
        return Vec::new();
    };
    let domain_depth = depth(domain);
    let mut path: Vec<String> = (1..=components.len().saturating_sub(domain_depth))
        .filter_map(|i| dn::compose(components.get(i..).unwrap_or_default()).ok())
        .collect();
    path.reverse();
    path
}

/// Inputs of `compute`.
#[derive(Debug)]
pub struct Inputs<'a> {
    pub part: Part,
    pub account: &'a str,
    pub sids: &'a HashSet<Sid>,
    /// Containers from the domain to the parent of the account (those without links too:
    /// they may block the inheritance).
    pub path: &'a [Container],
    pub gpos: &'a HashMap<String, Gpo>,
    pub domain_dns: &'a str,
    pub sites_linked: bool,
    pub wmi_filters: &'a HashMap<String, WmiFilter>,
}

/// Pure (`calculer`).
pub fn compute(inputs: &Inputs<'_>) -> ResultantPolicy {
    let domain_dn = inputs
        .domain_dns
        .to_lowercase()
        .split('.')
        .map(|p| format!("dc={p}"))
        .collect::<Vec<_>>()
        .join(",");
    let gpo_of = |link: &Link| link.guid().and_then(|g| inputs.gpos.get(&g));
    let mut ignored = Vec::new();
    // Links kept, from the nearest container to the domain; then the order of processing.
    let mut blocked = false;
    let mut normal: Vec<(&Container, Vec<&Link>)> = Vec::new();
    let mut enforced: Vec<(&Container, Vec<&Link>)> = Vec::new();
    for container in inputs.path.iter().rev() {
        let (mut kept_n, mut kept_e) = (Vec::new(), Vec::new());
        for link in container.gplink.links() {
            if link.disabled() {
                ignored.push(RsopLine::new(
                    link,
                    container,
                    gpo_of(link),
                    Reason::LinkDisabled,
                ));
            } else if link.enforced() {
                kept_e.push(link);
            } else if blocked {
                ignored.push(RsopLine::new(
                    link,
                    container,
                    gpo_of(link),
                    Reason::InheritanceBlocked,
                ));
            } else {
                kept_n.push(link);
            }
        }
        normal.push((container, kept_n));
        enforced.push((container, kept_e));
        if container.inheritance_blocked() {
            blocked = true;
        }
    }
    let processing: Vec<(&Container, &Link)> = normal
        .iter()
        .rev()
        .flat_map(|(c, links)| links.iter().map(move |l| (*c, *l)))
        .chain(
            enforced
                .iter()
                .flat_map(|(c, links)| links.iter().map(move |l| (*c, *l))),
        )
        .collect();
    // A GPO linked twice counts once, at its strongest place (the last).
    let mut seen = HashSet::new();
    let mut unique: Vec<(&Container, &Link)> = Vec::new();
    for (container, link) in processing.iter().rev() {
        let key = link.guid().unwrap_or_else(|| link.dn.to_lowercase());
        if seen.insert(key) {
            unique.push((container, link));
        }
    }
    unique.reverse();

    let mut kept = Vec::new();
    let mut discarded = Vec::new();
    for (container, link) in unique {
        let Some(gpo) = gpo_of(link) else {
            let reason = if link.domain() == domain_dn {
                Reason::NotFound
            } else {
                Reason::OtherDomain
            };
            discarded.push(RsopLine::new(link, container, None, reason));
            continue;
        };
        if !access(gpo.descriptor.as_ref(), inputs.sids).applies() {
            discarded.push(RsopLine::new(link, container, Some(gpo), Reason::Security));
            continue;
        }
        if gpo.disabled(inputs.part) {
            discarded.push(RsopLine::new(link, container, Some(gpo), Reason::Disabled));
            continue;
        }
        if gpo.versions().of(inputs.part) == 0 {
            discarded.push(RsopLine::new(link, container, Some(gpo), Reason::Empty));
            continue;
        }
        let mut line = RsopLine::new(link, container, Some(gpo), Reason::Applied);
        if let Some(guid) = gpo.wmi_guid() {
            line.wmi_not_evaluated = true;
            line.wmi_name = inputs
                .wmi_filters
                .get(&guid)
                .map_or(guid, |f| f.name.clone());
        }
        kept.push(line);
    }
    let applied: Vec<RsopLine> = kept
        .into_iter()
        .rev()
        .enumerate()
        .map(|(i, mut line)| {
            line.priority = i + 1;
            line
        })
        .collect();
    let mut remarks = Vec::new();
    if inputs.sites_linked {
        remarks.push(Remark::SitesLinked);
    }
    if applied.iter().any(|l| l.wmi_not_evaluated) {
        remarks.push(Remark::WmiNotEvaluated);
    }
    ResultantPolicy {
        part: inputs.part,
        account: inputs.account.to_owned(),
        location: inputs.path.last().map(|c| c.dn.clone()).unwrap_or_default(),
        applied,
        discarded,
        ignored,
        remarks,
    }
}

/// What must be read to compute the policy of an account (`DonneesRsop`).
#[derive(Debug, Clone)]
pub struct RsopData {
    pub account: String,
    pub classes: Vec<String>,
    pub sid: Option<Sid>,
    pub groups: Vec<Sid>,
    pub path: Vec<Container>,
    pub directory: GpoDirectory,
}

impl RsopData {
    pub fn part(&self) -> Part {
        if self
            .classes
            .iter()
            .any(|c| c.eq_ignore_ascii_case("computer"))
        {
            Part::Computer
        } else {
            Part::User
        }
    }

    fn token(&self, part: Part) -> HashSet<Sid> {
        self.sid
            .map(|sid| token(&sid, &self.groups, part))
            .unwrap_or_default()
    }

    pub fn compute(&self, part: Option<Part>) -> ResultantPolicy {
        let part = part.unwrap_or_else(|| self.part());
        self.compute_on(part, &self.token(part), &self.path)
    }

    fn compute_on(&self, part: Part, sids: &HashSet<Sid>, path: &[Container]) -> ResultantPolicy {
        compute(&Inputs {
            part,
            account: &self.account,
            sids,
            path,
            gpos: &self.directory.gpos,
            domain_dns: &self.directory.dns_name,
            sites_linked: !self.directory.linked_sites.is_empty(),
            wmi_filters: &self.directory.wmi_filters,
        })
    }
}

/// On the thread of the connection: the account (SID, `tokenGroups`), the containers of its
/// path and what the directory says of the GPOs (`lire_donnees_rsop`).
pub fn read_rsop_data(link: &mut LdapLink, dn_text: &str) -> Result<RsopData, LdapError> {
    let attributes: Vec<String> = ["objectClass", "objectSid", "tokenGroups"]
        .iter()
        .map(|&a| a.to_owned())
        .collect();
    let entry = search::read_entry(
        link.session.as_mut(),
        dn_text,
        &attributes,
        "(objectClass=*)",
        None,
        Some(link.timeout),
    )?
    .ok_or_else(|| LdapError::new(code::NO_SUCH_OBJECT, "objet introuvable"))?;
    let directory = read_gpo_directory(link)?;
    let by_dn: HashMap<String, &Container> = directory
        .containers
        .iter()
        .map(|c| (c.dn.to_lowercase(), c))
        .collect();
    let path = container_path(&entry.dn, &directory.domain)
        .into_iter()
        .map(|parent| {
            by_dn.get(&parent.to_lowercase()).map_or_else(
                // A container that is neither the domain nor an OU (CN=Users, CN=Computers):
                // it carries no links (MS-GPOL), but it is on the path.
                || Container {
                    name: name_from_dn(&parent),
                    dn: parent.clone(),
                    class: "container".into(),
                    gplink: GpLink::default(),
                    gpoptions: 0,
                },
                |c| (*c).clone(),
            )
        })
        .collect();
    Ok(RsopData {
        account: entry.dn.clone(),
        classes: entry
            .values("objectClass")
            .iter()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect(),
        sid: entry
            .values("objectSid")
            .first()
            .and_then(|v| Sid::decode(v).ok()),
        groups: entry
            .values("tokenGroups")
            .iter()
            .filter_map(|v| Sid::decode(v).ok())
            .collect(),
        path,
        directory,
    })
}

/// `lire_rsop`. Blocking.
pub fn read_rsop(connection: &Connection, dn_text: &str) -> Result<RsopData, Failure> {
    let dn_text = dn_text.to_owned();
    connection.run(true, move |link| read_rsop_data(link, &dn_text))
}

// --- Loopback processing ---------------------------------------------------------------------

pub const LOOPBACK_KEY: &str = "Software\\Policies\\Microsoft\\Windows\\System";
/// « Configure user group policy loopback processing mode », in the `Registry.pol` of the
/// computer part: 1 merge, 2 replace.
pub const LOOPBACK_VALUE: &str = "UserPolicyMode";

/// What a `Registry.pol` (computer part) says of the loopback; None if it says nothing
/// (`boucle_du_registre`).
pub fn loopback_of_registry(bytes: Option<&[u8]>) -> Option<Loopback> {
    let bytes = bytes.filter(|b| !b.is_empty())?;
    let entries = registry_pol::read(bytes).ok()?;
    let entry = registry_pol::value(&entries, LOOPBACK_KEY, LOOPBACK_VALUE)?;
    if entry.is_deletion() {
        return Some(Loopback::None); // setting « disabled »
    }
    Some(match entry.interpret() {
        Ok(RegValue::Integer(1)) => Loopback::Merge,
        Ok(RegValue::Integer(2)) => Loopback::Replace,
        _ => Loopback::None,
    })
}

/// `ModeBoucle`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopbackMode {
    pub mode: Loopback,
    /// The GPO whose setting wins (None: no GPO sets it).
    pub gpo: Option<Gpo>,
}

/// Path of the `Registry.pol` of the computer part, relative to the share (`chemin_registre`).
pub fn registry_path(domain_dns: &str, guid: &str) -> String {
    format!(
        "{}\\Policies\\{}\\Machine\\Registry.pol",
        domain_dns.to_lowercase(),
        guid.to_uppercase()
    )
}

/// Mode of the computer from its policy (computer part): the applied GPO of highest
/// priority that sets it wins (`mode_boucle`).
pub fn loopback_mode(
    computer: &ResultantPolicy,
    registries: &HashMap<String, Option<Vec<u8>>>,
) -> LoopbackMode {
    for line in &computer.applied {
        let Some(gpo) = &line.gpo else { continue };
        let bytes = registries.get(&gpo.guid).and_then(Option::as_deref);
        if let Some(mode) = loopback_of_registry(bytes) {
            return LoopbackMode {
                mode,
                gpo: Some(gpo.clone()),
            };
        }
    }
    LoopbackMode {
        mode: Loopback::None,
        gpo: None,
    }
}

/// Lines in the order of processing → by priority (the last processed wins); a GPO present
/// twice keeps its strongest place only (`_reclasser`).
fn reclassify(processing: &[RsopLine]) -> Vec<RsopLine> {
    let mut seen = HashSet::new();
    let mut out: Vec<RsopLine> = Vec::new();
    for line in processing.iter().rev() {
        if seen.insert(line.key()) {
            let mut line = line.clone();
            line.priority = out.len() + 1;
            out.push(line);
        }
    }
    out
}

/// User part of `user` opening a session on `computer` (MS-GPOL 3.2.5.1.2): in replace, the
/// list is computed on the path of the computer; in merge, the one of the path of the
/// computer is added after the one of the user (it wins). The security filtering is always
/// on the token of the user (`calculer_boucle`).
pub fn compute_loopback(
    user: &RsopData,
    computer: &RsopData,
    mode: &LoopbackMode,
) -> ResultantPolicy {
    let normal = user.compute(Some(Part::User));
    if mode.mode == Loopback::None {
        return normal;
    }
    let sids = user.token(Part::User);
    let machine = user.compute_on(Part::User, &sids, &computer.path);
    let remark = Remark::Loopback {
        mode: mode.mode,
        gpo: mode
            .gpo
            .as_ref()
            .map_or_else(|| "?".to_owned(), |g| g.name.clone()),
        computer: computer.account.clone(),
    };
    if mode.mode == Loopback::Replace {
        let mut remarks = vec![remark];
        remarks.extend(machine.remarks.iter().cloned());
        return ResultantPolicy { remarks, ..machine };
    }
    let processing: Vec<RsopLine> = normal
        .applied
        .iter()
        .rev()
        .chain(machine.applied.iter().rev())
        .cloned()
        .collect();
    let mut remarks = vec![remark];
    for r in normal.remarks.iter().chain(machine.remarks.iter()) {
        if !remarks.contains(r) {
            remarks.push(r.clone());
        }
    }
    ResultantPolicy {
        applied: reclassify(&processing),
        discarded: normal
            .discarded
            .iter()
            .chain(machine.discarded.iter())
            .cloned()
            .collect(),
        ignored: normal
            .ignored
            .iter()
            .chain(machine.ignored.iter())
            .cloned()
            .collect(),
        remarks,
        ..normal
    }
}

/// What the user part of an account on a given computer needs (`DonneesBoucle`).
#[derive(Debug, Clone)]
pub struct LoopbackData {
    pub user: RsopData,
    pub computer: RsopData,
    pub mode: LoopbackMode,
}

impl LoopbackData {
    pub fn compute(&self) -> ResultantPolicy {
        compute_loopback(&self.user, &self.computer, &self.mode)
    }
}

/// Why the loopback could not be read.
#[derive(Debug, Clone)]
pub enum LoopbackError {
    Failure(Failure),
    Sysvol(String),
    /// The computer named was not found.
    ComputerNotFound(String),
}

/// DN of the computer named (`sAMAccountName` with or without `$`, or full DNS name)
/// (`trouver_ordinateur`).
fn find_computer(link: &mut LdapLink, name: &str) -> Result<Option<String>, LdapError> {
    let trimmed = name.trim();
    let short = trimmed
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end_matches('$');
    if short.is_empty() {
        return Ok(None);
    }
    let filter = format!(
        "(&(objectClass=computer)(|{}{}))",
        search::eq("sAMAccountName", search::Value::Text(&format!("{short}$"))).unwrap_or_default(),
        search::eq("dNSHostName", search::Value::Text(trimmed)).unwrap_or_default()
    );
    let base = link.state.root_dse.default_naming_context.clone();
    Ok(
        search_all(link, &base, Scope::Subtree, &filter, &["cn"], &[])?
            .into_iter()
            .next()
            .map(|e| e.dn),
    )
}

/// Blocking: `Registry.pol` of the computer part of the GPOs applied to the computer, on the
/// SYSVOL of the DC of the connection, then the mode that wins (`_mode_de`).
pub fn mode_of(
    connection: &Connection,
    computer: &RsopData,
) -> Result<LoopbackMode, LoopbackError> {
    let policy = computer.compute(Some(Part::Computer));
    let guids: Vec<String> = policy
        .applied
        .iter()
        .filter_map(|l| l.gpo.as_ref().map(|g| g.guid.clone()))
        .collect();
    if guids.is_empty() {
        return Ok(LoopbackMode {
            mode: Loopback::None,
            gpo: None,
        });
    }
    let (dc, protection) = connection
        .run(true, |link| Ok((link.state.dc.clone(), link.sysvol)))
        .map_err(LoopbackError::Failure)?;
    let domain = &computer.directory.dns_name;
    let paths: Vec<String> = guids.iter().map(|g| registry_path(domain, g)).collect();
    let mut session = sysvol::Session::open(&dc, protection, Duration::from_secs(30))
        .map_err(|e| LoopbackError::Sysvol(e.to_string()))?;
    let read = session.read(&paths);
    session.close();
    let read = read.map_err(|e| LoopbackError::Sysvol(e.to_string()))?;
    let registries: HashMap<String, Option<Vec<u8>>> = guids.into_iter().zip(read).collect();
    Ok(loopback_mode(&policy, &registries))
}

/// The user and the computer (name or DN) read on the connection, then the `Registry.pol`
/// of the computer part of the GPOs applied to the computer, on the SYSVOL of the same DC
/// (`lire_boucle`). Blocking.
pub fn read_loopback(
    connection: &Connection,
    user_dn: &str,
    computer: &str,
) -> Result<LoopbackData, LoopbackError> {
    let (user_dn, name) = (user_dn.to_owned(), computer.to_owned());
    let read = connection
        .run(true, move |link| {
            let dn = if name.contains('=') {
                Some(name.clone())
            } else {
                find_computer(link, &name)?
            };
            let Some(dn) = dn else {
                return Ok(None);
            };
            Ok(Some((
                read_rsop_data(link, &user_dn)?,
                read_rsop_data(link, &dn)?,
            )))
        })
        .map_err(LoopbackError::Failure)?;
    let Some((user, computer_data)) = read else {
        return Err(LoopbackError::ComputerNotFound(computer.to_owned()));
    };
    let mode = mode_of(connection, &computer_data)?;
    Ok(LoopbackData {
        user,
        computer: computer_data,
        mode,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn container(dn: &str, gplink: &str, gpoptions: i64) -> Container {
        Container {
            dn: dn.into(),
            name: name_from_dn(dn),
            class: if dn.starts_with("DC=") {
                "domainDNS".into()
            } else {
                "organizationalUnit".into()
            },
            gplink: GpLink::parse(gplink),
            gpoptions,
        }
    }

    fn gpo(guid: &str, version: i64) -> Gpo {
        Gpo {
            dn: format!("CN={guid},CN=Policies,CN=System,DC=lab,DC=test"),
            guid: guid.into(),
            name: format!("GPO {guid}"),
            flags: 0,
            version,
            path: String::new(),
            computer_extensions: String::new(),
            user_extensions: String::new(),
            wmi_filter: String::new(),
            created: None,
            modified: None,
            descriptor: Some(SecurityDescriptor {
                revision: 1,
                control: sd::SE_DACL_PRESENT | sd::SE_SELF_RELATIVE,
                owner: None,
                group: None,
                sacl: None,
                dacl: None,
            }),
        }
    }

    fn link(guid: &str, options: u8) -> String {
        format!("[LDAP://cn={guid},cn=policies,cn=system,DC=lab,DC=test;{options}]")
    }

    #[test]
    fn lsdou_with_blocking_and_enforcing() {
        let (a, b, c, d) = (
            "{A0000000-0000-0000-0000-000000000000}",
            "{B0000000-0000-0000-0000-000000000000}",
            "{C0000000-0000-0000-0000-000000000000}",
            "{D0000000-0000-0000-0000-000000000000}",
        );
        let path = vec![
            container(
                "DC=lab,DC=test",
                &format!("{}{}", link(a, 0), link(b, 2)),
                0,
            ),
            container("OU=X,DC=lab,DC=test", &link(c, 0), 1),
            container(
                "OU=Y,OU=X,DC=lab,DC=test",
                &format!("{}{}", link(d, 0), link(c, 1)),
                0,
            ),
        ];
        let gpos: HashMap<String, Gpo> = [a, b, c, d]
            .iter()
            .map(|g| ((*g).to_owned(), gpo(g, 0x0001_0001)))
            .collect();
        let sids = HashSet::new();
        let wmi = HashMap::new();
        let policy = compute(&Inputs {
            part: Part::User,
            account: "CN=u,OU=Y,OU=X,DC=lab,DC=test",
            sids: &sids,
            path: &path,
            gpos: &gpos,
            domain_dns: "lab.test",
            sites_linked: false,
            wmi_filters: &wmi,
        });
        let applied: Vec<&str> = policy
            .applied
            .iter()
            .map(|l| l.gpo.as_ref().map_or("", |g| g.guid.as_str()))
            .collect();
        // B enforced on the domain wins; then D (nearest OU), then C (X); A blocked by X.
        assert_eq!(applied, [b, d, c]);
        let ignored: Vec<Reason> = policy.ignored.iter().map(|l| l.reason).collect();
        assert_eq!(ignored, [Reason::LinkDisabled, Reason::InheritanceBlocked]);
        assert_eq!(policy.location, "OU=Y,OU=X,DC=lab,DC=test");
    }

    #[test]
    fn paths_and_versions() {
        assert_eq!(
            container_path("CN=u,OU=Y,OU=X,DC=lab,DC=test", "DC=lab,DC=test"),
            [
                "DC=lab,DC=test",
                "OU=X,DC=lab,DC=test",
                "OU=Y,OU=X,DC=lab,DC=test"
            ]
        );
        let v = versions(0x0003_0002);
        assert_eq!((v.user, v.computer), (3, 2));
    }

    #[test]
    fn gpt_ini_read_and_written() {
        assert_eq!(
            read_gpt_ini(b"[General]\r\nVersion = 65540\r\n").version,
            Some(65540)
        );
        let named = read_gpt_ini(b"\xef\xbb\xbf[general]\r\ndisplayName=X\r\nversion=3\r\n");
        assert_eq!((named.version, named.name.as_deref()), (Some(3), Some("X")));
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                "[General]\r\nVersion=7\r\n"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes),
            )
            .collect();
        assert_eq!(read_gpt_ini(&utf16).version, Some(7));
        assert_eq!(
            read_gpt_ini(b"[General]\r\n").error,
            Some(GptError::NoVersion)
        );
        assert_eq!(
            read_gpt_ini(b"[General]\r\nVersion=x\r\n").error,
            Some(GptError::Unreadable("x".into()))
        );
        assert_eq!(read_gpt_ini(b"\xe9\xff").version, None);
        assert_eq!(
            gpt_ini_with_version(b"[General]\r\nVersion = 65540\r\n", 7),
            b"[General]\r\nVersion = 7\r\n"
        );
        assert_eq!(
            gpt_ini_with_version(b"[General]\r\ndisplayName=x\r\n", 7),
            b"[General]\r\nVersion=7\r\ndisplayName=x\r\n"
        );
        let written = gpt_ini_with_version(&utf16, 9);
        assert_eq!(&written[..2], &[0xFF, 0xFE]);
        assert_eq!(read_gpt_ini(&written).version, Some(9));
        assert_eq!(version_of(versions(0x0002_0009)), 0x0002_0009);
    }

    fn folder(guid: &str, version: Option<i64>, files: &[(&str, u64)]) -> SysvolGpo {
        SysvolGpo {
            guid: guid.into(),
            present: true,
            gpt: version.map(|v| GptIni {
                version: Some(v),
                name: None,
                error: None,
            }),
            files: files.iter().map(|(f, t)| ((*f).to_owned(), *t)).collect(),
            unreadable: Vec::new(),
        }
    }

    #[test]
    fn walk_deviations_and_inventory() {
        let (g1, g2, g9) = (
            "{10000000-0000-0000-0000-000000000000}",
            "{20000000-0000-0000-0000-000000000000}",
            "{90000000-0000-0000-0000-000000000000}",
        );
        let entry = |path: &str, directory: bool| sysvol::Entry {
            path: path.to_owned(),
            directory,
            size: if directory { 0 } else { 22 },
            modified: 0,
        };
        let lower = g1.to_lowercase();
        let tree = sysvol::Tree {
            root: "lab.test\\Policies".into(),
            present: true,
            entries: vec![
                entry(&lower, true),
                entry(&format!("{lower}\\GPT.INI"), false),
                entry(&format!("{lower}\\Machine"), true),
                entry(&format!("{lower}\\Machine\\Registry.pol"), false),
                entry(g9, true),
                entry("PolicyDefinitions", true),
                entry("PolicyDefinitions\\x.admx", false),
            ],
            unreadable: Vec::new(),
        };
        let gpt = HashMap::from([(
            g1.to_owned(),
            Some(b"[General]\r\nVersion=65537\r\n".to_vec()),
        )]);
        let dc = sysvol_from_walk("dc1", &tree, &gpt, 3);
        let one = dc.folder(g1).unwrap();
        assert_eq!(one.gpt.as_ref().and_then(|g| g.version), Some(65537));
        let mut files = one.files.clone();
        files.sort();
        assert_eq!(
            files,
            [
                ("GPT.INI".to_owned(), 22),
                ("Machine\\Registry.pol".to_owned(), 22)
            ]
        );
        assert!(!dc.folder(g2).unwrap().present);
        assert_eq!(dc.orphans(&[g1.to_owned(), g2.to_owned()]), [g9.to_owned()]);
        let absent = sysvol::Tree {
            present: false,
            ..tree.clone()
        };
        let none = sysvol_from_walk("dc1", &absent, &HashMap::new(), 0);
        assert_eq!(none.error, Some(SysvolReadError::NoPolicies));
        assert!(none.folder(g1).is_none());

        let g = gpo(g1, 65537);
        assert!(version_deviations(&g, Some(&folder(g1, Some(65537), &[]))).is_empty());
        assert_eq!(
            version_deviations(&g, Some(&folder(g1, Some(65538), &[]))),
            [Deviation::Versions {
                directory: versions(65537),
                sysvol: versions(65538)
            }]
        );
        assert_eq!(
            version_deviations(&g, Some(&SysvolGpo::absent(g1))),
            [Deviation::FolderMissing]
        );
        assert_eq!(
            version_deviations(&g, Some(&folder(g1, None, &[]))),
            [Deviation::GptMissing]
        );
        assert!(version_deviations(&g, None).is_empty());
        let compared = compare_folders(
            &folder(g1, Some(65537), &[("GPT.INI", 22), ("Machine\\a.pol", 3)]),
            &folder(
                g1,
                Some(65536),
                &[("gpt.ini", 22), ("User\\Registry.pol", 10)],
            ),
            "dc2",
        );
        assert_eq!(
            compared,
            [
                Deviation::GptVersionOn {
                    dc: "dc2".into(),
                    found: Some(65536),
                    reference: Some(65537)
                },
                Deviation::MissingFiles {
                    dc: "dc2".into(),
                    n: 1,
                    first: vec!["Machine\\a.pol".into()]
                },
                Deviation::ExtraFiles {
                    dc: "dc2".into(),
                    n: 1,
                    first: vec!["User\\Registry.pol".into()]
                },
            ]
        );

        let b = gpo(g2, 0);
        let directory = GpoDirectory {
            domain: "DC=lab,DC=test".into(),
            dns_name: "lab.test".into(),
            gpos: HashMap::from([(g1.to_owned(), g.clone()), (g2.to_owned(), b)]),
            containers: Vec::new(),
            linked_sites: Vec::new(),
            wmi_filters: HashMap::new(),
            dcs: vec!["dc1".into(), "dc2".into()],
            dc: "dc1".into(),
            names: HashMap::new(),
        };
        let pdc = SysvolDc {
            dc: "dc1".into(),
            folders: HashMap::from([
                (g1.to_owned(), folder(g1, Some(65537), &[])),
                (g9.to_owned(), folder(g9, None, &[])),
            ]),
            error: None,
            round_trips: 0,
            names: HashMap::from([(g9.to_owned(), g9.to_lowercase())]),
        };
        let dc2 = SysvolDc {
            dc: "dc2".into(),
            folders: HashMap::from([(g1.to_owned(), folder(g1, Some(1), &[]))]),
            ..pdc.clone()
        };
        let inventory = Inventory {
            directory,
            sysvol: pdc,
            others: vec![dc2.clone()],
        };
        assert_eq!(inventory.orphans(), [g9.to_lowercase()]);
        assert_eq!(inventory.without_folder(), [g2.to_owned()]);
        assert_eq!(
            inventory.deviations(g1),
            [Deviation::GptVersionOn {
                dc: "dc2".into(),
                found: Some(1),
                reference: Some(65537)
            }]
        );
        let summary = inventory.dc_deviations(&dc2);
        assert!(matches!(&summary[0], Deviation::Of { name, .. } if name.starts_with("GPO ")));
        assert_eq!(
            summary.last(),
            Some(&Deviation::OrphansDiffer {
                names: vec![g9.to_lowercase()]
            })
        );
    }

    #[test]
    fn filtering_of_a_descriptor() {
        let sd = |text: &str| annuaire_codecs::sddl::sd_from_sddl(text, None, false).unwrap();
        let lab = sd(
            "O:BAG:BAD:P(A;CI;LCRPLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED)(OD;;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;BG)(A;;RP;;;BG)",
        );
        let rights = filtering(Some(&lab));
        let au: Sid = "S-1-5-11".parse().unwrap();
        let bg: Sid = "S-1-5-32-546".parse().unwrap();
        assert_eq!(
            rights.iter().map(|r| r.sid).collect::<Vec<_>>(),
            [au, "S-1-5-9".parse().unwrap(), bg]
        );
        assert!(rights[0].applies());
        assert!(!rights[1].applies() && rights[1].read);
        assert!(rights[2].deny && !rights[2].applies());
    }
}

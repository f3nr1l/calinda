// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Local copy of a domain (JC.2, ADR 0008, `annuaire.core.stockage`): the SQLite store, for
//! the Rust interface (R4.4). **Same file and same schema as the Python application**
//! (`FORMAT` 1): both read and keep up to date the copy of `$XDG_CACHE_HOME/annuaire/`.
//!
//! One column per attribute of display and search (`COLUMNS`); memberships kept from
//! `member` alone, by GUID (table `liens`). Only the attributes of the white list enter the
//! copy, none of them secret. Each synchronization is applied in one transaction, its
//! landmark (`Landmark`) included: an abrupt stop leaves the copy in its previous state.
//! Writes go through one connection under a lock; each reading thread opens its own.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use annuaire_codecs::time::{self, Civil, UtcTime};
use annuaire_codecs::{Guid, Sid};
use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension, params, params_from_iter};

use crate::session::Entry;

/// Version of the schema (`PRAGMA user_version`); another version: copy made anew.
pub const FORMAT: i64 = 1;

/// How a column keeps its attribute (`Genre`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Text,
    Integer,
    Bytes,
    /// `objectCategory` reduced to the name of its class, without dashes, in lower case.
    Category,
    Boolean,
}

impl Kind {
    fn sql(self) -> &'static str {
        match self {
            Self::Integer | Self::Boolean => "INTEGER",
            Self::Bytes => "BLOB",
            Self::Text | Self::Category => "TEXT",
        }
    }
}

/// A column of the table `objets` (`Colonne`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub attribute: &'static str,
    pub name: &'static str,
    pub kind: Kind,
    /// Read back to build the object of the model (`entry_from_row`).
    pub model: bool,
}

const fn column(attribute: &'static str, name: &'static str, kind: Kind) -> Column {
    Column {
        attribute,
        name,
        kind,
        model: true,
    }
}

/// One column per attribute of display and search, in the order of `stockage.COLONNES`.
pub const COLUMNS: [Column; 19] = [
    column("name", "nom", Kind::Text),
    column("sAMAccountName", "sam", Kind::Text),
    column("userPrincipalName", "upn", Kind::Text),
    column("displayName", "affiche", Kind::Text),
    column("mail", "mail", Kind::Text),
    column("description", "description", Kind::Text),
    column("userAccountControl", "uac", Kind::Integer),
    column("groupType", "type_groupe", Kind::Integer),
    column("lastLogonTimestamp", "derniere_connexion", Kind::Integer),
    column("whenChanged", "modifie", Kind::Text),
    column("whenCreated", "cree", Kind::Text),
    column("lockoutTime", "verrouillage", Kind::Integer),
    column("pwdLastSet", "mot_de_passe", Kind::Integer),
    column("accountExpires", "expiration", Kind::Integer),
    column("objectSid", "sid", Kind::Bytes),
    column("primaryGroupID", "groupe_principal", Kind::Integer),
    column("uSNChanged", "usn", Kind::Integer),
    Column {
        attribute: "objectCategory",
        name: "categorie",
        kind: Kind::Category,
        model: false,
    },
    Column {
        attribute: "showInAdvancedViewOnly",
        name: "avance",
        kind: Kind::Boolean,
        model: false,
    },
];

/// The column of an attribute (name without case).
pub fn column_of(attribute: &str) -> Option<&'static Column> {
    COLUMNS
        .iter()
        .find(|c| c.attribute.eq_ignore_ascii_case(attribute))
}

/// What the synchronization asks the DC (plus `isDeleted` for a delta).
pub fn cache_attributes() -> Vec<String> {
    COLUMNS
        .iter()
        .map(|c| c.attribute.to_owned())
        .chain(["objectClass", "objectGUID", "member"].map(str::to_owned))
        .collect()
}

/// The only attributes that enter the copy. No secret.
pub fn white_listed(attribute: &str) -> bool {
    column_of(attribute).is_some()
        || ["objectClass", "objectGUID", "member", "isDeleted"]
            .iter()
            .any(|a| a.eq_ignore_ascii_case(attribute))
}

/// Columns of an object read back for the model (table `objets`, alias `o`).
pub fn select_object() -> String {
    let columns: Vec<String> = COLUMNS
        .iter()
        .filter(|c| c.model)
        .map(|c| format!("o.{}", c.name))
        .collect();
    format!(
        "SELECT o.dn, o.guid, o.classes, {} FROM objets o",
        columns.join(", ")
    )
}

fn schema() -> String {
    let columns: Vec<String> = COLUMNS
        .iter()
        .map(|c| format!("{} {}", c.name, c.kind.sql()))
        .collect();
    format!(
        "CREATE TABLE etat (cle TEXT PRIMARY KEY, valeur TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE objets (
    id INTEGER PRIMARY KEY,
    guid BLOB UNIQUE NOT NULL,
    dn TEXT NOT NULL COLLATE NOCASE,
    parent TEXT NOT NULL,
    classes TEXT NOT NULL,
    {}
);
CREATE INDEX objets_dn ON objets (dn);
CREATE INDEX objets_parent ON objets (parent);
CREATE TABLE liens (
    groupe BLOB NOT NULL,
    membre BLOB NOT NULL,
    dn TEXT NOT NULL,
    PRIMARY KEY (groupe, membre)
) WITHOUT ROWID;
CREATE INDEX liens_membre ON liens (membre);
",
        columns.join(", ")
    )
}

fn insert_sql() -> String {
    let names: Vec<&str> = ["guid", "dn", "parent", "classes"]
        .into_iter()
        .chain(COLUMNS.iter().map(|c| c.name))
        .collect();
    let marks = vec!["?"; names.len()].join(", ");
    format!(
        "INSERT OR REPLACE INTO objets ({}) VALUES ({marks})",
        names.join(", ")
    )
}

// --- DN and values ---------------------------------------------------------------------

/// First RDN as written (escaped commas respected), without decoding (`rdn_brut`).
pub fn raw_rdn(dn: &str) -> &str {
    let bytes = dn.as_bytes();
    let mut i = 0;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            i += 2;
            continue;
        }
        if b == b',' {
            return dn.get(..i).unwrap_or(dn);
        }
        i += 1;
    }
    dn
}

/// Key of the parent container, as kept in the column `parent`: the rest of the DN after
/// the first RDN, in lower case (`parent_brut`).
pub fn raw_parent(dn: &str) -> String {
    dn.get(raw_rdn(dn).len() + 1..).unwrap_or("").to_lowercase()
}

/// `<GUID=…>;<SID=…>;CN=…` (extended DN control, text form) → (GUID, DN).
pub fn split_extended_dn(text: &str) -> (Option<Vec<u8>>, &str) {
    let mut guid = None;
    let mut rest = text;
    while rest.starts_with('<') {
        let Some(end) = rest.find('>') else { break };
        let inner = rest.get(1..end).unwrap_or("");
        if let Some((key, value)) = inner.split_once('=') {
            if key.eq_ignore_ascii_case("GUID") {
                guid = value.parse::<Guid>().ok().map(|g| g.encode());
            }
        }
        rest = rest.get(end + 1..).unwrap_or("");
        rest = rest.strip_prefix(';').unwrap_or(rest);
    }
    (guid, rest)
}

/// `CN=Person,CN=Schema,…` or `person` → `person`; `Organizational-Unit` →
/// `organizationalunit` (`categorie_courte`).
pub fn short_category(value: &str) -> String {
    let mut value = value;
    while value.starts_with('<') {
        let Some(end) = value.find('>') else { break };
        value = value.get(end + 1..).unwrap_or("");
        value = value.strip_prefix(';').unwrap_or(value);
    }
    let name = if value.contains('=') {
        raw_rdn(value).split_once('=').map_or("", |(_, v)| v)
    } else {
        value
    };
    name.replace(['-', '\\'], "").to_lowercase()
}

fn value_of(column: &Column, values: &[Vec<u8>]) -> Value {
    let Some(first) = values.first() else {
        return Value::Null;
    };
    match column.kind {
        Kind::Bytes => Value::Blob(first.clone()),
        Kind::Integer => {
            let text = String::from_utf8_lossy(first).into_owned();
            // Kept as is if it is no integer: the model will say it unreadable, as directly.
            text.trim()
                .parse::<i64>()
                .map_or(Value::Text(text), Value::Integer)
        }
        Kind::Category => Value::Text(short_category(&String::from_utf8_lossy(first))),
        Kind::Boolean => Value::Integer(i64::from(first.eq_ignore_ascii_case(b"TRUE"))),
        Kind::Text => Value::Text(String::from_utf8_lossy(first).into_owned()),
    }
}

/// An object as the copy keeps it, or a change to apply to it (`Ligne`).
#[derive(Debug, Clone, PartialEq)]
pub struct Line {
    pub guid: Vec<u8>,
    pub dn: String,
    /// `objectClass`, values separated by a space.
    pub classes: String,
    /// In the order of `COLUMNS`; `Null` for an attribute absent.
    pub values: Vec<Value>,
    /// Group: (GUID, DN) of each value of `member`; None: links unchanged.
    pub members: Option<Vec<(Vec<u8>, String)>>,
    pub deleted: bool,
}

/// Why an entry cannot become a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineError {
    /// `member;range=…`: to complete before (the synchronization does it).
    Ranged(String),
    /// A value of `member` without GUID (extended DN expected).
    MemberWithoutGuid(String),
    NoGuid(String),
}

/// Line of an entry read with the extended DN control; only the attributes of the white list
/// are read (`ligne_depuis_entree`).
pub fn line_from_entry(entry: &Entry) -> Result<Line, LineError> {
    let (dn_guid, dn) = split_extended_dn(&entry.dn);
    let dn = dn.to_owned();
    let mut guid = dn_guid;
    let mut values = vec![Value::Null; COLUMNS.len()];
    let mut classes = String::new();
    let mut members: Option<Vec<(Vec<u8>, String)>> = None;
    let mut deleted = false;
    for (name, raw) in &entry.attributes {
        let low = name.to_lowercase();
        if low.starts_with("member;") {
            return Err(LineError::Ranged(dn));
        }
        if !white_listed(&low) {
            continue;
        }
        match low.as_str() {
            "objectguid" => {
                if let Some(g) = raw.first() {
                    guid = Some(g.clone());
                }
            }
            "objectclass" => {
                classes = raw
                    .iter()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");
            }
            "member" => {
                let mut list = Vec::new();
                for value in raw {
                    let text = String::from_utf8_lossy(value);
                    let (g, d) = split_extended_dn(&text);
                    let g = g.ok_or_else(|| LineError::MemberWithoutGuid(dn.clone()))?;
                    list.push((g, d.to_owned()));
                }
                members = Some(list);
            }
            "isdeleted" => {
                deleted = raw.first().is_some_and(|v| v.eq_ignore_ascii_case(b"TRUE"));
            }
            _ => {
                if let Some(i) = COLUMNS
                    .iter()
                    .position(|c| c.attribute.eq_ignore_ascii_case(&low))
                {
                    if let (Some(slot), Some(column)) = (values.get_mut(i), COLUMNS.get(i)) {
                        *slot = value_of(column, raw);
                    }
                }
            }
        }
    }
    let guid = guid.ok_or_else(|| LineError::NoGuid(dn.clone()))?;
    if members.is_none()
        && !deleted
        && classes
            .to_lowercase()
            .split_whitespace()
            .any(|c| c == "group")
    {
        members = Some(Vec::new()); // complete search: a group without `member` is empty
    }
    Ok(Line {
        guid,
        dn,
        classes,
        values,
        members,
        deleted,
    })
}

/// Entry (raw attributes) of a row read by `select_object`, for `object_from_entry`
/// (`entree_depuis_rang`).
pub fn entry_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entry> {
    let dn: String = row.get(0)?;
    let guid: Vec<u8> = row.get(1)?;
    let classes: String = row.get(2)?;
    let mut attributes: Vec<(String, Vec<Vec<u8>>)> = vec![
        ("objectGUID".into(), vec![guid]),
        (
            "objectClass".into(),
            classes
                .split_whitespace()
                .map(|c| c.as_bytes().to_vec())
                .collect(),
        ),
    ];
    for (i, column) in COLUMNS.iter().filter(|c| c.model).enumerate() {
        let value: Value = row.get(i + 3)?;
        let raw = match value {
            Value::Null => continue,
            Value::Blob(b) => b,
            Value::Integer(n) => n.to_string().into_bytes(),
            Value::Real(r) => r.to_string().into_bytes(),
            Value::Text(t) => t.into_bytes(),
        };
        attributes.push((column.attribute.to_owned(), vec![raw]));
    }
    Ok(Entry { dn, attributes })
}

// --- Landmark and changes ----------------------------------------------------------------

/// Point to resume from: it only moves with the data, in the same transaction (`Repere`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Landmark {
    /// The DC of the copy: the deltas are asked to it only.
    pub dc: String,
    /// `invocationId` of this DC (text of the GUID): it changes if the DC is restored.
    pub invocation: String,
    /// `highestCommittedUSN` read **before** the reading: the next delta starts at usn + 1.
    pub usn: i64,
    /// Instant of this reading: date of the copy, shown in the status bar.
    pub date: UtcTime,
    /// `defaultNamingContext`.
    pub root: String,
}

/// `datetime.isoformat()` of an aware UTC date, as the Python application writes it.
pub fn iso_format(time: UtcTime) -> String {
    let c = time.civil();
    let micro = c.fraction / 10;
    let base = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    );
    if micro == 0 {
        format!("{base}+00:00")
    } else {
        format!("{base}.{micro:06}+00:00")
    }
}

/// `datetime.fromisoformat` for what `iso_format` (or Python) writes: a UTC offset is
/// applied.
pub fn iso_parse(text: &str) -> Option<UtcTime> {
    let get = |a: usize, b: usize| text.get(a..b)?.parse::<u32>().ok();
    let (year, month, day) = (get(0, 4)?, get(5, 7)?, get(8, 10)?);
    let (hour, minute, second) = (get(11, 13)?, get(14, 16)?, get(17, 19)?);
    let rest = text.get(19..)?;
    let (fraction, offset) = match rest.strip_prefix('.') {
        Some(after) => {
            let end = after
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after.len());
            let digits = after.get(..end)?;
            let mut padded = digits.chars().take(7).collect::<String>();
            while padded.len() < 7 {
                padded.push('0');
            }
            (padded.parse::<u32>().ok()?, after.get(end..)?)
        }
        None => (0, rest),
    };
    let utc = UtcTime::from_civil(Civil {
        year: i32::try_from(year).ok()?,
        month: u8::try_from(month).ok()?,
        day: u8::try_from(day).ok()?,
        hour: u8::try_from(hour).ok()?,
        minute: u8::try_from(minute).ok()?,
        second: u8::try_from(second).ok()?,
        fraction,
    })
    .ok()?;
    let shift = match offset {
        "" | "Z" | "+00:00" => 0,
        o => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let h: i64 = o.get(1..3)?.parse().ok()?;
            let m: i64 = o.get(4..6)?.parse().ok()?;
            sign * (h * 3600 + m * 60)
        }
    };
    utc.add_seconds(-shift)
}

impl Landmark {
    /// Same JSON as `Repere.vers_json` (keys in this order).
    pub fn to_json(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("dc".into(), self.dc.clone().into());
        map.insert("invocation".into(), self.invocation.clone().into());
        map.insert("usn".into(), self.usn.into());
        map.insert("date".into(), iso_format(self.date).into());
        map.insert("racine".into(), self.root.clone().into());
        serde_json::Value::Object(map).to_string()
    }

    pub fn from_json(text: &str) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(text).ok()?;
        let usn = match value.get("usn")? {
            serde_json::Value::Number(n) => n.as_i64()?,
            serde_json::Value::String(s) => s.parse().ok()?,
            _ => return None,
        };
        Some(Self {
            dc: value.get("dc")?.as_str()?.to_owned(),
            invocation: value.get("invocation")?.as_str()?.to_owned(),
            usn,
            date: iso_parse(value.get("date")?.as_str()?)?,
            root: value.get("racine")?.as_str()?.to_owned(),
        })
    }
}

/// Now, as a `UtcTime`.
pub fn now() -> UtcTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    time::unix_to_nttime(seconds)
        .ok()
        .and_then(|n| time::nttime_to_utc(n).ok().flatten())
        .unwrap_or(time::NT_EPOCH)
}

/// What an application changed in the copy, to update the display (`Changements`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Everything was replaced: the display is read again entirely.
    pub complete: bool,
    /// GUID → (DN before, DN after); None before: created, None after: deleted. The
    /// descendants of a renamed container are there too.
    pub objects: HashMap<Vec<u8>, (Option<String>, Option<String>)>,
}

impl Changes {
    pub fn is_empty(&self) -> bool {
        !self.complete && self.objects.is_empty()
    }
}

// --- File ------------------------------------------------------------------------------

/// Literal LIKE pattern (`ESCAPE '\'`).
pub fn escape_like(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

#[cfg(unix)]
fn prepare(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        let file = PathBuf::from(name);
        if file.exists() {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

/// Unicode lower case (SQLite folds ASCII only), for the filters with accented letters.
fn add_fold(base: &Connection) -> rusqlite::Result<()> {
    base.create_scalar_function(
        "plier",
        1,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let value: Option<String> = ctx.get(0)?;
            Ok(value.map(|v| v.to_lowercase()))
        },
    )
}

/// A connection for reading, for one thread (`connexion_lecture`).
pub fn read_connection(path: &Path) -> rusqlite::Result<Connection> {
    let base = Connection::open(path)?;
    base.pragma_update(None, "query_only", 1)?;
    add_fold(&base)?;
    Ok(base)
}

/// Why the copy cannot be used.
#[derive(Debug)]
pub enum StoreError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{e}"),
            Self::Sqlite(e) => write!(f, "{e}"),
        }
    }
}

/// The copy of a domain. Writes under a lock, one transaction each (`Stockage`).
#[derive(Debug)]
pub struct Store {
    pub path: PathBuf,
    base: Mutex<Connection>,
}

fn open_base(path: &Path) -> Result<Connection, StoreError> {
    prepare(path)?;
    let base = Connection::open(path)?;
    base.pragma_update(None, "journal_mode", "WAL")?;
    base.pragma_update(None, "synchronous", "NORMAL")?;
    let version: i64 = base.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version != FORMAT {
        // New copy, or of another format: made anew.
        for table in ["etat", "objets", "liens"] {
            base.execute_batch(&format!("DROP TABLE IF EXISTS {table}"))?;
        }
        base.execute_batch(&schema())?;
        base.pragma_update(None, "user_version", FORMAT)?; // last
    }
    prepare(path)?; // the WAL was just created
    Ok(base)
}

impl Store {
    /// Opens (or creates) the copy; a damaged file is erased and the copy made anew.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let base = match open_base(path) {
            Ok(base) => base,
            Err(StoreError::Sqlite(_)) => {
                let _ = crate::storage::erase(path);
                open_base(path)?
            }
            Err(e) => return Err(e),
        };
        Ok(Self {
            path: path.to_path_buf(),
            base: Mutex::new(base),
        })
    }

    fn base(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.base.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn landmark(&self) -> Option<Landmark> {
        let base = self.base();
        let text: Option<String> = base
            .query_row("SELECT valeur FROM etat WHERE cle = 'repere'", [], |r| {
                r.get(0)
            })
            .optional()
            .ok()
            .flatten();
        text.and_then(|t| Landmark::from_json(&t))
    }

    pub fn guids(&self) -> HashSet<Vec<u8>> {
        let base = self.base();
        let Ok(mut statement) = base.prepare("SELECT guid FROM objets") else {
            return HashSet::new();
        };
        statement
            .query_map([], |r| r.get::<_, Vec<u8>>(0))
            .map(|rows| rows.flatten().collect())
            .unwrap_or_default()
    }

    /// Applies a synchronization **in one transaction**, landmark included. `complete`:
    /// the copy is replaced. `spared`: GUIDs written by a reading again after the start of
    /// the reading on the DC (ADR 0009); their present line is kept, the DC will give them
    /// again once the replication received (`epargner`).
    pub fn apply(
        &self,
        lines: &[Line],
        landmark: &Landmark,
        complete: bool,
        spared: &HashSet<Vec<u8>>,
    ) -> Result<Changes, StoreError> {
        let mut changes = Changes {
            complete,
            ..Changes::default()
        };
        let mut base = self.base();
        let tx = base.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        if complete {
            if spared.is_empty() {
                tx.execute("DELETE FROM objets", [])?;
            } else {
                let mut delete = tx.prepare("DELETE FROM objets WHERE guid = ?")?;
                let all: Vec<Vec<u8>> = {
                    let mut statement = tx.prepare("SELECT guid FROM objets")?;
                    let rows = statement.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
                    rows.flatten().collect()
                };
                for guid in all.iter().filter(|g| !spared.contains(*g)) {
                    delete.execute(params![guid])?;
                }
            }
            tx.execute("DELETE FROM liens", [])?;
            {
                let mut insert = tx.prepare(&insert_sql())?;
                let mut link = tx.prepare("INSERT OR IGNORE INTO liens VALUES (?, ?, ?)")?;
                for line in lines.iter().filter(|l| !l.deleted) {
                    // The links are taken even from a spared object.
                    for (member, dn) in line.members.iter().flatten() {
                        link.execute(params![line.guid, member, dn])?;
                    }
                    if !spared.contains(&line.guid) {
                        insert.execute(params_from_iter(parameters(line)))?;
                    }
                }
            }
        } else {
            for line in lines.iter().filter(|l| !spared.contains(&l.guid)) {
                apply_one(&tx, line, &mut changes)?;
            }
        }
        tx.execute(
            "INSERT OR REPLACE INTO etat VALUES ('repere', ?)",
            params![landmark.to_json()],
        )?;
        tx.commit()?;
        Ok(changes)
    }

    /// Objects read again after a write (ADR 0009): they enter the copy, in one transaction;
    /// the landmark does not move. Their links (`member`) stay until the next delta. Returns
    /// the GUIDs written (`ecrire_relus`).
    pub fn write_reread(&self, entries: &[Entry]) -> Result<HashSet<Vec<u8>>, StoreError> {
        let mut written = HashSet::new();
        let mut changes = Changes::default();
        let mut base = self.base();
        let tx = base.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for entry in entries {
            let Ok(mut line) = line_from_entry(entry) else {
                continue;
            };
            line.members = None;
            apply_one(&tx, &line, &mut changes)?;
            written.insert(line.guid);
        }
        tx.commit()?;
        Ok(written)
    }

    /// Objects deleted by a write (reading again: nothing left at this DN) (`retirer_dn`).
    pub fn remove_dns(&self, dns: &[String]) -> Result<(), StoreError> {
        let mut changes = Changes::default();
        let mut base = self.base();
        let tx = base.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for dn in dns {
            let guid: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT guid FROM objets WHERE dn = ? COLLATE NOCASE",
                    params![dn],
                    |r| r.get(0),
                )
                .optional()?;
            if let Some(guid) = guid {
                let line = Line {
                    guid,
                    dn: dn.clone(),
                    classes: String::new(),
                    values: Vec::new(),
                    members: None,
                    deleted: true,
                };
                apply_one(&tx, &line, &mut changes)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Deletions seen by the list of the GUIDs of the domain (account without access to
    /// `Deleted Objects`, ADR 0008 §3): removes the objects of `known` absent of `present`.
    pub fn remove_absent(
        &self,
        present: &HashSet<Vec<u8>>,
        known: &HashSet<Vec<u8>>,
    ) -> Result<Changes, StoreError> {
        let mut changes = Changes::default();
        let gone: Vec<&Vec<u8>> = known.difference(present).collect();
        if gone.is_empty() {
            return Ok(changes);
        }
        let mut base = self.base();
        let tx = base.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        for guid in gone {
            let line = Line {
                guid: guid.clone(),
                dn: String::new(),
                classes: String::new(),
                values: Vec::new(),
                members: None,
                deleted: true,
            };
            apply_one(&tx, &line, &mut changes)?;
        }
        tx.commit()?;
        Ok(changes)
    }
}

fn parameters(line: &Line) -> Vec<Value> {
    let mut values = vec![
        Value::Blob(line.guid.clone()),
        Value::Text(line.dn.clone()),
        Value::Text(raw_parent(&line.dn)),
        Value::Text(line.classes.clone()),
    ];
    values.extend(line.values.iter().cloned());
    values.resize(4 + COLUMNS.len(), Value::Null);
    values
}

fn apply_one(tx: &Connection, line: &Line, changes: &mut Changes) -> rusqlite::Result<()> {
    let old: Option<String> = tx
        .query_row(
            "SELECT dn FROM objets WHERE guid = ?",
            params![line.guid],
            |r| r.get(0),
        )
        .optional()?;
    if line.deleted {
        tx.execute(
            "DELETE FROM liens WHERE groupe = ? OR membre = ?",
            params![line.guid, line.guid],
        )?;
        if let Some(old) = old {
            tx.execute("DELETE FROM objets WHERE guid = ?", params![line.guid])?;
            changes.objects.insert(line.guid.clone(), (Some(old), None));
        }
        return Ok(());
    }
    if let Some(old) = old.as_deref().filter(|o| *o != line.dn) {
        move_descendants(tx, old, &line.dn, changes)?;
    }
    tx.execute(&insert_sql(), params_from_iter(parameters(line)))?;
    changes
        .objects
        .insert(line.guid.clone(), (old, Some(line.dn.clone())));
    if let Some(members) = &line.members {
        tx.execute("DELETE FROM liens WHERE groupe = ?", params![line.guid])?;
        for (member, dn) in members {
            tx.execute(
                "INSERT OR IGNORE INTO liens VALUES (?, ?, ?)",
                params![line.guid, member, dn],
            )?;
        }
    }
    Ok(())
}

/// A container renamed or moved: its descendants change their DN without their
/// `uSNChanged` moving (ADR 0008 §2); their DN is rewritten here.
fn move_descendants(
    tx: &Connection,
    old: &str,
    new: &str,
    changes: &mut Changes,
) -> rusqlite::Result<()> {
    let suffix = format!(",{}", old.to_lowercase());
    let pattern = format!("%{}", escape_like(&suffix));
    let rows: Vec<(Vec<u8>, String)> = {
        let mut statement =
            tx.prepare("SELECT guid, dn FROM objets WHERE dn LIKE ? ESCAPE '\\'")?;
        let rows = statement.query_map(params![pattern], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.flatten().collect()
    };
    for (guid, dn) in rows {
        if !dn.to_lowercase().ends_with(&suffix) {
            continue; // LIKE folds ASCII only
        }
        let Some(head) = dn.get(..dn.len().saturating_sub(old.len())) else {
            continue;
        };
        let new_dn = format!("{head}{new}");
        tx.execute(
            "UPDATE objets SET dn = ?, parent = ? WHERE guid = ?",
            params![new_dn, raw_parent(&new_dn), guid],
        )?;
        let before = changes
            .objects
            .get(&guid)
            .map_or(Some(dn.clone()), |c| c.0.clone());
        changes.objects.insert(guid, (before, Some(new_dn)));
    }
    Ok(())
}

// --- Group graph (JC.3) --------------------------------------------------------------

/// Subquery of the GUIDs reached by following the links from the GUIDs of the subquery
/// `start`: the members at any depth, or the groups that contain at any depth (`fermeture`).
/// `UNION` keeps each GUID once, which stops the cycles. The primary group is not followed,
/// as with IN_CHAIN.
pub fn closure(start: &str, towards_members: bool) -> String {
    let (own, other) = if towards_members {
        ("membre", "groupe")
    } else {
        ("groupe", "membre")
    };
    format!(
        "WITH RECURSIVE chaine(g) AS (SELECT {own} FROM liens WHERE {other} IN ({start}) \
         UNION SELECT l.{own} FROM liens l JOIN chaine c ON l.{other} = c.g) SELECT g FROM chaine"
    )
}

/// SID (bytes) of the primary group: SID of the domain of the object + `primaryGroupID`.
pub fn primary_group_sid(sid: &[u8], rid: i64) -> Option<Vec<u8>> {
    let sid = Sid::decode(sid).ok()?;
    let rid = u32::try_from(rid).ok()?;
    Some(sid.domain().ok()?.with_rid(rid).ok()?.encode())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dn_helpers() {
        assert_eq!(raw_rdn("CN=a\\,b,OU=x,DC=lab"), "CN=a\\,b");
        assert_eq!(raw_parent("CN=a\\,b,OU=X,DC=lab"), "ou=x,dc=lab");
        let (g, dn) = split_extended_dn(
            "<GUID=bf7a0c64-1c4a-4d1e-9d4b-5f1f5c1e2a3b>;<SID=S-1-5-21-1-2-3-500>;CN=x,DC=lab",
        );
        assert_eq!(dn, "CN=x,DC=lab");
        assert_eq!(g.map(|g| g.len()), Some(16));
        assert_eq!(
            short_category("CN=Person,CN=Schema,CN=Configuration,DC=lab"),
            "person"
        );
        assert_eq!(short_category("Organizational-Unit"), "organizationalunit");
    }

    #[test]
    fn landmark_json() {
        // As Python writes it (`Repere.vers_json`).
        let text = r#"{"dc": "dc1.lab.test", "invocation": "f0e1", "usn": 123, "date": "2026-10-15T20:01:02.345678+00:00", "racine": "DC=lab,DC=test"}"#;
        let landmark = Landmark::from_json(text).unwrap();
        assert_eq!(landmark.usn, 123);
        assert_eq!(
            iso_format(landmark.date),
            "2026-10-15T20:01:02.345678+00:00"
        );
        assert_eq!(Landmark::from_json(&landmark.to_json()), Some(landmark));
        assert_eq!(
            iso_format(iso_parse("2026-10-15T22:00:00+02:00").unwrap()),
            "2026-10-15T20:00:00+00:00"
        );
    }

    #[test]
    fn store_round_trip() {
        let dir = std::env::temp_dir().join(format!("annuaire-store-{}", std::process::id()));
        let path = dir.join("lab.test.sqlite");
        let store = Store::open(&path).unwrap();
        let guid = |n: u8| vec![n; 16];
        let line = |n: u8, dn: &str, classes: &str| Line {
            guid: guid(n),
            dn: dn.into(),
            classes: classes.into(),
            values: vec![Value::Null; COLUMNS.len()],
            members: None,
            deleted: false,
        };
        let landmark = Landmark {
            dc: "dc1.lab.test".into(),
            invocation: "x".into(),
            usn: 10,
            date: now(),
            root: "DC=lab,DC=test".into(),
        };
        let lines = vec![
            line(1, "OU=A,DC=lab,DC=test", "top organizationalUnit"),
            line(2, "CN=u,OU=A,DC=lab,DC=test", "top person user"),
        ];
        store
            .apply(&lines, &landmark, true, &HashSet::new())
            .unwrap();
        assert_eq!(store.guids().len(), 2);
        // Rename of the OU: its child follows.
        let renamed = vec![line(1, "OU=B,DC=lab,DC=test", "top organizationalUnit")];
        let changes = store
            .apply(&renamed, &landmark, false, &HashSet::new())
            .unwrap();
        assert_eq!(
            changes.objects.get(&guid(2)),
            Some(&(
                Some("CN=u,OU=A,DC=lab,DC=test".into()),
                Some("CN=u,OU=B,DC=lab,DC=test".into())
            ))
        );
        assert_eq!(store.landmark().map(|l| l.usn), Some(10));
        drop(store);
        let read = read_connection(&path).unwrap();
        let parent: String = read
            .query_row("SELECT parent FROM objets WHERE dn LIKE 'CN=u%'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(parent, "ou=b,dc=lab,dc=test");
        drop(read);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Group Policy Preferences (MS-GPPREF): XML files of the SYSVOL, reading and writing
//! (`annuaire.core.codecs.preferences`, J7.6).
//!
//! Four families, each one file under `Machine\Preferences` or `User\Preferences` of a GPO:
//!
//! ```text
//! Drives\Drives.xml         mapped drives (user part only)
//! Printers\Printers.xml     printers (shared ones: user part)
//! Shortcuts\Shortcuts.xml   shortcuts
//! Registry\Registry.xml     registry items
//! ```
//!
//! A file is a root (`<Drives clsid="…">`) holding elements (`<Drive …>`), each with its common
//! attributes (`clsid`, `name`, `status`, `image`, `changed`, `uid`, `disabled`, `desc`,
//! `bypassErrors`, `userContext`, `removePolicy`), a `<Properties action="C|R|U|D" …/>` of the
//! family and, when targeted, `<Filters>`.
//!
//! **Exact round trip.** The original bytes of each element are kept: a document read then
//! written without change gives the file back byte for byte, and an element left alone keeps
//! its form (order of the attributes, escapes, indentation) even when another changes. A
//! changed or new element is written in the style of the file: indentation of two spaces and
//! CRLF (form of the GroupPolicy module of the GPMC), or elements one after the other without
//! indentation (form of the console). Elements of another kind (`<Collection>`, local printer,
//! etc.), unknown attributes and children, comments and the `disabled` of the root are kept.
//!
//! `cpassword` (password encrypted by an AES key published by Microsoft, MS14-025) is **never
//! written**: a changed element loses it, a new one does not have it. `has_password` says an
//! element carries one, to warn about it; the value is never decrypted.

use std::fmt;

use crate::xml::{self, Node};

pub const BOM: &[u8] = b"\xef\xbb\xbf";
pub const DECLARATION: &str = r#"<?xml version="1.0" encoding="utf-8"?>"#;
pub const EOL: &str = "\r\n";
/// « Preferences » pair the GPMC console adds next to each preference extension (null CSE);
/// the GroupPolicy module does not set it.
pub const NULL_CSE: &str = "{00000000-0000-0000-0000-000000000000}";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Family {
    Drives,
    Printers,
    Shortcuts,
    Registry,
}

impl Family {
    pub const ALL: [Self; 4] = [
        Self::Drives,
        Self::Printers,
        Self::Shortcuts,
        Self::Registry,
    ];

    /// The name of the folder and of the file (`Famille.value`).
    pub fn value(self) -> &'static str {
        match self {
            Self::Drives => "Drives",
            Self::Printers => "Printers",
            Self::Shortcuts => "Shortcuts",
            Self::Registry => "Registry",
        }
    }

    pub fn description(self) -> &'static Description {
        match self {
            Self::Drives => &DRIVES,
            Self::Printers => &PRINTERS,
            Self::Shortcuts => &SHORTCUTS,
            Self::Registry => &REGISTRY,
        }
    }

    /// Path of the file under `Machine` or `User`.
    pub fn path(self) -> String {
        let v = self.value();
        format!("Preferences\\{v}\\{v}.xml")
    }
}

/// What makes a family: file, root, editable element, client-side extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Description {
    pub family: Family,
    pub root: &'static str,
    pub root_clsid: &'static str,
    pub tag: &'static str,
    pub clsid: &'static str,
    pub cse: &'static str,
    pub tool: &'static str,
    pub parts: &'static [&'static str],
}

static DRIVES: Description = Description {
    family: Family::Drives,
    root: "Drives",
    root_clsid: "{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}",
    tag: "Drive",
    clsid: "{935D1B74-9CB8-4e3c-9914-7DD559B7A417}",
    cse: "{5794DAFD-BE60-433F-88A2-1A31939AC01F}",
    tool: "{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}",
    parts: &["User"],
};

static PRINTERS: Description = Description {
    family: Family::Printers,
    root: "Printers",
    root_clsid: "{1F577D12-3D1B-471e-A1B7-060317597B9C}",
    tag: "SharedPrinter",
    clsid: "{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}",
    cse: "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}",
    tool: "{A8C42CEA-CDB8-4388-97F4-5831F933DA84}",
    parts: &["User"],
};

static SHORTCUTS: Description = Description {
    family: Family::Shortcuts,
    root: "Shortcuts",
    root_clsid: "{872ECB34-B2EC-401b-A585-D32574AA90EE}",
    tag: "Shortcut",
    clsid: "{4F2F7C55-2790-433e-8127-0739D1CFA327}",
    cse: "{C418DD9D-0D14-4EFB-8FBF-CFE535C8FAC7}",
    tool: "{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}",
    parts: &["Machine", "User"],
};

static REGISTRY: Description = Description {
    family: Family::Registry,
    root: "RegistrySettings",
    root_clsid: "{A3CCFC41-DFDB-43a5-8D26-0FE8B954DA51}",
    tag: "Registry",
    clsid: "{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}",
    cse: "{B087BE9D-ED37-454F-AF9C-04291E351182}",
    tool: "{BEE07A6A-EC9F-4659-B8C9-0B1937907C83}",
    parts: &["Machine", "User"],
};

/// Actions of an element: create, replace, update, delete; `image` = rank.
pub const ACTIONS: [&str; 4] = ["C", "R", "U", "D"];

// --- Targeting (Filters) ------------------------------------------------------------------

/// Targeting filters the tool can edit; the others stay `Filter::Raw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    Group,
    Ou,
    Computer,
    User,
}

impl Target {
    pub fn tag(self) -> &'static str {
        match self {
            Self::Group => "FilterGroup",
            Self::Ou => "FilterOrgUnit",
            Self::Computer => "FilterComputer",
            Self::User => "FilterUser",
        }
    }

    pub fn of_tag(tag: &str) -> Option<Self> {
        [Self::Group, Self::Ou, Self::Computer, Self::User]
            .into_iter()
            .find(|t| t.tag() == tag)
    }

    /// Attributes of the filter, in the order the console writes them, with their default.
    pub fn attributes(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Self::Group => &[
                ("bool", "AND"),
                ("not", "0"),
                ("name", ""),
                ("sid", ""),
                ("userContext", "1"),
                ("primaryGroup", "0"),
                ("localGroup", "0"),
            ],
            Self::Ou => &[
                ("bool", "AND"),
                ("not", "0"),
                ("name", ""),
                ("userContext", "1"),
                ("directMember", "0"),
            ],
            Self::Computer => &[
                ("bool", "AND"),
                ("not", "0"),
                ("type", "NETBIOS"),
                ("name", ""),
            ],
            Self::User => &[("bool", "AND"), ("not", "0"), ("name", ""), ("sid", "")],
        }
    }
}

/// An editable filter (`Filtre`). `attributes` keeps the unknown ones (and the order read).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditableFilter {
    pub target: Target,
    pub attributes: Vec<(String, String)>,
}

impl EditableFilter {
    /// New filter, attributes in the order of the console, defaults completed (`filtre`).
    pub fn new(target: Target, values: &[(&str, &str)]) -> Self {
        let attributes = target
            .attributes()
            .iter()
            .map(|(k, default)| {
                let v = values
                    .iter()
                    .find(|(n, _)| n == k)
                    .map_or(*default, |(_, v)| *v);
                ((*k).to_owned(), v.to_owned())
            })
            .collect();
        Self { target, attributes }
    }

    pub fn get_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map_or(default, |(_, v)| v.as_str())
    }

    pub fn name(&self) -> &str {
        self.get_or("name", "")
    }

    pub fn sid(&self) -> &str {
        self.get_or("sid", "")
    }

    pub fn negation(&self) -> bool {
        self.get_or("not", "0") == "1"
    }

    /// True if the filter combines with the previous one by OR (`bool="OR"`).
    pub fn or(&self) -> bool {
        self.get_or("bool", "AND").eq_ignore_ascii_case("OR")
    }

    /// Copy with these attributes changed (added at the end if absent) (`avec`).
    pub fn with(&self, values: &[(&str, &str)]) -> Self {
        let mut attributes = self.attributes.clone();
        for (k, v) in values {
            match attributes.iter_mut().find(|(n, _)| n == k) {
                Some((_, old)) => (*v).clone_into(old),
                None => attributes.push(((*k).to_owned(), (*v).to_owned())),
            }
        }
        Self {
            target: self.target,
            attributes,
        }
    }
}

/// A filter: editable, or kept as is (collection, WMI, system, address range…).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filter {
    Editable(EditableFilter),
    Raw(Node),
}

impl Filter {
    pub fn tag(&self) -> &str {
        match self {
            Self::Editable(f) => f.target.tag(),
            Self::Raw(n) => &n.tag,
        }
    }

    pub fn negation(&self) -> bool {
        match self {
            Self::Editable(f) => f.negation(),
            Self::Raw(n) => n.get_or("not", "0") == "1",
        }
    }

    pub fn or(&self) -> bool {
        match self {
            Self::Editable(f) => f.or(),
            Self::Raw(n) => n.get_or("bool", "AND").eq_ignore_ascii_case("OR"),
        }
    }

    fn read(node: &Node) -> Self {
        let Some(target) = Target::of_tag(&node.tag) else {
            return Self::Raw(node.clone());
        };
        let known = target.attributes();
        // An « editable » filter carrying children or an unknown attribute stays raw:
        // writing it again from the model would lose them.
        if !node.children.is_empty()
            || !node.text.trim().is_empty()
            || node
                .attributes
                .iter()
                .any(|(k, _)| !known.iter().any(|(n, _)| n == k))
        {
            return Self::Raw(node.clone());
        }
        Self::Editable(EditableFilter {
            target,
            attributes: node.attributes.clone(),
        })
    }

    fn node(&self) -> Node {
        match self {
            Self::Raw(n) => n.clone(),
            Self::Editable(f) => Node {
                tag: f.target.tag().to_owned(),
                attributes: f.attributes.clone(),
                ..Node::default()
            },
        }
    }
}

// --- Elements -----------------------------------------------------------------------------

/// Common options of an element (« Common » tab of the console).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Common {
    pub description: String,
    /// « Stop processing items in this extension if an error occurs » unchecked (default of
    /// the console): bypassErrors="1".
    pub ignore_errors: bool,
    pub user_context: bool,
    pub remove_when_not_applied: bool,
    pub disabled: bool,
}

impl Default for Common {
    fn default() -> Self {
        Self {
            description: String::new(),
            ignore_errors: true,
            user_context: false,
            remove_when_not_applied: false,
            disabled: false,
        }
    }
}

/// An element of the first level of the file. `raw`: its original bytes, if it did not change
/// since reading (it is then written again as is).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    pub node: Node,
    pub raw: Option<Vec<u8>>,
}

impl Element {
    pub fn tag(&self) -> &str {
        &self.node.tag
    }

    pub fn name(&self) -> &str {
        self.node.get_or("name", "")
    }

    pub fn status(&self) -> &str {
        self.node.get_or("status", "")
    }

    pub fn uid(&self) -> &str {
        self.node.get_or("uid", "")
    }

    pub fn changed(&self) -> &str {
        self.node.get_or("changed", "")
    }

    pub fn disabled(&self) -> bool {
        self.node.get_or("disabled", "0") == "1"
    }

    /// The attributes of `Properties`, in order.
    pub fn properties(&self) -> Vec<(String, String)> {
        self.node
            .find("Properties")
            .map(|p| p.attributes.clone())
            .unwrap_or_default()
    }

    pub fn property(&self, name: &str) -> Option<String> {
        self.node
            .find("Properties")
            .and_then(|p| p.get(name))
            .map(str::to_owned)
    }

    pub fn action(&self) -> String {
        self.property("action").unwrap_or_default()
    }

    pub fn common(&self) -> Common {
        let n = &self.node;
        Common {
            description: n.get_or("desc", "").to_owned(),
            ignore_errors: n.get_or("bypassErrors", "0") == "1",
            user_context: n.get_or("userContext", "0") == "1",
            remove_when_not_applied: n.get_or("removePolicy", "0") == "1",
            disabled: n.get_or("disabled", "0") == "1",
        }
    }

    pub fn filters(&self) -> Vec<Filter> {
        self.node
            .find("Filters")
            .map(|f| f.children.iter().map(Filter::read).collect())
            .unwrap_or_default()
    }

    /// True if the element (or a descendant) carries a non-empty `cpassword` (MS14-025).
    pub fn has_password(&self) -> bool {
        self.node
            .iter()
            .iter()
            .any(|e| e.get("cpassword").is_some_and(|v| !v.is_empty()))
    }

    /// True if the tool can edit this element: the tag of the family, `Properties`, and
    /// nothing else below than what the model writes again.
    pub fn editable(&self, description: &Description) -> bool {
        if self.tag() != description.tag || self.node.find("Properties").is_none() {
            return false;
        }
        self.node
            .children
            .iter()
            .all(|c| c.tag == "Properties" || c.tag == "Filters")
    }
}

/// A piece of the first level: an element, or what is not one (comment, processing
/// instruction, text), kept in its place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Element(Element),
    Raw(Vec<u8>),
}

/// A preferences file.
///
/// `header` goes from the beginning of the file to the end of the opening tag of the root;
/// `footer` from the closing tag to the end. `separators`: blank before the first piece,
/// between two, after the last, as read (the style of the file). `origin`: the bytes read, if
/// nothing changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub family: Family,
    pub header: Vec<u8>,
    pub pieces: Vec<Piece>,
    pub footer: Vec<u8>,
    pub separators: (String, String, String),
    pub origin: Option<Vec<u8>>,
    pub empty_root: bool,
}

fn default_separators() -> (String, String, String) {
    ("\r\n  ".into(), "\r\n  ".into(), "\r\n".into())
}

impl Document {
    pub fn description(&self) -> &'static Description {
        self.family.description()
    }

    pub fn elements(&self) -> Vec<&Element> {
        self.pieces
            .iter()
            .filter_map(|p| match p {
                Piece::Element(e) => Some(e),
                Piece::Raw(_) => None,
            })
            .collect()
    }

    /// `disabled="1"` on the root: the whole family is disabled in this part.
    pub fn disabled(&self) -> bool {
        disabled_attribute(&self.header)
    }

    pub fn passwords(&self) -> Vec<&Element> {
        self.elements()
            .into_iter()
            .filter(|e| e.has_password())
            .collect()
    }

    /// Indentation of an element in this file; `None` if the elements follow each other
    /// without a line break (form of the console).
    pub fn indentation(&self) -> Option<String> {
        let sep = if self.separators.1.is_empty() {
            &self.separators.0
        } else {
            &self.separators.1
        };
        sep.rsplit_once('\n').map(|(_, after)| after.to_owned())
    }
}

/// `\sdisabled\s*=\s*["']1["']` in the opening tag of the root.
fn disabled_attribute(header: &[u8]) -> bool {
    let text = String::from_utf8_lossy(header);
    let b = text.as_bytes();
    let mut from = 0;
    while let Some(i) = text.get(from..).and_then(|t| t.find("disabled")) {
        let at = from + i;
        from = at + 8;
        if at == 0 || !b.get(at - 1).is_some_and(u8::is_ascii_whitespace) {
            continue;
        }
        let rest = text.get(at + 8..).unwrap_or_default().trim_start();
        let Some(rest) = rest.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with("\"1\"") || rest.starts_with("'1'") {
            return true;
        }
    }
    false
}

// --- Reading ------------------------------------------------------------------------------

/// Why a preferences file cannot be read (`ErreurPreferences`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreferencesError {
    Dtd,
    Encoding,
    Malformed(String),
    Root { root: String, expected: String },
    RootContent,
    Unclosed,
}

impl fmt::Display for PreferencesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dtd => write!(f, "Preferences: a DTD is not accepted."),
            Self::Encoding => write!(f, "Preferences: unsupported encoding (UTF-8 expected)."),
            Self::Malformed(e) => write!(f, "Preferences: malformed XML ({e})."),
            Self::Root { root, expected } => {
                write!(
                    f,
                    "Preferences: root element “{root}” instead of “{expected}”."
                )
            }
            Self::RootContent => write!(f, "Preferences: unreadable root element content."),
            Self::Unclosed => write!(f, "Preferences: unclosed tag."),
        }
    }
}

impl std::error::Error for PreferencesError {}

fn declared_encoding(text: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(text.get(..text.len().min(200)).unwrap_or_default());
    let t = s.trim_start();
    let decl = t.strip_prefix("<?xml")?;
    let end = decl.find('>')?;
    let decl = decl.get(..end)?;
    let i = decl.find("encoding")?;
    let rest = decl
        .get(i + 8..)?
        .trim_start()
        .strip_prefix('=')?
        .trim_start();
    let quote = rest.chars().next().filter(|c| *c == '"' || *c == '\'')?;
    let rest = rest.get(1..)?;
    Some(rest.get(..rest.find(quote)?)?.to_owned())
}

/// Bytes of a preferences file → `Document`. Refused if malformed, not UTF-8, or if its root
/// is not that of the family (`lire`).
pub fn read(bytes: &[u8], family: Family) -> Result<Document, PreferencesError> {
    let description = family.description();
    let offset = if bytes.starts_with(BOM) { BOM.len() } else { 0 };
    let body = bytes.get(offset..).unwrap_or_default();
    if body.starts_with(b"\xff\xfe")
        || body.starts_with(b"\xfe\xff")
        || bytes
            .get(..bytes.len().min(200))
            .unwrap_or_default()
            .contains(&0)
    {
        return Err(PreferencesError::Encoding);
    }
    if let Some(encoding) = declared_encoding(body) {
        let lower = encoding.to_ascii_lowercase();
        if lower != "utf-8" && lower != "utf8" {
            return Err(PreferencesError::Encoding);
        }
    }
    let text = std::str::from_utf8(body).map_err(|e| PreferencesError::Malformed(e.to_string()))?;
    let doc =
        roxmltree::Document::parse_with_options(text, xml::options()).map_err(|e| match e {
            roxmltree::Error::DtdDetected => PreferencesError::Dtd,
            e => PreferencesError::Malformed(e.to_string()),
        })?;
    let root = doc.root_element();
    let root_tag = xml::tag_of(root);
    if root_tag != description.root {
        return Err(PreferencesError::Root {
            root: root_tag,
            expected: description.root.to_owned(),
        });
    }
    let range = root.range();
    let open = tag_end(bytes, offset + range.start)?;
    let empty_root = bytes.get(open.saturating_sub(2)..open) == Some(b"/>");
    if empty_root {
        return Ok(Document {
            family,
            header: bytes.get(..open).unwrap_or_default().to_vec(),
            pieces: Vec::new(),
            footer: bytes.get(open..).unwrap_or_default().to_vec(),
            separators: default_separators(),
            origin: Some(bytes.to_vec()),
            empty_root: true,
        });
    }
    // Start of the closing tag of the root: the last `</` of its range.
    let end = offset + range.end;
    let close = bytes
        .get(open..end)
        .and_then(|b| b.windows(2).rposition(|w| w == b"</"))
        .map(|i| open + i)
        .ok_or(PreferencesError::RootContent)?;

    // Pieces of the first level: the nodes that are not text, and the texts between them.
    let mut marks: Vec<(usize, usize, Option<roxmltree::Node<'_, '_>>)> = Vec::new();
    let mut at = open;
    for child in root.children().filter(|c| !c.is_text()) {
        let r = child.range();
        let (start, stop) = (offset + r.start, offset + r.end);
        if start > at {
            marks.push((at, start, None));
        }
        marks.push((start, stop, Some(child)));
        at = stop;
    }
    if close > at {
        marks.push((at, close, None));
    }

    let mut seen: Vec<Piece> = Vec::new();
    let mut blanks: Vec<String> = Vec::new();
    let mut blank = String::new();
    for (start, stop, node) in marks {
        let raw = bytes.get(start..stop).unwrap_or_default();
        match node {
            None if raw.iter().all(u8::is_ascii_whitespace) => {
                blank = String::from_utf8_lossy(raw).into_owned();
                continue;
            }
            _ => {}
        }
        blanks.push(std::mem::take(&mut blank));
        match node {
            Some(n) if n.is_element() => seen.push(Piece::Element(Element {
                node: Node::from_roxml(n),
                raw: Some(raw.to_vec()),
            })),
            _ => seen.push(Piece::Raw(raw.to_vec())),
        }
    }
    let before = blanks.first().cloned().unwrap_or_else(|| blank.clone());
    let between = blanks.get(1).cloned().unwrap_or_else(|| before.clone());
    let after = if seen.is_empty() {
        String::new()
    } else {
        blank
    };
    Ok(Document {
        family,
        header: bytes.get(..open).unwrap_or_default().to_vec(),
        pieces: seen,
        footer: bytes.get(close..).unwrap_or_default().to_vec(),
        separators: (before, between, after),
        origin: Some(bytes.to_vec()),
        empty_root: false,
    })
}

/// Position just after the `>` of the tag starting at `start` (quotes respected).
fn tag_end(bytes: &[u8], start: usize) -> Result<usize, PreferencesError> {
    let mut quote: Option<u8> = None;
    for (i, &c) in bytes.iter().enumerate().skip(start) {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if c == b'"' || c == b'\'' => quote = Some(c),
            None if c == b'>' => return Ok(i + 1),
            None => {}
        }
    }
    Err(PreferencesError::Unclosed)
}

// --- Writing ------------------------------------------------------------------------------

/// Empty document of the family, with the header of the GPMC (`nouveau_document`).
pub fn new_document(family: Family) -> Document {
    let d = family.description();
    let mut header = BOM.to_vec();
    header.extend(format!("{DECLARATION}{EOL}<{} clsid=\"{}\">", d.root, d.root_clsid).as_bytes());
    Document {
        family,
        header,
        pieces: Vec::new(),
        footer: format!("</{}>", d.root).into_bytes(),
        separators: default_separators(),
        origin: None,
        empty_root: false,
    }
}

/// `Document` → bytes; identical if nothing changed since `read` (`ecrire`).
pub fn write(document: &Document) -> Vec<u8> {
    if let Some(origin) = &document.origin {
        return origin.clone();
    }
    let (mut header, mut footer) = (document.header.clone(), document.footer.clone());
    if document.empty_root {
        if document.pieces.is_empty() {
            header.extend(footer);
            return header;
        }
        // `<Root …/>` becomes `<Root …>` … `</Root>`.
        header.truncate(header.len().saturating_sub(2));
        while header.last().is_some_and(u8::is_ascii_whitespace) {
            header.pop();
        }
        header.push(b'>');
        let mut f = format!("</{}>", document.description().root).into_bytes();
        f.extend(footer);
        footer = f;
    }
    if document.pieces.is_empty() {
        header.extend(footer);
        return header;
    }
    let (before, between, after) = &document.separators;
    let indentation = document.indentation();
    let mut out = header;
    out.extend(before.as_bytes());
    for (i, piece) in document.pieces.iter().enumerate() {
        if i > 0 {
            out.extend(between.as_bytes());
        }
        match piece {
            Piece::Raw(bytes) => out.extend(bytes),
            Piece::Element(Element { raw: Some(raw), .. }) => out.extend(raw),
            Piece::Element(e) => {
                out.extend(serialize(&e.node, indentation.as_deref(), 1).as_bytes())
            }
        }
    }
    out.extend(after.as_bytes());
    out.extend(footer);
    out
}

/// An element in the style of the file: `indentation` per level and CRLF, or everything on
/// one line (`None`). `/>` preceded by a space in the first style, as the GPMC.
fn serialize(node: &Node, indentation: Option<&str>, level: usize) -> String {
    let attributes: String = node
        .attributes
        .iter()
        .map(|(k, v)| format!(" {k}=\"{}\"", xml::escape(v, true)))
        .collect();
    let tag = &node.tag;
    if node.children.is_empty() && node.text.is_empty() {
        let close = if indentation.is_some() { " />" } else { "/>" };
        return format!("<{tag}{attributes}{close}");
    }
    if node.children.is_empty() {
        return format!(
            "<{tag}{attributes}>{}</{tag}>",
            xml::escape(&node.text, false)
        );
    }
    let Some(step) = indentation else {
        let inside: String = node
            .children
            .iter()
            .map(|c| serialize(c, None, level + 1))
            .collect();
        return format!("<{tag}{attributes}>{inside}</{tag}>");
    };
    let newline = format!("{EOL}{}", step.repeat(level + 1));
    let inside: String = node
        .children
        .iter()
        .map(|c| format!("{newline}{}", serialize(c, indentation, level + 1)))
        .collect();
    format!(
        "<{tag}{attributes}>{inside}{EOL}{}</{tag}>",
        step.repeat(level)
    )
}

// --- Changes (pure) -----------------------------------------------------------------------

/// Value of `changed`: UTC, `YYYY-MM-DD HH:MM:SS` (form of the console), for a time in
/// seconds since 1970.
pub fn timestamp(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let seconds = unix.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60
    )
}

/// Days since 1970-01-01 → (year, month, day) (Howard Hinnant's algorithm).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// Now, in seconds since 1970.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0))
}

/// Sets or removes the optional common attributes, at the end if new (`_poser_commun`).
fn set_common(node: &mut Node, common: &Common) {
    let one = |b: bool| if b { "1" } else { "" };
    for (name, value) in [
        ("desc", common.description.as_str()),
        ("bypassErrors", one(common.ignore_errors)),
        ("userContext", one(common.user_context)),
        ("removePolicy", one(common.remove_when_not_applied)),
    ] {
        if value.is_empty() {
            node.remove_attribute(name);
        } else {
            node.set(name, value);
        }
    }
    if common.disabled {
        node.set("disabled", "1");
    } else if node.has("disabled") {
        node.set("disabled", "0");
    }
}

fn set_filters(node: &mut Node, filters: &[Filter]) {
    if let Some(i) = node.position("Filters") {
        node.children.remove(i);
    }
    if filters.is_empty() {
        return;
    }
    let mut container = Node::new("Filters");
    container.children = filters.iter().map(Filter::node).collect();
    // After `Properties`, as the console.
    let at = node
        .position("Properties")
        .map_or(node.children.len(), |i| i + 1);
    node.children.insert(at, container);
}

/// Rank of the action; an original image in the second series (5 to 8, non-text registry
/// values in the console) keeps its series.
fn image(action: &str, old: Option<&str>) -> String {
    let rank = ACTIONS.iter().position(|a| *a == action).unwrap_or(2);
    let digits = old.filter(|o| !o.is_empty() && o.bytes().all(|b| b.is_ascii_digit()));
    let base = match digits.and_then(|o| o.parse::<u32>().ok()) {
        Some(5..=8) => 5,
        _ => 0,
    };
    (base + rank).to_string()
}

/// Replaces the values of `Properties` (original order kept, new ones at the end), removes
/// `cpassword` everywhere.
fn set_properties(node: &mut Node, properties: &[(String, String)]) {
    if node.find("Properties").is_none() {
        node.children.push(Node::new("Properties"));
    }
    if let Some(p) = node.find_mut("Properties") {
        for (k, v) in properties {
            p.set(k, v);
        }
    }
    node.walk_mut(&mut |e| e.remove_attribute("cpassword"));
}

/// New element of the family: attributes in the order of the GPMC, `image` from the action;
/// `properties` in the wanted order (that of the console) (`nouvel_element`).
#[allow(clippy::too_many_arguments)]
pub fn new_element(
    family: Family,
    name: &str,
    status: &str,
    properties: &[(String, String)],
    common: &Common,
    filters: &[Filter],
    uid: &str,
    instant: i64,
    children: &[Node],
) -> Element {
    let d = family.description();
    let mut node = Node::new(d.tag);
    let action = properties
        .iter()
        .find(|(k, _)| k == "action")
        .map_or("U", |(_, v)| v.as_str());
    for (k, v) in [
        ("clsid", d.clsid.to_owned()),
        ("name", name.to_owned()),
        ("status", status.to_owned()),
        ("image", image(action, None)),
        ("changed", timestamp(instant)),
        ("uid", uid.to_owned()),
    ] {
        node.set(k, &v);
    }
    set_common(&mut node, common);
    let mut p = Node::new("Properties");
    for (k, v) in properties {
        if k != "cpassword" {
            p.set(k, v);
        }
    }
    p.children = children.to_vec();
    node.children.push(p);
    set_filters(&mut node, filters);
    Element { node, raw: None }
}

/// Changed copy of an element: same `uid`, unknown attributes and children kept, `changed` and
/// `image` updated, `cpassword` removed. `children` replaces the children of `Properties`
/// (values of a REG_MULTI_SZ) if given (`modifier_element`).
#[allow(clippy::too_many_arguments)]
pub fn modify_element(
    element: &Element,
    name: &str,
    status: &str,
    properties: &[(String, String)],
    common: &Common,
    filters: &[Filter],
    instant: i64,
    children: Option<&[Node]>,
) -> Element {
    let mut node = element.node.clone();
    node.set("name", name);
    node.set("status", status);
    let action = properties
        .iter()
        .find(|(k, _)| k == "action")
        .map_or_else(|| element.action(), |(_, v)| v.clone());
    let old = node.get("image").map(str::to_owned);
    node.set("image", &image(&action, old.as_deref()));
    node.set("changed", &timestamp(instant));
    set_common(&mut node, common);
    set_properties(&mut node, properties);
    if let (Some(children), Some(p)) = (children, node.find_mut("Properties")) {
        p.children = children.to_vec();
    }
    set_filters(&mut node, filters);
    Element { node, raw: None }
}

/// The document with other pieces (the origin no longer holds).
pub fn with_pieces(document: &Document, pieces: Vec<Piece>) -> Document {
    Document {
        pieces,
        origin: None,
        ..document.clone()
    }
}

/// Rank among the elements → index in `pieces`.
fn index(document: &Document, rank: usize) -> Option<usize> {
    document
        .pieces
        .iter()
        .enumerate()
        .filter(|(_, p)| matches!(p, Piece::Element(_)))
        .nth(rank)
        .map(|(i, _)| i)
}

/// `None` if `rank` is out of range.
pub fn replace(document: &Document, rank: usize, element: Element) -> Option<Document> {
    let i = index(document, rank)?;
    let mut pieces = document.pieces.clone();
    *pieces.get_mut(i)? = Piece::Element(element);
    Some(with_pieces(document, pieces))
}

/// Adds last, as the console.
pub fn add(document: &Document, element: Element) -> Document {
    let mut pieces = document.pieces.clone();
    pieces.push(Piece::Element(element));
    with_pieces(document, pieces)
}

pub fn remove(document: &Document, rank: usize) -> Option<Document> {
    let i = index(document, rank)?;
    let mut pieces = document.pieces.clone();
    pieces.remove(i);
    Some(with_pieces(document, pieces))
}

/// Swaps the element `rank` with the one `offset` ranks further (±1: up, down); raw pieces
/// stay in their place (`deplacer`).
pub fn shift(document: &Document, rank: usize, offset: isize) -> Option<Document> {
    let target = rank.checked_add_signed(offset)?;
    let (i, j) = (index(document, rank)?, index(document, target)?);
    let mut pieces = document.pieces.clone();
    pieces.swap(i, j);
    Some(with_pieces(document, pieces))
}

#[cfg(test)]
mod tests;

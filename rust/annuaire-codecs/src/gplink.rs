// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! GPO links: attributes `gPLink` and `gPOptions` (MS-GPOL 2.2.2).
//!
//! `gPLink` is a string of links put end to end:
//!
//! ```text
//! [LDAP://cn={GUID},cn=policies,cn=system,DC=example,DC=com;0][LDAP://…;2]
//! ```
//!
//! Each link holds the DN of a GPO and an integer of options: bit 0 (1) link disabled, bit 1
//! (2) link enforced. **The order of the string is the reverse of the link order** of the
//! GPMC: the last link of the string has order 1, the highest precedence on this container;
//! a new link goes at the head of the string (GPMC and `samba-tool gpo setlink`), last in
//! precedence.
//!
//! `gPOptions` = 1 blocks inheritance on the container; the other bits are not defined.
//!
//! Exact round trip: the original case (Samba writes `CN=…,CN=Policies`, the GPMC
//! `cn=…,cn=policies`), the order, links to an absent GPO or another domain, and even a
//! piece that is not shaped like a link (kept `Raw`, with its reason) are written back as
//! they were. A `gPLink` holding only a space (what some tools leave after removing the
//! last link) has no link.

use std::fmt;

use crate::integer::{self, IntegerError, Width};
use crate::pytext::strip_str as strip;

/// Link option: disabled.
pub const DISABLED: u64 = 0x1;
/// Link option: enforced.
pub const ENFORCED: u64 = 0x2;
/// `gPOptions`: inheritance blocked.
pub const INHERITANCE_BLOCKED: i64 = 0x1;
pub const PREFIX: &str = "LDAP://";

/// Why a value was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GpLinkError {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// No link at this position.
    NoLink(usize),
    /// `gPOptions` is not a 32-bit integer.
    Options(IntegerError),
}

impl fmt::Display for GpLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "gPLink is not UTF-8"),
            Self::NoLink(i) => write!(f, "no link at position {i}"),
            Self::Options(e) => write!(f, "gPOptions: {e}"),
        }
    }
}

impl std::error::Error for GpLinkError {}

/// Why a piece of the string was kept raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawReason {
    MissingPrefix,
    MissingOptions,
    UnreadableOptions,
    UnclosedBracket,
    TextOutsideLink,
}

impl fmt::Display for RawReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MissingPrefix => "LDAP:// prefix missing",
            Self::MissingOptions => "options missing",
            Self::UnreadableOptions => "unreadable options",
            Self::UnclosedBracket => "bracket not closed",
            Self::TextOutsideLink => "text outside a link",
        })
    }
}

/// A link: DN of the GPO as written, options, prefix as written (case kept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub dn: String,
    pub options: u64,
    pub prefix: String,
}

impl Link {
    pub fn new(dn: impl Into<String>, options: u64) -> Self {
        Self {
            dn: dn.into(),
            options,
            prefix: PREFIX.to_owned(),
        }
    }

    pub fn disabled(&self) -> bool {
        self.options & DISABLED != 0
    }

    pub fn enforced(&self) -> bool {
        self.options & ENFORCED != 0
    }

    /// `{GUID}` in upper case, taken from the first RDN (`cn={…}`), else `None`.
    pub fn guid(&self) -> Option<String> {
        let components = split_dn(&self.dn);
        let first = components.first()?;
        let (name, value) = first.split_once('=').unwrap_or((first, ""));
        if strip(name).to_lowercase() != "cn" || !is_braced_guid(value) {
            return None;
        }
        Some(value.to_uppercase())
    }

    /// `DC=…` part of the DN (lower case), to recognise a link to another domain.
    pub fn domain(&self) -> String {
        split_dn(&self.dn)
            .iter()
            .map(|c| strip(c).to_lowercase())
            .filter(|c| c.starts_with("dc="))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// True if the link designates this GPO DN (case and spaces after commas ignored).
    pub fn designates(&self, dn: &str) -> bool {
        normalise(&self.dn) == normalise(dn)
    }

    fn text(&self) -> String {
        format!("[{}{};{}]", self.prefix, self.dn, self.options)
    }
}

/// One piece of the string: a link, or text that is not a well-formed link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Element {
    Link(Link),
    Raw { text: String, reason: RawReason },
}

/// Value of `gPLink`: links and raw pieces in the order of the string.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GpLink {
    pub elements: Vec<Element>,
}

impl GpLink {
    /// Links in the order of the string (the last one has order 1).
    pub fn links(&self) -> impl DoubleEndedIterator<Item = &Link> {
        self.elements.iter().filter_map(|e| match e {
            Element::Link(l) => Some(l),
            Element::Raw { .. } => None,
        })
    }

    /// Links in the order of the GPMC: order 1 (highest precedence) first.
    pub fn by_precedence(&self) -> impl Iterator<Item = &Link> {
        self.links().rev()
    }

    /// `gPLink` string → value. Never fails: what is not a link stays `Raw`.
    pub fn parse(text: &str) -> Self {
        let mut elements = Vec::new();
        let mut rest = text;
        while !rest.is_empty() {
            if rest.starts_with('[') {
                let Some(end) = rest.find(']') else {
                    elements.push(Element::Raw {
                        text: rest.to_owned(),
                        reason: RawReason::UnclosedBracket,
                    });
                    break;
                };
                let (piece, after) = rest.split_at(end + 1);
                elements.push(read_link(piece));
                rest = after;
            } else {
                let end = rest.find('[').unwrap_or(rest.len());
                let (piece, after) = rest.split_at(end);
                elements.push(Element::Raw {
                    text: piece.to_owned(),
                    reason: RawReason::TextOutsideLink,
                });
                rest = after;
            }
        }
        Self { elements }
    }

    /// Inverse of `parse`, byte for byte.
    pub fn write(&self) -> String {
        self.elements
            .iter()
            .map(|e| match e {
                Element::Link(l) => l.text(),
                Element::Raw { text, .. } => text.clone(),
            })
            .collect()
    }

    /// LDAP value (UTF-8) → value; an error only if the bytes are not UTF-8.
    pub fn decode(bytes: &[u8]) -> Result<Self, GpLinkError> {
        std::str::from_utf8(bytes)
            .map(Self::parse)
            .map_err(|_| GpLinkError::NotUtf8)
    }

    pub fn encode(&self) -> Vec<u8> {
        self.write().into_bytes()
    }

    fn position(&self, link: usize) -> Result<usize, GpLinkError> {
        self.elements
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e, Element::Link(_)))
            .nth(link)
            .map(|(i, _)| i)
            .ok_or(GpLinkError::NoLink(link))
    }

    // Changes (J5.3). Positions are those of `links()` (order of the string); raw pieces
    // stay where they are.

    /// Adds a link at the head of the string, last in precedence (as the GPMC does).
    pub fn link(&self, gpo_dn: &str, options: u64) -> Self {
        let mut elements = Vec::with_capacity(self.elements.len() + 1);
        elements.push(Element::Link(Link::new(gpo_dn, options)));
        elements.extend(self.elements.iter().cloned());
        Self { elements }
    }

    /// Removes the link at this position of `links()`.
    pub fn unlink(&self, position: usize) -> Result<Self, GpLinkError> {
        let target = self.position(position)?;
        let mut elements = self.elements.clone();
        elements.remove(target);
        Ok(Self { elements })
    }

    /// Changes the options of the link at this position (DN and prefix kept).
    pub fn with_options(&self, position: usize, options: u64) -> Result<Self, GpLinkError> {
        let target = self.position(position)?;
        let mut elements = self.elements.clone();
        if let Some(Element::Link(link)) = elements.get_mut(target) {
            link.options = options;
        }
        Ok(Self { elements })
    }

    /// Moves a link from `position` to `new` in `links()` (raw pieces do not move); `new`
    /// past the end means last, like Python's `list.insert`.
    pub fn move_link(&self, position: usize, new: usize) -> Result<Self, GpLinkError> {
        let slots: Vec<usize> = self
            .elements
            .iter()
            .enumerate()
            .filter(|(_, e)| matches!(e, Element::Link(_)))
            .map(|(i, _)| i)
            .collect();
        let mut links: Vec<Link> = self.links().cloned().collect();
        if position >= links.len() {
            return Err(GpLinkError::NoLink(position));
        }
        let link = links.remove(position);
        links.insert(new.min(links.len()), link);
        let mut elements = self.elements.clone();
        for (slot, link) in slots.into_iter().zip(links) {
            if let Some(e) = elements.get_mut(slot) {
                *e = Element::Link(link);
            }
        }
        Ok(Self { elements })
    }

    /// Link order of the GPMC (1 = highest precedence) of the link at this position.
    pub fn link_order(&self, position: usize) -> usize {
        self.links().count().saturating_sub(position)
    }

    /// Positions (in `links()`) of the links to this GPO DN; a GPO can be linked twice.
    pub fn find(&self, gpo_dn: &str) -> Vec<usize> {
        self.links()
            .enumerate()
            .filter(|(_, l)| l.designates(gpo_dn))
            .map(|(i, _)| i)
            .collect()
    }
}

/// Components of a DN, escaped commas respected (values not unescaped).
fn split_dn(dn: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut chars = dn.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                current.push(c);
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ',' => parts.push(std::mem::take(&mut current)),
            _ => current.push(c),
        }
    }
    parts.push(current);
    parts
}

fn normalise(dn: &str) -> String {
    split_dn(dn)
        .iter()
        .map(|c| {
            let (name, value) = c.split_once('=').unwrap_or((c, ""));
            format!(
                "{}={}",
                strip(name).to_lowercase(),
                strip(value).to_lowercase()
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn is_braced_guid(text: &str) -> bool {
    let Some(body) = text.strip_prefix('{').and_then(|t| t.strip_suffix('}')) else {
        return false;
    };
    text.len() == 38
        && body.split('-').map(str::len).eq([8, 4, 4, 4, 12])
        && body.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
}

/// A whole `[…]` piece → `Link` if it is shaped like one, else `Raw`.
fn read_link(text: &str) -> Element {
    let raw = |reason| Element::Raw {
        text: text.to_owned(),
        reason,
    };
    let inner = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or_default();
    // The first seven characters (not bytes), upper-cased as Python does.
    let cut = inner
        .char_indices()
        .nth(PREFIX.len())
        .map_or(inner.len(), |(i, _)| i);
    let (prefix, body) = inner.split_at(cut);
    if prefix.to_uppercase() != PREFIX {
        return raw(RawReason::MissingPrefix);
    }
    let Some((dn, options)) = body.rsplit_once(';') else {
        return raw(RawReason::MissingOptions);
    };
    if dn.is_empty() {
        return raw(RawReason::MissingOptions);
    }
    let canonical = !options.is_empty()
        && options.bytes().all(|b| b.is_ascii_digit())
        && (options == "0" || !options.starts_with('0'));
    // Beyond 2^64 - 1 the options stay raw (Python keeps any size of integer).
    match options.parse::<u64>() {
        Ok(value) if canonical => Element::Link(Link {
            dn: dn.to_owned(),
            options: value,
            prefix: prefix.to_owned(),
        }),
        _ => raw(RawReason::UnreadableOptions),
    }
}

/// `gPOptions` (signed 32-bit integer in decimal).
pub fn decode_gpoptions(bytes: &[u8]) -> Result<i64, GpLinkError> {
    integer::decode(bytes, Width::Bits32).map_err(GpLinkError::Options)
}

pub fn inheritance_blocked(gpoptions: i64) -> bool {
    gpoptions & INHERITANCE_BLOCKED != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const DN: &str =
        "cn={31B2F340-016D-11D2-945F-00C04FB984F9},cn=policies,cn=system,DC=lab,DC=test";

    #[test]
    fn round_trip_and_raw_pieces() {
        for text in [
            "",
            " ",
            "[LDAP://cn={A},CN=Policies;0]",
            "[ldap://x;1][LDAP://y;2]",
            "junk[LDAP://x;01]",
            "[LDAP://x]",
            "[LDAP://;0]",
            "[LDAP://x;0",
            "[LDAP://x;99999999999999999999999]",
            "[ŁDAP://x;0]",
        ] {
            assert_eq!(GpLink::parse(text).write(), text);
        }
        let g = GpLink::parse(" ");
        assert_eq!(g.links().count(), 0);
    }

    #[test]
    fn properties() {
        let g = GpLink::parse(&format!("[LDAP://{DN};3]"));
        let link = g.links().next().unwrap();
        assert!(link.disabled() && link.enforced());
        assert_eq!(
            link.guid().as_deref(),
            Some("{31B2F340-016D-11D2-945F-00C04FB984F9}")
        );
        assert_eq!(link.domain(), "dc=lab,dc=test");
        assert!(link.designates(&DN.to_uppercase().replace(",", ", ")));
    }

    #[test]
    fn changes() {
        let g = GpLink::parse("[LDAP://a;0]x[LDAP://b;0]");
        let g2 = g.link("c", 2);
        assert_eq!(g2.write(), "[LDAP://c;2][LDAP://a;0]x[LDAP://b;0]");
        assert_eq!(g2.unlink(1).unwrap().write(), "[LDAP://c;2]x[LDAP://b;0]");
        assert_eq!(
            g2.with_options(2, 1).unwrap().write(),
            "[LDAP://c;2][LDAP://a;0]x[LDAP://b;1]"
        );
        assert_eq!(
            g2.move_link(0, 9).unwrap().write(),
            "[LDAP://a;0][LDAP://b;0]x[LDAP://c;2]"
        );
        assert_eq!(g2.link_order(0), 3);
        assert_eq!(g2.find("B"), [2]);
        assert!(g2.unlink(3).is_err());
    }
}

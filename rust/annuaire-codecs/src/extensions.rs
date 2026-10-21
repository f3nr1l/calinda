// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `gPCMachineExtensionNames` and `gPCUserExtensionNames`: client-side extensions of a GPO
//! (MS-GPOL 2.2.4).
//!
//! A sequence of groups `[{CSE}{tool}{tool}…]`: the GUID of the client-side extension the
//! computer must call for this part of the GPO, then the GUIDs of the editor extensions
//! ("tools") that wrote the content. As written by the GPMC (Windows Server 2025 and RSAT of
//! Windows 11 on Samba, 2026-10-14): groups sorted by extension GUID, tools sorted within
//! their group, GUIDs in upper case, no separator; attribute absent when empty. The sort
//! follows the order of the upper-case text, as the GPMC does.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::pytext::strip_str as strip;

/// Client-side extension "Registry" (administrative templates, `Registry.pol`).
pub const REGISTRY: &str = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}";
/// Editor extension "Administrative templates", computer part.
pub const REGISTRY_TOOL_MACHINE: &str = "{D02B1F72-3407-48AE-BA88-E8213C6761F1}";
/// Editor extension "Administrative templates", user part.
pub const REGISTRY_TOOL_USER: &str = "{D02B1F73-3407-48AE-BA88-E8213C6761F1}";

/// The text is not a sequence of groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtensionsError {
    NotUtf8,
    Unreadable { position: usize, text: String },
}

impl fmt::Display for ExtensionsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 => write!(f, "GPO extension list is not UTF-8"),
            Self::Unreadable { position, text } => {
                write!(
                    f,
                    "GPO extension list unreadable at position {position}: {text}"
                )
            }
        }
    }
}

impl std::error::Error for ExtensionsError {}

/// One group: the client-side extension and the tools that use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    pub cse: String,
    pub tools: Vec<String>,
}

/// (client-side extension, tool): what a content writer declares.
pub type Pair = (String, String);

/// Length of `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`.
const GUID_LEN: usize = 38;

fn braced_guid_at(bytes: &[u8], at: usize) -> bool {
    let Some(g) = bytes.get(at..at + GUID_LEN) else {
        return false;
    };
    g.iter().enumerate().all(|(i, &b)| match i {
        0 => b == b'{',
        37 => b == b'}',
        9 | 14 | 19 | 24 => b == b'-',
        _ => b.is_ascii_hexdigit(),
    })
}

/// The groups in text order, GUIDs in upper case; empty text: none.
pub fn decode(text: &str) -> Result<Vec<Extension>, ExtensionsError> {
    let text = strip(text);
    let bytes = text.as_bytes();
    let mut groups = Vec::new();
    let mut position = 0;
    while position < bytes.len() {
        // `[`, one GUID or more, `]`.
        let mut cursor = position + 1;
        let mut guids = Vec::new();
        if bytes.get(position) == Some(&b'[') {
            while braced_guid_at(bytes, cursor) {
                guids.push(
                    text.get(cursor..cursor + GUID_LEN)
                        .unwrap_or_default()
                        .to_ascii_uppercase(),
                );
                cursor += GUID_LEN;
            }
        }
        let Some((cse, tools)) = guids.split_first() else {
            break;
        };
        if bytes.get(cursor) != Some(&b']') {
            break;
        }
        groups.push(Extension {
            cse: cse.clone(),
            tools: tools.to_vec(),
        });
        position = cursor + 1;
    }
    if position != bytes.len() {
        return Err(ExtensionsError::Unreadable {
            position: text.get(..position).map_or(position, |t| t.chars().count()),
            text: text.to_owned(),
        });
    }
    Ok(groups)
}

/// `decode` of the bytes of an LDAP value.
pub fn decode_bytes(bytes: &[u8]) -> Result<Vec<Extension>, ExtensionsError> {
    decode(std::str::from_utf8(bytes).map_err(|_| ExtensionsError::NotUtf8)?)
}

/// The form of the GPMC: groups sorted by extension, tools sorted and without duplicates.
pub fn encode(groups: &[Extension]) -> String {
    let mut merged: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for g in groups {
        merged
            .entry(g.cse.to_uppercase())
            .or_default()
            .extend(g.tools.iter().map(|t| t.to_uppercase()));
    }
    merged
        .into_iter()
        .map(|(cse, tools)| format!("[{cse}{}]", tools.into_iter().collect::<String>()))
        .collect()
}

/// The (extension, tool) pairs of the groups.
pub fn pairs(groups: &[Extension]) -> BTreeSet<Pair> {
    groups
        .iter()
        .flat_map(|g| g.tools.iter().map(|t| (g.cse.clone(), t.clone())))
        .collect()
}

/// The tools of `cse` in `result`, the entry made at the end if missing (insertion order
/// kept, as Python's dict).
fn entry<'a>(result: &'a mut Vec<(String, Vec<String>)>, cse: &str) -> &'a mut Vec<String> {
    if !result.iter().any(|(c, _)| c == cse) {
        result.push((cse.to_owned(), Vec::new()));
    }
    let found = result.iter_mut().find(|(c, _)| c == cse);
    &mut found.expect("entry just made").1
}

/// The groups with these pairs added and removed. A group whose last tool goes away
/// disappears; a group without a tool to begin with is kept as is.
pub fn with(groups: &[Extension], add: &[Pair], remove: &[Pair]) -> Vec<Extension> {
    let removed: BTreeSet<Pair> = remove
        .iter()
        .map(|(c, t)| (c.to_uppercase(), t.to_uppercase()))
        .collect();
    let mut result: Vec<(String, Vec<String>)> = Vec::new();
    let mut without_tool: BTreeSet<String> = BTreeSet::new();
    for g in groups {
        let tools = entry(&mut result, &g.cse);
        if g.tools.is_empty() {
            without_tool.insert(g.cse.clone());
        }
        for t in &g.tools {
            if !removed.contains(&(g.cse.clone(), t.clone())) && !tools.contains(t) {
                tools.push(t.clone());
            }
        }
    }
    for (cse, tool) in add {
        let tools = entry(&mut result, &cse.to_uppercase());
        let tool = tool.to_uppercase();
        if !tools.contains(&tool) {
            tools.push(tool);
        }
    }
    result
        .into_iter()
        .filter(|(cse, tools)| !tools.is_empty() || without_tool.contains(cse))
        .map(|(cse, tools)| Extension { cse, tools })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const ADMX: &str =
        "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]";

    #[test]
    fn decode_and_encode() {
        let groups = decode(&format!("  {}\n", ADMX.to_lowercase())).unwrap();
        assert_eq!(groups[0].cse, REGISTRY);
        assert_eq!(groups[0].tools, [REGISTRY_TOOL_MACHINE]);
        assert_eq!(encode(&groups), ADMX);
        assert!(decode("").unwrap().is_empty());
        for bad in [
            "[]",
            "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}",
            "x",
            "[{1}]",
        ] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn add_and_remove() {
        let groups = decode(ADMX).unwrap();
        let pair = (REGISTRY.to_owned(), REGISTRY_TOOL_MACHINE.to_owned());
        assert!(with(&groups, &[], std::slice::from_ref(&pair)).is_empty());
        let user = (REGISTRY.to_lowercase(), REGISTRY_TOOL_USER.to_owned());
        let both = with(&groups, &[user], &[]);
        assert_eq!(both[0].tools.len(), 2);
        assert_eq!(pairs(&both).len(), 2);
    }
}

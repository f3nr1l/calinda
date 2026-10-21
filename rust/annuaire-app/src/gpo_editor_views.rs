// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Content editor of a GPO (J7.3, `annuaire.vue.editeur_gpo`), without GTK: the tree and what
//! the sections exchange.
//!
//! The tree follows that of the GPMC editor:
//!
//! ```text
//! Computer Configuration
//!   Policies
//!     Windows Settings                  (Anchor::WindowsSettings: security, J7.5)
//!     Administrative Templates          (Anchor::Templates: ADMX categories, J7.3)
//!   Preferences
//!     Windows Settings                  (Anchor::PreferencesWindows: J7.6)
//!     Control Panel Settings            (Anchor::PreferencesControlPanel)
//! User Configuration
//!   (likewise)
//! ```
//!
//! Each **section** (administrative templates, security, preferences) puts its nodes under an
//! anchor, reads the files it declares (`ContentFile`) and gives its draft as `Modification`:
//! new whole content of a file, extension to declare, lines in clear for the preview. An
//! anchor without a node is not shown, but « Administrative Templates ».

use std::sync::Arc;

use annuaire_codecs::extensions::Pair;
use annuaire_core::gpo::Part;
use annuaire_core::gpo_write::GpoError;
use annuaire_core::gpp::Family;

use crate::i18n::{fill, tr};
use crate::template_views::TemplateView;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Anchor {
    WindowsSettings,
    Templates,
    PreferencesWindows,
    PreferencesControlPanel,
}

impl Anchor {
    pub fn value(self) -> &'static str {
        match self {
            Self::WindowsSettings => "parametres-windows",
            Self::Templates => "modeles",
            Self::PreferencesWindows => "preferences-windows",
            Self::PreferencesControlPanel => "preferences-panneau",
        }
    }

    pub fn title(self) -> String {
        match self {
            Self::WindowsSettings | Self::PreferencesWindows => tr("Windows Settings"),
            Self::Templates => tr("Administrative Templates"),
            Self::PreferencesControlPanel => tr("Control Panel Settings"),
        }
    }
}

/// The value of a part in the keys of the tree (`Partie.value`).
pub fn part_value(part: Part) -> &'static str {
    match part {
        Part::Computer => "ordinateur",
        Part::User => "utilisateur",
    }
}

pub fn part_label(part: Part) -> String {
    match part {
        Part::Computer => tr("Computer Configuration"),
        Part::User => tr("User Configuration"),
    }
}

/// What a section wants to find again in one of its nodes (`donnee`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeData {
    None,
    Templates(TemplateView),
    Security(String),
    Preferences(Part, Family),
}

/// A node of the tree. `key` is unique in the tree (prefixed by the section); `section`: the
/// one that shows the page of the node (empty for the nodes of the editor) (`Noeud`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorNode {
    pub key: String,
    pub title: String,
    pub section: &'static str,
    pub icon: &'static str,
    pub children: Vec<EditorNode>,
    pub data: NodeData,
    pub accessible: String,
}

impl EditorNode {
    pub fn new(key: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            section: "",
            icon: "folder-symbolic",
            children: Vec::new(),
            data: NodeData::None,
            accessible: String::new(),
        }
    }

    pub fn section(mut self, section: &'static str) -> Self {
        self.section = section;
        self
    }

    pub fn icon(mut self, icon: &'static str) -> Self {
        self.icon = icon;
        self
    }

    pub fn children(mut self, children: Vec<EditorNode>) -> Self {
        self.children = children;
        self
    }

    pub fn data(mut self, data: NodeData) -> Self {
        self.data = data;
        self
    }

    /// The name AT-SPI says.
    pub fn accessible_name(&self) -> &str {
        if self.accessible.is_empty() {
            &self.title
        } else {
            &self.accessible
        }
    }
}

/// A content file of a GPO: `path` relative to the folder of the part (`Machine` or `User`),
/// separated by `\` (`Fichier`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContentFile {
    pub part: Part,
    pub path: String,
}

impl ContentFile {
    pub fn new(part: Part, path: &str) -> Self {
        Self {
            part,
            path: path.to_owned(),
        }
    }
}

/// The new whole content of a file (`None`: delete it) from the content **read again when
/// writing** (`None`: absent).
pub type Modify = Arc<dyn Fn(Option<&[u8]>) -> Result<Option<Vec<u8>>, GpoError> + Send + Sync>;

/// What a section wants to write in a file (`Modification`). `modify` gives the new content
/// from the content read again when writing: a change made meanwhile by another tool is kept if
/// the section knows how to replay it. `extension`: the pair (client-side extension, tool) to
/// declare in the GPO (`None`: nothing); `lines`: what the preview says in clear;
/// `remove_extensions`: pairs to remove from the GPO (last element of a family of preferences
/// gone).
#[derive(Clone)]
pub struct Modification {
    pub file: ContentFile,
    pub modify: Modify,
    pub extension: Option<Pair>,
    pub lines: Vec<String>,
    pub remove_extensions: Vec<Pair>,
}

impl std::fmt::Debug for Modification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Modification")
            .field("file", &self.file)
            .field("lines", &self.lines)
            .finish_non_exhaustive()
    }
}

pub fn part_key(part: Part) -> String {
    format!("partie:{}", part_value(part))
}

/// Key of the node of an anchor. A section that gives, for an anchor, one node of this key
/// replaces the node of the editor: its page is then its own (`cle_ancre`).
pub fn anchor_key(part: Part, anchor: Anchor) -> String {
    format!("ancre:{}:{}", part_value(part), anchor.value())
}

fn anchor_node(
    part: Part,
    a: Anchor,
    by_anchor: &[(Anchor, Vec<EditorNode>)],
) -> Option<EditorNode> {
    let children: Vec<EditorNode> = by_anchor
        .iter()
        .filter(|(x, _)| *x == a)
        .flat_map(|(_, n)| n.iter().cloned())
        .collect();
    if children.is_empty() && a != Anchor::Templates {
        return None;
    }
    let key = anchor_key(part, a);
    if let [only] = children.as_slice()
        && only.key == key
    {
        // The section gives the node of the anchor itself (and so its page).
        return Some(only.clone());
    }
    Some(EditorNode::new(key, a.title()).children(children))
}

/// The nodes of the sections, by anchor.
pub type AnchoredNodes = Vec<(Anchor, Vec<EditorNode>)>;

/// The two parts, with under each the nodes of the sections under their anchors
/// (« Administrative Templates » always there, the other anchors only if they have nodes;
/// « Preferences » only if one of its anchors has some) (`arbre`).
pub fn tree(nodes: &[(Part, AnchoredNodes)]) -> Vec<EditorNode> {
    let mut roots = Vec::new();
    for part in [Part::Computer, Part::User] {
        let by_anchor: Vec<(Anchor, Vec<EditorNode>)> = nodes
            .iter()
            .filter(|(p, _)| *p == part)
            .flat_map(|(_, n)| n.iter().cloned())
            .collect();
        let p = part_value(part);
        let policies: Vec<EditorNode> = [Anchor::WindowsSettings, Anchor::Templates]
            .into_iter()
            .filter_map(|a| anchor_node(part, a, &by_anchor))
            .collect();
        let preferences: Vec<EditorNode> =
            [Anchor::PreferencesWindows, Anchor::PreferencesControlPanel]
                .into_iter()
                .filter_map(|a| anchor_node(part, a, &by_anchor))
                .collect();
        let mut children = vec![
            EditorNode::new(format!("ancre:{p}:strategies"), tr("Policies")).children(policies),
        ];
        if !preferences.is_empty() {
            children.push(
                EditorNode::new(format!("ancre:{p}:preferences"), tr("Preferences"))
                    .children(preferences),
            );
        }
        let icon = match part {
            Part::Computer => "computer-symbolic",
            Part::User => "avatar-default-symbolic",
        };
        roots.push(
            EditorNode::new(part_key(part), part_label(part))
                .icon(icon)
                .children(children),
        );
    }
    roots
}

/// Nodes from the root down to the one of key `key` (empty if not in the tree) (`chemin_vers`).
pub fn path_to<'a>(nodes: &'a [EditorNode], key: &str) -> Vec<&'a EditorNode> {
    for n in nodes {
        if n.key == key {
            return vec![n];
        }
        let rest = path_to(&n.children, key);
        if !rest.is_empty() {
            let mut out = vec![n];
            out.extend(rest);
            return out;
        }
    }
    Vec::new()
}

pub fn part_of(key: &str, nodes: &[EditorNode]) -> Option<Part> {
    let path = path_to(nodes, key);
    let first = path.first()?;
    [Part::Computer, Part::User]
        .into_iter()
        .find(|p| first.key == part_key(*p))
}

/// « n unsaved change(s) », empty without change (`resume_modifications`).
pub fn changes_summary(modifications: &[Modification]) -> String {
    let n: usize = modifications.iter().map(|m| m.lines.len().max(1)).sum();
    if n == 0 {
        return String::new();
    }
    fill(&tr("{n} unsaved change(s)"), &[("n", &n.to_string())])
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn tree_of_the_gpmc() {
        let security = EditorNode::new("secu:ordinateur", "Security");
        let nodes = vec![(
            Part::Computer,
            vec![(Anchor::WindowsSettings, vec![security])],
        )];
        let t = tree(&nodes);
        assert_eq!(t.len(), 2);
        assert_eq!(t[0].key, "partie:ordinateur");
        let policies = &t[0].children[0];
        assert_eq!(policies.key, "ancre:ordinateur:strategies");
        let keys: Vec<&str> = policies.children.iter().map(|n| n.key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "ancre:ordinateur:parametres-windows",
                "ancre:ordinateur:modeles"
            ]
        );
        // No preference node: no « Preferences ».
        assert_eq!(t[0].children.len(), 1);
        assert_eq!(t[1].children[0].children.len(), 1);
        let path = path_to(&t, "secu:ordinateur");
        assert_eq!(path.len(), 4);
        assert_eq!(part_of("secu:ordinateur", &t), Some(Part::Computer));
        assert_eq!(part_of("absent", &t), None);
        // A section that gives the node of the anchor itself replaces it.
        let own = EditorNode::new(anchor_key(Part::User, Anchor::Templates), "Own").section("admx");
        let t = tree(&[(Part::User, vec![(Anchor::Templates, vec![own.clone()])])]);
        assert_eq!(t[1].children[0].children[0], own);
    }
}

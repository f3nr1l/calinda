// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Texts and tree of the « Group Policy » window (J5.2, `annuaire.vue.gpo`), and its write
//! actions (J5.3 to J5.6, `annuaire.vue.gpo_ecriture`), without GTK.
//!
//! The tree follows the one of the GPMC: the domain, its nested OUs, and under each container
//! its linked GPOs **in the order of the links** (order 1, the highest precedence, first), a
//! link disabled, enforced or to a GPO missing said plainly; a container that blocks the
//! inheritance says it. At the head, « Group Policy Objects »: every GPO, linked or not; then,
//! if the SYSVOL of the PDC shows some, « Inconsistencies »: folders of the SYSVOL without a
//! GPO object (orphans) and GPOs without a folder.

use std::collections::{HashMap, HashSet};

use annuaire_codecs::Sid;
use annuaire_codecs::gplink::{Element, Link};
use annuaire_codecs::time::UtcTime;
use annuaire_core::dn;
use annuaire_core::gpo::{
    Container, Deviation, Gpo, GpoDirectory, GptError, Inventory, Part, SysvolDc, SysvolGpo,
    SysvolReadError, Versions, versions,
};
use annuaire_core::gpo_backup::Backup;
use annuaire_core::security::SidName;
use gtk::glib;

use crate::errors;
use crate::i18n::{fill, tr, tr_ctx, tr_n};
use crate::security_views::sid_name;

pub const ICON_DOMAIN: &str = "network-workgroup-symbolic";
pub const ICON_OU: &str = "folder-symbolic";
pub const ICON_GPO: &str = "text-x-generic-symbolic";
pub const ICON_LINK: &str = "emblem-symbolic-link-symbolic";
pub const ICON_LINK_DISABLED: &str = "action-unavailable-symbolic";
pub const ICON_ALL: &str = "view-list-symbolic";
pub const ICON_INCONSISTENCIES: &str = "dialog-warning-symbolic";

type Names = HashMap<Sid, SidName>;

/// What a node is (`Genre`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Domain,
    Ou,
    Link,
    All,
    Gpo,
    Inconsistencies,
    Orphan,
}

impl Kind {
    fn value(self) -> &'static str {
        match self {
            Self::Domain => "domaine",
            Self::Ou => "ou",
            Self::Link => "lien",
            Self::All => "toutes",
            Self::Gpo => "gpo",
            Self::Inconsistencies => "incoherences",
            Self::Orphan => "orphelin",
        }
    }
}

/// A node of the tree (`NoeudGpo`). `order`: order of the link in its container (1 = highest
/// precedence); `gpo` None for a link to a GPO missing from the directory; `folder`: written
/// name of an orphan folder (`{GUID}`).
#[derive(Debug, Clone, PartialEq)]
pub struct GpoNode {
    pub kind: Kind,
    pub title: String,
    pub subtitle: String,
    pub icon: &'static str,
    pub container: Option<Container>,
    pub link: Option<Link>,
    pub gpo: Option<Gpo>,
    pub order: usize,
    pub children: Vec<GpoNode>,
    pub alert: bool,
    pub folder: String,
}

impl GpoNode {
    fn new(kind: Kind, title: String, subtitle: String, icon: &'static str) -> Self {
        Self {
            kind,
            title,
            subtitle,
            icon,
            container: None,
            link: None,
            gpo: None,
            order: 0,
            children: Vec::new(),
            alert: false,
            folder: String::new(),
        }
    }

    pub fn accessible(&self) -> String {
        if self.subtitle.is_empty() {
            self.title.clone()
        } else {
            format!("{}, {}", self.title, self.subtitle)
        }
    }

    /// Stable identifier of a node between two readings (to choose it again) (`cle`).
    pub fn key(&self) -> String {
        if let (Kind::Link, Some(container), Some(link)) = (self.kind, &self.container, &self.link)
        {
            return format!(
                "lien:{}:{}:{}",
                container.dn.to_lowercase(),
                self.order,
                link.dn.to_lowercase()
            );
        }
        if let (Kind::Gpo, Some(gpo)) = (self.kind, &self.gpo) {
            return format!("gpo:{}", gpo.guid);
        }
        if self.kind == Kind::Orphan {
            return format!("orphelin:{}", self.folder.to_uppercase());
        }
        if let Some(container) = &self.container {
            return format!("conteneur:{}", container.dn.to_lowercase());
        }
        self.kind.value().to_owned()
    }
}

/// « user {u}, computer {o} » (`str(Versions)`).
pub fn versions_text(v: Versions) -> String {
    fill(
        &tr("user {u}, computer {o}"),
        &[("u", &v.user.to_string()), ("o", &v.computer.to_string())],
    )
}

/// « enforced, link disabled » …; empty for an ordinary active link (`etat_lien`).
pub fn link_state(link: &Link, gpo: Option<&Gpo>) -> String {
    let mut pieces = Vec::new();
    if link.enforced() {
        pieces.push(tr("enforced"));
    }
    if link.disabled() {
        pieces.push(tr("link disabled"));
    }
    match gpo {
        None => pieces.push(tr("GPO missing from the directory")),
        Some(g) if g.disabled(Part::User) || g.disabled(Part::Computer) => {
            pieces.push(gpo_state(g).to_lowercase());
        }
        Some(_) => {}
    }
    pieces.join(", ")
}

/// `etat_gpo`.
pub fn gpo_state(gpo: &Gpo) -> String {
    match (gpo.disabled(Part::User), gpo.disabled(Part::Computer)) {
        (true, true) => tr("All settings disabled"),
        (true, false) => tr("User configuration settings disabled"),
        (false, true) => tr("Computer configuration settings disabled"),
        (false, false) => tr_ctx("feminine", "Enabled"),
    }
}

/// Links of a container, order 1 first (`_noeuds_liens`).
fn link_nodes(container: &Container, gpos: &HashMap<String, Gpo>) -> Vec<GpoNode> {
    let links: Vec<&Link> = container.gplink.links().collect();
    let mut nodes = Vec::new();
    for position in (0..links.len()).rev() {
        let Some(link) = links.get(position) else {
            continue;
        };
        let gpo = link.guid().and_then(|g| gpos.get(&g)).cloned();
        let order = container.gplink.link_order(position);
        let state = link_state(link, gpo.as_ref());
        let mut subtitle = fill(&tr("order {n}"), &[("n", &order.to_string())]);
        if !state.is_empty() {
            subtitle.push_str(&format!(", {state}"));
        }
        let title = gpo
            .as_ref()
            .map(|g| g.name.clone())
            .or_else(|| link.guid())
            .unwrap_or_else(|| link.dn.clone());
        let icon = if link.disabled() || gpo.is_none() {
            ICON_LINK_DISABLED
        } else {
            ICON_LINK
        };
        nodes.push(GpoNode {
            container: Some(container.clone()),
            link: Some((*link).clone()),
            alert: gpo.is_none(),
            gpo,
            order,
            ..GpoNode::new(Kind::Link, title, subtitle, icon)
        });
    }
    nodes
}

fn key_of(dn_text: &str) -> String {
    dn::split(dn_text)
        .ok()
        .and_then(|c| dn::compose(&c).ok())
        .unwrap_or_else(|| dn_text.to_owned())
        .to_lowercase()
}

fn parent_key(dn_text: &str) -> String {
    let components = dn::split(dn_text).unwrap_or_default();
    if components.len() > 1 {
        dn::compose(components.get(1..).unwrap_or_default())
            .unwrap_or_default()
            .to_lowercase()
    } else {
        String::new()
    }
}

fn by_name(gpos: &HashMap<String, Gpo>) -> Vec<&Gpo> {
    let mut list: Vec<&Gpo> = gpos.values().collect();
    list.sort_by_cached_key(|g| g.name.to_lowercase());
    list
}

/// Roots of the tree (`arbre`): « Group Policy Objects », « Inconsistencies » if there are
/// some (`inventory`: the SYSVOL of the PDC is read), then the domain (nested OUs, links of
/// each container before its child OUs). The domain is always the last root.
pub fn tree(directory: &GpoDirectory, inventory: Option<&Inventory>) -> Vec<GpoNode> {
    let gpos = &directory.gpos;
    let mut children: HashMap<String, Vec<&Container>> = HashMap::new();
    let mut root: Option<Container> = None;
    for c in &directory.containers {
        if c.dn.eq_ignore_ascii_case(&directory.domain) {
            root = Some(c.clone());
            continue;
        }
        children.entry(parent_key(&c.dn)).or_default().push(c);
    }
    fn node(
        c: &Container,
        children: &HashMap<String, Vec<&Container>>,
        gpos: &HashMap<String, Gpo>,
        dns_name: &str,
    ) -> GpoNode {
        let mut under: Vec<&Container> = children.get(&key_of(&c.dn)).cloned().unwrap_or_default();
        under.sort_by_cached_key(|x| x.name.to_lowercase());
        let domain = c.class == "domainDNS";
        let mut kids = link_nodes(c, gpos);
        kids.extend(under.into_iter().map(|x| node(x, children, gpos, dns_name)));
        GpoNode {
            container: Some(c.clone()),
            children: kids,
            ..GpoNode::new(
                if domain { Kind::Domain } else { Kind::Ou },
                if domain {
                    dns_name.to_owned()
                } else {
                    c.name.clone()
                },
                if c.inheritance_blocked() {
                    tr("inheritance blocked")
                } else {
                    String::new()
                },
                if domain { ICON_DOMAIN } else { ICON_OU },
            )
        }
    }
    let n = u64::try_from(gpos.len()).unwrap_or(0);
    let all = GpoNode {
        children: by_name(gpos)
            .into_iter()
            .map(|g| GpoNode {
                gpo: Some(g.clone()),
                ..GpoNode::new(Kind::Gpo, g.name.clone(), String::new(), ICON_GPO)
            })
            .collect(),
        ..GpoNode::new(
            Kind::All,
            tr("Group Policy Objects"),
            fill(&tr_n("{n} GPO", "{n} GPOs", n), &[("n", &n.to_string())]),
            ICON_ALL,
        )
    };
    let root = root.unwrap_or_else(|| Container {
        dn: directory.domain.clone(),
        name: directory.dns_name.clone(),
        class: "domainDNS".into(),
        gplink: Default::default(),
        gpoptions: 0,
    });
    let domain = node(&root, &children, gpos, &directory.dns_name);
    match inventory.and_then(inconsistencies_node) {
        Some(inconsistencies) => vec![all, inconsistencies, domain],
        None => vec![all, domain],
    }
}

/// « Inconsistencies »: folders of the SYSVOL of the PDC without a GPO object, then GPOs
/// without a folder; None if there is none (or if the SYSVOL of the PDC could not be read)
/// (`noeud_incoherences`).
pub fn inconsistencies_node(inventory: &Inventory) -> Option<GpoNode> {
    let mut children: Vec<GpoNode> = inventory
        .orphans()
        .into_iter()
        .map(|name| GpoNode {
            alert: true,
            folder: name.clone(),
            ..GpoNode::new(
                Kind::Orphan,
                name,
                tr("SYSVOL folder without a GPO"),
                ICON_GPO,
            )
        })
        .collect();
    for guid in inventory.without_folder() {
        let Some(gpo) = inventory.directory.gpos.get(&guid) else {
            continue;
        };
        children.push(GpoNode {
            gpo: Some(gpo.clone()),
            alert: true,
            ..GpoNode::new(
                Kind::Gpo,
                gpo.name.clone(),
                tr("GPO without a folder in the SYSVOL"),
                ICON_GPO,
            )
        });
    }
    if children.is_empty() {
        return None;
    }
    let n = u64::try_from(children.len()).unwrap_or(0);
    Some(GpoNode {
        children,
        alert: true,
        ..GpoNode::new(
            Kind::Inconsistencies,
            tr("Inconsistencies"),
            fill(
                &tr_n("{n} inconsistency", "{n} inconsistencies", n),
                &[("n", &n.to_string())],
            ),
            ICON_INCONSISTENCIES,
        )
    })
}

/// The nodes of GPOs (and of links) whose GUID has an alert carry it (`marquer_alertes`).
pub fn mark_alerts(nodes: Vec<GpoNode>, alerts: &HashSet<String>) -> Vec<GpoNode> {
    nodes
        .into_iter()
        .map(|mut n| {
            let guid = n.gpo.as_ref().map(|g| g.guid.clone());
            n.alert = n.alert || guid.is_some_and(|g| alerts.contains(&g));
            n.children = mark_alerts(std::mem::take(&mut n.children), alerts);
            n
        })
        .collect()
}

// --- Detail of a GPO ---------------------------------------------------------------------------

/// A row of detail: title, value, and `alert` if it signals a problem (`Ligne`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub title: String,
    pub value: String,
    pub alert: bool,
}

impl Line {
    fn new(title: String, value: String) -> Self {
        Self {
            title,
            value,
            alert: false,
        }
    }

    fn alert(title: String, value: String, alert: bool) -> Self {
        Self {
            title,
            value,
            alert,
        }
    }
}

/// A place where a GPO is linked (`LienDe`).
#[derive(Debug, Clone, PartialEq)]
pub struct LinkOf {
    pub container: Container,
    pub link: Link,
    pub order: usize,
}

impl LinkOf {
    pub fn title(&self) -> String {
        self.container.dn.clone()
    }

    pub fn state(&self) -> String {
        [
            fill(&tr("order {n}"), &[("n", &self.order.to_string())]),
            if self.link.enforced() {
                tr("enforced")
            } else {
                tr("not enforced")
            },
            if self.link.disabled() {
                tr("link disabled")
            } else {
                tr("link enabled")
            },
        ]
        .join(", ")
    }
}

/// Containers where the GPO is linked, in the order of the tree (`liens_de`).
pub fn links_of(directory: &GpoDirectory, guid: &str) -> Vec<LinkOf> {
    let mut found = Vec::new();
    for c in directory.containers.iter().chain(&directory.linked_sites) {
        for (position, link) in c.gplink.links().enumerate() {
            if link.guid().as_deref() == Some(guid) {
                found.push(LinkOf {
                    container: c.clone(),
                    link: link.clone(),
                    order: c.gplink.link_order(position),
                });
            }
        }
    }
    found
}

/// Local date and time to the minute, « unknown » without a date (`_date`).
fn date(value: Option<&UtcTime>) -> String {
    value
        .and_then(|d| glib::DateTime::from_unix_local(d.unix_seconds()).ok())
        .and_then(|d| d.format(&tr("%d/%m/%Y %H:%M")).ok())
        .map_or_else(|| tr("unknown"), |s| s.to_string())
}

/// `lignes_etat`.
pub fn state_lines(gpo: &Gpo) -> Vec<Line> {
    vec![
        Line::new(tr("Status"), gpo_state(gpo)),
        Line::new(tr("Unique ID"), gpo.guid.clone()),
        Line::new(tr_ctx("feminine", "Created"), date(gpo.created.as_ref())),
        Line::new(tr_ctx("feminine", "Modified"), date(gpo.modified.as_ref())),
    ]
}

/// Directory and SYSVOL versions, part by part, with the alert said plainly if needed
/// (`lignes_versions`).
pub fn version_lines(gpo: &Gpo, folder: Option<&SysvolGpo>, dc: &str, read: bool) -> Vec<Line> {
    let a = gpo.versions();
    let mut lines = vec![
        Line::new(tr("Directory, user"), a.user.to_string()),
        Line::new(tr("Directory, computer"), a.computer.to_string()),
    ];
    if !read {
        lines.push(Line::new(tr("SYSVOL"), tr("reading…")));
        return lines;
    }
    let Some(folder) = folder else {
        lines.push(Line::alert(
            tr("SYSVOL"),
            fill(&tr("unreadable on {dc}"), &[("dc", dc)]),
            true,
        ));
        return lines;
    };
    if let Some(v) = folder
        .gpt
        .as_ref()
        .and_then(|g| g.version)
        .filter(|_| folder.present)
    {
        let s = versions(v);
        lines.push(Line::alert(
            fill(&tr("SYSVOL ({dc}), user"), &[("dc", dc)]),
            s.user.to_string(),
            s.user != a.user,
        ));
        lines.push(Line::alert(
            fill(&tr("SYSVOL ({dc}), computer"), &[("dc", dc)]),
            s.computer.to_string(),
            s.computer != a.computer,
        ));
    }
    lines
}

fn extensions(value: &str) -> String {
    if value.trim().is_empty() {
        return tr_ctx("feminine", "none");
    }
    let pairs = if value.starts_with('[') {
        value.matches("][").count() + 1
    } else {
        1
    };
    let n = u64::try_from(pairs).unwrap_or(0);
    fill(
        &tr_n("{n} extension", "{n} extensions", n),
        &[("n", &n.to_string())],
    )
}

/// `lignes_details`.
pub fn detail_lines(gpo: &Gpo, directory: &GpoDirectory) -> Vec<Line> {
    let wmi = match gpo.wmi_guid() {
        None if gpo.wmi_filter.is_empty() => tr("none"),
        None => gpo.wmi_filter.clone(),
        Some(guid) => directory.wmi_filters.get(&guid).map_or_else(
            || fill(&tr("{guid} (not found)"), &[("guid", &guid)]),
            |f| f.name.clone(),
        ),
    };
    vec![
        Line::new(tr("WMI filter"), wmi),
        Line::alert(
            tr("Path in the SYSVOL"),
            if gpo.path.is_empty() {
                tr("not set")
            } else {
                gpo.path.clone()
            },
            gpo.path.is_empty(),
        ),
        Line::new(
            tr("Computer extensions"),
            extensions(&gpo.computer_extensions),
        ),
        Line::new(tr("User extensions"), extensions(&gpo.user_extensions)),
        Line::new(tr("Object"), gpo.dn.clone()),
    ]
}

/// A row of the filtering (`LigneFiltrage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterLine {
    pub name: String,
    pub detail: String,
    pub applies: bool,
}

/// Accounts and groups the GPO applies to (reading and « Apply »), then those a denial
/// excludes; those that read without applying are not filtering (`lignes_filtrage`).
pub fn filter_lines(gpo: &Gpo, names: &Names) -> Vec<FilterLine> {
    let mut lines = Vec::new();
    for right in annuaire_core::gpo::filtering(gpo.descriptor.as_ref()) {
        if right.applies() {
            lines.push(FilterLine {
                name: sid_name(&right.sid, Some(names)),
                detail: tr("read and apply"),
                applies: true,
            });
        } else if right.deny {
            lines.push(FilterLine {
                name: sid_name(&right.sid, Some(names)),
                detail: tr("excluded by a Deny entry"),
                applies: false,
            });
        }
    }
    lines
}

/// A link of a container, for its page (`LigneLienConteneur`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerLine {
    pub order: usize,
    pub name: String,
    pub state: String,
    pub alert: bool,
}

/// `lignes_conteneur`.
pub fn container_lines(container: &Container, gpos: &HashMap<String, Gpo>) -> Vec<ContainerLine> {
    link_nodes(container, gpos)
        .into_iter()
        .filter_map(|n| {
            let link = n.link.as_ref()?;
            let mut state = link_state(link, n.gpo.as_ref());
            if state.is_empty() {
                state = tr("link enabled");
            }
            Some(ContainerLine {
                order: n.order,
                name: n.title.clone(),
                state,
                alert: n.alert,
            })
        })
        .collect()
}

/// `resume_conteneur`.
pub fn container_summary(container: &Container) -> String {
    let n = container.gplink.links().count();
    let mut text = if n > 0 {
        let n = u64::try_from(n).unwrap_or(0);
        fill(
            &tr_n("{n} linked GPO", "{n} linked GPOs", n),
            &[("n", &n.to_string())],
        )
    } else {
        tr("No linked GPO")
    };
    if container.inheritance_blocked() {
        text.push_str(&tr(
            "; inheritance blocked: GPOs of the containers above do not apply, except enforced links",
        ));
    }
    if container
        .gplink
        .elements
        .iter()
        .any(|e| matches!(e, Element::Raw { .. }))
    {
        text.push_str(&tr("; gPLink contains unreadable parts, kept as is"));
    }
    text
}

// --- Inconsistencies: orphan folders and GPOs without a folder ---------------------------------

pub fn orphan_explanation(dc: &str) -> String {
    fill(
        &tr(
            "This folder in the SYSVOL of {dc} matches no Group Policy Object in the directory: it is left over from an interrupted creation or a half-finished deletion. No client reads it. “Delete the Orphaned Folder” (Delete) removes it through the preview, after checking again that no GPO has this GUID; undoing recreates it exactly. The menu removes them all at once (“Remove Folders Without a GPO From SYSVOL”).",
        ),
        &[("dc", dc)],
    )
}

/// What the SYSVOL of the PDC says of an orphan folder, and the links that quote its GUID
/// (`lignes_orphelin`).
pub fn orphan_lines(inventory: &Inventory, name: &str) -> Vec<Line> {
    let sysvol = &inventory.sysvol;
    let mut lines = vec![
        Line::new(
            tr("Path"),
            format!(
                "SYSVOL\\{}\\Policies\\{name}",
                inventory.directory.dns_name.to_lowercase()
            ),
        ),
        Line::new(tr("Read on"), sysvol.dc.clone()),
    ];
    if let Some(folder) = sysvol.folders.get(&name.to_uppercase()) {
        let mut files: Vec<&str> = folder.files.iter().map(|(f, _)| f.as_str()).collect();
        files.sort_by_cached_key(|f| f.to_lowercase());
        let n = u64::try_from(files.len()).unwrap_or(0);
        lines.push(Line::new(
            tr("Files"),
            if files.is_empty() {
                tr("none")
            } else {
                fill(
                    &tr_n("{n} file: {liste}", "{n} files: {liste}", n),
                    &[("n", &n.to_string()), ("liste", &files.join(", "))],
                )
            },
        ));
        let version = folder.gpt.as_ref().and_then(|g| g.version);
        lines.push(Line::new(
            tr("GPT.INI version"),
            version.map_or_else(
                || tr("missing or unreadable"),
                |v| versions_text(versions(v)),
            ),
        ));
    }
    let links = links_of(&inventory.directory, &name.to_uppercase());
    lines.push(Line::alert(
        tr("Links to this GUID"),
        if links.is_empty() {
            tr("none")
        } else {
            links
                .iter()
                .map(|l| l.container.dn.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        },
        !links.is_empty(),
    ));
    lines
}

/// Description of the page « Inconsistencies » (`resume_incoherences`).
pub fn inconsistencies_summary(inventory: &Inventory) -> String {
    let mut pieces = Vec::new();
    let n = u64::try_from(inventory.orphans().len()).unwrap_or(0);
    if n > 0 {
        pieces.push(fill(
            &tr_n(
                "{n} SYSVOL folder without a GPO",
                "{n} SYSVOL folders without a GPO",
                n,
            ),
            &[("n", &n.to_string())],
        ));
    }
    let n = u64::try_from(inventory.without_folder().len()).unwrap_or(0);
    if n > 0 {
        pieces.push(fill(
            &tr_n(
                "{n} GPO without a folder in the SYSVOL",
                "{n} GPOs without a folder in the SYSVOL",
                n,
            ),
            &[("n", &n.to_string())],
        ));
    }
    fill(
        &tr("Read on {dc}: {liste}."),
        &[
            ("dc", &inventory.sysvol.dc),
            ("liste", &pieces.join(&tr("; "))),
        ],
    )
}

// --- Deviations ------------------------------------------------------------------------------------

/// Why the SYSVOL of `dc` could not be read (`SysvolDc.erreur`).
pub fn read_error_text(error: &SysvolReadError, dc: &str) -> String {
    match error {
        SysvolReadError::NoPolicies => fill(
            &tr("Policies folder missing from the SYSVOL of {dc}."),
            &[("dc", dc)],
        ),
        SysvolReadError::Sysvol(e) => errors::sysvol_problem(e, dc).1.message,
    }
}

fn gpt_error_text(error: &GptError) -> String {
    match error {
        GptError::NoVersion => tr("no version in GPT.INI"),
        GptError::Unreadable(v) => fill(&tr("unreadable version: {v}"), &[("v", v)]),
    }
}

fn files_text(template: &str, dc: &str, n: usize, first: &[String]) -> String {
    let mut list = first.join(", ");
    if n > 3 {
        list.push_str(", …");
    }
    fill(
        template,
        &[("n", &n.to_string()), ("dc", dc), ("liste", &list)],
    )
}

/// A deviation said plainly; `dc`: the DC of a comparison that could not be read.
pub fn deviation_text(deviation: &Deviation, dc: &str) -> String {
    let optional = |v: &Option<i64>| v.map_or_else(|| "?".to_owned(), |v| v.to_string());
    match deviation {
        Deviation::FolderMissing => tr("The GPO folder is missing from the SYSVOL."),
        Deviation::GptMissing => tr("GPT.INI is missing or cannot be read in the SYSVOL."),
        Deviation::GptUnreadable(e) => fill(
            &tr("Unreadable GPT.INI: {erreur}."),
            &[("erreur", &gpt_error_text(e))],
        ),
        Deviation::Versions { directory, sysvol } => fill(
            &tr(
                "Versions differ: directory ({a}), SYSVOL ({s}). One half of the GPO was modified without the other; clients may ignore it.",
            ),
            &[
                ("a", &versions_text(*directory)),
                ("s", &versions_text(*sysvol)),
            ],
        ),
        Deviation::AbsentOn { dc } => fill(&tr("Folder missing on {dc}."), &[("dc", dc)]),
        Deviation::OnlyOn { dc } => fill(&tr("Folder present on {dc} only."), &[("dc", dc)]),
        Deviation::GptVersionOn {
            dc,
            found,
            reference,
        } => fill(
            &tr("GPT.INI on {dc}: version {a} instead of {r}."),
            &[
                ("dc", dc),
                ("a", &optional(found)),
                ("r", &optional(reference)),
            ],
        ),
        Deviation::MissingFiles { dc, n, first } => {
            files_text(&tr("{n} file(s) missing on {dc}: {liste}"), dc, *n, first)
        }
        Deviation::ExtraFiles { dc, n, first } => {
            files_text(&tr("{n} extra file(s) on {dc}: {liste}"), dc, *n, first)
        }
        Deviation::OtherSize { dc, n, first } => files_text(
            &tr("{n} file(s) with a different size on {dc}: {liste}"),
            dc,
            *n,
            first,
        ),
        Deviation::Of { name, deviation } => fill(
            &tr("{nom}: {valeur}"),
            &[("nom", name), ("valeur", &deviation_text(deviation, dc))],
        ),
        Deviation::OrphansDiffer { names } => fill(
            &tr("Folders without a GPO differ from those of the PDC: {liste}"),
            &[("liste", &names.join(", "))],
        ),
        Deviation::Unreadable(e) => read_error_text(e, dc),
    }
}

/// Summary of the comparison of the SYSVOL of the DCs, for the banner of the window
/// (`EtatSysvols`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysvolsState {
    pub text: String,
    pub alert: bool,
    pub details: Vec<String>,
}

/// Comparison of the DCs; before it, the folders of the SYSVOL of the PDC without a GPO in
/// the directory (`etat_sysvols`).
pub fn sysvols_state(inventory: Option<&Inventory>, others: Option<&[SysvolDc]>) -> SysvolsState {
    if let Some(inventory) = inventory {
        let orphans = inventory.orphans();
        if !orphans.is_empty() {
            let n = u64::try_from(orphans.len()).unwrap_or(0);
            return SysvolsState {
                text: fill(
                    &tr_n(
                        "{n} folder in the PDC's SYSVOL without a GPO in the directory: see “Inconsistencies”.",
                        "{n} folders in the PDC's SYSVOL without a GPO in the directory: see “Inconsistencies”.",
                        n,
                    ),
                    &[("n", &n.to_string())],
                ),
                alert: true,
                details: orphans,
            };
        }
    }
    let (Some(inventory), Some(others)) = (inventory, others) else {
        return SysvolsState {
            text: tr("Comparing the DCs' SYSVOL…"),
            alert: false,
            details: Vec::new(),
        };
    };
    if others.is_empty() {
        return SysvolsState {
            text: tr("Only one DC: nothing to compare."),
            alert: false,
            details: Vec::new(),
        };
    }
    let mut details = Vec::new();
    let mut differ = Vec::new();
    for other in others {
        let deviations = inventory.dc_deviations(other);
        if !deviations.is_empty() {
            differ.push(other.dc.clone());
            details.extend(deviations.iter().map(|d| deviation_text(d, &other.dc)));
        }
    }
    if differ.is_empty() {
        let n = u64::try_from(others.len()).unwrap_or(0);
        return SysvolsState {
            text: fill(
                &tr_n(
                    "SYSVOL identical to the PDC on {n} other DC.",
                    "SYSVOL identical to the PDC on the {n} other DCs.",
                    n,
                ),
                &[("n", &n.to_string())],
            ),
            alert: false,
            details: Vec::new(),
        };
    }
    SysvolsState {
        text: fill(
            &tr("The SYSVOL differs from the PDC's ({pdc}) on: {liste}."),
            &[("pdc", &inventory.sysvol.dc), ("liste", &differ.join(", "))],
        ),
        alert: true,
        details,
    }
}

// --- Write actions (`vue.gpo_ecriture`) --------------------------------------------------------

/// Actions of the group « gpo » added by the writes (`ACTIONS`).
pub const ACTIONS: [&str; 18] = [
    "creer",
    "modifier",
    "lier",
    "delier",
    "monter",
    "descendre",
    "lien-actif",
    "lien-applique",
    "bloquer-heritage",
    "filtrage",
    "securite",
    "aligner",
    "sauvegarder",
    "restaurer",
    "orphelins",
    "supprimer",
    "supprimer-orphelin",
    "retirer",
];

/// The three toggles.
pub const TOGGLES: [&str; 3] = ["lien-actif", "lien-applique", "bloquer-heritage"];

/// `RACCOURCIS`.
pub const SHORTCUTS: [(&str, &str); 13] = [
    ("creer", "<Control>n"),
    ("modifier", "<Control>m"),
    ("lier", "<Control>l"),
    ("retirer", "Delete"),
    ("monter", "<Alt>Up"),
    ("descendre", "<Alt>Down"),
    ("lien-actif", "<Control>d"),
    ("lien-applique", "<Control>e"),
    ("bloquer-heritage", "<Control>b"),
    ("filtrage", "<Control>i"),
    ("securite", "<Control>t"),
    ("sauvegarder", "<Control>s"),
    ("restaurer", "<Control>o"),
];

/// Actions allowed for the chosen node, and the state of the three toggles (`EtatActions`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ActionsState {
    pub allowed: HashSet<&'static str>,
    pub link_enabled: bool,
    pub link_enforced: bool,
    pub inheritance_blocked: bool,
    /// What Delete does here: « delier » on a link, « supprimer » on a GPO,
    /// « supprimer-orphelin » on an orphan folder, otherwise empty.
    pub remove: &'static str,
}

/// What the chosen node allows (`etat_actions`). A read-only profile allows only the backup
/// (it writes nothing in the directory), the content editor (which will not write there) and
/// the reading of the security settings.
pub fn actions_state(node: Option<&GpoNode>, read_only: bool) -> ActionsState {
    let mut state = ActionsState {
        allowed: HashSet::from(["creer", "restaurer", "orphelins"]),
        ..ActionsState::default()
    };
    if let Some(node) = node {
        if let (Kind::Domain | Kind::Ou, Some(container)) = (node.kind, &node.container) {
            state.allowed.extend(["lier", "bloquer-heritage"]);
            state.inheritance_blocked = container.inheritance_blocked();
        }
        if let (Kind::Link, Some(link), Some(container)) = (node.kind, &node.link, &node.container)
        {
            state
                .allowed
                .extend(["delier", "lien-actif", "lien-applique", "retirer"]);
            let n = container.gplink.links().count();
            if node.order > 1 {
                state.allowed.insert("monter");
            }
            if node.order < n {
                state.allowed.insert("descendre");
            }
            state.link_enabled = !link.disabled();
            state.link_enforced = link.enforced();
            state.remove = "delier";
        }
        if node.gpo.is_some() {
            state.allowed.extend([
                "modifier",
                "filtrage",
                "securite",
                "aligner",
                "sauvegarder",
                "supprimer",
            ]);
            if node.kind == Kind::Gpo {
                state.allowed.insert("retirer");
                state.remove = "supprimer";
            }
        }
        if node.kind == Kind::Orphan && !node.folder.is_empty() {
            state.allowed.extend(["supprimer-orphelin", "retirer"]);
            state.remove = "supprimer-orphelin";
        }
    }
    if read_only {
        state
            .allowed
            .retain(|a| ["sauvegarder", "modifier", "securite"].contains(a));
    }
    state
}

pub fn copy_name(name: &str) -> String {
    fill(&tr("{nom} (copy)"), &[("nom", name)])
}

/// What is shown of an archive before restoring it (`resume_archive`).
pub fn archive_summary(backup: &Backup) -> Vec<Line> {
    let files: Vec<_> = backup.elements.iter().filter(|e| !e.directory).collect();
    let size: usize = files
        .iter()
        .map(|e| e.content.as_ref().map_or(0, Vec::len))
        .sum();
    let mut lines = vec![
        Line::new(tr("GPO"), backup.name.clone()),
        Line::new(tr("GUID"), backup.guid.clone()),
        Line::new(tr("Backed up on"), backup.date.clone()),
        Line::new(
            tr_ctx("feminine", "Read on"),
            format!("{} ({})", backup.dc, backup.domain),
        ),
        Line::new(tr("Version"), versions_text(versions(backup.version()))),
        Line::new(
            tr("SYSVOL"),
            fill(
                &tr("{f} file(s), {d} folder(s), {o} bytes"),
                &[
                    ("f", &files.len().to_string()),
                    ("d", &(backup.elements.len() - files.len()).to_string()),
                    ("o", &size.to_string()),
                ],
            ),
        ),
    ];
    if !backup.links.is_empty() {
        lines.push(Line::new(
            tr("Links (not restored)"),
            backup
                .links
                .iter()
                .map(|l| l.container.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ));
    }
    lines
}

/// (title, subtitle) of an archive from its name `date_name_{GUID}.tar.gz`
/// (`titre_archive`).
pub fn archive_title(file_name: &str) -> (String, String) {
    let base = file_name.strip_suffix(".tar.gz").unwrap_or(file_name);
    let (date, rest) = base.split_once('_').unwrap_or((base, ""));
    let (name, guid) = rest.rsplit_once('_').unwrap_or(("", rest));
    if !guid.starts_with('{') {
        return (file_name.to_owned(), String::new());
    }
    let day: String = date.chars().take(8).collect();
    let hour: String = date.chars().skip(9).take(6).collect();
    let when = if day.chars().count() == 8 {
        let part = |s: &str, a: usize, b: usize| s.chars().skip(a).take(b - a).collect::<String>();
        format!(
            "{}/{}/{} {}:{} UTC",
            part(&day, 6, 8),
            part(&day, 4, 6),
            part(&day, 0, 4),
            part(&hour, 0, 2),
            part(&hour, 2, 4)
        )
    } else {
        date.to_owned()
    };
    (name.replace('-', " "), format!("{when} · {guid}"))
}

/// Accounts and groups the GPO applies to, named, to check them for removal
/// (`principaux_filtrage`).
pub fn filtering_principals(gpo: &Gpo, names: &Names) -> Vec<(Sid, String)> {
    annuaire_core::gpo::filtering(gpo.descriptor.as_ref())
        .into_iter()
        .filter(|f| f.applies())
        .map(|f| (f.sid, sid_name(&f.sid, Some(names))))
        .collect()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use annuaire_codecs::gplink::GpLink;

    fn gpo(guid: &str, name: &str, flags: i64) -> Gpo {
        Gpo {
            dn: format!("CN={guid},CN=Policies,CN=System,DC=lab,DC=test"),
            guid: guid.into(),
            name: name.into(),
            flags,
            version: 0x0001_0002,
            path: String::new(),
            computer_extensions: String::new(),
            user_extensions: "[{A}{B}][{C}{D}]".into(),
            wmi_filter: String::new(),
            created: None,
            modified: None,
            descriptor: None,
        }
    }

    fn container(dn_text: &str, gplink: &str, gpoptions: i64) -> Container {
        Container {
            dn: dn_text.into(),
            name: annuaire_core::gpo::name_from_dn(dn_text),
            class: if dn_text.starts_with("DC=") {
                "domainDNS".into()
            } else {
                "organizationalUnit".into()
            },
            gplink: GpLink::parse(gplink),
            gpoptions,
        }
    }

    fn directory() -> GpoDirectory {
        let (a, b) = (
            "{A0000000-0000-0000-0000-000000000000}",
            "{B0000000-0000-0000-0000-000000000000}",
        );
        let link =
            |g: &str, o: u8| format!("[LDAP://cn={g},cn=policies,cn=system,DC=lab,DC=test;{o}]");
        GpoDirectory {
            domain: "DC=lab,DC=test".into(),
            dns_name: "lab.test".into(),
            gpos: HashMap::from([
                (a.to_owned(), gpo(a, "Alpha", 0)),
                (b.to_owned(), gpo(b, "beta", 3)),
            ]),
            containers: vec![
                container("DC=lab,DC=test", &link(a, 2), 0),
                container(
                    "OU=X,DC=lab,DC=test",
                    &format!(
                        "{}{}{}",
                        link(b, 1),
                        link(a, 0),
                        link("{C0000000-0000-0000-0000-000000000000}", 0)
                    ),
                    1,
                ),
                container("OU=Y,OU=X,DC=lab,DC=test", "", 0),
            ],
            linked_sites: Vec::new(),
            wmi_filters: HashMap::new(),
            dcs: vec!["dc1".into()],
            dc: "dc1".into(),
            names: HashMap::new(),
        }
    }

    #[test]
    fn tree_and_keys() {
        let roots = tree(&directory(), None);
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0].kind, Kind::All);
        assert_eq!(
            roots[0]
                .children
                .iter()
                .map(|c| c.title.as_str())
                .collect::<Vec<_>>(),
            ["Alpha", "beta"]
        );
        let domain = &roots[1];
        assert_eq!(
            (domain.kind, domain.title.as_str()),
            (Kind::Domain, "lab.test")
        );
        // The link of the domain, then the OU X.
        assert_eq!(domain.children[0].kind, Kind::Link);
        assert_eq!(domain.children[0].subtitle, "order 1, enforced");
        let ou = &domain.children[1];
        assert_eq!(
            (ou.kind, ou.subtitle.as_str()),
            (Kind::Ou, "inheritance blocked")
        );
        // Order 1 first: the missing GPO (last of the string), then A, then B.
        let titles: Vec<&str> = ou.children.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "{C0000000-0000-0000-0000-000000000000}",
                "Alpha",
                "beta",
                "Y"
            ]
        );
        assert!(ou.children[0].alert);
        assert_eq!(ou.children[0].icon, ICON_LINK_DISABLED);
        assert_eq!(
            ou.children[2].subtitle,
            "order 3, link disabled, all settings disabled"
        );
        assert_eq!(
            ou.children[1].key(),
            "lien:ou=x,dc=lab,dc=test:2:cn={a0000000-0000-0000-0000-000000000000},cn=policies,cn=system,dc=lab,dc=test"
        );
        assert_eq!(
            roots[0].children[0].key(),
            "gpo:{A0000000-0000-0000-0000-000000000000}"
        );
        assert_eq!(ou.key(), "conteneur:ou=x,dc=lab,dc=test");
        assert_eq!(roots[0].key(), "toutes");
        let marked = mark_alerts(
            roots,
            &HashSet::from(["{A0000000-0000-0000-0000-000000000000}".to_owned()]),
        );
        assert!(marked[0].children[0].alert && !marked[0].children[1].alert);
        let x = &directory().containers[1];
        assert_eq!(
            container_summary(x),
            "3 linked GPOs; inheritance blocked: GPOs of the containers above do not apply, except enforced links"
        );
        assert_eq!(
            container_lines(x, &directory().gpos)[1].state,
            "link enabled"
        );
        assert_eq!(
            links_of(&directory(), "{A0000000-0000-0000-0000-000000000000}").len(),
            2
        );
    }

    #[test]
    fn actions() {
        let roots = tree(&directory(), None);
        let link = &roots[1].children[1].children[1];
        let state = actions_state(Some(link), false);
        assert!(state.allowed.contains("monter") && state.allowed.contains("descendre"));
        assert!(state.allowed.contains("filtrage") && !state.allowed.contains("lier"));
        assert_eq!(state.remove, "delier");
        let gpo = actions_state(Some(&roots[0].children[0]), false);
        assert_eq!(gpo.remove, "supprimer");
        let read_only = actions_state(Some(&roots[0].children[0]), true);
        assert_eq!(
            read_only.allowed,
            HashSet::from(["sauvegarder", "modifier", "securite"])
        );
        let ou = actions_state(Some(&roots[1].children[1]), false);
        assert!(ou.inheritance_blocked && ou.allowed.contains("lier"));
    }

    #[test]
    fn archive_titles() {
        assert_eq!(
            archive_title("20261016T123456Z_Fond-d-écran_{A1}.tar.gz"),
            ("Fond d écran".into(), "16/10/2026 12:34 UTC · {A1}".into())
        );
        assert_eq!(
            archive_title("x.tar.gz"),
            ("x.tar.gz".into(), String::new())
        );
    }
}

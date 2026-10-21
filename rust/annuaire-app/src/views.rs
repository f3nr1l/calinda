// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! What the tree and the table show (`annuaire.vue.lignes`, `vue.arbre`, `vue.tri`, the
//! counter of `vue.textes`): an object of the model becomes a row of texts and sort keys, a
//! container a node. Pure, apart from the catalogue and the local time zone.

use std::cmp::Ordering;

use annuaire_codecs::time;
use annuaire_codecs::uac::{Scope, UserAccountControl};
use annuaire_core::dn;
use annuaire_core::model::{Kind, Object};
use annuaire_core::source::{Item, name_from_dn};
use gtk::glib;
use gtk::glib::Unichar;

use crate::i18n::{fill, tr, tr_ctx, tr_n};

/// Icon embedded in the resource: a theme such as Colloid draws `system-users` exactly as
/// `avatar-default`, and groups no longer stood out from accounts.
pub const GROUP_ICON: &str = "io.github.f3nr1l.Calinda-groupe-symbolic";
pub const DOMAIN_ICON: &str = "network-workgroup-symbolic";
pub const DC_ICON: &str = "network-server-symbolic";
pub const UNREADABLE_ICON: &str = "dialog-warning-symbolic";

fn kind_icon(kind: Kind) -> &'static str {
    match kind {
        Kind::User => "avatar-default-symbolic",
        Kind::Computer => "computer-symbolic",
        Kind::Group => GROUP_ICON,
        Kind::Ou | Kind::Container => "folder-symbolic",
        Kind::Contact => "x-office-address-book-symbolic",
        Kind::Unknown => "emblem-system-symbolic",
    }
}

/// Comparison form of the quick filter: case folded, without accents nor ligatures
/// (`normaliser`: `casefold`, NFKD, combining marks removed).
pub fn normalize(text: &str) -> String {
    let folded = glib::casefold(text);
    glib::normalize(folded.as_str(), glib::NormalizeMode::All)
        .chars()
        .filter(|c| c.combining_class() == 0)
        .collect()
}

/// Local date and time, to the minute; empty without a date.
pub fn format_unix(seconds: i64) -> String {
    glib::DateTime::from_unix_local(seconds)
        .and_then(|d| d.format(&tr("%d/%m/%Y %H:%M")))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// What a row of the table shows (`LigneVue`); the `*_sort` fields are numeric keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RowView {
    pub dn: String,
    pub kind: String,
    pub icon: String,
    pub name: String,
    pub kind_label: String,
    pub id: String,
    pub description: String,
    pub mail: String,
    pub state: String,
    /// User or computer: has a last logon, possibly "never".
    pub account: bool,
    /// Raw `lastLogonTimestamp` (100 ns), 0: never or without object.
    pub activity_sort: i64,
    /// `whenChanged` in Unix seconds, 0: unknown.
    pub modified_sort: i64,
    pub filter_key: String,
}

impl RowView {
    pub fn activity_text(&self) -> String {
        if !self.account {
            return String::new();
        }
        if self.activity_sort == 0 {
            return tr("Never");
        }
        match time::nttime_to_unix(self.activity_sort) {
            Ok(Some(seconds)) => format_unix(seconds),
            _ => String::new(),
        }
    }

    pub fn modified_text(&self) -> String {
        if self.modified_sort == 0 {
            String::new()
        } else {
            format_unix(self.modified_sort)
        }
    }

    pub fn location(&self) -> String {
        location(&self.dn)
    }
}

/// Parent container of an object, as a path from the root of the domain: `Société/Paris`
/// (the form of `canonicalName`, without the domain); the domain name for an object at the
/// root; empty if the DN cannot be read (`texte_emplacement`).
pub fn location(dn_text: &str) -> String {
    let Ok(components) = dn::split(dn_text) else {
        return String::new();
    };
    let parents = components.get(1..).unwrap_or_default();
    let path: Vec<&str> = parents
        .iter()
        .rev()
        .filter(|c| !c.attribute.eq_ignore_ascii_case("DC"))
        .map(|c| c.value.as_str())
        .collect();
    if path.is_empty() {
        parents
            .iter()
            .filter(|c| c.attribute.eq_ignore_ascii_case("DC"))
            .map(|c| c.value.as_str())
            .collect::<Vec<_>>()
            .join(".")
    } else {
        path.join("/")
    }
}

fn group_label(group_type: Option<&annuaire_codecs::uac::GroupType>) -> String {
    let Some(scope) = group_type.and_then(|t| t.scope) else {
        return tr("Group");
    };
    let scope_label = match scope {
        Scope::Global => tr("global"),
        Scope::DomainLocal => tr("domain local"),
        Scope::Universal => tr("universal"),
        Scope::Builtin => tr("built-in"),
    };
    let template = if group_type.is_some_and(|t| t.security) {
        tr("Security group, {portee}")
    } else {
        tr("Distribution group, {portee}")
    };
    fill(&template, &[("portee", &scope_label)])
}

fn is_dc(object: &Object) -> bool {
    matches!(object, Object::Computer { account, .. }
        if UserAccountControl(account.uac).contains(UserAccountControl::SERVER_TRUST_ACCOUNT))
}

fn is_domain(object: &Object) -> bool {
    object.kind() == Kind::Container
        && object
            .common()
            .classes
            .iter()
            .any(|c| c.eq_ignore_ascii_case("domainDNS"))
}

fn kind_label(object: &Object) -> String {
    match object {
        Object::User { .. } => tr("User"),
        Object::Computer { .. } if is_dc(object) => tr("Domain controller"),
        Object::Computer { .. } => tr("Computer"),
        Object::Group { group_type, .. } => group_label(group_type.as_ref()),
        Object::Ou(_) => tr("Organizational unit"),
        Object::Container(_) if is_domain(object) => tr("Domain"),
        Object::Container(_) => tr("Container"),
        Object::Contact { .. } => tr("Contact"),
        // A class the model does not handle: the most precise, as is.
        Object::Unknown(common) => common
            .classes
            .last()
            .cloned()
            .unwrap_or_else(|| tr("Object")),
    }
}

/// Icon of an object (`icone`).
pub fn icon(object: &Object) -> &'static str {
    if is_dc(object) {
        DC_ICON
    } else if is_domain(object) {
        DOMAIN_ICON
    } else {
        kind_icon(object.kind())
    }
}

/// Row of an item; an unreadable object gives a reported row, not an error
/// (`ligne_depuis_objet`).
pub fn row_from_item(item: &Item) -> RowView {
    let object = match item {
        Item::Unreadable { dn, name, error } => {
            return RowView {
                dn: dn.clone(),
                kind: Kind::Unknown.name().into(),
                icon: UNREADABLE_ICON.into(),
                name: name.clone(),
                kind_label: tr("Unreadable"),
                description: error.clone(),
                filter_key: normalize(name),
                ..RowView::default()
            };
        }
        Item::Object(object) => object,
    };
    let common = object.common();
    let (id, mail, display_name) = match object.as_ref() {
        Object::User {
            account,
            mail,
            display_name,
            ..
        } => (
            account.sam_account_name.as_str(),
            mail.as_str(),
            display_name.as_str(),
        ),
        Object::Computer { account, .. } => (account.sam_account_name.as_str(), "", ""),
        Object::Group {
            sam_account_name,
            mail,
            ..
        } => (sam_account_name.as_str(), mail.as_str(), ""),
        Object::Contact {
            display_name, mail, ..
        } => ("", mail.as_str(), display_name.as_str()),
        _ => ("", "", ""),
    };
    let (upn, state, activity) = match object.account() {
        Some(account) => {
            let state = if account.active() {
                tr_ctx("state", "Enabled")
            } else {
                tr("Disabled")
            };
            let activity = account
                .last_logon_timestamp
                .filter(|&t| !time::is_never(t).unwrap_or(true))
                .unwrap_or(0);
            (account.upn.as_str(), state, activity)
        }
        None => ("", String::new(), 0),
    };
    let fields = [
        common.name.as_str(),
        id,
        display_name,
        upn,
        mail,
        common.description.as_str(),
    ];
    let key: Vec<&str> = fields.into_iter().filter(|f| !f.is_empty()).collect();
    RowView {
        dn: common.dn.clone(),
        kind: object.kind().name().into(),
        icon: icon(object).into(),
        name: common.name.clone(),
        kind_label: kind_label(object),
        id: id.into(),
        description: common.description.clone(),
        mail: mail.into(),
        state,
        account: object.account().is_some(),
        activity_sort: activity,
        modified_sort: common.modified.map_or(0, |m| m.unix_seconds()),
        filter_key: normalize(&key.join(" ")),
    }
}

// --- Tree ------------------------------------------------------------------------------

/// A node of the tree (`NoeudVue`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeView {
    pub dn: String,
    pub name: String,
    pub icon: String,
    pub kind: String,
}

/// Root of the tree: the domain, named by its DNS name (`lab.test`).
pub fn root_node(domain: &str, dn: &str) -> NodeView {
    NodeView {
        dn: dn.into(),
        name: domain.into(),
        icon: DOMAIN_ICON.into(),
        kind: Kind::Container.name().into(),
    }
}

pub fn node_from_item(item: &Item) -> NodeView {
    match item {
        Item::Unreadable { dn, name, .. } => NodeView {
            dn: dn.clone(),
            name: name.clone(),
            icon: "folder-symbolic".into(),
            kind: Kind::Container.name().into(),
        },
        Item::Object(object) => {
            let common = object.common();
            let name = if common.name.is_empty() {
                name_from_dn(&common.dn)
            } else {
                common.name.clone()
            };
            NodeView {
                dn: common.dn.clone(),
                name,
                icon: icon(object).into(),
                kind: object.kind().name().into(),
            }
        }
    }
}

/// Alphabetical order without case nor accents, OUs and containers mixed (`ordonner_noeuds`).
pub fn sort_nodes(nodes: &mut [NodeView]) {
    nodes.sort_by_cached_key(|n| (normalize(&n.name), n.name.clone(), n.dn.clone()));
}

// --- Quick filter ----------------------------------------------------------------------

/// Words of the filter, normalized; a row must contain them all (`termes_filtre`).
pub fn filter_terms(input: &str) -> Vec<String> {
    normalize(input)
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}

pub fn matches(key: &str, terms: &[String]) -> bool {
    terms.iter().all(|t| key.contains(t.as_str()))
}

/// Effect of a new input on the filtered set (`Gtk.FilterChange`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Same,
    MoreStrict,
    LessStrict,
    Different,
}

/// True if every key containing the `strict` terms also contains the `wide` ones.
fn included(wide: &[String], strict: &[String]) -> bool {
    wide.iter()
        .all(|w| strict.iter().any(|s| s.contains(w.as_str())))
}

/// The filter only looks again at what it must: the kept rows when it becomes stricter, the
/// dropped ones when it becomes less so (`changement_filtre`).
pub fn filter_change(old: &[String], new: &[String]) -> Change {
    if old == new {
        Change::Same
    } else if included(old, new) {
        Change::MoreStrict
    } else if included(new, old) {
        Change::LessStrict
    } else {
        Change::Different
    }
}

// --- Sort ------------------------------------------------------------------------------

/// Sort key of a row for a column: the value, then the name to break ties (`vue.tri.CLES`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum SortKey {
    Text(String, String, String),
    Number(i64, String, String),
}

/// The column the table is sorted by, and the direction (`Ordre`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SortOrder {
    pub column: String,
    pub descending: bool,
}

impl Default for SortOrder {
    fn default() -> Self {
        Self {
            column: "nom".into(),
            descending: false,
        }
    }
}

impl SortOrder {
    pub fn key(&self, row: &RowView) -> SortKey {
        let name = || normalize(&row.name);
        let text = |value: &str| SortKey::Text(normalize(value), name(), row.dn.clone());
        let number = |value: i64| SortKey::Number(value, name(), row.dn.clone());
        match self.column.as_str() {
            "type" => text(&row.kind_label),
            "identifiant" => text(&row.id),
            "description" => text(&row.description),
            "courriel" => text(&row.mail),
            "etat" => text(&row.state),
            "activite" => number(row.activity_sort),
            "modifie" => number(row.modified_sort),
            "dn" => SortKey::Text(
                glib::casefold(&row.dn).to_string(),
                row.dn.clone(),
                String::new(),
            ),
            "emplacement" => text(&row.location()),
            _ => SortKey::Text(name(), row.dn.clone(), String::new()),
        }
    }

    /// Comparison in the direction of the order.
    pub fn compare(&self, a: &SortKey, b: &SortKey) -> Ordering {
        if self.descending { b.cmp(a) } else { a.cmp(b) }
    }
}

/// Keys of the rows shown, in the order of display (`ListeTriee`): where to insert a new row,
/// and the new order of all of them when the column changes. A tie keeps the order of
/// arrival.
#[derive(Debug, Default)]
pub struct SortedKeys {
    pub order: SortOrder,
    keys: Vec<SortKey>,
}

impl SortedKeys {
    pub fn clear(&mut self) {
        self.keys.clear();
    }

    /// Keeps the row; returns its position in the displayed list.
    pub fn insert(&mut self, row: &RowView) -> usize {
        let key = self.order.key(row);
        let position = self
            .keys
            .partition_point(|k| self.order.compare(k, &key) != Ordering::Greater);
        self.keys.insert(position, key);
        position
    }

    pub fn remove(&mut self, position: usize) {
        if position < self.keys.len() {
            self.keys.remove(position);
        }
    }

    /// New order (indexes into `rows`, the current display) under `order`; stable.
    pub fn sort(&mut self, rows: &[&RowView], order: SortOrder) -> Vec<usize> {
        let keys: Vec<SortKey> = rows.iter().map(|r| order.key(r)).collect();
        let mut ranks: Vec<usize> = (0..rows.len()).collect();
        ranks.sort_by(|&a, &b| match (keys.get(a), keys.get(b)) {
            (Some(x), Some(y)) => order.compare(x, y),
            _ => Ordering::Equal,
        });
        self.keys = ranks.iter().filter_map(|&i| keys.get(i).cloned()).collect();
        self.order = order;
        ranks
    }
}

// --- Status bar ------------------------------------------------------------------------

/// Integer with a thousands separator (narrow no-break space), as `nombre`.
pub fn number(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push('\u{202f}');
        }
        out.push(c);
    }
    out
}

/// Status bar of the table: « 3 032 objects », « 12 of 3 032 objects », « …, loading… »
/// (`decrire_compte`).
pub fn describe_count(shown: u64, total: u64, loading: bool) -> String {
    let text = if shown == total {
        fill(
            &tr_n("{n} object", "{n} objects", total),
            &[("n", &number(total))],
        )
    } else {
        fill(
            &tr_n("{n} of {total} object", "{n} of {total} objects", total),
            &[("n", &number(shown)), ("total", &number(total))],
        )
    };
    if loading {
        fill(&tr("{texte}, loading…"), &[("texte", &text)])
    } else {
        text
    }
}

// --- Update after a write (J2.11, `annuaire.vue.relecture`) ------------------------------

/// What changes in a table after a write, without reading the query again (`MiseAJour`).
#[derive(Debug, Default)]
pub struct Update {
    /// Position of the row → object read again (DN maybe new).
    pub replace: Vec<(usize, Item)>,
    pub remove: Vec<usize>,
    pub add: Vec<Item>,
}

impl Update {
    pub fn is_empty(&self) -> bool {
        self.replace.is_empty() && self.remove.is_empty() && self.add.is_empty()
    }
}

/// What changes in a table whose rows have the DN `dns`, in the order shown (`mise_a_jour`).
/// `container`: DN of the container whose content the table shows, None for a search result.
/// In a search, a row changed or moved stays (with its new state, as in the Windows console)
/// and only a deleted row leaves; a created object does not enter, for want of knowing whether
/// it satisfies the filter. In the content of a container, an object gone elsewhere leaves, an
/// object created or arrived enters.
pub fn update(
    dns: &[String],
    reread: &annuaire_core::reread::Reread,
    container: Option<&str>,
) -> Update {
    use annuaire_core::reread::{key, parent_key};
    let inside = container.map(key);
    let mut out = Update::default();
    let mut present = std::collections::HashSet::new();
    for (position, dn_text) in dns.iter().enumerate() {
        if !reread.concerns(dn_text) {
            continue;
        }
        let mut k = key(dn_text);
        if let Some(destination) = reread.moved.get(&k) {
            k = key(destination);
            if inside
                .as_ref()
                .is_some_and(|i| parent_key(destination) != *i)
            {
                out.remove.push(position);
                continue;
            }
        }
        match reread.objects.get(&k) {
            None => {}
            Some(None) => out.remove.push(position),
            Some(Some(item)) => {
                out.replace.push((position, item.clone()));
                present.insert(k);
            }
        }
    }
    if let Some(inside) = inside {
        let mut appeared: Vec<&String> = reread.appeared.iter().collect();
        appeared.sort();
        for k in appeared {
            if let Some(Some(item)) = reread.objects.get(k)
                && !present.contains(k)
                && parent_key(&row_from_item(item).dn) == inside
            {
                out.add.push(item.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization() {
        assert_eq!(normalize("Élodie ŒUF ﬁn"), "elodie œuf fin");
        assert_eq!(normalize("Straße"), "strasse");
        assert_eq!(filter_terms("  Jean  DUPONT "), ["jean", "dupont"]);
        assert!(matches("jean dupont jdupont", &filter_terms("dup jea")));
        assert!(!matches("jean dupont", &filter_terms("martin")));
    }

    #[test]
    fn filter_changes() {
        let t = |s: &str| filter_terms(s);
        assert_eq!(filter_change(&t("du"), &t("du")), Change::Same);
        assert_eq!(filter_change(&t("du"), &t("dup")), Change::MoreStrict);
        assert_eq!(filter_change(&t("dup"), &t("du")), Change::LessStrict);
        assert_eq!(filter_change(&t("ab"), &t("cd")), Change::Different);
        assert_eq!(filter_change(&[], &t("a")), Change::MoreStrict);
    }

    #[test]
    fn locations() {
        assert_eq!(
            location("CN=a,OU=Paris,OU=Société,DC=lab,DC=test"),
            "Société/Paris"
        );
        assert_eq!(location("CN=a,DC=lab,DC=test"), "lab.test");
        assert_eq!(location("pas un DN"), "");
    }

    #[test]
    fn counts() {
        assert_eq!(number(3032), "3\u{202f}032");
        assert_eq!(number(20012), "20\u{202f}012");
        assert_eq!(number(999), "999");
        assert_eq!(describe_count(3032, 3032, false), "3\u{202f}032 objects");
        assert_eq!(describe_count(1, 1, false), "1 object");
        assert_eq!(
            describe_count(12, 3032, true),
            "12 of 3\u{202f}032 objects, loading…"
        );
    }

    fn row(name: &str, dn: &str) -> RowView {
        RowView {
            name: name.into(),
            dn: dn.into(),
            ..RowView::default()
        }
    }

    #[test]
    fn sorted_insertion() {
        let mut keys = SortedKeys::default();
        assert_eq!(keys.insert(&row("b", "1")), 0);
        assert_eq!(keys.insert(&row("a", "2")), 0);
        assert_eq!(keys.insert(&row("c", "3")), 2);
        assert_eq!(keys.insert(&row("B", "4")), 2); // same name without case: after by DN
        let rows = [row("b", "1"), row("a", "2"), row("c", "3")];
        let refs: Vec<&RowView> = rows.iter().collect();
        let order = SortOrder {
            column: "nom".into(),
            descending: true,
        };
        assert_eq!(keys.sort(&refs, order), [2, 0, 1]);
    }

    #[test]
    fn update_after_write() {
        use annuaire_core::reread::Reread;
        let item = |dn: &str| Item::Unreadable {
            dn: dn.into(),
            name: String::new(),
            error: String::new(),
        };
        let mut objects = std::collections::HashMap::new();
        objects.insert("cn=a,ou=x,dc=t".to_owned(), Some(item("CN=a,OU=x,DC=t")));
        objects.insert("cn=b,ou=x,dc=t".to_owned(), None);
        objects.insert("cn=c,ou=x,dc=t".to_owned(), None);
        objects.insert("cn=c,ou=y,dc=t".to_owned(), Some(item("CN=c,OU=y,DC=t")));
        objects.insert("cn=n,ou=x,dc=t".to_owned(), Some(item("CN=n,OU=x,DC=t")));
        let reread = Reread {
            dc: String::new(),
            date: std::time::SystemTime::now(),
            objects,
            entries: Vec::new(),
            absent: Vec::new(),
            moved: [("cn=c,ou=x,dc=t".to_owned(), "CN=c,OU=y,DC=t".to_owned())].into(),
            appeared: ["cn=n,ou=x,dc=t".to_owned(), "cn=c,ou=y,dc=t".to_owned()].into(),
            forms: ["cn=a,ou=x,dc=t", "cn=b,ou=x,dc=t", "cn=c,ou=x,dc=t"]
                .map(str::to_owned)
                .into(),
        };
        let dns: Vec<String> = [
            "CN=a,OU=x,DC=t",
            "CN=b,OU=x,DC=t",
            "CN=c,OU=x,DC=t",
            "CN=z,OU=x,DC=t",
        ]
        .map(str::to_owned)
        .into();
        let inside = update(&dns, &reread, Some("OU=x,DC=t"));
        assert_eq!(inside.replace.len(), 1);
        assert_eq!(inside.remove, [1, 2]);
        assert_eq!(inside.add.len(), 1);
        let search = update(&dns, &reread, None);
        assert_eq!(
            (
                search.replace.len(),
                search.remove.clone(),
                search.add.len()
            ),
            (2, vec![1], 0)
        );
    }
}

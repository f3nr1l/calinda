// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Security settings of a GPO (J7.5, `annuaire.ui.gpo_securite`): pages of the editor and the
//! dialog that carries them.
//!
//! Four pages, each an `Adw.PreferencesPage` (Blueprint `gpo-securite-*.blp`) working on a
//! common `SecurityContext`: what `security_policy::read_security` read on the PDC emulator,
//! the names of the SIDs quoted, and a `gpo_security_views::Draft` where each page puts its
//! changes. The GPO editor hosts these pages as they are (`SecuritySection`);
//! `SecurityDialog` presents them from the « Group Policy » window. « Save » reads the file
//! again on the DC, replays the draft on it (`prepare_security`) and goes through the common
//! preview: file, version, extension and, on Samba, domain object, in one changeset
//! (ADR 0014).

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::{Rc, Weak};
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_codecs::gpt_tmpl::{Inf, RestrictedGroup};
use annuaire_core::cache::Source;
use annuaire_core::changes::Report;
use annuaire_core::gpo::Part;
use annuaire_core::gpo_write::GpoError;
use annuaire_core::model::Object;
use annuaire_core::security::{self as s, SidName};
use annuaire_core::security_policy::{self as sp, Kind, SecurityRead};
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::delegation::{MAX_RESULTS, candidate_row};
use crate::errors;
use crate::feed::Feed;
use crate::gpo::gpo_error_message;
use crate::gpo_dialogs::count_text;
use crate::gpo_editor::{GpoEditor, Section};
use crate::gpo_editor_views::{Anchor, ContentFile, EditorNode, Modification, NodeData};
use crate::gpo_security_views::{self as gsv, Draft, SecurityPage};
use crate::i18n::{fill, tr, tr_n};
use crate::scope::TemplateScope;
use crate::security_views as secv;
use crate::sheet_views as shv;
use crate::writes::{self, Options};

type Names = HashMap<Sid, SidName>;

fn escape(text: &str) -> String {
    glib::markup_escape_text(text).to_string()
}

fn empty(list: &gtk::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}

fn name_widget(widget: &impl IsA<gtk::Widget>, name: &str) {
    widget
        .as_ref()
        .update_property(&[gtk::accessible::Property::Label(name)]);
}

/// A row that carries a text (explanation), not activatable, named for AT-SPI
/// (`_rangee_texte`).
fn text_row(text: &str, name: &str) -> gtk::ListBoxRow {
    let label = gtk::Label::builder()
        .label(text)
        .xalign(0.0)
        .wrap(true)
        .margin_top(9)
        .margin_bottom(9)
        .margin_start(12)
        .margin_end(12)
        .build();
    label.add_css_class("dim-label");
    let row = gtk::ListBoxRow::builder()
        .child(&label)
        .activatable(false)
        .selectable(false)
        .focusable(false)
        .build();
    name_widget(&row, name);
    row
}

/// « Words » → « Words », first letter in upper case and the rest in lower case, as Python's
/// `str.capitalize`.
fn capitalize(text: &str) -> String {
    let lower = text.to_lowercase();
    let mut chars = lower.chars();
    chars
        .next()
        .map_or_else(String::new, |c| c.to_uppercase().chain(chars).collect())
}

// --- Context --------------------------------------------------------------------------------------

/// What the pages share: reading, names, draft, and the callback `changed`
/// (`ContexteSecurite`).
pub struct SecurityContext {
    pub source: Option<Arc<dyn Source>>,
    pub security: SecurityRead,
    pub names: RefCell<Names>,
    pub draft: RefCell<Draft>,
    changed: Box<dyn Fn()>,
}

impl std::fmt::Debug for SecurityContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityContext")
            .field("gpo", &self.security.name)
            .finish_non_exhaustive()
    }
}

impl SecurityContext {
    pub fn new(
        source: Option<Arc<dyn Source>>,
        security: SecurityRead,
        names: Names,
        changed: Box<dyn Fn()>,
    ) -> Rc<Self> {
        Rc::new(Self {
            source,
            security,
            names: RefCell::new(names),
            draft: RefCell::new(Draft::default()),
            changed,
        })
    }

    /// The content as the pages show it: read, plus the draft.
    pub fn inf(&self) -> Inf {
        self.draft
            .borrow()
            .apply(&self.security.inf)
            .unwrap_or_else(|_| self.security.inf.clone())
    }

    pub fn changed(&self) {
        (self.changed)();
    }

    pub fn name(&self, entry: &str, name: &str) {
        if let Some(sid) = gsv::entry_sid(entry) {
            self.names.borrow_mut().entry(sid).or_insert(SidName {
                sid,
                name: name.to_owned(),
                dn: String::new(),
                classes: Vec::new(),
            });
        }
    }
}

// --- Accounts and groups of a setting -------------------------------------------------------------

/// Groups whose name or identifier starts with the input (restricted group) (`filtre_groupes`).
pub fn groups_filter(input: &str) -> Option<String> {
    use annuaire_core::search::{self as q, Value};
    let text = input.trim();
    if text.is_empty() {
        return None;
    }
    let names: Vec<String> = ["name", "sAMAccountName"]
        .iter()
        .filter_map(|a| q::starts_with(a, text).ok())
        .collect();
    q::and(&[
        q::eq("objectClass", Value::Text("group")).ok()?,
        q::or(&names).ok()?,
    ])
    .ok()
}

fn object_sid(object: &Object) -> Option<Sid> {
    match object {
        Object::User { account, .. } | Object::Computer { account, .. } => account.sid,
        Object::Group { sid, .. } => *sid,
        _ => None,
    }
}

/// What follows « Validate »: the entries (`None`: not defined).
pub type Chosen = Box<dyn Fn(Option<Vec<String>>)>;

mod principals_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-principaux.ui")]
    pub struct PrincipalsDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub explanation: TemplateChild<gtk::Label>,
        #[template_child]
        pub defined_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub current_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub current_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub add_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub principal_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub known_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub known_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub confirm_button: TemplateChild<gtk::Button>,
        pub context: OnceCell<Rc<SecurityContext>>,
        pub chosen: RefCell<Option<Chosen>>,
        pub choose_group: Cell<bool>,
        /// Adw.SwitchRow cannot be derived: the entry of each row is kept beside.
        pub rows: RefCell<Vec<(adw::SwitchRow, String)>>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<(shv::ElementView, Option<Sid>)>>,
        pub ready: Cell<bool>,
    }

    impl std::fmt::Debug for PrincipalsDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PrincipalsDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PrincipalsDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoPrincipaux";
        type Type = super::PrincipalsDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PrincipalsDialog>(&[
                ("defined_toggled", |d, _| {
                    d.refresh();
                    None
                }),
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("confirm", |d, _| {
                    d.validate();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PrincipalsDialog {}
    impl WidgetImpl for PrincipalsDialog {}

    impl AdwDialogImpl for PrincipalsDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// List of accounts and groups of a setting, or choice of a group (`choose_group`)
    /// (`AnnuaireDialogueGpoPrincipaux`).
    pub struct PrincipalsDialog(ObjectSubclass<principals_imp::PrincipalsDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl PrincipalsDialog {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: Rc<SecurityContext>,
        title: &str,
        subtitle: &str,
        explanation: &str,
        entries: Option<&[String]>,
        chosen: Chosen,
        choose_group: bool,
        definable: bool,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.context.set(context.clone());
        *imp.chosen.borrow_mut() = Some(chosen);
        imp.choose_group.set(choose_group);
        dialog.set_title(title);
        imp.title.set_title(title);
        imp.title.set_subtitle(subtitle);
        imp.explanation.set_label(explanation);
        imp.explanation.set_visible(!explanation.is_empty());
        for e in entries.unwrap_or_default() {
            dialog.add_row(e, false);
        }
        // Lists of a restricted group: always defined (the GPMC writes both lines).
        imp.defined_switch
            .set_active(entries.is_some() || !definable);
        imp.defined_switch.set_visible(definable && !choose_group);
        imp.current_group.set_visible(!choose_group);
        imp.confirm_button.set_visible(!choose_group);
        if choose_group {
            imp.add_group.set_title(&tr("Group to restrict"));
            imp.principal_entry
                .set_placeholder_text(Some(&tr("Group name or identifier")));
        }
        for text in gsv::KNOWN_PRINCIPALS {
            if choose_group && !text.starts_with("S-1-5-32-") {
                continue;
            }
            let entry = annuaire_codecs::gpt_tmpl::sid_entry(text);
            let row = adw::ActionRow::builder()
                .title(escape(&gsv::entry_name(&entry, Some(&context.names.borrow()))).as_str())
                .subtitle(text)
                .activatable(true)
                .build();
            row.add_suffix(&gtk::Image::from_icon_name("list-add-symbolic"));
            row.set_tooltip_text(Some(&if choose_group {
                tr("Choose")
            } else {
                tr("Add")
            }));
            let weak = dialog.downgrade();
            row.connect_activated(move |_| {
                if let Some(d) = weak.upgrade() {
                    d.add(&entry, "");
                }
            });
            imp.known_list.append(&row);
        }
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(d) = weak.upgrade() {
                d.candidate_chosen(row);
            }
        });
        imp.ready.set(true);
        dialog.refresh();
        dialog
    }

    fn context(&self) -> &Rc<SecurityContext> {
        self.imp().context.get().expect("set by new")
    }

    // --- Current rows ------------------------------------------------------------------------

    fn add_row(&self, entry: &str, new: bool) {
        let imp = self.imp();
        let name = gsv::entry_name(entry, Some(&self.context().names.borrow()));
        let row = adw::SwitchRow::builder()
            .title(escape(&name).as_str())
            .active(true)
            .build();
        let detail = gsv::entry_sid(entry)
            .map_or_else(|| tr("account name, without SID"), |s| s.to_string());
        let subtitle = if new {
            fill(&tr("Will be added · {d}"), &[("d", &detail)])
        } else {
            detail
        };
        row.set_subtitle(&escape(&subtitle));
        let weak = self.downgrade();
        row.connect_active_notify(move |_| {
            if let Some(d) = weak.upgrade() {
                d.refresh();
            }
        });
        imp.current_list.append(&row);
        imp.rows.borrow_mut().push((row, entry.to_owned()));
    }

    fn entries(&self) -> Vec<String> {
        self.imp()
            .rows
            .borrow()
            .iter()
            .filter(|(row, _)| row.is_active())
            .map(|(_, e)| e.clone())
            .collect()
    }

    fn refresh(&self) {
        let imp = self.imp();
        if !imp.ready.get() {
            return;
        }
        let defined = imp.choose_group.get() || imp.defined_switch.is_active();
        imp.current_group.set_sensitive(defined);
        if imp.choose_group.get() {
            return;
        }
        let description = if !defined {
            tr("Not defined: the GPO says nothing about this setting.")
        } else if self.entries().is_empty() {
            tr("No one: the list is defined and empty.")
        } else {
            String::new()
        };
        imp.current_group
            .set_description((!description.is_empty()).then_some(description.as_str()));
    }

    // --- Search -------------------------------------------------------------------------------

    fn stop(&self) {
        if let Some(feed) = self.imp().search.take() {
            feed.cancel();
        }
    }

    fn search(&self) {
        self.stop();
        let imp = self.imp();
        empty(&imp.candidates_list);
        imp.received.borrow_mut().clear();
        let text = imp.principal_entry.text();
        let filter = if imp.choose_group.get() {
            groups_filter(&text)
        } else {
            secv::delegates_filter(&text)
        };
        imp.candidates_list.set_visible(false);
        let (Some(filter), Some(source)) = (filter, self.context().source.clone()) else {
            imp.candidates_count.set_label("");
            return;
        };
        imp.candidates_count.set_label(&tr("Searching…"));
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                let tooltip = if imp.choose_group.get() {
                    tr("Choose this group")
                } else {
                    tr("Add")
                };
                for item in &items {
                    let view = shv::element_from_item(item);
                    if imp.received.borrow().len() < MAX_RESULTS {
                        imp.candidates_list.append(&candidate_row(&view, &tooltip));
                    }
                    let sid = match item {
                        Item::Object(object) => object_sid(object),
                        Item::Unreadable { .. } => None,
                    };
                    imp.received.borrow_mut().push((view, sid));
                }
                imp.candidates_list
                    .set_visible(!imp.received.borrow().is_empty());
                let n = imp.received.borrow().len();
                imp.candidates_count.set_label(&count_text(n, false));
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                imp.search.take();
                match error {
                    Some(error) => imp
                        .candidates_count
                        .set_label(&errors::search_problem(&error, &domain).message),
                    None => {
                        let n = imp.received.borrow().len();
                        imp.candidates_count.set_label(&count_text(n, true));
                    }
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
    }

    fn candidate_chosen(&self, row: &gtk::ListBoxRow) {
        let dn = row.widget_name().to_string();
        let found = self
            .imp()
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, sid)) = found else { return };
        let name = if view.title.is_empty() {
            view.dn.clone()
        } else {
            view.title.clone()
        };
        if let Some(sid) = sid {
            self.add(&gsv::entry(&sid), &name);
            return;
        }
        let Some(source) = self.context().source.clone() else {
            return;
        };
        let weak = self.downgrade();
        let domain = source.profile().domain.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.record(&dn, &["objectSid"])).await;
            let Some(dialog) = weak.upgrade() else { return };
            match read {
                Ok(Ok(record)) => {
                    let sid = record
                        .as_ref()
                        .and_then(|r| r.values("objectSid").first().cloned())
                        .and_then(|v| Sid::decode(&v).ok());
                    if let Some(sid) = sid {
                        dialog.add(&gsv::entry(&sid), &name);
                    }
                }
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    writes::show_error(
                        &dialog,
                        &tr("Unreadable SID"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                Err(_) => {}
            }
        });
    }

    fn add(&self, entry: &str, name: &str) {
        let imp = self.imp();
        if !name.is_empty() {
            self.context().name(entry, name);
        }
        if imp.choose_group.get() {
            let chosen = imp.chosen.take();
            self.close();
            if let Some(chosen) = chosen {
                chosen(Some(vec![entry.to_owned()]));
            }
            return;
        }
        // Adding someone means defining the setting.
        imp.defined_switch.set_active(true);
        let existing = imp
            .rows
            .borrow()
            .iter()
            .find(|(_, e)| e.eq_ignore_ascii_case(entry))
            .map(|(row, _)| row.clone());
        if let Some(row) = existing {
            row.set_active(true);
            return;
        }
        self.add_row(entry, true);
        imp.principal_entry.set_text("");
        self.refresh();
        imp.confirm_button.grab_focus();
    }

    fn validate(&self) {
        let imp = self.imp();
        let result = imp.defined_switch.is_active().then(|| self.entries());
        let chosen = imp.chosen.take();
        self.close();
        if let Some(chosen) = chosen {
            chosen(result);
        }
    }

    // --- Trials -------------------------------------------------------------------------------

    /// Adds an entry (`*SID`) and validates (trials).
    pub fn trial(&self, entry: Option<&str>, validate: bool) {
        if let Some(e) = entry {
            self.add(e, "");
        }
        if validate && !self.imp().choose_group.get() {
            self.validate();
        }
    }
}

// --- Pages ----------------------------------------------------------------------------------------

/// A row of account setting: switch « Define », value, explanation (`_Reglage`).
pub struct SettingRow {
    setting: &'static sp::SettingDef,
    origin: Option<i64>,
    domain: String,
    row: adw::ExpanderRow,
    number: Option<adw::SpinRow>,
    never: Option<adw::SwitchRow>,
    toggle: Option<adw::SwitchRow>,
    loading: Cell<bool>,
}

impl std::fmt::Debug for SettingRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingRow")
            .field("key", &self.setting.key)
            .finish_non_exhaustive()
    }
}

impl SettingRow {
    fn value(&self) -> Option<i64> {
        if !self.row.enables_expansion() {
            return None;
        }
        if let Some(t) = &self.toggle {
            return Some(i64::from(t.is_active()));
        }
        if let (Some(never), Some(n)) = (&self.never, self.setting.never)
            && never.is_active()
        {
            return Some(n);
        }
        #[allow(clippy::cast_possible_truncation)]
        self.number.as_ref().map(|n| n.value() as i64)
    }

    fn subtitle(&self, value: Option<i64>) {
        let mut text = gsv::value_text(self.setting, value);
        if !self.domain.is_empty() {
            text = fill(
                &tr("{gpo} · domain: {domaine}"),
                &[("gpo", &text), ("domaine", &self.domain)],
            );
        }
        self.row.set_subtitle(&escape(&text));
        if let (Some(number), Some(never)) = (&self.number, &self.never) {
            number.set_sensitive(!never.is_active());
        }
    }
}

mod accounts_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/gpo-securite-comptes.ui")]
    pub struct AccountsPage {
        #[template_child]
        pub scope_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub scope_text: TemplateChild<gtk::Label>,
        #[template_child]
        pub settings_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub settings_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub pso_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub pso_list: TemplateChild<gtk::ListBox>,
        pub context: OnceCell<Rc<SecurityContext>>,
        pub page: Cell<Option<sp::Page>>,
        pub rows: RefCell<Vec<Rc<super::SettingRow>>>,
    }

    impl std::fmt::Debug for AccountsPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AccountsPage").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for AccountsPage {
        const NAME: &'static str = "AnnuaireSecuriteComptes";
        type Type = super::AccountsPage;
        type ParentType = adw::PreferencesPage;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for AccountsPage {}
    impl WidgetImpl for AccountsPage {}
    impl PreferencesPageImpl for AccountsPage {}
}

glib::wrapper! {
    /// « Password Policy » or « Account Lockout Policy » (`AnnuaireSecuriteComptes`).
    pub struct AccountsPage(ObjectSubclass<accounts_imp::AccountsPage>)
        @extends adw::PreferencesPage, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl AccountsPage {
    fn new(context: Rc<SecurityContext>, page: SecurityPage) -> Self {
        let obj: Self = glib::Object::new();
        let imp = obj.imp();
        obj.set_title(&page.title());
        obj.set_widget_name(match page {
            SecurityPage::Password => "mot-de-passe",
            _ => "verrouillage",
        });
        let banner = gsv::accounts_banner(&context.security);
        imp.scope_group.set_title(&escape(&banner.title));
        imp.scope_text.set_label(&banner.text);
        if banner.alert {
            imp.scope_text.add_css_class("warning");
        }
        imp.page.set(page.settings_page());
        let psos = if page == SecurityPage::Password {
            context.security.psos.clone()
        } else {
            Vec::new()
        };
        let _ = imp.context.set(context);
        obj.reload();
        for pso in &psos {
            let (title, summary) = gsv::pso_text(pso, &HashMap::new());
            let row = adw::ActionRow::builder()
                .title(escape(&title).as_str())
                .subtitle(escape(&summary).as_str())
                .subtitle_lines(0)
                .build();
            imp.pso_list.append(&row);
        }
        imp.pso_group.set_visible(!psos.is_empty());
        obj
    }

    fn context(&self) -> &Rc<SecurityContext> {
        self.imp().context.get().expect("set by new")
    }

    fn reload(&self) {
        let imp = self.imp();
        empty(&imp.settings_list);
        let Some(page) = imp.page.get() else { return };
        let context = self.context().clone();
        let rows: Vec<Rc<SettingRow>> =
            gsv::setting_rows(page, &context.inf(), Some(&context.security.domain))
                .into_iter()
                .map(|line| self.setting_row(&line))
                .collect();
        for r in &rows {
            imp.settings_list.append(&r.row);
        }
        *imp.rows.borrow_mut() = rows;
    }

    fn setting_row(&self, line: &gsv::SettingRow) -> Rc<SettingRow> {
        let r = line.setting;
        let title = line.title();
        let expander = adw::ExpanderRow::builder()
            .title(escape(&title).as_str())
            .show_enable_switch(true)
            .title_lines(0)
            .build();
        let value = line.value.unwrap_or(r.suggested);
        let (mut number, mut never, mut toggle) = (None, None, None);
        if r.kind == Kind::Boolean {
            let t = adw::SwitchRow::builder()
                .title(tr("Enabled").as_str())
                .active(value != 0)
                .build();
            expander.add_row(&t);
            toggle = Some(t);
        } else {
            #[allow(clippy::cast_precision_loss)]
            let n = adw::SpinRow::with_range(r.minimum as f64, r.maximum as f64, 1.0);
            n.set_title(&escape(&capitalize(&gsv::setting_unit(r.key))));
            let unlimited = r.never == Some(value);
            #[allow(clippy::cast_precision_loss)]
            n.set_value(if unlimited { r.suggested } else { value } as f64);
            expander.add_row(&n);
            number = Some(n);
            if r.never.is_some() {
                let j = adw::SwitchRow::builder()
                    .title(escape(&gsv::never_text(r.key)).as_str())
                    .active(unlimited)
                    .build();
                expander.add_row(&j);
                never = Some(j);
            }
        }
        expander.add_row(&text_row(&line.explanation(), &tr("Explanation")));
        name_widget(&expander, &title);
        expander.set_enable_expansion(line.value.is_some());
        expander.set_expanded(false);
        let row = Rc::new(SettingRow {
            setting: r,
            origin: sp::value(&self.context().security.inf, r),
            domain: line.domain.clone(),
            row: expander,
            number,
            never,
            toggle,
            loading: Cell::new(true),
        });
        let changed = {
            let (weak, context) = (Rc::downgrade(&row), Rc::downgrade(self.context()));
            move || {
                let (Some(row), Some(context)) = (weak.upgrade(), context.upgrade()) else {
                    return;
                };
                if row.loading.get() {
                    return;
                }
                let value = row.value();
                context
                    .draft
                    .borrow_mut()
                    .set_setting(row.setting.key, value, row.origin);
                row.subtitle(value);
                context.changed();
            }
        };
        let c = changed.clone();
        row.row.connect_enable_expansion_notify(move |_| c());
        if let Some(t) = &row.toggle {
            let c = changed.clone();
            t.connect_active_notify(move |_| c());
        }
        if let Some(n) = &row.number {
            let c = changed.clone();
            n.connect_value_notify(move |_| c());
        }
        if let Some(j) = &row.never {
            j.connect_active_notify(move |_| changed());
        }
        row.loading.set(false);
        row.subtitle(line.value);
        row
    }

    // --- Trials -------------------------------------------------------------------------------

    /// Defines the setting `key` to `value` (`None`: not defined) (trials).
    pub fn trial_set(&self, key: &str, value: Option<i64>) {
        let row = self
            .imp()
            .rows
            .borrow()
            .iter()
            .find(|r| r.setting.key == key)
            .cloned();
        let Some(row) = row else { return };
        match value {
            None => row.row.set_enable_expansion(false),
            Some(v) => {
                row.row.set_enable_expansion(true);
                if let Some(t) = &row.toggle {
                    t.set_active(v != 0);
                } else if let (Some(j), Some(n)) = (&row.never, row.setting.never)
                    && v == n
                {
                    j.set_active(true);
                } else if let Some(n) = &row.number {
                    if let Some(j) = &row.never {
                        j.set_active(false);
                    }
                    #[allow(clippy::cast_precision_loss)]
                    n.set_value(v as f64);
                }
            }
        }
    }
}

mod rights_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/gpo-securite-droits.ui")]
    pub struct RightsPage {
        #[template_child]
        pub warning: TemplateChild<gtk::Label>,
        #[template_child]
        pub filter_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub rights_list: TemplateChild<gtk::ListBox>,
        pub context: OnceCell<Rc<SecurityContext>>,
        pub rows: RefCell<Vec<gsv::RightRow>>,
    }

    impl std::fmt::Debug for RightsPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RightsPage").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RightsPage {
        const NAME: &'static str = "AnnuaireSecuriteDroits";
        type Type = super::RightsPage;
        type ParentType = adw::PreferencesPage;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::RightsPage>(&[
                ("filter", |p, _| {
                    p.imp().rights_list.invalidate_filter();
                    None
                }),
                ("right_selected", |p, args| {
                    if let Some(row) = args.get(1).and_then(|v| v.get::<gtk::ListBoxRow>().ok()) {
                        p.right_chosen(&row);
                    }
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for RightsPage {}
    impl WidgetImpl for RightsPage {}
    impl PreferencesPageImpl for RightsPage {}
}

glib::wrapper! {
    /// « User Rights Assignment » (`AnnuaireSecuriteDroits`).
    pub struct RightsPage(ObjectSubclass<rights_imp::RightsPage>)
        @extends adw::PreferencesPage, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl RightsPage {
    fn new(context: Rc<SecurityContext>) -> Self {
        let obj: Self = glib::Object::new();
        let imp = obj.imp();
        obj.set_title(&SecurityPage::Rights.title());
        obj.set_widget_name("droits");
        imp.warning.set_label(&gsv::rights_warning());
        let _ = imp.context.set(context);
        let weak = obj.downgrade();
        imp.rights_list
            .set_filter_func(move |row| weak.upgrade().is_none_or(|p| p.visible_row(row)));
        obj.reload();
        obj
    }

    fn context(&self) -> &Rc<SecurityContext> {
        self.imp().context.get().expect("set by new")
    }

    fn reload(&self) {
        let imp = self.imp();
        empty(&imp.rights_list);
        let rows = gsv::right_rows(&self.context().inf());
        for line in &rows {
            imp.rights_list.append(&self.row(line));
        }
        *imp.rows.borrow_mut() = rows;
    }

    fn row(&self, line: &gsv::RightRow) -> adw::ActionRow {
        let names = self.context().names.borrow();
        let row = adw::ActionRow::builder()
            .title(escape(&line.title).as_str())
            .subtitle(escape(&gsv::names_list(line.entries.as_deref(), Some(&names))).as_str())
            .activatable(true)
            .title_lines(0)
            .subtitle_lines(0)
            .build();
        row.set_widget_name(&line.name);
        if line.sensitive {
            let icon = gtk::Image::from_icon_name("dialog-warning-symbolic");
            let text = tr("Right that gives control of the machine");
            icon.set_tooltip_text(Some(&text));
            name_widget(&icon, &text);
            row.add_suffix(&icon);
        }
        row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
        row
    }

    fn visible_row(&self, row: &gtk::ListBoxRow) -> bool {
        let text = self.imp().filter_entry.text().trim().to_lowercase();
        if text.is_empty() || row.downcast_ref::<adw::ActionRow>().is_none() {
            return true;
        }
        let name = row.widget_name();
        self.imp().rows.borrow().iter().any(|l| {
            l.name == name.as_str()
                && (l.title.to_lowercase().contains(&text) || l.name.to_lowercase().contains(&text))
        })
    }

    fn right_chosen(&self, row: &gtk::ListBoxRow) {
        let name = row.widget_name().to_string();
        let Some(line) = self
            .imp()
            .rows
            .borrow()
            .iter()
            .find(|l| l.name == name)
            .cloned()
        else {
            return;
        };
        let context = self.context().clone();
        let origin = context.security.inf.right(&line.name);
        let (weak, row) = (self.downgrade(), row.clone());
        let chosen_line = line.clone();
        PrincipalsDialog::new(
            context.clone(),
            &line.title,
            &context.security.name,
            &line.explanation,
            line.entries.as_deref(),
            Box::new(move |entries| {
                let Some(page) = weak.upgrade() else { return };
                let context = page.context().clone();
                context.draft.borrow_mut().set_right(
                    &chosen_line.name,
                    entries.clone(),
                    origin.clone(),
                );
                if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                    let names = context.names.borrow();
                    r.set_subtitle(&escape(&gsv::names_list(entries.as_deref(), Some(&names))));
                }
                if let Some(l) = page
                    .imp()
                    .rows
                    .borrow_mut()
                    .iter_mut()
                    .find(|l| l.name == chosen_line.name)
                {
                    l.entries = entries;
                }
                context.changed();
            }),
            false,
            true,
        )
        .present(Some(self));
    }

    /// Opens the dialog of the right `name` (trials).
    pub fn trial_open(&self, name: &str) {
        let mut i = 0;
        while let Some(row) = self.imp().rights_list.row_at_index(i) {
            if row.widget_name() == name {
                self.right_chosen(&row);
                return;
            }
            i += 1;
        }
    }
}

mod groups_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/gpo-securite-groupes.ui")]
    pub struct GroupsPage {
        #[template_child]
        pub warning: TemplateChild<gtk::Label>,
        #[template_child]
        pub list_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub groups_list: TemplateChild<gtk::ListBox>,
        pub context: OnceCell<Rc<SecurityContext>>,
        pub added: RefCell<Vec<String>>,
    }

    impl std::fmt::Debug for GroupsPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GroupsPage").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for GroupsPage {
        const NAME: &'static str = "AnnuaireSecuriteGroupes";
        type Type = super::GroupsPage;
        type ParentType = adw::PreferencesPage;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::GroupsPage>(&[(
                "add",
                |p, _| {
                    p.add();
                    None
                },
            )]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for GroupsPage {}
    impl WidgetImpl for GroupsPage {}
    impl PreferencesPageImpl for GroupsPage {}
}

glib::wrapper! {
    /// « Restricted Groups » (`AnnuaireSecuriteGroupes`).
    pub struct GroupsPage(ObjectSubclass<groups_imp::GroupsPage>)
        @extends adw::PreferencesPage, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl GroupsPage {
    fn new(context: Rc<SecurityContext>) -> Self {
        let obj: Self = glib::Object::new();
        let imp = obj.imp();
        obj.set_title(&SecurityPage::Groups.title());
        obj.set_widget_name("groupes");
        imp.warning.set_label(&gsv::groups_warning());
        let _ = imp.context.set(context);
        obj.reload();
        obj
    }

    fn context(&self) -> &Rc<SecurityContext> {
        self.imp().context.get().expect("set by new")
    }

    fn origin(&self, group: &str) -> Option<RestrictedGroup> {
        self.context()
            .security
            .inf
            .restricted_groups()
            .into_iter()
            .find(|x| x.group.eq_ignore_ascii_case(group))
    }

    fn reload(&self) {
        let imp = self.imp();
        empty(&imp.groups_list);
        let mut groups: Vec<RestrictedGroup> = self.context().inf().restricted_groups();
        for added in imp.added.borrow().iter() {
            if !groups.iter().any(|g| g.group.eq_ignore_ascii_case(added)) {
                groups.push(RestrictedGroup {
                    group: added.clone(),
                    members: None,
                    member_of: None,
                });
            }
        }
        if groups.is_empty() {
            let row = adw::ActionRow::builder()
                .title(tr("No restricted group").as_str())
                .subtitle(tr("The GPO does not touch any group membership.").as_str())
                .build();
            imp.groups_list.append(&row);
        }
        for x in &groups {
            imp.groups_list.append(&self.row(x));
        }
    }

    fn row(&self, x: &RestrictedGroup) -> adw::ExpanderRow {
        let names = self.context().names.borrow().clone();
        let title = gsv::entry_name(&x.group, Some(&names));
        let expander = adw::ExpanderRow::builder()
            .title(escape(&title).as_str())
            .build();
        name_widget(&expander, &title);
        let summary = if x.members.is_none() && x.member_of.is_none() {
            tr("To be defined: choose its members or the groups it is a member of.")
        } else {
            fill(
                &tr("Members: {m} · Member of: {d}"),
                &[
                    ("m", &gsv::members_text(x.members.as_deref(), Some(&names))),
                    ("d", &gsv::names_list(x.member_of.as_deref(), Some(&names))),
                ],
            )
        };
        expander.set_subtitle(&escape(&summary));
        expander.set_subtitle_lines(0);
        for (title, text, members) in [
            (
                tr("Members of this group"),
                gsv::members_text(x.members.as_deref(), Some(&names)),
                true,
            ),
            (
                tr("This group is a member of"),
                gsv::names_list(x.member_of.as_deref(), Some(&names)),
                false,
            ),
        ] {
            let line = adw::ActionRow::builder()
                .title(title.as_str())
                .subtitle(escape(&text).as_str())
                .activatable(true)
                .subtitle_lines(0)
                .build();
            line.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
            let (weak, group) = (self.downgrade(), x.clone());
            line.connect_activated(move |_| {
                if let Some(page) = weak.upgrade() {
                    page.modify(&group, members);
                }
            });
            expander.add_row(&line);
        }
        let remove = gtk::Button::builder()
            .label(tr("Remove this restricted group").as_str())
            .halign(gtk::Align::Start)
            .margin_top(6)
            .margin_bottom(6)
            .margin_start(12)
            .build();
        remove.add_css_class("destructive-action");
        let (weak, group) = (self.downgrade(), x.clone());
        remove.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.remove(&group);
            }
        });
        let holder = gtk::ListBoxRow::builder()
            .child(&remove)
            .activatable(false)
            .selectable(false)
            .build();
        name_widget(&holder, &tr("Remove this restricted group"));
        expander.add_row(&holder);
        expander
    }

    fn put(&self, group: &str, lists: Option<(Vec<String>, Vec<String>)>) {
        let before = self.origin(group).map(|o| {
            (
                o.members.unwrap_or_default(),
                o.member_of.unwrap_or_default(),
            )
        });
        self.context()
            .draft
            .borrow_mut()
            .set_group(group, lists, before);
        self.reload();
        self.context().changed();
    }

    fn modify(&self, x: &RestrictedGroup, members: bool) {
        let context = self.context().clone();
        let name = gsv::entry_name(&x.group, Some(&context.names.borrow()));
        let (title, explanation) = if members {
            (
                fill(&tr("Members of {g}"), &[("g", &name)]),
                tr(
                    "The group's members on each computer will be exactly these: the others are removed each time the policy applies. An empty list empties the group (except a domain group, which computers do not change).",
                ),
            )
        } else {
            (
                fill(&tr("{g} is a member of"), &[("g", &name)]),
                tr(
                    "The group is added to these groups on each computer, without removing their other members.",
                ),
            )
        };
        let (weak, group) = (self.downgrade(), x.clone());
        let entries = if members {
            x.members.clone()
        } else {
            x.member_of.clone()
        };
        PrincipalsDialog::new(
            context.clone(),
            &title,
            &context.security.name,
            &explanation,
            entries.as_deref(),
            Box::new(move |entries| {
                let Some(page) = weak.upgrade() else { return };
                let list = entries.unwrap_or_default();
                let lists = if members {
                    (list, group.member_of.clone().unwrap_or_default())
                } else {
                    (group.members.clone().unwrap_or_default(), list)
                };
                page.put(&group.group, Some(lists));
            }),
            false,
            false,
        )
        .present(Some(self));
    }

    fn remove(&self, x: &RestrictedGroup) {
        self.imp()
            .added
            .borrow_mut()
            .retain(|a| !a.eq_ignore_ascii_case(&x.group));
        if self.origin(&x.group).is_none() {
            self.context().draft.borrow_mut().forget_group(&x.group);
            self.reload();
            self.context().changed();
        } else {
            self.put(&x.group, None);
        }
    }

    fn add(&self) {
        let context = self.context().clone();
        let weak = self.downgrade();
        PrincipalsDialog::new(
            context.clone(),
            &tr("Add a restricted group"),
            &context.security.name,
            &tr("Choose the group whose membership the GPO will set on the computers."),
            None,
            Box::new(move |entries| {
                let Some(page) = weak.upgrade() else { return };
                let Some(group) = entries.and_then(|e| e.into_iter().next()) else {
                    return;
                };
                let present = page
                    .context()
                    .inf()
                    .restricted_groups()
                    .iter()
                    .any(|x| x.group.eq_ignore_ascii_case(&group));
                if !present && !page.imp().added.borrow().contains(&group) {
                    page.imp().added.borrow_mut().push(group);
                }
                page.reload();
            }),
            true,
            true,
        )
        .present(Some(self));
    }

    /// Adds the group `entry` with these members (trials).
    pub fn trial_put(&self, entry: &str, members: Vec<String>) {
        self.put(entry, Some((members, Vec::new())));
    }

    /// Removes the restricted group `entry` (trials).
    pub fn trial_remove(&self, entry: &str) {
        let x = self
            .context()
            .inf()
            .restricted_groups()
            .into_iter()
            .find(|g| g.group.eq_ignore_ascii_case(entry));
        if let Some(x) = x {
            self.remove(&x);
        }
    }
}

/// The page of `key` (`_page`).
fn page_of(context: &Rc<SecurityContext>, page: SecurityPage) -> adw::PreferencesPage {
    match page {
        SecurityPage::Rights => RightsPage::new(context.clone()).upcast(),
        SecurityPage::Groups => GroupsPage::new(context.clone()).upcast(),
        _ => AccountsPage::new(context.clone(), page).upcast(),
    }
}

fn page_key(page: SecurityPage) -> &'static str {
    match page {
        SecurityPage::Password => "mot-de-passe",
        SecurityPage::Lockout => "verrouillage",
        SecurityPage::Rights => "droits",
        SecurityPage::Groups => "groupes",
    }
}

fn page_of_key(key: &str) -> Option<SecurityPage> {
    SecurityPage::ALL.into_iter().find(|p| page_key(*p) == key)
}

/// Reads the security settings of the GPO and names the SIDs they quote. Blocking.
fn read_named(
    connection: &annuaire_core::Connection,
    dn: &str,
    contents: Option<Option<Vec<u8>>>,
) -> Result<(SecurityRead, Names), GpoError> {
    let mut security = sp::read_security(connection, dn)?;
    if let Some(content) = contents {
        // The content shown is the one the editor read (same batch as the other sections).
        security.inf = match &content {
            Some(bytes) if !bytes.is_empty() => {
                Inf::read(bytes).map_err(|e| GpoError::Invalid(e.to_string()))?
            }
            _ => Inf::new_gpmc(),
        };
        security.exists = content.is_some();
    }
    let sids: HashSet<Sid> = gsv::sids(&security.inf);
    let names = s::name_sids(connection, sids).unwrap_or_default();
    Ok((security, names))
}

// --- Dialog -------------------------------------------------------------------------------------

/// What follows the write of the dialog (the window reads again).
pub type WhenDone = Box<dyn Fn(Option<&Report>)>;

mod dialog_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-securite.ui")]
    pub struct SecurityDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub navigation: TemplateChild<adw::NavigationView>,
        #[template_child]
        pub pages_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub state: TemplateChild<gtk::Label>,
        #[template_child]
        pub summary: TemplateChild<gtk::Label>,
        #[template_child]
        pub save_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub cancel_button: TemplateChild<gtk::Button>,
        pub source: RefCell<Option<Arc<dyn Source>>>,
        pub connection: OnceCell<Arc<annuaire_core::Connection>>,
        pub gpo: OnceCell<(String, String)>,
        pub read_only: Cell<bool>,
        pub when_done: RefCell<Option<WhenDone>>,
        pub context: RefCell<Option<Rc<SecurityContext>>>,
        pub pages: RefCell<HashMap<&'static str, adw::PreferencesPage>>,
        pub page_rows: RefCell<Vec<(SecurityPage, adw::ActionRow)>>,
    }

    impl std::fmt::Debug for SecurityDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecurityDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for SecurityDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoSecurite";
        type Type = super::SecurityDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::SecurityDialog>(&[
                ("page_selected", |d, args| {
                    if let Some(row) = args.get(1).and_then(|v| v.get::<gtk::ListBoxRow>().ok()) {
                        d.open(&row.widget_name());
                    }
                    None
                }),
                ("forget", |d, _| {
                    d.forget();
                    None
                }),
                ("save", |d, _| {
                    d.save();
                    None
                }),
                ("closing", |d, _| {
                    d.close_attempt();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for SecurityDialog {}
    impl WidgetImpl for SecurityDialog {}
    impl AdwDialogImpl for SecurityDialog {}
}

glib::wrapper! {
    /// The security settings of a GPO, from the « Group Policy » window
    /// (`AnnuaireDialogueGpoSecurite`).
    pub struct SecurityDialog(ObjectSubclass<dialog_imp::SecurityDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl SecurityDialog {
    pub fn new(
        source: Option<Arc<dyn Source>>,
        connection: Arc<annuaire_core::Connection>,
        gpo: (String, String),
        read_only: bool,
        when_done: Option<WhenDone>,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.source.borrow_mut() = source;
        let _ = imp.connection.set(connection);
        imp.title.set_subtitle(&gpo.1);
        let _ = imp.gpo.set(gpo);
        imp.read_only.set(read_only);
        *imp.when_done.borrow_mut() = when_done;
        let actions = gio::SimpleActionGroup::new();
        let save = gio::SimpleAction::new("enregistrer", None);
        let weak = dialog.downgrade();
        save.connect_activate(move |_, _| {
            if let Some(d) = weak.upgrade() {
                d.save();
            }
        });
        actions.add_action(&save);
        dialog.insert_action_group("securite", Some(&actions));
        for page in SecurityPage::ALL {
            let row = adw::ActionRow::builder()
                .title(page.title().as_str())
                .activatable(true)
                .sensitive(false)
                .build();
            row.set_widget_name(page_key(page));
            row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
            imp.pages_list.append(&row);
            imp.page_rows.borrow_mut().push((page, row));
        }
        dialog.read();
        dialog
    }

    fn read(&self) {
        let imp = self.imp();
        imp.state
            .set_label(&tr("Reading the GPO on the PDC emulator…"));
        let connection = imp.connection.get().expect("set by new").clone();
        let dn = imp.gpo.get().expect("set by new").0.clone();
        let domain = imp
            .source
            .borrow()
            .as_ref()
            .map(|s| s.profile().domain.clone())
            .unwrap_or_default();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || read_named(&connection, &dn, None)).await;
            let Some(dialog) = weak.upgrade() else { return };
            match read {
                Ok(Ok((security, names))) => dialog.named(security, names),
                Ok(Err(error)) => {
                    let (message, detail) = gpo_error_message(&error, &domain);
                    dialog
                        .imp()
                        .state
                        .set_label(&fill(&tr("Cannot read: {e}"), &[("e", &message)]));
                    writes::show_error(
                        &dialog,
                        &tr("Security settings unreadable"),
                        &message,
                        &detail,
                    );
                }
                Err(_) => {}
            }
        });
    }

    fn named(&self, security: SecurityRead, names: Names) {
        let imp = self.imp();
        let weak = self.downgrade();
        let exists = security.exists;
        let inf = security.inf.clone();
        let context = SecurityContext::new(
            imp.source.borrow().clone(),
            security,
            names,
            Box::new(move || {
                if let Some(d) = weak.upgrade() {
                    d.changed();
                }
            }),
        );
        *imp.context.borrow_mut() = Some(context);
        imp.pages.borrow_mut().clear();
        let mut state = if exists {
            tr("GptTmpl.inf file read on the PDC emulator.")
        } else {
            tr("This GPO has no security settings yet: the file will be created.")
        };
        if imp.read_only.get() {
            state.push(' ');
            state.push_str(&tr("Read-only profile: nothing will be written."));
        }
        imp.state.set_label(&state);
        for (page, row) in imp.page_rows.borrow().iter() {
            row.set_sensitive(true);
            row.set_subtitle(&gsv::page_summary(*page, &inf));
        }
        self.changed();
    }

    /// Pushes the page `key` (`ouvrir`).
    pub fn open(&self, key: &str) {
        let imp = self.imp();
        let (Some(context), Some(page)) = (imp.context.borrow().clone(), page_of_key(key)) else {
            return;
        };
        let k = page_key(page);
        let widget = imp
            .pages
            .borrow_mut()
            .entry(k)
            .or_insert_with(|| page_of(&context, page))
            .clone();
        let view = adw::ToolbarView::new();
        view.add_top_bar(&adw::HeaderBar::new());
        view.set_content(Some(&widget));
        let navigation = adw::NavigationPage::new(&view, &widget.title());
        imp.navigation.push(&navigation);
    }

    fn changed(&self) {
        let imp = self.imp();
        let mut n = 0;
        if let Some(context) = imp.context.borrow().as_ref() {
            n = context.draft.borrow().len();
            let inf = context.inf();
            for (page, row) in imp.page_rows.borrow().iter() {
                row.set_subtitle(&gsv::page_summary(*page, &inf));
            }
        }
        imp.summary.set_label(&if n > 0 {
            fill(
                &tr_n(
                    "{n} change",
                    "{n} changes",
                    u64::try_from(n).unwrap_or(u64::MAX),
                ),
                &[("n", &n.to_string())],
            )
        } else {
            tr("No change")
        });
        imp.save_button.set_sensitive(n > 0 && !imp.read_only.get());
        imp.cancel_button.set_sensitive(n > 0);
        // « close-attempt » (confirmation) is only emitted if `can-close` is false.
        self.set_can_close(n == 0);
    }

    fn forget(&self) {
        let imp = self.imp();
        if let Some(context) = imp.context.borrow().as_ref() {
            *context.draft.borrow_mut() = Draft::default();
        }
        imp.navigation.pop_to_tag("accueil");
        imp.pages.borrow_mut().clear();
        self.changed();
    }

    fn save(&self) {
        let imp = self.imp();
        let Some(context) = imp.context.borrow().clone() else {
            return;
        };
        if context.draft.borrow().is_empty() || imp.read_only.get() {
            return;
        }
        let draft = context.draft.borrow().clone();
        imp.save_button.set_sensitive(false);
        let connection = imp.connection.get().expect("set by new").clone();
        let dn = imp.gpo.get().expect("set by new").0.clone();
        let domain = imp
            .source
            .borrow()
            .as_ref()
            .map(|s| s.profile().domain.clone())
            .unwrap_or_default();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let prepared = gio::spawn_blocking(move || {
                sp::prepare_security(
                    &connection,
                    &dn,
                    Arc::new(move |inf: &Inf| draft.apply(inf)),
                    true,
                    Arc::new(AppCatalog),
                )
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            dialog.changed();
            let changeset = match prepared {
                Ok(Ok(c)) => c,
                Ok(Err(error)) => {
                    let (message, detail) = gpo_error_message(&error, &domain);
                    writes::show_error(
                        &dialog,
                        &tr("Security settings not saved"),
                        &message,
                        &detail,
                    );
                    return;
                }
                Err(_) => return,
            };
            let weak = dialog.downgrade();
            writes::propose(
                &dialog,
                changeset,
                Options {
                    finished: Some(Box::new(move |report| {
                        if let Some(dialog) = weak.upgrade() {
                            dialog.written(report);
                        }
                    })),
                    ..Options::default()
                },
            );
        });
    }

    fn written(&self, report: Option<&Report>) {
        if report.is_none() {
            return; // preview closed: the draft stays
        }
        let imp = self.imp();
        let when_done = imp.when_done.take();
        if let Some(context) = imp.context.borrow().as_ref() {
            *context.draft.borrow_mut() = Draft::default();
        }
        self.force_close();
        if let Some(when_done) = when_done {
            when_done(report);
        }
    }

    /// Closing asked with unsaved changes: confirm (`closing`).
    fn close_attempt(&self) {
        let alert = adw::AlertDialog::new(
            Some(&tr("Discard the changes?")),
            Some(&tr("The changed settings have not been saved to the GPO.")),
        );
        alert.add_response("rester", &tr("Stay"));
        alert.add_response("abandonner", &tr("Discard"));
        alert.set_response_appearance("abandonner", adw::ResponseAppearance::Destructive);
        alert.set_default_response(Some("rester"));
        alert.set_close_response("rester");
        let weak = self.downgrade();
        alert.connect_response(None, move |_, response| {
            if response == "abandonner"
                && let Some(d) = weak.upgrade()
            {
                d.force_close();
            }
        });
        alert.present(Some(self));
    }

    // --- Trials -------------------------------------------------------------------------------

    /// The pages can be opened (trials).
    pub fn trial_ready(&self) -> bool {
        self.imp().context.borrow().is_some()
    }

    pub fn trial_save(&self) {
        self.save();
    }
}

// --- Section of the GPO editor (gpo_editor) ----------------------------------------------------

pub const SECTION: &str = "secu";

fn inf_file() -> ContentFile {
    ContentFile::new(Part::Computer, &sp::PATH.replace('/', "\\"))
}

#[derive(Debug, Default)]
struct SectionState {
    editor: glib::WeakRef<GpoEditor>,
    context: Option<Rc<SecurityContext>>,
    content: Option<Vec<u8>>,
    holders: HashMap<&'static str, adw::Bin>,
    error: String,
    generation: u64,
}

/// « Security Settings » under Computer Configuration › Policies › Windows Settings: the four
/// pages, on the `GptTmpl.inf` read by the editor. The scope and the policy of the domain
/// object are read apart (`read_security`); when writing, the editor adds the domain object on
/// Samba (`security_policy::complete_domain`) (`SectionSecurite`).
#[derive(Debug)]
pub struct SecuritySection {
    me: Weak<SecuritySection>,
    state: RefCell<SectionState>,
}

impl SecuritySection {
    pub fn new() -> Rc<Self> {
        Rc::new_cyclic(|me| Self {
            me: me.clone(),
            state: RefCell::new(SectionState::default()),
        })
    }

    fn fill(&self) {
        let holders: Vec<(&'static str, adw::Bin)> = self
            .state
            .borrow()
            .holders
            .iter()
            .map(|(k, b)| (*k, b.clone()))
            .collect();
        for (key, holder) in holders {
            holder.set_child(Some(&self.page_content(key)));
        }
    }

    fn page_content(&self, key: &str) -> gtk::Widget {
        let state = self.state.borrow();
        if let (Some(context), Some(page)) = (&state.context, page_of_key(key)) {
            return page_of(context, page).upcast();
        }
        let status = adw::StatusPage::builder()
            .icon_name("security-high-symbolic")
            .build();
        if state.error.is_empty() {
            status.set_title(&tr("Reading the GPO on the PDC emulator…"));
        } else {
            status.set_title(&tr("Security settings unreadable"));
            status.set_description(Some(&escape(&state.error)));
        }
        status.upcast()
    }
}

impl Section for SecuritySection {
    fn ident(&self) -> &'static str {
        SECTION
    }

    fn files(&self) -> Vec<ContentFile> {
        vec![inf_file()]
    }

    fn load(&self, editor: &GpoEditor, contents: &HashMap<ContentFile, Option<Vec<u8>>>) {
        let content = contents.get(&inf_file()).cloned().flatten();
        let generation = {
            let mut state = self.state.borrow_mut();
            state.editor.set(Some(editor));
            state.content.clone_from(&content);
            state.context = None;
            state.error.clear();
            state.generation += 1;
            state.generation
        };
        self.fill();
        let Some(context) = editor.context() else {
            return;
        };
        let source = editor
            .transient_for()
            .and_downcast::<crate::gpo::GpoWindow>()
            .map(|w| w.source().clone());
        let (connection, dn) = (context.connection.clone(), editor.gpo().dn.clone());
        let domain = context.profile.domain.clone();
        let me = self.me.clone();
        glib::spawn_future_local(async move {
            let read =
                gio::spawn_blocking(move || read_named(&connection, &dn, Some(content))).await;
            let Some(section) = me.upgrade() else { return };
            if section.state.borrow().generation != generation {
                return;
            }
            match read {
                Ok(Ok((security, names))) => {
                    let editor = section.state.borrow().editor.clone();
                    let context = SecurityContext::new(
                        source,
                        security,
                        names,
                        Box::new(move || {
                            if let Some(editor) = editor.upgrade() {
                                editor.changed();
                            }
                        }),
                    );
                    section.state.borrow_mut().context = Some(context);
                }
                Ok(Err(error)) => {
                    section.state.borrow_mut().error = gpo_error_message(&error, &domain).0;
                }
                Err(_) => return,
            }
            section.fill();
        });
    }

    fn nodes(&self, part: Part) -> Vec<(Anchor, Vec<EditorNode>)> {
        if part != Part::Computer {
            return Vec::new();
        }
        let page = |p: SecurityPage, icon: &'static str| {
            EditorNode::new(format!("secu:{}", page_key(p)), p.title())
                .section(SECTION)
                .icon(icon)
                .data(NodeData::Security(page_key(p).to_owned()))
        };
        let accounts = EditorNode::new("secu:comptes", tr("Account Policies")).children(vec![
            page(SecurityPage::Password, "dialog-password-symbolic"),
            page(SecurityPage::Lockout, "system-lock-screen-symbolic"),
        ]);
        let local = EditorNode::new("secu:locales", tr("Local Policies"))
            .children(vec![page(SecurityPage::Rights, "emblem-system-symbolic")]);
        let root = EditorNode::new("secu:ordinateur", tr("Security Settings"))
            .icon("security-high-symbolic")
            .children(vec![
                accounts,
                local,
                page(SecurityPage::Groups, "system-users-symbolic"),
            ]);
        vec![(Anchor::WindowsSettings, vec![root])]
    }

    fn page(&self, _editor: &GpoEditor, node: &EditorNode) -> gtk::Widget {
        let NodeData::Security(key) = &node.data else {
            return adw::Bin::new().upcast();
        };
        let Some(page) = page_of_key(key) else {
            return adw::Bin::new().upcast();
        };
        let k = page_key(page);
        let existing = self.state.borrow().holders.get(k).cloned();
        if let Some(holder) = existing {
            return holder.upcast();
        }
        let holder = adw::Bin::new();
        holder.set_child(Some(&self.page_content(k)));
        self.state.borrow_mut().holders.insert(k, holder.clone());
        holder.upcast()
    }

    fn modifications(&self) -> Vec<Modification> {
        let Some(context) = self.state.borrow().context.clone() else {
            return Vec::new();
        };
        let draft = context.draft.borrow().clone();
        if draft.is_empty() {
            return Vec::new();
        }
        let after = draft
            .apply(&context.security.inf)
            .unwrap_or_else(|_| context.security.inf.clone());
        let lines = gsv::preview_lines(&draft, &after, Some(&context.names.borrow()));
        let empty = after.is_empty();
        let replay = draft.clone();
        vec![Modification {
            file: inf_file(),
            modify: Arc::new(move |current: Option<&[u8]>| {
                let read = match current {
                    Some(bytes) if !bytes.is_empty() => {
                        Inf::read(bytes).map_err(|e| GpoError::Invalid(e.to_string()))?
                    }
                    _ => Inf::new_gpmc(),
                };
                let inf = replay
                    .apply(&read)
                    .map_err(|p| GpoError::Security(vec![p]))?;
                let problems = sp::problems(&inf);
                if !problems.is_empty() {
                    return Err(GpoError::Security(problems));
                }
                if current.is_none() && inf.is_empty() {
                    return Ok(None);
                }
                inf.write()
                    .map(Some)
                    .map_err(|e| GpoError::Invalid(e.to_string()))
            }),
            extension: (!empty).then(sp::extension),
            lines,
            remove_extensions: if empty {
                vec![sp::extension()]
            } else {
                Vec::new()
            },
        }]
    }

    fn discard(&self) {
        if let Some(context) = self.state.borrow().context.clone() {
            *context.draft.borrow_mut() = Draft::default();
        }
        self.fill();
    }
}

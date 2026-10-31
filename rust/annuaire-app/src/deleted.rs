// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Deleted Objects » window (J9.1, ADR 0024) and dialog of a restoration. Structures in
//! `corbeille.blp` and `dialogue-restaurer.blp`; texts in `deleted_views`, reading and
//! changesets in `annuaire_core::recycle`. A window apart, as « Password Policies »: the
//! deleted objects belong to no OU of the tree, they all lie flat under `CN=Deleted Objects`.
//!
//! Read on the write connection of the main window (PDC emulator), whose versions guard the
//! restorations. The list goes from the most recent deletion, filtered by a text (name,
//! class, last known parent, values kept), a kind and a period, 500 rows at most; the object
//! selected shows what it kept. « Restore… » (or Enter on a row) asks where and under which
//! name, checks it on the DC, then goes through the common preview (journal, Ctrl+Z: the
//! inverse of a restoration is a deletion). Read-only profile: the list only.

use std::cell::{Cell, OnceCell, RefCell};
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Guid;
use annuaire_codecs::time::{self, UtcTime};
use annuaire_core::cache::Source;
use annuaire_core::changes::{Issue, Report};
use annuaire_core::recycle::{self, Bin, Filter, Problem, Restoration};
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::account_views as av;
use crate::catalog::AppCatalog;
use crate::deleted_views as dv;
use crate::errors;
use crate::feed::Feed;
use crate::i18n::{fill, tr};
use crate::writes::{self, Options};

/// Rows shown at most.
pub const MAX_ROWS: usize = 500;

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

fn now() -> Option<UtcTime> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    let nttime = time::unix_to_nttime(i64::try_from(seconds).ok()?).ok()?;
    time::nttime_to_utc(nttime).ok().flatten()
}

// --- The window -------------------------------------------------------------------------------

mod imp {
    use super::*;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/corbeille.ui")]
    pub struct DeletedWindow {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub restore_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub state_banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub search_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub kind_dropdown: TemplateChild<gtk::DropDown>,
        #[template_child]
        pub period_dropdown: TemplateChild<gtk::DropDown>,
        #[template_child]
        pub list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub count_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub detail_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub bin: RefCell<Option<Bin>>,
        /// The GUID of each row, in its order.
        pub rows: RefCell<Vec<Guid>>,
        pub generation: Cell<u64>,
    }

    impl std::fmt::Debug for DeletedWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeletedWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for DeletedWindow {
        const NAME: &'static str = "AnnuaireCorbeille";
        type Type = super::DeletedWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::DeletedWindow>(&[
                ("filter_changed", |w, _| {
                    w.show();
                    None
                }),
                ("selection_changed", |w, _| {
                    w.selection_changed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for DeletedWindow {}
    impl WidgetImpl for DeletedWindow {}

    impl WindowImpl for DeletedWindow {
        fn close_request(&self) -> glib::Propagation {
            self.generation.set(self.generation.get() + 1);
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for DeletedWindow {}
}

glib::wrapper! {
    /// The objects under `CN=Deleted Objects`, from the most recent deletion
    /// (`AnnuaireCorbeille`).
    pub struct DeletedWindow(ObjectSubclass<imp::DeletedWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl DeletedWindow {
    pub fn new(source: Arc<dyn Source>, parent: &crate::window::Window) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = window.imp();
        imp.title.set_subtitle(&source.profile().domain);
        let _ = imp.source.set(source);
        let kinds: Vec<String> = dv::KINDS.iter().map(|k| dv::kind_label(*k)).collect();
        let kinds: Vec<&str> = kinds.iter().map(String::as_str).collect();
        imp.kind_dropdown
            .set_model(Some(&gtk::StringList::new(&kinds)));
        let periods: Vec<String> = dv::PERIODS.iter().map(|p| dv::period_label(*p)).collect();
        let periods: Vec<&str> = periods.iter().map(String::as_str).collect();
        imp.period_dropdown
            .set_model(Some(&gtk::StringList::new(&periods)));
        imp.list.connect_row_activated({
            let weak = window.downgrade();
            move |_, _| {
                if let Some(window) = weak.upgrade() {
                    window.restore();
                }
            }
        });
        window.install_actions();
        window.reload();
        window
    }

    pub fn source(&self) -> &Arc<dyn Source> {
        self.imp().source.get().expect("set by new")
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    fn read_only(&self) -> bool {
        self.source().profile().read_only
    }

    fn install_actions(&self) {
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&DeletedWindow);
        let plain: [(&str, Handler); 3] = [
            ("actualiser", Self::reload),
            ("restaurer", Self::restore),
            ("annuler-derniere", |w| crate::history::undo_last(w)),
        ];
        for (name, handler) in plain {
            let action = gio::SimpleAction::new(name, None);
            let weak = self.downgrade();
            action.connect_activate(move |_, _| {
                if let Some(window) = weak.upgrade().filter(|w| w.visible_dialog().is_none()) {
                    handler(&window);
                }
            });
            group.add_action(&action);
        }
        self.insert_action_group("corbeille", Some(&group));
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [
            ("F5", "corbeille.actualiser"),
            ("<Control>r", "corbeille.actualiser"),
            ("<Control>z", "corbeille.annuler-derniere"),
        ] {
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::NamedAction::new(action)),
            ));
        }
        let weak = self.downgrade();
        shortcuts.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::CallbackAction::new(move |_, _| {
                if let Some(window) = weak.upgrade() {
                    window.close();
                }
                glib::Propagation::Stop
            })),
        ));
        self.add_controller(shortcuts);
        self.imp().restore_button.set_visible(!self.read_only());
    }

    // --- Reading ------------------------------------------------------------------------------

    pub fn reload(&self) {
        let imp = self.imp();
        let Some(context) = writes::context(self) else {
            imp.error.set_title(&tr("No domain is open."));
            imp.state.set_visible_child_name("erreur");
            return;
        };
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.state.set_visible_child_name("chargement");
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        let domain = context.profile.domain.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || recycle::read_bin(&connection)).await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            match read {
                Ok(Ok(bin)) => {
                    imp.state_banner.set_title(&dv::state_text(&bin));
                    imp.state_banner.set_revealed(true);
                    *imp.bin.borrow_mut() = Some(bin);
                    window.show();
                    imp.state.set_visible_child_name("contenu");
                }
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    imp.error.set_title(&tr("Deleted objects cannot be read"));
                    imp.error
                        .set_description(Some(&glib::markup_escape_text(&problem.message)));
                    imp.state.set_visible_child_name("erreur");
                }
                Err(_) => {}
            }
        });
    }

    fn filter(&self) -> Filter {
        let imp = self.imp();
        let kind = dv::KINDS
            .get(imp.kind_dropdown.selected() as usize)
            .copied()
            .flatten();
        let since = dv::PERIODS
            .get(imp.period_dropdown.selected() as usize)
            .copied()
            .flatten()
            .and_then(|days| now()?.add_seconds(-days * 86_400));
        Filter {
            text: imp.search_entry.text().to_string(),
            kind,
            since,
        }
    }

    /// The list, filtered.
    fn show(&self) {
        let imp = self.imp();
        let filter = self.filter();
        empty(&imp.list);
        let guard = imp.bin.borrow();
        let Some(bin) = guard.as_ref() else { return };
        let matching: Vec<&recycle::DeletedObject> = bin
            .objects
            .iter()
            .filter(|o| recycle::matches(o, &filter))
            .collect();
        let mut rows = Vec::new();
        for object in matching.iter().take(MAX_ROWS) {
            imp.list.append(&self.row(bin, object));
            rows.push(object.guid);
        }
        imp.count_label.set_label(&dv::count_text(
            rows.len(),
            matching.len(),
            bin.objects.len(),
        ));
        *imp.rows.borrow_mut() = rows;
        drop(guard);
        self.selection_changed();
    }

    fn row(&self, bin: &Bin, object: &recycle::DeletedObject) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&object.name).as_str())
            .subtitle(glib::markup_escape_text(&dv::row_subtitle(bin, object)).as_str())
            .subtitle_lines(2)
            .activatable(!self.read_only())
            .build();
        if let Some(why) = bin.unrestorable(object) {
            let label = gtk::Label::builder()
                .label(dv::unrestorable_text(why))
                .wrap(true)
                .max_width_chars(28)
                .xalign(1.0)
                .build();
            label.add_css_class("dim-label");
            row.add_suffix(&label);
        }
        row
    }

    fn selected(&self) -> Vec<Guid> {
        let imp = self.imp();
        let rows = imp.rows.borrow();
        imp.list
            .selected_rows()
            .iter()
            .filter_map(|r| rows.get(usize::try_from(r.index()).ok()?).copied())
            .collect()
    }

    fn selection_changed(&self) {
        let imp = self.imp();
        let selected = self.selected();
        let bin = imp.bin.borrow();
        let detail = match (selected.as_slice(), bin.as_ref()) {
            ([one], Some(bin)) => bin.get(one).map(dv::kept_text),
            ([_, _, ..], _) => Some(fill(
                &tr("{n} objects selected."),
                &[("n", &selected.len().to_string())],
            )),
            _ => None,
        };
        imp.detail_label.set_label(
            &detail.unwrap_or_else(|| tr("Select a deleted object to see what it kept.")),
        );
        let restorable = bin.as_ref().is_some_and(|b| {
            selected
                .iter()
                .filter_map(|g| b.get(g))
                .any(|o| b.unrestorable(o).is_none())
        });
        imp.restore_button
            .set_sensitive(restorable && !self.read_only());
    }

    // --- Restoration --------------------------------------------------------------------------

    fn restore(&self) {
        if self.read_only() || writes::context(self).is_none() {
            return;
        }
        let selected = self.selected();
        let Some(bin) = self.imp().bin.borrow().clone() else {
            return;
        };
        if selected.is_empty() {
            return;
        }
        let weak = self.downgrade();
        RestoreDialog::new(
            self.source().clone(),
            bin,
            selected,
            Rc::new(move |report: &Report| {
                if let (Some(window), Issue::Applied) = (weak.upgrade(), report.issue) {
                    window.reload();
                }
            }),
        )
        .present(Some(self));
    }

    /// Called by the common preview after a write (undo by the toast included)
    /// (`apres_ecriture`).
    pub fn after_write(&self, _report: &Report) {
        self.reload();
    }

    // --- Trials ------------------------------------------------------------------------------

    /// The list is shown (trials).
    pub fn trial_ready(&self) -> bool {
        self.imp().state.visible_child_name().as_deref() == Some("contenu")
    }

    /// The banner, then each row (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let imp = self.imp();
        let mut out = vec![imp.state_banner.title().to_string()];
        let mut i = 0;
        while let Some(row) = imp.list.row_at_index(i) {
            if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                out.push(format!(
                    "{} | {}",
                    r.title(),
                    r.subtitle().unwrap_or_default()
                ));
            }
            i += 1;
        }
        out
    }

    /// Filters by `text`, selects the rows named `names` and opens the dialog (trials).
    pub fn trial_restore(&self, text: &str, names: &[&str]) -> bool {
        let imp = self.imp();
        imp.search_entry.set_text(text);
        self.show();
        let mut i = 0;
        let mut found = 0;
        while let Some(row) = imp.list.row_at_index(i) {
            let name = row
                .downcast_ref::<adw::ActionRow>()
                .map(|r| r.title().to_string())
                .unwrap_or_default();
            if names.contains(&name.as_str()) {
                imp.list.select_row(Some(&row));
                found += 1;
            }
            i += 1;
        }
        if found == 0 {
            return false;
        }
        self.restore();
        true
    }
}

// --- The dialog of a restoration ------------------------------------------------------------

/// What follows a restoration applied.
type Restored = Rc<dyn Fn(&Report)>;

crate::accounts::dialog_type!(
    restore_imp, RestoreDialog, "AnnuaireDialogueRestaurer",
    "/io/github/f3nr1l/Calinda/ui/dialogue-restaurer.ui",
    {
        message: adw::Banner,
        confirm_button: gtk::Button,
        elsewhere_switch: adw::SwitchRow,
        search_entry: adw::EntryRow,
        destinations_group: adw::PreferencesGroup,
        list: gtk::ListBox,
        name_group: adw::PreferencesGroup,
        name_entry: adw::EntryRow,
        children_group: adw::PreferencesGroup,
        children_switch: adw::SwitchRow,
    },
    {
        source: RefCell<Option<std::sync::Arc<dyn annuaire_core::cache::Source>>>,
        bin: RefCell<Option<annuaire_core::recycle::Bin>>,
        selected: RefCell<Vec<annuaire_codecs::Guid>>,
        results: OnceCell<gtk::gio::ListStore>,
        feed: RefCell<Option<std::rc::Rc<crate::feed::Feed>>>,
        restored: RefCell<Option<super::Restored>>,
    },
    [
        "elsewhere_changed" => |d, _| { d.elsewhere_changed(); None },
        "search_changed" => |d, _| { d.search_changed(); None },
        "selected" => |d, _| { d.chosen(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

/// Destinations shown at most.
const DESTINATIONS: usize = 200;

impl RestoreDialog {
    pub fn new(source: Arc<dyn Source>, bin: Bin, selected: Vec<Guid>, restored: Restored) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let results = gio::ListStore::new::<gtk::StringObject>();
        imp.list.bind_model(Some(&results), |item| {
            let dn = item
                .downcast_ref::<gtk::StringObject>()
                .map(|s| s.string().to_string())
                .unwrap_or_default();
            adw::ActionRow::builder()
                .title(glib::markup_escape_text(&av::parent_label(&dn)).as_str())
                .subtitle(glib::markup_escape_text(&dn).as_str())
                .subtitle_lines(1)
                .build()
                .upcast()
        });
        let _ = imp.results.set(results);
        let objects: Vec<&recycle::DeletedObject> =
            selected.iter().filter_map(|g| bin.get(g)).collect();
        dialog.set_title(&match objects.as_slice() {
            [one] => fill(&tr("Restore “{nom}”"), &[("nom", &one.name)]),
            many => fill(
                &tr("Restore {n} objects"),
                &[("n", &many.len().to_string())],
            ),
        });
        if let [one] = objects.as_slice() {
            imp.name_entry.set_text(&one.name);
        } else {
            imp.name_group.set_visible(false);
        }
        let parents = objects
            .iter()
            .any(|o| bin.children(&o.guid).next().is_some());
        imp.children_group.set_visible(parents);
        *imp.source.borrow_mut() = Some(source);
        *imp.bin.borrow_mut() = Some(bin);
        *imp.selected.borrow_mut() = selected;
        *imp.restored.borrow_mut() = Some(restored);
        dialog
    }

    fn show_problem(&self, problem: Option<&str>) {
        let text = problem.unwrap_or("");
        let banner = &self.imp().message;
        banner.set_title(text);
        banner.set_revealed(!text.is_empty());
    }

    fn elsewhere_changed(&self) {
        let imp = self.imp();
        let elsewhere = imp.elsewhere_switch.is_active();
        imp.search_entry.set_visible(elsewhere);
        imp.destinations_group.set_visible(elsewhere);
        if elsewhere && imp.feed.borrow().is_none() {
            self.search("");
        }
    }

    /// Destinations searched by their name among the OUs and containers (reading by the
    /// source), as the dialog « Move ».
    fn search(&self, text: &str) {
        let imp = self.imp();
        if let Some(feed) = imp.feed.take() {
            feed.cancel();
        }
        let Some(source) = imp.source.borrow().clone() else {
            return;
        };
        let mut filter = "(objectClass=organizationalUnit)".to_owned();
        if !text.is_empty() {
            let start = annuaire_core::search::starts_with("name", text).unwrap_or_default();
            filter =
                format!("(&(|(objectClass=organizationalUnit)(objectClass=container)){start})");
        }
        let found: Rc<RefCell<Vec<String>>> = Rc::default();
        let (into, weak) = (found.clone(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = weak.upgrade() else { return };
                let mut found = into.borrow_mut();
                for item in &items {
                    if let Item::Object(object) = item
                        && found.len() < DESTINATIONS
                    {
                        found.push(object.common().dn.clone());
                    }
                }
                let mut sorted = found.clone();
                sorted.sort_by_cached_key(|d| av::parent_label(d));
                if let Some(results) = dialog.imp().results.get() {
                    let objects: Vec<glib::Object> = sorted
                        .iter()
                        .map(|d| gtk::StringObject::new(d).upcast())
                        .collect();
                    results.splice(0, results.n_items(), &objects);
                }
            },
            |_| {},
        );
        *imp.feed.borrow_mut() = Some(feed);
    }

    fn search_changed(&self) {
        let text = self.imp().search_entry.text().trim().to_owned();
        self.search(&text);
    }

    fn chosen(&self) {
        self.show_problem(None);
    }

    /// The destination chosen, read back from the model (the subtitle is escaped markup).
    fn destination(&self) -> Option<String> {
        let imp = self.imp();
        let row = imp.list.selected_row()?;
        imp.results
            .get()?
            .item(u32::try_from(row.index()).ok()?)
            .and_downcast::<gtk::StringObject>()
            .map(|s| s.string().to_string())
    }

    fn confirm(&self) {
        let imp = self.imp();
        let target = if imp.elsewhere_switch.is_active() {
            let Some(target) = self.destination() else {
                self.show_problem(Some(&tr("Choose a destination.")));
                return;
            };
            Some(target)
        } else {
            None
        };
        let Some(bin) = imp.bin.borrow().clone() else {
            return;
        };
        let selected = imp.selected.borrow().clone();
        let name = imp.name_entry.text().trim().to_owned();
        let original = match selected.as_slice() {
            [one] => bin.get(one).map(|o| o.name.clone()),
            _ => None,
        };
        let choice = Restoration {
            selected,
            target,
            name: (original.as_ref().is_some_and(|o| *o != name) && !name.is_empty())
                .then_some(name),
            children: imp.children_group.is_visible() && imp.children_switch.is_active(),
        };
        let Some(context) = writes::context(self) else {
            return;
        };
        imp.confirm_button.set_sensitive(false);
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        let domain = context.profile.domain.clone();
        glib::spawn_future_local(async move {
            let prepared = gio::spawn_blocking(move || {
                recycle::prepare(&connection, &bin, &choice, &AppCatalog)
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            dialog.imp().confirm_button.set_sensitive(true);
            match prepared {
                Ok(Ok(Ok(changeset))) => {
                    dialog.show_problem(None);
                    let restored = dialog.imp().restored.borrow().clone();
                    let weak = dialog.downgrade();
                    writes::propose(
                        &dialog,
                        changeset,
                        Options {
                            finished: Some(Box::new(move |report| {
                                if let Some(report) = report.filter(|r| r.issue == Issue::Applied) {
                                    if let Some(dialog) = weak.upgrade() {
                                        dialog.close();
                                    }
                                    if let Some(restored) = &restored {
                                        restored(report);
                                    }
                                }
                            })),
                            ..Options::default()
                        },
                    );
                }
                Ok(Ok(Err(problems))) => dialog.refused(&problems),
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    dialog.show_problem(Some(&problem.message));
                }
                Err(_) => {}
            }
        });
    }

    /// What prevents the restoration; a free name proposed goes in the field « Name ».
    fn refused(&self, problems: &[Problem]) {
        let texts: Vec<String> = problems.iter().map(dv::problem_text).collect();
        self.show_problem(Some(&texts.join("\n")));
        let imp = self.imp();
        if let ([Problem::NameTaken { free, .. }], true) = (problems, imp.name_group.is_visible()) {
            imp.name_entry.set_text(&dv::free_name(free));
        }
    }

    // --- Trials ------------------------------------------------------------------------------

    /// Sets the destination (its DN, or None for the last parent), the name and the children,
    /// then « Continue » (trials).
    pub fn trial(&self, target: Option<&str>, name: Option<&str>, children: Option<bool>) {
        let imp = self.imp();
        if let Some(target) = target {
            imp.elsewhere_switch.set_active(true);
            if let Some(feed) = imp.feed.take() {
                feed.cancel();
            }
            if let Some(results) = imp.results.get() {
                results.splice(
                    0,
                    results.n_items(),
                    &[gtk::StringObject::new(target).upcast::<glib::Object>()],
                );
            }
            if let Some(row) = imp.list.row_at_index(0) {
                imp.list.select_row(Some(&row));
            }
        }
        if let Some(name) = name {
            imp.name_entry.set_text(name);
        }
        if let Some(children) = children {
            imp.children_switch.set_active(children);
        }
        self.confirm();
    }

    /// The text of the banner (trials).
    pub fn trial_message(&self) -> String {
        let banner = &self.imp().message;
        if banner.is_revealed() {
            banner.title().to_string()
        } else {
            String::new()
        }
    }
}

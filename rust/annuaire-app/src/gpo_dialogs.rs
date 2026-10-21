// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Dialogs of the writes on the GPOs (J5.3 to J5.6, `annuaire.ui.gpo_dialogues`): name of a
//! new GPO, GPO to link, security filtering, backup, restoration. Structures in
//! `dialogue-gpo-*.blp`.
//!
//! Each dialog only gathers a choice and gives it back through its callback; the window
//! (`gpo`) builds the changeset and goes through the common preview.

use std::cell::{OnceCell, RefCell};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_core::cache::Source;
use annuaire_core::gpo::Gpo;
use annuaire_core::gpo_backup::{self, Backup};
use annuaire_core::gpo_write::GpoError;
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::delegation::{MAX_RESULTS, candidate_row, object_sid};
use crate::errors;
use crate::feed::Feed;
use crate::gpo_views as gv;
use crate::i18n::{fill, tr, tr_n};
use crate::scope::TemplateScope;
use crate::security_views as sv;
use crate::sheet_views::{self as shv, ElementView};
use crate::writes;

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

fn property_row(title: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(title).as_str())
        .subtitle(glib::markup_escape_text(value).as_str())
        .subtitle_selectable(true)
        .subtitle_lines(0)
        .build();
    row.add_css_class("property");
    row
}

// --- Name of a new GPO (J5.4) ----------------------------------------------------------------

/// What follows the name chosen.
pub type NameChosen = Box<dyn Fn(String)>;

mod name_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-nom.ui")]
    pub struct NameDialog {
        #[template_child]
        pub name_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub chosen: OnceCell<NameChosen>,
    }

    impl std::fmt::Debug for NameDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("NameDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for NameDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoNom";
        type Type = super::NameDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::NameDialog>(&[
                ("name_changed", |d, _| {
                    let imp = d.imp();
                    imp.continue_button
                        .set_sensitive(!imp.name_entry.text().trim().is_empty());
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for NameDialog {}
    impl WidgetImpl for NameDialog {}
    impl AdwDialogImpl for NameDialog {}
}

glib::wrapper! {
    /// The name of a new GPO (`AnnuaireDialogueGpoNom`).
    pub struct NameDialog(ObjectSubclass<name_imp::NameDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl NameDialog {
    pub fn new(chosen: NameChosen) -> Self {
        let dialog: Self = glib::Object::new();
        let _ = dialog.imp().chosen.set(chosen);
        dialog
    }

    fn proceed(&self) {
        let name = self.imp().name_entry.text().trim().to_owned();
        if name.is_empty() {
            return;
        }
        self.close();
        if let Some(chosen) = self.imp().chosen.get() {
            chosen(name);
        }
    }

    /// Types a name and continues (trials).
    pub fn trial(&self, name: &str) {
        self.imp().name_entry.set_text(name);
        self.proceed();
    }
}

// --- Link a GPO (J5.3) -------------------------------------------------------------------------

/// What follows the GPO chosen, and whether the link is enforced.
pub type LinkChosen = Box<dyn Fn(Gpo, bool)>;

mod link_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-lier.ui")]
    pub struct LinkDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub filter_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub gpo_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub enforced_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub gpos: RefCell<Vec<Gpo>>,
        pub chosen: OnceCell<LinkChosen>,
    }

    impl std::fmt::Debug for LinkDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("LinkDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for LinkDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoLier";
        type Type = super::LinkDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::LinkDialog>(&[
                ("filter", |d, _| {
                    d.imp().gpo_list.invalidate_filter();
                    None
                }),
                ("activate_first", |d, _| {
                    d.first();
                    None
                }),
                ("gpo_selected", |d, _| {
                    let imp = d.imp();
                    imp.continue_button
                        .set_sensitive(imp.gpo_list.selected_row().is_some());
                    None
                }),
                ("gpo_activated", |d, args| {
                    if let Some(row) = args.get(1).and_then(|v| v.get::<gtk::ListBoxRow>().ok()) {
                        let imp = d.imp();
                        imp.gpo_list.select_row(Some(&row));
                        imp.enforced_switch.grab_focus();
                    }
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for LinkDialog {}
    impl WidgetImpl for LinkDialog {}
    impl AdwDialogImpl for LinkDialog {}
}

glib::wrapper! {
    /// A GPO to link to a container (`AnnuaireDialogueGpoLier`).
    pub struct LinkDialog(ObjectSubclass<link_imp::LinkDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl LinkDialog {
    pub fn new(container: &str, mut gpos: Vec<Gpo>, chosen: LinkChosen) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title.set_subtitle(container);
        gpos.sort_by_cached_key(|g| g.name.to_lowercase());
        for (index, gpo) in gpos.iter().enumerate() {
            // An AdwActionRow is already a row of the list: no nesting (`_LigneGpo`).
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&gpo.name).as_str())
                .subtitle(
                    glib::markup_escape_text(&fill(&tr("GUID {guid}"), &[("guid", &gpo.guid)]))
                        .as_str(),
                )
                .activatable(true)
                .build();
            row.add_prefix(&gtk::Image::from_icon_name("text-x-generic-symbolic"));
            row.set_widget_name(&index.to_string());
            imp.gpo_list.append(&row);
        }
        *imp.gpos.borrow_mut() = gpos;
        let _ = imp.chosen.set(chosen);
        let weak = dialog.downgrade();
        imp.gpo_list
            .set_filter_func(move |row| weak.upgrade().is_none_or(|d| d.keep(row)));
        dialog
    }

    fn gpo_of(&self, row: &gtk::ListBoxRow) -> Option<Gpo> {
        let index: usize = row.widget_name().parse().ok()?;
        self.imp().gpos.borrow().get(index).cloned()
    }

    fn keep(&self, row: &gtk::ListBoxRow) -> bool {
        let text = self.imp().filter_entry.text().trim().to_lowercase();
        text.is_empty()
            || self
                .gpo_of(row)
                .is_some_and(|g| g.name.to_lowercase().contains(&text))
    }

    /// Enter in the filter: the first visible GPO is chosen, the focus goes there (`activate_first`).
    fn first(&self) {
        let list = &self.imp().gpo_list;
        let mut i = 0;
        while let Some(row) = list.row_at_index(i) {
            if row.is_child_visible() && self.keep(&row) {
                list.select_row(Some(&row));
                row.grab_focus();
                return;
            }
            i += 1;
        }
    }

    fn proceed(&self) {
        let imp = self.imp();
        let Some(gpo) = imp.gpo_list.selected_row().and_then(|r| self.gpo_of(&r)) else {
            return;
        };
        let enforced = imp.enforced_switch.is_active();
        self.close();
        if let Some(chosen) = imp.chosen.get() {
            chosen(gpo, enforced);
        }
    }

    /// Chooses the GPO named `name`, enforced or not, and continues (trials).
    pub fn trial(&self, name: &str, enforced: bool) -> bool {
        let imp = self.imp();
        let mut i = 0;
        while let Some(row) = imp.gpo_list.row_at_index(i) {
            if self.gpo_of(&row).is_some_and(|g| g.name == name) {
                imp.gpo_list.select_row(Some(&row));
                imp.enforced_switch.set_active(enforced);
                self.proceed();
                return true;
            }
            i += 1;
        }
        false
    }
}

// --- Security filtering (J5.5) -------------------------------------------------------------------

/// What follows the filtering chosen: SIDs to add, SIDs to remove.
pub type FilteringChosen = Box<dyn Fn(Vec<Sid>, Vec<Sid>)>;

mod filtering_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-filtrage.ui")]
    pub struct FilteringDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub current_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub principal_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub additions_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub additions_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub chosen: OnceCell<FilteringChosen>,
        /// Adw.SwitchRow cannot be derived: the SID of each row is kept beside it.
        pub present: RefCell<Vec<(adw::SwitchRow, Sid)>>,
        pub added: RefCell<Vec<(gtk::ListBoxRow, Sid)>>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<(ElementView, Option<Sid>)>>,
    }

    impl std::fmt::Debug for FilteringDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FilteringDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FilteringDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoFiltrage";
        type Type = super::FilteringDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::FilteringDialog>(&[
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for FilteringDialog {}
    impl WidgetImpl for FilteringDialog {}

    impl AdwDialogImpl for FilteringDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// The security filtering of a GPO (`AnnuaireDialogueGpoFiltrage`).
    pub struct FilteringDialog(ObjectSubclass<filtering_imp::FilteringDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl FilteringDialog {
    pub fn new(
        source: Arc<dyn Source>,
        gpo_name: &str,
        present: Vec<(Sid, String)>,
        chosen: FilteringChosen,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title.set_subtitle(gpo_name);
        let _ = imp.source.set(source);
        let _ = imp.chosen.set(chosen);
        for (sid, name) in &present {
            let row = adw::SwitchRow::builder()
                .title(glib::markup_escape_text(name).as_str())
                .active(true)
                .build();
            row.set_subtitle(&tr("Keep (uncheck to remove)"));
            let weak = dialog.downgrade();
            row.connect_active_notify(move |row| {
                row.set_subtitle(&if row.is_active() {
                    tr("Keep (uncheck to remove)")
                } else {
                    tr("Will be removed")
                });
                if let Some(dialog) = weak.upgrade() {
                    dialog.update();
                }
            });
            imp.current_list.append(&row);
            imp.present.borrow_mut().push((row, *sid));
        }
        if present.is_empty() {
            imp.current_list.append(&property_row(
                &tr("Nobody"),
                &tr("No account receives this GPO."),
            ));
        }
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.chosen(row);
            }
        });
        dialog
    }

    fn update(&self) {
        let imp = self.imp();
        let removed = imp.present.borrow().iter().any(|(r, _)| !r.is_active());
        let added = !imp.added.borrow().is_empty();
        imp.continue_button.set_sensitive(removed || added);
        imp.additions_group.set_visible(added);
    }

    fn stop(&self) {
        if let Some(feed) = self.imp().search.take() {
            feed.cancel();
        }
    }

    /// The search of the delegation wizard (`search`).
    fn search(&self) {
        self.stop();
        let imp = self.imp();
        empty(&imp.candidates_list);
        imp.received.borrow_mut().clear();
        imp.candidates_list.set_visible(false);
        let Some(filter) = sv::delegates_filter(&imp.principal_entry.text()) else {
            imp.candidates_count.set_label("");
            return;
        };
        imp.candidates_count.set_label(&tr("Searching…"));
        let source = imp.source.get().expect("set by new").clone();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                for item in &items {
                    let view = shv::element_from_item(item);
                    if imp.received.borrow().len() < MAX_RESULTS {
                        imp.candidates_list
                            .append(&candidate_row(&view, &tr("Add to the filtering")));
                    }
                    imp.received.borrow_mut().push((view, object_sid(item)));
                }
                imp.candidates_list
                    .set_visible(!imp.received.borrow().is_empty());
                dialog.count(false);
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                dialog.imp().search.take();
                match error {
                    Some(error) => dialog
                        .imp()
                        .candidates_count
                        .set_label(&errors::search_problem(&error, &domain).message),
                    None => dialog.count(true),
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
    }

    fn count(&self, finished: bool) {
        self.imp()
            .candidates_count
            .set_label(&count_text(self.imp().received.borrow().len(), finished));
    }

    fn chosen(&self, row: &gtk::ListBoxRow) {
        let imp = self.imp();
        let dn = row.widget_name().to_string();
        let found = imp
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, sid)) = found else { return };
        if let Some(sid) = sid {
            self.add(sid, &view.title);
            return;
        }
        // The local copy may not carry the SID: it is read on the DC.
        let source = imp.source.get().expect("set by new").clone();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let reading = source.clone();
            let read = gio::spawn_blocking(move || reading.record(&view.dn, &["objectSid"])).await;
            let Some(dialog) = weak.upgrade() else { return };
            match read {
                Ok(Ok(Some(record))) => {
                    if let Some(sid) = record
                        .values("objectSid")
                        .first()
                        .and_then(|v| Sid::decode(v).ok())
                    {
                        dialog.add(sid, &view.title);
                    }
                }
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &source.profile().domain);
                    writes::show_error(
                        &dialog,
                        &tr("Unreadable SID"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                _ => {}
            }
        });
    }

    fn add(&self, sid: Sid, name: &str) {
        let imp = self.imp();
        if let Some((row, _)) = imp.present.borrow().iter().find(|(_, s)| *s == sid) {
            row.set_active(true);
            return;
        }
        if imp.added.borrow().iter().any(|(_, s)| *s == sid) {
            return;
        }
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(name).as_str())
            .build();
        let button = gtk::Button::builder()
            .icon_name("list-remove-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(tr("Do not add"))
            .build();
        button.add_css_class("flat");
        button.update_property(&[gtk::accessible::Property::Label(&fill(
            &tr("Do not add {n}"),
            &[("n", name)],
        ))]);
        row.add_suffix(&button);
        let list_row: gtk::ListBoxRow = row.clone().upcast();
        let weak = self.downgrade();
        let target = list_row.clone();
        button.connect_clicked(move |_| {
            if let Some(dialog) = weak.upgrade() {
                let imp = dialog.imp();
                imp.additions_list.remove(&target);
                imp.added.borrow_mut().retain(|(r, _)| r != &target);
                dialog.update();
            }
        });
        imp.additions_list.append(&row);
        imp.added.borrow_mut().push((list_row, sid));
        imp.principal_entry.set_text("");
        self.update();
        imp.continue_button.grab_focus();
    }

    fn proceed(&self) {
        let imp = self.imp();
        let add: Vec<Sid> = imp.added.borrow().iter().map(|(_, s)| *s).collect();
        let remove: Vec<Sid> = imp
            .present
            .borrow()
            .iter()
            .filter(|(r, _)| !r.is_active())
            .map(|(_, s)| *s)
            .collect();
        if add.is_empty() && remove.is_empty() {
            return;
        }
        self.close();
        if let Some(chosen) = imp.chosen.get() {
            chosen(add, remove);
        }
    }

    /// Adds `sid` (named `name`), removes the present rows named in `remove`, and continues
    /// (trials).
    pub fn trial(&self, add: Option<(Sid, &str)>, remove: &[&str]) {
        if let Some((sid, name)) = add {
            self.add(sid, name);
        }
        for (row, _) in self.imp().present.borrow().iter() {
            if remove.contains(&row.title().as_str()) {
                row.set_active(false);
            }
        }
        self.proceed();
    }
}

/// The count of the results of a search (`_compter`).
pub fn count_text(n: usize, finished: bool) -> String {
    if finished && n == 0 {
        tr("No group or account found.")
    } else if n > MAX_RESULTS {
        fill(
            &tr("First {montres} results out of {n}: refine the search."),
            &[("montres", &MAX_RESULTS.to_string()), ("n", &n.to_string())],
        )
    } else {
        fill(
            &tr_n("{n} result", "{n} results", n as u64),
            &[("n", &n.to_string())],
        )
    }
}

// --- Backup (J5.6) ----------------------------------------------------------------------------

/// Chooses a folder for `entry` (`_choisir_dossier`).
fn choose_folder(parent: &impl IsA<gtk::Widget>, entry: &adw::EntryRow) {
    let dialog = gtk::FileDialog::builder()
        .title(tr("Backup folder"))
        .build();
    let present = entry.text().trim().to_owned();
    if !present.is_empty() && Path::new(&present).is_dir() {
        dialog.set_initial_folder(Some(&gio::File::for_path(&present)));
    }
    let window = parent.root().and_downcast::<gtk::Window>();
    let entry = entry.clone();
    dialog.select_folder(window.as_ref(), gio::Cancellable::NONE, move |result| {
        let Ok(folder) = result else { return }; // given up
        if let Some(path) = folder.path() {
            entry.set_text(&path.to_string_lossy());
            entry.emit_by_name::<()>("apply", &[]);
        }
    });
}

fn expand_user(text: &str) -> PathBuf {
    match text.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with('/') => {
            let home = std::env::var_os("HOME").unwrap_or_default();
            PathBuf::from(home).join(rest.trim_start_matches('/'))
        }
        _ => PathBuf::from(text),
    }
}

/// How the backup is made: blocking, on a thread apart.
pub type BackUp = Box<dyn FnOnce(PathBuf) -> Result<PathBuf, GpoError> + Send>;

mod backup_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-sauvegarde.ui")]
    pub struct BackupDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub folder_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub back_up_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub cancel_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub button_stack: TemplateChild<gtk::Stack>,
        pub back_up: RefCell<Option<BackUp>>,
        pub host: RefCell<Option<gtk::Widget>>,
        pub domain: RefCell<String>,
    }

    impl std::fmt::Debug for BackupDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("BackupDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for BackupDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoSauvegarde";
        type Type = super::BackupDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::BackupDialog>(&[
                ("choose", |d, _| {
                    choose_folder(d, &d.imp().folder_entry);
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("back_up", |d, _| {
                    d.save();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for BackupDialog {}
    impl WidgetImpl for BackupDialog {}
    impl AdwDialogImpl for BackupDialog {}
}

glib::wrapper! {
    /// The backup of a GPO (`AnnuaireDialogueGpoSauvegarde`).
    pub struct BackupDialog(ObjectSubclass<backup_imp::BackupDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl BackupDialog {
    pub fn new(gpo_name: &str, back_up: BackUp) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title.set_subtitle(gpo_name);
        imp.folder_entry
            .set_text(&gpo_backup::default_folder().to_string_lossy());
        *imp.back_up.borrow_mut() = Some(back_up);
        dialog
    }

    /// Shows the dialog; the messages after go to the window of `parent` (`presenter`).
    pub fn show(&self, parent: &impl IsA<gtk::Widget>) {
        *self.imp().host.borrow_mut() = Some(parent.as_ref().clone());
        if let Some(context) = writes::context(parent) {
            *self.imp().domain.borrow_mut() = context.profile.domain.clone();
        }
        self.present(Some(parent.as_ref()));
    }

    fn save(&self) {
        let imp = self.imp();
        let text = imp.folder_entry.text().trim().to_owned();
        if text.is_empty() {
            return;
        }
        let Some(back_up) = imp.back_up.take() else {
            return;
        };
        imp.back_up_button.set_sensitive(false);
        imp.cancel_button.set_sensitive(false);
        imp.button_stack.set_visible_child_name("attente");
        self.set_can_close(false);
        let folder = expand_user(&text);
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let done = gio::spawn_blocking(move || back_up(folder)).await;
            let Some(dialog) = weak.upgrade() else { return };
            dialog.done(done.ok());
        });
    }

    fn done(&self, result: Option<Result<PathBuf, GpoError>>) {
        let imp = self.imp();
        self.set_can_close(true);
        let host = imp
            .host
            .borrow()
            .clone()
            .unwrap_or_else(|| self.clone().upcast());
        self.close();
        match result {
            Some(Ok(path)) => writes::announce(
                &host,
                &fill(
                    &tr("GPO backed up: {nom}"),
                    &[(
                        "nom",
                        &path
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                    )],
                ),
                None,
            ),
            Some(Err(error)) => {
                let (message, detail) = crate::gpo::gpo_error_message(&error, &imp.domain.borrow());
                writes::show_error(&host, &tr("Backup failed"), &message, &detail);
            }
            None => {}
        }
    }

    /// Saves in `folder` (trials).
    pub fn trial(&self, folder: &str) {
        self.imp().folder_entry.set_text(folder);
        self.save();
    }
}

// --- Restoration (J5.6) ---------------------------------------------------------------------------

/// What follows the backup chosen: the backup, a copy or not, the name of the copy.
pub type RestoreChosen = Box<dyn Fn(Backup, bool, String)>;

mod restore_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-gpo-restaurer.ui")]
    pub struct RestoreDialog {
        #[template_child]
        pub folder_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub archives_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub archives_state: TemplateChild<gtk::Label>,
        #[template_child]
        pub summary_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub summary_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub mode_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub copy_choice: TemplateChild<gtk::CheckButton>,
        #[template_child]
        pub name_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub archives: RefCell<Vec<PathBuf>>,
        pub backup: RefCell<Option<Backup>>,
        pub chosen: OnceCell<RestoreChosen>,
    }

    impl std::fmt::Debug for RestoreDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RestoreDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RestoreDialog {
        const NAME: &'static str = "AnnuaireDialogueGpoRestaurer";
        type Type = super::RestoreDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::RestoreDialog>(&[
                ("choose", |d, _| {
                    choose_folder(d, &d.imp().folder_entry);
                    None
                }),
                ("reload", |d, _| {
                    d.read_again();
                    None
                }),
                ("archive_selected", |d, _| {
                    d.archive_chosen();
                    None
                }),
                ("mode_changed", |d, _| {
                    d.mode_changed();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for RestoreDialog {}
    impl WidgetImpl for RestoreDialog {}
    impl AdwDialogImpl for RestoreDialog {}
}

glib::wrapper! {
    /// The restoration of a GPO from an archive (`AnnuaireDialogueGpoRestaurer`).
    pub struct RestoreDialog(ObjectSubclass<restore_imp::RestoreDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl RestoreDialog {
    pub fn new(chosen: RestoreChosen) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.chosen.set(chosen);
        imp.folder_entry
            .set_text(&gpo_backup::default_folder().to_string_lossy());
        dialog.read_again();
        dialog
    }

    /// `reload`.
    fn read_again(&self) {
        let imp = self.imp();
        empty(&imp.archives_list);
        self.show_backup(None);
        let folder = expand_user(imp.folder_entry.text().trim());
        let archives = gpo_backup::list_archives(&folder);
        for (index, path) in archives.iter().enumerate() {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let (title, subtitle) = gv::archive_title(&name);
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&title).as_str())
                .subtitle(glib::markup_escape_text(&subtitle).as_str())
                .activatable(true)
                .build();
            row.add_prefix(&gtk::Image::from_icon_name("package-x-generic-symbolic"));
            row.set_widget_name(&index.to_string());
            imp.archives_list.append(&row);
        }
        imp.archives_list.set_visible(!archives.is_empty());
        let n = u64::try_from(archives.len()).unwrap_or(0);
        imp.archives_state.set_label(&if archives.is_empty() {
            tr("No backup in this folder.")
        } else {
            fill(
                &tr_n("{n} backup", "{n} backups", n),
                &[("n", &n.to_string())],
            )
        });
        *imp.archives.borrow_mut() = archives;
    }

    /// `archive_selected`.
    fn archive_chosen(&self) {
        let imp = self.imp();
        let path = imp
            .archives_list
            .selected_row()
            .and_then(|r| r.widget_name().parse::<usize>().ok())
            .and_then(|i| imp.archives.borrow().get(i).cloned());
        let Some(path) = path else {
            self.show_backup(None);
            return;
        };
        match gpo_backup::read_archive(&path) {
            Ok(backup) => self.show_backup(Some(backup)),
            Err(error) => {
                self.show_backup(None);
                let (message, detail) = crate::gpo::backup_error_message(&error);
                writes::show_error(self, &tr("Unreadable backup"), &message, &detail);
            }
        }
    }

    fn show_backup(&self, backup: Option<Backup>) {
        let imp = self.imp();
        empty(&imp.summary_list);
        imp.summary_group.set_visible(backup.is_some());
        imp.mode_group.set_visible(backup.is_some());
        if let Some(backup) = &backup {
            for line in gv::archive_summary(backup) {
                imp.summary_list
                    .append(&property_row(&line.title, &line.value));
            }
            imp.name_entry.set_text(&gv::copy_name(&backup.name));
        }
        *imp.backup.borrow_mut() = backup;
        self.mode_changed();
    }

    /// `mode_changed`.
    fn mode_changed(&self) {
        let imp = self.imp();
        let copy = imp.copy_choice.is_active();
        imp.name_entry.set_visible(copy);
        let ready =
            imp.backup.borrow().is_some() && (!copy || !imp.name_entry.text().trim().is_empty());
        imp.continue_button.set_sensitive(ready);
    }

    fn proceed(&self) {
        let imp = self.imp();
        let Some(backup) = imp.backup.borrow().clone() else {
            return;
        };
        let copy = imp.copy_choice.is_active();
        let name = imp.name_entry.text().trim().to_owned();
        self.close();
        if let Some(chosen) = imp.chosen.get() {
            chosen(backup, copy, name);
        }
    }

    /// Reads `folder`, chooses the archive whose name contains `guid`, as a copy or not, and
    /// continues (trials).
    pub fn trial(&self, folder: &str, guid: &str, copy: Option<&str>) -> bool {
        let imp = self.imp();
        imp.folder_entry.set_text(folder);
        self.read_again();
        let index = imp.archives.borrow().iter().position(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().contains(guid))
        });
        let Some(row) = index.and_then(|i| imp.archives_list.row_at_index(i32::try_from(i).ok()?))
        else {
            return false;
        };
        imp.archives_list.select_row(Some(&row));
        if let Some(name) = copy {
            imp.copy_choice.set_active(true);
            imp.name_entry.set_text(name);
        }
        self.proceed();
        true
    }
}

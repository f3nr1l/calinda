// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Password Policies » window (ADR 0014 § 6, `annuaire.ui.pso`) and dialog of a
//! fine-grained password policy. Structures in `pso.blp` and `dialogue-pso.blp`; texts in
//! `pso_views`, changesets in `annuaire_core::pso`. A window apart, as « Group Policy » and
//! « DNS »: a PSO is an object of the whole domain, under `CN=System`, that belongs to no OU
//! of the tree; the list of the PSOs by precedence, beside the domain policy, says at a glance
//! what wins.
//!
//! Read on the write connection of the main window (PDC emulator): the versions read guard
//! the modifications (ADR 0006). « New policy » (Ctrl+N) starts from the domain policy, as
//! `samba-tool domain passwordsettings pso create`; « Edit » reads the PSO again, « Delete »
//! too; everything goes through the common preview (journal, Ctrl+Z). Read-only profile: the
//! list only.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::cache::Source;
use annuaire_core::changes::{Changeset, Report};
use annuaire_core::pso::{self as p, PsoRead, Settings};
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::delegation::{MAX_RESULTS, candidate_row};
use crate::errors;
use crate::feed::Feed;
use crate::gpo_dialogs::count_text;
use crate::i18n::{fill, tr};
use crate::pso_views as pv;
use crate::scope::TemplateScope;
use crate::security_views as sv;
use crate::sheet_views::{self as shv, ElementView};
use crate::writes::{self, Options};

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

/// What follows a write of the dialog (the window reads again).
type Finished = Rc<dyn Fn(Option<&Report>)>;

/// What follows a PSO read again.
type Then = Box<dyn FnOnce(&PsoWindow, PsoRead)>;

// --- The window -------------------------------------------------------------------------------

mod imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/pso.ui")]
    pub struct PsoWindow {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub new_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub domain_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub psos_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub none_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub psos: RefCell<Vec<PsoRead>>,
        pub domain: RefCell<Option<Settings>>,
        pub generation: Cell<u64>,
    }

    impl std::fmt::Debug for PsoWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PsoWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PsoWindow {
        const NAME: &'static str = "AnnuairePso";
        type Type = super::PsoWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PsoWindow {}
    impl WidgetImpl for PsoWindow {}

    impl WindowImpl for PsoWindow {
        fn close_request(&self) -> glib::Propagation {
            self.generation.set(self.generation.get() + 1);
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for PsoWindow {}
}

glib::wrapper! {
    /// The domain policy and the fine-grained password policies, by precedence
    /// (`AnnuairePso`).
    pub struct PsoWindow(ObjectSubclass<imp::PsoWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl PsoWindow {
    pub fn new(source: Arc<dyn Source>, parent: &crate::window::Window) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = window.imp();
        imp.title.set_subtitle(&source.profile().domain);
        let _ = imp.source.set(source);
        imp.psos_list.connect_row_activated({
            let weak = window.downgrade();
            move |_, row| {
                if let Some(window) = weak.upgrade() {
                    window.row_activated(row);
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
        type Handler = fn(&PsoWindow);
        let plain: [(&str, Handler); 3] = [
            ("actualiser", Self::reload),
            ("nouvelle", Self::new_policy),
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
            if name == "nouvelle" {
                action.set_enabled(!self.read_only());
            }
            group.add_action(&action);
        }
        self.insert_action_group("pso", Some(&group));
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [
            ("F5", "pso.actualiser"),
            ("<Control>r", "pso.actualiser"),
            ("<Control>n", "pso.nouvelle"),
            ("<Control>z", "pso.annuler-derniere"),
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
        self.imp().new_button.set_visible(!self.read_only());
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
            let read = gio::spawn_blocking(move || {
                Ok::<_, annuaire_core::connection::Failure>((
                    p::read_psos(&connection)?,
                    p::read_domain(&connection)?,
                ))
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            match read {
                Ok(Ok((psos, settings))) => {
                    *imp.psos.borrow_mut() = psos;
                    *imp.domain.borrow_mut() = Some(settings);
                    window.show();
                }
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    imp.error.set_title(&tr("Policies cannot be read"));
                    imp.error
                        .set_description(Some(&glib::markup_escape_text(&problem.message)));
                    imp.state.set_visible_child_name("erreur");
                }
                Err(_) => {}
            }
        });
    }

    fn show(&self) {
        let imp = self.imp();
        if let Some(settings) = imp.domain.borrow().as_ref() {
            imp.domain_row
                .set_subtitle(&glib::markup_escape_text(&pv::summary(settings)));
        }
        empty(&imp.psos_list);
        let psos = imp.psos.borrow().clone();
        for (index, pso) in psos.iter().enumerate() {
            imp.psos_list.append(&self.row(index, pso));
        }
        imp.psos_list.set_visible(!psos.is_empty());
        imp.none_label.set_visible(psos.is_empty());
        imp.state.set_visible_child_name("contenu");
    }

    fn row(&self, index: usize, pso: &PsoRead) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&pv::title(pso)).as_str())
            .subtitle(
                glib::markup_escape_text(&format!(
                    "{}\n{}",
                    pv::summary(&pso.settings),
                    pv::targets_text(&pso.targets)
                ))
                .as_str(),
            )
            .activatable(!self.read_only())
            .subtitle_lines(0)
            .build();
        row.set_widget_name(&index.to_string());
        if !self.read_only() {
            type Handler = fn(&PsoWindow, PsoRead);
            let actions: [(&str, String, Handler); 2] = [
                ("document-edit-symbolic", tr("Edit"), Self::edit),
                ("user-trash-symbolic", tr("Delete"), Self::delete),
            ];
            for (icon, text, handler) in actions {
                let button = gtk::Button::builder()
                    .icon_name(icon)
                    .valign(gtk::Align::Center)
                    .tooltip_text(text.as_str())
                    .build();
                button.add_css_class("flat");
                button.update_property(&[gtk::accessible::Property::Label(&format!(
                    "{text} : {}",
                    pso.name
                ))]);
                let (weak, pso) = (self.downgrade(), pso.clone());
                button.connect_clicked(move |_| {
                    if let Some(window) = weak.upgrade() {
                        handler(&window, pso.clone());
                    }
                });
                row.add_suffix(&button);
            }
        }
        row
    }

    fn row_activated(&self, row: &gtk::ListBoxRow) {
        if self.read_only() {
            return;
        }
        let pso = row
            .widget_name()
            .parse::<usize>()
            .ok()
            .and_then(|i| self.imp().psos.borrow().get(i).cloned());
        if let Some(pso) = pso {
            self.edit(pso);
        }
    }

    // --- Writes -----------------------------------------------------------------------------

    fn finished(&self) -> Finished {
        let weak = self.downgrade();
        Rc::new(move |report: Option<&Report>| {
            if let (Some(window), Some(_)) = (weak.upgrade(), report) {
                window.reload();
            }
        })
    }

    fn new_policy(&self) {
        if writes::context(self).is_none() || self.read_only() {
            return;
        }
        let imp = self.imp();
        let start = imp.domain.borrow().unwrap_or_default();
        let precedences: Vec<i64> = imp
            .psos
            .borrow()
            .iter()
            .map(|x| x.settings.precedence)
            .collect();
        let settings = Settings {
            precedence: precedences.iter().max().map_or(10, |m| m + 10),
            ..start
        };
        let others: Vec<String> = imp.psos.borrow().iter().map(|x| x.name.clone()).collect();
        PsoDialog::new(
            self.source().clone(),
            None,
            settings,
            others,
            self.finished(),
        )
        .present(Some(self));
    }

    /// The PSO read again just before a write (`reload`).
    fn read_again(&self, pso: PsoRead, then: Then) {
        let Some(context) = writes::context(self) else {
            return;
        };
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        let domain = context.profile.domain.clone();
        glib::spawn_future_local(async move {
            let dn = pso.dn.clone();
            let read = gio::spawn_blocking(move || p::read_pso(&connection, &dn)).await;
            let Some(window) = weak.upgrade() else { return };
            match read {
                Ok(Ok(Some(again))) => then(&window, again),
                Ok(Ok(None)) => {
                    writes::announce(&window, &tr("This policy no longer exists."), None);
                    window.reload();
                }
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    writes::show_error(
                        &window,
                        &tr("Policy cannot be read"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                Err(_) => {}
            }
        });
    }

    fn edit(&self, pso: PsoRead) {
        self.read_again(
            pso,
            Box::new(|window, again| {
                let others: Vec<String> = window
                    .imp()
                    .psos
                    .borrow()
                    .iter()
                    .filter(|x| x.dn != again.dn)
                    .map(|x| x.name.clone())
                    .collect();
                let settings = again.settings;
                PsoDialog::new(
                    window.source().clone(),
                    Some(again),
                    settings,
                    others,
                    window.finished(),
                )
                .present(Some(window));
            }),
        );
    }

    fn delete(&self, pso: PsoRead) {
        self.read_again(
            pso,
            Box::new(|window, again| {
                let changeset = match p::delete(&again) {
                    Ok(c) => c,
                    Err(e) => {
                        writes::show_error(
                            window,
                            &tr("Invalid policy"),
                            &pv::pso_error_text(&e),
                            "",
                        );
                        return;
                    }
                };
                let remarks = vec![
                    fill(
                        &tr("Deletion of the fine-grained password policy “{nom}”; {cibles}."),
                        &[
                            ("nom", &again.name),
                            ("cibles", &pv::targets_text(&again.targets).to_lowercase()),
                        ],
                    ),
                    tr(
                        "The accounts it applied to fall back to the domain policy, or to the next policy by precedence. Undoing recreates the policy with the accounts and groups it applies to.",
                    ),
                ];
                let finished = window.finished();
                writes::propose(
                    window,
                    Changeset {
                        operations: changeset.operations,
                        remarks,
                    },
                    Options {
                        finished: Some(Box::new(move |report| finished(report))),
                        ..Options::default()
                    },
                );
            }),
        );
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

    /// The texts shown: the domain policy, then each PSO (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let imp = self.imp();
        let mut out = vec![imp.domain_row.subtitle().unwrap_or_default().to_string()];
        let mut i = 0;
        while let Some(row) = imp.psos_list.row_at_index(i) {
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

    /// Opens the dialog of a new policy, or of the PSO named `name` (trials).
    pub fn trial_open(&self, name: Option<&str>) {
        match name {
            None => self.new_policy(),
            Some(name) => {
                let found = self
                    .imp()
                    .psos
                    .borrow()
                    .iter()
                    .find(|x| x.name == name)
                    .cloned();
                if let Some(pso) = found {
                    self.edit(pso);
                }
            }
        }
    }

    /// Deletes the PSO named `name` (trials).
    pub fn trial_delete(&self, name: &str) {
        let found = self
            .imp()
            .psos
            .borrow()
            .iter()
            .find(|x| x.name == name)
            .cloned();
        if let Some(pso) = found {
            self.delete(pso);
        }
    }
}

// --- The dialog of a policy -------------------------------------------------------------------

mod dialog_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-pso.ui")]
    pub struct PsoDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub name_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub description_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub precedence: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub minimum_length: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub history: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub complexity: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub reversible_encryption: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub minimum_age: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub maximum_age: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub lockout_threshold: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub lockout_duration: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub lockout_window: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub targets_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub target_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub problems_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub problems: TemplateChild<gtk::Label>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub pso: OnceCell<Option<PsoRead>>,
        pub others: RefCell<Vec<String>>,
        pub finished: RefCell<Option<Finished>>,
        pub settings: RefCell<Option<Settings>>,
        pub targets: RefCell<Vec<String>>,
        /// Targets added on which a PSO has no effect (key: DN in lower case).
        pub without_effect: RefCell<HashMap<String, String>>,
        /// Durations read: text shown and exact value, kept if the text does not change.
        pub origins: RefCell<HashMap<&'static str, (String, i64)>>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<(ElementView, String)>>,
        pub ready: Cell<bool>,
    }

    impl std::fmt::Debug for PsoDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PsoDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PsoDialog {
        const NAME: &'static str = "AnnuaireDialoguePso";
        type Type = super::PsoDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PsoDialog>(&[
                ("changed", |d, _| {
                    d.changed();
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

    impl ObjectImpl for PsoDialog {}
    impl WidgetImpl for PsoDialog {}

    impl AdwDialogImpl for PsoDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// A fine-grained password policy, new (`pso` None) or to modify (`AnnuaireDialoguePso`).
    pub struct PsoDialog(ObjectSubclass<dialog_imp::PsoDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

const NUMBERS: [&str; 4] = [
    "priorite",
    "longueur_minimale",
    "historique",
    "seuil_verrouillage",
];
const DURATIONS: [&str; 4] = [
    "age_minimal",
    "age_maximal",
    "duree_verrouillage",
    "fenetre_verrouillage",
];

impl PsoDialog {
    fn new(
        source: Arc<dyn Source>,
        pso: Option<PsoRead>,
        settings: Settings,
        others: Vec<String>,
        finished: Finished,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.source.set(source);
        *imp.others.borrow_mut() = others.iter().map(|n| n.to_lowercase()).collect();
        *imp.finished.borrow_mut() = Some(finished);
        *imp.targets.borrow_mut() = pso.as_ref().map(|x| x.targets.clone()).unwrap_or_default();
        dialog.fill(&settings);
        match &pso {
            Some(pso) => {
                imp.title.set_subtitle(&glib::markup_escape_text(&pso.name));
                imp.name_entry.set_text(&pso.name);
                imp.name_entry.set_editable(false);
                imp.name_entry
                    .set_tooltip_text(Some(&tr("A policy name cannot be changed here.")));
                imp.description_entry.set_text(&pso.description);
                dialog.set_focus(Some(&*imp.precedence));
            }
            None => imp.title.set_subtitle(&tr("New policy")),
        }
        let _ = imp.pso.set(pso);
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.chosen(row);
            }
        });
        imp.ready.set(true);
        dialog.show_targets();
        dialog.changed();
        dialog
    }

    fn spin(&self, name: &str) -> &adw::SpinRow {
        let imp = self.imp();
        match name {
            "priorite" => &imp.precedence,
            "longueur_minimale" => &imp.minimum_length,
            "historique" => &imp.history,
            _ => &imp.lockout_threshold,
        }
    }

    fn duration_entry(&self, name: &str) -> &adw::EntryRow {
        let imp = self.imp();
        match name {
            "age_minimal" => &imp.minimum_age,
            "age_maximal" => &imp.maximum_age,
            "duree_verrouillage" => &imp.lockout_duration,
            _ => &imp.lockout_window,
        }
    }

    /// `_remplir`.
    fn fill(&self, settings: &Settings) {
        let imp = self.imp();
        for name in NUMBERS {
            if let p::FieldValue::Number(n) = settings.get(name) {
                self.spin(name).set_value(n as f64);
            }
        }
        imp.complexity.set_active(settings.complexity);
        imp.reversible_encryption.set_active(settings.reversible);
        for name in DURATIONS {
            if let p::FieldValue::Number(value) = settings.get(name) {
                let text = pv::duration_input(value);
                imp.origins.borrow_mut().insert(name, (text.clone(), value));
                self.duration_entry(name).set_text(&text);
            }
        }
    }

    /// The settings typed, or the reasons that prevent writing them (`_lire`).
    fn read(&self) -> Result<Settings, Vec<String>> {
        let imp = self.imp();
        let mut errors = Vec::new();
        let mut settings = Settings::default();
        for name in NUMBERS {
            settings.set(name, p::FieldValue::Number(self.spin(name).value() as i64));
        }
        settings.complexity = imp.complexity.is_active();
        settings.reversible = imp.reversible_encryption.is_active();
        for name in DURATIONS {
            let entry = self.duration_entry(name);
            let text = entry.text().to_string();
            let origin = imp.origins.borrow().get(name).cloned();
            let value = match origin {
                Some((shown, value)) if text.trim() == shown => Ok(value),
                _ => pv::duration_from_input(&text, name),
            };
            match value {
                Ok(v) => {
                    entry.remove_css_class("error");
                    settings.set(name, p::FieldValue::Number(v));
                }
                Err(e) => {
                    entry.add_css_class("error");
                    errors.push(format!("{} : {e}", pv::field_title(name)));
                }
            }
        }
        if imp.pso.get().is_none_or(Option::is_none) {
            match p::check_name(&imp.name_entry.text()) {
                Ok(name) => {
                    if imp.others.borrow().contains(&name.to_lowercase()) {
                        errors.push(tr("A policy with this name already exists."));
                    }
                }
                Err(e) => errors.push(pv::pso_error_text(&e)),
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let problems = p::problems(&settings);
        if problems.is_empty() {
            Ok(settings)
        } else {
            Err(problems.iter().map(pv::problem_text).collect())
        }
    }

    /// `changed`.
    fn changed(&self) {
        let imp = self.imp();
        if !imp.ready.get() {
            return;
        }
        let read = self.read();
        let errors = read.as_ref().err().cloned().unwrap_or_default();
        imp.problems.set_label(&errors.join("\n"));
        imp.problems_group.set_visible(!errors.is_empty());
        imp.continue_button.set_sensitive(read.is_ok());
        *imp.settings.borrow_mut() = read.ok();
    }

    // --- Targets ----------------------------------------------------------------------------

    fn show_targets(&self) {
        let imp = self.imp();
        empty(&imp.targets_list);
        let targets = imp.targets.borrow().clone();
        for dn in &targets {
            let mut subtitle = dn.clone();
            if let Some(why) = imp.without_effect.borrow().get(&dn.to_lowercase()) {
                subtitle = format!("{why} · {dn}");
            }
            let name = pv::target_name(dn);
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&name).as_str())
                .subtitle(glib::markup_escape_text(&subtitle).as_str())
                .subtitle_lines(2)
                .build();
            let button = gtk::Button::builder()
                .icon_name("list-remove-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text(tr("Remove"))
                .build();
            button.add_css_class("flat");
            button.update_property(&[gtk::accessible::Property::Label(&fill(
                &tr("Remove: {nom}"),
                &[("nom", &name)],
            ))]);
            let (weak, dn) = (self.downgrade(), dn.clone());
            button.connect_clicked(move |_| {
                if let Some(dialog) = weak.upgrade() {
                    dialog
                        .imp()
                        .targets
                        .borrow_mut()
                        .retain(|x| !x.eq_ignore_ascii_case(&dn));
                    dialog.show_targets();
                }
            });
            row.add_suffix(&button);
            imp.targets_list.append(&row);
        }
        imp.targets_list.set_visible(!targets.is_empty());
    }

    fn stop(&self) {
        if let Some(feed) = self.imp().search.take() {
            feed.cancel();
        }
    }

    /// `search`.
    fn search(&self) {
        self.stop();
        let imp = self.imp();
        empty(&imp.candidates_list);
        imp.received.borrow_mut().clear();
        imp.candidates_list.set_visible(false);
        let Some(filter) = sv::delegates_filter(&imp.target_entry.text()) else {
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
                            .append(&candidate_row(&view, &tr("Add")));
                    }
                    let why = match item {
                        Item::Object(object) => pv::without_effect(object),
                        Item::Unreadable { .. } => String::new(),
                    };
                    imp.received.borrow_mut().push((view, why));
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

    /// `selected`.
    fn chosen(&self, row: &gtk::ListBoxRow) {
        let imp = self.imp();
        let dn = row.widget_name().to_string();
        let found = imp
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, why)) = found else { return };
        let known = imp
            .targets
            .borrow()
            .iter()
            .any(|x| x.eq_ignore_ascii_case(&view.dn));
        if !known {
            imp.targets.borrow_mut().push(view.dn.clone());
            if !why.is_empty() {
                imp.without_effect
                    .borrow_mut()
                    .insert(view.dn.to_lowercase(), why);
            }
        }
        imp.target_entry.set_text("");
        self.show_targets();
    }

    // --- Writing ------------------------------------------------------------------------------

    /// `next`.
    fn proceed(&self) {
        self.changed();
        let imp = self.imp();
        let Some(settings) = *imp.settings.borrow() else {
            return;
        };
        let Some(context) = writes::context(self) else {
            return;
        };
        let Some(state) = context.connection.state() else {
            return;
        };
        let description = imp.description_entry.text().to_string();
        let targets = imp.targets.borrow().clone();
        let built = match imp.pso.get().cloned().flatten() {
            None => p::create(
                &state.root_dse.default_naming_context,
                &imp.name_entry.text(),
                &settings,
                &targets,
                &description,
            ),
            Some(pso) => p::modify(&pso, &settings, Some(&targets), Some(&description)),
        };
        let changeset = match built {
            Ok(c) => c,
            Err(e) => {
                writes::show_error(self, &tr("Invalid policy"), &pv::pso_error_text(&e), "");
                return;
            }
        };
        let without: Vec<String> = targets
            .iter()
            .filter(|d| imp.without_effect.borrow().contains_key(&d.to_lowercase()))
            .map(|d| pv::target_name(d))
            .collect();
        let weak = self.downgrade();
        writes::propose(
            self,
            Changeset {
                operations: changeset.operations,
                remarks: pv::remarks(&without),
            },
            Options {
                finished: Some(Box::new(move |report| {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.written(report);
                    }
                })),
                ..Options::default()
            },
        );
    }

    /// `_ecrit`: the preview closed without writing leaves the dialog open.
    fn written(&self, report: Option<&Report>) {
        if report.is_none() {
            return;
        }
        let finished = self.imp().finished.take();
        self.close();
        if let Some(finished) = finished {
            finished(report);
        }
    }

    /// Fills the dialog and continues (trials): name, precedence, minimum length, a target
    /// searched by `target` (the first result).
    pub fn trial(&self, name: Option<&str>, precedence: Option<i64>, min_length: Option<i64>) {
        let imp = self.imp();
        if let Some(name) = name {
            imp.name_entry.set_text(name);
        }
        if let Some(n) = precedence {
            imp.precedence.set_value(n as f64);
        }
        if let Some(n) = min_length {
            imp.minimum_length.set_value(n as f64);
        }
        self.proceed();
    }

    /// The problems shown (trials).
    pub fn trial_problems(&self) -> String {
        self.imp().problems.label().to_string()
    }
}

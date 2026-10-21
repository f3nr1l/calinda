// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « DNS health » window (J3.5, `annuaire.ui.sante_dns`). The structure lives in
//! `sante-dns.blp`.
//!
//! Opened from the DNS window (menu, Ctrl+D). It reads the state of the DNS on the PDC
//! emulator, through the write connection of the main window: the diagnosis and its fixes
//! see the same DC, without replication delay between the two. The diagnosis itself
//! (`dns_health::diagnose`, pure) runs off the thread of the interface; changing a setting
//! (thresholds, static A) makes it again without reading the directory.
//!
//! One row per anomaly, from the most severe to the least; the details of the one chosen
//! (explanation, records targeted, fix) below. « Fix » (button, Enter on a row) builds the
//! changeset of the anomalies chosen, read on the PDC, and proposes it through the common
//! preview: nothing is written without confirmation. After a write, the window reads and
//! diagnoses again, and the DNS window reads the names touched again. Read-only profile:
//! the diagnosis is complete, no fix is proposed.

use std::cell::Cell;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::changes::Report;
use annuaire_core::dns_health::{self, Anomaly, Diagnosis, DnsState, Settings};
use annuaire_core::dns_write;
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::errors;
use crate::health_views::{self as hv, AnomalyLine};
use crate::i18n::{fill, tr};
use crate::writes::{self, Options};

mod line {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::health_views::AnomalyLine;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::HealthLine)]
    pub struct HealthLine {
        #[property(name = "gravite", get = |l: &Self| l.view().severity.clone(), type = String)]
        #[property(name = "icone", get = |l: &Self| l.view().icon.clone(), type = String)]
        #[property(name = "regle", get = |l: &Self| l.view().rule.clone(), type = String)]
        #[property(name = "titre", get = |l: &Self| l.view().title.clone(), type = String)]
        #[property(name = "correction", get = |l: &Self| l.view().fix.clone(), type = String)]
        #[property(name = "accessible", get = |l: &Self| l.view().accessible.clone(), type = String)]
        pub view: OnceCell<AnomalyLine>,
    }

    impl HealthLine {
        pub fn view(&self) -> &AnomalyLine {
            self.view.get().expect("line built by HealthLine::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for HealthLine {
        const NAME: &'static str = "AnnuaireLigneSante";
        type Type = super::HealthLine;
    }

    #[glib::derived_properties]
    impl ObjectImpl for HealthLine {}
}

glib::wrapper! {
    /// A row of the table of the anomalies (`LigneSanteObjet`).
    pub struct HealthLine(ObjectSubclass<line::HealthLine>);
}

impl HealthLine {
    fn new(view: AnomalyLine) -> Self {
        let line: Self = glib::Object::new();
        let _ = line.imp().view.set(view);
        line
    }

    pub fn view(&self) -> &AnomalyLine {
        self.imp().view()
    }
}

mod imp {
    use std::cell::{Cell, RefCell};
    use std::collections::HashMap;

    use adw::subclass::prelude::*;
    use annuaire_core::dns_health::{Diagnosis, DnsState};
    use gtk::glib;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/sante-dns.ui")]
    pub struct HealthWindow {
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub fix_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub summary: TemplateChild<gtk::Label>,
        #[template_child]
        pub threshold: TemplateChild<gtk::SpinButton>,
        #[template_child]
        pub tombstone_threshold: TemplateChild<gtk::SpinButton>,
        #[template_child]
        pub static_records: TemplateChild<gtk::CheckButton>,
        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub table: TemplateChild<gtk::ColumnView>,
        #[template_child]
        pub selection: TemplateChild<gtk::MultiSelection>,
        #[template_child]
        pub store: TemplateChild<gtk::gio::ListStore>,
        #[template_child]
        pub details: TemplateChild<gtk::Label>,
        #[template_child]
        pub empty_page: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub write_state: TemplateChild<gtk::Label>,
        #[template_child]
        pub reading: TemplateChild<gtk::Label>,
        pub state: RefCell<Option<std::sync::Arc<DnsState>>>,
        pub diagnosis: RefCell<Option<Diagnosis>>,
        pub generation: Cell<u64>,
        pub actions: RefCell<HashMap<&'static str, gtk::gio::SimpleAction>>,
    }

    impl std::fmt::Debug for HealthWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HealthWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for HealthWindow {
        const NAME: &'static str = "AnnuaireSanteDns";
        type Type = super::HealthWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            <super::HealthLine as gtk::prelude::StaticTypeExt>::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::HealthWindow>(&[
                ("settings_changed", |w, _| {
                    w.diagnose();
                    None
                }),
                ("selection_changed", |w, _| {
                    w.chosen();
                    None
                }),
                ("activated", |w, args| {
                    if let Some(position) = args.get(1).and_then(|v| v.get::<u32>().ok()) {
                        w.row_activated(position);
                    }
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for HealthWindow {}
    impl WidgetImpl for HealthWindow {}

    impl WindowImpl for HealthWindow {
        fn close_request(&self) -> glib::Propagation {
            self.generation.set(self.generation.get() + 1);
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for HealthWindow {}
}

glib::wrapper! {
    /// The « DNS health » window (`AnnuaireSanteDns`).
    pub struct HealthWindow(ObjectSubclass<imp::HealthWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl HealthWindow {
    pub fn new(parent: &crate::dns::DnsWindow) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        window.install_actions();
        crate::a11y::name_menus(&window);
        if let Some(context) = window.context() {
            window.imp().title.set_subtitle(&context.profile.domain);
        }
        window.read();
        window
    }

    /// The one of the DNS window, so of the main window (connection to the PDC).
    fn context(&self) -> Option<Arc<writes::WriteContext>> {
        writes::context(self)
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    fn install_actions(&self) {
        let imp = self.imp();
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&HealthWindow);
        let actions: [(&'static str, Handler); 4] = [
            ("actualiser", Self::read),
            ("corriger", Self::fix),
            ("tout", Self::select_all),
            ("annuler", |w| crate::history::undo_last(w)),
        ];
        for (name, handler) in actions {
            let action = gio::SimpleAction::new(name, None);
            let weak = self.downgrade();
            action.connect_activate(move |_, _| {
                // The shortcuts do not count while a dialog is open (`_si_libre`).
                if let Some(window) = weak.upgrade().filter(|w| w.visible_dialog().is_none()) {
                    handler(&window);
                }
            });
            group.add_action(&action);
            imp.actions.borrow_mut().insert(name, action);
        }
        self.insert_action_group("sante", Some(&group));
        self.update_actions();

        // Escape in the capture phase: a toast shown (« Undo ») would take it otherwise.
        let escape = gtk::ShortcutController::new();
        escape.set_propagation_phase(gtk::PropagationPhase::Capture);
        let weak = self.downgrade();
        escape.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::CallbackAction::new(move |_, _| {
                let Some(window) = weak.upgrade() else {
                    return glib::Propagation::Proceed;
                };
                if window.visible_dialog().is_some() {
                    return glib::Propagation::Proceed;
                }
                window.close();
                glib::Propagation::Stop
            })),
        ));
        self.add_controller(escape);
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [("F5", "sante.actualiser"), ("<Control>z", "sante.annuler")] {
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::NamedAction::new(action)),
            ));
        }
        self.add_controller(shortcuts);
    }

    fn action(&self, name: &str) -> Option<gio::SimpleAction> {
        self.imp().actions.borrow().get(name).cloned()
    }

    // --- Reading and diagnosis ----------------------------------------------------------

    fn settings(&self) -> Settings {
        let imp = self.imp();
        Settings {
            days: i64::from(imp.threshold.value_as_int()),
            tombstone_days: i64::from(imp.tombstone_threshold.value_as_int()),
            statics: imp.static_records.is_active(),
        }
    }

    fn next_generation(&self) -> u64 {
        let imp = self.imp();
        imp.generation.set(imp.generation.get() + 1);
        imp.generation.get()
    }

    /// Reads the state of the DNS again on the PDC, then diagnoses (`lire`).
    fn read(&self) {
        let imp = self.imp();
        let generation = self.next_generation();
        let Some(context) = self.context() else {
            self.failed(&tr("No domain open"), "");
            return;
        };
        imp.stack.set_visible_child_name("chargement");
        imp.summary
            .set_label(&tr("Reading the zones on the controller…"));
        imp.reading.set_label("");
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let connection = context.connection.clone();
            let read = gio::spawn_blocking(move || dns_health::read_state(&connection)).await;
            let Some(window) = weak.upgrade() else { return };
            if generation != window.imp().generation.get() {
                return;
            }
            match read {
                Ok(Ok(state)) => {
                    *window.imp().state.borrow_mut() = Some(Arc::new(state));
                    window.diagnose();
                }
                Ok(Err(error)) => {
                    let domain = &context.profile.domain;
                    let problem = match &error {
                        dns_health::ReadError::Failure(f) => errors::failure_problem(f, domain),
                        dns_health::ReadError::Search(s) => errors::search_problem(s, domain),
                    };
                    window.failed(&problem.message, &problem.detail);
                }
                Err(_) => {}
            }
        });
    }

    /// Makes the diagnosis of the state read again, off the thread of the interface
    /// (`diagnostiquer`).
    fn diagnose(&self) {
        let Some(state) = self.imp().state.borrow().clone() else {
            return;
        };
        let generation = self.next_generation();
        let settings = self.settings();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let reading = state.clone();
            let made =
                gio::spawn_blocking(move || dns_health::diagnose(&reading, settings, None)).await;
            let Some(window) = weak.upgrade() else { return };
            if generation != window.imp().generation.get() {
                return;
            }
            if let Ok(diagnosis) = made {
                window.show(&state, diagnosis);
            }
        });
    }

    fn failed(&self, title: &str, detail: &str) {
        let imp = self.imp();
        imp.error.set_title(title);
        imp.error.set_description(Some(detail));
        imp.summary.set_label("");
        imp.stack.set_visible_child_name("erreur");
        self.update_actions();
    }

    fn show(&self, state: &DnsState, diagnosis: Diagnosis) {
        let imp = self.imp();
        let lines: Vec<HealthLine> = diagnosis
            .anomalies
            .iter()
            .map(|a| HealthLine::new(hv::line(a)))
            .collect();
        imp.store.remove_all();
        imp.store.extend_from_slice(&lines);
        imp.selection.unselect_all();
        imp.summary.set_label(&hv::summary(&diagnosis));
        imp.reading
            .set_label(&hv::read_text(&state.dc, state.read_at));
        if lines.is_empty() {
            imp.empty_page
                .set_description(Some(&hv::summary(&diagnosis)));
            imp.stack.set_visible_child_name("vide");
        } else {
            imp.details
                .set_label(&tr("Choose an issue to read its details."));
            imp.stack.set_visible_child_name("table");
        }
        *imp.diagnosis.borrow_mut() = Some(diagnosis);
        self.update_actions();
    }

    // --- Choice and fixes ---------------------------------------------------------------

    fn chosen_anomalies(&self) -> Vec<Anomaly> {
        let imp = self.imp();
        (0..imp.store.n_items())
            .filter(|&i| imp.selection.is_selected(i))
            .filter_map(|i| imp.store.item(i).and_downcast::<HealthLine>())
            .map(|l| l.view().anomaly.clone())
            .collect()
    }

    /// `selection_changed`.
    fn chosen(&self) {
        let imp = self.imp();
        let chosen = self.chosen_anomalies();
        match chosen.as_slice() {
            [only] => imp.details.set_label(&hv::details(only)),
            [] if imp.store.n_items() > 0 => imp
                .details
                .set_label(&tr("Choose an issue to read its details.")),
            [] => {}
            several => {
                let fixable = several.iter().filter(|a| a.fix.is_some()).count();
                imp.details.set_label(&fill(
                    &tr("{n} issues selected, {c} of them with a proposed fix."),
                    &[
                        ("n", &several.len().to_string()),
                        ("c", &fixable.to_string()),
                    ],
                ));
            }
        }
        self.update_actions();
    }

    fn writing_possible(&self) -> bool {
        self.context().is_some_and(|c| !c.profile.read_only)
    }

    /// `_mettre_a_jour_actions`.
    fn update_actions(&self) {
        let imp = self.imp();
        let possible = self.writing_possible();
        let chosen = self.chosen_anomalies();
        let fixable = chosen.iter().any(|a| a.fix.is_some());
        for (name, enabled) in [
            ("corriger", possible && fixable),
            ("tout", imp.store.n_items() > 0),
            ("annuler", possible),
        ] {
            if let Some(action) = self.action(name) {
                action.set_enabled(enabled);
            }
        }
        imp.fix_button.set_label(&hv::fix_button(&chosen));
        let text = if !possible {
            Some(tr("Read-only profile: diagnosis only, no fix."))
        } else if !chosen.is_empty() && !fixable {
            Some(tr(
                "No automatic fix for this selection: to be done by hand.",
            ))
        } else {
            None
        };
        imp.write_state.set_visible(text.is_some());
        if let Some(text) = text {
            imp.write_state.set_label(&text);
        }
    }

    fn select_all(&self) {
        let imp = self.imp();
        imp.selection.select_all();
        imp.table.grab_focus();
    }

    /// `activated`: Enter on a row fixes what is chosen.
    fn row_activated(&self, position: u32) {
        let imp = self.imp();
        if !imp.selection.is_selected(position) {
            imp.selection.select_item(position, true);
        }
        if self.action("corriger").is_some_and(|a| a.is_enabled()) {
            self.fix();
        }
    }

    fn fix(&self) {
        let anomalies: Vec<Anomaly> = self
            .chosen_anomalies()
            .into_iter()
            .filter(|a| a.fix.is_some())
            .collect();
        let Some(context) = self.context() else {
            return;
        };
        if anomalies.is_empty() || !self.writing_possible() {
            return;
        }
        let requests = dns_health::requests(&anomalies);
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let (connection, asked) = (context.connection.clone(), requests.clone());
            let built = gio::spawn_blocking(move || {
                dns_write::build(&connection, asked, Arc::new(AppCatalog))
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            match built {
                Ok(Ok(changeset)) => {
                    writes::propose(
                        &window,
                        changeset,
                        Options {
                            retry: Some(dns_write::rebuild(requests, Arc::new(AppCatalog))),
                            ..Options::default()
                        },
                    );
                }
                Ok(Err(error)) => {
                    let (message, detail) =
                        crate::dns::prepare_message(&error, &context.profile.domain);
                    writes::show_error(&window, &tr("Cannot fix"), &message, &detail);
                }
                Err(_) => {}
            }
        });
    }

    /// Reads and diagnoses again; the DNS window reads the names touched again
    /// (`apres_ecriture`).
    pub fn after_write(&self, report: &Report) {
        if let Some(dns) = self.transient_for().and_downcast::<crate::dns::DnsWindow>() {
            dns.after_write(report);
        }
        self.read();
    }

    /// Selects the anomalies whose title contains `text` (trials); their number.
    pub fn trial_select(&self, text: &str) -> u32 {
        let imp = self.imp();
        imp.selection.unselect_all();
        let selected = Cell::new(0);
        for i in 0..imp.store.n_items() {
            let matches = imp
                .store
                .item(i)
                .and_downcast::<HealthLine>()
                .is_some_and(|l| l.view().title.contains(text));
            if matches {
                imp.selection.select_item(i, false);
                selected.set(selected.get() + 1);
            }
        }
        selected.get()
    }

    /// Clicks « Fix » (trials).
    pub fn trial_fix(&self) -> bool {
        let enabled = self.action("corriger").is_some_and(|a| a.is_enabled());
        if enabled {
            self.fix();
        }
        enabled
    }

    /// The summary shown (trials).
    pub fn trial_summary(&self) -> String {
        self.imp().summary.label().to_string()
    }

    /// Each row with its details, as shown (trials: comparison with the Python window).
    pub fn trial_lines(&self) -> Vec<String> {
        let imp = self.imp();
        (0..imp.store.n_items())
            .filter_map(|i| imp.store.item(i).and_downcast::<HealthLine>())
            .map(|l| {
                let v = l.view();
                format!(
                    "{} | {} | {} | {}\n{}",
                    v.severity,
                    v.rule,
                    v.title,
                    v.fix,
                    hv::details(&v.anomaly)
                )
            })
            .collect()
    }
}

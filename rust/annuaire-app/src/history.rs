// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! History of the changes, Ctrl+Z and resuming at the start (J2.7, J2.9,
//! `annuaire.ui.historique`, `annuer_derniere` of `annuaire.ui.clavier`).
//!
//! The history reads the local journal (`writer::read_journal`) and lists the applications of
//! the open domain, from the most recent to the oldest; « Undo this change » proposes the
//! inverse of what stays applied (`changes::inverse`) through the common preview, with
//! `resumes`: the application undone is then marked resumed and no longer offered. Structure
//! in `historique.blp`. Ctrl+Z proposes the inverse of the last change that can be undone.
//!
//! When a domain opens, `propose_resume` looks for the applications interrupted by an abrupt
//! stop or left incomplete (`to_resume`), reads the directory to settle the doubtful
//! operations (`ascertain`), then proposes to undo (`inverse`) or to complete
//! (`continuation`); each choice goes through the preview.

use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::changes::{self, Report};
use annuaire_core::writer;
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::errors;
use crate::i18n::{fill, tr};
use crate::preview_views::{self as pv, HistoryEntry};
use crate::writes::{self, Options, WriteContext};

// --- Entry of the list ---------------------------------------------------------------------

mod entry {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::preview_views::HistoryEntry;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::Entry)]
    pub struct Entry {
        #[property(name = "titre", get = |e: &Self| e.view().title.clone(), type = String)]
        #[property(name = "sous-titre", get = |e: &Self| e.view().subtitle.clone(), type = String)]
        pub view: OnceCell<HistoryEntry>,
    }

    impl Entry {
        pub fn view(&self) -> &HistoryEntry {
            self.view.get().expect("entry built by Entry::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Entry {
        const NAME: &'static str = "AnnuaireEntreeHistorique";
        type Type = super::Entry;
    }

    #[glib::derived_properties]
    impl ObjectImpl for Entry {}
}

glib::wrapper! {
    /// An application of the journal (`EntreeHistoriqueObjet`).
    pub struct Entry(ObjectSubclass<entry::Entry>);
}

impl Entry {
    pub fn new(view: HistoryEntry) -> Self {
        let entry: Self = glib::Object::new();
        let _ = entry.imp().view.set(view);
        entry
    }

    pub fn view(&self) -> &HistoryEntry {
        self.imp().view()
    }
}

// --- Dialog --------------------------------------------------------------------------------

mod imp {
    use std::cell::{OnceCell, RefCell};
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_core::changes::Report;
    use gtk::glib;

    use crate::scope::TemplateScope;
    use crate::writes::WriteContext;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/historique.ui")]
    pub struct HistoryDialog {
        #[template_child]
        pub undo_change_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub store: TemplateChild<gtk::gio::ListStore>,
        #[template_child]
        pub detail: TemplateChild<gtk::Label>,
        pub context: OnceCell<Arc<WriteContext>>,
        pub reports: RefCell<Vec<Report>>,
    }

    impl std::fmt::Debug for HistoryDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("HistoryDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for HistoryDialog {
        const NAME: &'static str = "AnnuaireDialogueHistorique";
        type Type = super::HistoryDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            <super::Entry as gtk::prelude::StaticTypeExt>::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::HistoryDialog>(&[
                ("reload", |d, _| {
                    d.read();
                    None
                }),
                ("selected", |d, _| {
                    d.chosen();
                    None
                }),
                ("undo_change", |d, _| {
                    d.undo();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for HistoryDialog {}
    impl WidgetImpl for HistoryDialog {}
    impl AdwDialogImpl for HistoryDialog {}
}

glib::wrapper! {
    /// History of the changes of the open domain (`AnnuaireDialogueHistorique`).
    pub struct HistoryDialog(ObjectSubclass<imp::HistoryDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl HistoryDialog {
    pub fn new(context: Arc<WriteContext>) -> Self {
        let dialog: Self = glib::Object::new();
        let _ = dialog.imp().context.set(context);
        dialog.read();
        dialog
    }

    fn context(&self) -> &Arc<WriteContext> {
        self.imp().context.get().expect("set by new")
    }

    /// `reload`.
    fn read(&self) {
        let imp = self.imp();
        let context = self.context().clone();
        let reports = writer::read_journal(&context.journal);
        let entries = pv::history_entries(&reports, &context.profile.domain);
        *imp.reports.borrow_mut() = reports;
        imp.store.remove_all();
        let objects: Vec<glib::Object> = entries
            .into_iter()
            .map(|e| Entry::new(e).upcast())
            .collect();
        imp.store.splice(0, 0, &objects);
        imp.stack
            .set_visible_child_name(if objects.is_empty() { "vide" } else { "liste" });
        self.chosen();
    }

    fn entry(&self) -> Option<HistoryEntry> {
        self.imp()
            .selection
            .selected_item()
            .and_downcast::<Entry>()
            .map(|e| e.view().clone())
    }

    /// `selected`.
    fn chosen(&self) {
        let imp = self.imp();
        let entry = self.entry();
        imp.detail
            .set_label(entry.as_ref().map_or("", |e| e.detail.as_str()));
        imp.undo_change_button
            .set_sensitive(entry.is_some_and(|e| e.undoable));
    }

    /// `undo_change`.
    fn undo(&self) {
        let Some(entry) = self.entry() else { return };
        let reports = self.imp().reports.borrow().clone();
        let Some(report) = reports.iter().find(|r| r.id == entry.id) else {
            return;
        };
        let Some(inverse) = pv::inverse(report, &reports) else {
            return;
        };
        let weak = self.downgrade();
        writes::propose(
            self,
            inverse,
            Options {
                resumes: Some(report.id.clone()),
                finished: Some(Box::new(move |_| {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.read();
                    }
                })),
                ..Options::default()
            },
        );
    }

    /// Selects the first entry and undoes it (trials).
    pub fn trial_undo_first(&self) -> bool {
        self.imp().selection.set_selected(0);
        let undoable = self.entry().is_some_and(|e| e.undoable);
        if undoable {
            self.undo();
        }
        undoable
    }
}

// --- Ctrl+Z ---------------------------------------------------------------------------------

/// Proposes the inverse of the last change of the open domain (`annuler_derniere`), from any
/// window of the domain (the main window, the DNS window, its health window).
pub fn undo_last(window: &impl IsA<gtk::Widget>) {
    let Some(context) = writes::context(window) else {
        return;
    };
    let reports = writer::read_journal(&context.journal);
    let Some(report) = pv::last_undoable(&reports, &context.profile.domain) else {
        writes::announce(window, &tr("No change to undo."), None);
        return;
    };
    writes::announce(
        window,
        &fill(
            &tr("Undo of “{titre}”"),
            &[("titre", &pv::changeset_title(&report.changeset))],
        ),
        None,
    );
    // The whole journal: an object already brought back by a previous Ctrl+Z is expected in
    // the version this one left (ADR 0006 § 5.1).
    let Some(inverse) = pv::inverse(report, &reports) else {
        return;
    };
    writes::propose(
        window,
        inverse,
        Options {
            resumes: Some(report.id.clone()),
            ..Options::default()
        },
    );
}

// --- Resuming at the start -----------------------------------------------------------------

/// Applications to settle (abrupt stop, incomplete rollback): undo or complete
/// (`proposer_reprise`).
pub fn propose_resume(window: &crate::window::Window) {
    let Some(context) = window.write_context() else {
        return;
    };
    let weak = window.downgrade();
    glib::spawn_future_local(async move {
        let for_reading = context.clone();
        let settled = gio::spawn_blocking(move || {
            let domain = for_reading.profile.domain.clone();
            let first = writer::to_resume(&for_reading.journal)
                .into_iter()
                .find(|r| r.domain == domain)?;
            Some(writer::ascertain(&for_reading.connection, &first))
        })
        .await;
        let (Some(window), Ok(Some(settled))) = (weak.upgrade(), settled) else {
            return;
        };
        match settled {
            Ok(report) => ask(&window, report),
            Err(failure) => {
                let problem = errors::failure_problem(&failure, &context.profile.domain);
                writes::show_error(
                    &window,
                    &tr("Cannot resume"),
                    &problem.message,
                    &problem.detail,
                );
            }
        }
    });
}

/// `_demander`.
fn ask(window: &crate::window::Window, report: Report) {
    let complete = changes::continuation(&report)
        .ok()
        .filter(|c| !c.operations.is_empty());
    let body = format!(
        "{}\n\n{}",
        pv::describe(&report, &[]),
        fill(
            &tr("Started on {date} on {dc}."),
            &[("date", &report.timestamp), ("dc", &report.dc)],
        )
    );
    let alert = adw::AlertDialog::new(
        Some(&fill(
            &tr("Change to settle: {titre}"),
            &[("titre", &pv::changeset_title(&report.changeset))],
        )),
        Some(&body),
    );
    alert.add_response("plus-tard", &tr("Later"));
    alert.add_response("annuler", &tr("Undo what was done"));
    alert.set_response_appearance("annuler", adw::ResponseAppearance::Destructive);
    if complete.is_some() {
        alert.add_response("terminer", &tr("Complete"));
        alert.set_response_appearance("terminer", adw::ResponseAppearance::Suggested);
    }
    alert.set_close_response("plus-tard");
    let weak = window.downgrade();
    alert.connect_response(None, move |_, response| {
        let Some(window) = weak.upgrade() else { return };
        let changeset = match response {
            "annuler" => changes::inverse(&report, &[], &AppCatalog).ok(),
            "terminer" => complete.clone(),
            _ => None,
        };
        if let Some(changeset) = changeset {
            writes::propose(
                &window,
                changeset,
                Options {
                    resumes: Some(report.id.clone()),
                    ..Options::default()
                },
            );
        }
    });
    alert.present(Some(window));
}

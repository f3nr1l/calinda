// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The only door of the interface to the writes (J2.7, plan 0.1, `annuaire.ui.ecrire`):
//! preview, confirmation, report. `propose(widget, changeset)` checks the changeset (prior
//! verification, J1.10), shows the preview (table object / attribute / before / after,
//! problems found, read-only that blocks), applies it on confirmation, then announces the
//! result: a toast with « Undo » if everything is applied, an error dialog otherwise.
//! Structure of the dialog in `apercu.blp`.
//!
//! Where to write: the window of the open domain keeps a `WriteContext` (connection to the
//! PDC emulator, distinct from the source of the readings, and the local journal), found from
//! any widget of the window by its root. The operations of a changeset carry a `Read` (DC,
//! `uSNChanged`) that only compares on the same DC (ADR 0006, 2): the versions are read
//! through `WriteContext::connection`, not through the source.

use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::changes::{Changeset, Issue, Report};
use annuaire_core::connection::Connection;
use annuaire_core::dns_write;
use annuaire_core::journal::Journal;
use annuaire_core::profile::Profile;
use annuaire_core::security;
use annuaire_core::writer::{self, ApplyError, Outcome, Problem};
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::errors;
use crate::i18n::{fill, tr};
use crate::preview_views::{self as pv, PreviewLine};

/// What writing in a domain needs: connection to the PDC and local journal
/// (`ContexteEcriture`).
#[derive(Debug)]
pub struct WriteContext {
    pub profile: Profile,
    pub connection: Arc<Connection>,
    pub journal: Arc<Journal>,
}

impl WriteContext {
    pub fn new(profile: Profile) -> Self {
        Self {
            connection: Arc::new(annuaire_core::source::pdc_connection(&profile)),
            journal: Arc::new(Journal::new(
                None,
                annuaire_core::journal::MAX_SIZE,
                annuaire_core::journal::ARCHIVES,
            )),
            profile,
        }
    }

    pub fn close(&self) {
        self.connection.close();
    }
}

/// The write context of the window that holds `widget` (None without an open domain)
/// (`contexte`): the one of the main window, reached through the windows a window is
/// transient for (the DNS window, its health window).
pub fn context(widget: &impl IsA<gtk::Widget>) -> Option<Arc<WriteContext>> {
    let mut window = widget.root().and_downcast::<gtk::Window>();
    while let Some(w) = window {
        if let Some(main) = w.downcast_ref::<crate::window::Window>() {
            return main.write_context();
        }
        window = w.transient_for();
    }
    None
}

/// What reads again after a write: the window of `host` (`apres_ecriture` of the root).
fn after_write(host: &gtk::Widget, report: &Report) {
    let Some(root) = host.root() else { return };
    if let Some(w) = root.downcast_ref::<crate::window::Window>() {
        w.after_write(report);
    } else if let Some(w) = root.downcast_ref::<crate::dns::DnsWindow>() {
        w.after_write(report);
    } else if let Some(w) = root.downcast_ref::<crate::dns_health::HealthWindow>() {
        w.after_write(report);
    } else if let Some(w) = root.downcast_ref::<crate::gpo::GpoWindow>() {
        w.after_write(report);
    } else if let Some(w) = root.downcast_ref::<crate::pso::PsoWindow>() {
        w.after_write(report);
    } else if let Some(w) = root.downcast_ref::<crate::gpo_editor::GpoEditor>() {
        w.after_write(report);
    }
}

/// What follows the application: the report, or None if nothing was tried.
pub type Finished = Box<dyn FnOnce(Option<&Report>)>;

// --- Messages (J2.8) --------------------------------------------------------------------------

/// Error dialog: the clear sentence, and the technical detail folded (`montrer_erreur`).
pub fn show_error(parent: &impl IsA<gtk::Widget>, title: &str, text: &str, detail: &str) {
    let alert = adw::AlertDialog::new(Some(title), Some(text));
    if !detail.is_empty() {
        let view = gtk::Label::builder()
            .label(detail)
            .xalign(0.0)
            .wrap(true)
            .selectable(true)
            .build();
        view.add_css_class("monospace");
        let expander = gtk::Expander::builder()
            .label(tr("Technical details"))
            .child(&view)
            .build();
        alert.set_extra_child(Some(&expander));
    }
    alert.add_response("fermer", &tr("Close"));
    alert.present(Some(parent.as_ref()));
}

/// Toast of the window; with an « Undo » button if `undo` is given (`annoncer`).
pub fn announce(parent: &impl IsA<gtk::Widget>, text: &str, undo: Option<Box<dyn Fn()>>) {
    let Some(root) = parent.root() else { return };
    let toast = adw::Toast::new(text);
    toast.set_timeout(if undo.is_some() { 8 } else { 4 });
    if let Some(undo) = undo {
        toast.set_button_label(Some(&tr("Cancel")));
        toast.connect_button_clicked(move |_| undo());
    }
    if let Some(w) = root.downcast_ref::<crate::window::Window>() {
        w.add_toast(toast);
    } else if let Some(w) = root.downcast_ref::<crate::dns::DnsWindow>() {
        w.add_toast(toast);
    } else if let Some(w) = root.downcast_ref::<crate::dns_health::HealthWindow>() {
        w.add_toast(toast);
    } else if let Some(w) = root.downcast_ref::<crate::gpo::GpoWindow>() {
        w.add_toast(toast);
    } else if let Some(w) = root.downcast_ref::<crate::pso::PsoWindow>() {
        w.add_toast(toast);
    } else if let Some(w) = root.downcast_ref::<crate::gpo_editor::GpoEditor>() {
        w.add_toast(toast);
    }
}

/// Toast if everything is applied (with « Undo »), error dialog otherwise
/// (`signaler_bilan`).
pub fn signal_report(parent: &gtk::Widget, outcome: &Outcome) {
    let report = &outcome.report;
    if report.issue == Issue::Applied {
        let inverse = pv::inverse(report, &[]);
        let (weak, id) = (parent.downgrade(), report.id.clone());
        announce(
            parent,
            &fill(
                &tr("Change applied ({n} operation(s))."),
                &[("n", &report.changeset.operations.len().to_string())],
            ),
            inverse.map(|changeset| -> Box<dyn Fn()> {
                Box::new(move || {
                    if let Some(parent) = weak.upgrade() {
                        propose(
                            &parent,
                            changeset.clone(),
                            Options {
                                resumes: Some(id.clone()),
                                ..Options::default()
                            },
                        );
                    }
                })
            }),
        );
        return;
    }
    let title = match report.issue {
        Issue::Refused => tr("Change refused, nothing was written"),
        Issue::Cancelled => tr("Change undone, the directory is back to its previous state"),
        Issue::Incomplete => tr("Incomplete change"),
        _ => tr("Interrupted change"),
    };
    let detail = report
        .error
        .as_ref()
        .map(|e| e.detail.clone())
        .unwrap_or_default();
    show_error(
        parent,
        &title,
        &pv::describe(report, &outcome.problems),
        &detail,
    );
}

// --- Preview ----------------------------------------------------------------------------------

mod line {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::preview_views::PreviewLine;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::Line)]
    pub struct Line {
        #[property(name = "objet", get = |l: &Self| l.view().object.clone(), type = String)]
        #[property(name = "action", get = |l: &Self| l.view().action.clone(), type = String)]
        #[property(name = "attribut", get = |l: &Self| l.view().attribute.clone(), type = String)]
        #[property(name = "avant", get = |l: &Self| l.view().before.clone(), type = String)]
        #[property(name = "apres", get = |l: &Self| l.view().after.clone(), type = String)]
        pub view: OnceCell<PreviewLine>,
    }

    impl Line {
        pub fn view(&self) -> &PreviewLine {
            self.view.get().expect("line built by Line::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Line {
        const NAME: &'static str = "AnnuaireLigneApercu";
        type Type = super::Line;
    }

    #[glib::derived_properties]
    impl ObjectImpl for Line {}
}

glib::wrapper! {
    /// A row of the preview table (`LigneApercuObjet`).
    pub struct Line(ObjectSubclass<line::Line>);
}

impl Line {
    fn new(view: PreviewLine) -> Self {
        let line: Self = glib::Object::new();
        let _ = line.imp().view.set(view);
        line
    }
}

fn objects(lines: Vec<PreviewLine>) -> Vec<glib::Object> {
    lines.into_iter().map(|l| Line::new(l).upcast()).collect()
}

/// How a changeset is proposed.
#[derive(Default)]
pub struct Options {
    /// Identifier of the application of the journal this one undoes or finishes.
    pub resumes: Option<String>,
    pub title: Option<String>,
    pub label: Option<String>,
    pub destructive: bool,
    pub finished: Option<Finished>,
    /// New attempt after a conflict (DNS: the serial number of the SOA overtaken by another
    /// write). A DNS changeset proposed without it (undo, resume) gets its increment of the
    /// SOA read on the DC first: the inverse of an increment would lower the serial number.
    pub retry: Option<writer::Retry>,
}

mod imp {
    use std::cell::{OnceCell, RefCell};
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_core::changes::Changeset;
    use gtk::glib;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/apercu.ui")]
    pub struct PreviewDialog {
        #[template_child]
        pub cancel_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub apply_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub button_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub apply_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub summary: TemplateChild<gtk::Label>,
        #[template_child]
        pub check_spinner: TemplateChild<gtk::Spinner>,
        #[template_child]
        pub check_state: TemplateChild<gtk::Label>,
        #[template_child]
        pub problems: TemplateChild<gtk::Label>,
        #[template_child]
        pub warnings: TemplateChild<gtk::Label>,
        #[template_child]
        pub store: TemplateChild<gtk::gio::ListStore>,
        pub context: OnceCell<Arc<super::WriteContext>>,
        pub changeset: OnceCell<Changeset>,
        pub resumes: RefCell<Option<String>>,
        pub finished: RefCell<Option<super::Finished>>,
        pub retry: RefCell<Option<annuaire_core::writer::Retry>>,
        /// Where the messages after go: the window (the parent may be a dialog closed since).
        pub host: RefCell<Option<gtk::Widget>>,
    }

    impl std::fmt::Debug for PreviewDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PreviewDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PreviewDialog {
        const NAME: &'static str = "AnnuaireDialogueApercu";
        type Type = super::PreviewDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            <super::Line as gtk::prelude::StaticTypeExt>::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PreviewDialog>(&[
                ("cancel", |d, _| {
                    adw::prelude::AdwDialogExt::close(d);
                    None
                }),
                ("apply", |d, _| {
                    d.apply();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PreviewDialog {}
    impl WidgetImpl for PreviewDialog {}

    impl AdwDialogImpl for PreviewDialog {
        fn closed(&self) {
            // Closed without applying: the caller learns it too.
            if let Some(finished) = self.finished.take() {
                finished(None);
            }
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// Preview of a changeset, prior verification, confirmation and application
    /// (`AnnuaireDialogueApercu`).
    pub struct PreviewDialog(ObjectSubclass<imp::PreviewDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl PreviewDialog {
    fn new(context: Arc<WriteContext>, changeset: Changeset, options: Options) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        if let Some(title) = &options.title {
            dialog.set_title(title);
        }
        if let Some(label) = &options.label {
            imp.apply_label.set_label(label);
        }
        if options.destructive {
            imp.apply_button.remove_css_class("suggested-action");
            imp.apply_button.add_css_class("destructive-action");
        }
        imp.store
            .splice(0, 0, &objects(pv::lines(&changeset, None)));
        imp.summary.set_label(&pv::summary(&changeset));
        let warnings = pv::warnings(&changeset);
        if !warnings.is_empty() {
            imp.warnings.set_label(&warnings.join("\n"));
            imp.warnings.set_visible(true);
        }
        if context.profile.read_only {
            imp.banner.set_title(&tr(
                "Read-only profile: no write possible. Edit the profile to write.",
            ));
            imp.banner.set_revealed(true);
        }
        *imp.resumes.borrow_mut() = options.resumes;
        *imp.finished.borrow_mut() = options.finished;
        *imp.retry.borrow_mut() = options.retry;
        dialog.name_sids(&context, &changeset);
        dialog.verify(&context, &changeset);
        let _ = imp.context.set(context);
        let _ = imp.changeset.set(changeset);
        dialog
    }

    /// Delegates and other SIDs of the ACEs: named once the directory answered (J4.2).
    fn name_sids(&self, context: &Arc<WriteContext>, changeset: &Changeset) {
        let sids = pv::quoted_sids(changeset);
        if sids.is_empty() {
            return;
        }
        let (connection, weak, changeset) = (
            context.connection.clone(),
            self.downgrade(),
            changeset.clone(),
        );
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || security::name_sids(&connection, sids)).await;
            let (Some(dialog), Ok(Ok(names))) = (weak.upgrade(), read) else {
                return; // the SIDs stay as they are
            };
            let store = &dialog.imp().store;
            store.splice(
                0,
                store.n_items(),
                &objects(pv::lines(&changeset, Some(&names))),
            );
        });
    }

    fn verify(&self, context: &Arc<WriteContext>, changeset: &Changeset) {
        let (connection, weak, changeset) = (
            context.connection.clone(),
            self.downgrade(),
            changeset.clone(),
        );
        let domain = context.profile.domain.clone();
        glib::spawn_future_local(async move {
            let checking = connection.clone();
            let read = gio::spawn_blocking(move || {
                writer::verify(&checking, &changeset, Arc::new(AppCatalog))
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            let imp = dialog.imp();
            imp.check_spinner.set_spinning(false);
            imp.check_spinner.set_visible(false);
            let problems = match read {
                Ok(Ok(problems)) => problems,
                Ok(Err(failure)) => {
                    imp.check_state.set_label(&fill(
                        &tr("Check not possible: {message}"),
                        &[(
                            "message",
                            &errors::failure_problem(&failure, &domain).message,
                        )],
                    ));
                    return;
                }
                Err(_) => return,
            };
            let dc = connection
                .state()
                .map_or_else(|| "?".to_owned(), |s| s.dc.clone());
            dialog.verified(&problems, &dc);
        });
    }

    fn verified(&self, problems: &[Problem], dc: &str) {
        let imp = self.imp();
        if !problems.is_empty() {
            imp.check_state.set_label(&fill(
                &tr("The check on {dc} found problems: nothing will be written."),
                &[("dc", dc)],
            ));
            imp.problems.set_label(
                &problems
                    .iter()
                    .map(pv::problem_text)
                    .collect::<Vec<_>>()
                    .join("\n"),
            );
            imp.problems.set_visible(true);
            return;
        }
        imp.check_state
            .set_label(&fill(&tr("Check passed. Writing on {dc}."), &[("dc", dc)]));
        let read_only = imp.context.get().is_none_or(|c| c.profile.read_only);
        if !read_only {
            imp.apply_button.set_sensitive(true);
            imp.apply_button.grab_focus();
        }
    }

    /// Shows the dialog over `parent`; the messages after go to its window (`presenter`).
    pub fn show(&self, parent: &impl IsA<gtk::Widget>) {
        let host = parent
            .root()
            .and_then(|r| r.dynamic_cast::<gtk::Widget>().ok())
            .unwrap_or_else(|| parent.as_ref().clone());
        *self.imp().host.borrow_mut() = Some(host);
        self.present(Some(parent.as_ref()));
    }

    fn apply(&self) {
        let imp = self.imp();
        let (Some(context), Some(changeset)) =
            (imp.context.get().cloned(), imp.changeset.get().cloned())
        else {
            return;
        };
        imp.apply_button.set_sensitive(false);
        imp.cancel_button.set_sensitive(false);
        imp.button_stack.set_visible_child_name("attente");
        self.set_can_close(false);
        let resumes = imp.resumes.borrow().clone();
        let retry = imp.retry.take();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let applying = context.clone();
            let result = gio::spawn_blocking(move || {
                writer::apply(
                    &applying.connection,
                    &applying.profile,
                    &changeset,
                    applying.journal.clone(),
                    Arc::new(AppCatalog),
                    resumes,
                    retry,
                )
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            match result {
                Ok(result) => dialog.done(result, &context.profile.domain),
                Err(_) => dialog.done(
                    Err(ApplyError::Record(annuaire_core::changes::ErrorRecord {
                        class: String::new(),
                        message: tr("Change not applied"),
                        detail: String::new(),
                    })),
                    &context.profile.domain,
                ),
            }
        });
    }

    fn done(&self, result: Result<Outcome, ApplyError>, domain: &str) {
        let imp = self.imp();
        let host = imp
            .host
            .borrow()
            .clone()
            .unwrap_or_else(|| self.clone().upcast());
        self.set_can_close(true);
        let finished = imp.finished.take();
        self.close();
        match &result {
            Err(ApplyError::Failure(failure)) => {
                let problem = errors::failure_problem(failure, domain);
                show_error(
                    &host,
                    &tr("Change not applied"),
                    &problem.message,
                    &problem.detail,
                );
            }
            Err(ApplyError::Record(record)) => {
                show_error(
                    &host,
                    &tr("Change not applied"),
                    &record.message,
                    &record.detail,
                );
            }
            Ok(outcome) => {
                if std::env::var_os("ANNUAIRE_ESSAI_ACTION").is_some()
                    || std::env::var_os("ANNUAIRE_ESSAI_DNS").is_some()
                {
                    eprintln!(
                        "essai bilan : {}",
                        pv::describe(&outcome.report, &outcome.problems).replace('\n', " | ")
                    );
                }
                signal_report(&host, outcome);
                // The window reads again what may have changed (table, tree).
                if outcome.report.issue != Issue::Refused {
                    after_write(&host, &outcome.report);
                }
            }
        }
        if let Some(finished) = finished {
            finished(result.as_ref().ok().map(|o| &o.report));
        }
    }

    /// Clicks « Apply » once the verification passed (trials).
    pub fn trial_apply(&self) -> bool {
        let imp = self.imp();
        if !imp.apply_button.is_sensitive() {
            return false;
        }
        self.apply();
        true
    }

    /// The verification state and its problems (trials).
    pub fn trial_problems(&self) -> String {
        let imp = self.imp();
        format!("{} | {}", imp.check_state.label(), imp.problems.label())
    }

    /// The verification is over (trials).
    pub fn trial_verified(&self) -> bool {
        !self.imp().check_spinner.is_visible()
    }
}

/// Checks, shows the preview, applies on confirmation, announces the result (`proposer`).
/// `options.finished` gets the report, or None if nothing was tried.
pub fn propose(
    parent: &impl IsA<gtk::Widget>,
    changeset: Changeset,
    mut options: Options,
) -> Option<PreviewDialog> {
    let finished = options.finished.take();
    let Some(context) = context(parent) else {
        show_error(parent, &tr("Cannot write"), &tr("No domain is open."), "");
        if let Some(finished) = finished {
            finished(None);
        }
        return None;
    };
    if changeset.operations.is_empty() {
        announce(parent, &tr("No change."), None);
        if let Some(finished) = finished {
            finished(None);
        }
        return None;
    }
    options.finished = finished;
    if options.retry.is_none() && dns_write::touches_dns(&changeset) {
        propose_dns(parent, context, changeset, options);
        return None;
    }
    let dialog = PreviewDialog::new(context, changeset, options);
    dialog.show(parent);
    Some(dialog)
}

/// DNS changeset come from the journal (undo, resume): SOA read before the preview
/// (`_proposer_dns`).
fn propose_dns(
    parent: &impl IsA<gtk::Widget>,
    context: Arc<WriteContext>,
    changeset: Changeset,
    mut options: Options,
) {
    let weak = parent.as_ref().downgrade();
    glib::spawn_future_local(async move {
        let (connection, read) = (context.connection.clone(), changeset.clone());
        let refreshed = gio::spawn_blocking(move || {
            dns_write::refresh_soa(&connection, read, Arc::new(AppCatalog))
        })
        .await;
        let Some(parent) = weak.upgrade() else { return };
        let up_to_date = match refreshed {
            Ok(Ok(up_to_date)) => up_to_date,
            Ok(Err(error)) => {
                let (message, detail) =
                    crate::dns::prepare_message(&error, &context.profile.domain);
                show_error(&parent, &tr("Change not proposed"), &message, &detail);
                if let Some(finished) = options.finished.take() {
                    finished(None);
                }
                return;
            }
            Err(_) => return,
        };
        options.retry = Some(dns_write::soa_up_to_date(changeset, Arc::new(AppCatalog)));
        PreviewDialog::new(context, up_to_date, options).show(&parent);
    });
}

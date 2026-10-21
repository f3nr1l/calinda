// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Group Policy » window (J5.2, `annuaire.ui.gpo`), and its writes (J5.3 to J5.6,
//! `annuaire.ui.actions_gpo`). The structure lives in `gpo.blp`.
//!
//! On the left, « Group Policy Objects » (every GPO) then the domain, its OUs and, under each
//! container, its linked GPOs in the order of the links (`gpo_views::tree`); on the right, the
//! detail of the chosen node: for a GPO, state, directory and SYSVOL versions (the deviation
//! said plainly), links, security filtering; for a container, its links and the inheritance
//! blocked. If the SYSVOL of the PDC shows some, « Inconsistencies » gathers the folders
//! without a GPO object (orphans, deletable through the preview) and the GPOs without a
//! folder.
//!
//! Read on the write connection of the main window (PDC emulator), never in the local copy
//! (ADR 0012): the directory first (the tree shows), the SYSVOL of the PDC at the same time,
//! then the SYSVOL of the other DCs, compared with the one of the PDC, whose banner says the
//! result. F5 reads everything again, Escape closes.
//!
//! Writes: create, link, unlink, move up and down, enable the link, enforce it, block the
//! inheritance, security filtering, align the ACL, back up, restore, delete, delete an orphan
//! folder, remove every orphan folder, and « remove » (Delete: unlinks a link, deletes a GPO
//! or an orphan folder). What is allowed follows the chosen node (`gpo_views::actions_state`).
//! Every write goes through the common preview (`writes::propose`): verification, journal,
//! undo; the window reads itself again and chooses the node touched again. Ctrl+Z undoes the
//! last change of the domain, as in the main window. « Edit… » opens the content editor of the
//! GPO (`gpo_editor`).

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_codecs::gplink;
use annuaire_core::cache::Source;
use annuaire_core::changes::{Changeset, Report};
use annuaire_core::gpo::{self as core_gpo, Container, Gpo, GpoDirectory, Inventory, SysvolDc};
use annuaire_core::gpo_backup::{self, Backup, BackupError};
use annuaire_core::gpo_write::{self as gw, GpoError, LinkChange};
use annuaire_core::sysvol::Protection;
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::errors;
use crate::gpo_dialogs::{BackupDialog, FilteringDialog, LinkDialog, NameDialog, RestoreDialog};
use crate::gpo_views::{self as gv, GpoNode, Kind};
use crate::i18n::{fill, tr};
use crate::writes::{self, Options};

// --- A node of the tree ------------------------------------------------------------------------

mod node {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::gpo_views::GpoNode;
    use crate::i18n::tr;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::GpoNodeObject)]
    pub struct GpoNodeObject {
        #[property(name = "titre", get = |n: &Self| n.view().title.replace('\n', " "), type = String)]
        #[property(name = "sous-titre", get = |n: &Self| n.view().subtitle.clone(), type = String)]
        #[property(name = "a-sous-titre", get = |n: &Self| !n.view().subtitle.is_empty(), type = bool)]
        #[property(name = "icone", get = |n: &Self| n.view().icon.to_owned(), type = String)]
        #[property(name = "alerte", get = |n: &Self| n.view().alert, type = bool)]
        #[property(name = "accessible", get = |n: &Self| n.accessible(), type = String)]
        pub view: OnceCell<GpoNode>,
    }

    impl GpoNodeObject {
        pub fn view(&self) -> &GpoNode {
            self.view.get().expect("node built by GpoNodeObject::new")
        }

        fn accessible(&self) -> String {
            let view = self.view();
            let mut text = view.accessible().replace('\n', " ");
            if view.alert {
                text.push_str(&tr(", alert"));
            }
            text
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for GpoNodeObject {
        const NAME: &'static str = "AnnuaireNoeudGpo";
        type Type = super::GpoNodeObject;
    }

    #[glib::derived_properties]
    impl ObjectImpl for GpoNodeObject {}
}

glib::wrapper! {
    /// A node of the tree (`NoeudGpoObjet`).
    pub struct GpoNodeObject(ObjectSubclass<node::GpoNodeObject>);
}

impl GpoNodeObject {
    fn new(view: GpoNode) -> Self {
        let object: Self = glib::Object::new();
        let _ = object.imp().view.set(view);
        object
    }

    pub fn view(&self) -> &GpoNode {
        self.imp().view()
    }
}

fn store_of(nodes: &[GpoNode]) -> gio::ListStore {
    let store = gio::ListStore::new::<GpoNodeObject>();
    let objects: Vec<GpoNodeObject> = nodes.iter().cloned().map(GpoNodeObject::new).collect();
    store.extend_from_slice(&objects);
    store
}

/// A row of detail (`_rangee`).
fn row(title: &str, value: &str, alert: bool) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(title).as_str())
        .subtitle(glib::markup_escape_text(value).as_str())
        .subtitle_selectable(true)
        .subtitle_lines(0)
        .build();
    row.add_css_class("property");
    if alert {
        let image = gtk::Image::from_icon_name("dialog-warning-symbolic");
        image.add_css_class("warning");
        image.update_property(&[gtk::accessible::Property::Label(&tr("Alert"))]);
        row.add_prefix(&image);
    }
    row
}

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

/// Nodes from the root to the node of key `key` (empty if it is not in the tree)
/// (`_chemin_vers`).
fn path_to<'a>(nodes: &'a [GpoNode], key: &str) -> Vec<&'a GpoNode> {
    for n in nodes {
        if n.key() == key {
            return vec![n];
        }
        let rest = path_to(&n.children, key);
        if !rest.is_empty() {
            let mut path = vec![n];
            path.extend(rest);
            return path;
        }
    }
    Vec::new()
}

/// A preparation error said plainly: (message, detail).
pub fn gpo_error_message(error: &GpoError, domain: &str) -> (String, String) {
    let text = |t: String| (t, String::new());
    match error {
        GpoError::Failure(failure) => {
            let problem = errors::failure_problem(failure, domain);
            (problem.message, problem.detail)
        }
        GpoError::Sysvol(e) => {
            let (_, problem) = errors::sysvol_problem(e, "");
            (problem.message, problem.detail)
        }
        GpoError::OffPdc(msg) => {
            use annuaire_core::writer::WriteCatalog as _;
            text(AppCatalog.write_text(msg))
        }
        GpoError::EmptyName => text(tr("The GPO name is empty.")),
        GpoError::NoPermission => text(tr(
            "The GPO's security descriptor grants no permission: refused.",
        )),
        GpoError::DomainSidUnreadable => text(tr("The domain SID cannot be read.")),
        GpoError::DefaultDescriptorUnreadable => text(tr(
            "The default security descriptor of GPOs cannot be read.",
        )),
        GpoError::DescriptorUnreadable { .. } => {
            text(tr("The GPO's security descriptor cannot be read."))
        }
        GpoError::Missing { dn } => {
            text(fill(&tr("The GPO “{dn}” does not exist."), &[("dn", dn)]))
        }
        GpoError::NotAGpo { dn } => text(fill(&tr("“{dn}” is not a GPO."), &[("dn", dn)])),
        GpoError::ContainerMissing { dn } => {
            text(fill(&tr("“{dn}” does not exist."), &[("dn", dn)]))
        }
        GpoError::AlreadyLinked => text(tr("This GPO is already linked to this container.")),
        GpoError::NoLongerLinked => text(tr(
            "This GPO is no longer linked to this container: read it again.",
        )),
        GpoError::OrderOutOfRange { order, n } => text(fill(
            &tr("link order out of range: {ordre} (1 to {n})"),
            &[("ordre", &order.to_string()), ("n", &n.to_string())],
        )),
        GpoError::OrphanGone { name, dc } => text(fill(
            &tr("The folder “{nom}” is no longer in the SYSVOL of {dc}."),
            &[("nom", name), ("dc", dc)],
        )),
        GpoError::NotOrphan { name, dn } => text(fill(
            &tr("The folder “{nom}” is not orphaned: the GPO {dn} has this GUID."),
            &[("nom", name), ("dn", dn)],
        )),
        GpoError::InvalidFolderName { name } => text(fill(
            &tr("invalid GPO folder name: {nom}"),
            &[("nom", &format!("'{name}'"))],
        )),
        GpoError::Invalid(detail) => (crate::codec_texts::codec_message(detail), String::new()),
        GpoError::Backup(e) => backup_error_message(e),
        GpoError::NotRead { path } => text(fill(
            &tr("GPO file not read: {chemin}"),
            &[("chemin", path)],
        )),
        GpoError::IsFolder { path, .. } => text(fill(
            &tr("“{chemin}” is a folder, not a file."),
            &[("chemin", path)],
        )),
        GpoError::IsFile { path, .. } => text(fill(
            &tr("“{chemin}” is a file, not a folder."),
            &[("chemin", path)],
        )),
        GpoError::FolderAbsent { name, .. } => text(fill(
            &tr("The folder of “{nom}” is missing from this DC's SYSVOL."),
            &[("nom", name)],
        )),
        GpoError::DomainUnreadable { .. } => text(tr("The domain object cannot be read.")),
        GpoError::Security(problems) => text(
            problems
                .iter()
                .map(crate::gpo_security_views::problem_text)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        GpoError::Preferences { path, error } => text(fill(
            &tr("The file “{chemin}” cannot be read: {erreur}"),
            &[
                ("chemin", path),
                ("erreur", &crate::preference_views::error_text(error)),
            ],
        )),
        GpoError::PreferenceGone { .. } => text(tr(
            "An item changed in the draft is no longer in the file (removed by another tool): reload the GPO.",
        )),
    }
}

/// `ErreurSauvegarde` said plainly: (message, detail).
pub fn backup_error_message(error: &BackupError) -> (String, String) {
    match error {
        BackupError::ArchiveExists(path) => (
            fill(&tr("The archive “{c}” already exists."), &[("c", path)]),
            String::new(),
        ),
        BackupError::NoManifest => (
            tr("Archive without a manifest: this is not a backup."),
            String::new(),
        ),
        BackupError::UnknownFormat(f) => (tr("Unknown backup format."), f.clone()),
        BackupError::PathRefused(p) => (tr("Path rejected in the archive."), p.clone()),
        BackupError::FileMissing(p) => (tr("File missing from the archive."), p.clone()),
        BackupError::UnexpectedSize(p) => (tr("Unexpected size in the archive."), p.clone()),
        BackupError::Altered(p) => (tr("Corrupted file in the archive."), p.clone()),
        BackupError::Unreadable(d) => (tr("Unreadable archive."), d.clone()),
        BackupError::InvalidGuid(g) => (tr("Invalid GUID in the archive."), g.clone()),
        BackupError::NoDescriptor => (
            tr("Security descriptor missing from the archive."),
            String::new(),
        ),
        BackupError::InvalidObject(o) => (tr("Invalid object in the archive."), o.clone()),
        BackupError::OtherDomain(d) => (
            fill(&tr("This backup comes from the domain {d}."), &[("d", d)]),
            String::new(),
        ),
    }
}

// --- The window ---------------------------------------------------------------------------------

mod imp {
    use super::*;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/gpo.ui")]
    pub struct GpoWindow {
        #[template_child]
        pub split_view: TemplateChild<adw::NavigationSplitView>,
        #[template_child]
        pub domain_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub sysvol_banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub tree_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub tree: TemplateChild<gtk::ListView>,
        #[template_child]
        pub tree_selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub tree_error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub detail_page: TemplateChild<adw::NavigationPage>,
        #[template_child]
        pub detail_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub detail_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub alerts_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub alerts_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub state_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub versions_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub links_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub filtering_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub details_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub container_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub container_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub directory: RefCell<Option<GpoDirectory>>,
        pub sysvol: RefCell<Option<SysvolDc>>,
        pub others: RefCell<Option<Vec<SysvolDc>>>,
        pub generation: Cell<u64>,
        pub editor: RefCell<Option<crate::gpo_editor::GpoEditor>>,
        pub to_choose: RefCell<Option<String>>,
        pub domain_rank: Cell<u32>,
        pub roots: RefCell<Vec<GpoNode>>,
        pub actions: RefCell<HashMap<&'static str, gio::SimpleAction>>,
        pub remove: Cell<&'static str>,
        /// Instants of the last reading asked and drawn (measures of the trials).
        pub asked_at: Cell<Option<Instant>>,
        pub drawn_at: Cell<Option<Instant>>,
    }

    impl std::fmt::Debug for GpoWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GpoWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for GpoWindow {
        const NAME: &'static str = "AnnuaireGpo";
        type Type = super::GpoWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            <super::GpoNodeObject as gtk::prelude::StaticTypeExt>::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::GpoWindow>(&[
                ("selected", |w, _| {
                    w.show_chosen();
                    w.update_actions();
                    None
                }),
                ("sysvol_details", |w, _| {
                    w.sysvol_details();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for GpoWindow {}
    impl WidgetImpl for GpoWindow {}

    impl WindowImpl for GpoWindow {
        fn close_request(&self) -> glib::Propagation {
            self.generation.set(self.generation.get() + 1);
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for GpoWindow {}
}

glib::wrapper! {
    /// The « Group Policy » window of the open domain (`AnnuaireGpo`).
    pub struct GpoWindow(ObjectSubclass<imp::GpoWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

/// How a changeset is prepared: blocking, on a thread apart.
type Preparation = Box<dyn FnOnce() -> Result<Changeset, GpoError> + Send>;

impl GpoWindow {
    pub fn new(source: Arc<dyn Source>, parent: &crate::window::Window) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = window.imp();
        imp.domain_title.set_subtitle(&source.profile().domain);
        let _ = imp.source.set(source);
        window.install_actions();
        crate::a11y::name_menus(&window);
        window.reload(None);
        window
    }

    /// The source this window was opened for (the main window compares it with its own).
    pub fn source(&self) -> &Arc<dyn Source> {
        self.imp().source.get().expect("set by new")
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    fn domain(&self) -> String {
        self.source().profile().domain.clone()
    }

    fn context(&self) -> Option<Arc<writes::WriteContext>> {
        writes::context(self)
    }

    fn read_only(&self) -> bool {
        self.context().is_none_or(|c| c.profile.read_only)
    }

    /// Called by the common preview after a write (undo by the toast included)
    /// (`apres_ecriture`).
    pub fn after_write(&self, _report: &Report) {
        self.reload(None);
    }

    /// The inventory, once the SYSVOL of the PDC is read (`inventaire`).
    pub fn inventory(&self) -> Option<Inventory> {
        let imp = self.imp();
        let directory = imp.directory.borrow().clone()?;
        let sysvol = imp.sysvol.borrow().clone()?;
        Some(Inventory {
            directory,
            sysvol,
            others: imp.others.borrow().clone().unwrap_or_default(),
        })
    }

    pub fn chosen_node(&self) -> Option<GpoNode> {
        let row = self
            .imp()
            .tree_selection
            .selected_item()
            .and_downcast::<gtk::TreeListRow>()?;
        Some(row.item().and_downcast::<GpoNodeObject>()?.view().clone())
    }

    fn chosen_gpo(&self) -> Option<Gpo> {
        self.chosen_node()?.gpo
    }

    // --- Actions --------------------------------------------------------------------------

    fn install_actions(&self) {
        let imp = self.imp();
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&GpoWindow);
        let plain: [(&'static str, Handler); 3] = [
            ("actualiser", |w| w.reload(None)),
            ("comparer", Self::compare),
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
        for name in gv::ACTIONS {
            let action = if gv::TOGGLES.contains(&name) {
                let action = gio::SimpleAction::new_stateful(name, None, &false.to_variant());
                let weak = self.downgrade();
                action.connect_change_state(move |action, value| {
                    let (Some(window), Some(value)) = (weak.upgrade(), value) else {
                        return;
                    };
                    window.toggle(action.name().as_str(), value.get::<bool>().unwrap_or(false));
                });
                action
            } else {
                let action = gio::SimpleAction::new(name, None);
                let weak = self.downgrade();
                action.connect_activate(move |action, _| {
                    if let Some(window) = weak.upgrade().filter(|w| w.visible_dialog().is_none()) {
                        window.activate(action.name().as_str());
                    }
                });
                action
            };
            group.add_action(&action);
            imp.actions.borrow_mut().insert(name, action);
        }
        self.insert_action_group("gpo", Some(&group));

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
                let split = &window.imp().split_view;
                if split.is_collapsed() && split.shows_content() {
                    split.set_show_content(false);
                    return glib::Propagation::Stop;
                }
                window.close();
                glib::Propagation::Stop
            })),
        ));
        self.add_controller(escape);
        let shortcuts = gtk::ShortcutController::new();
        let mut triggers: Vec<(&str, String)> = vec![
            ("F5", "gpo.actualiser".into()),
            ("<Control>z", "gpo.annuler-derniere".into()),
        ];
        triggers.extend(
            gv::SHORTCUTS
                .iter()
                .map(|(name, key)| (*key, format!("gpo.{name}"))),
        );
        for (trigger, action) in triggers {
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::NamedAction::new(&action)),
            ));
        }
        self.add_controller(shortcuts);
        self.update_actions();
    }

    /// Allowed actions and toggles from the chosen node (`actualiser`).
    fn update_actions(&self) {
        let imp = self.imp();
        let state = gv::actions_state(self.chosen_node().as_ref(), self.read_only());
        for (name, action) in imp.actions.borrow().iter() {
            action.set_enabled(state.allowed.contains(name));
        }
        let set = |name: &str, value: bool| {
            if let Some(action) = imp.actions.borrow().get(name) {
                action.set_state(&value.to_variant());
            }
        };
        set("lien-actif", state.link_enabled);
        set("lien-applique", state.link_enforced);
        set("bloquer-heritage", state.inheritance_blocked);
        imp.remove.set(state.remove);
    }

    fn activate(&self, name: &str) {
        let name = if name == "retirer" {
            self.imp().remove.get()
        } else {
            name
        };
        match name {
            "creer" => self.create(),
            "lier" => self.link(),
            "delier" => self.on_link(gw::unlink, tr("Link not removed"), None),
            "monter" => self.on_link(gw::move_up, tr("Link not moved"), Some(-1)),
            "descendre" => self.on_link(gw::move_down, tr("Link not moved"), Some(1)),
            "filtrage" => self.filtering(),
            "aligner" => self.align(),
            "sauvegarder" => self.back_up(),
            "restaurer" => self.restore(),
            "orphelins" => self.remove_orphans(),
            "supprimer" => self.delete(),
            "supprimer-orphelin" => self.delete_orphan(),
            "modifier" => self.edit(),
            "securite" => self.security(),
            _ => {}
        }
    }

    /// The content editor of the chosen GPO; the window reads itself again after each write
    /// (versions, extensions) (`_modifier`).
    fn edit(&self) {
        let Some(gpo) = self.chosen_gpo() else { return };
        if self.context().is_none() {
            return;
        }
        let key = format!("gpo:{}", gpo.guid);
        let weak = self.downgrade();
        let editor = crate::gpo_editor::GpoEditor::new(
            crate::gpo_editor::EditedGpo {
                dn: gpo.dn.clone(),
                guid: gpo.guid.clone(),
                name: gpo.name.clone(),
            },
            self,
            crate::gpo_editor::sections(),
            Some(Box::new(move || {
                if let Some(window) = weak.upgrade() {
                    window.reload(Some(key.clone()));
                }
            })),
        );
        *self.imp().editor.borrow_mut() = Some(editor.clone());
        editor.present();
    }

    /// Security settings of the GPO (J7.5): `GptTmpl.inf`, and on Samba the domain object; the
    /// window reads itself again after the write (`_securite`).
    fn security(&self) {
        let (Some(gpo), Some(connection)) = (self.chosen_gpo(), self.connection()) else {
            return;
        };
        let key = self.chosen_node().map(|n| n.key());
        let weak = self.downgrade();
        crate::gpo_security::SecurityDialog::new(
            Some(self.source().clone()),
            connection,
            (gpo.dn.clone(), gpo.name.clone()),
            self.read_only(),
            Some(Box::new(move |report| {
                if let (Some(window), Some(_)) = (weak.upgrade(), report) {
                    window.reload(key.clone());
                }
            })),
        )
        .present(Some(self));
    }

    /// The editor opened last (trials).
    pub fn editor(&self) -> Option<crate::gpo_editor::GpoEditor> {
        self.imp().editor.borrow().clone()
    }

    /// A changeset prepared apart, then the common preview; the window reads itself again
    /// and chooses `key()` again once the write is done (`_proposer`).
    fn propose(
        &self,
        preparation: Preparation,
        title: String,
        key: Box<dyn Fn() -> Option<String>>,
    ) {
        let (weak, domain) = (self.downgrade(), self.domain());
        glib::spawn_future_local(async move {
            let prepared = gio::spawn_blocking(preparation).await;
            let Some(window) = weak.upgrade() else { return };
            let changeset = match prepared {
                Ok(Ok(changeset)) => changeset,
                Ok(Err(error)) => {
                    let (message, detail) = gpo_error_message(&error, &domain);
                    writes::show_error(&window, &title, &message, &detail);
                    return;
                }
                Err(_) => return,
            };
            let weak = window.downgrade();
            writes::propose(
                &window,
                changeset,
                Options {
                    finished: Some(Box::new(move |report| {
                        if let (Some(window), Some(_)) = (weak.upgrade(), report) {
                            window.reload(key());
                        }
                    })),
                    ..Options::default()
                },
            );
        });
    }

    fn connection(&self) -> Option<Arc<annuaire_core::Connection>> {
        match self.context() {
            Some(context) => Some(context.connection.clone()),
            None => {
                writes::show_error(self, &tr("Cannot write"), &tr("No domain is open."), "");
                None
            }
        }
    }

    fn catalog() -> Arc<dyn annuaire_core::messages::Catalog + Send + Sync> {
        Arc::new(AppCatalog)
    }

    fn toggle(&self, name: &str, wanted: bool) {
        let (Some(node), Some(connection)) = (self.chosen_node(), self.connection()) else {
            return;
        };
        let key = node.key();
        if name == "bloquer-heritage" {
            let Some(container) = node.container.clone() else {
                return;
            };
            self.propose(
                Box::new(move || gw::prepare_inheritance(&connection, &container.dn, wanted)),
                tr("Inheritance not changed"),
                Box::new(move || Some(key.clone())),
            );
            return;
        }
        let (Some(link), Some(container)) = (node.link.clone(), node.container.clone()) else {
            return;
        };
        let change = if name == "lien-actif" {
            gw::link_options(&link.dn, Some(!wanted), None)
        } else {
            gw::link_options(&link.dn, None, Some(wanted))
        };
        self.propose(
            Box::new(move || gw::prepare_links(&connection, &container.dn, change)),
            tr("Link not changed"),
            Box::new(move || Some(key.clone())),
        );
    }

    fn create(&self) {
        let Some(connection) = self.connection() else {
            return;
        };
        let weak = self.downgrade();
        NameDialog::new(Box::new(move |name: String| {
            let Some(window) = weak.upgrade() else { return };
            let guid = gw::new_guid();
            let (connection, chosen) = (connection.clone(), guid.clone());
            window.propose(
                Box::new(move || {
                    gw::prepare_creation(&connection, &name, Some(&guid), GpoWindow::catalog())
                }),
                tr("GPO not created"),
                Box::new(move || Some(format!("gpo:{chosen}"))),
            );
        }))
        .present(Some(self));
    }

    fn delete(&self) {
        let (Some(gpo), Some(connection)) = (self.chosen_gpo(), self.connection()) else {
            return;
        };
        self.propose(
            Box::new(move || gw::prepare_deletion(&connection, &gpo.dn, GpoWindow::catalog())),
            tr("GPO not deleted"),
            Box::new(|| None),
        );
    }

    /// Folder of the SYSVOL without a GPO object: the core reads again that no GPO carries
    /// this GUID, then the preview shows each file and folder removed (`_supprimer_orphelin`).
    fn delete_orphan(&self) {
        let (Some(node), Some(connection)) = (self.chosen_node(), self.connection()) else {
            return;
        };
        if node.folder.is_empty() {
            return;
        }
        let name = node.folder.clone();
        self.propose(
            Box::new(move || gw::prepare_orphan_deletion(&connection, &name, GpoWindow::catalog())),
            tr("Orphaned folder not deleted"),
            Box::new(|| None),
        );
    }

    fn link(&self) {
        let imp = self.imp();
        let (Some(node), Some(connection)) = (self.chosen_node(), self.connection()) else {
            return;
        };
        let (Some(container), Some(directory)) =
            (node.container.clone(), imp.directory.borrow().clone())
        else {
            return;
        };
        let already: HashSet<String> = container.gplink.links().filter_map(|l| l.guid()).collect();
        let candidates: Vec<Gpo> = directory
            .gpos
            .values()
            .filter(|g| !already.contains(&g.guid))
            .cloned()
            .collect();
        if candidates.is_empty() {
            writes::show_error(
                self,
                &tr("No GPO to link"),
                &tr("All the domain's GPOs are already linked to this container."),
                "",
            );
            return;
        }
        let weak = self.downgrade();
        let container_dn = container.dn.clone();
        LinkDialog::new(
            &container_dn,
            candidates,
            Box::new(move |gpo: Gpo, enforced: bool| {
                let Some(window) = weak.upgrade() else { return };
                let options = if enforced { gplink::ENFORCED } else { 0 };
                let order = container.gplink.links().count() + 1;
                let key = format!(
                    "lien:{}:{order}:{}",
                    container.dn.to_lowercase(),
                    gpo.dn.to_lowercase()
                );
                let (connection, dn) = (connection.clone(), container.dn.clone());
                window.propose(
                    Box::new(move || {
                        gw::prepare_links(&connection, &dn, gw::link_gpo(&gpo.dn, options))
                    }),
                    tr("GPO not linked"),
                    Box::new(move || Some(key.clone())),
                );
            }),
        )
        .present(Some(self));
    }

    fn on_link(&self, change: fn(&str) -> LinkChange, title: String, shift: Option<i64>) {
        let (Some(node), Some(connection)) = (self.chosen_node(), self.connection()) else {
            return;
        };
        let (Some(link), Some(container)) = (node.link.clone(), node.container.clone()) else {
            return;
        };
        let key = match shift {
            None => format!("conteneur:{}", container.dn.to_lowercase()),
            Some(s) => {
                let order = i64::try_from(node.order).unwrap_or(0) + s;
                format!(
                    "lien:{}:{order}:{}",
                    container.dn.to_lowercase(),
                    link.dn.to_lowercase()
                )
            }
        };
        let modification = change(&link.dn);
        self.propose(
            Box::new(move || gw::prepare_links(&connection, &container.dn, modification)),
            title,
            Box::new(move || Some(key.clone())),
        );
    }

    fn filtering(&self) {
        let imp = self.imp();
        let (Some(gpo), Some(connection)) = (self.chosen_gpo(), self.connection()) else {
            return;
        };
        let Some(directory) = imp.directory.borrow().clone() else {
            return;
        };
        let key = self.chosen_node().map(|n| n.key());
        let present = gv::filtering_principals(&gpo, &directory.names);
        let weak = self.downgrade();
        let dn = gpo.dn.clone();
        FilteringDialog::new(
            self.source().clone(),
            &gpo.name,
            present,
            Box::new(move |add: Vec<Sid>, remove: Vec<Sid>| {
                let Some(window) = weak.upgrade() else { return };
                let (connection, dn, key) = (connection.clone(), dn.clone(), key.clone());
                window.propose(
                    Box::new(move || {
                        gw::prepare_filtering(&connection, &dn, add, remove, GpoWindow::catalog())
                    }),
                    tr("Filtering not changed"),
                    Box::new(move || key.clone()),
                );
            }),
        )
        .present(Some(self));
    }

    /// ACL of the folder set back from the descriptor of the GPO (`sysvolreset` of a GPO)
    /// (`_aligner`).
    fn align(&self) {
        let (Some(gpo), Some(connection)) = (self.chosen_gpo(), self.connection()) else {
            return;
        };
        let key = self.chosen_node().map(|n| n.key());
        self.propose(
            Box::new(move || gw::prepare_alignment(&connection, &gpo.dn, GpoWindow::catalog())),
            tr("Permissions not aligned"),
            Box::new(move || key.clone()),
        );
    }

    /// `{GUID}` folders of the SYSVOL of the PDC without an object in the directory, removed
    /// through the preview (`_orphelins`).
    fn remove_orphans(&self) {
        let Some(connection) = self.connection() else {
            return;
        };
        let key = self.chosen_node().map(|n| n.key());
        self.propose(
            Box::new(move || gw::prepare_orphans_removal(&connection, GpoWindow::catalog())),
            tr("Folders not removed"),
            Box::new(move || key.clone()),
        );
    }

    fn back_up(&self) {
        let (Some(gpo), Some(connection)) = (self.chosen_gpo(), self.connection()) else {
            return;
        };
        let dn = gpo.dn.clone();
        BackupDialog::new(
            &gpo.name,
            Box::new(move |folder| gpo_backup::back_up(&connection, &dn, &folder)),
        )
        .show(self);
    }

    fn restore(&self) {
        let Some(connection) = self.connection() else {
            return;
        };
        let weak = self.downgrade();
        RestoreDialog::new(Box::new(move |backup: Backup, copy: bool, name: String| {
            let Some(window) = weak.upgrade() else { return };
            let guid = backup.guid.clone();
            let connection = connection.clone();
            window.propose(
                Box::new(move || {
                    gpo_backup::prepare_restoration(
                        &connection,
                        &backup,
                        copy,
                        copy.then_some(name.as_str()),
                        GpoWindow::catalog(),
                    )
                }),
                tr("GPO not restored"),
                Box::new(move || (!copy).then(|| format!("gpo:{guid}"))),
            );
        }))
        .present(Some(self));
    }

    // --- Reading --------------------------------------------------------------------------

    /// Reads the directory and the SYSVOL again; `key` (`GpoNode::key`): node to choose
    /// again, otherwise the chosen one (`recharger`).
    pub fn reload(&self, key: Option<String>) {
        let imp = self.imp();
        let Some(context) = self.context() else {
            imp.tree_error.set_title(&tr("No domain open"));
            imp.tree_stack.set_visible_child_name("erreur");
            return;
        };
        *imp.to_choose.borrow_mut() = key.or_else(|| self.chosen_node().map(|n| n.key()));
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.directory.take();
        imp.sysvol.take();
        imp.others.take();
        imp.asked_at.set(Some(Instant::now()));
        imp.drawn_at.set(None);
        if imp.tree_selection.model().is_none() {
            imp.tree_stack.set_visible_child_name("chargement");
        }
        self.show_banner();
        let domain = self.domain();
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || core_gpo::read_directory(&connection)).await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            match read {
                Ok(Ok(directory)) => *imp.directory.borrow_mut() = Some(directory),
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    imp.tree_error.set_title(&problem.message);
                    imp.tree_error.set_description(Some(&problem.detail));
                    imp.tree_stack.set_visible_child_name("erreur");
                    return;
                }
                Err(_) => return,
            }
            window.build_tree();
            if imp.sysvol.borrow().is_some() {
                window.sysvol_ready();
            }
        });
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || core_gpo::read_pdc_sysvol(&connection)).await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            let Ok(Ok(sysvol)) = read else { return };
            *imp.sysvol.borrow_mut() = Some(sysvol);
            if imp.directory.borrow().is_some() {
                window.sysvol_ready();
            }
        });
    }

    /// SYSVOL of the PDC read: alerts of the tree and of the detail, then the other DCs
    /// (`_sysvol_pret`).
    fn sysvol_ready(&self) {
        self.build_tree();
        self.compare();
    }

    /// `_comparer`.
    fn compare(&self) {
        let imp = self.imp();
        let (Some(directory), Some(pdc)) = (
            imp.directory.borrow().clone(),
            imp.sysvol.borrow().as_ref().map(|s| s.dc.clone()),
        ) else {
            return;
        };
        let protection = self.context().map_or(Protection::Encrypted, |c| {
            Protection::of_profile(c.connection.profile().smb2_signing)
        });
        let generation = imp.generation.get();
        imp.others.take();
        self.show_banner();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read =
                gio::spawn_blocking(move || core_gpo::compare_dcs(&directory, &pdc, protection))
                    .await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            let Ok(others) = read else { return };
            *imp.others.borrow_mut() = Some(others);
            window.build_tree();
        });
    }

    fn show_banner(&self) {
        let imp = self.imp();
        if let Some(sysvol) = imp.sysvol.borrow().as_ref()
            && let Some(error) = &sysvol.error
        {
            imp.sysvol_banner.set_title(&fill(
                &tr("Unreadable SYSVOL on the PDC: {erreur}"),
                &[("erreur", &gv::read_error_text(error, &sysvol.dc))],
            ));
            imp.sysvol_banner.set_revealed(true);
            return;
        }
        let state = self.sysvols_state();
        imp.sysvol_banner.set_title(&state.text);
        let details = tr("Details");
        imp.sysvol_banner
            .set_button_label((!state.details.is_empty()).then_some(details.as_str()));
        imp.sysvol_banner.set_revealed(state.alert);
    }

    fn sysvols_state(&self) -> gv::SysvolsState {
        let others = self.imp().others.borrow().clone();
        gv::sysvols_state(self.inventory().as_ref(), others.as_deref())
    }

    /// `sysvol_details`.
    fn sysvol_details(&self) {
        let state = self.sysvols_state();
        let alert = adw::AlertDialog::new(Some(&tr("SYSVOL Comparison")), Some(&state.text));
        if !state.details.is_empty() {
            let view = gtk::Label::builder()
                .label(state.details.join("\n"))
                .xalign(0.0)
                .wrap(true)
                .selectable(true)
                .build();
            let scrolled = gtk::ScrolledWindow::builder()
                .child(&view)
                .min_content_height(200)
                .build();
            alert.set_extra_child(Some(&scrolled));
        }
        alert.add_response("fermer", &tr("Close"));
        alert.present(Some(self));
    }

    fn alerts(&self) -> HashSet<String> {
        let Some(inventory) = self.inventory() else {
            return HashSet::new();
        };
        inventory
            .directory
            .gpos
            .keys()
            .filter(|g| !inventory.deviations(g).is_empty())
            .cloned()
            .collect()
    }

    /// `_construire_arbre`.
    fn build_tree(&self) {
        let imp = self.imp();
        let Some(directory) = imp.directory.borrow().clone() else {
            return;
        };
        let key = imp
            .to_choose
            .take()
            .or_else(|| self.chosen_node().map(|n| n.key()));
        let inventory = self.inventory();
        let roots = gv::mark_alerts(gv::tree(&directory, inventory.as_ref()), &self.alerts());
        let store = store_of(&roots);
        let model = gtk::TreeListModel::new(store, false, false, |item| {
            let node = item.downcast_ref::<GpoNodeObject>()?;
            if node.view().children.is_empty() {
                return None;
            }
            Some(store_of(&node.view().children).upcast())
        });
        // Domain (last root) expanded at once: its links and OUs are seen at once.
        let domain_rank = u32::try_from(roots.len().saturating_sub(1)).unwrap_or(0);
        imp.domain_rank.set(domain_rank);
        *imp.roots.borrow_mut() = roots;
        imp.tree_selection.set_model(Some(&model));
        if let Some(row) = model.row(domain_rank) {
            row.set_expanded(true);
        }
        let first = imp.tree_stack.visible_child_name().as_deref() != Some("arbre");
        imp.tree_stack.set_visible_child_name("arbre");
        self.choose_again(&model, key.as_deref());
        if first {
            imp.tree.grab_focus(); // the keyboard walk starts from the tree
        }
        let weak = self.downgrade();
        glib::idle_add_local_once(move || {
            if let Some(window) = weak.upgrade() {
                window.focus_on_choice();
            }
        });
        self.show_banner();
        self.show_chosen();
        self.update_actions();
        if imp.drawn_at.get().is_none() {
            let weak = self.downgrade();
            glib::idle_add_local_once(move || {
                if let Some(window) = weak.upgrade()
                    && window.imp().drawn_at.get().is_none()
                {
                    window.imp().drawn_at.set(Some(Instant::now()));
                }
            });
        }
    }

    /// If the focus is in the tree, it joins the chosen row: a tree built again (SYSVOL read,
    /// « Inconsistencies » inserted before the domain) would leave it at its old position
    /// otherwise (`_focus_sur_choix`).
    fn focus_on_choice(&self) {
        let imp = self.imp();
        let position = imp.tree_selection.selected();
        let Some(focus) = gtk::prelude::GtkWindowExt::focus(self) else {
            return;
        };
        if position == gtk::INVALID_LIST_POSITION {
            return;
        }
        let tree: &gtk::Widget = imp.tree.upcast_ref();
        if &focus == tree || focus.is_ancestor(tree) {
            imp.tree
                .scroll_to(position, gtk::ListScrollFlags::FOCUS, None);
        }
    }

    /// Chooses the node of key `key` again, expanding its parents if needed
    /// (`_reselectionner`).
    fn choose_again(&self, model: &gtk::TreeListModel, key: Option<&str>) {
        let imp = self.imp();
        let domain = imp.domain_rank.get();
        let Some(key) = key else {
            imp.tree_selection.set_selected(domain);
            return;
        };
        let roots = imp.roots.borrow().clone();
        let path = path_to(&roots, key);
        if path.is_empty() {
            imp.tree_selection.set_selected(domain);
            return;
        }
        let mut position: u32 = 0;
        for (depth, n) in path.iter().enumerate() {
            let wanted = n.key();
            loop {
                if position >= model.n_items() {
                    return;
                }
                let found = model.row(position).is_some_and(|row| {
                    row.depth() as usize == depth
                        && row
                            .item()
                            .and_downcast::<GpoNodeObject>()
                            .is_some_and(|o| o.view().key() == wanted)
                });
                if found {
                    break;
                }
                position += 1;
            }
            if depth + 1 < path.len() {
                if let Some(row) = model.row(position) {
                    row.set_expanded(true);
                }
                position += 1;
            }
        }
        imp.tree_selection.set_selected(position);
    }

    // --- Detail ------------------------------------------------------------------------------

    fn show_chosen(&self) {
        let imp = self.imp();
        let node = self.chosen_node();
        let directory = imp.directory.borrow().clone();
        let (Some(node), Some(directory)) = (node, directory) else {
            imp.detail_title.set_title("");
            imp.detail_stack.set_visible_child_name("vide");
            return;
        };
        if let Some(gpo) = &node.gpo {
            self.show_gpo(gpo, &node, &directory);
        } else if let Some(container) = &node.container {
            self.show_container(container, &directory);
        } else if node.kind == Kind::All {
            self.show_all(&directory);
        } else if node.kind == Kind::Orphan {
            self.show_orphan(&node);
        } else if node.kind == Kind::Inconsistencies {
            self.show_inconsistencies(&node);
        } else {
            // A link to a GPO missing from the directory.
            self.show_orphan_link(&node);
        }
    }

    fn show_gpo(&self, gpo: &Gpo, node: &GpoNode, directory: &GpoDirectory) {
        let imp = self.imp();
        imp.detail_title.set_title(&gpo.name);
        imp.detail_title.set_subtitle(&if node.kind == Kind::Link {
            node.subtitle.clone()
        } else {
            gv::gpo_state(gpo)
        });
        imp.detail_page.set_title(&gpo.name);
        let inventory = self.inventory();
        let mut alerts: Vec<String> = inventory
            .as_ref()
            .map(|i| {
                i.deviations(&gpo.guid)
                    .iter()
                    .map(|d| gv::deviation_text(d, &i.sysvol.dc))
                    .collect()
            })
            .unwrap_or_default();
        if node.link.as_ref().is_some_and(|l| l.disabled()) {
            alerts.insert(
                0,
                tr("This link is disabled: the GPO does not apply through it."),
            );
        }
        empty(&imp.alerts_list);
        for text in &alerts {
            imp.alerts_list.append(&row(&tr("Alert"), text, true));
        }
        imp.alerts_group.set_visible(!alerts.is_empty());
        empty(&imp.state_list);
        for line in gv::state_lines(gpo) {
            imp.state_list
                .append(&row(&line.title, &line.value, line.alert));
        }
        empty(&imp.versions_list);
        let sysvol = imp.sysvol.borrow().clone();
        let folder = sysvol.as_ref().and_then(|s| s.folder(&gpo.guid));
        let dc = sysvol
            .as_ref()
            .map_or(directory.dc.as_str(), |s| s.dc.as_str());
        for line in gv::version_lines(gpo, folder.as_ref(), dc, sysvol.is_some()) {
            imp.versions_list
                .append(&row(&line.title, &line.value, line.alert));
        }
        empty(&imp.links_list);
        let links = gv::links_of(directory, &gpo.guid);
        for link in &links {
            imp.links_list
                .append(&row(&link.title(), &link.state(), link.link.disabled()));
        }
        if links.is_empty() {
            imp.links_list.append(&row(
                &tr("No links"),
                &tr("This GPO is not linked anywhere."),
                false,
            ));
        }
        empty(&imp.filtering_list);
        let filtering = gv::filter_lines(gpo, &directory.names);
        for f in &filtering {
            imp.filtering_list
                .append(&row(&f.name, &f.detail, !f.applies));
        }
        if filtering.is_empty() {
            imp.filtering_list.append(&row(
                &tr("Nobody"),
                &tr("No account receives this GPO."),
                true,
            ));
        }
        empty(&imp.details_list);
        for line in gv::detail_lines(gpo, directory) {
            imp.details_list
                .append(&row(&line.title, &line.value, line.alert));
        }
        imp.detail_stack.set_visible_child_name("gpo");
    }

    fn show_container(&self, container: &Container, directory: &GpoDirectory) {
        let imp = self.imp();
        let name = if container.class == "domainDNS" {
            directory.dns_name.clone()
        } else {
            container.name.clone()
        };
        imp.detail_title.set_title(&name.replace('\n', " "));
        imp.detail_title
            .set_subtitle(&container.dn.replace('\n', " "));
        imp.detail_page.set_title(&name);
        imp.container_group
            .set_title(&tr("Linked GPOs, in link order"));
        imp.container_group
            .set_description(Some(&gv::container_summary(container)));
        empty(&imp.container_list);
        for line in gv::container_lines(container, &directory.gpos) {
            let title = fill(
                &tr("{n}. {nom}"),
                &[("n", &line.order.to_string()), ("nom", &line.name)],
            );
            imp.container_list
                .append(&row(&title, &line.state, line.alert));
        }
        imp.detail_stack.set_visible_child_name("conteneur");
    }

    fn show_all(&self, directory: &GpoDirectory) {
        let imp = self.imp();
        imp.detail_title.set_title(&tr("Group Policy Objects"));
        imp.detail_title.set_subtitle(&directory.dns_name);
        imp.detail_page.set_title(&tr("Group Policy Objects"));
        let alerts = self.alerts();
        imp.container_group.set_title(&tr("All the domain's GPOs"));
        let orphans = self.inventory().map_or(0, |i| i.orphans().len());
        let mut description = fill(&tr("Read on {dc}."), &[("dc", &directory.dc)]);
        if !alerts.is_empty() {
            description.push(' ');
            description.push_str(&fill(
                &tr("{n} with an alert."),
                &[("n", &alerts.len().to_string())],
            ));
        }
        if orphans > 0 {
            description.push(' ');
            description.push_str(&fill(
                &tr("{n} SYSVOL folder(s) without a GPO: see “Inconsistencies”."),
                &[("n", &orphans.to_string())],
            ));
        }
        imp.container_group.set_description(Some(&description));
        empty(&imp.container_list);
        let mut gpos: Vec<&Gpo> = directory.gpos.values().collect();
        gpos.sort_by_cached_key(|g| g.name.to_lowercase());
        for gpo in gpos {
            let links = gv::links_of(directory, &gpo.guid).len();
            let state = format!(
                "{}, {}",
                gv::gpo_state(gpo),
                if links > 0 {
                    fill(&tr("linked {n} time(s)"), &[("n", &links.to_string())])
                } else {
                    tr("not linked")
                }
            );
            imp.container_list
                .append(&row(&gpo.name, &state, alerts.contains(&gpo.guid)));
        }
        imp.detail_stack.set_visible_child_name("conteneur");
    }

    fn show_orphan(&self, node: &GpoNode) {
        let imp = self.imp();
        let Some(inventory) = self.inventory() else {
            return;
        };
        imp.detail_title.set_title(&node.title);
        imp.detail_title.set_subtitle(&node.subtitle);
        imp.detail_page.set_title(&node.title);
        imp.container_group
            .set_title(&tr("SYSVOL Folder Without a GPO"));
        imp.container_group
            .set_description(Some(&gv::orphan_explanation(&inventory.sysvol.dc)));
        empty(&imp.container_list);
        for line in gv::orphan_lines(&inventory, &node.folder) {
            imp.container_list
                .append(&row(&line.title, &line.value, line.alert));
        }
        imp.detail_stack.set_visible_child_name("conteneur");
    }

    fn show_inconsistencies(&self, node: &GpoNode) {
        let imp = self.imp();
        let Some(inventory) = self.inventory() else {
            return;
        };
        imp.detail_title.set_title(&node.title);
        imp.detail_title.set_subtitle(&node.subtitle);
        imp.detail_page.set_title(&node.title);
        imp.container_group
            .set_title(&tr("Inconsistencies Between the Directory and the SYSVOL"));
        imp.container_group
            .set_description(Some(&gv::inconsistencies_summary(&inventory)));
        empty(&imp.container_list);
        for child in &node.children {
            imp.container_list
                .append(&row(&child.title, &child.subtitle, true));
        }
        imp.detail_stack.set_visible_child_name("conteneur");
    }

    fn show_orphan_link(&self, node: &GpoNode) {
        let imp = self.imp();
        imp.detail_title.set_title(&node.title);
        imp.detail_title.set_subtitle(&node.subtitle);
        imp.container_group.set_title(&tr("Link to a missing GPO"));
        imp.container_group.set_description(Some(&tr(
            "The container keeps a link to a GPO that the directory does not have (deleted, or from another domain). The link is kept as is.",
        )));
        empty(&imp.container_list);
        if let Some(link) = &node.link {
            imp.container_list.append(&row(&tr("Link"), &link.dn, true));
        }
        imp.detail_stack.set_visible_child_name("conteneur");
    }

    // --- Trials -----------------------------------------------------------------------------

    /// The tree and the comparison are read (trials).
    pub fn trial_ready(&self) -> bool {
        let imp = self.imp();
        imp.directory.borrow().is_some() && imp.others.borrow().is_some()
    }

    /// Seconds from the reading asked to the tree drawn (trials).
    pub fn trial_measure(&self) -> Option<f64> {
        let imp = self.imp();
        Some(
            imp.drawn_at
                .get()?
                .duration_since(imp.asked_at.get()?)
                .as_secs_f64(),
        )
    }

    /// Chooses the node of key `key` (trials).
    pub fn trial_choose(&self, key: &str) -> bool {
        let Some(model) = self
            .imp()
            .tree_selection
            .model()
            .and_downcast::<gtk::TreeListModel>()
        else {
            return false;
        };
        self.choose_again(&model, Some(key));
        self.chosen_node().is_some_and(|n| n.key() == key)
    }

    /// Activates an action of the window (trials).
    pub fn trial_action(&self, name: &str) {
        let _ = WidgetExt::activate_action(self, &format!("gpo.{name}"), None);
    }

    /// The texts of the detail shown (trials): title, subtitle, then each row.
    pub fn trial_detail(&self) -> Vec<String> {
        let imp = self.imp();
        let mut out = vec![
            imp.detail_title.title().to_string(),
            imp.detail_title.subtitle().to_string(),
            imp.sysvol_banner.title().to_string(),
        ];
        let lists = [
            &imp.alerts_list,
            &imp.state_list,
            &imp.versions_list,
            &imp.links_list,
            &imp.filtering_list,
            &imp.details_list,
            &imp.container_list,
        ];
        let page = imp.detail_stack.visible_child_name().unwrap_or_default();
        for (i, list) in lists.iter().enumerate() {
            if (page == "gpo") != (i < 6) {
                continue;
            }
            let mut n = 0;
            while let Some(r) = list.row_at_index(n) {
                if let Some(r) = r.downcast_ref::<adw::ActionRow>() {
                    out.push(
                        format!("{} = {}", r.title(), r.subtitle().unwrap_or_default())
                            .replace('\n', " "),
                    );
                }
                n += 1;
            }
        }
        out
    }

    /// The key of a node found by a description (trials): `gpo:NAME` (the GPO of that name),
    /// `conteneur:NAME` (domain or OU), `lien:CONTAINER:GPO`, `orphelin:NAME`, `=` (the
    /// chosen node).
    pub fn trial_find(&self, spec: &str) -> Option<String> {
        if spec == "=" {
            return self.chosen_node().map(|n| n.key());
        }
        fn walk<'a>(
            nodes: &'a [GpoNode],
            out: &mut Vec<(&'a GpoNode, Option<&'a GpoNode>)>,
            parent: Option<&'a GpoNode>,
        ) {
            for n in nodes {
                out.push((n, parent));
                walk(&n.children, out, Some(n));
            }
        }
        let roots = self.imp().roots.borrow();
        let mut all = Vec::new();
        walk(&roots, &mut all, None);
        let (kind, rest) = spec.split_once(':')?;
        let found = all.iter().find(|(n, parent)| match kind {
            "gpo" => n.kind == Kind::Gpo && n.title == rest,
            "conteneur" => matches!(n.kind, Kind::Domain | Kind::Ou) && n.title == rest,
            "orphelin" => n.kind == Kind::Orphan && n.title.eq_ignore_ascii_case(rest),
            "lien" => {
                let (c, g) = rest.split_once(':').unwrap_or((rest, ""));
                n.kind == Kind::Link && n.title == g && parent.is_some_and(|p| p.title == c)
            }
            _ => false,
        });
        found.map(|(n, _)| n.key())
    }

    /// Every node of the tree, depth first, with its subtitle (trials).
    pub fn trial_tree(&self) -> Vec<String> {
        fn walk(nodes: &[GpoNode], depth: usize, out: &mut Vec<String>) {
            for n in nodes {
                out.push(format!(
                    "{}{} | {}{}",
                    "  ".repeat(depth),
                    n.title.replace('\n', "⏎"),
                    n.subtitle,
                    if n.alert { " | !" } else { "" }
                ));
                walk(&n.children, depth + 1, out);
            }
        }
        let mut out = Vec::new();
        walk(&self.imp().roots.borrow(), 0, &mut out);
        out
    }
}

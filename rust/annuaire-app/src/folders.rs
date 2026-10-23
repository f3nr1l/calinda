// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Folders and NTFS Permissions » of a share (ADR 0023 § 5, J8.4): the tree of its folders,
//! each level read when it is unfolded, and for the folder chosen its path, its « Security »
//! tab (`file_security`) and its files, read when asked. Structure in `dossiers.blp`.
//!
//! Everything goes through one SMB session on the share (`ShareFiles`), opened at the first
//! reading and kept while the window is open: one negotiation instead of one per click. The
//! listings and descriptors go in compound requests, as for the SYSVOL (`Session::children`,
//! `Session::descriptors`). A window apart, transient for « Shares ».

use std::cell::{Cell, OnceCell, RefCell};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::cache::Source;
use annuaire_core::changes::{Report, unc};
use annuaire_core::smb::{ErrorKind, SmbError};
use annuaire_core::sysvol::{self, Protection, Session, SysvolError};
use gtk::{gio, glib};

use crate::errors;
use crate::i18n::{fill, tr, tr_n};
use crate::scope::TemplateScope;

const DELAY: Duration = Duration::from_secs(30);

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

// --- The session of a share ---------------------------------------------------------------------

/// The SMB session of a share, opened at the first need and kept for the window and its
/// dialogs; dropped after an error of the session itself, opened again at the next reading.
#[derive(Clone)]
pub struct ShareFiles {
    pub server: String,
    pub share: String,
    protection: Protection,
    session: Arc<Mutex<Option<Session>>>,
}

impl std::fmt::Debug for ShareFiles {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShareFiles")
            .field("server", &self.server)
            .field("share", &self.share)
            .finish_non_exhaustive()
    }
}

fn lost() -> SysvolError {
    SysvolError::Session(SmbError::new(ErrorKind::Protocol, "session lost"))
}

impl ShareFiles {
    pub fn new(server: &str, share: &str, protection: Protection) -> Self {
        Self {
            server: server.to_owned(),
            share: share.to_owned(),
            protection,
            session: Arc::new(Mutex::new(None)),
        }
    }

    /// `\\server\share\path`.
    pub fn unc(&self, path: &str) -> String {
        unc(&self.server, &self.share, path)
    }

    /// `work` on the session, in a thread of its own.
    pub async fn run<T: Send + 'static>(
        &self,
        work: impl FnOnce(&mut Session) -> sysvol::Result<T> + Send + 'static,
    ) -> sysvol::Result<T> {
        let (session, server, share, protection) = (
            self.session.clone(),
            self.server.clone(),
            self.share.clone(),
            self.protection,
        );
        gio::spawn_blocking(move || {
            let mut guard = session.lock().map_err(|_| lost())?;
            if guard.is_none() {
                *guard = Some(Session::open_share(&server, &share, protection, DELAY)?);
            }
            let result = work(guard.as_mut().ok_or_else(lost)?);
            if matches!(result, Err(SysvolError::Session(_)))
                && let Some(s) = guard.take()
            {
                s.close();
            }
            result
        })
        .await
        .unwrap_or_else(|_| Err(lost()))
    }

    /// Closes the session, in a thread (the server may be slow to answer).
    pub fn close(&self) {
        let session = self.session.clone();
        std::thread::spawn(move || {
            if let Ok(mut guard) = session.lock()
                && let Some(s) = guard.take()
            {
                s.close();
            }
        });
    }
}

/// An error of the share in words: as for the SYSVOL, the file server named.
pub fn file_problem(error: &SysvolError, server: &str) -> errors::Problem {
    errors::file_problem(error, server)
}

// --- A folder of the tree -----------------------------------------------------------------------

mod node {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::FolderNode)]
    pub struct FolderNode {
        #[property(name = "nom", get = |n: &Self| n.data().0.clone(), type = String)]
        #[property(name = "chemin", get = |n: &Self| n.data().1.clone(), type = String)]
        pub data: OnceCell<(String, String)>,
    }

    impl FolderNode {
        pub fn data(&self) -> &(String, String) {
            self.data.get().expect("node built by FolderNode::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FolderNode {
        const NAME: &'static str = "AnnuaireDossierNtfs";
        type Type = super::FolderNode;
    }

    #[glib::derived_properties]
    impl ObjectImpl for FolderNode {}
}

glib::wrapper! {
    /// A folder of the tree: its name, its path in the share (`AnnuaireDossierNtfs`).
    pub struct FolderNode(ObjectSubclass<node::FolderNode>);
}

impl FolderNode {
    pub fn new(name: &str, path: &str) -> Self {
        let node: Self = glib::Object::new();
        let _ = node.imp().data.set((name.to_owned(), path.to_owned()));
        node
    }

    pub fn path(&self) -> String {
        self.imp().data().1.clone()
    }

    pub fn name(&self) -> String {
        self.imp().data().0.clone()
    }
}

/// What reads the folders under a folder, the first time `GtkTreeListModel` asks how many
/// there are (at the expansion).
type Load = Box<dyn FnOnce(&FolderList)>;

mod list {
    use std::cell::RefCell;

    use gtk::gio;
    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;
    use gtk::subclass::prelude::*;

    #[derive(Default)]
    pub struct FolderList {
        pub items: RefCell<Vec<super::FolderNode>>,
        pub load: RefCell<Option<super::Load>>,
    }

    impl std::fmt::Debug for FolderList {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FolderList")
                .field("items", &self.items.borrow().len())
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FolderList {
        const NAME: &'static str = "AnnuaireListeDossiers";
        type Type = super::FolderList;
        type Interfaces = (gio::ListModel,);
    }

    impl ObjectImpl for FolderList {}

    impl ListModelImpl for FolderList {
        fn item_type(&self) -> glib::Type {
            super::FolderNode::static_type()
        }

        fn n_items(&self) -> u32 {
            if let Some(load) = self.load.take() {
                let list = self.obj().clone();
                glib::idle_add_local_once(move || load(&list));
            }
            u32::try_from(self.items.borrow().len()).unwrap_or(u32::MAX)
        }

        fn item(&self, position: u32) -> Option<glib::Object> {
            self.items
                .borrow()
                .get(usize::try_from(position).ok()?)
                .map(|n| n.clone().upcast())
        }
    }
}

glib::wrapper! {
    /// The folders under a folder, read at the first expansion (`AnnuaireListeDossiers`).
    pub struct FolderList(ObjectSubclass<list::FolderList>)
        @implements gio::ListModel;
}

impl FolderList {
    fn lazy(load: Load) -> Self {
        let list: Self = glib::Object::new();
        *list.imp().load.borrow_mut() = Some(load);
        list
    }

    fn filled(nodes: Vec<FolderNode>) -> Self {
        let list: Self = glib::Object::new();
        *list.imp().items.borrow_mut() = nodes;
        list
    }

    fn fill(&self, nodes: Vec<FolderNode>) {
        let imp = self.imp();
        let old = u32::try_from(imp.items.borrow().len()).unwrap_or(0);
        let new = u32::try_from(nodes.len()).unwrap_or(0);
        *imp.items.borrow_mut() = nodes;
        self.items_changed(0, old, new);
    }
}

// --- The window ---------------------------------------------------------------------------------

mod imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dossiers.ui")]
    pub struct FoldersWindow {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub tree: TemplateChild<gtk::ListView>,
        #[template_child]
        pub tree_selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub folder_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub security_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub folder_problem: TemplateChild<gtk::Label>,
        #[template_child]
        pub files_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub files_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub files_state: TemplateChild<gtk::Label>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub files: OnceCell<ShareFiles>,
        /// Path of the folder chosen in the tree.
        pub current: RefCell<Option<String>>,
        /// The files shown: their path and name.
        pub shown: RefCell<Vec<(String, String)>>,
        pub generation: Cell<u64>,
    }

    impl std::fmt::Debug for FoldersWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("FoldersWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for FoldersWindow {
        const NAME: &'static str = "AnnuaireDossiers";
        type Type = super::FoldersWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            FolderNode::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::FoldersWindow>(&[
                ("selected", |w, _| {
                    w.selected();
                    None
                }),
                ("security", |w, _| {
                    w.folder_security();
                    None
                }),
                ("files", |w, _| {
                    w.show_files();
                    None
                }),
                ("access", |w, _| {
                    w.folder_access();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for FoldersWindow {}
    impl WidgetImpl for FoldersWindow {}

    impl WindowImpl for FoldersWindow {
        fn close_request(&self) -> glib::Propagation {
            self.generation.set(self.generation.get() + 1);
            if let Some(files) = self.files.get() {
                files.close();
            }
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for FoldersWindow {}
}

glib::wrapper! {
    /// The folders of a share and their NTFS permissions (`AnnuaireDossiers`).
    pub struct FoldersWindow(ObjectSubclass<imp::FoldersWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl FoldersWindow {
    pub fn new(
        source: Arc<dyn Source>,
        server: &str,
        share: &str,
        protection: Protection,
        parent: &impl IsA<gtk::Window>,
    ) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = window.imp();
        let files = ShareFiles::new(server, share, protection);
        imp.title.set_title(share);
        imp.title.set_subtitle(&files.unc(""));
        let _ = imp.files.set(files);
        let _ = imp.source.set(source);
        window.install_actions();
        window.reload();
        window
    }

    pub fn source(&self) -> &Arc<dyn Source> {
        self.imp().source.get().expect("set by new")
    }

    pub fn files(&self) -> &ShareFiles {
        self.imp().files.get().expect("set by new")
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    fn install_actions(&self) {
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&FoldersWindow);
        let plain: [(&str, Handler); 2] = [
            ("actualiser", Self::reload),
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
        self.insert_action_group("dossiers", Some(&group));
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [
            ("F5", "dossiers.actualiser"),
            ("<Control>r", "dossiers.actualiser"),
            ("<Control>z", "dossiers.annuler-derniere"),
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
    }

    /// The root of the share read (the session opens), then the tree from it.
    pub fn reload(&self) {
        let imp = self.imp();
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.state.set_visible_child_name("chargement");
        let (files, weak) = (self.files().clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = files.run(|s| s.children(&[String::new()])).await;
            let Some(window) = weak.upgrade() else { return };
            if window.imp().generation.get() != generation {
                return;
            }
            match read.map(|mut r| r.pop()) {
                Ok(Some(Ok(entries))) => window.build_tree(&entries),
                Ok(Some(Err(status))) => {
                    window.failed(&SysvolError::status(status, ""));
                }
                Ok(None) => window.failed(&lost()),
                Err(error) => window.failed(&error),
            }
        });
    }

    fn failed(&self, error: &SysvolError) {
        let imp = self.imp();
        let problem = file_problem(error, &self.files().server);
        imp.error.set_title(&fill(
            &tr("The folders of {partage} cannot be read"),
            &[("partage", &self.files().unc(""))],
        ));
        imp.error
            .set_description(Some(&glib::markup_escape_text(&format!(
                "{}\n\n{}",
                problem.message, problem.detail
            ))));
        imp.state.set_visible_child_name("erreur");
    }

    fn folder_nodes(entries: &[sysvol::Entry]) -> Vec<FolderNode> {
        entries
            .iter()
            .filter(|e| e.directory)
            .map(|e| {
                let name = e.path.rsplit('\\').next().unwrap_or(&e.path);
                FolderNode::new(name, &e.path)
            })
            .collect()
    }

    fn build_tree(&self, root_entries: &[sysvol::Entry]) {
        let imp = self.imp();
        let share = self.files().share.clone();
        let roots = gio::ListStore::new::<FolderNode>();
        roots.append(&FolderNode::new(&share, ""));
        let first = Self::folder_nodes(root_entries);
        let weak = self.downgrade();
        let first = RefCell::new(Some(first));
        let model = gtk::TreeListModel::new(roots, false, false, move |item| {
            let window = weak.upgrade()?;
            let node = item.downcast_ref::<FolderNode>()?;
            // The root's folders are already read; the others at their expansion.
            if node.path().is_empty()
                && let Some(nodes) = first.take()
            {
                return Some(FolderList::filled(nodes).upcast());
            }
            let (path, weak) = (node.path(), window.downgrade());
            Some(
                FolderList::lazy(Box::new(move |list: &FolderList| {
                    if let Some(window) = weak.upgrade() {
                        window.read_folders(&path, list);
                    }
                }))
                .upcast(),
            )
        });
        imp.tree_selection.set_model(Some(&model));
        if let Some(row) = model.row(0) {
            row.set_expanded(true);
        }
        imp.tree_selection.set_selected(0);
        imp.state.set_visible_child_name("contenu");
        self.selected();
    }

    fn read_folders(&self, path: &str, list: &FolderList) {
        let (files, weak, list) = (self.files().clone(), self.downgrade(), list.downgrade());
        let target = path.to_owned();
        glib::spawn_future_local(async move {
            let read = files.run(move |s| s.children(&[target])).await;
            let (Some(window), Some(list)) = (weak.upgrade(), list.upgrade()) else {
                return;
            };
            match read.map(|mut r| r.pop()) {
                Ok(Some(Ok(entries))) => list.fill(Self::folder_nodes(&entries)),
                Ok(Some(Err(status))) => window.toast_error(&SysvolError::status(status, "")),
                Ok(None) => {}
                Err(error) => window.toast_error(&error),
            }
        });
    }

    fn toast_error(&self, error: &SysvolError) {
        let problem = file_problem(error, &self.files().server);
        self.add_toast(adw::Toast::new(&problem.message));
    }

    fn selected_node(&self) -> Option<FolderNode> {
        self.imp()
            .tree_selection
            .selected_item()
            .and_downcast::<gtk::TreeListRow>()?
            .item()
            .and_downcast::<FolderNode>()
    }

    fn selected(&self) {
        let imp = self.imp();
        let Some(node) = self.selected_node() else {
            return;
        };
        let path = node.path();
        imp.folder_row
            .set_title(&glib::markup_escape_text(&self.files().unc(&path)));
        imp.folder_row.set_subtitle(&if path.is_empty() {
            tr("Root of the share")
        } else {
            String::new()
        });
        imp.folder_problem.set_visible(false);
        *imp.current.borrow_mut() = Some(path);
        empty(&imp.files_list);
        imp.shown.borrow_mut().clear();
        imp.files_list.set_visible(false);
        imp.files_button.set_sensitive(true);
        imp.files_state.set_label(&tr(
            "The files are read when asked: a folder may hold thousands.",
        ));
    }

    /// The files of the folder chosen, read now.
    fn show_files(&self) {
        let imp = self.imp();
        let Some(path) = imp.current.borrow().clone() else {
            return;
        };
        imp.files_button.set_sensitive(false);
        imp.files_state.set_label(&tr("Reading…"));
        let (files, weak) = (self.files().clone(), self.downgrade());
        let generation = imp.generation.get();
        let target = path.clone();
        glib::spawn_future_local(async move {
            let read = files.run(move |s| s.children(&[target])).await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if imp.generation.get() != generation || imp.current.borrow().as_ref() != Some(&path) {
                return;
            }
            match read.map(|mut r| r.pop()) {
                Ok(Some(Ok(entries))) => window.fill_files(&entries),
                Ok(Some(Err(status))) => {
                    let problem =
                        file_problem(&SysvolError::status(status, &path), &window.files().server);
                    imp.files_state.set_label(&problem.message);
                    imp.files_button.set_sensitive(true);
                }
                Ok(None) => {}
                Err(error) => {
                    imp.files_state
                        .set_label(&file_problem(&error, &window.files().server).message);
                    imp.files_button.set_sensitive(true);
                }
            }
        });
    }

    fn fill_files(&self, entries: &[sysvol::Entry]) {
        let imp = self.imp();
        empty(&imp.files_list);
        let mut shown = Vec::new();
        for entry in entries.iter().filter(|e| !e.directory) {
            let name = entry
                .path
                .rsplit('\\')
                .next()
                .unwrap_or(&entry.path)
                .to_owned();
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&name).as_str())
                .subtitle(glib::format_size(entry.size).as_str())
                .build();
            let button = gtk::Button::builder()
                .icon_name("system-users-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text(tr("Security"))
                .build();
            button.add_css_class("flat");
            button.update_property(&[gtk::accessible::Property::Label(&fill(
                &tr("Security: {nom}"),
                &[("nom", &name)],
            ))]);
            let (weak, path) = (self.downgrade(), entry.path.clone());
            button.connect_clicked(move |_| {
                if let Some(window) = weak.upgrade() {
                    window.open_security(&path, false);
                }
            });
            row.add_suffix(&button);
            let access = gtk::Button::builder()
                .icon_name("avatar-default-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text(tr("Effective Access"))
                .build();
            access.add_css_class("flat");
            access.update_property(&[gtk::accessible::Property::Label(&fill(
                &tr("Effective access: {nom}"),
                &[("nom", &name)],
            ))]);
            let (weak, path) = (self.downgrade(), entry.path.clone());
            access.connect_clicked(move |_| {
                if let Some(window) = weak.upgrade() {
                    window.open_access(&path, false);
                }
            });
            row.add_suffix(&access);
            imp.files_list.append(&row);
            shown.push((entry.path.clone(), name));
        }
        let n = shown.len();
        imp.files_list.set_visible(n > 0);
        imp.files_state.set_label(&if n == 0 {
            tr("No file in this folder.")
        } else {
            fill(
                &tr_n("{n} file", "{n} files", n as u64),
                &[("n", &n.to_string())],
            )
        });
        *imp.shown.borrow_mut() = shown;
    }

    fn folder_security(&self) {
        let path = self.imp().current.borrow().clone();
        if let Some(path) = path {
            self.open_security(&path, true);
        }
    }

    /// The « Security » tab of `path`.
    pub fn open_security(&self, path: &str, folder: bool) {
        crate::file_security::FileSecurityDialog::new(
            self.source().clone(),
            crate::writes::context(self).map(|c| c.connection.clone()),
            self.files().clone(),
            path,
            folder,
        )
        .present(Some(self));
    }

    fn folder_access(&self) {
        let path = self.imp().current.borrow().clone();
        if let Some(path) = path {
            self.open_access(&path, true);
        }
    }

    /// The « Effective Access » of `path`.
    pub fn open_access(&self, path: &str, folder: bool) -> crate::access::AccessDialog {
        let files = self.files();
        let dialog = crate::access::AccessDialog::new(
            self.source().clone(),
            crate::writes::context(self).map(|c| c.connection.clone()),
            &files.server,
            &files.share,
            path,
            folder,
        );
        dialog.present(Some(self));
        dialog
    }

    /// Called by the common preview after a write (undo by the toast included): nothing to
    /// read again in the tree, the « Security » tab reads its element when it opens.
    pub fn after_write(&self, _report: &Report) {}

    // --- Trials ------------------------------------------------------------------------------

    /// The page shown: `contenu`, `erreur`, `chargement` (trials).
    pub fn trial_state(&self) -> String {
        self.imp()
            .state
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    /// The rows of the tree, indented by depth (trials).
    pub fn trial_tree(&self) -> Vec<String> {
        let Some(model) = self.imp().tree_selection.model() else {
            return Vec::new();
        };
        (0..model.n_items())
            .filter_map(|i| model.item(i).and_downcast::<gtk::TreeListRow>())
            .filter_map(|row| {
                let node = row.item().and_downcast::<FolderNode>()?;
                Some(format!(
                    "{}{}",
                    "  ".repeat(row.depth() as usize),
                    node.name()
                ))
            })
            .collect()
    }

    /// Selects the folder `path` if its row is shown, and unfolds it (trials).
    pub fn trial_select(&self, path: &str) -> bool {
        let imp = self.imp();
        let Some(model) = imp.tree_selection.model() else {
            return false;
        };
        for i in 0..model.n_items() {
            let Some(row) = model.item(i).and_downcast::<gtk::TreeListRow>() else {
                continue;
            };
            let found = row
                .item()
                .and_downcast::<FolderNode>()
                .is_some_and(|n| n.path().eq_ignore_ascii_case(path));
            if found {
                row.set_expanded(true);
                imp.tree_selection.set_selected(i);
                return true;
            }
        }
        false
    }

    /// Reads the files of the folder chosen (trials).
    pub fn trial_files(&self) {
        self.show_files();
    }

    /// The files shown, or the state of the reading (trials).
    pub fn trial_file_rows(&self) -> (String, Vec<String>) {
        let imp = self.imp();
        (
            imp.files_state.label().to_string(),
            imp.shown.borrow().iter().map(|(_, n)| n.clone()).collect(),
        )
    }
}

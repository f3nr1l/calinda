// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Content editor of a GPO (J7.3, `annuaire.ui.editeur_gpo`). The structure lives in
//! `editeur-gpo.blp`.
//!
//! Opened by « Edit… » on a GPO of the « Group Policy » window. On the left the tree of the
//! GPMC (`gpo_editor_views::tree`), on the right the page of the section that owns the chosen
//! node, at the bottom the common draft.
//!
//! **Pluggable sections.** Each section (`Section`) declares the files of the GPO it reads,
//! puts its nodes under anchors (`gpo_editor_views::Anchor`), gives the page of one of its nodes
//! and its draft as `Modification`. The editor reads every file in one batch on the SYSVOL of
//! the PDC (at the opening and after each write), then hands them to each section; Ctrl+S
//! gathers the changes of all the sections in one changeset, shown by the common preview
//! (`writes::propose`); Ctrl+Z proposes to undo the last write of the domain. A section calls
//! `GpoEditor::changed` when its draft changes and `GpoEditor::rebuild` when its nodes change
//! (store of the templates read, for example).

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Instant;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::changes::Report;
use annuaire_core::gpo::Part;
use annuaire_core::gpo_content::{self as gc, ContentChange, Work};
use annuaire_core::gpo_write::GpoError;
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::gpo::gpo_error_message;
use crate::gpo_editor_views::{self as ev, Anchor, ContentFile, EditorNode, Modification};
use crate::i18n::{fill, tr};
use crate::scope::TemplateScope;
use crate::writes::{self, Options, WriteContext};

/// A pluggable part of the editor (administrative templates, security, preferences)
/// (`Section`).
pub trait Section {
    fn ident(&self) -> &'static str;

    /// Files of the GPO to read for this section.
    fn files(&self) -> Vec<ContentFile>;

    /// Contents read (`None`: file absent), on the GTK thread; the draft is emptied.
    fn load(&self, editor: &GpoEditor, contents: &HashMap<ContentFile, Option<Vec<u8>>>);

    fn nodes(&self, part: Part) -> Vec<(Anchor, Vec<EditorNode>)>;

    /// The page to show for a node of the section (the same widget possibly).
    fn page(&self, editor: &GpoEditor, node: &EditorNode) -> gtk::Widget;

    fn modifications(&self) -> Vec<Modification>;

    fn discard(&self);

    /// Ctrl+F on `page`: gives the focus to its search; false if the page has none.
    fn focus_search(&self, _page: &gtk::Widget) -> bool {
        false
    }
}

/// What the editor shows of the GPO: its DN, its GUID, its name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditedGpo {
    pub dn: String,
    pub guid: String,
    pub name: String,
}

// --- A node of the tree ------------------------------------------------------------------------

mod node {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::gpo_editor_views::EditorNode;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::EditorNodeObject)]
    pub struct EditorNodeObject {
        #[property(name = "titre", get = |n: &Self| n.view().title.clone(), type = String)]
        #[property(name = "icone", get = |n: &Self| n.view().icon.to_owned(), type = String)]
        #[property(name = "accessible", get = |n: &Self| n.view().accessible_name().to_owned(), type = String)]
        pub view: OnceCell<EditorNode>,
    }

    impl EditorNodeObject {
        pub fn view(&self) -> &EditorNode {
            self.view
                .get()
                .expect("node built by EditorNodeObject::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for EditorNodeObject {
        const NAME: &'static str = "AnnuaireNoeudEditeur";
        type Type = super::EditorNodeObject;
    }

    #[glib::derived_properties]
    impl ObjectImpl for EditorNodeObject {}
}

glib::wrapper! {
    /// A node of the tree of the editor (`NoeudEditeurObjet`).
    pub struct EditorNodeObject(ObjectSubclass<node::EditorNodeObject>);
}

impl EditorNodeObject {
    fn new(view: EditorNode) -> Self {
        let object: Self = glib::Object::new();
        let _ = object.imp().view.set(view);
        object
    }

    pub fn view(&self) -> &EditorNode {
        self.imp().view()
    }
}

fn store_of(nodes: &[EditorNode]) -> gio::ListStore {
    let store = gio::ListStore::new::<EditorNodeObject>();
    let objects: Vec<EditorNodeObject> = nodes.iter().cloned().map(EditorNodeObject::new).collect();
    store.extend_from_slice(&objects);
    store
}

/// What follows a write of the editor (the « Group Policy » window reads again).
pub type AfterWrite = Box<dyn Fn()>;

// --- The window ---------------------------------------------------------------------------------

mod imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/editeur-gpo.ui")]
    pub struct GpoEditor {
        #[template_child]
        pub split_view: TemplateChild<adw::NavigationSplitView>,
        #[template_child]
        pub gpo_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub tree_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub tree: TemplateChild<gtk::ListView>,
        #[template_child]
        pub tree_selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub content_page: TemplateChild<adw::NavigationPage>,
        #[template_child]
        pub page_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub folder_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub folder_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub draft_bar: TemplateChild<gtk::ActionBar>,
        #[template_child]
        pub draft_summary: TemplateChild<gtk::Label>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        pub gpo: OnceCell<EditedGpo>,
        pub sections: RefCell<Vec<Rc<dyn Section>>>,
        pub contents: RefCell<HashMap<ContentFile, Option<Vec<u8>>>>,
        pub roots: RefCell<Vec<EditorNode>>,
        pub pages: RefCell<Vec<(gtk::Widget, String)>>,
        pub folder_keys: RefCell<Vec<String>>,
        pub generation: Cell<u64>,
        pub actions: RefCell<HashMap<&'static str, gio::SimpleAction>>,
        pub after_write: RefCell<Option<AfterWrite>>,
        pub close_anyway: Cell<bool>,
        /// Instant of the last reading asked, and of its end (measures of the trials).
        pub asked_at: Cell<Option<Instant>>,
        pub read_at: Cell<Option<Instant>>,
    }

    impl std::fmt::Debug for GpoEditor {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GpoEditor").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for GpoEditor {
        const NAME: &'static str = "AnnuaireEditeurGpo";
        type Type = super::GpoEditor;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            EditorNodeObject::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::GpoEditor>(&[
                ("selected", |w, _| {
                    w.show();
                    None
                }),
                ("folder_activated", |w, args| {
                    if let Some(row) = args.get(1).and_then(|v| v.get::<gtk::ListBoxRow>().ok()) {
                        w.folder_activated(&row);
                    }
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for GpoEditor {}
    impl WidgetImpl for GpoEditor {}

    impl WindowImpl for GpoEditor {
        /// Closing with a draft: asked first (`_fermeture`).
        fn close_request(&self) -> glib::Propagation {
            let obj = self.obj();
            if obj.modifications().is_empty() || self.close_anyway.get() {
                self.generation.set(self.generation.get() + 1);
                return self.parent_close_request();
            }
            let alert = adw::AlertDialog::new(
                Some(&tr("Discard the changes?")),
                Some(&tr("The changes to this GPO have not been saved.")),
            );
            alert.add_response("rester", &tr("Continue"));
            alert.add_response("fermer", &tr("Discard"));
            alert.set_response_appearance("fermer", adw::ResponseAppearance::Destructive);
            alert.set_default_response(Some("rester"));
            let weak = obj.downgrade();
            alert.connect_response(None, move |_, response| {
                if response == "fermer"
                    && let Some(editor) = weak.upgrade()
                {
                    editor.imp().close_anyway.set(true);
                    editor.close();
                }
            });
            alert.present(Some(&*obj));
            glib::Propagation::Stop
        }
    }

    impl AdwWindowImpl for GpoEditor {}
}

glib::wrapper! {
    /// The content editor of a GPO (`AnnuaireEditeurGpo`).
    pub struct GpoEditor(ObjectSubclass<imp::GpoEditor>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl GpoEditor {
    pub fn new(
        gpo: EditedGpo,
        parent: &impl IsA<gtk::Window>,
        sections: Vec<Rc<dyn Section>>,
        after_write: Option<AfterWrite>,
    ) -> Self {
        let editor: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = editor.imp();
        editor.set_title(Some(&fill(&tr("Edit “{nom}”"), &[("nom", &gpo.name)])));
        imp.gpo_title.set_title(&gpo.name);
        imp.gpo_title.set_subtitle(&gpo.guid);
        let _ = imp.gpo.set(gpo);
        *imp.sections.borrow_mut() = sections;
        *imp.after_write.borrow_mut() = after_write;
        editor.install_actions();
        crate::a11y::name_menus(&editor);
        editor.reload();
        editor
    }

    pub fn gpo(&self) -> &EditedGpo {
        self.imp().gpo.get().expect("set by new")
    }

    // --- What the sections call ------------------------------------------------------------

    pub fn context(&self) -> Option<Arc<WriteContext>> {
        writes::context(self)
    }

    pub fn read_only(&self) -> bool {
        self.context().is_none_or(|c| c.profile.read_only)
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    /// The draft of a section changed: bar at the bottom and actions (`modifie`).
    pub fn changed(&self) {
        let imp = self.imp();
        let modifications = self.modifications();
        imp.draft_summary
            .set_label(&ev::changes_summary(&modifications));
        imp.draft_bar.set_revealed(!modifications.is_empty());
        let read_only = self.read_only();
        let actions = imp.actions.borrow();
        if let Some(a) = actions.get("enregistrer") {
            a.set_enabled(!modifications.is_empty() && !read_only);
        }
        if let Some(a) = actions.get("abandonner") {
            a.set_enabled(!modifications.is_empty());
        }
    }

    /// The nodes of a section changed: the tree is made again, the chosen node kept
    /// (`reconstruire`).
    pub fn rebuild(&self) {
        self.build_tree();
    }

    pub fn show_banner(&self, text: Option<&str>) {
        let imp = self.imp();
        imp.banner.set_title(text.unwrap_or_default());
        imp.banner.set_revealed(text.is_some_and(|t| !t.is_empty()));
    }

    /// Selects the node of key `key` (its parents expanded) (`choisir`).
    pub fn choose(&self, key: &str) {
        if let Some(model) = self
            .imp()
            .tree_selection
            .model()
            .and_downcast::<gtk::TreeListModel>()
        {
            self.choose_again(&model, key);
        }
    }

    pub fn modifications(&self) -> Vec<Modification> {
        let sections = self.imp().sections.borrow().clone();
        sections.iter().flat_map(|s| s.modifications()).collect()
    }

    pub fn chosen_node(&self) -> Option<EditorNode> {
        self.imp()
            .tree_selection
            .selected_item()
            .and_downcast::<gtk::TreeListRow>()
            .and_then(|row| row.item())
            .and_downcast::<EditorNodeObject>()
            .map(|n| n.view().clone())
    }

    // --- Actions --------------------------------------------------------------------------------

    fn install_actions(&self) {
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&GpoEditor);
        let plain: [(&'static str, Handler); 5] = [
            ("relire", Self::ask_reload),
            ("enregistrer", Self::save),
            ("abandonner", Self::discard),
            ("annuler", |w| crate::history::undo_last(w)),
            ("chercher", Self::search),
        ];
        for (name, handler) in plain {
            let action = gio::SimpleAction::new(name, None);
            let weak = self.downgrade();
            action.connect_activate(move |_, _| {
                if let Some(editor) = weak.upgrade() {
                    handler(&editor);
                }
            });
            group.add_action(&action);
            self.imp().actions.borrow_mut().insert(name, action);
        }
        self.insert_action_group("editeur", Some(&group));
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [
            ("<Control>f", "editeur.chercher"),
            ("<Control>s", "editeur.enregistrer"),
            ("<Control>z", "editeur.annuler"),
            ("F5", "editeur.relire"),
        ] {
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::NamedAction::new(action)),
            ));
        }
        self.add_controller(shortcuts);
        let escape = gtk::ShortcutController::new();
        escape.set_propagation_phase(gtk::PropagationPhase::Capture);
        let weak = self.downgrade();
        escape.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::CallbackAction::new(move |_, _| {
                weak.upgrade()
                    .map_or(glib::Propagation::Proceed, |editor| editor.escape())
            })),
        ));
        self.add_controller(escape);
        self.changed();
    }

    /// Ctrl+F: the search of the page shown, otherwise that of the administrative templates of
    /// the chosen part (`search`).
    fn search(&self) {
        let imp = self.imp();
        let sections = imp.sections.borrow().clone();
        let focus = |page: Option<gtk::Widget>| {
            page.is_some_and(|page| sections.iter().any(|s| s.focus_search(&page)))
        };
        if focus(imp.stack.visible_child()) {
            return;
        }
        let part = self
            .chosen_node()
            .and_then(|n| ev::part_of(&n.key, &imp.roots.borrow()))
            .unwrap_or(Part::Computer);
        self.choose(&ev::anchor_key(part, Anchor::Templates));
        focus(imp.stack.visible_child());
    }

    fn escape(&self) -> glib::Propagation {
        let imp = self.imp();
        if self.visible_dialog().is_some() {
            return glib::Propagation::Proceed;
        }
        let focus = gtk::prelude::GtkWindowExt::focus(self);
        let search = focus
            .as_ref()
            .and_then(|f| f.ancestor(gtk::SearchEntry::static_type()))
            .and_downcast::<gtk::SearchEntry>();
        if search.is_some_and(|s| !s.text().is_empty()) {
            return glib::Propagation::Proceed; // Escape empties the search first
        }
        if imp.split_view.is_collapsed() && imp.split_view.shows_content() {
            imp.split_view.set_show_content(false);
            return glib::Propagation::Stop;
        }
        self.close();
        glib::Propagation::Stop
    }

    fn ask_reload(&self) {
        if self.modifications().is_empty() {
            self.reload();
            return;
        }
        let alert = adw::AlertDialog::new(
            Some(&tr("Reload the GPO?")),
            Some(&tr("Unsaved changes will be discarded.")),
        );
        alert.add_response("non", &tr("Cancel"));
        alert.add_response("oui", &tr("Read Again"));
        alert.set_response_appearance("oui", adw::ResponseAppearance::Destructive);
        let weak = self.downgrade();
        alert.connect_response(None, move |_, response| {
            if response == "oui"
                && let Some(editor) = weak.upgrade()
            {
                editor.reload();
            }
        });
        alert.present(Some(self));
    }

    fn discard(&self) {
        let sections = self.imp().sections.borrow().clone();
        for s in &sections {
            s.discard();
        }
        self.changed();
        self.show();
    }

    fn save(&self) {
        let modifications = self.modifications();
        if modifications.is_empty() {
            return;
        }
        let Some(context) = self.context() else {
            writes::show_error(self, &tr("Cannot write"), &tr("No domain is open."), "");
            return;
        };
        let mut files: Vec<&ContentFile> = modifications.iter().map(|m| &m.file).collect();
        files.sort_by(|a, b| (a.part == Part::User, &a.path).cmp(&(b.part == Part::User, &b.path)));
        if files.windows(2).any(|w| w.first() == w.get(1)) {
            writes::show_error(
                self,
                &tr("Cannot write"),
                &tr("Two sections of the editor change the same file."),
                "",
            );
            return;
        }
        let (connection, dn) = (context.connection.clone(), self.gpo().dn.clone());
        let domain = context.profile.domain.clone();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let prepared =
                gio::spawn_blocking(move || prepare_write(&connection, &dn, &modifications)).await;
            let Some(editor) = weak.upgrade() else { return };
            match prepared {
                Ok(Ok(changeset)) => {
                    writes::propose(&editor, changeset, Options::default());
                }
                Ok(Err(error)) => {
                    let (message, detail) = gpo_error_message(&error, &domain);
                    writes::show_error(&editor, &tr("GPO not changed"), &message, &detail);
                }
                Err(_) => {}
            }
        });
    }

    /// Called by the common preview after a write (undo by the toast or Ctrl+Z included): the
    /// GPO is read again here, and the « Group Policy » window told (`apres_ecriture`).
    pub fn after_write(&self, _report: &Report) {
        self.reload();
        if let Some(after) = self.imp().after_write.borrow().as_ref() {
            after();
        }
    }

    // --- Reading --------------------------------------------------------------------------------

    /// Reads every file of the sections again; the drafts are discarded (`relire`).
    pub fn reload(&self) {
        let imp = self.imp();
        let Some(context) = self.context() else {
            imp.error.set_title(&tr("No domain open"));
            imp.tree_stack.set_visible_child_name("erreur");
            return;
        };
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.asked_at.set(Some(Instant::now()));
        imp.read_at.set(None);
        if imp.tree_selection.model().is_none() {
            imp.tree_stack.set_visible_child_name("chargement");
        }
        let sections = imp.sections.borrow().clone();
        let mut files: Vec<ContentFile> = Vec::new();
        for f in sections.iter().flat_map(|s| s.files()) {
            if !files.contains(&f) {
                files.push(f);
            }
        }
        let (connection, dn) = (context.connection.clone(), self.gpo().dn.clone());
        let domain = context.profile.domain.clone();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || read_contents(&connection, &dn, &files)).await;
            let Some(editor) = weak.upgrade() else { return };
            let imp = editor.imp();
            if generation != imp.generation.get() {
                return;
            }
            let contents = match read {
                Ok(Ok(contents)) => contents,
                Ok(Err(error)) => {
                    let (message, detail) = gpo_error_message(&error, &domain);
                    imp.error.set_title(&message);
                    imp.error
                        .set_description(Some(&glib::markup_escape_text(&detail)));
                    imp.tree_stack.set_visible_child_name("erreur");
                    return;
                }
                Err(_) => return,
            };
            imp.read_at.set(Some(Instant::now()));
            *imp.contents.borrow_mut() = contents.clone();
            let sections = imp.sections.borrow().clone();
            for s in &sections {
                let mine: HashMap<ContentFile, Option<Vec<u8>>> = s
                    .files()
                    .into_iter()
                    .map(|f| {
                        let content = contents.get(&f).cloned().flatten();
                        (f, content)
                    })
                    .collect();
                s.load(&editor, &mine);
            }
            editor.build_tree();
            editor.changed();
        });
    }

    // --- Tree -----------------------------------------------------------------------------------

    fn build_tree(&self) {
        let imp = self.imp();
        let key = self.chosen_node().map(|n| n.key);
        let sections = imp.sections.borrow().clone();
        let by_part: Vec<(Part, ev::AnchoredNodes)> = [Part::Computer, Part::User]
            .into_iter()
            .map(|part| (part, sections.iter().flat_map(|s| s.nodes(part)).collect()))
            .collect();
        let roots = ev::tree(&by_part);
        let store = store_of(&roots);
        let model = gtk::TreeListModel::new(store, false, false, |item| {
            let node = item.downcast_ref::<EditorNodeObject>()?;
            if node.view().children.is_empty() {
                return None;
            }
            Some(store_of(&node.view().children).upcast())
        });
        let first = imp.tree_selection.model().is_none();
        *imp.roots.borrow_mut() = roots.clone();
        imp.tree_selection.set_model(Some(&model));
        // The two parts and their policies expanded at once, as the GPMC.
        for i in (0..roots.len()).rev() {
            if let Some(row) = u32::try_from(i).ok().and_then(|i| model.row(i)) {
                row.set_expanded(true);
            }
        }
        imp.tree_stack.set_visible_child_name("arbre");
        if first {
            imp.tree.grab_focus();
        }
        let key = key.unwrap_or_else(|| ev::anchor_key(Part::Computer, Anchor::Templates));
        self.choose_again(&model, &key);
        self.show();
    }

    fn choose_again(&self, model: &gtk::TreeListModel, key: &str) {
        let imp = self.imp();
        let roots = imp.roots.borrow().clone();
        let path = ev::path_to(&roots, key);
        if path.is_empty() {
            imp.tree_selection.set_selected(0);
            return;
        }
        let mut position = 0u32;
        for (depth, n) in path.iter().enumerate() {
            loop {
                if position >= model.n_items() {
                    return;
                }
                let found = model.row(position).is_some_and(|row| {
                    row.depth() as usize == depth
                        && row
                            .item()
                            .and_downcast::<EditorNodeObject>()
                            .is_some_and(|o| o.view().key == n.key)
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
        let weak = self.downgrade();
        glib::idle_add_local_once(move || {
            if let Some(editor) = weak.upgrade() {
                editor.focus_on_choice();
            }
        });
    }

    /// The keyboard focus follows the selection if it is in the tree: a tree built again
    /// (store of the templates read) would leave it on the first row otherwise
    /// (`_focus_sur_choix`).
    fn focus_on_choice(&self) {
        let imp = self.imp();
        let position = imp.tree_selection.selected();
        if position == gtk::INVALID_LIST_POSITION {
            return;
        }
        let tree: &gtk::Widget = imp.tree.upcast_ref();
        let in_tree = gtk::prelude::GtkWindowExt::focus(self)
            .is_none_or(|f| &f == tree || f.is_ancestor(tree));
        let flags = if in_tree {
            gtk::ListScrollFlags::FOCUS
        } else {
            gtk::ListScrollFlags::NONE
        };
        imp.tree.scroll_to(position, flags, None);
    }

    // --- Page -----------------------------------------------------------------------------------

    fn section(&self, ident: &str) -> Option<Rc<dyn Section>> {
        self.imp()
            .sections
            .borrow()
            .iter()
            .find(|s| s.ident() == ident)
            .cloned()
    }

    /// The page of the chosen node (`_montrer`).
    pub fn show(&self) {
        let imp = self.imp();
        let Some(node) = self.chosen_node() else {
            return;
        };
        imp.page_title.set_title(&node.title);
        imp.content_page.set_title(&node.title);
        let roots = imp.roots.borrow().clone();
        let path = ev::path_to(&roots, &node.key);
        let parents: Vec<&str> = path
            .iter()
            .take(path.len().saturating_sub(1))
            .map(|n| n.title.as_str())
            .collect();
        imp.page_title.set_subtitle(&parents.join(" › "));
        let Some(section) = self.section(node.section) else {
            self.show_folder(&node);
            return;
        };
        let page = section.page(self, &node);
        let name = {
            let pages = imp.pages.borrow();
            pages
                .iter()
                .find(|(w, _)| *w == page)
                .map(|(_, n)| n.clone())
        };
        let name = name.unwrap_or_else(|| {
            let mut pages = imp.pages.borrow_mut();
            let name = format!("section-{}", pages.len());
            imp.stack.add_named(&page, Some(&name));
            pages.push((page.clone(), name.clone()));
            name
        });
        imp.stack.set_visible_child_name(&name);
    }

    /// Node of the editor (part, anchor): its children, to open by Enter (`_montrer_dossier`).
    fn show_folder(&self, node: &EditorNode) {
        let imp = self.imp();
        imp.folder_group
            .set_title(&glib::markup_escape_text(&node.title));
        while let Some(row) = imp.folder_list.row_at_index(0) {
            imp.folder_list.remove(&row);
        }
        let mut keys = Vec::new();
        for child in &node.children {
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&child.title).as_str())
                .activatable(true)
                .build();
            row.add_prefix(&gtk::Image::from_icon_name(child.icon));
            row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
            imp.folder_list.append(&row);
            keys.push(child.key.clone());
        }
        *imp.folder_keys.borrow_mut() = keys;
        imp.stack.set_visible_child_name("dossier");
    }

    fn folder_activated(&self, row: &gtk::ListBoxRow) {
        let key = usize::try_from(row.index())
            .ok()
            .and_then(|i| self.imp().folder_keys.borrow().get(i).cloned());
        if let Some(key) = key {
            self.choose(&key);
            self.imp().tree.grab_focus();
        }
    }

    // --- Trials ---------------------------------------------------------------------------------

    /// The tree is shown (trials).
    /// The summary of the draft at the bottom (trials).
    pub fn trial_draft(&self) -> String {
        self.imp().draft_summary.label().to_string()
    }

    pub fn trial_ready(&self) -> bool {
        self.imp().tree_stack.visible_child_name().as_deref() == Some("arbre")
    }

    /// (asked, read): instants of the last reading (trials).
    pub fn trial_times(&self) -> (Option<Instant>, Option<Instant>) {
        let imp = self.imp();
        (imp.asked_at.get(), imp.read_at.get())
    }

    /// The two first levels of the tree, and the number of nodes under each (trials).
    pub fn trial_tree(&self) -> Vec<String> {
        fn count(n: &EditorNode) -> usize {
            n.children.iter().map(|c| 1 + count(c)).sum()
        }
        fn walk(nodes: &[EditorNode], depth: usize, out: &mut Vec<String>) {
            for n in nodes {
                out.push(format!(
                    "{}{} [{}] ({})",
                    "  ".repeat(depth),
                    n.title,
                    n.key,
                    count(n)
                ));
                if depth < 3 {
                    walk(&n.children, depth + 1, out);
                }
            }
        }
        let mut out = Vec::new();
        walk(&self.imp().roots.borrow(), 0, &mut out);
        out
    }

    /// Saves the draft (trials: Ctrl+S).
    pub fn trial_save(&self) {
        self.save();
    }
}

// --- Reading and writing through the content API (J7.4, gpo_content) ------------------------------

/// The files of the sections, read on the SYSVOL of the write DC (the PDC emulator)
/// (`lire_contenus`). Blocking.
pub fn read_contents(
    connection: &annuaire_core::Connection,
    dn: &str,
    files: &[ContentFile],
) -> Result<HashMap<ContentFile, Option<Vec<u8>>>, GpoError> {
    let mut by_part: Vec<(Part, Vec<String>)> = Vec::new();
    for f in files {
        match by_part.iter_mut().find(|(p, _)| *p == f.part) {
            Some((_, paths)) => paths.push(f.path.clone()),
            None => by_part.push((f.part, vec![f.path.clone()])),
        }
    }
    let reads = gc::read_files(connection, dn, by_part.clone())?;
    let mut out = HashMap::new();
    for ((part, paths), read) in by_part.iter().zip(reads) {
        for path in paths {
            out.insert(
                ContentFile::new(*part, path),
                read.content(path)?.map(<[u8]>::to_vec),
            );
        }
    }
    Ok(out)
}

fn work(modifications: Vec<Modification>) -> Work {
    Arc::new(move |read| {
        let mut change = ContentChange::default();
        for m in &modifications {
            let new = (m.modify)(read.content(&m.file.path)?)?;
            change.files.push((m.file.path.clone(), new));
            if let Some(e) = &m.extension
                && !change.add_extensions.contains(e)
            {
                change.add_extensions.push(e.clone());
            }
            for e in &m.remove_extensions {
                if !change.remove_extensions.contains(e) {
                    change.remove_extensions.push(e.clone());
                }
            }
            change.remarks.extend(m.lines.iter().cloned());
        }
        Ok(change)
    })
}

/// One changeset for every change: files, version and extensions of each part touched; each
/// `modify` replayed on the content read again on the PDC; on Samba, the account policy of a
/// GPO linked to the root goes to the domain object too (`preparer_ecriture`). Blocking.
pub fn prepare_write(
    connection: &annuaire_core::Connection,
    dn: &str,
    modifications: &[Modification],
) -> Result<annuaire_core::changes::Changeset, GpoError> {
    let mut works = Vec::new();
    for part in [Part::Computer, Part::User] {
        let mine: Vec<Modification> = modifications
            .iter()
            .filter(|m| m.file.part == part)
            .cloned()
            .collect();
        if mine.is_empty() {
            continue;
        }
        let paths = mine.iter().map(|m| m.file.path.clone()).collect();
        works.push((part, paths, work(mine)));
    }
    gc::prepare_contents(connection, dn, works, true, Arc::new(AppCatalog))
}

/// The sections of the editor, in the order of `SECTIONS` of the Python application.
pub fn sections() -> Vec<Rc<dyn Section>> {
    vec![
        crate::templates::TemplatesSection::new(),
        crate::gpo_security::SecuritySection::new(),
        crate::preferences::PreferencesSection::new(),
    ]
}

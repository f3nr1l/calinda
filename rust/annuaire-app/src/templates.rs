// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Administrative Templates » section of the GPO editor (J7.3, `annuaire.ui.editeur_modeles`).
//!
//! Structure in `editeur-modeles.blp` (page), `dialogue-strategie.blp` (sheet of a policy) and
//! `dialogue-registre-brut.blp` (raw entry added or changed). The central store is read once
//! per editor (`admx_store::load`, local cache), at the same time as the `Registry.pol`; the
//! state of each policy comes from the file (`policies`), or from the draft if it is there. A
//! sheet « Apply » puts the setting in the draft; the editor writes it with those of the other
//! sections (Ctrl+S), replaying the draft on the `Registry.pol` read again just before the
//! preview. The entries the templates do not know stay in the file (« Extra Registry
//! Settings »). The raw registry is changed entry by entry too (add, change, remove), through
//! the same draft, replayed likewise on the file read again. An unreadable `Registry.pol`
//! blocks the writing of its part.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::time::Instant;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::registry_pol::{self as rp, Entry};
use annuaire_core::admx::{
    self as admx, Control, ControlKind, Element, ElementKind, Policy, Store,
};
use annuaire_core::admx_store::{self, LoadError};
use annuaire_core::gpo::Part;
use annuaire_core::gpo_content as gc;
use annuaire_core::gpo_write::GpoError;
use annuaire_core::policies::{
    self as pol, Footprint, OptionValue, Options, Registry, Setting, State,
};
use gtk::{gio, glib};

use crate::errors;
use crate::gpo_editor::{GpoEditor, Section};
use crate::gpo_editor_views::{
    Anchor, ContentFile, EditorNode, Modification, NodeData, part_label, part_value,
};
use crate::i18n::{fill, tr, tr_ctx};
use crate::scope::TemplateScope;
use crate::template_views::{
    self as tv, Addition, RawAction, RawForm, Row, States, TemplateView, ViewKind,
};
use crate::writes;

const PARTS: [Part; 2] = [Part::Computer, Part::User];

fn escape(text: &str) -> String {
    glib::markup_escape_text(text).to_string()
}

// --- A row of the list --------------------------------------------------------------------------

mod row {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::template_views::Row;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::RowObject)]
    pub struct RowObject {
        #[property(name = "titre", get = |r: &Self| r.view().title.clone(), type = String)]
        #[property(name = "sous-titre", get = |r: &Self| r.view().subtitle.clone(), type = String)]
        #[property(name = "a-sous-titre", get = |r: &Self| !r.view().subtitle.is_empty(), type = bool)]
        #[property(name = "icone", get = |r: &Self| r.view().icon.to_owned(), type = String)]
        #[property(name = "accessible", get = |r: &Self| r.view().accessible(), type = String)]
        #[property(name = "modifiee", get = |r: &Self| r.view().changed, type = bool)]
        pub view: OnceCell<Row>,
    }

    impl RowObject {
        pub fn view(&self) -> &Row {
            self.view.get().expect("row built by RowObject::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RowObject {
        const NAME: &'static str = "AnnuaireLigneModele";
        type Type = super::RowObject;
    }

    #[glib::derived_properties]
    impl ObjectImpl for RowObject {}
}

glib::wrapper! {
    /// A row of the list of policies (`LigneModeleObjet`).
    pub struct RowObject(ObjectSubclass<row::RowObject>);
}

impl RowObject {
    fn new(view: Row) -> Self {
        let object: Self = glib::Object::new();
        let _ = object.imp().view.set(view);
        object
    }
}

// --- The section --------------------------------------------------------------------------------

/// What the section knows of the store: not read yet, being read, read (`None`: no central
/// store on this DC), unreadable.
#[derive(Debug, Clone)]
enum StoreState {
    NotRead,
    Reading,
    Read(Option<Arc<Store>>),
    Error(String),
}

#[derive(Debug)]
struct Inner {
    editor: glib::WeakRef<GpoEditor>,
    store: StoreState,
    entries: HashMap<Part, Vec<Entry>>,
    unreadable: HashMap<Part, String>,
    states: HashMap<Part, States>,
    removals: HashMap<Part, Vec<Entry>>,
    additions: HashMap<Part, Vec<Addition>>,
    known: HashMap<Part, Footprint>,
    page: Option<TemplatesPage>,
    /// Instant the store was ready (measures of the trials).
    ready_at: Option<Instant>,
}

/// Administrative templates: the `Registry.pol` of each part and the central store
/// (`SectionModeles`).
#[derive(Debug)]
pub struct TemplatesSection {
    me: Weak<TemplatesSection>,
    inner: RefCell<Inner>,
}

impl TemplatesSection {
    pub fn new() -> Rc<Self> {
        Rc::new_cyclic(|me| Self {
            me: me.clone(),
            inner: RefCell::new(Inner {
                editor: glib::WeakRef::new(),
                store: StoreState::NotRead,
                entries: HashMap::new(),
                unreadable: HashMap::new(),
                states: HashMap::new(),
                removals: HashMap::new(),
                additions: HashMap::new(),
                known: HashMap::new(),
                page: None,
                ready_at: None,
            }),
        })
    }

    fn editor(&self) -> Option<GpoEditor> {
        self.inner.borrow().editor.upgrade()
    }

    pub fn store(&self) -> Option<Arc<Store>> {
        match &self.inner.borrow().store {
            StoreState::Read(store) => store.clone(),
            _ => None,
        }
    }

    pub fn states(&self, part: Part) -> States {
        self.inner
            .borrow()
            .states
            .get(&part)
            .cloned()
            .unwrap_or_default()
    }

    /// Takes a removal of a raw entry of the Registry.pol (« Extra Registry Settings » and
    /// « Registry (raw) »), put in the draft. An entry typed and not written yet leaves the
    /// draft; the one of the file it changed is removed (`retirer`).
    pub fn remove(&self, part: Part, entry: &Entry) {
        {
            let mut inner = self.inner.borrow_mut();
            let additions = inner.additions.entry(part).or_default();
            let addition = additions
                .iter()
                .position(|a| &a.1 == entry)
                .map(|i| additions.remove(i));
            let of_file = match addition {
                Some((old, _)) => old,
                None => Some(entry.clone()),
            };
            if let Some(e) = of_file {
                let removals = inner.removals.entry(part).or_default();
                if !removals.contains(&e) {
                    removals.push(e);
                }
            }
        }
        self.modified();
    }

    /// Raw entry added (`old` `None`) or changed, put in the draft. An entry already typed is
    /// replaced in the draft, which keeps the entry of the file it changed (`poser`).
    pub fn put(&self, part: Part, old: Option<&Entry>, new: Entry) {
        {
            let mut inner = self.inner.borrow_mut();
            let additions = inner.additions.entry(part).or_default();
            match old.and_then(|o| additions.iter_mut().find(|a| &a.1 == o)) {
                Some(slot) => slot.1 = new,
                None => additions.push((old.cloned(), new)),
            }
        }
        self.modified();
    }

    /// The entry comes from the draft (typed, not written yet) (`saisie`).
    pub fn typed(&self, part: Part, entry: &Entry) -> bool {
        self.inner
            .borrow()
            .additions
            .get(&part)
            .is_some_and(|a| a.iter().any(|x| &x.1 == entry))
    }

    /// The entries of the file as the draft of the raw registry will leave them (`brutes`).
    pub fn raw_entries(&self, part: Part) -> Vec<Entry> {
        let inner = self.inner.borrow();
        tv::apply_raw(
            inner.entries.get(&part).map_or(&[][..], Vec::as_slice),
            inner.removals.get(&part).map_or(&[][..], Vec::as_slice),
            inner.additions.get(&part).map_or(&[][..], Vec::as_slice),
        )
    }

    fn modified(&self) {
        if let Some(editor) = self.editor() {
            editor.changed();
        }
        self.refresh_page();
    }

    fn refresh_page(&self) {
        let page = self.inner.borrow().page.clone();
        if let Some(page) = page {
            page.refresh();
        }
    }

    /// Puts a setting in the draft (or takes it out if it comes back to what is read)
    /// (`regler`).
    pub fn set(&self, part: Part, policy: &str, setting: Setting) {
        self.inner
            .borrow_mut()
            .states
            .entry(part)
            .or_default()
            .set(policy, setting);
        self.modified();
    }

    /// Reason to refuse a change of this part, else `None` (`modifiable`).
    pub fn refusal(&self, part: Part) -> Option<String> {
        if let Some(error) = self.inner.borrow().unreadable.get(&part) {
            return Some(fill(
                &tr(
                    "The Registry.pol of this part is unreadable ({erreur}): nothing will be written to it.",
                ),
                &[("erreur", error)],
            ));
        }
        if self
            .editor()
            .and_then(|e| e.context())
            .is_some_and(|c| c.profile.read_only)
        {
            return Some(tr("Read-only profile."));
        }
        None
    }

    // --- Store and states ------------------------------------------------------------------

    fn read_store(&self) {
        let Some(editor) = self.editor() else { return };
        let Some(context) = editor.context() else {
            return;
        };
        self.inner.borrow_mut().store = StoreState::Reading;
        let connection = context.connection.clone();
        let domain = context.profile.domain.clone();
        let me = self.me.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || {
                let preferred = admx::preferred_languages(&|n| std::env::var(n).ok());
                admx_store::load(&connection, &preferred)
            })
            .await;
            let Some(section) = me.upgrade() else { return };
            match read {
                Ok(Ok(loading)) => {
                    {
                        let mut inner = section.inner.borrow_mut();
                        inner.store = StoreState::Read(loading.store.map(Arc::new));
                        inner.ready_at = Some(Instant::now());
                    }
                    section.compute();
                    section.banner();
                    if let Some(editor) = section.editor() {
                        editor.rebuild();
                    }
                }
                Ok(Err(error)) => {
                    let message = match error {
                        LoadError::Failure(f) => errors::failure_problem(&f, &domain).message,
                        LoadError::Sysvol(e) => errors::sysvol_problem(&e, "").1.message,
                    };
                    section.inner.borrow_mut().store = StoreState::Error(message);
                    section.banner();
                    section.refresh_page();
                }
                Err(_) => {}
            }
        });
    }

    /// States read of the policies configured, and what the templates know (`_calculer`).
    fn compute(&self) {
        let Some(store) = self.store() else { return };
        let mut inner = self.inner.borrow_mut();
        for part in PARTS {
            let class = tv::class_of(part);
            inner
                .known
                .entry(part)
                .or_insert_with(|| pol::store_footprint(&store, class));
            let entries = inner.entries.get(&part).cloned().unwrap_or_default();
            let registry = Registry::new(&entries);
            let read: HashMap<String, Setting> = pol::configured(&store, class, &entries)
                .into_iter()
                .filter_map(|ident| {
                    let p = store.policy(&ident)?;
                    Some((ident, pol::read_setting(p, &registry)))
                })
                .collect();
            inner.states.entry(part).or_default().read = read;
        }
    }

    pub fn extra(&self, part: Part) -> Vec<Entry> {
        let known = self.inner.borrow().known.get(&part).cloned();
        let Some(known) = known else {
            return Vec::new();
        };
        pol::extra(&known, &self.raw_entries(part))
    }

    fn banner(&self) {
        let Some(editor) = self.editor() else { return };
        let mut texts = Vec::new();
        let inner = self.inner.borrow();
        match &inner.store {
            StoreState::Error(e) => texts.push(fill(
                &tr("Unreadable administrative templates: {erreur}"),
                &[("erreur", e)],
            )),
            StoreState::Read(None) => {
                texts.push(tr(
                    "No central store of templates: only the raw registry is shown.",
                ));
            }
            StoreState::Read(Some(store)) if !store.errors.is_empty() => texts.push(fill(
                &tr("{n} problem(s) in the central store (files skipped or without texts)."),
                &[("n", &store.errors.len().to_string())],
            )),
            _ => {}
        }
        for part in PARTS {
            if let Some(error) = inner.unreadable.get(&part) {
                texts.push(fill(
                    &tr("{partie}: unreadable Registry.pol ({erreur})."),
                    &[("partie", &part_label(part)), ("erreur", error)],
                ));
            }
        }
        drop(inner);
        let text = texts.join(" ");
        editor.show_banner((!text.is_empty()).then_some(text.as_str()));
    }

    /// Instant the store was ready (trials).
    pub fn ready_at(&self) -> Option<Instant> {
        self.inner.borrow().ready_at
    }
}

impl Section for TemplatesSection {
    fn ident(&self) -> &'static str {
        tv::SECTION
    }

    fn files(&self) -> Vec<ContentFile> {
        PARTS
            .iter()
            .map(|p| ContentFile::new(*p, gc::REGISTRY_POL))
            .collect()
    }

    fn load(&self, editor: &GpoEditor, contents: &HashMap<ContentFile, Option<Vec<u8>>>) {
        let read_store;
        {
            let mut inner = self.inner.borrow_mut();
            inner.editor.set(Some(editor));
            inner.unreadable.clear();
            for part in PARTS {
                let raw = contents
                    .get(&ContentFile::new(part, gc::REGISTRY_POL))
                    .cloned()
                    .flatten();
                let entries = match raw.as_deref() {
                    Some(bytes) if !bytes.is_empty() => match rp::read(bytes) {
                        Ok(e) => e,
                        Err(e) => {
                            inner
                                .unreadable
                                .insert(part, crate::codec_texts::codec_message(&e.to_string()));
                            Vec::new()
                        }
                    },
                    _ => Vec::new(),
                };
                inner.entries.insert(part, entries);
                inner.states.insert(part, States::default());
                inner.removals.insert(part, Vec::new());
                inner.additions.insert(part, Vec::new());
            }
            read_store = matches!(inner.store, StoreState::NotRead);
        }
        if self.store().is_some() {
            self.compute();
        } else if read_store {
            self.read_store();
        }
        self.banner();
        self.refresh_page();
    }

    fn nodes(&self, part: Part) -> Vec<(Anchor, Vec<EditorNode>)> {
        let store = self.store();
        tv::nodes(store.as_deref(), part, !self.extra(part).is_empty())
    }

    fn page(&self, _editor: &GpoEditor, node: &EditorNode) -> gtk::Widget {
        let page = {
            let mut inner = self.inner.borrow_mut();
            inner
                .page
                .get_or_insert_with(|| TemplatesPage::new(self.me.clone()))
                .clone()
        };
        if let NodeData::Templates(view) = &node.data {
            page.show_view(view.clone());
        }
        page.upcast()
    }

    fn modifications(&self) -> Vec<Modification> {
        let store = self.store();
        let inner = self.inner.borrow();
        let mut out = Vec::new();
        for part in PARTS {
            let draft: Vec<(String, Setting)> = if store.is_some() {
                inner
                    .states
                    .get(&part)
                    .map(|s| s.draft.clone())
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let removals = inner.removals.get(&part).cloned().unwrap_or_default();
            let additions = inner.additions.get(&part).cloned().unwrap_or_default();
            if draft.is_empty() && removals.is_empty() && additions.is_empty() {
                continue;
            }
            let mut lines: Vec<String> = Vec::new();
            if let Some(store) = &store {
                lines.extend(draft.iter().filter_map(|(ident, setting)| {
                    store
                        .policy(ident)
                        .map(|p| tv::preview_line(p, part, setting))
                }));
            }
            lines.extend(removals.iter().map(|e| tv::removal_line(part, e)));
            lines.extend(
                additions
                    .iter()
                    .map(|(old, new)| tv::addition_line(part, old.as_ref(), new)),
            );
            let store = store.clone();
            out.push(Modification {
                file: ContentFile::new(part, gc::REGISTRY_POL),
                modify: Arc::new(move |raw: Option<&[u8]>| {
                    let current = match raw {
                        Some(bytes) if !bytes.is_empty() => {
                            rp::read(bytes).map_err(|e| GpoError::Invalid(e.to_string()))?
                        }
                        _ => Vec::new(),
                    };
                    let before = tv::apply_raw(&current, &removals, &additions);
                    let after = match &store {
                        Some(store) => tv::apply_settings(&before, store, &draft),
                        None => before,
                    };
                    rp::encode(&after)
                        .map(Some)
                        .map_err(|e| GpoError::Invalid(e.to_string()))
                }),
                extension: Some(gc::registry_extension(part)),
                lines,
                remove_extensions: Vec::new(),
            });
        }
        out
    }

    fn discard(&self) {
        {
            let mut inner = self.inner.borrow_mut();
            for s in inner.states.values_mut() {
                s.draft.clear();
            }
            for r in inner.removals.values_mut() {
                r.clear();
            }
            for a in inner.additions.values_mut() {
                a.clear();
            }
        }
        self.refresh_page();
    }

    fn focus_search(&self, page: &gtk::Widget) -> bool {
        let Some(page) = page.downcast_ref::<TemplatesPage>() else {
            return false;
        };
        page.focus_search();
        true
    }
}

// --- The page -----------------------------------------------------------------------------------

mod page_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/editeur-modeles.ui")]
    pub struct TemplatesPage {
        #[template_child]
        pub search: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub configured_only: TemplateChild<gtk::ToggleButton>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub list: TemplateChild<gtk::ListView>,
        #[template_child]
        pub selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub empty: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub loading_text: TemplateChild<gtk::Label>,
        #[template_child]
        pub entries_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub add_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub entries_list: TemplateChild<gtk::ListBox>,
        pub section: OnceCell<Weak<TemplatesSection>>,
        pub view: RefCell<Option<TemplateView>>,
        pub rows: RefCell<Vec<Row>>,
        /// Raw entries of the list, in the order of the rows.
        pub shown: RefCell<Vec<Entry>>,
        /// Measures: request of the last list, and list filled.
        pub searched_at: Cell<Option<Instant>>,
        pub shown_at: Cell<Option<Instant>>,
    }

    impl std::fmt::Debug for TemplatesPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TemplatesPage").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for TemplatesPage {
        const NAME: &'static str = "AnnuairePageModeles";
        type Type = super::TemplatesPage;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            RowObject::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::TemplatesPage>(&[
                ("search_changed", |p, _| {
                    p.refresh();
                    None
                }),
                ("filter_toggled", |p, _| {
                    p.refresh();
                    None
                }),
                ("activate_first", |p, _| {
                    p.first();
                    None
                }),
                ("activated", |p, args| {
                    if let Some(position) = args.get(1).and_then(|v| v.get::<u32>().ok()) {
                        p.activated(position);
                    }
                    None
                }),
                ("add", |p, _| {
                    p.input(None);
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for TemplatesPage {}
    impl WidgetImpl for TemplatesPage {}
    impl BinImpl for TemplatesPage {}
}

glib::wrapper! {
    /// The « Administrative Templates » page (`AnnuairePageModeles`).
    pub struct TemplatesPage(ObjectSubclass<page_imp::TemplatesPage>)
        @extends adw::Bin, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl TemplatesPage {
    fn new(section: Weak<TemplatesSection>) -> Self {
        let page: Self = glib::Object::new();
        let _ = page.imp().section.set(section);
        let shortcuts = gtk::ShortcutController::new();
        shortcuts.set_scope(gtk::ShortcutScope::Managed);
        type Handler = fn(&TemplatesPage) -> bool;
        let handlers: [(&str, Handler); 3] = [
            ("<Control><Shift>f", Self::toggle_filter),
            ("<Control>n", Self::shortcut_add),
            ("Delete", Self::shortcut_remove),
        ];
        for (trigger, handler) in handlers {
            let weak = page.downgrade();
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::CallbackAction::new(move |_, _| {
                    if weak.upgrade().is_some_and(|p| handler(&p)) {
                        glib::Propagation::Stop
                    } else {
                        glib::Propagation::Proceed
                    }
                })),
            ));
        }
        page.add_controller(shortcuts);
        let keys = gtk::EventControllerKey::new();
        let weak = page.downgrade();
        keys.connect_key_pressed(move |_, key, _, _| {
            // Down in the search: into the list.
            if key == gtk::gdk::Key::Down
                && let Some(page) = weak.upgrade()
                && page.imp().state.visible_child_name().as_deref() == Some("liste")
            {
                page.imp().list.grab_focus();
                return glib::Propagation::Stop;
            }
            glib::Propagation::Proceed
        });
        page.imp().search.add_controller(keys);
        page
    }

    fn section(&self) -> Option<Rc<TemplatesSection>> {
        self.imp().section.get().and_then(Weak::upgrade)
    }

    /// Ctrl+F of the editor.
    pub fn focus_search(&self) {
        let search = &self.imp().search;
        if search.parent().is_some_and(|p| p.is_visible()) {
            search.grab_focus();
        }
    }

    fn toggle_filter(&self) -> bool {
        let toggle = &self.imp().configured_only;
        toggle.set_active(!toggle.is_active());
        true
    }

    fn show_view(&self, view: TemplateView) {
        let imp = self.imp();
        let changed = imp.view.borrow().as_ref() != Some(&view);
        if changed {
            *imp.view.borrow_mut() = Some(view);
            if !imp.search.text().is_empty() {
                imp.search.set_text(""); // the search starts from the chosen node
            }
        }
        self.refresh();
    }

    pub fn refresh(&self) {
        let imp = self.imp();
        let (Some(view), Some(s)) = (imp.view.borrow().clone(), self.section()) else {
            return;
        };
        imp.searched_at.set(Some(Instant::now()));
        imp.shown_at.set(None);
        let store = s.store();
        let in_list = matches!(
            view.kind,
            ViewKind::Root | ViewKind::Category | ViewKind::All
        );
        if let Some(parent) = imp.search.parent() {
            parent.set_visible(in_list && store.is_some());
        }
        match view.kind {
            ViewKind::Raw => {
                self.show_entries(
                    &tr("All entries of Registry.pol"),
                    &tr("The file as it is, in its order, including what policies write."),
                    &s.raw_entries(view.part),
                );
                return;
            }
            ViewKind::Extra => {
                self.show_entries(
                    &tr("Extra Registry Settings"),
                    &tr(
                        "Registry.pol entries that no administrative template of the central store describes. They are kept as they are on every write.",
                    ),
                    &s.extra(view.part),
                );
                return;
            }
            _ => {}
        }
        let Some(store) = store else {
            let waiting = matches!(
                s.inner.borrow().store,
                StoreState::Reading | StoreState::NotRead
            );
            imp.state
                .set_visible_child_name(if waiting { "chargement" } else { "absent" });
            return;
        };
        let rows = tv::rows(
            &store,
            view.part,
            &view,
            &s.states(view.part),
            &imp.search.text(),
            imp.configured_only.is_active(),
        );
        self.fill(rows);
    }

    fn fill(&self, rows: Vec<Row>) {
        let imp = self.imp();
        let old = usize::try_from(imp.selection.selected())
            .ok()
            .and_then(|i| imp.rows.borrow().get(i).and_then(|r| r.policy.clone()));
        let store = gio::ListStore::new::<RowObject>();
        let objects: Vec<RowObject> = rows.iter().cloned().map(RowObject::new).collect();
        store.extend_from_slice(&objects);
        *imp.rows.borrow_mut() = rows.clone();
        imp.selection.set_model(Some(&store));
        if rows.is_empty() {
            let text = imp.search.text().trim().to_owned();
            imp.empty.set_title(&tr("No Policy"));
            let description = if !text.is_empty() {
                fill(&tr("Nothing matches “{texte}”."), &[("texte", &text)])
            } else if imp.configured_only.is_active() {
                tr("No setting configured here.")
            } else {
                tr("This folder is empty.")
            };
            imp.empty.set_description(Some(&escape(&description)));
            imp.state.set_visible_child_name("vide");
        } else {
            imp.state.set_visible_child_name("liste");
            if let Some(old) = old
                && let Some(rank) = rows
                    .iter()
                    .position(|r| r.policy.as_deref() == Some(old.as_str()))
                && let Ok(rank) = u32::try_from(rank)
            {
                imp.selection.set_selected(rank);
            }
        }
        imp.shown_at.set(Some(Instant::now()));
    }

    fn show_entries(&self, title: &str, description: &str, entries: &[Entry]) {
        let imp = self.imp();
        let (Some(view), Some(s)) = (imp.view.borrow().clone(), self.section()) else {
            return;
        };
        let part = view.part;
        imp.entries_group.set_title(&escape(title));
        imp.entries_group
            .set_description(Some(&escape(description)));
        while let Some(row) = imp.entries_list.row_at_index(0) {
            imp.entries_list.remove(&row);
        }
        let refusal = s.refusal(part);
        imp.add_button.set_sensitive(refusal.is_none());
        *imp.shown.borrow_mut() = entries.to_vec();
        for entry in entries {
            let (name, detail) = tv::raw_row(part, entry);
            let row = adw::ActionRow::builder()
                .title(escape(&name).as_str())
                .subtitle(escape(&detail).as_str())
                .subtitle_lines(0)
                .build();
            row.add_css_class("property");
            if refusal.is_none() && tv::raw_form(Some(entry)).is_some() {
                // Enter (or a click) opens the change of the entry.
                row.set_activatable(true);
                let (weak, e) = (self.downgrade(), entry.clone());
                row.connect_activated(move |_| {
                    if let Some(page) = weak.upgrade() {
                        page.input(Some(e.clone()));
                    }
                });
            } else {
                row.set_subtitle_selectable(true);
            }
            if s.typed(part, entry) {
                let mark = gtk::Image::from_icon_name("document-edit-symbolic");
                mark.add_css_class("accent");
                mark.set_tooltip_text(Some(&tr("Changed, not saved yet")));
                row.add_prefix(&mark);
                row.upcast_ref::<gtk::Widget>().update_property(&[
                    gtk::accessible::Property::Description(&tr_ctx(
                        "feminine",
                        "Changed, not saved yet",
                    )),
                ]);
            }
            let remove = gtk::Button::builder()
                .icon_name("user-trash-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text(tr("Remove this entry from Registry.pol").as_str())
                .sensitive(refusal.is_none())
                .build();
            remove.add_css_class("flat");
            remove.update_property(&[gtk::accessible::Property::Label(&fill(
                &tr("Remove the entry {nom}"),
                &[("nom", &name)],
            ))]);
            let (weak, e) = (Rc::downgrade(&s), entry.clone());
            remove.connect_clicked(move |_| {
                if let Some(section) = weak.upgrade() {
                    section.remove(part, &e);
                }
            });
            row.add_suffix(&remove);
            imp.entries_list.append(&row);
        }
        if entries.is_empty() {
            imp.entries_list.append(
                &adw::ActionRow::builder()
                    .title(tr("No entry").as_str())
                    .subtitle(tr("The file is missing or empty.").as_str())
                    .build(),
            );
        }
        imp.state.set_visible_child_name("entrees");
        imp.shown_at.set(Some(Instant::now()));
    }

    /// Ctrl+N in « Registry (raw) » or « Extra Registry Settings ».
    fn shortcut_add(&self) -> bool {
        let imp = self.imp();
        if imp.state.visible_child_name().as_deref() != Some("entrees")
            || !imp.add_button.is_sensitive()
        {
            return false;
        }
        self.input(None);
        true
    }

    /// Delete on a raw entry: removed in the draft, the focus on the next one.
    fn shortcut_remove(&self) -> bool {
        let imp = self.imp();
        let (Some(view), Some(s)) = (imp.view.borrow().clone(), self.section()) else {
            return false;
        };
        if imp.state.visible_child_name().as_deref() != Some("entrees")
            || s.refusal(view.part).is_some()
        {
            return false;
        }
        let Some(row) = imp
            .entries_list
            .focus_child()
            .and_downcast::<gtk::ListBoxRow>()
        else {
            return false;
        };
        let Some(rank) = usize::try_from(row.index()).ok() else {
            return false;
        };
        let Some(entry) = imp.shown.borrow().get(rank).cloned() else {
            return false;
        };
        let (name, _) = tv::raw_row(view.part, &entry);
        s.remove(view.part, &entry);
        let n = imp.shown.borrow().len();
        let next = rank.min(n.saturating_sub(1));
        if let Some(row) = i32::try_from(next)
            .ok()
            .and_then(|i| imp.entries_list.row_at_index(i))
        {
            row.grab_focus();
        }
        writes::announce(
            self,
            &fill(
                &tr("Entry {nom} removed in the draft (Ctrl+S saves)."),
                &[("nom", &name)],
            ),
            None,
        );
        true
    }

    /// Dialog of a raw entry: new (`entry` `None`) or to change (`_saisir`).
    fn input(&self, entry: Option<Entry>) {
        let (Some(view), Some(s)) = (self.imp().view.borrow().clone(), self.section()) else {
            return;
        };
        let (refuse, apply) = (Rc::downgrade(&s), Rc::downgrade(&s));
        let old = entry.clone();
        RawDialog::new(
            view.part,
            entry.as_ref(),
            Box::new(move |part| refuse.upgrade().and_then(|s| s.refusal(part))),
            Box::new(move |part, new| {
                if let Some(section) = apply.upgrade() {
                    section.put(part, old.as_ref(), new);
                }
            }),
        )
        .present(Some(self));
    }

    /// Enter in the search: the first policy found opens (`activate_first`).
    fn first(&self) {
        let imp = self.imp();
        if imp.state.visible_child_name().as_deref() != Some("liste") {
            return;
        }
        let first = imp.rows.borrow().first().cloned();
        if let Some(row) = first {
            imp.selection.set_selected(0);
            self.open(&row);
        }
    }

    fn activated(&self, position: u32) {
        let row = usize::try_from(position)
            .ok()
            .and_then(|i| self.imp().rows.borrow().get(i).cloned());
        if let Some(row) = row {
            self.open(&row);
        }
    }

    fn open(&self, row: &Row) {
        let (Some(view), Some(s)) = (self.imp().view.borrow().clone(), self.section()) else {
            return;
        };
        if let Some(category) = &row.category {
            if let Some(editor) = s.editor() {
                editor.choose(&format!(
                    "{}:{}:{category}",
                    tv::SECTION,
                    part_value(view.part)
                ));
            }
            return;
        }
        let (Some(ident), Some(store)) = (row.policy.clone(), s.store()) else {
            return;
        };
        let Some(policy) = store.policy(&ident).cloned() else {
            return;
        };
        let part = view.part;
        let weak = Rc::downgrade(&s);
        PolicyDialog::new(
            &policy,
            part,
            &s.states(part).setting(&ident),
            Some(&store),
            s.refusal(part),
            Box::new(move |setting| {
                if let Some(section) = weak.upgrade() {
                    section.set(part, &ident, setting);
                }
            }),
        )
        .present(Some(self));
    }

    // --- Trials ---------------------------------------------------------------------------------

    /// What the list or the entries show (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let imp = self.imp();
        if imp.state.visible_child_name().as_deref() == Some("entrees") {
            let mut out = Vec::new();
            let mut i = 0;
            while let Some(row) = imp.entries_list.row_at_index(i) {
                if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                    out.push(format!(
                        "{} | {}",
                        r.title(),
                        r.subtitle().unwrap_or_default()
                    ));
                }
                i += 1;
            }
            return out;
        }
        imp.rows
            .borrow()
            .iter()
            .map(|r| format!("{} | {}", r.title, r.subtitle))
            .collect()
    }

    /// Opens the sheet of the policy `ident` of the list (trials).
    pub fn trial_open(&self, ident: &str) -> bool {
        let row = self
            .imp()
            .rows
            .borrow()
            .iter()
            .find(|r| r.policy.as_deref() == Some(ident))
            .cloned();
        match row {
            Some(row) => {
                self.open(&row);
                true
            }
            None => false,
        }
    }

    /// The dialog of a new raw entry (trials).
    pub fn trial_input(&self) {
        self.input(None);
    }

    /// Removes the raw entry of rank `rank` (trials).
    pub fn trial_remove(&self, rank: usize) {
        let entry = self.imp().shown.borrow().get(rank).cloned();
        let (Some(view), Some(s), Some(entry)) =
            (self.imp().view.borrow().clone(), self.section(), entry)
        else {
            return;
        };
        s.remove(view.part, &entry);
    }

    pub fn trial_search(&self, text: &str) {
        self.imp().search.set_text(text);
        self.refresh();
    }

    pub fn trial_times(&self) -> (Option<Instant>, Option<Instant>) {
        let imp = self.imp();
        (imp.searched_at.get(), imp.shown_at.get())
    }
}

// --- Sheet of a policy --------------------------------------------------------------------------

type ReadOption = Box<dyn Fn() -> Option<OptionValue>>;

/// An option in the sheet: its widget, its value, its error (`_Champ`).
pub struct Field {
    element: Element,
    row: gtk::Widget,
    read: ReadOption,
}

impl std::fmt::Debug for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Field")
            .field("element", &self.element.id)
            .finish_non_exhaustive()
    }
}

impl Field {
    fn error(&self, text: Option<&str>) {
        if text.is_some() {
            self.row.add_css_class("error");
        } else {
            self.row.remove_css_class("error");
        }
        self.row.set_tooltip_text(text);
    }
}

fn text_lines(view: &gtk::TextView) -> Vec<String> {
    let buffer = view.buffer();
    let text = buffer.text(&buffer.start_iter(), &buffer.end_iter(), false);
    text.split('\n')
        .filter(|l| !l.trim().is_empty())
        .map(str::to_owned)
        .collect()
}

/// What follows « Apply » in the sheet.
type ApplySetting = Box<dyn Fn(Setting)>;

mod policy_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-strategie.ui")]
    pub struct PolicyDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub apply_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub state_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub not_configured: TemplateChild<gtk::CheckButton>,
        #[template_child]
        pub enabled: TemplateChild<gtk::CheckButton>,
        #[template_child]
        pub disabled: TemplateChild<gtk::CheckButton>,
        #[template_child]
        pub options_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub supported_on: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub registry: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub file: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub help: TemplateChild<gtk::Label>,
        pub policy: OnceCell<Policy>,
        pub fields: RefCell<Vec<Field>>,
        pub refusal: RefCell<Option<String>>,
        pub apply: RefCell<Option<ApplySetting>>,
        pub ready: Cell<bool>,
    }

    impl std::fmt::Debug for PolicyDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PolicyDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PolicyDialog {
        const NAME: &'static str = "AnnuaireDialogueStrategie";
        type Type = super::PolicyDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PolicyDialog>(&[
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("apply", |d, _| {
                    d.apply();
                    None
                }),
                ("state_changed", |d, _| {
                    d.validate();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PolicyDialog {}
    impl WidgetImpl for PolicyDialog {}
    impl AdwDialogImpl for PolicyDialog {}
}

glib::wrapper! {
    /// Sheet of a policy: state, options, information, help (`AnnuaireDialogueStrategie`).
    pub struct PolicyDialog(ObjectSubclass<policy_imp::PolicyDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl PolicyDialog {
    pub fn new(
        policy: &Policy,
        part: Part,
        setting: &Setting,
        store: Option<&Store>,
        refusal: Option<String>,
        apply: ApplySetting,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.policy.set(policy.clone());
        *imp.refusal.borrow_mut() = refusal.clone();
        *imp.apply.borrow_mut() = Some(apply);
        dialog.set_title(&policy.label);
        imp.title.set_title(&policy.label);
        let path: Vec<String> = store
            .map(|s| {
                s.path(policy.category.as_deref())
                    .iter()
                    .map(|c| c.label.clone())
                    .collect()
            })
            .unwrap_or_default();
        imp.title.set_subtitle(&if path.is_empty() {
            part_label(part)
        } else {
            path.join(" › ")
        });
        let mut description = part_label(part);
        if setting.state == State::Undetermined {
            description = tr(
                "The Registry.pol sets values of this policy that its template does not expect. Choosing a state replaces them.",
            );
        }
        if let Some(r) = &refusal {
            description.clone_from(r);
        }
        imp.state_group.set_description(Some(&escape(&description)));
        imp.supported_on
            .set_subtitle(&escape(&if policy.supported.is_empty() {
                tr("(not specified)")
            } else {
                policy.supported.clone()
            }));
        let key = format!("{}\\{}", tv::hive(part), policy.key);
        imp.registry
            .set_subtitle(&escape(&if policy.value_name.is_empty() {
                key
            } else {
                format!("{key}\\{}", policy.value_name)
            }));
        imp.file
            .set_subtitle(&escape(&format!("{} · {}", policy.file, policy.name)));
        imp.help.set_label(&if policy.explain.is_empty() {
            tr("No explanation in the template.")
        } else {
            policy.explain.clone()
        });
        let mut options = if setting.state == State::Enabled {
            setting.options.clone()
        } else {
            pol::default_options(policy)
        };
        if setting.state == State::Enabled {
            // An option the file does not say takes the value proposed by default.
            for (k, v) in pol::default_options(policy) {
                if options.get(&k).cloned().flatten().is_none() {
                    options.insert(k, v);
                }
            }
        }
        dialog.build_options(&options);
        let button: &gtk::CheckButton = match setting.state {
            State::Enabled => &imp.enabled,
            State::Disabled => &imp.disabled,
            _ => &imp.not_configured,
        };
        button.set_active(true);
        // Starting focus on the current state (otherwise on the selectable explanation, which
        // would be shown all selected).
        dialog.set_focus(Some(button));
        if setting.state == State::Undetermined {
            imp.not_configured.set_active(false);
            imp.enabled.set_active(false);
        }
        let shortcut = gtk::ShortcutController::new();
        let weak = dialog.downgrade();
        shortcut.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>Return"),
            Some(gtk::CallbackAction::new(move |_, _| {
                if let Some(d) = weak.upgrade() {
                    d.apply();
                }
                glib::Propagation::Stop
            })),
        ));
        dialog.add_controller(shortcut);
        imp.ready.set(true);
        dialog.validate();
        dialog
    }

    fn policy(&self) -> &Policy {
        self.imp().policy.get().expect("set by new")
    }

    // --- Options ----------------------------------------------------------------------------

    fn build_options(&self, options: &Options) {
        let s = self.policy().clone();
        let mut seen = Vec::new();
        for control in &s.presentation {
            if control.kind == ControlKind::Static {
                let label = gtk::Label::builder()
                    .label(control.label.as_str())
                    .xalign(0.0)
                    .wrap(true)
                    .build();
                label.add_css_class("dim-label");
                self.imp().options_group.add(&label);
                continue;
            }
            let Some(element) = s.element(&control.ref_id) else {
                continue;
            };
            seen.push(element.id.clone());
            self.add_field(
                element,
                options.get(&element.id).cloned().flatten(),
                &control.label,
                Some(control),
            );
        }
        // Options without presentation: under their identifier.
        for element in &s.elements {
            if !seen.contains(&element.id) {
                self.add_field(
                    element,
                    options.get(&element.id).cloned().flatten(),
                    &element.id,
                    None,
                );
            }
        }
        if s.elements.is_empty() {
            self.imp().options_group.set_visible(false);
        }
    }

    fn changed_callback(&self) -> impl Fn() + 'static {
        let weak = self.downgrade();
        move || {
            if let Some(d) = weak.upgrade() {
                d.validate();
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn add_field(
        &self,
        e: &Element,
        value: Option<OptionValue>,
        label: &str,
        control: Option<&Control>,
    ) {
        let imp = self.imp();
        let trimmed = label.trim_end_matches([' ', ':']);
        let title = escape(if trimmed.is_empty() { &e.id } else { trimmed });
        let changed = self.changed_callback();
        let (row, read): (gtk::Widget, ReadOption) = match e.kind {
            ElementKind::Boolean => {
                let check = adw::SwitchRow::builder()
                    .title(title.as_str())
                    .active(matches!(value, Some(OptionValue::Bool(true))))
                    .build();
                check.connect_active_notify(move |_| changed());
                let c = check.clone();
                (
                    check.upcast(),
                    Box::new(move || Some(OptionValue::Bool(c.is_active()))),
                )
            }
            ElementKind::Decimal | ElementKind::Long => {
                let step = control.map_or(1, |c| c.step).max(1);
                #[allow(clippy::cast_precision_loss)]
                let number =
                    adw::SpinRow::with_range(e.minimum as f64, e.maximum as f64, step as f64);
                number.set_title(&title);
                number.set_digits(0);
                number.set_numeric(true);
                if let Some(OptionValue::Int(n)) = value {
                    #[allow(clippy::cast_precision_loss)]
                    number.set_value(n as f64);
                }
                number.connect_value_notify(move |_| changed());
                let n = number.clone();
                #[allow(clippy::cast_possible_truncation)]
                let read: ReadOption = Box::new(move || Some(OptionValue::Int(n.value() as i128)));
                (number.upcast(), read)
            }
            ElementKind::Text => {
                let text = match &value {
                    Some(OptionValue::Text(t)) => t.clone(),
                    Some(OptionValue::Int(n)) => n.to_string(),
                    _ => String::new(),
                };
                let entry = adw::EntryRow::builder()
                    .title(title.as_str())
                    .text(text.as_str())
                    .build();
                entry.connect_changed(move |_| changed());
                if let Some(c) = control.filter(|c| !c.suggestions.is_empty()) {
                    let strings: Vec<&str> = c.suggestions.iter().map(String::as_str).collect();
                    let choice = gtk::DropDown::from_strings(&strings);
                    choice.set_valign(gtk::Align::Center);
                    choice.set_tooltip_text(Some(&tr("Suggestions")));
                    choice.update_property(&[gtk::accessible::Property::Label(&tr("Suggestions"))]);
                    choice.set_selected(gtk::INVALID_LIST_POSITION);
                    let target = entry.clone();
                    choice.connect_selected_item_notify(move |d| {
                        if let Some(item) = d.selected_item().and_downcast::<gtk::StringObject>() {
                            target.set_text(&item.string());
                        }
                    });
                    entry.add_suffix(&choice);
                }
                let t = entry.clone();
                (
                    entry.upcast(),
                    Box::new(move || Some(OptionValue::Text(t.text().to_string()))),
                )
            }
            ElementKind::Enum => {
                let mut order: Vec<usize> = (0..e.choices.len()).collect();
                if control.is_none_or(|c| c.sort) {
                    order.sort_by_cached_key(|&i| e.choices.get(i).map(|c| admx::fold(&c.label)));
                }
                let labels: Vec<&str> = order
                    .iter()
                    .filter_map(|&i| e.choices.get(i).map(|c| c.label.as_str()))
                    .collect();
                let combo = adw::ComboRow::builder()
                    .title(title.as_str())
                    .model(&gtk::StringList::new(&labels))
                    .build();
                let selected = match value {
                    Some(OptionValue::Int(i)) => usize::try_from(i)
                        .ok()
                        .and_then(|i| order.iter().position(|&o| o == i))
                        .and_then(|p| u32::try_from(p).ok())
                        .unwrap_or(gtk::INVALID_LIST_POSITION),
                    _ => gtk::INVALID_LIST_POSITION,
                };
                combo.set_selected(selected);
                combo.connect_selected_notify(move |_| changed());
                let c = combo.clone();
                let read: ReadOption = Box::new(move || {
                    let rank = usize::try_from(c.selected()).ok()?;
                    order
                        .get(rank)
                        .and_then(|&o| i128::try_from(o).ok())
                        .map(OptionValue::Int)
                });
                (combo.upcast(), read)
            }
            ElementKind::List | ElementKind::MultiText => {
                // One value per line.
                let explicit = e.kind == ElementKind::List && e.explicit;
                let header = adw::ActionRow::builder()
                    .title(title.as_str())
                    .subtitle(
                        if explicit {
                            tr("One “name = value” line per entry")
                        } else {
                            tr("One value per line")
                        }
                        .as_str(),
                    )
                    .build();
                let view = gtk::TextView::builder()
                    .top_margin(6)
                    .bottom_margin(6)
                    .left_margin(8)
                    .right_margin(8)
                    .accepts_tab(false)
                    .build();
                view.add_css_class("monospace");
                let name = label.trim_end_matches([' ', ':']);
                view.update_property(&[gtk::accessible::Property::Label(if name.is_empty() {
                    &e.id
                } else {
                    name
                })]);
                let text = match &value {
                    Some(OptionValue::Pairs(p)) => p
                        .iter()
                        .map(|(n, v)| format!("{n} = {v}"))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    Some(OptionValue::Texts(t)) => t.join("\n"),
                    _ => String::new(),
                };
                view.buffer().set_text(&text);
                view.buffer().connect_changed(move |_| changed());
                let frame = gtk::Frame::builder()
                    .child(
                        &gtk::ScrolledWindow::builder()
                            .child(&view)
                            .min_content_height(90)
                            .build(),
                    )
                    .build();
                let column = gtk::Box::new(gtk::Orientation::Vertical, 6);
                let list = gtk::ListBox::builder()
                    .selection_mode(gtk::SelectionMode::None)
                    .build();
                list.add_css_class("boxed-list");
                list.append(&header);
                column.append(&list);
                column.append(&frame);
                imp.options_group.add(&column);
                let read: ReadOption = Box::new(move || {
                    let lines = text_lines(&view);
                    Some(if explicit {
                        OptionValue::Pairs(
                            lines
                                .iter()
                                .map(|l| {
                                    let (n, v) = l.split_once('=').unwrap_or((l, ""));
                                    (n.trim().to_owned(), v.trim().to_owned())
                                })
                                .collect(),
                        )
                    } else {
                        OptionValue::Texts(lines.iter().map(|l| l.trim().to_owned()).collect())
                    })
                });
                imp.fields.borrow_mut().push(Field {
                    element: e.clone(),
                    row: frame.upcast(),
                    read,
                });
                return;
            }
        };
        imp.options_group.add(&row);
        imp.fields.borrow_mut().push(Field {
            element: e.clone(),
            row,
            read,
        });
    }

    fn options(&self) -> Options {
        self.imp()
            .fields
            .borrow()
            .iter()
            .map(|f| (f.element.id.clone(), (f.read)()))
            .collect()
    }

    fn state(&self) -> Option<State> {
        let imp = self.imp();
        if imp.enabled.is_active() {
            Some(State::Enabled)
        } else if imp.disabled.is_active() {
            Some(State::Disabled)
        } else if imp.not_configured.is_active() {
            Some(State::NotConfigured)
        } else {
            None
        }
    }

    // --- Validation -----------------------------------------------------------------------------

    fn validate(&self) -> bool {
        let imp = self.imp();
        if !imp.ready.get() {
            return false;
        }
        let state = self.state();
        imp.options_group
            .set_sensitive(state == Some(State::Enabled));
        let errors = if state == Some(State::Enabled) {
            pol::validate(self.policy(), &self.options())
        } else {
            std::collections::BTreeMap::new()
        };
        let mut texts = Vec::new();
        for f in imp.fields.borrow().iter() {
            let error = errors.get(&f.element.id).map(tv::option_error_text);
            f.error(error.as_deref());
            if let Some(error) = error {
                texts.push(format!(
                    "{} : {error}",
                    tv::element_label(self.policy(), &f.element)
                ));
            }
        }
        let description = (!texts.is_empty()).then(|| escape(&texts.join("\n")));
        imp.options_group.set_description(description.as_deref());
        imp.apply_button
            .set_sensitive(errors.is_empty() && state.is_some() && imp.refusal.borrow().is_none());
        errors.is_empty()
    }

    fn apply(&self) {
        let Some(state) = self.state() else { return };
        if !self.validate() || self.imp().refusal.borrow().is_some() {
            return;
        }
        let options = if state == State::Enabled {
            self.options()
        } else {
            Options::new()
        };
        let apply = self.imp().apply.take();
        self.close();
        if let Some(apply) = apply {
            apply(Setting { state, options });
        }
    }

    // --- Trials ---------------------------------------------------------------------------------

    /// Chooses a state and applies (trials).
    pub fn trial_apply(&self, state: State) {
        let imp = self.imp();
        match state {
            State::Enabled => imp.enabled.set_active(true),
            State::Disabled => imp.disabled.set_active(true),
            _ => imp.not_configured.set_active(true),
        }
        self.apply();
    }
}

// --- Raw entry ----------------------------------------------------------------------------------

/// Reason to refuse the part chosen in the dialog.
type Refuse = Box<dyn Fn(Part) -> Option<String>>;
/// What follows « Apply »: the part and the entry.
type ApplyEntry = Box<dyn Fn(Part, Entry)>;

mod raw_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-registre-brut.ui")]
    pub struct RawDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub apply_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub part_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub action_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub key_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub name_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub type_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub data_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub decimal_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub multiple_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub multi_text: TemplateChild<gtk::TextView>,
        #[template_child]
        pub message: TemplateChild<gtk::Label>,
        pub refuse: RefCell<Option<Refuse>>,
        pub apply: RefCell<Option<ApplyEntry>>,
        pub ready: Cell<bool>,
    }

    impl std::fmt::Debug for RawDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("RawDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for RawDialog {
        const NAME: &'static str = "AnnuaireDialogueRegistreBrut";
        type Type = super::RawDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::RawDialog>(&[
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("apply", |d, _| {
                    d.apply();
                    None
                }),
                ("changed", |d, _| {
                    d.changed();
                    None
                }),
                ("base_changed", |d, _| {
                    d.base_changed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for RawDialog {}
    impl WidgetImpl for RawDialog {}
    impl AdwDialogImpl for RawDialog {}
}

glib::wrapper! {
    /// Addition or change of an entry of the `Registry.pol`: part, action (set, delete the value,
    /// delete every value of the key), key, name, type and data checked as typed. « Apply » (or
    /// Ctrl+Enter) puts the entry in the draft (`AnnuaireDialogueRegistreBrut`).
    pub struct RawDialog(ObjectSubclass<raw_imp::RawDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

fn index_of<T: PartialEq>(list: &[T], value: &T) -> u32 {
    list.iter()
        .position(|x| x == value)
        .and_then(|i| u32::try_from(i).ok())
        .unwrap_or(0)
}

impl RawDialog {
    pub fn new(part: Part, entry: Option<&Entry>, refuse: Refuse, apply: ApplyEntry) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.refuse.borrow_mut() = Some(refuse);
        *imp.apply.borrow_mut() = Some(apply);
        let form = tv::raw_form(entry).unwrap_or_default();
        if entry.is_some() {
            dialog.set_title(&tr("Edit the registry entry"));
            imp.title.set_title(&tr("Edit the registry entry"));
        }
        imp.part_combo.set_selected(index_of(&tv::PARTS, &part));
        // An entry of the file stays in its part: changing it means removing it and adding
        // another.
        imp.part_combo.set_sensitive(entry.is_none());
        imp.action_combo
            .set_selected(index_of(&tv::RAW_ACTIONS, &form.action));
        imp.key_entry.set_text(&form.key);
        imp.name_entry.set_text(&form.name);
        imp.type_combo
            .set_selected(index_of(&tv::RAW_TYPES, &form.rtype));
        if form.rtype == rp::REG_MULTI_SZ {
            imp.multi_text.buffer().set_text(&form.data);
        } else {
            imp.data_entry.set_text(&form.data);
        }
        imp.decimal_switch.set_active(form.decimal);
        let weak = dialog.downgrade();
        imp.multi_text.buffer().connect_changed(move |_| {
            if let Some(d) = weak.upgrade() {
                d.changed();
            }
        });
        let shortcut = gtk::ShortcutController::new();
        let weak = dialog.downgrade();
        shortcut.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>Return"),
            Some(gtk::CallbackAction::new(move |_, _| {
                if let Some(d) = weak.upgrade() {
                    d.apply();
                }
                glib::Propagation::Stop
            })),
        ));
        dialog.add_controller(shortcut);
        dialog.set_focus(Some(&*imp.key_entry));
        imp.ready.set(true);
        dialog.changed();
        dialog
    }

    fn part(&self) -> Part {
        usize::try_from(self.imp().part_combo.selected())
            .ok()
            .and_then(|i| tv::PARTS.get(i).copied())
            .unwrap_or(Part::Computer)
    }

    fn form(&self) -> RawForm {
        let imp = self.imp();
        let rtype = usize::try_from(imp.type_combo.selected())
            .ok()
            .and_then(|i| tv::RAW_TYPES.get(i).copied())
            .unwrap_or(rp::REG_SZ);
        let data = if rtype == rp::REG_MULTI_SZ {
            let buffer = imp.multi_text.buffer();
            buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string()
        } else {
            imp.data_entry.text().to_string()
        };
        RawForm {
            action: usize::try_from(imp.action_combo.selected())
                .ok()
                .and_then(|i| tv::RAW_ACTIONS.get(i).copied())
                .unwrap_or(RawAction::Set),
            key: imp.key_entry.text().to_string(),
            name: imp.name_entry.text().to_string(),
            rtype,
            data,
            decimal: imp.decimal_switch.is_active(),
        }
    }

    fn errors(&self) -> std::collections::BTreeMap<&'static str, String> {
        let mut errors = tv::validate_raw(&self.form());
        let refusal = self
            .imp()
            .refuse
            .borrow()
            .as_ref()
            .and_then(|r| r(self.part()));
        if let Some(r) = refusal {
            errors.insert("partie", r);
        }
        errors
    }

    fn changed(&self) {
        let imp = self.imp();
        if !imp.ready.get() {
            return;
        }
        let form = self.form();
        let set = form.action == RawAction::Set;
        let multiple = form.rtype == rp::REG_MULTI_SZ;
        imp.name_entry
            .set_visible(form.action != RawAction::DeleteAll);
        imp.type_combo.set_visible(set);
        imp.data_entry.set_visible(set && !multiple);
        imp.multiple_group.set_visible(set && multiple);
        imp.decimal_switch
            .set_visible(set && (form.rtype == rp::REG_DWORD || form.rtype == rp::REG_QWORD));
        let errors = self.errors();
        let fields: [(&str, gtk::Widget); 4] = [
            ("partie", imp.part_combo.clone().upcast()),
            ("cle", imp.key_entry.clone().upcast()),
            ("nom", imp.name_entry.clone().upcast()),
            (
                "donnees",
                if multiple {
                    imp.multiple_group.clone().upcast()
                } else {
                    imp.data_entry.clone().upcast()
                },
            ),
        ];
        for (name, widget) in fields {
            if errors.contains_key(name) {
                widget.add_css_class("error");
            } else {
                widget.remove_css_class("error");
            }
        }
        // In the order of the Python dictionary: part last.
        let mut texts: Vec<&str> = ["cle", "nom", "type", "donnees"]
            .iter()
            .filter_map(|k| errors.get(k).map(String::as_str))
            .collect();
        if let Some(p) = errors.get("partie") {
            texts.push(p);
        }
        let text = texts.join("\n");
        imp.message.set_label(&text);
        imp.message.set_visible(!text.is_empty());
        imp.apply_button.set_sensitive(errors.is_empty());
    }

    /// « Decimal » switched: the integer typed is written again in the other base.
    fn base_changed(&self) {
        let imp = self.imp();
        if imp.ready.get() {
            imp.ready.set(false);
            let text = tv::convert_integer(&imp.data_entry.text(), imp.decimal_switch.is_active());
            imp.data_entry.set_text(&text);
            imp.ready.set(true);
        }
        self.changed();
    }

    fn apply(&self) {
        if !self.errors().is_empty() {
            return;
        }
        let Ok(entry) = tv::raw_entry(&self.form()) else {
            return;
        };
        let part = self.part();
        let apply = self.imp().apply.take();
        self.close();
        if let Some(apply) = apply {
            apply(part, entry);
        }
    }

    // --- Trials ---------------------------------------------------------------------------------

    /// Fills the dialog and applies (trials).
    pub fn trial_fill(&self, form: &RawForm, apply: bool) {
        let imp = self.imp();
        imp.action_combo
            .set_selected(index_of(&tv::RAW_ACTIONS, &form.action));
        imp.key_entry.set_text(&form.key);
        imp.name_entry.set_text(&form.name);
        imp.type_combo
            .set_selected(index_of(&tv::RAW_TYPES, &form.rtype));
        imp.decimal_switch.set_active(form.decimal);
        if form.rtype == rp::REG_MULTI_SZ {
            imp.multi_text.buffer().set_text(&form.data);
        } else {
            imp.data_entry.set_text(&form.data);
        }
        if apply {
            self.apply();
        }
    }
}

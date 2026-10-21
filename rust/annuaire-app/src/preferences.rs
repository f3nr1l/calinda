// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Group Policy Preferences in the GPO editor (J7.6, `annuaire.ui.preferences`).
//!
//! `PreferencesSection` plugs into the editor (`gpo_editor::Section`): nodes « Drive Maps »,
//! « Shortcuts », « Registry » under « Preferences → Windows Settings » and « Printers » under
//! « Control Panel Settings », as the GPMC; files `Preferences\<Family>\<Family>.xml` of each
//! part.
//!
//! One page by family (`AnnuairePreferences`, `preferences.blp`): list of the elements in the
//! order of processing, add (Ctrl+N), edit (Enter), delete (Delete), move up and down (Alt+Up,
//! Alt+Down); alert of a stored password (MS14-025) or of an unreadable file. One Blueprint
//! dialog by family (`dialogue-pref-*.blp`), checked as typed (`preference_views::validate`),
//! with the targeting (`dialogue-pref-cible.blp`: group, OU or user searched in the directory,
//! computer name typed; the other filters are kept and said not editable) and the common
//! options.
//!
//! Nothing is written at once: each gesture is added to the draft of the family
//! (`gpo_preferences::Operation`, by uid), which the editor replays on the content read again
//! when saving (Ctrl+S), through the common preview.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashMap;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::gpo::Part;
use annuaire_core::gpo_preferences::{self as gp, File, Operation, Principal};
use annuaire_core::gpp::{self, Common, Document, Element, Family, Filter, Target};
use gtk::{gio, glib};

use crate::errors;
use crate::gpo_editor::{GpoEditor, Section};
use crate::gpo_editor_views::{
    Anchor, ContentFile, EditorNode, Modification, NodeData, part_value,
};
use crate::i18n::{fill, tr};
use crate::preference_views::{self as pv, Form};
use crate::scope::TemplateScope;
use crate::writes;

pub const SECTION: &str = "preferences";

const PARTS: [Part; 2] = [Part::Computer, Part::User];

fn anchor(family: Family) -> Anchor {
    match family {
        Family::Printers => Anchor::PreferencesControlPanel,
        _ => Anchor::PreferencesWindows,
    }
}

fn icon(family: Family) -> &'static str {
    match family {
        Family::Drives => "drive-harddisk-symbolic",
        Family::Printers => "printer-symbolic",
        Family::Shortcuts => "emblem-symbolic-link-symbolic",
        Family::Registry => "text-x-generic-symbolic",
    }
}

fn escape(text: &str) -> String {
    glib::markup_escape_text(text).to_string()
}

fn empty(list: &gtk::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}

pub fn node_key(part: Part, family: Family) -> String {
    format!("pref:{}:{}", part_value(part), family.value())
}

// --- Section of the editor --------------------------------------------------------------------

#[derive(Debug, Default)]
struct State {
    editor: glib::WeakRef<GpoEditor>,
    files: HashMap<(Part, Family), File>,
    drafts: Vec<((Part, Family), Vec<Operation>)>,
    pages: HashMap<(Part, Family), PreferencesPage>,
    netbios: Option<String>,
}

/// The preferences of both parts: files read, draft by family, pages (`SectionPreferences`).
#[derive(Debug)]
pub struct PreferencesSection {
    me: Weak<PreferencesSection>,
    state: RefCell<State>,
}

impl PreferencesSection {
    pub fn new() -> Rc<Self> {
        Rc::new_cyclic(|me| Self {
            me: me.clone(),
            state: RefCell::new(State::default()),
        })
    }

    fn editor(&self) -> Option<GpoEditor> {
        self.state.borrow().editor.upgrade()
    }

    fn draft(&self, part: Part, family: Family) -> Vec<Operation> {
        self.state
            .borrow()
            .drafts
            .iter()
            .find(|(k, _)| *k == (part, family))
            .map(|(_, ops)| ops.clone())
            .unwrap_or_default()
    }

    /// The document of the family with the draft applied (`document`).
    pub fn document(&self, part: Part, family: Family) -> Document {
        let base = self
            .state
            .borrow()
            .files
            .get(&(part, family))
            .and_then(|f| f.document.clone())
            .unwrap_or_else(|| gpp::new_document(family));
        gp::apply(base.clone(), &self.draft(part, family)).unwrap_or(base)
    }

    pub fn file(&self, part: Part, family: Family) -> Option<File> {
        self.state.borrow().files.get(&(part, family)).cloned()
    }

    pub fn add_operation(&self, part: Part, family: Family, op: Operation) {
        {
            let mut state = self.state.borrow_mut();
            match state.drafts.iter_mut().find(|(k, _)| *k == (part, family)) {
                Some((_, ops)) => ops.push(op),
                None => state.drafts.push(((part, family), vec![op])),
            }
        }
        if let Some(editor) = self.editor() {
            editor.changed();
        }
    }

    pub fn connection(&self) -> Option<Arc<annuaire_core::Connection>> {
        self.editor()
            .and_then(|e| e.context())
            .map(|c| c.connection.clone())
    }

    pub fn read_only(&self) -> bool {
        self.editor().is_none_or(|e| e.read_only())
    }

    pub fn domain(&self) -> String {
        self.editor()
            .and_then(|e| e.context())
            .map(|c| c.profile.domain.clone())
            .unwrap_or_default()
    }

    /// NetBIOS name of the domain (read once), to name the groups and accounts targeted
    /// (`netbios`).
    pub fn netbios(&self, then: Box<dyn FnOnce(String)>) {
        if let Some(name) = self.state.borrow().netbios.clone() {
            then(name);
            return;
        }
        let Some(connection) = self.connection() else {
            then(String::new());
            return;
        };
        let me = self.me.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || gp::netbios_name(&connection)).await;
            let name = match read {
                Ok(Ok(name)) => name,
                _ => String::new(),
            };
            if let Some(section) = me.upgrade() {
                section.state.borrow_mut().netbios = Some(name.clone());
            }
            then(name);
        });
    }

    fn banner(&self) {
        let state = self.state.borrow();
        let documents: Vec<(Part, &Document)> = state
            .files
            .iter()
            .filter_map(|((part, _), f)| f.document.as_ref().map(|d| (*part, d)))
            .collect();
        let text = pv::passwords_alert(&documents);
        let editor = state.editor.upgrade();
        drop(state);
        if let (false, Some(editor)) = (text.is_empty(), editor) {
            editor.show_banner(Some(&text));
        }
    }

    /// The page of a family, if built (trials).
    pub fn trial_page(&self, part: Part, family: Family) -> Option<PreferencesPage> {
        self.state.borrow().pages.get(&(part, family)).cloned()
    }
}

impl Section for PreferencesSection {
    fn ident(&self) -> &'static str {
        SECTION
    }

    fn files(&self) -> Vec<ContentFile> {
        PARTS
            .iter()
            .flat_map(|p| {
                gp::families(*p)
                    .into_iter()
                    .map(move |f| ContentFile::new(*p, &f.path()))
            })
            .collect()
    }

    fn load(&self, editor: &GpoEditor, contents: &HashMap<ContentFile, Option<Vec<u8>>>) {
        let pages: Vec<PreferencesPage> = {
            let mut state = self.state.borrow_mut();
            state.editor.set(Some(editor));
            state.drafts.clear();
            for part in PARTS {
                for f in gp::families(part) {
                    let content = contents
                        .get(&ContentFile::new(part, &f.path()))
                        .cloned()
                        .flatten();
                    state
                        .files
                        .insert((part, f), gp::file(f, content.as_deref()));
                }
            }
            state.pages.values().cloned().collect()
        };
        for page in pages {
            page.refresh(None);
        }
        self.banner();
    }

    fn nodes(&self, part: Part) -> Vec<(Anchor, Vec<EditorNode>)> {
        let mut out: Vec<(Anchor, Vec<EditorNode>)> = Vec::new();
        for f in gp::families(part) {
            let n = self.document(part, f).elements().len();
            let title = pv::family_name(f);
            let mut node = EditorNode::new(node_key(part, f), title.clone())
                .section(SECTION)
                .icon(icon(f))
                .data(NodeData::Preferences(part, f));
            node.accessible = fill(
                &tr("{titre}, {n} item(s)"),
                &[("titre", &title), ("n", &n.to_string())],
            );
            match out.iter_mut().find(|(a, _)| *a == anchor(f)) {
                Some((_, list)) => list.push(node),
                None => out.push((anchor(f), vec![node])),
            }
        }
        out
    }

    fn page(&self, _editor: &GpoEditor, node: &EditorNode) -> gtk::Widget {
        let NodeData::Preferences(part, family) = node.data else {
            return adw::Bin::new().upcast();
        };
        let existing = self.state.borrow().pages.get(&(part, family)).cloned();
        if let Some(page) = existing {
            return page.upcast();
        }
        let page = PreferencesPage::new(self.me.clone(), part, family);
        self.state
            .borrow_mut()
            .pages
            .insert((part, family), page.clone());
        page.upcast()
    }

    fn modifications(&self) -> Vec<Modification> {
        let drafts = self.state.borrow().drafts.clone();
        let mut out = Vec::new();
        for ((part, family), ops) in drafts {
            if ops.is_empty() {
                continue;
            }
            let before = self
                .state
                .borrow()
                .files
                .get(&(part, family))
                .and_then(|f| f.document.clone());
            let after = self.document(part, family);
            let (add, remove) = gp::extension_pairs(family, after.elements().is_empty());
            let lines = pv::remarks_text(family, part, &gp::remarks(before.as_ref(), &after));
            out.push(Modification {
                file: ContentFile::new(part, &family.path()),
                modify: Arc::new(move |current: Option<&[u8]>| gp::replay(family, current, &ops)),
                extension: add.into_iter().next(),
                lines,
                remove_extensions: remove,
            });
        }
        out
    }

    fn discard(&self) {
        let pages: Vec<PreferencesPage> = {
            let mut state = self.state.borrow_mut();
            state.drafts.clear();
            state.pages.values().cloned().collect()
        };
        for page in pages {
            page.refresh(None);
        }
    }
}

// --- Page of a family -----------------------------------------------------------------------------

mod page_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/preferences.ui")]
    pub struct PreferencesPage {
        #[template_child]
        pub banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub empty: TemplateChild<gtk::Label>,
        #[template_child]
        pub add_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub edit_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub delete_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub up_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub down_button: TemplateChild<gtk::Button>,
        pub section: OnceCell<Weak<PreferencesSection>>,
        pub place: Cell<Option<(Part, Family)>>,
        pub shown: RefCell<Vec<Element>>,
    }

    impl std::fmt::Debug for PreferencesPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PreferencesPage").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PreferencesPage {
        const NAME: &'static str = "AnnuairePreferences";
        type Type = super::PreferencesPage;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PreferencesPage>(&[
                ("add", |p, _| {
                    p.add();
                    None
                }),
                ("edit", |p, _| {
                    p.edit();
                    None
                }),
                ("delete", |p, _| {
                    p.delete();
                    None
                }),
                ("move_up", |p, _| {
                    if p.imp().up_button.is_sensitive() {
                        p.shift(-1);
                    }
                    None
                }),
                ("move_down", |p, _| {
                    if p.imp().down_button.is_sensitive() {
                        p.shift(1);
                    }
                    None
                }),
                ("activated", |p, _| {
                    p.edit();
                    None
                }),
                ("selected", |p, _| {
                    p.update();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PreferencesPage {}
    impl WidgetImpl for PreferencesPage {}
    impl BinImpl for PreferencesPage {}
}

glib::wrapper! {
    /// The elements of a family in a part (`AnnuairePreferences`).
    pub struct PreferencesPage(ObjectSubclass<page_imp::PreferencesPage>)
        @extends adw::Bin, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

fn element_row(rank: usize, family: Family, element: &Element) -> adw::ActionRow {
    let view = pv::row(family, element);
    let subtitle: Vec<&str> = [view.subtitle.as_str(), view.targeting.as_str()]
        .into_iter()
        .filter(|x| !x.is_empty())
        .collect();
    let row = adw::ActionRow::builder()
        .title(escape(&format!("{}. {}", rank + 1, view.title)).as_str())
        .subtitle(escape(&subtitle.join("\n")).as_str())
        .activatable(true)
        .subtitle_lines(3)
        .build();
    if !view.alert.is_empty() {
        let image = gtk::Image::from_icon_name("dialog-warning-symbolic");
        image.set_tooltip_text(Some(&view.alert));
        image.add_css_class("warning");
        row.add_prefix(&image);
    }
    let action = gtk::Label::builder()
        .label(view.action.as_str())
        .valign(gtk::Align::Center)
        .build();
    action.add_css_class("dim-label");
    row.add_suffix(&action);
    let changed = element.raw.is_none();
    if changed {
        let mark = gtk::Label::builder()
            .label(tr("modified").as_str())
            .valign(gtk::Align::Center)
            .build();
        mark.add_css_class("accent");
        row.add_suffix(&mark);
    }
    let mut accessible = view.accessible();
    if changed {
        accessible.push_str(&tr(", changed"));
    }
    row.upcast_ref::<gtk::Widget>()
        .update_property(&[gtk::accessible::Property::Label(&format!(
            "{}. {accessible}",
            rank + 1
        ))]);
    row.set_widget_name(&rank.to_string());
    row
}

impl PreferencesPage {
    fn new(section: Weak<PreferencesSection>, part: Part, family: Family) -> Self {
        let page: Self = glib::Object::new();
        let imp = page.imp();
        let _ = imp.section.set(section);
        imp.place.set(Some((part, family)));
        imp.group.set_title(&pv::family_name(family));
        imp.group.set_description(Some(&pv::part_name(part)));
        let shortcuts = gtk::ShortcutController::new();
        type Handler = fn(&PreferencesPage);
        let handlers: [(&str, Handler); 4] = [
            ("<Control>n", Self::add),
            ("Delete", Self::delete),
            ("<Alt>Up", |p| {
                if p.imp().up_button.is_sensitive() {
                    p.shift(-1);
                }
            }),
            ("<Alt>Down", |p| {
                if p.imp().down_button.is_sensitive() {
                    p.shift(1);
                }
            }),
        ];
        for (trigger, handler) in handlers {
            let weak = page.downgrade();
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::CallbackAction::new(move |_, _| {
                    if let Some(p) = weak.upgrade() {
                        handler(&p);
                    }
                    glib::Propagation::Stop
                })),
            ));
        }
        page.add_controller(shortcuts);
        page.refresh(None);
        page
    }

    fn section(&self) -> Option<Rc<PreferencesSection>> {
        self.imp().section.get().and_then(Weak::upgrade)
    }

    fn place(&self) -> (Part, Family) {
        self.imp().place.get().expect("set by new")
    }

    fn chosen(&self) -> Option<(usize, Element)> {
        let row = self.imp().list.selected_row()?;
        let rank = row.widget_name().parse::<usize>().ok()?;
        self.imp()
            .shown
            .borrow()
            .get(rank)
            .cloned()
            .map(|e| (rank, e))
    }

    /// List made again from the file read and the draft; `choose`: uid to select again
    /// (`rafraichir`).
    pub fn refresh(&self, choose: Option<String>) {
        let imp = self.imp();
        let Some(section) = self.section() else {
            return;
        };
        let (part, family) = self.place();
        let file = section.file(part, family);
        match file.as_ref().and_then(|f| f.error.as_ref()) {
            Some(error) => {
                imp.banner.set_title(&escape(&fill(
                    &tr("Unreadable file, cannot be edited here: {erreur}"),
                    &[("erreur", &pv::error_text(error))],
                )));
                imp.banner.set_revealed(true);
            }
            None => {
                let alert = file
                    .as_ref()
                    .and_then(|f| f.document.as_ref())
                    .filter(|d| !d.passwords().is_empty())
                    .map(|d| pv::passwords_alert(&[(part, d)]))
                    .unwrap_or_default();
                imp.banner.set_title(&escape(&alert));
                imp.banner.set_revealed(!alert.is_empty());
            }
        }
        let choose = choose.or_else(|| self.chosen().map(|(_, e)| e.uid().to_owned()));
        empty(&imp.list);
        let document = section.document(part, family);
        let elements: Vec<Element> = document.elements().into_iter().cloned().collect();
        let mut to_choose = None;
        for (i, e) in elements.iter().enumerate() {
            let row = element_row(i, family, e);
            imp.list.append(&row);
            if choose.as_deref() == Some(e.uid()) {
                to_choose = Some(row);
            }
        }
        imp.list.set_visible(!elements.is_empty());
        imp.empty.set_visible(elements.is_empty());
        *imp.shown.borrow_mut() = elements;
        imp.stack.set_visible_child_name("liste");
        if let Some(row) = to_choose {
            imp.list.select_row(Some(&row));
            row.grab_focus();
        }
        self.update();
    }

    fn update(&self) {
        let imp = self.imp();
        let Some(section) = self.section() else {
            return;
        };
        let (part, family) = self.place();
        let unreadable = section
            .file(part, family)
            .is_some_and(|f| f.error.is_some());
        let editable = !section.read_only() && !unreadable;
        let chosen = self.chosen();
        let n = imp.shown.borrow().len();
        imp.add_button.set_sensitive(editable);
        imp.edit_button.set_sensitive(editable && chosen.is_some());
        imp.delete_button
            .set_sensitive(editable && chosen.is_some());
        imp.up_button
            .set_sensitive(editable && chosen.as_ref().is_some_and(|(r, _)| *r > 0));
        imp.down_button
            .set_sensitive(editable && chosen.as_ref().is_some_and(|(r, _)| r + 1 < n));
    }

    // --- Gestures -----------------------------------------------------------------------------

    fn operation(&self, op: Operation, choose: String) {
        let Some(section) = self.section() else {
            return;
        };
        let (part, family) = self.place();
        section.add_operation(part, family, op);
        self.refresh(Some(choose));
    }

    fn add(&self) {
        if !self.imp().add_button.is_sensitive() {
            return;
        }
        let Some(section) = self.section() else {
            return;
        };
        let (part, family) = self.place();
        let weak = self.downgrade();
        open_dialog(
            self,
            &section,
            part,
            family,
            None,
            Box::new(move |element| {
                if let Some(page) = weak.upgrade() {
                    let uid = element.uid().to_owned();
                    page.operation(Operation::Add(element), uid);
                }
            }),
        );
    }

    fn edit(&self) {
        let Some((_, element)) = self.chosen() else {
            return;
        };
        if !self.imp().edit_button.is_sensitive() {
            return;
        }
        let Some(section) = self.section() else {
            return;
        };
        let (part, family) = self.place();
        if !element.editable(family.description()) {
            writes::announce(
                self,
                &tr("This item cannot be edited here (type managed by the GPMC)."),
                None,
            );
            return;
        }
        let uid = element.uid().to_owned();
        let weak = self.downgrade();
        open_dialog(
            self,
            &section,
            part,
            family,
            Some(element),
            Box::new(move |new| {
                if let Some(page) = weak.upgrade() {
                    page.operation(
                        Operation::Replace {
                            uid: uid.clone(),
                            element: new,
                        },
                        uid.clone(),
                    );
                }
            }),
        );
    }

    fn delete(&self) {
        let Some((rank, element)) = self.chosen() else {
            return;
        };
        if !self.imp().delete_button.is_sensitive() {
            return;
        }
        let shown = self.imp().shown.borrow().clone();
        let mut next = shown
            .get((rank + 1).min(shown.len().saturating_sub(1)))
            .map(|e| e.uid().to_owned())
            .unwrap_or_default();
        if next == element.uid() && rank > 0 {
            next = shown
                .get(rank - 1)
                .map(|e| e.uid().to_owned())
                .unwrap_or_default();
        }
        self.operation(
            Operation::Remove {
                uid: element.uid().to_owned(),
            },
            next,
        );
        writes::announce(
            self,
            &fill(
                &tr("“{nom}” removed in the draft (Ctrl+S saves)."),
                &[("nom", element.name())],
            ),
            None,
        );
    }

    fn shift(&self, offset: isize) {
        let Some((_, element)) = self.chosen() else {
            return;
        };
        let uid = element.uid().to_owned();
        self.operation(
            Operation::Shift {
                uid: uid.clone(),
                offset,
            },
            uid,
        );
    }

    // --- Trials -------------------------------------------------------------------------------

    /// The key of the node of the page (trials).
    pub fn trial_key(&self) -> String {
        let (part, family) = self.place();
        node_key(part, family)
    }

    /// The rows shown (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(row) = self.imp().list.row_at_index(i) {
            if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                out.push(format!(
                    "{} | {}",
                    r.title(),
                    r.subtitle().unwrap_or_default().replace('\n', " / ")
                ));
            }
            i += 1;
        }
        out
    }

    /// Chooses the row `rank` and runs a gesture: `ajouter`, `modifier`, `supprimer`,
    /// `monter`, `descendre` (trials).
    pub fn trial_gesture(&self, gesture: &str, rank: i32) {
        if let Some(row) = self.imp().list.row_at_index(rank) {
            self.imp().list.select_row(Some(&row));
        }
        match gesture {
            "ajouter" => self.add(),
            "modifier" => self.edit(),
            "supprimer" => self.delete(),
            "monter" => self.shift(-1),
            "descendre" => self.shift(1),
            _ => {}
        }
    }
}

// --- Dialogs of an element ------------------------------------------------------------------------

/// What follows « Continue »: the element made.
type Done = Box<dyn Fn(Element)>;

/// What the four dialogs share: section, part, element changed, filters (`_DialogueElement`).
#[derive(Default)]
pub struct Shared {
    section: OnceCell<Weak<PreferencesSection>>,
    part: Cell<Option<Part>>,
    old: RefCell<Option<Element>>,
    done: RefCell<Option<Done>>,
    filters: RefCell<Vec<Filter>>,
    ready: Cell<bool>,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

/// The widgets the four dialogs have in common.
struct Widgets {
    title: adw::WindowTitle,
    continue_button: gtk::Button,
    action_combo: adw::ComboRow,
    targets_list: gtk::ListBox,
    description_entry: adw::EntryRow,
    stop_switch: adw::SwitchRow,
    context_switch: adw::SwitchRow,
    remove_switch: adw::SwitchRow,
    disabled_switch: adw::SwitchRow,
    message: gtk::Label,
}

/// A dialog of an element: what each family provides (`_lire`, `_remplir`, `_champs`).
trait ElementDialog: IsA<adw::Dialog> + IsA<gtk::Widget> + Clone + 'static {
    const FAMILY: Family;
    fn shared(&self) -> &Shared;
    fn widgets(&self) -> Widgets;
    fn fill_form(&self, form: &Form);
    fn read_form(&self, action: &str) -> Form;
    fn fields(&self) -> Vec<(&'static str, gtk::Widget)>;
    /// Visibility of the fields according to the type or the action (registry).
    fn update_family(&self) {}
    /// Sets a field of the family by its name in `fields` (trials).
    fn trial_field(&self, field: &str, value: &str) -> bool;
}

fn weak_of<D: ElementDialog>(d: &D) -> glib::WeakRef<D> {
    let weak = glib::WeakRef::new();
    weak.set(Some(d));
    weak
}

fn combo_choose(combo: &adw::ComboRow, values: &[&str], value: &str) {
    let rank = values.iter().position(|v| *v == value).unwrap_or(0);
    combo.set_selected(u32::try_from(rank).unwrap_or(0));
}

fn combo_value(combo: &adw::ComboRow, values: &[&str]) -> String {
    usize::try_from(combo.selected())
        .ok()
        .and_then(|i| values.get(i))
        .copied()
        .unwrap_or_default()
        .to_owned()
}

fn action_of<D: ElementDialog>(d: &D) -> String {
    combo_value(&d.widgets().action_combo, &gpp::ACTIONS)
}

fn common_of<D: ElementDialog>(d: &D) -> Common {
    let w = d.widgets();
    Common {
        description: w.description_entry.text().to_string(),
        ignore_errors: !w.stop_switch.is_active(),
        user_context: w.context_switch.is_active(),
        remove_when_not_applied: w.remove_switch.is_active(),
        disabled: w.disabled_switch.is_active(),
    }
}

fn prepare<D: ElementDialog>(
    d: &D,
    section: &Rc<PreferencesSection>,
    part: Part,
    element: Option<Element>,
    done: Done,
) {
    let shared = d.shared();
    let _ = shared.section.set(Rc::downgrade(section));
    shared.part.set(Some(part));
    *shared.filters.borrow_mut() = element.as_ref().map(Element::filters).unwrap_or_default();
    *shared.done.borrow_mut() = Some(done);
    let w = d.widgets();
    w.title.set_subtitle(&pv::part_name(part));
    let form = pv::form(D::FAMILY, element.as_ref(), part);
    let action = gpp::ACTIONS
        .iter()
        .position(|a| *a == form.action())
        .unwrap_or(2);
    w.action_combo
        .set_selected(u32::try_from(action).unwrap_or(2));
    d.fill_form(&form);
    let common = element
        .as_ref()
        .map_or_else(Common::default, Element::common);
    w.description_entry.set_text(&common.description);
    w.stop_switch.set_active(!common.ignore_errors);
    w.context_switch.set_active(common.user_context);
    w.remove_switch.set_active(common.remove_when_not_applied);
    w.disabled_switch.set_active(common.disabled);
    *shared.old.borrow_mut() = element;
    let group = gio::SimpleActionGroup::new();
    let action = gio::SimpleAction::new("cible", Some(glib::VariantTy::STRING));
    let weak = weak_of(d);
    action.connect_activate(move |_, value| {
        let target = value.and_then(glib::Variant::str).and_then(Target::of_tag);
        if let (Some(d), Some(target)) = (weak.upgrade(), target) {
            new_target(&d, target);
        }
    });
    group.add_action(&action);
    d.insert_action_group("dialogue", Some(&group));
    show_targets(d);
    shared.ready.set(true);
    changed(d);
}

fn show_targets<D: ElementDialog>(d: &D) {
    let list = d.widgets().targets_list;
    empty(&list);
    let filters = d.shared().filters.borrow().clone();
    let texts = pv::filters_texts(&filters);
    for (i, (text, f)) in texts.iter().zip(&filters).enumerate() {
        let row = adw::ActionRow::builder()
            .title(escape(text).as_str())
            .title_lines(0)
            .build();
        if matches!(f, Filter::Raw(_)) {
            row.set_subtitle(&tr("Cannot be edited here, kept as is"));
        } else {
            let button = gtk::Button::builder()
                .icon_name("user-trash-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text(tr("Remove this filter").as_str())
                .build();
            button.add_css_class("flat");
            button.update_property(&[gtk::accessible::Property::Label(&tr("Remove this filter"))]);
            let weak = weak_of(d);
            button.connect_clicked(move |_| {
                if let Some(d) = weak.upgrade() {
                    let mut filters = d.shared().filters.borrow_mut();
                    if i < filters.len() {
                        filters.remove(i);
                    }
                    drop(filters);
                    show_targets(&d);
                }
            });
            row.add_suffix(&button);
        }
        list.append(&row);
    }
    if filters.is_empty() {
        let row = adw::ActionRow::builder()
            .title(tr("No filter").as_str())
            .build();
        row.add_css_class("dim-label");
        list.append(&row);
    }
}

fn new_target<D: ElementDialog>(d: &D, target: Target) {
    let shared = d.shared();
    let (Some(section), Some(part)) = (
        shared.section.get().and_then(Weak::upgrade),
        shared.part.get(),
    ) else {
        return;
    };
    let weak = weak_of(d);
    let parent = d.clone();
    let s = section.clone();
    section.netbios(Box::new(move |netbios| {
        let weak = weak.clone();
        TargetDialog::new(
            &s,
            part,
            target,
            netbios,
            Box::new(move |f| {
                if let Some(d) = weak.upgrade() {
                    d.shared().filters.borrow_mut().push(f);
                    show_targets(&d);
                }
            }),
        )
        .present(Some(&parent));
    }));
}

fn problems<D: ElementDialog>(d: &D) -> Vec<pv::Problem> {
    let action = action_of(d);
    let part = d.shared().part.get().unwrap_or(Part::User);
    let mut out = pv::validate(&d.read_form(&action), part);
    out.extend(pv::validate_common(&common_of(d), &action));
    out
}

fn changed<D: ElementDialog>(d: &D) {
    if !d.shared().ready.get() {
        return;
    }
    d.update_family();
    let problems = problems(d);
    for (name, widget) in d.fields() {
        if problems.iter().any(|p| p.field == name) {
            widget.add_css_class("error");
        } else {
            widget.remove_css_class("error");
        }
    }
    let text: Vec<&str> = problems.iter().map(|p| p.message.as_str()).collect();
    let w = d.widgets();
    w.message.set_label(&text.join("\n"));
    w.message.set_visible(!text.is_empty());
    w.continue_button.set_sensitive(problems.is_empty());
}

fn proceed<D: ElementDialog>(d: &D) {
    if !problems(d).is_empty() {
        return;
    }
    let shared = d.shared();
    let old = shared.old.borrow().clone();
    let filters = shared.filters.borrow().clone();
    let made = pv::to_element(
        D::FAMILY,
        &d.read_form(&action_of(d)),
        &common_of(d),
        &filters,
        old.as_ref(),
        &annuaire_core::gpo_write::new_guid(),
        gpp::now(),
    );
    let element = match made {
        Ok(e) => e,
        Err(e) => {
            writes::show_error(d, &tr("Item rejected"), &e, "");
            return;
        }
    };
    let done = shared.done.take();
    d.upcast_ref::<adw::Dialog>().close();
    if let Some(done) = done {
        done(element);
    }
}

/// Class of a dialog of an element: the common children, those of the family, the callbacks
/// of the Blueprint (`changed`, `cancel`, `next`).
macro_rules! element_dialog {
    (
        $module:ident, $Type:ident, $name:literal, $resource:literal, $doc:literal,
        { $( $child:ident : $ty:ty ),* $(,)? }
    ) => {
        mod $module {
            use super::*;

            #[derive(Default, gtk::CompositeTemplate)]
            #[template(resource = $resource)]
            pub struct $Type {
                #[template_child]
                pub title: TemplateChild<adw::WindowTitle>,
                #[template_child]
                pub continue_button: TemplateChild<gtk::Button>,
                #[template_child]
                pub action_combo: TemplateChild<adw::ComboRow>,
                #[template_child]
                pub target_button: TemplateChild<gtk::MenuButton>,
                #[template_child]
                pub targets_list: TemplateChild<gtk::ListBox>,
                #[template_child]
                pub description_entry: TemplateChild<adw::EntryRow>,
                #[template_child]
                pub stop_switch: TemplateChild<adw::SwitchRow>,
                #[template_child]
                pub context_switch: TemplateChild<adw::SwitchRow>,
                #[template_child]
                pub remove_switch: TemplateChild<adw::SwitchRow>,
                #[template_child]
                pub disabled_switch: TemplateChild<adw::SwitchRow>,
                #[template_child]
                pub message: TemplateChild<gtk::Label>,
                $(
                    #[template_child]
                    pub $child: TemplateChild<$ty>,
                )*
                pub shared: Shared,
            }

            impl std::fmt::Debug for $Type {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct(stringify!($Type)).finish_non_exhaustive()
                }
            }

            #[glib::object_subclass]
            impl ObjectSubclass for $Type {
                const NAME: &'static str = $name;
                type Type = super::$Type;
                type ParentType = adw::Dialog;

                fn class_init(klass: &mut Self::Class) {
                    klass.bind_template();
                    klass.set_template_scope(&TemplateScope::new::<super::$Type>(&[
                        ("changed", |d, _| {
                            changed(d);
                            None
                        }),
                        ("cancel", |d, _| {
                            d.close();
                            None
                        }),
                        ("next", |d, _| {
                            proceed(d);
                            None
                        }),
                    ]));
                }

                fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
                    obj.init_template();
                }
            }

            impl ObjectImpl for $Type {}
            impl WidgetImpl for $Type {}
            impl AdwDialogImpl for $Type {}
        }

        glib::wrapper! {
            #[doc = $doc]
            pub struct $Type(ObjectSubclass<$module::$Type>)
                @extends adw::Dialog, gtk::Widget,
                @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget,
                    gtk::ShortcutManager;
        }

        impl $Type {
            fn common_widgets(&self) -> Widgets {
                let imp = self.imp();
                Widgets {
                    title: imp.title.get(),
                    continue_button: imp.continue_button.get(),
                    action_combo: imp.action_combo.get(),
                    targets_list: imp.targets_list.get(),
                    description_entry: imp.description_entry.get(),
                    stop_switch: imp.stop_switch.get(),
                    context_switch: imp.context_switch.get(),
                    remove_switch: imp.remove_switch.get(),
                    disabled_switch: imp.disabled_switch.get(),
                    message: imp.message.get(),
                }
            }

            /// Proceeds as « Continue » (trials).
            pub fn trial_continue(&self) {
                proceed(self);
            }

            /// The messages that prevent continuing (trials).
            pub fn trial_message(&self) -> String {
                self.imp().message.label().to_string()
            }

            /// Sets a field of the form: `action` (C, R, U, D), `description` or one of the
            /// family (trials).
            pub fn trial_set(&self, field: &str, value: &str) -> bool {
                let imp = self.imp();
                match field {
                    "action" => combo_choose(&imp.action_combo, &gpp::ACTIONS, value),
                    "description" => imp.description_entry.set_text(value),
                    _ => {
                        if !ElementDialog::trial_field(self, field, value) {
                            return false;
                        }
                    }
                }
                changed(self);
                true
            }

            /// Opens the dialog of a targeting filter (`FilterGroup`…) (trials).
            pub fn trial_target(&self, tag: &str) {
                if let Some(target) = Target::of_tag(tag) {
                    new_target(self, target);
                }
            }
        }
    };
}

element_dialog!(
    drive_imp,
    DriveDialog,
    "AnnuaireDialoguePrefLecteur",
    "/io/github/f3nr1l/Calinda/ui/dialogue-pref-lecteur.ui",
    "A mapped drive (`AnnuaireDialoguePrefLecteur`).",
    {
        path_entry: adw::EntryRow,
        label_entry: adw::EntryRow,
        letter_combo: adw::ComboRow,
        first_available_switch: adw::SwitchRow,
        reconnect_switch: adw::SwitchRow,
        this_drive_combo: adw::ComboRow,
        all_drives_combo: adw::ComboRow,
    }
);

element_dialog!(
    printer_imp,
    PrinterDialog,
    "AnnuaireDialoguePrefImprimante",
    "/io/github/f3nr1l/Calinda/ui/dialogue-pref-imprimante.ui",
    "A shared printer (`AnnuaireDialoguePrefImprimante`).",
    {
        path_entry: adw::EntryRow,
        default_switch: adw::SwitchRow,
        no_local_switch: adw::SwitchRow,
        delete_all_switch: adw::SwitchRow,
        location_entry: adw::EntryRow,
        comment_entry: adw::EntryRow,
        port_entry: adw::EntryRow,
        reconnect_switch: adw::SwitchRow,
        delete_port_switch: adw::SwitchRow,
    }
);

element_dialog!(
    shortcut_imp,
    ShortcutDialog,
    "AnnuaireDialoguePrefRaccourci",
    "/io/github/f3nr1l/Calinda/ui/dialogue-pref-raccourci.ui",
    "A shortcut (`AnnuaireDialoguePrefRaccourci`).",
    {
        path_entry: adw::EntryRow,
        kind_combo: adw::ComboRow,
        target_entry: adw::EntryRow,
        arguments_entry: adw::EntryRow,
        start_in_entry: adw::EntryRow,
        window_combo: adw::ComboRow,
        comment_entry: adw::EntryRow,
        icon_entry: adw::EntryRow,
        index_entry: adw::EntryRow,
    }
);

element_dialog!(
    registry_imp,
    RegistryDialog,
    "AnnuaireDialoguePrefRegistre",
    "/io/github/f3nr1l/Calinda/ui/dialogue-pref-registre.ui",
    "A registry item (`AnnuaireDialoguePrefRegistre`).",
    {
        hive_combo: adw::ComboRow,
        key_entry: adw::EntryRow,
        default_value_switch: adw::SwitchRow,
        name_entry: adw::EntryRow,
        type_combo: adw::ComboRow,
        data_entry: adw::EntryRow,
        decimal_switch: adw::SwitchRow,
        multiple_group: adw::PreferencesGroup,
        multi_text: gtk::TextView,
    }
);

const LETTERS: [&str; 26] = [
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S",
    "T", "U", "V", "W", "X", "Y", "Z",
];

impl ElementDialog for DriveDialog {
    fn trial_field(&self, field: &str, value: &str) -> bool {
        let imp = self.imp();
        match field {
            "chemin" => imp.path_entry.set_text(value),
            "libelle" => imp.label_entry.set_text(value),
            "lettre" => combo_choose(&imp.letter_combo, &LETTERS, value),
            _ => return false,
        }
        true
    }

    const FAMILY: Family = Family::Drives;

    fn shared(&self) -> &Shared {
        &self.imp().shared
    }

    fn widgets(&self) -> Widgets {
        self.common_widgets()
    }

    fn fill_form(&self, form: &Form) {
        let Form::Drive(f) = form else { return };
        let imp = self.imp();
        imp.path_entry.set_text(&f.path);
        imp.label_entry.set_text(&f.label);
        combo_choose(&imp.letter_combo, &LETTERS, &f.letter.to_uppercase());
        imp.first_available_switch.set_active(f.first_free);
        imp.reconnect_switch.set_active(f.reconnect);
        combo_choose(&imp.this_drive_combo, &pv::DISPLAY, &f.this_drive);
        combo_choose(&imp.all_drives_combo, &pv::DISPLAY, &f.all_drives);
    }

    fn read_form(&self, action: &str) -> Form {
        let imp = self.imp();
        Form::Drive(pv::DriveForm {
            action: action.to_owned(),
            path: imp.path_entry.text().to_string(),
            letter: combo_value(&imp.letter_combo, &LETTERS),
            first_free: imp.first_available_switch.is_active(),
            label: imp.label_entry.text().to_string(),
            reconnect: imp.reconnect_switch.is_active(),
            this_drive: combo_value(&imp.this_drive_combo, &pv::DISPLAY),
            all_drives: combo_value(&imp.all_drives_combo, &pv::DISPLAY),
        })
    }

    fn fields(&self) -> Vec<(&'static str, gtk::Widget)> {
        let imp = self.imp();
        vec![
            ("chemin", imp.path_entry.get().upcast()),
            ("lettre", imp.letter_combo.get().upcast()),
            ("retirer", imp.remove_switch.get().upcast()),
        ]
    }
}

impl ElementDialog for PrinterDialog {
    fn trial_field(&self, field: &str, value: &str) -> bool {
        let imp = self.imp();
        match field {
            "chemin" => imp.path_entry.set_text(value),
            "port" => imp.port_entry.set_text(value),
            "defaut" => imp.default_switch.set_active(value == "1"),
            _ => return false,
        }
        true
    }

    const FAMILY: Family = Family::Printers;

    fn shared(&self) -> &Shared {
        &self.imp().shared
    }

    fn widgets(&self) -> Widgets {
        self.common_widgets()
    }

    fn fill_form(&self, form: &Form) {
        let Form::Printer(f) = form else { return };
        let imp = self.imp();
        imp.path_entry.set_text(&f.path);
        imp.default_switch.set_active(f.default);
        imp.no_local_switch.set_active(f.only_without_local);
        imp.delete_all_switch.set_active(f.delete_all);
        imp.location_entry.set_text(&f.location);
        imp.comment_entry.set_text(&f.comment);
        imp.port_entry.set_text(&f.port);
        imp.reconnect_switch.set_active(f.reconnect);
        imp.delete_port_switch.set_active(f.delete_port);
    }

    fn read_form(&self, action: &str) -> Form {
        let imp = self.imp();
        Form::Printer(pv::PrinterForm {
            action: action.to_owned(),
            path: imp.path_entry.text().to_string(),
            default: imp.default_switch.is_active(),
            only_without_local: imp.no_local_switch.is_active(),
            delete_all: imp.delete_all_switch.is_active(),
            location: imp.location_entry.text().to_string(),
            comment: imp.comment_entry.text().to_string(),
            port: imp.port_entry.text().trim().to_owned(),
            reconnect: imp.reconnect_switch.is_active(),
            delete_port: imp.delete_port_switch.is_active(),
        })
    }

    fn fields(&self) -> Vec<(&'static str, gtk::Widget)> {
        let imp = self.imp();
        vec![
            ("chemin", imp.path_entry.get().upcast()),
            ("port", imp.port_entry.get().upcast()),
            ("retirer", imp.remove_switch.get().upcast()),
        ]
    }
}

impl ElementDialog for ShortcutDialog {
    fn trial_field(&self, field: &str, value: &str) -> bool {
        let imp = self.imp();
        match field {
            "chemin" => imp.path_entry.set_text(value),
            "cible" => imp.target_entry.set_text(value),
            "indice_icone" => imp.index_entry.set_text(value),
            _ => return false,
        }
        true
    }

    const FAMILY: Family = Family::Shortcuts;

    fn shared(&self) -> &Shared {
        &self.imp().shared
    }

    fn widgets(&self) -> Widgets {
        self.common_widgets()
    }

    fn fill_form(&self, form: &Form) {
        let Form::Shortcut(f) = form else { return };
        let imp = self.imp();
        imp.path_entry.set_text(&f.path);
        combo_choose(&imp.kind_combo, &pv::TARGET_KINDS, &f.kind);
        imp.target_entry.set_text(&f.target);
        imp.arguments_entry.set_text(&f.arguments);
        imp.start_in_entry.set_text(&f.start_in);
        combo_choose(&imp.window_combo, &pv::WINDOWS, &f.window);
        imp.comment_entry.set_text(&f.comment);
        imp.icon_entry.set_text(&f.icon);
        imp.index_entry.set_text(&f.icon_index);
    }

    fn read_form(&self, action: &str) -> Form {
        let imp = self.imp();
        Form::Shortcut(pv::ShortcutForm {
            action: action.to_owned(),
            kind: combo_value(&imp.kind_combo, &pv::TARGET_KINDS),
            path: imp.path_entry.text().to_string(),
            target: imp.target_entry.text().to_string(),
            arguments: imp.arguments_entry.text().to_string(),
            start_in: imp.start_in_entry.text().to_string(),
            window: combo_value(&imp.window_combo, &pv::WINDOWS),
            comment: imp.comment_entry.text().to_string(),
            icon: imp.icon_entry.text().to_string(),
            icon_index: imp.index_entry.text().trim().to_owned(),
        })
    }

    fn fields(&self) -> Vec<(&'static str, gtk::Widget)> {
        let imp = self.imp();
        vec![
            ("chemin", imp.path_entry.get().upcast()),
            ("cible", imp.target_entry.get().upcast()),
            ("indice_icone", imp.index_entry.get().upcast()),
            ("retirer", imp.remove_switch.get().upcast()),
        ]
    }
}

impl ElementDialog for RegistryDialog {
    fn trial_field(&self, field: &str, value: &str) -> bool {
        let imp = self.imp();
        match field {
            "ruche" => combo_choose(&imp.hive_combo, &pv::HIVES, value),
            "cle" => imp.key_entry.set_text(value),
            "nom" => imp.name_entry.set_text(value),
            "type" => combo_choose(&imp.type_combo, &pv::REGISTRY_TYPES, value),
            "donnees" => imp.data_entry.set_text(value),
            "multiple" => imp
                .multi_text
                .buffer()
                .set_text(&value.replace("\\n", "\n")),
            _ => return false,
        }
        true
    }

    const FAMILY: Family = Family::Registry;

    fn shared(&self) -> &Shared {
        &self.imp().shared
    }

    fn widgets(&self) -> Widgets {
        self.common_widgets()
    }

    fn fill_form(&self, form: &Form) {
        let Form::Registry(f) = form else { return };
        let imp = self.imp();
        combo_choose(&imp.hive_combo, &pv::HIVES, &f.hive);
        imp.key_entry.set_text(&f.key);
        imp.default_value_switch.set_active(f.default);
        imp.name_entry.set_text(&f.name);
        combo_choose(&imp.type_combo, &pv::REGISTRY_TYPES, &f.rtype);
        if f.rtype == "REG_MULTI_SZ" {
            imp.multi_text.buffer().set_text(&f.data);
        } else {
            imp.data_entry.set_text(&f.data);
        }
        imp.decimal_switch.set_active(f.decimal);
        self.update_family();
    }

    fn read_form(&self, action: &str) -> Form {
        let imp = self.imp();
        let rtype = combo_value(&imp.type_combo, &pv::REGISTRY_TYPES);
        let data = if rtype == "REG_MULTI_SZ" {
            let buffer = imp.multi_text.buffer();
            buffer
                .text(&buffer.start_iter(), &buffer.end_iter(), false)
                .to_string()
        } else {
            imp.data_entry.text().to_string()
        };
        Form::Registry(pv::RegistryForm {
            action: action.to_owned(),
            hive: combo_value(&imp.hive_combo, &pv::HIVES),
            key: imp.key_entry.text().to_string(),
            name: imp.name_entry.text().to_string(),
            default: imp.default_value_switch.is_active(),
            rtype,
            data,
            decimal: imp.decimal_switch.is_active(),
        })
    }

    fn update_family(&self) {
        let imp = self.imp();
        let rtype = combo_value(&imp.type_combo, &pv::REGISTRY_TYPES);
        let multiple = rtype == "REG_MULTI_SZ";
        imp.multiple_group.set_visible(multiple);
        imp.data_entry.set_visible(!multiple);
        imp.decimal_switch
            .set_visible(rtype == "REG_DWORD" || rtype == "REG_QWORD");
        imp.name_entry
            .set_sensitive(!imp.default_value_switch.is_active());
    }

    fn fields(&self) -> Vec<(&'static str, gtk::Widget)> {
        let imp = self.imp();
        vec![
            ("cle", imp.key_entry.get().upcast()),
            ("donnees", imp.data_entry.get().upcast()),
            ("retirer", imp.remove_switch.get().upcast()),
        ]
    }
}

/// The dialog of the family, new or to change, presented over `parent` (`ouvrir_dialogue`).
fn open_dialog(
    parent: &impl IsA<gtk::Widget>,
    section: &Rc<PreferencesSection>,
    part: Part,
    family: Family,
    element: Option<Element>,
    done: Done,
) {
    match family {
        Family::Drives => {
            let d: DriveDialog = glib::Object::new();
            prepare(&d, section, part, element, done);
            d.present(Some(parent));
            crate::a11y::name_menus(&d); // the content is in the tree once presented
        }
        Family::Printers => {
            let d: PrinterDialog = glib::Object::new();
            prepare(&d, section, part, element, done);
            d.present(Some(parent));
            crate::a11y::name_menus(&d); // the content is in the tree once presented
        }
        Family::Shortcuts => {
            let d: ShortcutDialog = glib::Object::new();
            prepare(&d, section, part, element, done);
            d.present(Some(parent));
            crate::a11y::name_menus(&d); // the content is in the tree once presented
        }
        Family::Registry => {
            let d: RegistryDialog = glib::Object::new();
            let weak = weak_of(&d);
            d.imp().multi_text.buffer().connect_changed(move |_| {
                if let Some(d) = weak.upgrade() {
                    changed(&d);
                }
            });
            prepare(&d, section, part, element, done);
            d.present(Some(parent));
            crate::a11y::name_menus(&d); // the content is in the tree once presented
        }
    }
}

// --- Targeting filter -----------------------------------------------------------------------------

fn target_title(target: Target) -> String {
    match target {
        Target::Group => tr("Security group"),
        Target::Ou => tr("Organizational unit"),
        Target::Computer => tr("Computer name"),
        Target::User => tr("User"),
    }
}

/// What follows « Continue »: the filter made.
type FilterDone = Box<dyn Fn(Filter)>;

mod target_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-pref-cible.ui")]
    pub struct TargetDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub search_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub search_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub count: TemplateChild<gtk::Label>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub computer_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub computer_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub dns_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub chosen_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub not_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub ou_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub computer_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub direct_switch: TemplateChild<adw::SwitchRow>,
        pub section: OnceCell<Weak<PreferencesSection>>,
        pub target: Cell<Option<Target>>,
        pub netbios: RefCell<String>,
        pub done: RefCell<Option<FilterDone>>,
        pub chosen: RefCell<Option<Principal>>,
        pub found: RefCell<Vec<Principal>>,
        pub generation: Cell<u64>,
    }

    impl std::fmt::Debug for TargetDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TargetDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for TargetDialog {
        const NAME: &'static str = "AnnuaireDialoguePrefCible";
        type Type = super::TargetDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::TargetDialog>(&[
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("changed", |d, _| {
                    d.changed();
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

    impl ObjectImpl for TargetDialog {}
    impl WidgetImpl for TargetDialog {}
    impl AdwDialogImpl for TargetDialog {}
}

glib::wrapper! {
    /// A targeting filter: group, OU or user searched in the directory, computer name typed
    /// (`AnnuaireDialoguePrefCible`).
    pub struct TargetDialog(ObjectSubclass<target_imp::TargetDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl TargetDialog {
    fn new(
        section: &Rc<PreferencesSection>,
        part: Part,
        target: Target,
        netbios: String,
        done: FilterDone,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.section.set(Rc::downgrade(section));
        imp.target.set(Some(target));
        *imp.netbios.borrow_mut() = netbios;
        *imp.done.borrow_mut() = Some(done);
        imp.title.set_subtitle(&target_title(target));
        let typed = target == Target::Computer;
        imp.search_group.set_visible(!typed);
        imp.computer_group.set_visible(typed);
        imp.chosen_row.set_visible(!typed);
        imp.computer_switch
            .set_visible(matches!(target, Target::Group | Target::Ou));
        imp.computer_switch.set_active(part == Part::Computer);
        imp.direct_switch.set_visible(target == Target::Ou);
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(d) = weak.upgrade() {
                d.candidate(row);
            }
        });
        if typed {
            dialog.set_focus(Some(&*imp.computer_entry));
        }
        dialog
    }

    fn target(&self) -> Target {
        self.imp().target.get().unwrap_or(Target::Group)
    }

    fn search(&self) {
        let imp = self.imp();
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        empty(&imp.candidates_list);
        imp.candidates_list.set_visible(false);
        let text = imp.search_entry.text().trim().to_owned();
        let section = imp.section.get().and_then(Weak::upgrade);
        let connection = section.as_ref().and_then(|s| s.connection());
        let (Some(connection), false) = (connection, text.is_empty()) else {
            imp.count.set_label("");
            return;
        };
        let domain = section.map(|s| s.domain()).unwrap_or_default();
        imp.count.set_label(&tr("Searching…"));
        let target = self.target();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read =
                gio::spawn_blocking(move || gp::search_principals(&connection, target, &text))
                    .await;
            let Some(d) = weak.upgrade() else { return };
            let imp = d.imp();
            if generation != imp.generation.get() {
                return;
            }
            match read {
                Ok(Ok(None)) => imp
                    .count
                    .set_label(&tr("Too many results: refine the search.")),
                Ok(Ok(Some(found))) => {
                    for x in found.iter().take(20) {
                        let row = adw::ActionRow::builder()
                            .title(escape(&x.name).as_str())
                            .subtitle(escape(&x.dn).as_str())
                            .activatable(true)
                            .build();
                        imp.candidates_list.append(&row);
                    }
                    imp.candidates_list.set_visible(!found.is_empty());
                    imp.count.set_label(&if found.is_empty() {
                        tr("No results.")
                    } else {
                        fill(
                            &tr("{n} result(s); Enter on a row chooses it."),
                            &[("n", &found.len().to_string())],
                        )
                    });
                    *imp.found.borrow_mut() = found;
                }
                Ok(Err(failure)) => imp
                    .count
                    .set_label(&errors::failure_problem(&failure, &domain).message),
                Err(_) => {}
            }
        });
    }

    fn name_of(&self, x: &Principal) -> String {
        if self.target() == Target::Ou {
            return x.dn.clone();
        }
        let account = if x.account.is_empty() {
            &x.name
        } else {
            &x.account
        };
        let netbios = self.imp().netbios.borrow();
        if netbios.is_empty() {
            account.clone()
        } else {
            format!("{netbios}\\{account}")
        }
    }

    fn candidate(&self, row: &gtk::ListBoxRow) {
        let imp = self.imp();
        let Some(x) = usize::try_from(row.index())
            .ok()
            .and_then(|i| imp.found.borrow().get(i).cloned())
        else {
            return;
        };
        imp.chosen_row.set_subtitle(&escape(&self.name_of(&x)));
        *imp.chosen.borrow_mut() = Some(x);
        self.changed();
        imp.continue_button.grab_focus();
    }

    fn changed(&self) {
        let imp = self.imp();
        let ok = if self.target() == Target::Computer {
            !imp.computer_entry.text().trim().is_empty()
        } else {
            imp.chosen
                .borrow()
                .as_ref()
                .is_some_and(|x| self.target() == Target::Ou || x.sid.is_some())
        };
        imp.continue_button.set_sensitive(ok);
    }

    /// Searches `text`, chooses the first result (or types the computer name), continues;
    /// false if nothing could be chosen (trials).
    pub async fn trial_choose(&self, text: &str) -> bool {
        let imp = self.imp();
        if self.target() == Target::Computer {
            imp.computer_entry.set_text(text);
        } else {
            imp.search_entry.set_text(text);
            self.search();
            for _ in 0..500 {
                if !imp.found.borrow().is_empty() {
                    break;
                }
                glib::timeout_future(std::time::Duration::from_millis(10)).await;
            }
            eprintln!("essai préférences recherche : {}", imp.count.label());
            let Some(row) = imp.candidates_list.row_at_index(0) else {
                return false;
            };
            self.candidate(&row);
        }
        self.changed();
        let ok = imp.continue_button.is_sensitive();
        self.proceed();
        ok
    }

    fn proceed(&self) {
        let imp = self.imp();
        if !imp.continue_button.is_sensitive() {
            return;
        }
        let not = imp.not_switch.is_active();
        let or = imp.ou_switch.is_active();
        let computer = imp.computer_switch.is_active();
        let chosen = imp.chosen.borrow().clone();
        let f = match (self.target(), chosen) {
            (Target::Computer, _) => pv::computer_filter(
                imp.computer_entry.text().trim(),
                imp.dns_switch.is_active(),
                not,
                or,
            ),
            (_, None) => return,
            (Target::Group, Some(x)) => pv::group_filter(
                &self.name_of(&x),
                x.sid.as_deref().unwrap_or_default(),
                computer,
                not,
                or,
            ),
            (Target::Ou, Some(x)) => {
                pv::ou_filter(&x.dn, computer, imp.direct_switch.is_active(), not, or)
            }
            (Target::User, Some(x)) => pv::user_filter(
                &self.name_of(&x),
                x.sid.as_deref().unwrap_or_default(),
                not,
                or,
            ),
        };
        let done = imp.done.take();
        self.close();
        if let Some(done) = done {
            done(f);
        }
    }
}

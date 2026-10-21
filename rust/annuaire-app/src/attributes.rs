// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Attribute editor, « Attributes » tab of the sheet (J4.4, `annuaire.ui.attributs`):
//! structure in `attributs.blp`, `dialogue-attribut.blp` and `dialogue-classes.blp`, logic in
//! `attribute_views` and `inputs`. The tab reads, when it is opened, the whole object on the
//! source (`EDITOR_ATTRIBUTES`) and the schema (once per source), in parallel, without
//! delaying the sheet. Enter or a double click on a row opens its values; a change checked
//! against the syntax goes to the draft of the sheet, as the inputs of the other tabs, and is
//! applied with them.

use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::cache::Source;
use annuaire_core::schema::SchemaError;
use gtk::{gio, glib};

use crate::attribute_views::{self as av, AttributeLine, AuxiliaryClass};
use crate::errors;
use crate::i18n::{fill, tr, tr_n};
use crate::inputs;
use crate::sheet_views::AttributeEdit;

/// The changes waiting in the draft of the sheet (it changes at each reading).
pub type Edits = Rc<dyn Fn() -> Vec<AttributeEdit>>;
/// Puts a change in the draft; a message if it is refused (`_garder`).
pub type Keep = Rc<dyn Fn(AttributeEdit) -> Option<String>>;

// --- Row of the table --------------------------------------------------------------------

mod line {
    use std::cell::OnceCell;
    use std::sync::OnceLock;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::attribute_views::AttributeLine;

    /// Properties declared by hand: the derive of gtk-rs cannot name one `type`, which the
    /// Blueprint binds (`item as <$AnnuaireLigneAttribut>.type`).
    #[derive(Debug, Default)]
    pub struct Line {
        pub view: OnceCell<AttributeLine>,
    }

    impl Line {
        pub fn view(&self) -> &AttributeLine {
            self.view.get().expect("line built by Line::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Line {
        const NAME: &'static str = "AnnuaireLigneAttribut";
        type Type = super::Line;
    }

    impl ObjectImpl for Line {
        fn properties() -> &'static [glib::ParamSpec] {
            static PROPERTIES: OnceLock<Vec<glib::ParamSpec>> = OnceLock::new();
            PROPERTIES.get_or_init(|| {
                ["nom", "resume", "type", "etat", "raison"]
                    .into_iter()
                    .map(|name| glib::ParamSpecString::builder(name).read_only().build())
                    .collect()
            })
        }

        fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
            let view = self.view();
            match pspec.name() {
                "nom" => view.name.to_value(),
                "resume" => view.summary().to_value(),
                "type" => view.kind().to_value(),
                "etat" => view.state().to_value(),
                _ => view.reason.clone().unwrap_or_default().to_value(),
            }
        }
    }
}

glib::wrapper! {
    /// A row of the table (`LigneAttributObjet`).
    pub struct Line(ObjectSubclass<line::Line>);
}

impl Line {
    pub fn new(view: AttributeLine) -> Self {
        let line: Self = glib::Object::new();
        let _ = line.imp().view.set(view);
        line
    }

    pub fn view(&self) -> &AttributeLine {
        self.imp().view()
    }
}

// --- Editor ------------------------------------------------------------------------------

mod imp {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::sync::Arc;

    use annuaire_core::cache::Source;
    use annuaire_core::schema::Schema;
    use annuaire_core::source::Record;
    use gtk::glib;
    use gtk::subclass::prelude::*;

    use crate::attribute_views::AttributeLine;
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/attributs.ui")]
    pub struct AttributesPage {
        #[template_child]
        pub search: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub filled_button: TemplateChild<gtk::ToggleButton>,
        #[template_child]
        pub editable_button: TemplateChild<gtk::ToggleButton>,
        #[template_child]
        pub classes_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub store: TemplateChild<gtk::gio::ListStore>,
        #[template_child]
        pub count: TemplateChild<gtk::Label>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub dn: OnceCell<String>,
        pub read_only: Cell<bool>,
        pub edits: OnceCell<super::Edits>,
        pub keep: OnceCell<super::Keep>,
        /// The rows no longer show the draft (refreshed when shown).
        pub stale: Cell<bool>,
        pub read: RefCell<Option<(Record, Arc<Schema>)>>,
        pub all: RefCell<Vec<AttributeLine>>,
        /// Number of the reading in progress: an answer of an outdated reading is ignored.
        pub reading: Cell<u64>,
        pub busy: Cell<bool>,
    }

    impl std::fmt::Debug for AttributesPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AttributesPage")
                .field("dn", &self.dn.get())
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for AttributesPage {
        const NAME: &'static str = "AnnuaireEditeurAttributs";
        type Type = super::AttributesPage;
        type ParentType = gtk::Box;

        fn class_init(klass: &mut Self::Class) {
            <super::Line as gtk::prelude::StaticTypeExt>::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::AttributesPage>(&[
                ("filter_changed", |p, _| {
                    p.filter_changed();
                    None
                }),
                ("activated", |p, args| {
                    if let Some(position) = args.get(1).and_then(|v| v.get::<u32>().ok()) {
                        p.activated(position);
                    }
                    None
                }),
                ("edit_classes", |p, _| {
                    let _ = p.classes();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for AttributesPage {}
    impl WidgetImpl for AttributesPage {}
    impl BoxImpl for AttributesPage {}
}

glib::wrapper! {
    /// Table of every attribute of an object, filterable, opened on a value
    /// (`AnnuaireEditeurAttributs`).
    pub struct AttributesPage(ObjectSubclass<imp::AttributesPage>)
        @extends gtk::Box, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Orientable;
}

fn schema_message(error: &SchemaError, domain: &str) -> String {
    match error {
        SchemaError::Failure(f) => errors::failure_problem(f, domain).message,
        SchemaError::Search(e) => errors::search_problem(e, domain).message,
    }
}

impl AttributesPage {
    /// `edits` gives those of the draft of the sheet; `keep` puts a change there
    /// (`configurer`).
    pub fn configure(
        &self,
        source: Arc<dyn Source>,
        dn: &str,
        read_only: bool,
        edits: Edits,
        keep: Keep,
    ) {
        let imp = self.imp();
        let _ = imp.source.set(source);
        let _ = imp.dn.set(dn.to_owned());
        imp.read_only.set(read_only);
        let _ = imp.edits.set(edits);
        let _ = imp.keep.set(keep);
    }

    /// The tab becomes visible: read the object if it is not, else bring the rows up to date
    /// with the draft (`montrer`).
    pub fn show_tab(&self) {
        let imp = self.imp();
        if imp.read.borrow().is_none() {
            self.load();
        } else if imp.stale.get() {
            self.fill();
        }
    }

    /// The draft of the sheet changed: rows to redo, at once if shown (`rafraichir`).
    pub fn refresh(&self) {
        let imp = self.imp();
        imp.stale.set(true);
        if self.is_mapped() && imp.read.borrow().is_some() {
            self.fill();
        }
    }

    /// The object was read again (« Read again »): read at the next opening, at once if the
    /// tab is shown (`invalider`).
    pub fn invalidate(&self) {
        let imp = self.imp();
        imp.read.take();
        imp.reading.set(imp.reading.get() + 1);
        imp.busy.set(false);
        if self.is_mapped() {
            self.load();
        }
    }

    fn load(&self) {
        let imp = self.imp();
        let Some(source) = imp.source.get().cloned() else {
            return;
        };
        if imp.busy.replace(true) {
            return;
        }
        let number = imp.reading.get() + 1;
        imp.reading.set(number);
        imp.state.set_visible_child_name("chargement");
        let dn = imp.dn.get().cloned().unwrap_or_default();
        let domain = source.profile().domain.clone();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            // The object and the schema in parallel.
            let (for_record, for_schema, asked) = (source.clone(), source, dn.clone());
            let record =
                gio::spawn_blocking(move || for_record.record(&asked, &av::EDITOR_ATTRIBUTES));
            let schema = gio::spawn_blocking(move || for_schema.schema());
            let (record, schema) = (record.await, schema.await);
            let Some(page) = weak.upgrade() else { return };
            let imp = page.imp();
            if number != imp.reading.get() || !imp.busy.get() {
                return; // outdated reading
            }
            imp.busy.set(false);
            let failed = |message: &str| {
                imp.error
                    .set_description(Some(&glib::markup_escape_text(message)));
                imp.state.set_visible_child_name("erreur");
            };
            let (Ok(record), Ok(schema)) = (record, schema) else {
                return;
            };
            let schema = match schema {
                Ok(schema) => schema,
                Err(error) => return failed(&schema_message(&error, &domain)),
            };
            match record {
                Ok(Some(record)) => {
                    *imp.read.borrow_mut() = Some((record, schema));
                    page.fill();
                }
                Ok(None) => failed(&tr("This object no longer exists.")),
                Err(failure) => failed(&errors::failure_problem(&failure, &domain).message),
            }
        });
    }

    fn edits(&self) -> Vec<AttributeEdit> {
        self.imp().edits.get().map(|e| e()).unwrap_or_default()
    }

    /// Every row from the object read and the draft, then the filter (`_remplir`).
    fn fill(&self) {
        let imp = self.imp();
        let edits = self.edits();
        {
            let read = imp.read.borrow();
            let Some((record, schema)) = read.as_ref() else {
                return;
            };
            imp.stale.set(false);
            *imp.all.borrow_mut() = av::lines(
                &record.entry.dn,
                &record.entry.attributes,
                schema,
                &edits,
                imp.read_only.get(),
            );
        }
        self.apply_filter();
        // No objectClass in allowedAttributesEffective with Samba: the DC will decide.
        let class = imp
            .all
            .borrow()
            .iter()
            .any(|x| x.name.eq_ignore_ascii_case("objectclass"));
        imp.classes_button
            .set_sensitive(class && !imp.read_only.get());
    }

    /// Puts the change in the draft; a message if it is refused (`_garder`).
    fn keep(&self, line: &AttributeLine, wanted: Vec<Vec<u8>>) -> Option<String> {
        let edit = AttributeEdit {
            attribute: line.name.clone(),
            single: line.single(),
            origin: line.values.clone(),
            wanted,
        };
        let keep = self.imp().keep.get()?.clone();
        if let Some(problem) = keep(edit) {
            return Some(problem);
        }
        self.fill();
        None
    }

    /// « Auxiliary Classes… » (`edit_classes`).
    fn classes(&self) -> Option<ClassesDialog> {
        let imp = self.imp();
        let read = imp.read.borrow();
        let (_, schema) = read.as_ref()?;
        let all = imp.all.borrow();
        let class = all
            .iter()
            .find(|x| x.name.eq_ignore_ascii_case("objectclass"))
            .cloned()?;
        let text = |v: &Vec<u8>| String::from_utf8_lossy(v).into_owned();
        let read_classes: Vec<String> = class.values.iter().map(text).collect();
        let wanted: Vec<String> = class.wanted.iter().map(text).collect();
        let filled: HashSet<String> = all
            .iter()
            .filter(|x| x.filled())
            .map(|x| x.name.to_lowercase())
            .collect();
        let offered = av::auxiliary_classes(&read_classes, schema, &wanted, &filled);
        drop(all);
        drop(read);
        let weak = self.downgrade();
        let dialog = ClassesDialog::new(
            class,
            offered,
            Rc::new(move |line, wanted| weak.upgrade().and_then(|page| page.keep(line, wanted))),
        );
        dialog.present(Some(self));
        Some(dialog)
    }

    fn filter_changed(&self) {
        if self.imp().read.borrow().is_some() {
            self.apply_filter();
        }
    }

    fn apply_filter(&self) {
        let imp = self.imp();
        let chosen = imp
            .selection
            .selected_item()
            .and_downcast::<Line>()
            .map(|l| l.view().name.clone());
        let all = imp.all.borrow();
        let shown = av::filter(
            &all,
            &imp.search.text(),
            imp.filled_button.is_active(),
            imp.editable_button.is_active(),
        );
        let objects: Vec<glib::Object> = shown
            .iter()
            .map(|x| Line::new((*x).clone()).upcast())
            .collect();
        imp.store.splice(0, imp.store.n_items(), &objects);
        imp.count
            .set_label(&av::describe_count(shown.len(), all.len()));
        imp.state
            .set_visible_child_name(if shown.is_empty() { "vide" } else { "liste" });
        let position = shown
            .iter()
            .position(|x| chosen.as_deref() == Some(x.name.as_str()))
            .and_then(|p| u32::try_from(p).ok());
        imp.selection
            .set_selected(position.unwrap_or(gtk::INVALID_LIST_POSITION));
    }

    /// Every row once read, as `name, type, state, reason, values` (trials).
    pub fn trial_lines(&self) -> Option<Vec<String>> {
        let imp = self.imp();
        imp.read.borrow().as_ref()?;
        Some(
            imp.all
                .borrow()
                .iter()
                .map(|l| {
                    let values: Vec<String> = l
                        .values
                        .iter()
                        .map(|v| av::show(l.description.as_ref(), &l.name, v, true))
                        .collect();
                    format!(
                        "{}\t{}\t{}\t{}\t{}\t{}",
                        l.name,
                        l.kind(),
                        l.state(),
                        l.reason.clone().unwrap_or_default(),
                        l.summary(),
                        values.join(" | ")
                    )
                })
                .collect(),
        )
    }

    /// Opens the values of `name`, types `text` and confirms; `classe:NAME` ticks or unticks
    /// an auxiliary class (`text`: 1 or 0) (trials).
    pub fn trial_edit(&self, name: &str, text: &str) {
        if let Some(class) = name.strip_prefix("classe:") {
            if let Some(dialog) = self.classes() {
                dialog.trial_tick(class, text == "1");
            }
            return;
        }
        let line = self
            .imp()
            .all
            .borrow()
            .iter()
            .find(|l| l.name.eq_ignore_ascii_case(name))
            .cloned();
        let Some(line) = line else {
            eprintln!("essai attribut : {name} absent");
            return;
        };
        let weak = self.downgrade();
        let dialog = AttributeDialog::new(
            &line,
            Rc::new(move |line, wanted| weak.upgrade().and_then(|page| page.keep(line, wanted))),
        );
        dialog.present(Some(self));
        let confirmed = dialog.trial_confirm(text);
        eprintln!(
            "essai attribut {name} : {confirmed} ({})",
            dialog.imp().message.label()
        );
    }

    fn activated(&self, position: u32) {
        let imp = self.imp();
        let Some(line) = imp.store.item(position).and_downcast::<Line>() else {
            return;
        };
        imp.selection.set_selected(position);
        let weak = self.downgrade();
        AttributeDialog::new(
            line.view(),
            Rc::new(move |line, wanted| weak.upgrade().and_then(|page| page.keep(line, wanted))),
        )
        .present(Some(self));
    }
}

/// What a dialog gives its change to: the editor, that puts it in the draft.
type Give = Rc<dyn Fn(&AttributeLine, Vec<Vec<u8>>) -> Option<String>>;

// --- Dialog of the values of an attribute ------------------------------------------------

mod dialog_imp {
    use std::cell::{Cell, OnceCell, RefCell};

    use adw::subclass::prelude::*;
    use gtk::glib;

    use crate::attribute_views::AttributeLine;
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-attribut.ui")]
    pub struct AttributeDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub cancel_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub confirm_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub syntax_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub reason_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub single_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub value_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub values_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub values_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub values_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub add_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub add_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub message: TemplateChild<gtk::Label>,
        pub line: OnceCell<AttributeLine>,
        pub give: OnceCell<super::Give>,
        pub wanted: RefCell<Vec<Vec<u8>>>,
        pub invalid: Cell<bool>,
        pub initial: RefCell<String>,
    }

    impl std::fmt::Debug for AttributeDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AttributeDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for AttributeDialog {
        const NAME: &'static str = "AnnuaireDialogueAttribut";
        type Type = super::AttributeDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::AttributeDialog>(&[
                ("cancel", |d, _| {
                    adw::prelude::AdwDialogExt::close(d);
                    None
                }),
                ("confirm", |d, _| {
                    d.confirm();
                    None
                }),
                ("entry_changed", |d, _| {
                    d.input_changed();
                    None
                }),
                ("addition_changed", |d, _| {
                    let entry = d.imp().add_entry.get();
                    d.check(&entry, true);
                    None
                }),
                ("add", |d, _| {
                    d.add();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for AttributeDialog {}
    impl WidgetImpl for AttributeDialog {}
    impl AdwDialogImpl for AttributeDialog {}
}

glib::wrapper! {
    /// Value(s) of an attribute: change checked according to the syntax, or reading
    /// (`AnnuaireDialogueAttribut`).
    pub struct AttributeDialog(ObjectSubclass<dialog_imp::AttributeDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl AttributeDialog {
    fn new(line: &AttributeLine, give: Give) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.line.set(line.clone());
        let _ = imp.give.set(give);
        *imp.wanted.borrow_mut() = line.wanted.clone();
        dialog.set_title(&line.name);
        imp.title.set_title(&line.name);
        let description = av::attribute_description(line);
        imp.title.set_subtitle(&description);
        imp.syntax_row.set_subtitle(&description);
        imp.reason_row.set_visible(!line.editable());
        imp.reason_row.set_subtitle(&glib::markup_escape_text(
            line.reason.as_deref().unwrap_or(""),
        ));
        let editable = line.editable() && line.description.is_some();
        let single = editable && line.single();
        imp.single_group.set_visible(single);
        imp.values_group.set_visible(!single);
        imp.add_group.set_visible(editable && !line.single());
        imp.confirm_button.set_visible(editable);
        if !editable {
            imp.cancel_button.set_label(&tr("Close"));
        }
        imp.message.set_label(&if editable {
            av::input_help(line)
        } else {
            String::new()
        });
        if let (true, Some(d)) = (single, line.description.as_ref()) {
            let text = line
                .wanted
                .first()
                .map(|v| annuaire_core::schema::edit_text(d, v))
                .unwrap_or_default();
            *imp.initial.borrow_mut() = text.clone();
            imp.value_entry.set_text(&text);
            dialog.set_focus(Some(&*imp.value_entry));
        } else {
            dialog.show_values();
            if editable {
                dialog.set_focus(Some(&*imp.add_entry));
            }
        }
        dialog
    }

    fn line(&self) -> &AttributeLine {
        self.imp().line.get().expect("set by new")
    }

    // --- Several values -----------------------------------------------------------------

    /// `_montrer_valeurs`.
    fn show_values(&self) {
        let imp = self.imp();
        while let Some(child) = imp.values_list.first_child() {
            imp.values_list.remove(&child);
        }
        let line = self.line().clone();
        let wanted = imp.wanted.borrow().clone();
        for value in &wanted {
            let text = av::show(line.description.as_ref(), &line.name, value, true);
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&text).as_str())
                .title_selectable(true)
                .title_lines(6)
                .build();
            if !line.values.contains(value) {
                row.set_subtitle(&tr("to add"));
            }
            if line.editable() {
                let button = gtk::Button::builder()
                    .icon_name("list-remove-symbolic")
                    .valign(gtk::Align::Center)
                    .tooltip_text(tr("Remove this value"))
                    .build();
                button.add_css_class("flat");
                button.update_property(&[gtk::accessible::Property::Label(&fill(
                    &tr("Remove {valeur}"),
                    &[("valeur", &text)],
                ))]);
                let (weak, value) = (self.downgrade(), value.clone());
                button.connect_clicked(move |_| {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.remove(&value);
                    }
                });
                row.add_suffix(&button);
            }
            imp.values_list.append(&row);
        }
        let removed = line.values.iter().filter(|v| !wanted.contains(v)).count();
        let n = wanted.len();
        let mut text = fill(
            &tr_n("{n} value", "{n} values", n as u64),
            &[("n", &n.to_string())],
        );
        if removed > 0 {
            text = fill(
                &tr("{texte}, {r} to remove"),
                &[("texte", &text), ("r", &removed.to_string())],
            );
        }
        imp.values_count.set_label(&text);
        if wanted.is_empty() {
            let empty = adw::ActionRow::builder().title(tr("No value")).build();
            empty.add_css_class("dim-label");
            imp.values_list.append(&empty);
        }
        self.update();
    }

    /// `_retirer`.
    fn remove(&self, value: &[u8]) {
        let imp = self.imp();
        {
            let mut wanted = imp.wanted.borrow_mut();
            if let Some(i) = wanted.iter().position(|v| v == value) {
                wanted.remove(i);
            }
        }
        self.show_values();
        imp.add_entry.grab_focus();
    }

    /// `add`.
    fn add(&self) {
        let imp = self.imp();
        let Some(description) = self.line().description.clone() else {
            return;
        };
        let value = match inputs::read_input(&description, &imp.add_entry.text()) {
            Ok(value) => value,
            Err(problem) => {
                self.signal(&imp.add_entry, Some(&problem));
                return;
            }
        };
        if imp.wanted.borrow().contains(&value) {
            self.signal(&imp.add_entry, Some(&tr("This value is already there.")));
            return;
        }
        imp.wanted.borrow_mut().push(value);
        imp.add_entry.set_text("");
        self.show_values();
        imp.add_entry.grab_focus();
    }

    // --- One value ----------------------------------------------------------------------

    /// `entry_changed`.
    fn input_changed(&self) {
        let entry = self.imp().value_entry.get();
        self.check(&entry, true);
        self.update();
    }

    /// The value read back from the input; message and error mark otherwise (`_verifier`).
    fn check(&self, entry: &adw::EntryRow, empty_allowed: bool) -> Option<Vec<u8>> {
        let text = entry.text();
        let Some(description) = self.line().description.clone() else {
            self.signal(entry, None);
            return None;
        };
        if empty_allowed && text.trim().is_empty() {
            self.signal(entry, None);
            return None;
        }
        match inputs::read_input(&description, &text) {
            Ok(value) => {
                self.signal(entry, None);
                Some(value)
            }
            Err(problem) => {
                self.signal(entry, Some(&problem));
                None
            }
        }
    }

    /// `_signaler`.
    fn signal(&self, entry: &adw::EntryRow, problem: Option<&str>) {
        let imp = self.imp();
        imp.invalid.set(problem.is_some());
        match problem {
            None => {
                entry.remove_css_class("error");
                imp.message.set_label(&av::input_help(self.line()));
            }
            Some(problem) => {
                entry.add_css_class("error");
                imp.message.set_label(problem);
            }
        }
        self.update();
    }

    /// Wanted value of an attribute of one value; None if the input is invalid
    /// (`_voulues_unique`).
    fn single_wanted(&self) -> Option<Vec<Vec<u8>>> {
        let imp = self.imp();
        let line = self.line();
        let description = line.description.as_ref()?;
        let text = imp.value_entry.text();
        if text.trim().is_empty() {
            return Some(Vec::new());
        }
        if text.trim() == imp.initial.borrow().trim() && !line.wanted.is_empty() {
            return Some(line.wanted.clone()); // unchanged: the value read, byte for byte
        }
        inputs::read_input(description, &text).ok().map(|v| vec![v])
    }

    /// `_actualiser`.
    fn update(&self) {
        let imp = self.imp();
        let line = self.line();
        let possible = if line.single() {
            self.single_wanted()
                .is_some_and(|wanted| wanted != line.wanted)
        } else {
            *imp.wanted.borrow() != line.wanted
                && !(imp.invalid.get() && !imp.add_entry.text().trim().is_empty())
        };
        imp.confirm_button.set_sensitive(possible);
    }

    /// `confirm`.
    fn confirm(&self) {
        let imp = self.imp();
        if !imp.confirm_button.is_sensitive() {
            return;
        }
        let wanted = if self.line().single() {
            self.single_wanted()
        } else {
            Some(imp.wanted.borrow().clone())
        };
        let (Some(wanted), Some(give)) = (wanted, imp.give.get().cloned()) else {
            return;
        };
        if let Some(problem) = give(self.line(), wanted) {
            imp.message.set_label(&problem);
            return;
        }
        self.close();
    }

    /// Types `text` and confirms (trials).
    pub fn trial_confirm(&self, text: &str) -> bool {
        let imp = self.imp();
        if self.line().single() {
            imp.value_entry.set_text(text);
        } else {
            imp.add_entry.set_text(text);
            self.add();
        }
        let sensitive = imp.confirm_button.is_sensitive();
        self.confirm();
        sensitive
    }
}

// --- Dialog of the auxiliary classes -----------------------------------------------------

mod classes_imp {
    use std::cell::{OnceCell, RefCell};

    use adw::subclass::prelude::*;
    use gtk::glib;

    use crate::attribute_views::{AttributeLine, AuxiliaryClass};
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-classes.ui")]
    pub struct ClassesDialog {
        #[template_child]
        pub confirm_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub message: TemplateChild<gtk::Label>,
        pub line: OnceCell<AttributeLine>,
        pub classes: OnceCell<Vec<AuxiliaryClass>>,
        pub give: OnceCell<super::Give>,
        pub boxes: RefCell<Vec<(String, gtk::CheckButton)>>,
    }

    impl std::fmt::Debug for ClassesDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ClassesDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ClassesDialog {
        const NAME: &'static str = "AnnuaireDialogueClasses";
        type Type = super::ClassesDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::ClassesDialog>(&[
                ("cancel", |d, _| {
                    adw::prelude::AdwDialogExt::close(d);
                    None
                }),
                ("confirm", |d, _| {
                    d.confirm();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ClassesDialog {}
    impl WidgetImpl for ClassesDialog {}
    impl AdwDialogImpl for ClassesDialog {}
}

glib::wrapper! {
    /// Auxiliary classes offered by the schema: tick to add, untick to remove
    /// (`AnnuaireDialogueClasses`).
    pub struct ClassesDialog(ObjectSubclass<classes_imp::ClassesDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl ClassesDialog {
    fn new(line: AttributeLine, classes: Vec<AuxiliaryClass>, give: Give) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        for class in &classes {
            let check = gtk::CheckButton::builder()
                .active(class.wanted)
                .valign(gtk::Align::Center)
                .build();
            check.update_property(&[gtk::accessible::Property::Label(&class.name)]);
            let mut details = vec![class.subtitle()];
            if !class.mandatory.is_empty() {
                details.push(fill(
                    &tr("Mandatory: {liste}"),
                    &[("liste", &class.mandatory.join(", "))],
                ));
            }
            if let Some(reason) = &class.reason {
                details.push(reason.clone());
                check.set_sensitive(false);
            }
            let row = adw::ActionRow::builder()
                .title(&class.name)
                .subtitle(glib::markup_escape_text(&details.join("\n")).as_str())
                .activatable_widget(&check)
                .subtitle_lines(0)
                .build();
            row.add_prefix(&check);
            let weak = dialog.downgrade();
            check.connect_toggled(move |_| {
                if let Some(dialog) = weak.upgrade() {
                    dialog.changed();
                }
            });
            imp.list.append(&row);
            imp.boxes.borrow_mut().push((class.name.clone(), check));
        }
        if classes.is_empty() {
            let empty = adw::ActionRow::builder()
                .title(tr("No auxiliary class offered for this object."))
                .build();
            imp.list.append(&empty);
        }
        let _ = imp.line.set(line);
        let _ = imp.classes.set(classes);
        let _ = imp.give.set(give);
        dialog.changed();
        dialog
    }

    fn edit(&self) -> AttributeEdit {
        let imp = self.imp();
        let chosen: HashSet<String> = imp
            .boxes
            .borrow()
            .iter()
            .filter(|(_, c)| c.is_active())
            .map(|(n, _)| n.clone())
            .collect();
        let line = imp.line.get().expect("set by new");
        av::classes_edit(
            &line.values,
            imp.classes.get().map(Vec::as_slice).unwrap_or_default(),
            &chosen,
        )
    }

    /// `_change`.
    fn changed(&self) {
        let imp = self.imp();
        let Some(line) = imp.line.get() else { return };
        let wanted = self.edit().wanted;
        imp.confirm_button.set_sensitive(wanted != line.wanted);
        let text = |v: &Vec<u8>| String::from_utf8_lossy(v).into_owned();
        let added: Vec<String> = wanted
            .iter()
            .filter(|v| !line.values.contains(v))
            .map(text)
            .collect();
        let removed: Vec<String> = line
            .values
            .iter()
            .filter(|v| !wanted.contains(v))
            .map(text)
            .collect();
        let mut pieces = Vec::new();
        if !added.is_empty() {
            pieces.push(fill(
                &tr("To add: {liste}"),
                &[("liste", &added.join(", "))],
            ));
        }
        if !removed.is_empty() {
            pieces.push(fill(
                &tr("To remove: {liste}"),
                &[("liste", &removed.join(", "))],
            ));
        }
        imp.message.set_label(&pieces.join(&tr("; ")));
    }

    /// Ticks or unticks `name`, then confirms (trials).
    pub fn trial_tick(&self, name: &str, active: bool) {
        let check = self
            .imp()
            .boxes
            .borrow()
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, c)| c.clone());
        if let Some(check) = check {
            check.set_active(active);
        }
        eprintln!("essai classes : {}", self.imp().message.label());
        self.confirm();
    }

    /// `confirm`.
    fn confirm(&self) {
        let imp = self.imp();
        if !imp.confirm_button.is_sensitive() {
            return;
        }
        let (Some(line), Some(give)) = (imp.line.get(), imp.give.get().cloned()) else {
            return;
        };
        if let Some(problem) = give(line, self.edit().wanted) {
            imp.message.set_label(&problem);
            return;
        }
        self.close();
    }
}

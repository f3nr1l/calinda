// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Search of the objects to add to the members of a group (J2.5, `AnnuaireDialogueMembres`
//! of `annuaire.ui.fiche`). Structure in `dialogue-membres.blp`. A result chosen goes to the
//! draft of the sheet; nothing is written here.

use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::cache::Source;
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::errors;
use crate::feed::Feed;
use crate::i18n::{fill, tr, tr_n};
use crate::objects::Element;
use crate::sheet_views::{self as sv, ElementView};
use crate::views;

/// Results shown at once; « Show more » shows the next slice (`RESULTATS_MAX`).
const MAX_RESULTS: u32 = 50;

/// What a chosen result is given to.
pub type Add = Box<dyn Fn(ElementView)>;

mod imp {
    use std::cell::{OnceCell, RefCell};
    use std::rc::Rc;
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_core::cache::Source;
    use gtk::glib;

    use crate::feed::Feed;
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-membres.ui")]
    pub struct MembersDialog {
        #[template_child]
        pub member_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub search_state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub search_message: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub more_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub add: OnceCell<super::Add>,
        pub search: RefCell<Option<Rc<Feed>>>,
        /// Shown results; `all` holds every result received.
        pub results: OnceCell<gtk::gio::ListStore>,
        pub all: RefCell<Vec<super::Element>>,
        /// The search ended with an error (shown once nothing came).
        pub failed: RefCell<Option<String>>,
    }

    impl std::fmt::Debug for MembersDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MembersDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for MembersDialog {
        const NAME: &'static str = "AnnuaireDialogueMembres";
        type Type = super::MembersDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::MembersDialog>(&[
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("show_more", |d, _| {
                    d.show_more();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for MembersDialog {}
    impl WidgetImpl for MembersDialog {}

    impl AdwDialogImpl for MembersDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    pub struct MembersDialog(ObjectSubclass<imp::MembersDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

/// A row of a result (`_ligne`).
fn result_row(element: &glib::Object) -> gtk::Widget {
    let Some(element) = element.downcast_ref::<Element>() else {
        return gtk::Label::new(None).upcast();
    };
    let view = element.view();
    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(&view.title).as_str())
        .subtitle(glib::markup_escape_text(&view.subtitle).as_str())
        .title_lines(1)
        .subtitle_lines(1)
        .activatable(true)
        .tooltip_text(tr("Add to the Members"))
        .build();
    row.add_prefix(&gtk::Image::from_icon_name(&view.icon));
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    row.set_widget_name(&view.dn);
    row.upcast()
}

impl MembersDialog {
    pub fn new(source: Arc<dyn Source>, add: Add) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.source.set(source);
        let _ = imp.add.set(add);
        let results = gio::ListStore::new::<Element>();
        imp.candidates_list.bind_model(Some(&results), result_row);
        let _ = imp.results.set(results);
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.chosen(row);
            }
        });
        dialog
    }

    fn results(&self) -> &gio::ListStore {
        self.imp().results.get().expect("set by new")
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
        self.results().remove_all();
        imp.all.borrow_mut().clear();
        imp.failed.replace(None);
        self.count();
        let Some(filter) = sv::candidates_filter(&imp.member_entry.text()) else {
            imp.search_state.set_visible_child_name("invite");
            return;
        };
        imp.search_state.set_visible_child_name("resultats");
        let source = imp.source.get().expect("set by new").clone();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let elements: Vec<Element> = items
                    .iter()
                    .map(|i| Element::new(sv::element_from_item(i)))
                    .collect();
                let results = dialog.results();
                let room = MAX_RESULTS.saturating_sub(results.n_items()) as usize;
                let shown: Vec<glib::Object> = elements
                    .iter()
                    .take(room)
                    .map(|e| e.clone().upcast())
                    .collect();
                results.splice(results.n_items(), 0, &shown);
                dialog.imp().all.borrow_mut().extend(elements);
                dialog.count();
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                imp.search.take();
                let message = error.map(|e| errors::search_problem(&e, &domain).message);
                let none = imp.all.borrow().is_empty();
                dialog.count();
                match (message, none) {
                    (Some(message), true) => {
                        imp.search_message.set_title(&message);
                        imp.search_state.set_visible_child_name("vide");
                    }
                    (Some(message), false) => imp.candidates_count.set_label(&message),
                    (None, true) => {
                        imp.search_message.set_title(&tr("No results"));
                        imp.search_state.set_visible_child_name("vide");
                    }
                    (None, false) => {}
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
        self.count();
    }

    /// `_compter`.
    fn count(&self) {
        let imp = self.imp();
        let shown = self.results().n_items() as usize;
        let received = imp.all.borrow().len();
        let reading = imp.search.borrow().is_some();
        imp.more_button.set_visible(shown < received);
        let text = if shown < received || reading {
            let text = fill(
                &tr("{montres} results shown out of {recus}"),
                &[
                    ("montres", &views::number(shown as u64)),
                    ("recus", &views::number(received as u64)),
                ],
            );
            if reading {
                fill(&tr("{texte}, reading…"), &[("texte", &text)])
            } else {
                text
            }
        } else {
            fill(
                &tr_n("{n} result", "{n} results", received as u64),
                &[("n", &views::number(received as u64))],
            )
        };
        imp.candidates_count.set_label(&text);
    }

    /// `show_more`.
    fn show_more(&self) {
        let imp = self.imp();
        let results = self.results();
        let start = results.n_items();
        let next: Vec<glib::Object> = imp
            .all
            .borrow()
            .iter()
            .skip(start as usize)
            .take(MAX_RESULTS as usize)
            .map(|e| e.clone().upcast())
            .collect();
        results.splice(start, 0, &next);
        self.count();
        // The focus goes to the first result added (the button may disappear).
        if let Some(row) = imp.candidates_list.row_at_index(start as i32) {
            row.grab_focus();
        }
    }

    /// `_choisi`.
    fn chosen(&self, row: &gtk::ListBoxRow) {
        let dn = row.widget_name();
        let element = self
            .imp()
            .all
            .borrow()
            .iter()
            .find(|e| e.view().dn == dn.as_str())
            .cloned();
        let (Some(element), Some(add)) = (element, self.imp().add.get()) else {
            return;
        };
        add(element.view().clone());
        row.set_sensitive(false);
        if let Some(row) = row.downcast_ref::<adw::ActionRow>() {
            row.set_subtitle(&tr("Added (pending)"));
        }
    }

    /// Types `text` in the search (trials).
    pub fn trial_search(&self, text: &str) {
        self.imp().member_entry.set_text(text);
    }
}

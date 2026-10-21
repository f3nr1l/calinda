// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Writes of the « Security » tab (J4.3, `annuaire.ui.delegation` and `AnnuaireDialogueAce`
//! of `annuaire.ui.securite`): the delegation wizard (to whom, which tasks, preview in clear
//! and in SDDL) and an entry typed in SDDL. Structures in `dialogue-delegation.blp` and
//! `dialogue-ace.blp`, texts in `security_views`. « Continue » reads the descriptor of the
//! object on the write connection (version included), builds the changeset
//! (`actions::delegate`, `actions::add_aces`) and gives it to `writes::propose`: common
//! preview, journal, undo by the original descriptor.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_core::actions::{self, ActionError, ReadObject};
use annuaire_core::cache::Source;
use annuaire_core::changes::{Changeset, Report};
use annuaire_core::connection::Failure;
use annuaire_core::model::Object;
use annuaire_core::security::{Nomenclature, SecurityReading, SidName, Template};
use annuaire_core::source::{Item, name_from_dn};
use gtk::{gio, glib};

use crate::account_views::action_error;
use crate::errors;
use crate::feed::Feed;
use crate::i18n::{fill, tr, tr_n};
use crate::security_views as sv;
use crate::sheet_views as shv;
use crate::writes::{self, Options};

/// Results shown in the wizard (`RESULTATS_MAX`).
pub const MAX_RESULTS: usize = 20;

/// What follows a write (the tab reads again).
pub type Written = Rc<dyn Fn()>;

/// Name of the switch of a template in the Blueprint (`Modele.ident`).
pub fn template_ident(template: Template) -> &'static str {
    match template {
        Template::ResetPasswords => "reinitialiser-mots-de-passe",
        Template::GroupMembers => "membres-des-groupes",
        Template::JoinComputers => "joindre-des-ordinateurs",
        Template::ReadUsers => "lire-les-utilisateurs",
        Template::ManageUsers => "gerer-les-utilisateurs",
    }
}

fn no_hyphens(label: &gtk::Label) {
    // A SDDL cut at the end of a line gets no hyphen: it reads and copies as is.
    if let Ok(attributes) = gtk::pango::AttrList::from_string("0 -1 insert-hyphens false") {
        label.set_attributes(Some(&attributes));
    }
}

/// Error of the preparation of a write: failure of the connection, or of the action.
pub enum Prepared {
    Failure(Failure),
    Action(ActionError),
}

/// Reads the descriptor of `dn` on the write connection and builds the changeset with
/// `build`; the error dialog says what failed. `done` gets the changeset, or None after the
/// error.
pub fn prepare(
    widget: &impl IsA<gtk::Widget>,
    dn: &str,
    title: String,
    build: impl FnOnce(&ReadObject) -> Result<Changeset, ActionError> + Send + 'static,
    done: impl FnOnce(Option<Changeset>) + 'static,
) {
    let Some(context) = writes::context(widget) else {
        done(None);
        return;
    };
    let (connection, domain, asked) = (
        context.connection.clone(),
        context.profile.domain.clone(),
        dn.to_owned(),
    );
    let weak = widget.upcast_ref::<gtk::Widget>().downgrade();
    glib::spawn_future_local(async move {
        let built = gio::spawn_blocking(move || {
            let objects = actions::read_descriptors(&connection, std::slice::from_ref(&asked))
                .map_err(Prepared::Failure)?;
            let object = objects
                .first()
                .ok_or_else(|| Prepared::Action(ActionError::UnreadableDescriptor(asked)))?;
            build(object).map_err(Prepared::Action)
        })
        .await;
        let Some(widget) = weak.upgrade() else { return };
        match built {
            Ok(Ok(changeset)) => return done(Some(changeset)),
            Ok(Err(Prepared::Failure(f))) => {
                let problem = errors::failure_problem(&f, &domain);
                writes::show_error(&widget, &title, &problem.message, &problem.detail);
            }
            Ok(Err(Prepared::Action(e))) => {
                writes::show_error(&widget, &title, &action_error(&e), "");
            }
            Err(_) => {}
        }
        done(None);
    });
}

/// Proposes `changeset` with `remarks`; `written` follows a write (`proposer`).
pub fn propose(
    widget: &impl IsA<gtk::Widget>,
    changeset: Changeset,
    remarks: Vec<String>,
    written: Rc<dyn Fn(&Report)>,
) {
    writes::propose(
        widget,
        Changeset {
            operations: changeset.operations,
            remarks,
        },
        Options {
            finished: Some(Box::new(move |report| {
                if let Some(report) = report {
                    written(report);
                }
            })),
            ..Options::default()
        },
    );
}

// --- Delegation wizard -------------------------------------------------------------------

mod wizard_imp {
    use std::cell::{OnceCell, RefCell};
    use std::rc::Rc;
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_codecs::Sid;
    use annuaire_core::cache::Source;
    use annuaire_core::security::{Nomenclature, SecurityReading, Template};
    use gtk::glib;

    use crate::feed::Feed;
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-delegation.ui")]
    pub struct DelegationDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub delegate_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub delegate_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub preview_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub plain_preview: TemplateChild<gtk::Label>,
        #[template_child]
        pub sddl_preview: TemplateChild<gtk::Label>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub reading: OnceCell<SecurityReading>,
        pub nomenclature: OnceCell<Option<Arc<Nomenclature>>>,
        pub written: RefCell<Option<super::Written>>,
        pub switches: RefCell<Vec<(Template, adw::SwitchRow)>>,
        /// The delegate: DN and name.
        pub delegate: RefCell<Option<(String, String)>>,
        pub sid: RefCell<Option<Sid>>,
        pub search: RefCell<Option<Rc<Feed>>>,
        /// Results received, with the SID their object carries.
        pub received: RefCell<Vec<(crate::sheet_views::ElementView, Option<Sid>)>>,
    }

    impl std::fmt::Debug for DelegationDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DelegationDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for DelegationDialog {
        const NAME: &'static str = "AnnuaireDialogueDelegation";
        type Type = super::DelegationDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::DelegationDialog>(&[
                ("cancel", |d, _| {
                    adw::prelude::AdwDialogExt::close(d);
                    None
                }),
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("tasks_changed", |d, _| {
                    d.update();
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

    impl ObjectImpl for DelegationDialog {}
    impl WidgetImpl for DelegationDialog {}

    impl AdwDialogImpl for DelegationDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// Delegation of tasks on an OU, a container or the domain (`AnnuaireDialogueDelegation`).
    pub struct DelegationDialog(ObjectSubclass<wizard_imp::DelegationDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

fn find_switch(root: &gtk::Widget, name: &str) -> Option<adw::SwitchRow> {
    let mut to_see = vec![root.clone()];
    while let Some(widget) = to_see.pop() {
        if widget.widget_name() == name
            && let Ok(row) = widget.clone().downcast::<adw::SwitchRow>()
        {
            return Some(row);
        }
        let mut child = widget.first_child();
        while let Some(c) = child {
            child = c.next_sibling();
            to_see.push(c);
        }
    }
    None
}

pub fn object_sid(item: &Item) -> Option<Sid> {
    match item {
        Item::Object(object) => match &**object {
            Object::Group { sid, .. } => *sid,
            other => other.account().and_then(|a| a.sid),
        },
        Item::Unreadable { .. } => None,
    }
}

impl DelegationDialog {
    pub fn new(
        source: Arc<dyn Source>,
        reading: SecurityReading,
        nomenclature: Option<Arc<Nomenclature>>,
        written: Written,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title.set_subtitle(&name_from_dn(&reading.dn));
        let _ = imp.source.set(source);
        let _ = imp.reading.set(reading);
        let _ = imp.nomenclature.set(nomenclature);
        *imp.written.borrow_mut() = Some(written);
        if let Some(root) = dialog.child() {
            for template in Template::ALL {
                if let Some(switch) = find_switch(&root, template_ident(template)) {
                    switch.set_title(&sv::template_title(template));
                    switch.set_title_lines(0);
                    imp.switches.borrow_mut().push((template, switch));
                }
            }
        }
        no_hyphens(&imp.sddl_preview);
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.chosen(row);
            }
        });
        imp.candidates_list.set_visible(false);
        dialog
    }

    fn stop(&self) {
        if let Some(feed) = self.imp().search.take() {
            feed.cancel();
        }
    }

    fn source(&self) -> Arc<dyn Source> {
        self.imp().source.get().expect("set by new").clone()
    }

    /// `search`.
    fn search(&self) {
        self.stop();
        let imp = self.imp();
        while let Some(row) = imp.candidates_list.row_at_index(0) {
            imp.candidates_list.remove(&row);
        }
        imp.received.borrow_mut().clear();
        imp.candidates_list.set_visible(false);
        let Some(filter) = sv::delegates_filter(&imp.delegate_entry.text()) else {
            imp.candidates_count.set_label("");
            return;
        };
        imp.candidates_count.set_label(&tr("Searching…"));
        let source = self.source();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                for item in &items {
                    let view = shv::element_from_item(item);
                    let shown = imp.received.borrow().len() < MAX_RESULTS;
                    if shown {
                        imp.candidates_list
                            .append(&candidate_row(&view, &tr("Delegate to this object")));
                    }
                    imp.received.borrow_mut().push((view, object_sid(item)));
                }
                imp.candidates_list
                    .set_visible(!imp.received.borrow().is_empty());
                dialog.count(false);
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                dialog.imp().search.take();
                match error {
                    Some(error) => dialog
                        .imp()
                        .candidates_count
                        .set_label(&errors::search_problem(&error, &domain).message),
                    None => dialog.count(true),
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
    }

    /// `_compter`.
    fn count(&self, finished: bool) {
        let imp = self.imp();
        let n = imp.received.borrow().len();
        imp.candidates_count.set_label(&if finished && n == 0 {
            tr("No group or account found.")
        } else if n > MAX_RESULTS {
            fill(
                &tr("First {montres} results out of {n}: refine the search."),
                &[("montres", &MAX_RESULTS.to_string()), ("n", &n.to_string())],
            )
        } else {
            fill(
                &tr_n("{n} result", "{n} results", n as u64),
                &[("n", &n.to_string())],
            )
        });
    }

    /// `_choisi`.
    fn chosen(&self, row: &gtk::ListBoxRow) {
        let imp = self.imp();
        let dn = row.widget_name().to_string();
        let found = imp
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, sid)) = found else { return };
        imp.delegate_row
            .set_subtitle(&glib::markup_escape_text(&format!(
                "{} · {}",
                view.title, view.subtitle
            )));
        *imp.delegate.borrow_mut() = Some((view.dn.clone(), view.title.clone()));
        *imp.sid.borrow_mut() = sid;
        if sid.is_none() {
            // The local copy may not carry the SID: it is read on the DC.
            let (source, weak) = (self.source(), self.downgrade());
            glib::spawn_future_local(async move {
                let read =
                    gio::spawn_blocking(move || source.record(&view.dn, &["objectSid"])).await;
                let Some(dialog) = weak.upgrade() else { return };
                let sid = match read {
                    Ok(Ok(Some(record))) => record
                        .values("objectSid")
                        .first()
                        .and_then(|v| Sid::decode(v).ok()),
                    Ok(Err(failure)) => {
                        let domain = dialog.source().profile().domain.clone();
                        let problem = errors::failure_problem(&failure, &domain);
                        writes::show_error(
                            &dialog,
                            &tr("Unreadable SID of the delegate"),
                            &problem.message,
                            &problem.detail,
                        );
                        None
                    }
                    _ => None,
                };
                *dialog.imp().sid.borrow_mut() = sid;
                dialog.update();
            });
        }
        self.update();
        if let Some((_, first)) = imp.switches.borrow().first() {
            first.grab_focus();
        }
    }

    fn templates(&self) -> Vec<Template> {
        self.imp()
            .switches
            .borrow()
            .iter()
            .filter(|(_, s)| s.is_active())
            .map(|(t, _)| *t)
            .collect()
    }

    fn who(&self) -> String {
        self.imp()
            .delegate
            .borrow()
            .as_ref()
            .map(|(dn, name)| {
                if name.is_empty() {
                    name_from_dn(dn)
                } else {
                    name.clone()
                }
            })
            .unwrap_or_default()
    }

    /// `_actualiser`.
    fn update(&self) {
        let imp = self.imp();
        let templates = self.templates();
        let sid = *imp.sid.borrow();
        let ready = sid.is_some() && !templates.is_empty();
        imp.continue_button.set_sensitive(ready);
        imp.preview_group.set_visible(ready);
        let (Some(sid), true) = (sid, ready) else {
            return;
        };
        let Some(reading) = imp.reading.get() else {
            return;
        };
        let nomenclature = imp.nomenclature.get().cloned().flatten();
        let (sddl, clear) = sv::delegation_preview(
            &self.who(),
            &sid,
            &templates,
            &reading.classes,
            nomenclature.as_deref(),
        );
        imp.plain_preview.set_label(&clear.join("\n"));
        imp.sddl_preview.set_label(&sddl.join("\n"));
    }

    /// `next`.
    fn proceed(&self) {
        let imp = self.imp();
        let (Some(sid), templates) = (*imp.sid.borrow(), self.templates()) else {
            return;
        };
        let Some(dn) = imp.reading.get().map(|r| r.dn.clone()) else {
            return;
        };
        if templates.is_empty() || writes::context(self).is_none() {
            return;
        }
        imp.continue_button.set_sensitive(false);
        let (weak, who, chosen) = (self.downgrade(), self.who(), templates.clone());
        let target = dn.clone();
        prepare(
            self,
            &dn,
            tr("Delegation not possible"),
            move |object| actions::delegate(object, &sid, &templates),
            move |changeset| {
                let Some(dialog) = weak.upgrade() else { return };
                dialog.update();
                let Some(changeset) = changeset else { return };
                let remarks = sv::delegation_remarks(&who, &chosen, &target, false);
                let after = dialog.downgrade();
                propose(
                    &dialog,
                    changeset,
                    remarks,
                    Rc::new(move |_| {
                        if let Some(dialog) = after.upgrade() {
                            dialog.written();
                        }
                    }),
                );
            },
        );
    }

    /// `_ecrit`: the preview closed without writing keeps the wizard open.
    fn written(&self) {
        let written = self.imp().written.take();
        self.close();
        if let Some(written) = written {
            written();
        }
    }

    /// Types `search`, chooses the first result, ticks `templates` and continues (trials).
    pub fn trial(&self, search: &str, templates: &[String]) {
        let imp = self.imp();
        imp.delegate_entry.set_text(search);
        self.search();
        let (weak, templates) = (self.downgrade(), templates.to_vec());
        glib::timeout_add_local(std::time::Duration::from_millis(50), move || {
            let Some(dialog) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let imp = dialog.imp();
            if imp.search.borrow().is_some() {
                return glib::ControlFlow::Continue;
            }
            if imp.delegate.borrow().is_none() {
                if let Some(row) = imp.candidates_list.row_at_index(0) {
                    dialog.chosen(&row);
                }
                for (template, switch) in imp.switches.borrow().iter() {
                    switch.set_active(templates.iter().any(|t| t == template_ident(*template)));
                }
                return glib::ControlFlow::Continue;
            }
            if imp.sid.borrow().is_none() {
                return glib::ControlFlow::Continue;
            }
            eprintln!(
                "essai délégation : {} | {}",
                imp.plain_preview.label().replace('\n', " / "),
                imp.sddl_preview.label().replace('\n', " ")
            );
            dialog.proceed();
            glib::ControlFlow::Break
        });
    }
}

/// A row of the results of a search of groups and accounts (`_Candidat`); its name is the DN.
pub fn candidate_row(view: &shv::ElementView, tooltip: &str) -> gtk::ListBoxRow {
    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(&view.title).as_str())
        .subtitle(glib::markup_escape_text(&view.subtitle).as_str())
        .activatable(true)
        .tooltip_text(tooltip)
        .build();
    row.add_prefix(&gtk::Image::from_icon_name(&view.icon));
    let wrapper = gtk::ListBoxRow::builder().child(&row).build();
    wrapper.set_widget_name(&view.dn);
    wrapper.update_property(&[gtk::accessible::Property::Label(&format!(
        "{}, {}",
        view.title, view.subtitle
    ))]);
    wrapper
}

// --- Entry typed in SDDL -----------------------------------------------------------------

mod ace_imp {
    use std::cell::{OnceCell, RefCell};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_codecs::Sid;
    use annuaire_core::security::{Nomenclature, SecurityReading, SidName};
    use gtk::glib;

    use crate::scope::TemplateScope;
    use crate::security_views::AceInput;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-ace.ui")]
    pub struct AceDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub preview_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub plain_preview: TemplateChild<gtk::Label>,
        #[template_child]
        pub sddl_preview: TemplateChild<gtk::Label>,
        #[template_child]
        pub preview_remarks: TemplateChild<gtk::Label>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub reading: OnceCell<SecurityReading>,
        pub nomenclature: OnceCell<Option<Arc<Nomenclature>>>,
        pub written: RefCell<Option<super::Written>>,
        pub input: RefCell<Option<AceInput>>,
        pub names: RefCell<HashMap<Sid, SidName>>,
        /// SIDs already looked for in the directory (once each).
        pub asked: RefCell<HashSet<Sid>>,
    }

    impl std::fmt::Debug for AceDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AceDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for AceDialog {
        const NAME: &'static str = "AnnuaireDialogueAce";
        type Type = super::AceDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::AceDialog>(&[
                ("cancel", |d, _| {
                    adw::prelude::AdwDialogExt::close(d);
                    None
                }),
                ("entry_changed", |d, _| {
                    d.input_changed();
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

    impl ObjectImpl for AceDialog {}
    impl WidgetImpl for AceDialog {}
    impl AdwDialogImpl for AceDialog {}
}

glib::wrapper! {
    /// An entry typed in SDDL, added to the DACL by the common preview (`AnnuaireDialogueAce`).
    pub struct AceDialog(ObjectSubclass<ace_imp::AceDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl AceDialog {
    pub fn new(
        reading: SecurityReading,
        nomenclature: Option<Arc<Nomenclature>>,
        written: Written,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title
            .set_subtitle(&glib::markup_escape_text(&reading.dn));
        *imp.names.borrow_mut() = reading.names.clone();
        let _ = imp.reading.set(reading);
        let _ = imp.nomenclature.set(nomenclature);
        *imp.written.borrow_mut() = Some(written);
        no_hyphens(&imp.sddl_preview);
        dialog.input_changed();
        dialog
    }

    /// `entry_changed`.
    fn input_changed(&self) {
        let imp = self.imp();
        let text = imp.entry.text();
        imp.input.take();
        imp.sddl_preview.set_label("");
        imp.preview_remarks.set_visible(false);
        if text.trim().is_empty() {
            imp.entry.remove_css_class("error");
            imp.plain_preview.set_label(&tr(
                "Type an entry in parentheses, for example (A;;RP;;;AU).",
            ));
        } else {
            let Some(reading) = imp.reading.get() else {
                return;
            };
            let nomenclature = imp.nomenclature.get().cloned().flatten();
            let read = sv::ace_input(
                &text,
                nomenclature.as_deref(),
                &reading.classes,
                &imp.names.borrow(),
            );
            match read {
                Err(problem) => {
                    imp.entry.add_css_class("error");
                    imp.plain_preview.set_label(&problem);
                }
                Ok(input) => {
                    imp.entry.remove_css_class("error");
                    imp.plain_preview.set_label(&input.text);
                    imp.sddl_preview.set_label(&input.sddl);
                    imp.preview_remarks.set_label(&input.remarks.join("\n"));
                    imp.preview_remarks.set_visible(!input.remarks.is_empty());
                    *imp.input.borrow_mut() = Some(input);
                }
            }
        }
        let ace = imp.input.borrow().as_ref().map(|i| i.ace.clone());
        imp.continue_button.set_sensitive(ace.is_some());
        if let Some(ace) = ace {
            self.name(&ace);
        }
    }

    /// Looks for the name of the SIDs of the entry (holder, condition), then says the
    /// sentence again (`_nommer`).
    fn name(&self, ace: &annuaire_codecs::sd::Ace) {
        let imp = self.imp();
        let Some(context) = writes::context(self) else {
            return;
        };
        let unknown: HashSet<Sid> = annuaire_core::security::ace_sids(ace)
            .into_iter()
            .filter(|s| !imp.names.borrow().contains_key(s) && !imp.asked.borrow().contains(s))
            .collect();
        if unknown.is_empty() {
            return;
        }
        imp.asked.borrow_mut().extend(unknown.iter().copied());
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let named: Result<Result<HashMap<Sid, SidName>, Failure>, _> =
                gio::spawn_blocking(move || {
                    annuaire_core::security::name_sids(&connection, unknown)
                })
                .await;
            let Some(dialog) = weak.upgrade() else { return };
            // On failure, the SIDs stay as they are.
            if let Ok(Ok(names)) = named {
                dialog.imp().names.borrow_mut().extend(names);
                dialog.input_changed();
            }
        });
    }

    /// `next`.
    fn proceed(&self) {
        let imp = self.imp();
        let Some(input) = imp.input.borrow().clone() else {
            return;
        };
        let Some(dn) = imp.reading.get().map(|r| r.dn.clone()) else {
            return;
        };
        if writes::context(self).is_none() {
            return;
        }
        imp.continue_button.set_sensitive(false);
        let weak = self.downgrade();
        let ace = input.ace.clone();
        let target = dn.clone();
        prepare(
            self,
            &dn,
            tr("Cannot add"),
            move |object| actions::add_aces(object, &[ace]),
            move |changeset| {
                let Some(dialog) = weak.upgrade() else { return };
                dialog.imp().continue_button.set_sensitive(true);
                let Some(changeset) = changeset else { return };
                if changeset.operations.is_empty() {
                    writes::show_error(
                        &dialog,
                        &tr("Nothing to add"),
                        &tr("This entry is already present."),
                        "",
                    );
                    return;
                }
                let mut remarks = vec![fill(
                    &tr("Entry added on {dn}: {texte}"),
                    &[("dn", &target), ("texte", &input.text)],
                )];
                remarks.extend(input.remarks.iter().cloned());
                remarks.push(sv::undo_remark());
                let after = dialog.downgrade();
                propose(
                    &dialog,
                    changeset,
                    remarks,
                    Rc::new(move |_| {
                        if let Some(dialog) = after.upgrade() {
                            let written = dialog.imp().written.take();
                            dialog.close();
                            if let Some(written) = written {
                                written();
                            }
                        }
                    }),
                );
            },
        );
    }

    /// Types `text` and continues (trials).
    pub fn trial(&self, text: &str) {
        self.imp().entry.set_text(text);
        eprintln!(
            "essai ACE : {} | {}",
            self.imp().plain_preview.label(),
            self.imp().sddl_preview.label()
        );
        self.proceed();
    }
}

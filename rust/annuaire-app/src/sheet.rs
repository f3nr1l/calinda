// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Sheet of an object (J2.4 user, J2.5 group and computer, `annuaire.ui.fiche`): structure in
//! `fiche.blp` and `dialogue-membres.blp`, texts and draft in `sheet_views`. A named row of the
//! Blueprint is bound to the LDAP attribute of the same name: an `Adw.EntryRow` is changed in
//! place, an `Adw.ActionRow` shows the value. The changes pile up in a `Draft`; « Apply »
//! turns it into a changeset (object read again on the DC, through the write connection) and
//! gives it to `writes::propose` (preview, confirmation). After a write, the sheet reads the
//! object again. A read-only profile shows value rows and greyed-out switches.
//!
//! The opening reads the object only (one round trip); the last activity (every DC), the
//! groups and the members come next, without delaying the display. The tabs « Attributes »
//! (`attributes`), « Security » (`security`) and « Policy » (`policy`) read when they are
//! shown.

use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::uac::UserAccountControl;
use annuaire_core::cache::Source;
use annuaire_core::changes::Report;
use annuaire_core::model::Object;
use annuaire_core::source::{Item, Record, name_from_dn};
use annuaire_core::store::now;
use annuaire_core::writer::PrepareError;
use gtk::{gio, glib};

use crate::countries::{self, Country};
use crate::errors;
use crate::feed::Feed;
use crate::i18n::{fill, tr, tr_n};
use crate::members::MembersDialog;
use crate::objects::Element;
use crate::sheet_views::{self as sv, Draft, ElementView};
use crate::views;
use crate::writes::{self, Options};

/// Read for the sheet besides the attributes of the model (`ATTRIBUTS_DETAIL`).
pub const DETAIL_ATTRIBUTES: [&str; 25] = [
    // identity and contact (user)
    "initials",
    "physicalDeliveryOfficeName",
    "telephoneNumber",
    "mobile",
    "wWWHomePage",
    "streetAddress",
    "postalCode",
    "l",
    "st",
    "c",
    "co",
    "countryCode",
    "title",
    "department",
    "company",
    "manager",
    // profile
    "profilePath",
    "scriptPath",
    "homeDirectory",
    "homeDrive",
    // group, computer
    "info",
    "managedBy",
    "location",
    "operatingSystemServicePack",
    // user: effective password policy (constructed attribute, ADR 0014 § 6)
    "msDS-ResultantPSO",
];

/// `widget` and every widget under it (trials).
pub fn all_under(widget: &gtk::Widget) -> Vec<gtk::Widget> {
    let mut all = vec![widget.clone()];
    all.extend(descendants(widget));
    all
}

fn descendants(widget: &gtk::Widget) -> Vec<gtk::Widget> {
    let mut all = Vec::new();
    let mut child = widget.first_child();
    while let Some(c) = child {
        all.push(c.clone());
        all.extend(descendants(&c));
        child = c.next_sibling();
    }
    all
}

/// A row of a list of groups (`_ligne_element`).
fn element_row(element: &glib::Object) -> gtk::Widget {
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
        .build();
    row.add_prefix(&gtk::Image::from_icon_name(&view.icon));
    row.add_suffix(&gtk::Image::from_icon_name("go-next-symbolic"));
    row.set_widget_name(&view.dn);
    row.upcast()
}

mod imp {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::rc::Rc;
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_core::cache::Source;
    use annuaire_core::model::DomainPolicy;
    use annuaire_core::source::Record;
    use gtk::glib;
    use gtk::prelude::*;

    use crate::feed::Feed;
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/fiche.ui")]
    pub struct Sheet {
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        #[template_child]
        pub sheet_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub banner: TemplateChild<adw::Banner>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub pages: TemplateChild<adw::ViewStack>,
        #[template_child]
        pub header: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub identity_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub contact_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub country_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub organization_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub manager_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub group_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub category_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub scope_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub computer_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub directory_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub location_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub dn_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub created_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub modified_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub account_page: TemplateChild<adw::ViewStackPage>,
        #[template_child]
        pub logon_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub sid_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub state_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub state_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub pso_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub password_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub activity_row: TemplateChild<adw::ExpanderRow>,
        #[template_child]
        pub activity_spinner: TemplateChild<gtk::Spinner>,
        #[template_child]
        pub options_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub change_password_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub expiration_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub expiration_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub expiration_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub profile_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub members_page: TemplateChild<adw::ViewStackPage>,
        #[template_child]
        pub members_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub remove_members_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub add_member_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub members_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub members_selection: TemplateChild<gtk::MultiSelection>,
        #[template_child]
        pub members_store: TemplateChild<gtk::gio::ListStore>,
        #[template_child]
        pub groups_page: TemplateChild<adw::ViewStackPage>,
        #[template_child]
        pub principal_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub primary_group_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub direct_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub recursive_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub policy_page: TemplateChild<adw::ViewStackPage>,
        #[template_child]
        pub attribute_editor: TemplateChild<crate::attributes::AttributesPage>,
        #[template_child]
        pub security_page: TemplateChild<crate::security::SecurityPage>,
        #[template_child]
        pub policy_view: TemplateChild<crate::policy::PolicyPage>,
        #[template_child]
        pub changes_bar: TemplateChild<gtk::ActionBar>,
        #[template_child]
        pub changes_summary: TemplateChild<gtk::Label>,
        #[template_child]
        pub apply_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub dn: OnceCell<String>,
        pub record: RefCell<Option<Record>>,
        pub policy: Cell<Option<DomainPolicy>>,
        /// Value row of the last valid day, in place of the entry (`_expiration_lecture`).
        pub expiration: OnceCell<adw::ActionRow>,
        pub activity_rows: RefCell<Vec<adw::ActionRow>>,
        pub members: RefCell<Option<Rc<Feed>>>,
        pub directs: OnceCell<gtk::gio::ListStore>,
        pub recursive: OnceCell<gtk::gio::ListStore>,
        /// Readings started before a « Read again »: their results are dropped.
        pub generation: Cell<u64>,
        pub read_only: Cell<bool>,
        pub draft: RefCell<crate::sheet_views::Draft>,
        /// The sheet is being filled: the signals of the rows are not inputs.
        pub filling: Cell<bool>,
        /// Attributes whose input is refused beforehand: « Apply » waits.
        pub invalid: RefCell<Vec<String>>,
        pub entries: RefCell<Vec<adw::EntryRow>>,
        pub options: RefCell<Vec<(u32, adw::SwitchRow)>>,
        /// One entry per row of the list of countries: none, then the ISO list (preceded by the
        /// value read if it is not in it).
        pub countries: RefCell<Vec<Option<crate::countries::Country>>>,
        /// Last row changed: the focus goes back there when the sheet is read again (J2.9).
        pub last_row: glib::WeakRef<gtk::Widget>,
        pub refocus: Cell<bool>,
        /// Preview of the last « Apply » (trials).
        pub preview: glib::WeakRef<crate::writes::PreviewDialog>,
    }

    impl std::fmt::Debug for Sheet {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Sheet")
                .field("dn", &self.dn.get())
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Sheet {
        const NAME: &'static str = "AnnuaireFiche";
        type Type = super::Sheet;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            crate::objects::ensure_types();
            crate::attributes::AttributesPage::ensure_type();
            crate::security::SecurityPage::ensure_type();
            crate::policy::PolicyPage::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::Sheet>(&[
                ("reload", |s, _| {
                    s.load();
                    None
                }),
                ("member_activated", |s, args| {
                    let position = args.get(1).and_then(|v| v.get::<u32>().ok());
                    if let Some(position) = position {
                        s.member_activated(position);
                    }
                    None
                }),
                ("page_changed", |s, _| {
                    s.page_changed();
                    None
                }),
                ("country_changed", |s, _| {
                    s.country_changed();
                    None
                }),
                ("change_required", |s, _| {
                    s.change_required();
                    None
                }),
                ("expiration_changed", |s, _| {
                    s.expiration_changed();
                    None
                }),
                ("remove_members", |s, _| {
                    s.remove_members();
                    None
                }),
                ("add_members", |s, _| {
                    let _ = s.add_members();
                    None
                }),
                ("members_selection_changed", |s, _| {
                    s.selection_changed();
                    None
                }),
                ("abandon", |s, _| {
                    s.discard();
                    None
                }),
                ("apply", |s, _| {
                    s.apply();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for Sheet {}
    impl WidgetImpl for Sheet {}

    impl AdwDialogImpl for Sheet {
        fn close_attempt(&self) {
            self.obj().close_attempt();
        }

        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// Sheet of a user, a group or a computer; the other objects only show the common pages.
    pub struct Sheet(ObjectSubclass<imp::Sheet>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl Sheet {
    pub fn new(source: Arc<dyn Source>, dn: &str) -> Self {
        let sheet: Self = glib::Object::new();
        let imp = sheet.imp();
        let read_only = source.profile().read_only;
        imp.read_only.set(read_only);
        let _ = imp.source.set(source);
        let _ = imp.dn.set(dn.to_owned());
        sheet.setup(read_only);
        sheet.read_policy();
        sheet.load();
        sheet
    }

    fn source(&self) -> Arc<dyn Source> {
        self.imp().source.get().expect("source set by new").clone()
    }

    fn dn(&self) -> String {
        self.imp().dn.get().cloned().unwrap_or_default()
    }

    fn setup(&self, read_only: bool) {
        let imp = self.imp();
        // Escape in the capture phase: a toast shown would take it otherwise, and it would
        // take two Escape to close the sheet (seen in J3.5).
        let escape = gtk::ShortcutController::new();
        escape.set_propagation_phase(gtk::PropagationPhase::Capture);
        let weak = self.downgrade();
        escape.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::CallbackAction::new(move |_, _| {
                if let Some(sheet) = weak.upgrade() {
                    sheet.close();
                }
                glib::Propagation::Stop
            })),
        ));
        self.add_controller(escape);
        let directs = gio::ListStore::new::<Element>();
        let recursive = gio::ListStore::new::<Element>();
        imp.direct_list.bind_model(Some(&directs), element_row);
        imp.recursive_list.bind_model(Some(&recursive), element_row);
        for list in [&*imp.direct_list, &*imp.recursive_list] {
            let weak = self.downgrade();
            list.connect_row_activated(move |_, row| {
                if let Some(sheet) = weak.upgrade() {
                    sheet.open(&row.widget_name());
                }
            });
        }
        let _ = imp.directs.set(directs);
        let _ = imp.recursive.set(recursive);
        let (for_edits, for_keep) = (self.downgrade(), self.downgrade());
        imp.attribute_editor.configure(
            self.source(),
            &self.dn(),
            read_only,
            Rc::new(move || {
                for_edits
                    .upgrade()
                    .map(|s| s.imp().draft.borrow().edits.clone())
                    .unwrap_or_default()
            }),
            Rc::new(move |edit| {
                let sheet = for_keep.upgrade()?;
                let kept = sheet.imp().draft.borrow_mut().edit(edit);
                match kept {
                    Ok(()) => {
                        sheet.update_bar();
                        None
                    }
                    Err(error) => Some(error.message()),
                }
            }),
        );
        imp.security_page.configure(self.source(), &self.dn());
        self.bind_rows();
        if read_only {
            imp.banner
                .set_title(&tr("Read-only profile: the properties cannot be modified."));
            imp.banner.set_revealed(true);
        }
    }

    /// The rows named after an attribute, once (`_relier_lignes`). Read-only profile: the
    /// entry rows become value rows (without the pencil of an `Adw.EntryRow`), the switches
    /// are greyed out.
    fn bind_rows(&self) {
        let imp = self.imp();
        let read_only = imp.read_only.get();
        for widget in descendants(imp.pages.upcast_ref()) {
            let name = widget.widget_name().to_string();
            if let Some(entry) = widget.downcast_ref::<adw::EntryRow>()
                && sv::editable(&name)
            {
                if read_only {
                    to_value_row(widget.upcast_ref(), &name);
                    continue;
                }
                let weak = self.downgrade();
                entry.connect_changed(move |entry| {
                    if let Some(sheet) = weak.upgrade() {
                        sheet.input_changed(entry);
                    }
                });
                entry.set_show_apply_button(false);
            } else if let Some(row) = widget.downcast_ref::<adw::SwitchRow>() {
                if let Some((_, flag)) = sv::OPTIONS.iter().find(|(n, _)| *n == name) {
                    imp.options.borrow_mut().push((*flag, row.clone()));
                    let (weak, flag) = (self.downgrade(), *flag);
                    row.connect_active_notify(move |row| {
                        if let Some(sheet) = weak.upgrade() {
                            sheet.option_changed(row, flag);
                        }
                    });
                }
                if read_only {
                    row.set_sensitive(false);
                }
            } else if let Some(row) = widget.downcast_ref::<adw::ActionRow>()
                && !widget.is::<adw::ComboRow>()
            {
                // A long value without a space (DN, SID) is cut instead of widening the sheet.
                row.set_subtitle_lines(2);
            }
        }
        if read_only {
            to_value_row(imp.country_row.upcast_ref(), "co");
            imp.expiration_switch.set_visible(false);
            let expiration = to_value_row(imp.expiration_entry.upcast_ref(), "");
            expiration.set_title(&tr("Last valid day"));
            let _ = imp.expiration.set(expiration);
            imp.add_member_button.set_visible(false);
            imp.remove_members_button.set_visible(false);
        } else {
            imp.country_row.set_model(Some(&gtk::StringList::new(&[])));
        }
    }

    fn read_policy(&self) {
        let source = self.source();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.policy()).await;
            let (Some(sheet), Ok(Ok(policy))) = (weak.upgrade(), read) else {
                return; // the state « locked out » will not be shown
            };
            sheet.imp().policy.set(Some(policy));
            let object = sheet.object();
            if let Some(account) = object.as_ref().and_then(Object::account) {
                sheet.imp().state_row.set_subtitle(&sv::account_state(
                    account,
                    Some(&policy),
                    now(),
                ));
            }
        });
    }

    fn object(&self) -> Option<Object> {
        match self.imp().record.borrow().as_ref().map(|r| &r.item) {
            Some(Item::Object(object)) => Some((**object).clone()),
            _ => None,
        }
    }

    /// Reads the object from the source and shows it; the rest follows (`charger`).
    pub fn load(&self) {
        self.stop();
        let imp = self.imp();
        // Read again (after a write, « Read again »): the page disappears during the reading
        // and the focus with it; `show_record` gives it back.
        imp.refocus
            .set(imp.state.visible_child_name().as_deref() == Some("fiche"));
        let generation = imp.generation.get() + 1;
        imp.generation.set(generation);
        imp.state.set_visible_child_name("chargement");
        let (source, dn, weak) = (self.source(), self.dn(), self.downgrade());
        glib::spawn_future_local(async move {
            let asked = dn.clone();
            let read = gio::spawn_blocking(move || source.record(&asked, &DETAIL_ATTRIBUTES)).await;
            let Some(sheet) = weak.upgrade() else { return };
            if sheet.imp().generation.get() != generation {
                return;
            }
            let domain = sheet.source().profile().domain.clone();
            match read {
                Ok(Ok(Some(record))) => sheet.show_record(record),
                Ok(Ok(None)) => sheet.failed(&tr("This object no longer exists."), &dn),
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &domain);
                    sheet.failed(&problem.message, &problem.detail);
                }
                Err(_) => {}
            }
        });
    }

    fn stop(&self) {
        if let Some(feed) = self.imp().members.take() {
            feed.cancel();
        }
    }

    fn failed(&self, title: &str, detail: &str) {
        let imp = self.imp();
        imp.error.set_title(title);
        imp.error.set_description(Some(detail));
        imp.state.set_visible_child_name("erreur");
    }

    /// Groups of rows shown for the type of the object (`_groupes_visibles`).
    fn visible_groups(&self, object: &Object) -> Vec<gtk::Widget> {
        let imp = self.imp();
        let user = matches!(object, Object::User { .. });
        let account = object.account().is_some();
        let group = matches!(object, Object::Group { .. });
        let groups: [(&adw::PreferencesGroup, bool); 10] = [
            (&imp.identity_group, user),
            (&imp.contact_group, user),
            (&imp.organization_group, user),
            (&imp.group_group, group),
            (
                &imp.computer_group,
                matches!(object, Object::Computer { .. }),
            ),
            (&imp.profile_group, user),
            (&imp.logon_group, account),
            (&imp.state_group, account),
            (&imp.options_group, account),
            (&imp.expiration_group, account),
        ];
        for (widget, visible) in groups {
            widget.set_visible(visible);
        }
        imp.account_page.set_visible(account);
        imp.change_password_switch.set_visible(user);
        imp.members_page.set_visible(group);
        imp.groups_page.set_visible(account || group);
        imp.policy_page.set_visible(account);
        imp.principal_group.set_visible(account);
        let mut visible: Vec<gtk::Widget> = vec![
            imp.header.clone().upcast(),
            imp.directory_group.clone().upcast(),
        ];
        visible.extend(
            groups
                .iter()
                .filter(|(_, v)| *v)
                .map(|(w, _)| (*w).clone().upcast()),
        );
        visible
    }

    /// Shows the object read, then reads what follows (`_fiche_lue`).
    fn show_record(&self, record: Record) {
        let object = match &record.item {
            Item::Object(object) => Some((**object).clone()),
            Item::Unreadable { .. } => None,
        };
        self.show(record);
        if let Some(object) = object {
            // Object read again: the editor will read it again.
            self.imp().attribute_editor.invalidate();
            self.follow_up(&object);
        }
    }

    /// Fills the sheet and starts from an empty draft, without reading the directory again
    /// (`afficher`).
    fn show(&self, record: Record) {
        let imp = self.imp();
        let Item::Object(object) = &record.item else {
            let (dn, error) = match &record.item {
                Item::Unreadable { dn, error, .. } => (dn.clone(), error.clone()),
                Item::Object(_) => unreachable!(),
            };
            self.failed(&error, &dn);
            return;
        };
        let object = (**object).clone();
        let common = object.common();
        let dn = common.dn.clone();
        self.set_title(if common.name.is_empty() {
            &dn
        } else {
            &common.name
        });
        imp.filling.set(true);
        let mut origin: Vec<(String, String)> = Vec::new();
        imp.entries.borrow_mut().clear();
        for group in self.visible_groups(&object) {
            for widget in descendants(&group) {
                let name = widget.widget_name();
                if let Some(entry) = widget.downcast_ref::<adw::EntryRow>()
                    && sv::editable(&name)
                {
                    let text = record.text(&name);
                    entry.set_text(&text);
                    entry.remove_css_class("error");
                    entry.set_tooltip_text(None);
                    origin.push((name.to_string(), text));
                    imp.entries.borrow_mut().push(entry.clone());
                    continue;
                }
                let Some(row) = widget.downcast_ref::<adw::ActionRow>() else {
                    continue;
                };
                if widget.is::<adw::ComboRow>() || name.is_empty() || name.starts_with("uac:") {
                    continue;
                }
                let text = record.text(&name);
                row.set_subtitle(
                    if text.is_empty() {
                        "—".to_owned()
                    } else {
                        glib::markup_escape_text(&text).to_string()
                    }
                    .as_str(),
                );
            }
        }
        imp.location_row.set_subtitle(&sv::location(&dn));
        imp.dn_row.set_subtitle(&glib::markup_escape_text(&dn));
        imp.created_row.set_subtitle(&sv::date_text(common.created));
        imp.modified_row
            .set_subtitle(&sv::date_text(common.modified));
        imp.sheet_title.set_title(
            if common.name.is_empty() {
                name_from_dn(&dn)
            } else {
                common.name.clone()
            }
            .as_str(),
        );
        let row = views::row_from_item(&record.item);
        imp.sheet_title.set_subtitle(&row.kind_label);
        let manager = record.text("manager");
        imp.manager_row.set_subtitle(&if manager.is_empty() {
            "—".to_owned()
        } else {
            glib::markup_escape_text(&sv::readable_path(&manager)).to_string()
        });
        if let Object::Group { group_type, .. } = &object {
            imp.category_row
                .set_subtitle(&sv::category_label(group_type.as_ref()));
            imp.scope_row
                .set_subtitle(&sv::scope_label(group_type.as_ref()));
        }
        let user = matches!(object, Object::User { .. });
        if user && !imp.read_only.get() {
            for attribute in countries::ATTRIBUTES {
                origin.push((attribute.to_owned(), record.text(attribute)));
            }
            self.show_countries(&origin);
        }
        imp.pso_row.set_visible(user);
        if user {
            let resultant = record.text("msDS-ResultantPSO");
            imp.pso_row
                .set_subtitle(&glib::markup_escape_text(&sv::resultant_policy(
                    (!resultant.is_empty()).then_some(resultant.as_str()),
                )));
        }
        if let Some(account) = object.account() {
            origin.push((
                "userAccountControl".to_owned(),
                UserAccountControl(account.uac).encode().to_string(),
            ));
            origin.push(("accountExpires".to_owned(), record.text("accountExpires")));
            origin.push(("pwdLastSet".to_owned(), record.text("pwdLastSet")));
        }
        *imp.record.borrow_mut() = Some(record);
        if object.account().is_some() {
            self.show_account(&object);
        }
        *imp.draft.borrow_mut() = Draft::new(origin);
        imp.invalid.borrow_mut().clear();
        imp.filling.set(false);
        self.update_bar();
        imp.state.set_visible_child_name("fiche");
        if imp.refocus.replace(false) {
            let row = imp.last_row.upgrade();
            if !row.is_some_and(|r| r.is_mapped() && r.grab_focus()) {
                imp.pages.child_focus(gtk::DirectionType::TabForward);
            }
        }
        imp.security_page.invalidate();
        if imp.pages.visible_child_name().as_deref() == Some("securite") {
            imp.security_page.load();
        }
        imp.policy_view.invalidate();
        if imp.pages.visible_child_name().as_deref() == Some("strategie") {
            imp.policy_view.load(&dn);
        }
    }

    fn show_account(&self, object: &Object) {
        let imp = self.imp();
        let Some(account) = object.account() else {
            return;
        };
        imp.sid_row.set_subtitle(
            &account
                .sid
                .as_ref()
                .map_or_else(|| "—".to_owned(), ToString::to_string),
        );
        let policy = imp.policy.get();
        imp.state_row
            .set_subtitle(&sv::account_state(account, policy.as_ref(), now()));
        imp.password_row
            .set_subtitle(&if account.must_change_password() {
                tr("Change required at next logon")
            } else {
                sv::nttime_text(account.pwd_last_set)
            });
        for (flag, row) in imp.options.borrow().iter() {
            row.set_active(UserAccountControl(account.uac).contains(*flag));
        }
        imp.change_password_switch
            .set_active(account.must_change_password());
        self.update_change_required(account.uac);
        let end = sv::end_of_account(account.account_expires);
        imp.expiration_switch.set_active(end.is_some());
        imp.expiration_entry.set_text(&sv::day_text(end.as_ref()));
        imp.expiration_entry.remove_css_class("error");
        if let Some(row) = imp.expiration.get() {
            let day = sv::day_text(end.as_ref());
            row.set_subtitle(&if day.is_empty() { tr("Never") } else { day });
        }
    }

    /// What is read after the display: activity, groups, members (`_lancer_suites`).
    fn follow_up(&self, object: &Object) {
        let imp = self.imp();
        let dn = object.common().dn.clone();
        let generation = imp.generation.get();
        if object.account().is_some() {
            for row in imp.activity_rows.take() {
                imp.activity_row.remove(&row);
            }
            imp.activity_row
                .set_subtitle(&tr("Checking each controller…"));
            imp.activity_spinner.set_visible(true);
            let (source, asked, weak) = (self.source(), dn.clone(), self.downgrade());
            glib::spawn_future_local(async move {
                let read = gio::spawn_blocking(move || source.activity(&asked, &|| false)).await;
                let Some(sheet) = weak.upgrade() else { return };
                if sheet.imp().generation.get() == generation
                    && let Ok(read) = read
                {
                    sheet.activity_read(read);
                }
            });
        }
        let group = matches!(object, Object::Group { .. });
        if object.account().is_some() || group {
            if let Some(store) = imp.directs.get() {
                store.remove_all();
            }
            if let Some(store) = imp.recursive.get() {
                store.remove_all();
            }
            imp.primary_group_row.set_title(&tr("Reading…"));
            imp.primary_group_row.set_subtitle("");
            let (source, asked, weak) = (self.source(), dn.clone(), self.downgrade());
            glib::spawn_future_local(async move {
                let read = gio::spawn_blocking(move || source.groups(&asked)).await;
                let Some(sheet) = weak.upgrade() else { return };
                if sheet.imp().generation.get() == generation
                    && let Ok(read) = read
                {
                    sheet.groups_read(read);
                }
            });
        }
        if group {
            self.read_members(&dn);
        }
    }

    fn activity_read(
        &self,
        read: Result<annuaire_core::source::Survey, annuaire_core::source::SurveyError>,
    ) {
        let imp = self.imp();
        imp.activity_spinner.set_visible(false);
        let Some(object) = self.object() else { return };
        let domain = self.source().profile().domain.clone();
        let survey = match read {
            Ok(survey) => survey,
            Err(error) => {
                let message = match error {
                    annuaire_core::source::SurveyError::Failure(f) => {
                        errors::failure_problem(&f, &domain).message
                    }
                    annuaire_core::source::SurveyError::Search(e) => {
                        errors::search_problem(&e, &domain).message
                    }
                    annuaire_core::source::SurveyError::Cancelled => String::new(),
                };
                imp.activity_row.set_subtitle(&fill(
                    &tr("Check not possible: {message}"),
                    &[("message", &message)],
                ));
                return;
            }
        };
        let mut summary = sv::activity_summary(&survey, &object.common().dn);
        if !survey.failures.is_empty() {
            summary = fill(
                &tr("{resume}, a controller did not respond"),
                &[("resume", &summary)],
            );
        }
        imp.activity_row
            .set_subtitle(&glib::markup_escape_text(&summary));
        let message =
            |e: &annuaire_core::search::SearchError| errors::search_problem(e, &domain).message;
        for line in sv::activity_lines(&survey, &object, &message) {
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&line.title).as_str())
                .subtitle(&line.text)
                .build();
            row.add_css_class("property");
            if line.chosen {
                let mark = gtk::Image::from_icon_name("object-select-symbolic");
                mark.set_tooltip_text(Some(&tr("Most recent value")));
                row.add_suffix(&mark);
            }
            imp.activity_row.add_row(&row);
            imp.activity_rows.borrow_mut().push(row);
        }
    }

    fn groups_read(
        &self,
        read: Result<
            annuaire_core::membership::Membership,
            annuaire_core::membership::MembershipError,
        >,
    ) {
        let imp = self.imp();
        let domain = self.source().profile().domain.clone();
        let membership = match read {
            Ok(m) => m,
            Err(error) => {
                imp.primary_group_row
                    .set_title(&errors::membership_message(&error, &domain));
                return;
            }
        };
        match &membership.primary {
            Some(primary) => {
                imp.primary_group_row
                    .set_title(&glib::markup_escape_text(&name_from_dn(primary)));
                imp.primary_group_row
                    .set_subtitle(&glib::markup_escape_text(&sv::location(primary)));
            }
            None => {
                imp.primary_group_row.set_title("—");
                imp.primary_group_row.set_subtitle("");
            }
        }
        let elements = |dns: &[String]| -> Vec<glib::Object> {
            let mut views: Vec<ElementView> = dns.iter().map(|d| sv::element_from_dn(d)).collect();
            sv::sort_elements(&mut views);
            views
                .into_iter()
                .map(|v| Element::new(v).upcast())
                .collect()
        };
        if let Some(store) = imp.directs.get() {
            store.splice(0, 0, &elements(&membership.direct));
        }
        if let Some(store) = imp.recursive.get() {
            store.splice(
                0,
                0,
                &elements(membership.recursive.as_deref().unwrap_or_default()),
            );
        }
    }

    // --- Members of a group -----------------------------------------------------------

    fn read_members(&self, dn: &str) {
        let imp = self.imp();
        imp.members_store.remove_all();
        imp.members_stack.set_visible_child_name("chargement");
        imp.members_count.set_label(&tr("Reading members…"));
        let source = self.source();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.members(dn, notifier).flux,
            move |items: Vec<Item>| {
                let Some(sheet) = deliver_to.upgrade() else {
                    return;
                };
                let store = &sheet.imp().members_store;
                let elements: Vec<glib::Object> = items
                    .iter()
                    .map(|i| Element::new(sv::element_from_item(i)).upcast())
                    .collect();
                store.splice(store.n_items(), 0, &elements);
                sheet.imp().members_stack.set_visible_child_name("liste");
            },
            move |error| {
                let Some(sheet) = finish_to.upgrade() else {
                    return;
                };
                let imp = sheet.imp();
                imp.members.take();
                if let Some(error) = error {
                    imp.toasts.add_toast(adw::Toast::new(
                        &errors::search_problem(&error, &domain).message,
                    ));
                }
                // Shown in the order of `member` as they arrive, then by name.
                let store = &imp.members_store;
                let mut elements: Vec<Element> = (0..store.n_items())
                    .filter_map(|i| store.item(i).and_downcast::<Element>())
                    .collect();
                elements.sort_by_cached_key(|e| {
                    (
                        glib::casefold(&e.view().title),
                        glib::casefold(&e.view().dn),
                    )
                });
                let sorted: Vec<glib::Object> = elements.into_iter().map(Element::upcast).collect();
                store.splice(0, store.n_items(), &sorted);
                sheet.count_members();
            },
        );
        *imp.members.borrow_mut() = Some(feed);
    }

    fn count_members(&self) {
        let imp = self.imp();
        let n = imp.members_store.n_items();
        imp.members_stack
            .set_visible_child_name(if n == 0 { "vide" } else { "liste" });
        imp.members_count.set_label(&fill(
            &tr_n("{n} member", "{n} members", u64::from(n)),
            &[("n", &views::number(u64::from(n)))],
        ));
    }

    fn member_activated(&self, position: u32) {
        let element = self
            .imp()
            .members_store
            .item(position)
            .and_downcast::<Element>();
        if let Some(element) = element {
            self.open(&element.view().dn.clone());
        }
    }

    /// List of the countries: none, the value read if the ISO list does not know it, the list
    /// (`_afficher_pays`).
    fn show_countries(&self, origin: &[(String, String)]) {
        let imp = self.imp();
        let value = |attribute: &str| {
            origin
                .iter()
                .find(|(a, _)| a == attribute)
                .map_or_else(String::new, |(_, v)| v.clone())
        };
        let (c, co, number) = (value("c"), value("co"), value("countryCode"));
        let mut present = countries::current(&c, &co);
        let mut choices: Vec<Option<Country>> = vec![None];
        if present.is_none() && !co.trim().is_empty() {
            let unknown = Country {
                code: c.clone(),
                number: number.trim().parse().unwrap_or(0),
                name: co.clone(),
            };
            choices.push(Some(unknown.clone()));
            present = Some(unknown);
        }
        choices.extend(countries::sorted().into_iter().map(Some));
        let labels: Vec<String> = choices
            .iter()
            .map(|p| match p {
                None => tr("None"),
                // The value read is shown as is (`co`), not translated.
                Some(p) if Some(p) == present.as_ref() && countries::by_code(&p.code).is_none() => {
                    p.name.clone()
                }
                Some(p) => p.label(),
            })
            .collect();
        let selected = choices.iter().position(|p| *p == present).unwrap_or(0);
        *imp.countries.borrow_mut() = choices;
        if let Some(model) = imp.country_row.model().and_downcast::<gtk::StringList>() {
            let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
            model.splice(0, model.n_items(), &labels);
        }
        imp.country_row
            .set_selected(u32::try_from(selected).unwrap_or(0));
    }

    // --- Changes in place ---------------------------------------------------------------

    /// Input that cannot be applied: marked, and « Apply » waits.
    fn mark_invalid(&self, row: &impl IsA<gtk::Widget>, attribute: &str, problem: Option<&str>) {
        let mut invalid = self.imp().invalid.borrow_mut();
        invalid.retain(|a| a != attribute);
        match problem {
            None => {
                row.remove_css_class("error");
                row.set_tooltip_text(None);
            }
            Some(problem) => {
                row.add_css_class("error");
                row.set_tooltip_text(Some(problem));
                invalid.push(attribute.to_owned());
            }
        }
    }

    /// `entry_changed`.
    fn input_changed(&self, entry: &adw::EntryRow) {
        let imp = self.imp();
        if imp.filling.get() {
            return;
        }
        imp.last_row.set(Some(entry.upcast_ref()));
        let (attribute, text) = (entry.widget_name().to_string(), entry.text().to_string());
        self.mark_invalid(
            entry,
            &attribute,
            sv::check_input(&attribute, &text).as_deref(),
        );
        let _ = imp.draft.borrow_mut().input(&attribute, &text);
        self.update_bar();
    }

    /// `_option_changee`.
    fn option_changed(&self, row: &adw::SwitchRow, flag: u32) {
        let imp = self.imp();
        if imp.filling.get() {
            return;
        }
        imp.last_row.set(Some(row.upcast_ref()));
        let present = imp
            .draft
            .borrow()
            .value("userAccountControl")
            .trim()
            .parse::<i64>()
            .unwrap_or(0);
        let new = sv::uac_with(present, flag, row.is_active());
        let _ = imp
            .draft
            .borrow_mut()
            .input("userAccountControl", &new.to_string());
        self.update_change_required((new & 0xFFFF_FFFF) as u32);
        self.update_bar();
    }

    /// « Must change the password »: not possible if the password never expires
    /// (`_actualiser_changement_exige`).
    fn update_change_required(&self, uac: u32) {
        let imp = self.imp();
        let switch = &imp.change_password_switch;
        let possible = sv::change_possible(uac);
        if !possible && switch.is_active() && !imp.filling.get() {
            switch.set_active(false);
        }
        switch.set_sensitive(possible && !imp.read_only.get());
        switch.set_subtitle(&if possible {
            String::new()
        } else {
            tr("Not applicable: the password never expires.")
        });
    }

    /// `change_required`.
    fn change_required(&self) {
        let imp = self.imp();
        if imp.filling.get() || imp.record.borrow().is_none() {
            return;
        }
        imp.last_row
            .set(Some(imp.change_password_switch.upcast_ref()));
        let origin = imp
            .draft
            .borrow()
            .origin
            .iter()
            .find(|(a, _)| a == "pwdLastSet")
            .map_or_else(String::new, |(_, v)| v.clone());
        let value = sv::change_required_value(&origin, imp.change_password_switch.is_active());
        let _ = imp.draft.borrow_mut().input("pwdLastSet", &value);
        self.update_bar();
    }

    /// `country_changed`.
    fn country_changed(&self) {
        let imp = self.imp();
        if imp.filling.get() || imp.record.borrow().is_none() || imp.countries.borrow().is_empty() {
            return;
        }
        imp.last_row.set(Some(imp.country_row.upcast_ref()));
        let choice = imp
            .countries
            .borrow()
            .get(imp.country_row.selected() as usize)
            .cloned();
        if let Some(choice) = choice {
            imp.draft.borrow_mut().input_country(choice.as_ref());
            self.update_bar();
        }
    }

    /// `expiration_changed`.
    fn expiration_changed(&self) {
        let imp = self.imp();
        if imp.filling.get() || imp.record.borrow().is_none() {
            return;
        }
        let origin = imp
            .draft
            .borrow()
            .origin
            .iter()
            .find(|(a, _)| a == "accountExpires")
            .map_or_else(String::new, |(_, v)| v.clone());
        let mut end = None;
        if imp.expiration_switch.is_active() {
            match sv::parse_day(&imp.expiration_entry.text()) {
                Ok(day) => end = Some(day),
                Err(problem) => {
                    self.mark_invalid(&*imp.expiration_entry, "accountExpires", Some(&problem));
                    self.update_bar();
                    return;
                }
            }
        }
        self.mark_invalid(&*imp.expiration_entry, "accountExpires", None);
        let _ = imp
            .draft
            .borrow_mut()
            .input("accountExpires", &sv::expiration_value(&origin, end));
        self.update_bar();
    }

    /// `_actualiser_barre`.
    fn update_bar(&self) {
        let imp = self.imp();
        let n = imp.draft.borrow().count();
        imp.changes_bar.set_revealed(n > 0 && !imp.read_only.get());
        imp.changes_summary.set_label(&fill(
            &tr_n("{n} pending change", "{n} pending changes", n as u64),
            &[("n", &n.to_string())],
        ));
        imp.apply_button
            .set_sensitive(n > 0 && imp.invalid.borrow().is_empty());
        self.set_can_close(n == 0);
        imp.attribute_editor.refresh();
    }

    /// `abandon`.
    fn discard(&self) {
        let record = self.imp().record.borrow().clone();
        if let Some(record) = record {
            let group =
                matches!(&record.item, Item::Object(o) if matches!(**o, Object::Group { .. }));
            self.show(record);
            if group {
                self.read_members(&self.dn());
            }
        }
    }

    /// Closing refused while changes remain: proposes to discard them (`do_close_attempt`).
    fn close_attempt(&self) {
        let alert = adw::AlertDialog::new(
            Some(&tr("Discard the changes?")),
            Some(&tr(
                "The changes in these properties have not been applied.",
            )),
        );
        alert.add_response("garder", &tr("Keep Editing"));
        alert.add_response("abandonner", &tr("Discard"));
        alert.set_response_appearance("abandonner", adw::ResponseAppearance::Destructive);
        let weak = self.downgrade();
        alert.connect_response(None, move |_, response| {
            if response != "abandonner" {
                return;
            }
            if let Some(sheet) = weak.upgrade() {
                sheet.imp().draft.borrow_mut().clear();
                sheet.set_can_close(true);
                sheet.close();
            }
        });
        alert.present(Some(self));
    }

    /// `apply`.
    fn apply(&self) {
        let imp = self.imp();
        let Some(context) = writes::context(self) else {
            return;
        };
        if imp.draft.borrow().count() == 0 {
            return;
        }
        imp.apply_button.set_sensitive(false);
        let (draft, dn, weak) = (imp.draft.borrow().clone(), self.dn(), self.downgrade());
        let domain = context.profile.domain.clone();
        let connection = context.connection.clone();
        glib::spawn_future_local(async move {
            let asked = dn.clone();
            let prepared =
                gio::spawn_blocking(move || sv::prepare_changeset(&connection, &asked, &draft))
                    .await;
            let Some(sheet) = weak.upgrade() else { return };
            sheet.update_bar();
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(_) => return,
            };
            match prepared {
                Err(error) => {
                    let message = match &error {
                        PrepareError::Failure(f) => errors::failure_problem(f, &domain).message,
                        PrepareError::Missing(dn) => {
                            fill(&tr("“{dn}” does not exist."), &[("dn", dn)])
                        }
                        PrepareError::Unsupported(text) => crate::codec_texts::codec_message(text),
                    };
                    let alert = adw::AlertDialog::new(Some(&tr("Cannot prepare")), Some(&message));
                    alert.add_response("fermer", &tr("Close"));
                    alert.present(Some(&sheet));
                }
                Ok(None) => {
                    // The directory already has the values wanted (changed elsewhere meanwhile).
                    sheet.imp().toasts.add_toast(adw::Toast::new(&tr(
                        "The directory already has these values.",
                    )));
                    sheet.imp().draft.borrow_mut().clear();
                    sheet.load();
                }
                Ok(Some(changeset)) => {
                    let weak = sheet.downgrade();
                    let preview = writes::propose(
                        &sheet,
                        changeset,
                        Options {
                            finished: Some(Box::new(move |report: Option<&Report>| {
                                if let Some(sheet) = weak.upgrade() {
                                    sheet.write_finished(report);
                                }
                            })),
                            ..Options::default()
                        },
                    );
                    sheet.imp().preview.set(preview.as_ref());
                }
            }
        });
    }

    /// `_ecriture_finie`: the preview closed without writing keeps the draft.
    fn write_finished(&self, report: Option<&Report>) {
        if report.is_none() {
            return;
        }
        self.imp().draft.borrow_mut().clear();
        self.update_bar();
        self.load();
    }

    // --- Members (changes) --------------------------------------------------------------

    fn member_position(&self, dn: &str) -> Option<u32> {
        let store = &self.imp().members_store;
        (0..store.n_items()).find(|&i| {
            store
                .item(i)
                .and_downcast::<Element>()
                .is_some_and(|e| e.view().dn.eq_ignore_ascii_case(dn))
        })
    }

    /// Member to add (search dialog); without effect if it is already there
    /// (`ajouter_membre`).
    pub fn add_member(&self, view: ElementView) {
        let imp = self.imp();
        if let Some(position) = self.member_position(&view.dn) {
            let element = imp.members_store.item(position).and_downcast::<Element>();
            if let Some(element) = element
                && element.etat() == tr("to remove")
            {
                imp.draft.borrow_mut().add_member(element.view().clone());
                element.set_etat("");
                self.update_bar();
            }
            return;
        }
        imp.draft.borrow_mut().add_member(view.clone());
        let element = Element::new(view);
        element.set_etat(tr("to add"));
        imp.members_store.append(&element);
        self.count_members();
        self.update_bar();
    }

    /// `remove_members`.
    fn remove_members(&self) {
        let imp = self.imp();
        let chosen = imp.members_selection.selection();
        let mut positions: Vec<u32> = (0..chosen.size())
            .map(|i| chosen.nth(u32::try_from(i).unwrap_or(u32::MAX)))
            .collect();
        positions.sort_unstable_by(|a, b| b.cmp(a));
        for position in positions {
            let Some(element) = imp.members_store.item(position).and_downcast::<Element>() else {
                continue;
            };
            imp.draft.borrow_mut().remove_member(element.view().clone());
            if element.etat() == tr("to add") {
                imp.members_store.remove(position);
            } else {
                element.set_etat(tr("to remove"));
            }
        }
        imp.members_selection.unselect_all();
        self.count_members();
        self.update_bar();
    }

    /// `members_selection_changed`.
    fn selection_changed(&self) {
        let imp = self.imp();
        let empty = imp.members_selection.selection().is_empty();
        imp.remove_members_button
            .set_sensitive(!empty && !imp.read_only.get());
    }

    /// `add_members`.
    fn add_members(&self) -> MembersDialog {
        let weak = self.downgrade();
        let dialog = MembersDialog::new(
            self.source(),
            Box::new(move |view| {
                if let Some(sheet) = weak.upgrade() {
                    sheet.add_member(view);
                }
            }),
        );
        dialog.present(Some(self));
        dialog
    }

    /// Inputs of a trial, separated by `;;`: `attribute=text`, `uac:FLAG=0|1`, `changer=0|1`,
    /// `pays=CODE` (empty: none), `expiration=DD/MM/YYYY` (empty: never), `+DN` (member to
    /// add), `-DN` (member to remove) (trials).
    pub fn trial_input(&self, spec: &str) {
        let imp = self.imp();
        for piece in spec.split(";;").filter(|p| !p.is_empty()) {
            if let Some(dn) = piece.strip_prefix('+') {
                self.add_member(sv::element_from_dn(dn));
                continue;
            }
            if let Some(dn) = piece.strip_prefix('-') {
                if let Some(position) = self.member_position(dn) {
                    imp.members_selection.select_item(position, true);
                    self.remove_members();
                }
                continue;
            }
            let Some((name, value)) = piece.split_once('=') else {
                continue;
            };
            if let Some(attribute) = name.strip_prefix("attr:") {
                imp.attribute_editor.trial_edit(attribute, value);
                continue;
            }
            match name {
                "deleguer" => imp.security_page.trial(Some(value), None, None),
                // `§` stands for `;` (the inputs are separated by `;;`).
                "ace" => imp
                    .security_page
                    .trial(None, Some(&value.replace('§', ";")), None),
                "retirer" => imp.security_page.trial(None, None, Some(value)),
                "chercher" => {
                    let dialog = self.add_members();
                    dialog.trial_search(value);
                }
                "changer" => imp.change_password_switch.set_active(value == "1"),
                "pays" => {
                    let position = imp.countries.borrow().iter().position(|c| match c {
                        None => value.is_empty(),
                        Some(c) => c.code == value,
                    });
                    if let Some(position) = position {
                        imp.country_row
                            .set_selected(u32::try_from(position).unwrap_or(0));
                    }
                }
                "expiration" => {
                    imp.expiration_switch.set_active(!value.is_empty());
                    if !value.is_empty() {
                        imp.expiration_entry.set_text(value);
                    }
                }
                _ => {
                    if let Some((_, row)) =
                        imp.options.borrow().iter().find(|(flag, _)| {
                            sv::OPTIONS.iter().any(|(n, f)| *n == name && f == flag)
                        })
                    {
                        row.set_active(value == "1");
                        continue;
                    }
                    let entry = imp
                        .entries
                        .borrow()
                        .iter()
                        .find(|e| e.widget_name() == name)
                        .cloned();
                    if let Some(entry) = entry {
                        entry.set_text(value);
                    }
                }
            }
        }
        eprintln!(
            "essai saisies : {} modification(s), {}",
            imp.draft.borrow().count(),
            imp.changes_summary.label()
        );
    }

    /// « Apply » (trials).
    pub fn trial_apply(&self) {
        self.apply();
    }

    /// The preview of the last « Apply », once shown (trials).
    pub fn trial_preview(&self) -> Option<crate::writes::PreviewDialog> {
        self.imp().preview.upgrade()
    }

    /// The object is shown, without the activity nor the groups (trials).
    pub fn trial_shown(&self) -> bool {
        self.imp().state.visible_child_name().as_deref() == Some("fiche")
    }

    /// Members once read (trials); None while they are read.
    pub fn trial_members(&self) -> Option<u32> {
        let imp = self.imp();
        (imp.members.borrow().is_none()
            && imp.members_stack.visible_child_name().as_deref() != Some("chargement"))
        .then(|| imp.members_store.n_items())
    }

    /// A tab shown: the editor reads the object the first time (`page_changed`).
    fn page_changed(&self) {
        let imp = self.imp();
        if imp.record.borrow().is_none() {
            return;
        }
        match imp.pages.visible_child_name().as_deref() {
            Some("attributs") => imp.attribute_editor.show_tab(),
            Some("securite") => imp.security_page.load(),
            Some("strategie") => imp.policy_view.load(&self.dn()),
            _ => {}
        }
    }

    /// Rows of the attribute editor once read (trials).
    pub fn trial_attributes(&self) -> Option<Vec<String>> {
        self.imp().attribute_editor.trial_lines()
    }

    /// Sentences and ACEs of the « Security » tab once shown (trials).
    pub fn trial_security(&self) -> Option<Vec<String>> {
        self.imp().security_page.trial_lines()
    }

    /// The policy of the account on `computer` (trials).
    pub fn trial_loopback(&self, computer: &str) {
        self.imp().policy_view.trial_loopback(computer);
    }

    /// Rows of the « Policy » tab once shown (trials).
    pub fn trial_policy(&self) -> Option<Vec<String>> {
        self.imp().policy_view.trial_lines()
    }

    /// Shows a tab (trials).
    pub fn trial_page(&self, name: &str) {
        self.imp().pages.set_visible_child_name(name);
    }

    /// The sheet of another object, over this one.
    fn open(&self, dn: &str) {
        if !dn.is_empty() {
            Sheet::new(self.source(), dn).present(Some(self));
        }
    }
}

/// Replaces a row that can be changed by a value row, at the same place (`name`: the
/// attribute whose value `show_record` puts there) (`_en_lecture`).
fn to_value_row(row: &gtk::Widget, name: &str) -> adw::ActionRow {
    let title = row
        .downcast_ref::<adw::PreferencesRow>()
        .map(|r| r.title().to_string())
        .unwrap_or_default();
    let value = adw::ActionRow::builder()
        .title(&title)
        .name(name)
        .subtitle_selectable(true)
        .subtitle_lines(2)
        .build();
    value.add_css_class("property");
    if let Some(list) = row.parent().and_downcast::<gtk::ListBox>() {
        let index = row
            .downcast_ref::<gtk::ListBoxRow>()
            .map_or(-1, gtk::prelude::ListBoxRowExt::index);
        list.insert(&value, index);
        list.remove(row);
    }
    value
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Dialogs of the actions on the accounts (J2.6, `annuaire.ui.comptes`): create a user, a
//! group, an OU, reset a password, rename, move. Each dialog only gathers the input and builds
//! the changeset (`annuaire_core::actions`); the write goes through `writes::propose`
//! (preview, confirmation). The dialog stays open during the preview and closes if the
//! report is complete: an input is not lost when the preview is cancelled. Structures in
//! `dialogue-*.blp`; logic of the inputs in `account_views`.
//!
//! Passwords: read from the `Adw.PasswordEntryRow` when the changeset is built, then the
//! fields are emptied. The password lives in memory in the changeset (value of `unicodePwd`)
//! until the end of the application, never in the journal nor on the screen.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_core::actions::{self, ActionError, NewUser, ReadObject};
use annuaire_core::cache::Source;
use annuaire_core::changes::{Changeset, Issue, Report};
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::account_views as av;
use crate::feed::Feed;
use crate::i18n::{fill, tr};
use crate::writes::{self, Options};

/// What follows a complete report (the protection of a new OU).
pub type After = Rc<dyn Fn(&Report)>;

/// Shows `problem` in the banner; true if there is one (`_erreur`).
fn show_problem(banner: &adw::Banner, problem: Option<&str>) -> bool {
    let text = problem.unwrap_or("");
    banner.set_title(text);
    banner.set_revealed(!text.is_empty());
    !text.is_empty()
}

/// Proposes the changeset built; the dialog closes once it is entirely applied
/// (`_proposer`).
fn propose_from(
    dialog: &adw::Dialog,
    banner: &adw::Banner,
    built: Result<Changeset, ActionError>,
    after: Option<After>,
) {
    let changeset = match built {
        Ok(c) => c,
        Err(e) => {
            show_problem(banner, Some(&av::action_error(&e)));
            return;
        }
    };
    show_problem(banner, None);
    let weak = dialog.downgrade();
    writes::propose(
        dialog,
        changeset,
        Options {
            finished: Some(Box::new(move |report| {
                if let Some(report) = report.filter(|r| r.issue == Issue::Applied) {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.close();
                    }
                    if let Some(after) = &after {
                        after(report);
                    }
                }
            })),
            ..Options::default()
        },
    );
}

macro_rules! dialog_type {
    ($module:ident, $type:ident, $name:literal, $resource:literal,
     { $($field:ident : $kind:ty),* $(,)? },
     { $($state:ident : $skind:ty),* $(,)? },
     [ $($callback:literal => $handler:expr),* $(,)? ]) => {
        mod $module {
            #[allow(unused_imports)]
            use std::cell::{OnceCell, RefCell};

            use adw::subclass::prelude::*;
            use gtk::glib;

            use crate::scope::TemplateScope;

            #[derive(Default, gtk::CompositeTemplate)]
            #[template(resource = $resource)]
            pub struct $type {
                $(#[template_child] pub $field: TemplateChild<$kind>,)*
                $(pub $state: $skind,)*
            }

            impl std::fmt::Debug for $type {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.debug_struct($name).finish_non_exhaustive()
                }
            }

            #[glib::object_subclass]
            impl ObjectSubclass for $type {
                const NAME: &'static str = $name;
                type Type = super::$type;
                type ParentType = adw::Dialog;

                fn class_init(klass: &mut Self::Class) {
                    klass.bind_template();
                    klass.set_template_scope(&TemplateScope::new::<super::$type>(&[
                        ("cancel", |d, _| {
                            adw::prelude::AdwDialogExt::close(d);
                            None
                        }),
                        $(($callback, $handler),)*
                    ]));
                }

                fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
                    obj.init_template();
                }
            }

            impl ObjectImpl for $type {}
            impl WidgetImpl for $type {}
            impl AdwDialogImpl for $type {}
        }

        glib::wrapper! {
            pub struct $type(ObjectSubclass<$module::$type>)
                @extends adw::Dialog, gtk::Widget,
                @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
        }
    };
}

// --- New user ----------------------------------------------------------------------------------

dialog_type!(
    user_imp, UserDialog, "AnnuaireDialogueUtilisateur",
    "/io/github/f3nr1l/Calinda/ui/dialogue-utilisateur.ui",
    {
        message: adw::Banner,
        given_name_entry: adw::EntryRow,
        name_entry: adw::EntryRow,
        full_name_entry: adw::EntryRow,
        identifier_entry: adw::EntryRow,
        upn_entry: adw::EntryRow,
        location_row: adw::ActionRow,
        password_entry: adw::PasswordEntryRow,
        confirmation_entry: adw::PasswordEntryRow,
        change_switch: adw::SwitchRow,
        enable_switch: adw::SwitchRow,
    },
    {
        parent: RefCell<String>,
        domain: RefCell<String>,
        // Values proposed while the user did not change them by hand.
        proposed: RefCell<[String; 3]>,
    },
    [
        "names_changed" => |d, _| { d.names_changed(); None },
        "identifier_changed" => |d, _| { d.identifier_changed(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

impl UserDialog {
    pub fn new(parent: &str, domain: &str) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.parent.borrow_mut() = parent.to_owned();
        *imp.domain.borrow_mut() = domain.to_owned();
        imp.location_row.set_subtitle(&av::parent_label(parent));
        imp.location_row.set_tooltip_text(Some(parent));
        dialog
    }

    fn follow(&self, entry: &adw::EntryRow, rank: usize, value: String) {
        let mut proposed = self.imp().proposed.borrow_mut();
        if let Some(slot) = proposed.get_mut(rank) {
            if entry.text() == slot.as_str() {
                entry.set_text(&value);
            }
            *slot = value;
        }
    }

    fn names_changed(&self) {
        let imp = self.imp();
        let (given, surname) = (imp.given_name_entry.text(), imp.name_entry.text());
        self.follow(&imp.full_name_entry, 0, av::full_name(&given, &surname));
        self.follow(
            &imp.identifier_entry,
            1,
            av::proposed_identifier(&given, &surname),
        );
    }

    fn identifier_changed(&self) {
        let imp = self.imp();
        let identifier = imp.identifier_entry.text().trim().to_owned();
        let domain = imp.domain.borrow().clone();
        self.follow(&imp.upn_entry, 2, av::proposed_upn(&identifier, &domain));
    }

    fn confirm(&self) {
        let imp = self.imp();
        let identifier = imp.identifier_entry.text().trim().to_owned();
        let (password, confirmation) = (
            imp.password_entry.text().to_string(),
            imp.confirmation_entry.text().to_string(),
        );
        let enable = imp.enable_switch.is_active();
        let problem = av::name_problem(&imp.full_name_entry.text())
            .or_else(|| av::identifier_problem(&identifier))
            .or_else(|| av::password_problem(&password, &confirmation, enable));
        if show_problem(&imp.message, problem.as_deref()) {
            return;
        }
        imp.password_entry.set_text("");
        imp.confirmation_entry.set_text("");
        let user = NewUser {
            full_name: imp.full_name_entry.text().to_string(),
            identifier,
            upn: imp.upn_entry.text().to_string(),
            given_name: imp.given_name_entry.text().to_string(),
            surname: imp.name_entry.text().to_string(),
            password: (!password.is_empty()).then_some(password),
            change_at_next_logon: imp.change_switch.is_active(),
            enable,
        };
        let built = actions::create_user(&imp.parent.borrow(), &user);
        propose_from(self.upcast_ref(), &imp.message, built, None);
    }
}

// --- New group ---------------------------------------------------------------------------------

const SCOPES: [GroupScope; 3] = [
    GroupScope::Global,
    GroupScope::DomainLocal,
    GroupScope::Universal,
];

dialog_type!(
    group_imp, GroupDialog, "AnnuaireDialogueGroupe",
    "/io/github/f3nr1l/Calinda/ui/dialogue-groupe.ui",
    {
        message: adw::Banner,
        name_entry: adw::EntryRow,
        identifier_entry: adw::EntryRow,
        description_entry: adw::EntryRow,
        location_row: adw::ActionRow,
        scope_combo: adw::ComboRow,
        security_switch: adw::SwitchRow,
    },
    { parent: RefCell<String>, proposed: RefCell<String> },
    [
        "name_changed" => |d, _| { d.name_changed(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

impl GroupDialog {
    pub fn new(parent: &str) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.parent.borrow_mut() = parent.to_owned();
        imp.location_row.set_subtitle(&av::parent_label(parent));
        dialog
    }

    fn name_changed(&self) {
        let imp = self.imp();
        let name = imp.name_entry.text().trim().to_owned();
        if imp.identifier_entry.text() == imp.proposed.borrow().as_str() {
            imp.identifier_entry.set_text(&name);
        }
        *imp.proposed.borrow_mut() = name;
    }

    fn confirm(&self) {
        let imp = self.imp();
        let identifier = imp.identifier_entry.text().trim().to_owned();
        let problem = av::name_problem(&imp.name_entry.text()).or_else(|| {
            (!identifier.is_empty())
                .then(|| av::identifier_problem(&identifier.replace(' ', "")))
                .flatten()
        });
        if show_problem(&imp.message, problem.as_deref()) {
            return;
        }
        let scope = SCOPES
            .get(usize::try_from(imp.scope_combo.selected()).unwrap_or(0))
            .copied()
            .unwrap_or(GroupScope::Global);
        let built = actions::create_group(
            &imp.parent.borrow(),
            &imp.name_entry.text(),
            &identifier,
            scope,
            imp.security_switch.is_active(),
            &imp.description_entry.text(),
        );
        propose_from(self.upcast_ref(), &imp.message, built, None);
    }
}

// --- New OU ------------------------------------------------------------------------------------

dialog_type!(
    ou_imp, OuDialog, "AnnuaireDialogueOU",
    "/io/github/f3nr1l/Calinda/ui/dialogue-ou.ui",
    {
        message: adw::Banner,
        name_entry: adw::EntryRow,
        description_entry: adw::EntryRow,
        location_row: adw::ActionRow,
        protect_switch: adw::SwitchRow,
    },
    { parent: RefCell<String>, protect: RefCell<Option<std::rc::Rc<dyn Fn(&str)>>> },
    [ "confirm" => |d, _| { d.confirm(); None } ]
);

impl OuDialog {
    /// `protect`: called with the DN of the new OU once created, if asked.
    pub fn new(parent: &str, protect: Rc<dyn Fn(&str)>) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.parent.borrow_mut() = parent.to_owned();
        *imp.protect.borrow_mut() = Some(protect);
        imp.location_row.set_subtitle(&av::parent_label(parent));
        dialog
    }

    fn confirm(&self) {
        let imp = self.imp();
        if show_problem(
            &imp.message,
            av::name_problem(&imp.name_entry.text()).as_deref(),
        ) {
            return;
        }
        let built = actions::create_ou(
            &imp.parent.borrow(),
            &imp.name_entry.text(),
            &imp.description_entry.text(),
        );
        let after: Option<After> = imp
            .protect_switch
            .is_active()
            .then(|| imp.protect.borrow().clone())
            .flatten()
            .map(|protect| -> After {
                Rc::new(move |report: &Report| {
                    if let Some(op) = report.changeset.operations.first() {
                        protect(op.dn());
                    }
                })
            });
        propose_from(self.upcast_ref(), &imp.message, built, after);
    }
}

// --- Password ----------------------------------------------------------------------------------

dialog_type!(
    password_imp, PasswordDialog, "AnnuaireDialogueMotDePasse",
    "/io/github/f3nr1l/Calinda/ui/dialogue-mot-de-passe.ui",
    {
        message: adw::Banner,
        group: adw::PreferencesGroup,
        password_entry: adw::PasswordEntryRow,
        confirmation_entry: adw::PasswordEntryRow,
        change_switch: adw::SwitchRow,
    },
    { object: RefCell<Option<annuaire_core::actions::ReadObject>> },
    [ "confirm" => |d, _| { d.confirm(); None } ]
);

impl PasswordDialog {
    pub fn new(object: ReadObject, name: &str) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.group.set_title(name);
        *imp.object.borrow_mut() = Some(object);
        dialog
    }

    fn confirm(&self) {
        let imp = self.imp();
        let (password, confirmation) = (
            imp.password_entry.text().to_string(),
            imp.confirmation_entry.text().to_string(),
        );
        if show_problem(
            &imp.message,
            av::password_problem(&password, &confirmation, true).as_deref(),
        ) {
            return;
        }
        imp.password_entry.set_text("");
        imp.confirmation_entry.set_text("");
        let Some(object) = imp.object.borrow().clone() else {
            return;
        };
        let built = actions::reset_password(&object, &password, imp.change_switch.is_active());
        propose_from(self.upcast_ref(), &imp.message, built, None);
    }
}

// --- Rename ------------------------------------------------------------------------------------

dialog_type!(
    rename_imp, RenameDialog, "AnnuaireDialogueRenommer",
    "/io/github/f3nr1l/Calinda/ui/dialogue-renommer.ui",
    {
        message: adw::Banner,
        name_entry: adw::EntryRow,
        account_group: adw::PreferencesGroup,
        display_switch: adw::SwitchRow,
        display_entry: adw::EntryRow,
        identifier_switch: adw::SwitchRow,
        identifier_entry: adw::EntryRow,
    },
    { object: RefCell<Option<annuaire_core::actions::ReadObject>>, account: std::cell::Cell<bool> },
    [
        "name_changed" => |d, _| { d.name_changed(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

impl RenameDialog {
    /// `account`: groups and accounts have a `sAMAccountName`; an OU has neither.
    pub fn new(object: ReadObject, account: bool) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let cn = object.text("cn");
        imp.name_entry.set_text(&if cn.is_empty() {
            object.text("name")
        } else {
            cn
        });
        imp.display_entry.set_text(&object.text("displayName"));
        imp.identifier_entry
            .set_text(&object.text("sAMAccountName"));
        imp.account_group.set_visible(account);
        imp.account.set(account);
        *imp.object.borrow_mut() = Some(object);
        dialog
    }

    fn name_changed(&self) {
        let imp = self.imp();
        if imp.account.get() {
            imp.display_entry.set_text(imp.name_entry.text().trim());
        }
    }

    fn confirm(&self) {
        let imp = self.imp();
        if show_problem(
            &imp.message,
            av::name_problem(&imp.name_entry.text()).as_deref(),
        ) {
            return;
        }
        let account = imp.account.get();
        let display = (account && imp.display_switch.is_active())
            .then(|| imp.display_entry.text().to_string());
        let identifier = (account && imp.identifier_switch.is_active())
            .then(|| imp.identifier_entry.text().trim().to_owned());
        if let Some(identifier) = &identifier
            && show_problem(&imp.message, av::identifier_problem(identifier).as_deref())
        {
            return;
        }
        let Some(object) = imp.object.borrow().clone() else {
            return;
        };
        let built = actions::rename(
            &object,
            &imp.name_entry.text(),
            display.as_deref(),
            identifier.as_deref(),
        );
        propose_from(self.upcast_ref(), &imp.message, built, None);
    }
}

// --- Move --------------------------------------------------------------------------------------

dialog_type!(
    move_imp, MoveDialog, "AnnuaireDialogueDeplacer",
    "/io/github/f3nr1l/Calinda/ui/dialogue-deplacer.ui",
    {
        message: adw::Banner,
        confirm_button: gtk::Button,
        search_entry: adw::EntryRow,
        list: gtk::ListBox,
    },
    {
        source: RefCell<Option<std::sync::Arc<dyn annuaire_core::cache::Source>>>,
        objects: RefCell<Vec<annuaire_core::actions::ReadObject>>,
        results: OnceCell<gtk::gio::ListStore>,
        feed: RefCell<Option<std::rc::Rc<crate::feed::Feed>>>,
    },
    [
        "search_changed" => |d, _| { d.search_changed(); None },
        "selected" => |d, _| { d.chosen(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

/// Destinations shown at most.
const MOVE_RESULTS: usize = 200;

impl MoveDialog {
    /// Destination searched by its name among the OUs and containers (reading by the source).
    pub fn new(source: Arc<dyn Source>, objects: Vec<ReadObject>) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let results = gio::ListStore::new::<gtk::StringObject>();
        imp.list.bind_model(Some(&results), |item| {
            let dn = item
                .downcast_ref::<gtk::StringObject>()
                .map(|s| s.string().to_string())
                .unwrap_or_default();
            adw::ActionRow::builder()
                .title(glib::markup_escape_text(&av::parent_label(&dn)).as_str())
                .subtitle(glib::markup_escape_text(&dn).as_str())
                .subtitle_lines(1)
                .build()
                .upcast()
        });
        let _ = imp.results.set(results);
        imp.confirm_button.set_sensitive(false);
        dialog.set_title(&if objects.len() > 1 {
            fill(
                &tr("Move {n} object(s)"),
                &[("n", &objects.len().to_string())],
            )
        } else {
            let first = objects.first();
            let name = first.map(|o| o.text("name")).unwrap_or_default();
            let name = if name.is_empty() {
                first.map(|o| o.dn.clone()).unwrap_or_default()
            } else {
                name
            };
            fill(&tr("Move “{nom}”"), &[("nom", &name)])
        });
        *imp.source.borrow_mut() = Some(source);
        *imp.objects.borrow_mut() = objects;
        dialog.search("");
        dialog
    }

    fn search(&self, text: &str) {
        let imp = self.imp();
        if let Some(feed) = imp.feed.take() {
            feed.cancel();
        }
        let Some(source) = imp.source.borrow().clone() else {
            return;
        };
        let mut filter = "(objectClass=organizationalUnit)".to_owned();
        if !text.is_empty() {
            let start = annuaire_core::search::starts_with("name", text).unwrap_or_default();
            filter =
                format!("(&(|(objectClass=organizationalUnit)(objectClass=container)){start})");
        }
        let found: Rc<RefCell<Vec<String>>> = Rc::default();
        let (into, weak) = (found.clone(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = weak.upgrade() else { return };
                let mut found = into.borrow_mut();
                for item in &items {
                    if let Item::Object(object) = item
                        && found.len() < MOVE_RESULTS
                    {
                        found.push(object.common().dn.clone());
                    }
                }
                let mut sorted = found.clone();
                sorted.sort_by_cached_key(|d| av::parent_label(d));
                if let Some(results) = dialog.imp().results.get() {
                    let objects: Vec<glib::Object> = sorted
                        .iter()
                        .map(|d| gtk::StringObject::new(d).upcast())
                        .collect();
                    results.splice(0, results.n_items(), &objects);
                }
            },
            |_| {},
        );
        *imp.feed.borrow_mut() = Some(feed);
    }

    fn search_changed(&self) {
        let text = self.imp().search_entry.text().trim().to_owned();
        self.search(&text);
    }

    fn chosen(&self) {
        let imp = self.imp();
        imp.confirm_button
            .set_sensitive(imp.list.selected_row().is_some());
    }

    fn confirm(&self) {
        let imp = self.imp();
        let Some(row) = imp.list.selected_row().and_downcast::<adw::ActionRow>() else {
            return;
        };
        let target = row.subtitle().unwrap_or_default().to_string();
        // The subtitle is escaped markup: the DN is read back from the model instead.
        let position = usize::try_from(row.index()).unwrap_or(0);
        let target = imp
            .results
            .get()
            .and_then(|r| r.item(u32::try_from(position).unwrap_or(0)))
            .and_downcast::<gtk::StringObject>()
            .map_or(target, |s| s.string().to_string());
        let built = actions::move_to(&imp.objects.borrow(), &target);
        propose_from(self.upcast_ref(), &imp.message, built, None);
    }
}

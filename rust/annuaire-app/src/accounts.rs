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
use annuaire_core::home_folder;
use annuaire_core::source::Item;
use gtk::{gio, glib};

use crate::account_views as av;
use crate::feed::Feed;
use crate::i18n::{fill, tr};
use crate::sheet_views as sv;
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

pub(crate) use dialog_type;

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
        profile_entry: adw::EntryRow,
        drive_entry: adw::EntryRow,
        home_entry: adw::EntryRow,
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
            profile_path: imp.profile_entry.text().to_string(),
            home_drive: imp.drive_entry.text().trim().to_owned(),
            home_directory: imp.home_entry.text().to_string(),
        };
        let built = actions::create_user(&imp.parent.borrow(), &user);
        let directory =
            home_folder::expand_username(user.home_directory.trim(), user.identifier.trim());
        let (Ok(changeset), false, Some(context)) = (
            &built,
            user.home_drive.is_empty() || home_folder::Unc::parse(&directory).is_none(),
            writes::context(self),
        ) else {
            propose_from(self.upcast_ref(), &imp.message, built, None);
            return;
        };
        // A drive connected to a folder of a share (ADR 0027): the folder created with the
        // account, in the same changeset, if it does not exist.
        let mut changeset = changeset.clone();
        let dn = changeset
            .operations
            .first()
            .map(|o| o.dn().to_owned())
            .unwrap_or_default();
        let sam = user.identifier.clone();
        let connection = context.connection.clone();
        let domain = context.profile.domain.clone();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let planned = gio::spawn_blocking(move || {
                home_folder::plan_new(&connection, &dn, &sam, &directory)
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            let imp = dialog.imp();
            match planned {
                Ok(Ok(plan)) => {
                    match plan {
                        Some(home_folder::Plan::Create(op)) => changeset.operations.push(*op),
                        Some(home_folder::Plan::Exists { unc }) => {
                            changeset.remarks.push(sv::folder_exists_remark(&unc));
                        }
                        None => {}
                    }
                    propose_from(dialog.upcast_ref(), &imp.message, Ok(changeset), None);
                }
                Ok(Err(error)) => {
                    show_problem(
                        &imp.message,
                        Some(&crate::errors::home_folder_message(&error, &domain)),
                    );
                }
                Err(_) => {}
            }
        });
    }
}

impl UserDialog {
    /// Trials (ADR 0027): a disabled account named `name`, with its profile, then « Continue ».
    pub fn trial_create(&self, name: &str, drive: &str, home: &str, profile: &str) {
        let imp = self.imp();
        imp.full_name_entry.set_text(name);
        imp.identifier_entry.set_text(name);
        imp.drive_entry.set_text(drive);
        imp.home_entry.set_text(home);
        imp.profile_entry.set_text(profile);
        imp.enable_switch.set_active(false);
        self.confirm();
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

// --- New computer (J9.2) ------------------------------------------------------------------------

/// Called with the DN of the new computer and the SID of the joiner, once the computer exists.
pub type AllowJoin = Rc<dyn Fn(&str, annuaire_codecs::Sid)>;

dialog_type!(
    computer_imp, ComputerDialog, "AnnuaireDialogueOrdinateur",
    "/io/github/f3nr1l/Calinda/ui/dialogue-ordinateur.ui",
    {
        message: adw::Banner,
        name_entry: adw::EntryRow,
        identifier_entry: adw::EntryRow,
        description_entry: adw::EntryRow,
        location_row: adw::ActionRow,
        joiner_row: adw::ActionRow,
        pre_windows_switch: adw::SwitchRow,
    },
    {
        parent: RefCell<String>,
        proposed: RefCell<String>,
        source: RefCell<Option<std::sync::Arc<dyn annuaire_core::cache::Source>>>,
        joiner: RefCell<Option<(annuaire_codecs::Sid, String)>>,
        allow_join: RefCell<Option<super::AllowJoin>>,
    },
    [
        "name_changed" => |d, _| { d.name_changed(); None },
        "choose_joiner" => |d, _| { d.choose_joiner(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

impl ComputerDialog {
    pub fn new(parent: &str, source: Arc<dyn Source>, allow_join: AllowJoin) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.parent.borrow_mut() = parent.to_owned();
        *imp.source.borrow_mut() = Some(source);
        *imp.allow_join.borrow_mut() = Some(allow_join);
        imp.location_row.set_subtitle(&av::parent_label(parent));
        imp.location_row.set_tooltip_text(Some(parent));
        dialog
    }

    fn name_changed(&self) {
        let imp = self.imp();
        let proposed = annuaire_core::computers::proposed_identifier(&imp.name_entry.text());
        if imp.identifier_entry.text() == imp.proposed.borrow().as_str() {
            imp.identifier_entry.set_text(&proposed);
        }
        *imp.proposed.borrow_mut() = proposed;
    }

    /// « Change… »: an account or a group chosen by the dialog of the members, its SID read.
    fn choose_joiner(&self) {
        let Some(source) = self.imp().source.borrow().clone() else {
            return;
        };
        let weak = self.downgrade();
        let reader = source.clone();
        let dialog = crate::members::MembersDialog::new(
            source,
            Box::new(move |view| {
                let (Some(dialog), source) = (weak.upgrade(), reader.clone()) else {
                    return;
                };
                let (dn, name, weak) = (view.dn.clone(), view.title.clone(), dialog.downgrade());
                glib::spawn_future_local(async move {
                    let read =
                        gio::spawn_blocking(move || source.record(&dn, &["objectSid"])).await;
                    let Some(dialog) = weak.upgrade() else { return };
                    let sid = match read {
                        Ok(Ok(Some(record))) => record
                            .entry
                            .values("objectSid")
                            .first()
                            .and_then(|v| annuaire_codecs::Sid::decode(v).ok()),
                        _ => None,
                    };
                    dialog.joiner_chosen(sid, &name);
                });
            }),
        );
        dialog.present(Some(self));
    }

    fn joiner_chosen(&self, sid: Option<annuaire_codecs::Sid>, name: &str) {
        let imp = self.imp();
        let Some(sid) = sid else {
            show_problem(
                &imp.message,
                Some(&fill(
                    &tr("“{nom}” has no security identifier: it cannot be allowed to join."),
                    &[("nom", name)],
                )),
            );
            return;
        };
        show_problem(&imp.message, None);
        imp.joiner_row.set_subtitle(&glib::markup_escape_text(name));
        *imp.joiner.borrow_mut() = Some((sid, name.to_owned()));
    }

    fn confirm(&self) {
        let imp = self.imp();
        let identifier = imp.identifier_entry.text().trim().to_owned();
        let problem = av::name_problem(&imp.name_entry.text())
            .or_else(|| av::computer_identifier_problem(&identifier));
        if show_problem(&imp.message, problem.as_deref()) {
            return;
        }
        let computer = annuaire_core::computers::NewComputer {
            name: imp.name_entry.text().to_string(),
            identifier,
            description: imp.description_entry.text().to_string(),
            pre_windows_2000: imp.pre_windows_switch.is_active(),
            joiner: imp.joiner.borrow().as_ref().map(|(sid, _)| *sid),
        };
        // What the DC accepts as a default password, read first (off the interface thread).
        let Some(context) = writes::context(self) else {
            return;
        };
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        let domain = context.profile.domain.clone();
        glib::spawn_future_local(async move {
            let rule =
                gio::spawn_blocking(move || annuaire_core::computers::read_rule(&connection)).await;
            let Some(dialog) = weak.upgrade() else { return };
            match rule {
                Ok(Ok(rule)) => dialog.propose_computer(&computer, &rule),
                Ok(Err(failure)) => {
                    show_problem(
                        &dialog.imp().message,
                        Some(&crate::errors::failure_problem(&failure, &domain).message),
                    );
                }
                Err(_) => {}
            }
        });
    }

    fn propose_computer(
        &self,
        computer: &annuaire_core::computers::NewComputer,
        rule: &annuaire_core::computers::PasswordRule,
    ) {
        let imp = self.imp();
        let joiner = imp.joiner.borrow().clone();
        let built = annuaire_core::computers::create_computer(&imp.parent.borrow(), computer, rule);
        // The ACEs of the joiner on the descriptor the DC gave the account (as the protection
        // of a new OU): a second preview.
        let after: Option<After> =
            joiner
                .zip(imp.allow_join.borrow().clone())
                .map(|((sid, _), allow)| -> After {
                    Rc::new(move |report: &Report| {
                        if let Some(op) = report.changeset.operations.first() {
                            allow(op.dn(), sid);
                        }
                    })
                });
        if let Ok(changeset) = &built
            && let Some((_, name)) = &*imp.joiner.borrow()
        {
            let mut changeset = changeset.clone();
            changeset.remarks.push(fill(
                &tr("“{nom}” will be allowed to join this computer to the domain: its permissions are proposed once the account is created."),
                &[("nom", name)],
            ));
            propose_from(self.upcast_ref(), &imp.message, Ok(changeset), after);
            return;
        }
        propose_from(self.upcast_ref(), &imp.message, built, after);
    }
}

impl ComputerDialog {
    /// Trials: the computer `name`, pre-Windows 2000 or not, then « Continue ».
    pub fn trial_create(&self, name: &str, pre_windows_2000: bool) {
        let imp = self.imp();
        imp.name_entry.set_text(name);
        imp.pre_windows_switch.set_active(pre_windows_2000);
        self.confirm();
    }
}

// --- New contact (J9.2) -------------------------------------------------------------------------

dialog_type!(
    contact_imp, ContactDialog, "AnnuaireDialogueContact",
    "/io/github/f3nr1l/Calinda/ui/dialogue-contact.ui",
    {
        message: adw::Banner,
        given_name_entry: adw::EntryRow,
        initials_entry: adw::EntryRow,
        name_entry: adw::EntryRow,
        full_name_entry: adw::EntryRow,
        display_entry: adw::EntryRow,
        location_row: adw::ActionRow,
        mail_entry: adw::EntryRow,
        telephone_entry: adw::EntryRow,
        street_entry: adw::EntryRow,
        postal_code_entry: adw::EntryRow,
        city_entry: adw::EntryRow,
        description_entry: adw::EntryRow,
    },
    { parent: RefCell<String>, proposed: RefCell<[String; 2]> },
    [
        "names_changed" => |d, _| { d.names_changed(); None },
        "full_name_changed" => |d, _| { d.full_name_changed(); None },
        "confirm" => |d, _| { d.confirm(); None },
    ]
);

impl ContactDialog {
    pub fn new(parent: &str) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        *imp.parent.borrow_mut() = parent.to_owned();
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
        let full = av::full_name(&imp.given_name_entry.text(), &imp.name_entry.text());
        self.follow(&imp.full_name_entry, 0, full);
    }

    fn full_name_changed(&self) {
        let imp = self.imp();
        let full = imp.full_name_entry.text().trim().to_owned();
        self.follow(&imp.display_entry, 1, full);
    }

    fn confirm(&self) {
        let imp = self.imp();
        if show_problem(
            &imp.message,
            av::name_problem(&imp.full_name_entry.text()).as_deref(),
        ) {
            return;
        }
        let text = |e: &adw::EntryRow| e.text().to_string();
        let contact = annuaire_core::computers::NewContact {
            full_name: text(&imp.full_name_entry),
            given_name: text(&imp.given_name_entry),
            initials: text(&imp.initials_entry),
            surname: text(&imp.name_entry),
            display_name: text(&imp.display_entry),
            mail: text(&imp.mail_entry),
            telephone: text(&imp.telephone_entry),
            street: text(&imp.street_entry),
            postal_code: text(&imp.postal_code_entry),
            city: text(&imp.city_entry),
            description: text(&imp.description_entry),
        };
        let built = annuaire_core::computers::create_contact(&imp.parent.borrow(), &contact);
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

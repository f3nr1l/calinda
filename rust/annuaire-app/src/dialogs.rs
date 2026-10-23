// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Dialogs of the home screen (J2.2, `annuaire.ui.dialogues`): domain profile, Kerberos
//! ticket. Structure in `dialogue-profil.blp` and `dialogue-ticket.blp`. The discovery of the
//! DCs (DNS) and the ticket (KDC) are asked off the interface thread.

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::kerberos::{self, PrincipalError, Ticket, TicketError, TicketErrorKind};
use annuaire_core::profile::{self, FingerprintError, Mode, Profile};
use annuaire_core::srv::{self, ResolvConf, SrvError};
use annuaire_core::storage;
use gtk::{gio, glib};

use crate::i18n::{fill, tr};
use crate::settings::ProfileStore;
use crate::texts;

const MODES: [Mode; 3] = [Mode::Sealed, Mode::Ldaps, Mode::StartTls];

/// What a banner shows: the message with its first letter in upper case (`_erreur`).
fn capitalized(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map_or_else(String::new, |first| {
        first.to_uppercase().chain(chars).collect()
    })
}

fn show_error(banner: &adw::Banner, text: Option<&str>) {
    let text = text.unwrap_or("");
    banner.set_title(&capitalized(text));
    banner.set_revealed(!text.is_empty());
}

fn srv_message(error: &SrvError, domain: &str) -> String {
    match error {
        SrvError::NotFound { .. } => fill(
            &tr("No domain controller found for “{domaine}”."),
            &[("domaine", domain)],
        ),
        SrvError::Unreachable { .. } => tr("This computer's DNS server is not responding."),
    }
}

fn fingerprint_message(error: &FingerprintError) -> String {
    match error {
        FingerprintError::NoCertificate => tr("no PEM certificate"),
        FingerprintError::Unreadable => tr("unreadable PEM certificate"),
    }
}

fn principal_message(error: &PrincipalError) -> String {
    match error {
        PrincipalError::Invalid => tr("Invalid user name: “user” or “user@REALM”."),
        PrincipalError::ForbiddenCharacter => {
            tr("The user name contains a character that is not allowed.")
        }
        PrincipalError::NoRealm => tr("Specify the realm: “user@REALM”."),
        PrincipalError::InvalidRealm(realm) => {
            fill(&tr("Invalid realm: {royaume}."), &[("royaume", realm)])
        }
    }
}

/// Message of a failure to obtain a ticket (`traduire_gss`, `obtenir_ticket`).
pub fn ticket_message(error: &TicketError, principal: &str) -> String {
    let realm = principal.rsplit_once('@').map_or("", |(_, r)| r);
    let fields = [("principal", principal), ("royaume", realm)];
    // Each message is written out for xgettext: `tr` takes literal strings.
    let text = match error.kind {
        TicketErrorKind::PasswordRefused => tr("Password rejected for {principal}."),
        TicketErrorKind::UnknownAccount => tr("The account {principal} is unknown to the domain."),
        TicketErrorKind::PasswordExpired => {
            tr("The password of {principal} has expired: it must be changed first.")
        }
        TicketErrorKind::Revoked => {
            tr("The account {principal} is disabled, locked out or expired.")
        }
        TicketErrorKind::ClockSkew => {
            tr("The clocks of this computer and of the domain controller differ too much.")
        }
        TicketErrorKind::NoKdc => tr("No Kerberos server responds for the realm {royaume}."),
        TicketErrorKind::Other => tr("Unable to obtain a Kerberos ticket."),
        TicketErrorKind::NotStored => {
            tr("The ticket was obtained but could not be stored in the Kerberos cache.")
        }
        TicketErrorKind::NotReadable => {
            tr("The ticket was obtained but cannot be read from the Kerberos cache.")
        }
    };
    fill(&text, &fields)
}

/// Replaces the proposed DCs after the automatic choice; keeps the chosen DC, even when the
/// DNS no longer announces it (`_proposer_dcs`).
fn propose_dcs(choice: &adw::ComboRow, list: &gtk::StringList, dcs: &[String]) {
    let selected = choice.selected();
    let chosen = list.string(selected).map(|s| s.to_string());
    let names: Vec<&str> = dcs.iter().map(String::as_str).collect();
    list.splice(1, list.n_items().saturating_sub(1), &names);
    let position = chosen
        .as_deref()
        .and_then(|c| dcs.iter().position(|d| d == c));
    if let Some(i) = position {
        choice.set_selected(u32::try_from(i + 1).unwrap_or(0));
    } else if selected != 0 {
        if let Some(chosen) = chosen.filter(|c| !c.is_empty()) {
            list.append(&chosen);
            choice.set_selected(u32::try_from(dcs.len() + 1).unwrap_or(0));
        }
    }
}

// --- Profile ---------------------------------------------------------------------------

type Saved = Box<dyn Fn(&Profile)>;

mod profile_imp {
    use std::cell::{OnceCell, RefCell};

    use adw::prelude::*;
    use adw::subclass::prelude::*;
    use annuaire_core::profile::Profile;
    use gtk::glib;

    use crate::scope::TemplateScope;
    use crate::settings::ProfileStore;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-profil.ui")]
    pub struct ProfileDialog {
        #[template_child]
        pub confirm_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub domain_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub discovery_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub discovery_spinner: TemplateChild<gtk::Spinner>,
        #[template_child]
        pub dc_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub dc_list: TemplateChild<gtk::StringList>,
        #[template_child]
        pub write_dc_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub write_dc_list: TemplateChild<gtk::StringList>,
        #[template_child]
        pub mode_combo: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub ca_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub read_only_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub cache_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub smb2_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub message: TemplateChild<adw::Banner>,
        pub store: OnceCell<ProfileStore>,
        pub origin: RefCell<Option<Profile>>,
        pub ca: RefCell<Option<String>>,
        pub searched: RefCell<String>,
        pub saved: RefCell<Option<super::Saved>>,
    }

    impl std::fmt::Debug for ProfileDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ProfileDialog")
                .field("origin", &self.origin)
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ProfileDialog {
        const NAME: &'static str = "AnnuaireDialogueProfil";
        type Type = super::ProfileDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::ProfileDialog>(&[
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("mode_changed", |d, _| {
                    d.mode_changed();
                    None
                }),
                ("discover", |d, _| {
                    d.discover();
                    None
                }),
                ("choose_ca", |d, _| {
                    d.choose_ca();
                    None
                }),
                ("confirm", |d, _| {
                    d.validate();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ProfileDialog {}
    impl WidgetImpl for ProfileDialog {}
    impl AdwDialogImpl for ProfileDialog {}
}

glib::wrapper! {
    /// Adding or editing a domain profile.
    pub struct ProfileDialog(ObjectSubclass<profile_imp::ProfileDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl ProfileDialog {
    pub fn new(store: ProfileStore, profile: Option<&Profile>, saved: Saved) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.store.set(store);
        *imp.saved.borrow_mut() = Some(saved);
        *imp.origin.borrow_mut() = profile.cloned();
        if let Some(profile) = profile {
            dialog.set_title(&tr("Edit the Profile"));
            imp.confirm_button.set_label(&tr("Save"));
            imp.domain_entry.set_text(&profile.domain);
            imp.domain_entry.set_editable(false); // key of the profile
            if let Some(dc) = &profile.preferred_dc {
                imp.dc_list.append(dc);
                imp.dc_combo.set_selected(1);
            }
            if let Some(dc) = &profile.write_dc {
                imp.write_dc_list.append(dc);
                imp.write_dc_combo.set_selected(1);
            }
            let mode = MODES.iter().position(|&m| m == profile.mode).unwrap_or(0);
            imp.mode_combo
                .set_selected(u32::try_from(mode).unwrap_or(0));
            dialog.choose_ca_file(
                profile
                    .ca
                    .as_ref()
                    .map(|c| c.to_string_lossy().into_owned()),
            );
            imp.read_only_switch.set_active(profile.read_only);
            imp.cache_switch.set_active(profile.cache);
            imp.smb2_switch.set_active(profile.smb2_signing);
            dialog.discover();
        }
        dialog
    }

    fn selected_mode(&self) -> Mode {
        let index = usize::try_from(self.imp().mode_combo.selected()).unwrap_or(0);
        MODES.get(index).copied().unwrap_or(Mode::Sealed)
    }

    /// Looks the DCs of the domain up in the DNS (SRV), off the interface thread.
    fn discover(&self) {
        let imp = self.imp();
        let domain = imp.domain_entry.text().trim().to_lowercase();
        if domain.is_empty() {
            return;
        }
        imp.searched.replace(domain.clone());
        imp.discovery_spinner.set_visible(true);
        imp.discovery_spinner.set_spinning(true);
        imp.discovery_row.set_subtitle(&tr("Looking up DNS…"));
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let asked = domain.clone();
            let found =
                gio::spawn_blocking(move || srv::find_dcs(&ResolvConf::system(), &asked)).await;
            let Some(dialog) = weak.upgrade() else { return };
            let imp = dialog.imp();
            if *imp.searched.borrow() != domain {
                return; // a more recent search is running
            }
            imp.discovery_spinner.set_visible(false);
            imp.discovery_spinner.set_spinning(false);
            match found {
                Ok(Ok(records)) => {
                    let dcs: Vec<String> = records.into_iter().map(|r| r.target).collect();
                    imp.discovery_row.set_subtitle(&dcs.join(", "));
                    propose_dcs(&imp.dc_combo, &imp.dc_list, &dcs);
                    propose_dcs(&imp.write_dc_combo, &imp.write_dc_list, &dcs);
                }
                Ok(Err(error)) => imp
                    .discovery_row
                    .set_subtitle(&srv_message(&error, &domain)),
                Err(_) => imp.discovery_row.set_subtitle(""),
            }
        });
    }

    /// Keeps the CA and shows its fingerprint, to compare with the one of the DC.
    fn choose_ca_file(&self, path: Option<String>) {
        let imp = self.imp();
        imp.ca.replace(path.clone());
        let Some(path) = path else { return };
        imp.ca_row.set_subtitle(&path);
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read = gio::File::for_path(&path).load_contents_future().await;
            let Some(dialog) = weak.upgrade() else { return };
            let fingerprint =
                read.map_err(|e| e.message().to_owned())
                    .and_then(|(content, _etag)| {
                        profile::certificate_fingerprint(&content)
                            .map_err(|e| fingerprint_message(&e))
                    });
            let subtitle = match fingerprint {
                Ok(fingerprint) => fill(
                    &tr("{chemin}\nSHA-256: {empreinte}"),
                    &[("chemin", &path), ("empreinte", &fingerprint)],
                ),
                Err(error) => fill(
                    &tr("{chemin}\nUnreadable certificate: {erreur}"),
                    &[("chemin", &path), ("erreur", &error)],
                ),
            };
            dialog.imp().ca_row.set_subtitle(&subtitle);
        });
    }
}

// Template callbacks (`TemplateScope`).
impl ProfileDialog {
    fn mode_changed(&self) {
        self.imp().ca_row.set_visible(self.selected_mode().tls());
    }

    fn choose_ca(&self) {
        let files = gtk::FileDialog::builder()
            .title(tr("Certificate of the domain CA"))
            .modal(true)
            .build();
        let root = self.root().and_downcast::<gtk::Window>();
        let weak = self.downgrade();
        files.open(root.as_ref(), gio::Cancellable::NONE, move |result| {
            // Cancelled: nothing to do.
            let Ok(file) = result else { return };
            if let (Some(dialog), Some(path)) = (weak.upgrade(), file.path()) {
                dialog.choose_ca_file(Some(path.to_string_lossy().into_owned()));
            }
        });
    }

    fn validate(&self) {
        let imp = self.imp();
        let Some(store) = imp.store.get() else { return };
        let domain = imp.domain_entry.text().trim().to_lowercase();
        let chosen = |choice: &adw::ComboRow, list: &gtk::StringList| {
            let selected = choice.selected();
            (selected > 0)
                .then(|| list.string(selected))
                .flatten()
                .map(|s| s.to_string())
        };
        let mode = self.selected_mode();
        let profile = Profile {
            domain: domain.clone(),
            preferred_dc: chosen(&imp.dc_combo, &imp.dc_list),
            mode,
            ca: if mode.tls() {
                imp.ca.borrow().clone().map(Into::into)
            } else {
                None
            },
            read_only: imp.read_only_switch.is_active(),
            write_dc: chosen(&imp.write_dc_combo, &imp.write_dc_list),
            cache: imp.cache_switch.is_active(),
            smb2_signing: imp.smb2_switch.is_active(),
            // Not edited here: kept as the « Shares » window left them.
            file_servers: imp
                .origin
                .borrow()
                .as_ref()
                .map(|p| p.file_servers.clone())
                .unwrap_or_default(),
        };
        if let Err(error) = profile.validate() {
            show_error(&imp.message, Some(&texts::profile_error(&error)));
            return;
        }
        if imp.origin.borrow().is_none() && store.list().iter().any(|p| p.domain == domain) {
            let text = fill(
                &tr("A profile already exists for {domaine}."),
                &[("domaine", &domain)],
            );
            show_error(&imp.message, Some(&text));
            return;
        }
        store.save(&profile);
        if !profile.cache {
            // No more copy on this computer (JC.4).
            let _ = storage::erase(&storage::cache_path(&profile.domain, None));
        }
        self.close();
        if let Some(saved) = imp.saved.borrow().as_ref() {
            saved(&profile);
        }
    }
}

// --- Ticket ----------------------------------------------------------------------------

type Obtained = Box<dyn Fn(&Ticket)>;

mod ticket_imp {
    use std::cell::RefCell;

    use adw::subclass::prelude::*;
    use gtk::glib;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-ticket.ui")]
    pub struct TicketDialog {
        #[template_child]
        pub get_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub button_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub account_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub password_entry: TemplateChild<adw::PasswordEntryRow>,
        #[template_child]
        pub message: TemplateChild<adw::Banner>,
        pub realm: RefCell<Option<String>>,
        pub obtained: RefCell<Option<super::Obtained>>,
    }

    impl std::fmt::Debug for TicketDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("TicketDialog")
                .field("realm", &self.realm)
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for TicketDialog {
        const NAME: &'static str = "AnnuaireDialogueTicket";
        type Type = super::TicketDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::TicketDialog>(&[
                ("cancel", |d, _| {
                    d.cancel();
                    None
                }),
                ("get", |d, _| {
                    d.obtain();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for TicketDialog {}
    impl WidgetImpl for TicketDialog {}
    impl AdwDialogImpl for TicketDialog {}
}

glib::wrapper! {
    /// A ticket obtained by password; the password is never kept: the typed text is copied
    /// once into a buffer and the field is emptied at once; the core overwrites the buffer as
    /// soon as GSSAPI has read it.
    pub struct TicketDialog(ObjectSubclass<ticket_imp::TicketDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl TicketDialog {
    pub fn new(realm: Option<String>, account: &str, obtained: Obtained) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.account_entry.set_text(account);
        if let Some(realm) = &realm {
            imp.group
                .set_title(&fill(&tr("Realm {royaume}"), &[("royaume", realm)]));
        }
        *imp.realm.borrow_mut() = realm;
        *imp.obtained.borrow_mut() = Some(obtained);
        let focus: gtk::Widget = if account.is_empty() {
            imp.account_entry.get().upcast()
        } else {
            imp.password_entry.get().upcast()
        };
        dialog.set_focus(Some(&focus));
        dialog
    }

    fn busy(&self, active: bool) {
        let imp = self.imp();
        imp.button_stack
            .set_visible_child_name(if active { "attente" } else { "texte" });
        imp.get_button.set_sensitive(!active);
        imp.account_entry.set_sensitive(!active);
        imp.password_entry.set_sensitive(!active);
    }
}

// Template callbacks (`TemplateScope`).
impl TicketDialog {
    fn cancel(&self) {
        self.imp().password_entry.set_text("");
        self.close();
    }

    fn obtain(&self) {
        let imp = self.imp();
        let realm = imp.realm.borrow().clone();
        let principal =
            match kerberos::principal_from_input(&imp.account_entry.text(), realm.as_deref()) {
                Ok(p) => p,
                Err(e) => {
                    show_error(&imp.message, Some(&principal_message(&e)));
                    return;
                }
            };
        let mut password = imp.password_entry.text().as_bytes().to_vec();
        imp.password_entry.set_text("");
        if password.is_empty() {
            show_error(&imp.message, Some(&tr("Enter the password.")));
            return;
        }
        show_error(&imp.message, None);
        self.busy(true);
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let asked = principal.clone();
            let result =
                gio::spawn_blocking(move || kerberos::obtain_ticket(&asked, &mut password)).await;
            let Some(dialog) = weak.upgrade() else { return };
            dialog.busy(false);
            let imp = dialog.imp();
            match result {
                Ok(Ok(ticket)) => {
                    dialog.close();
                    if let Some(obtained) = imp.obtained.borrow().as_ref() {
                        obtained(&ticket);
                    }
                }
                Ok(Err(error)) => {
                    show_error(&imp.message, Some(&ticket_message(&error, &principal)));
                    let field: gtk::Widget = imp.password_entry.get().upcast();
                    dialog.set_focus(Some(&field));
                }
                Err(_) => show_error(
                    &imp.message,
                    Some(&tr("Unable to obtain a Kerberos ticket.")),
                ),
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn banner_text() {
        assert_eq!(
            capitalized("invalid domain name: 'X'"),
            "Invalid domain name: 'X'"
        );
        assert_eq!(capitalized("é"), "É");
        assert_eq!(capitalized(""), "");
    }

    #[test]
    fn ticket_messages() {
        let error = |kind| TicketError {
            kind,
            detail: String::new(),
        };
        assert_eq!(
            ticket_message(&error(TicketErrorKind::PasswordRefused), "x@LAB.TEST"),
            "Password rejected for x@LAB.TEST."
        );
        assert_eq!(
            ticket_message(&error(TicketErrorKind::NoKdc), "x@LAB.TEST"),
            "No Kerberos server responds for the realm LAB.TEST."
        );
    }
}

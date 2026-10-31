// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Secrets of a computer in its sheet (ADR 0025): the « LAPS » tab (J9.4) and the « BitLocker »
//! tab (J9.5, recovery passwords under the computer). Read on the DC at
//! the first showing of the tab (`Source::reader`, never the local copy), kept while the sheet is
//! open and forgotten when it is read again or closed. A password is shown only on demand and
//! copied with the clipboard emptied after 30 s if it still holds it; never in a log, a journal
//! or a toast. « Expire now » is a changeset of the common path (preview, journal, inverse).

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::laps::{self, Managed, Reading, Schema, Secret, State};
use gtk::{gdk, gio, glib};

use super::Sheet;
use crate::errors;
use crate::i18n::{fill, tr};
use crate::sheet_views as sv;
use crate::writes::{self, Options};

/// Seconds the clipboard keeps a secret copied.
pub const CLIPBOARD_SECONDS: u32 = 30;

/// What the secret tabs read, and the groups they show.
#[derive(Debug, Default)]
pub struct Secrets {
    /// LAPS read for this generation of the sheet (None: not read yet).
    pub laps: Option<u64>,
    pub reading: Option<Reading>,
    pub groups: Vec<adw::PreferencesGroup>,
    /// BitLocker read for this generation of the sheet.
    pub bitlocker: Option<u64>,
    pub recovery_groups: Vec<adw::PreferencesGroup>,
}

/// Copies `secret` to the clipboard of `widget`, and empties the clipboard after
/// [`CLIPBOARD_SECONDS`] if it still holds it.
pub fn copy_secret(widget: &impl IsA<gtk::Widget>, secret: &Secret) {
    let clipboard = widget.as_ref().clipboard();
    clipboard.set_text(secret.reveal());
    let copied = secret.clone();
    glib::timeout_add_seconds_local_once(CLIPBOARD_SECONDS, move || {
        let display = gdk::Display::default();
        let Some(clipboard) = display.map(|d| d.clipboard()) else {
            return;
        };
        let check = clipboard.clone();
        clipboard.read_text_async(gio::Cancellable::NONE, move |text| {
            if text
                .ok()
                .flatten()
                .is_some_and(|t| t.as_str() == copied.reveal())
            {
                check.set_content(None::<&gdk::ContentProvider>).ok();
            }
        });
    });
}

/// A row that shows a secret only on demand (« Show »), with « Copy ».
pub fn secret_row(title: &str, secret: &Secret, toasts: &adw::ToastOverlay) -> adw::ActionRow {
    const HIDDEN: &str = "••••••••••••";
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(HIDDEN)
        .build();
    row.add_css_class("property");
    let show = gtk::ToggleButton::builder()
        .icon_name("view-reveal-symbolic")
        .tooltip_text(tr("Show"))
        .valign(gtk::Align::Center)
        .build();
    show.add_css_class("flat");
    let copy = gtk::Button::builder()
        .icon_name("edit-copy-symbolic")
        .tooltip_text(tr("Copy"))
        .valign(gtk::Align::Center)
        .build();
    copy.add_css_class("flat");
    let (shown, weak) = (secret.clone(), row.downgrade());
    show.connect_toggled(move |button| {
        if let Some(row) = weak.upgrade() {
            if button.is_active() {
                row.set_subtitle(&glib::markup_escape_text(shown.reveal()));
                row.add_css_class("monospace");
                button.set_tooltip_text(Some(&tr("Hide")));
            } else {
                row.set_subtitle(HIDDEN);
                row.remove_css_class("monospace");
                button.set_tooltip_text(Some(&tr("Show")));
            }
        }
    });
    let (copied, toasts) = (secret.clone(), toasts.clone());
    copy.connect_clicked(move |button| {
        copy_secret(button, &copied);
        toasts.add_toast(adw::Toast::new(&fill(
            &tr("Copied. The clipboard is emptied in {n} seconds."),
            &[("n", &CLIPBOARD_SECONDS.to_string())],
        )));
    });
    row.add_suffix(&show);
    row.add_suffix(&copy);
    row
}

fn value_row(title: &str, value: &str) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(title)
        .subtitle(glib::markup_escape_text(value).as_str())
        .subtitle_selectable(true)
        .build();
    row.add_css_class("property");
    row
}

fn schema_title(schema: Schema) -> String {
    match schema {
        Schema::Windows => tr("Windows LAPS"),
        Schema::Legacy => tr("Microsoft LAPS (legacy)"),
    }
}

/// What the tab says of a state that is not a password read.
pub fn state_text(managed: &Managed) -> Option<String> {
    match &managed.state {
        State::Readable => None,
        State::Encrypted => Some(tr(
            "The password is kept encrypted (msLAPS-EncryptedPassword) and could not be read: your account may not be allowed to decrypt it, or the domain does not serve the key distribution service.",
        )),
        State::Refused => Some(fill(
            &tr(
                "Your account is not allowed to read this password: {attribut} is a confidential attribute, read only with the “All extended rights” (control access) permission on it.",
            ),
            &[("attribut", managed.schema.password_attribute())],
        )),
        State::Malformed(_) => Some(tr("The value of msLAPS-Password cannot be read.")),
    }
}

impl Sheet {
    /// Forgets the secrets read and the groups that show them.
    pub(super) fn secrets_forget(&self) {
        let imp = self.imp();
        let groups = std::mem::take(&mut imp.secrets.borrow_mut().groups);
        for group in groups {
            imp.laps_content.remove(&group);
        }
        let recovery = std::mem::take(&mut imp.secrets.borrow_mut().recovery_groups);
        for group in recovery {
            imp.bitlocker_content.remove(&group);
        }
        let mut secrets = imp.secrets.borrow_mut();
        secrets.laps = None;
        secrets.reading = None;
        secrets.bitlocker = None;
    }

    fn recovery_group(&self, group: adw::PreferencesGroup) {
        let imp = self.imp();
        imp.bitlocker_content.add(&group);
        imp.secrets.borrow_mut().recovery_groups.push(group);
    }

    /// Reads the recovery passwords under the computer, once per generation of the sheet.
    pub(super) fn bitlocker_load(&self) {
        let imp = self.imp();
        let generation = imp.generation.get();
        if imp.secrets.borrow().bitlocker == Some(generation) {
            return;
        }
        imp.secrets.borrow_mut().bitlocker = Some(generation);
        let (source, dn, weak) = (self.source(), self.dn(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || {
                annuaire_core::bitlocker::under(&source.reader(&dn), &dn)
            })
            .await;
            let Some(sheet) = weak.upgrade() else { return };
            if sheet.imp().generation.get() != generation {
                return;
            }
            let Ok(read) = read else { return };
            let domain = sheet.source().profile().domain.clone();
            match read {
                Err(error) => sheet.recovery_group(
                    adw::PreferencesGroup::builder()
                        .title(tr("BitLocker"))
                        .description(glib::markup_escape_text(
                            &errors::search_problem(&error, &domain).message,
                        ))
                        .build(),
                ),
                Ok(found) if found.is_empty() => sheet.recovery_group(
                    adw::PreferencesGroup::builder()
                        .title(tr("BitLocker"))
                        .description(tr(
                            "No BitLocker recovery password of this computer is in the directory, or your account cannot see them.",
                        ))
                        .build(),
                ),
                Ok(found) => {
                    let toasts = sheet.imp().toasts.clone();
                    for recovery in &found {
                        sheet.recovery_group(recovery_group(recovery, &toasts, false));
                    }
                }
            }
        });
    }

    fn secrets_group(&self, group: adw::PreferencesGroup) {
        let imp = self.imp();
        imp.laps_content.add(&group);
        imp.secrets.borrow_mut().groups.push(group);
    }

    /// Reads LAPS on the DC, once per generation of the sheet (`again`: after « Expire now »).
    pub(super) fn laps_load(&self, again: bool) {
        let imp = self.imp();
        let generation = imp.generation.get();
        if !again && imp.secrets.borrow().laps == Some(generation) {
            return;
        }
        let groups = std::mem::take(&mut imp.secrets.borrow_mut().groups);
        for group in groups {
            imp.laps_content.remove(&group);
        }
        imp.secrets.borrow_mut().reading = None;
        imp.secrets.borrow_mut().laps = Some(generation);
        let reading = adw::PreferencesGroup::new();
        reading.add(&adw::ActionRow::builder().title(tr("Reading…")).build());
        self.secrets_group(reading);
        let (source, dn, weak) = (self.source(), self.dn(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || laps::read(&source.reader(&dn), &dn)).await;
            let Some(sheet) = weak.upgrade() else { return };
            if sheet.imp().generation.get() != generation {
                return;
            }
            let Ok(read) = read else { return };
            sheet.laps_show(read);
        });
    }

    fn laps_show(&self, read: Result<Option<Reading>, annuaire_core::connection::Failure>) {
        let imp = self.imp();
        let groups = std::mem::take(&mut imp.secrets.borrow_mut().groups);
        for group in groups {
            imp.laps_content.remove(&group);
        }
        let reading = match read {
            Ok(Some(reading)) => reading,
            Ok(None) => return,
            Err(failure) => {
                let domain = self.source().profile().domain.clone();
                let group = adw::PreferencesGroup::builder()
                    .title(tr("LAPS"))
                    .description(glib::markup_escape_text(
                        &errors::failure_problem(&failure, &domain).message,
                    ))
                    .build();
                self.secrets_group(group);
                return;
            }
        };
        if reading.managed.is_empty() {
            let group = adw::PreferencesGroup::builder()
                .title(tr("LAPS"))
                .description(tr(
                    "No local administrator password of this computer is kept in the directory by LAPS, or its expiration date cannot be read with your account.",
                ))
                .build();
            self.secrets_group(group);
        }
        for managed in &reading.managed {
            let group = adw::PreferencesGroup::builder()
                .title(schema_title(managed.schema))
                .build();
            if let Some(text) = state_text(managed) {
                group.set_description(Some(&glib::markup_escape_text(&text)));
            }
            if let Some(account) = &managed.account {
                group.add(&value_row(&tr("Managed account"), account));
            }
            if let Some(password) = &managed.password {
                group.add(&secret_row(&tr("Password"), password, &imp.toasts));
            }
            if managed.updated.is_some() {
                group.add(&value_row(
                    &tr("Updated"),
                    &sv::nttime_text(managed.updated),
                ));
            }
            group.add(&value_row(
                &tr("Expires"),
                &sv::nttime_text(managed.expiration),
            ));
            if !imp.read_only.get() && !managed.expiration_values.is_empty() {
                let button = gtk::Button::builder()
                    .label(tr("Expire Now…"))
                    .valign(gtk::Align::Center)
                    .tooltip_text(tr(
                        "The computer changes its password at its next policy processing",
                    ))
                    .build();
                let (weak, schema) = (self.downgrade(), managed.schema);
                button.connect_clicked(move |_| {
                    if let Some(sheet) = weak.upgrade() {
                        sheet.laps_expire(schema);
                    }
                });
                group.set_header_suffix(Some(&button));
            }
            self.secrets_group(group);
        }
        if reading.encrypted_extra {
            let group = adw::PreferencesGroup::builder()
                .description(tr(
                    "An encrypted history or directory services restore mode password is kept too: readable in a later version.",
                ))
                .build();
            self.secrets_group(group);
        }
        imp.secrets.borrow_mut().reading = Some(reading);
    }

    /// « Expire now »: the expiration date set to now, through the preview.
    fn laps_expire(&self, schema: Schema) {
        let Some(reading) = self.imp().secrets.borrow().reading.clone() else {
            return;
        };
        let built = laps::expire_now(&reading, schema, laps::now());
        let changeset = match built {
            Ok(mut c) => {
                c.remarks.push(tr(
                    "The computer changes its password at its next processing of the LAPS policy (every hour, or Invoke-LapsPolicyProcessing). The password is not written by Calinda.",
                ));
                c
            }
            Err(e) => {
                self.imp()
                    .toasts
                    .add_toast(adw::Toast::new(&crate::account_views::action_error(&e)));
                return;
            }
        };
        let weak = self.downgrade();
        writes::propose(
            self,
            changeset,
            Options {
                finished: Some(Box::new(move |report| {
                    if report.is_some()
                        && let Some(sheet) = weak.upgrade()
                    {
                        sheet.laps_load(true);
                    }
                })),
                ..Options::default()
            },
        );
    }
}

/// One recovery password: its identifier, its date, the password on demand (`computer`: name the
/// computer too, for the search of the window).
pub fn recovery_group(
    recovery: &annuaire_core::bitlocker::Recovery,
    toasts: &adw::ToastOverlay,
    computer: bool,
) -> adw::PreferencesGroup {
    let id = recovery.id.clone().unwrap_or_else(|| "—".to_owned());
    let group = adw::PreferencesGroup::builder()
        .title(glib::markup_escape_text(&fill(
            &tr("Password ID {id}"),
            &[("id", &id)],
        )))
        .build();
    if computer {
        group.add(&value_row(
            &tr("Computer"),
            &annuaire_core::source::name_from_dn(&recovery.computer),
        ));
    }
    group.add(&value_row(
        &tr("Backed up"),
        if recovery.date.is_empty() {
            &recovery.created
        } else {
            &recovery.date
        },
    ));
    if let Some(volume) = &recovery.volume {
        group.add(&value_row(&tr("Volume"), volume));
    }
    match &recovery.password {
        Some(password) => group.add(&secret_row(&tr("Recovery password"), password, toasts)),
        None => group.set_description(Some(&tr(
            "Your account is not allowed to read this recovery password: msFVE-RecoveryPassword is a confidential attribute.",
        ))),
    }
    group
}

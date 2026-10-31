// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Account tabs of the sheet (J9.3, ADR 0024): logon hours (grid in local time, the
//! directory keeps UTC), logon workstations (an entry of the « Account » tab, plain draft
//! input), the « Delegation » tab of ADUC (none, unconstrained, constrained with or without
//! protocol transition, services chosen among the SPNs of the directory), resource-based
//! constrained delegation, service principal names checked against the forest, and the
//! protection against accidental deletion.
//!
//! Every change goes into the draft of the sheet like the others: the delegation flags as
//! an input of `userAccountControl`, the lists and binary values as edits of the attribute
//! (`AttributeEdit`), the protection as `Draft::protect`. « Apply » makes one changeset of
//! them (`sheet_views::prepare_changeset`): no other way of writing.

use std::collections::HashMap;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_codecs::logon_hours::{self, LogonHours};
use annuaire_core::account_tabs::{self as at, Delegation};
use annuaire_core::changes::Values;
use annuaire_core::model::Object;
use annuaire_core::source::{Record, name_from_dn};
use gtk::{gio, glib};

use super::Sheet;
use crate::errors;
use crate::i18n::{fill, tr, tr_n};
use crate::members::MembersDialog;
use crate::sheet_views::AttributeEdit;

/// What the tabs read at the opening of the sheet; what is wanted lives in the draft.
#[derive(Debug, Default)]
pub struct Tabs {
    pub hours: Values,
    pub services: Values,
    pub spns: Values,
    pub rbcd: Values,
    /// Names of the accounts of the RBCD descriptor (read after the display, or chosen).
    pub names: HashMap<Sid, String>,
    /// Read after the display; None until then, or unreadable.
    pub protected: Option<bool>,
    /// The bound account may write the RBCD descriptor (not on Samba 4.22, which applies the
    /// `systemOnly` of its schema).
    pub rbcd_writable: bool,
    /// Readings in flight (protection, SID of an account, SPN checked): the trials wait.
    pub pending: u32,
}

/// Offset of the local time zone now, in seconds ahead of UTC.
pub fn local_offset_seconds() -> i64 {
    glib::DateTime::now_local().map_or(0, |d| d.utc_offset().as_seconds())
}

/// « UTC−04:00 ».
pub fn offset_text(seconds: i64) -> String {
    let sign = if seconds < 0 { '−' } else { '+' };
    let minutes = seconds.abs() / 60;
    format!("UTC{sign}{:02}:{:02}", minutes / 60, minutes % 60)
}

/// Days in the order of the grid (Monday first), as indexes of the codec (0: Sunday).
pub const DAYS: [usize; 7] = [1, 2, 3, 4, 5, 6, 0];

pub fn day_name(day: usize) -> String {
    match day {
        0 => tr("Sunday"),
        1 => tr("Monday"),
        2 => tr("Tuesday"),
        3 => tr("Wednesday"),
        4 => tr("Thursday"),
        5 => tr("Friday"),
        _ => tr("Saturday"),
    }
}

/// What the « Logon hours » row says of the hours (`values`: the attribute).
pub fn hours_summary(values: &[Vec<u8>], offset_seconds: i64) -> String {
    match LogonHours::from_attribute(values) {
        Err(_) => tr("Unreadable value"),
        Ok(hours) if hours.all_allowed() => tr("Logon allowed at all hours"),
        Ok(hours) if hours.allowed() == 0 => tr("Logon never allowed"),
        Ok(hours) => fill(
            &tr_n(
                "Logon allowed {n} hour a week (local time, {offset})",
                "Logon allowed {n} hours a week (local time, {offset})",
                hours.allowed() as u64,
            ),
            &[
                ("n", &hours.allowed().to_string()),
                ("offset", &offset_text(offset_seconds)),
            ],
        ),
    }
}

/// The value of `logonHours` to want for `hours`: unchanged when the attribute is absent and
/// every hour stays allowed, otherwise the 21 bytes (all allowed: `0xFF` everywhere, as ADUC).
pub fn hours_value(origin: &[Vec<u8>], hours: &LogonHours) -> Values {
    if origin.is_empty() && hours.all_allowed() {
        Vec::new()
    } else {
        vec![hours.encode()]
    }
}

fn texts(values: &[Vec<u8>]) -> Vec<String> {
    values
        .iter()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .collect()
}

fn values_of(texts: &[String]) -> Values {
    texts.iter().map(|t| t.as_bytes().to_vec()).collect()
}

impl Sheet {
    fn tabs_current(&self, attribute: &str, origin: &Values) -> Values {
        self.imp()
            .draft
            .borrow()
            .edit_of(attribute)
            .map_or_else(|| origin.clone(), |e| e.wanted.clone())
    }

    /// Puts an edit of an account tab in the draft (back to the origin: removed).
    fn tabs_edit(&self, attribute: &str, single: bool, origin: Values, wanted: Values) {
        let kept = self.imp().draft.borrow_mut().edit(AttributeEdit {
            attribute: attribute.to_owned(),
            single,
            origin,
            wanted,
        });
        if let Err(error) = kept {
            self.imp()
                .toasts
                .add_toast(adw::Toast::new(&error.message()));
        }
        self.update_bar();
        self.tabs_refresh();
    }

    /// Fills the account tabs from the object read (in `show`, while `filling`).
    pub(super) fn tabs_show(&self, record: &Record, object: &Object) {
        let imp = self.imp();
        let account = object.account();
        let user = matches!(object, Object::User { .. });
        imp.delegation_page.set_visible(account.is_some());
        imp.restrictions_group.set_visible(user);
        {
            let mut tabs = imp.tabs.borrow_mut();
            let entry = &record.entry;
            tabs.hours = entry.values(at::LOGON_HOURS).to_vec();
            tabs.services = entry.values(at::DELEGATE_TO).to_vec();
            tabs.spns = entry.values(at::SPN).to_vec();
            tabs.rbcd = entry.values(at::RBCD).to_vec();
        }
        // The protection read before (« Discard ») is shown until it is read again.
        let read_only = imp.read_only.get();
        let protected = imp.tabs.borrow().protected;
        imp.protection_switch.set_active(protected.unwrap_or(false));
        imp.protection_switch
            .set_sensitive(protected.is_some() && !read_only);
        imp.protection_switch.set_subtitle(&if protected.is_some() {
            String::new()
        } else {
            tr("Reading…")
        });
        imp.logon_hours_button.set_label(&if read_only {
            tr("Show…")
        } else {
            tr("Edit…")
        });
        for widget in [
            imp.delegation_none.upcast_ref::<gtk::Widget>(),
            imp.delegation_any.upcast_ref(),
            imp.delegation_services.upcast_ref(),
            imp.protocol_kerberos.upcast_ref(),
            imp.protocol_any.upcast_ref(),
        ] {
            widget.set_sensitive(!read_only);
        }
        imp.spn_add_group.set_visible(!read_only);
        if let Some(account) = account {
            let tabs = imp.tabs.borrow();
            let choice = Delegation::of(account.uac, tabs.services.len());
            drop(tabs);
            self.tabs_show_delegation(choice);
        }
        self.tabs_refresh();
    }

    fn tabs_show_delegation(&self, choice: Delegation) {
        let imp = self.imp();
        match choice {
            Delegation::None => imp.delegation_none.set_active(true),
            Delegation::Unconstrained => imp.delegation_any.set_active(true),
            Delegation::Constrained { any_protocol } => {
                imp.delegation_services.set_active(true);
                if any_protocol {
                    imp.protocol_any.set_active(true);
                } else {
                    imp.protocol_kerberos.set_active(true);
                }
            }
        }
        if !matches!(choice, Delegation::Constrained { .. }) {
            imp.protocol_kerberos.set_active(true);
        }
    }

    /// What is read after the display: the protection (DACL of the object), the names of
    /// the accounts of the RBCD descriptor, whether the DC lets the account write it.
    pub(super) fn tabs_read(&self, generation: u64, object: &Object) {
        let (source, dn, weak) = (self.source(), self.dn(), self.downgrade());
        let rbcd = self.imp().tabs.borrow().rbcd.clone();
        let account = object.account().is_some();
        self.tabs_busy(true);
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || {
                let reader = source.reader(&dn);
                let protected = at::read_protection(&reader, &dn);
                let sids: std::collections::HashSet<Sid> = at::rbcd_sids(&rbcd)
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                let names = if sids.is_empty() {
                    HashMap::new()
                } else {
                    annuaire_core::security::name_sids(&reader, sids).unwrap_or_default()
                };
                let writable = account && at::rbcd_writable(&reader, &dn).unwrap_or(false);
                (protected, names, writable)
            })
            .await;
            let Some(sheet) = weak.upgrade() else { return };
            sheet.tabs_busy(false);
            let imp = sheet.imp();
            if imp.generation.get() != generation {
                return;
            }
            let Ok((protected, names, writable)) = read else {
                return;
            };
            {
                let mut tabs = imp.tabs.borrow_mut();
                tabs.names
                    .extend(names.into_iter().map(|(sid, n)| (sid, n.name)));
                tabs.rbcd_writable = writable;
            }
            let domain = sheet.source().profile().domain.clone();
            imp.filling.set(true);
            match protected {
                Ok(Some(protected)) => {
                    imp.tabs.borrow_mut().protected = Some(protected);
                    let wanted = imp.draft.borrow().protect.unwrap_or(protected);
                    imp.protection_switch.set_active(wanted);
                    imp.protection_switch.set_subtitle("");
                    imp.protection_switch.set_sensitive(!imp.read_only.get());
                }
                Ok(None) => imp
                    .protection_switch
                    .set_subtitle(&tr("The permissions of the object cannot be read.")),
                Err(failure) => imp
                    .protection_switch
                    .set_subtitle(&errors::failure_problem(&failure, &domain).message),
            }
            imp.filling.set(false);
            sheet.tabs_refresh();
        });
    }

    /// The lists and summaries of the tabs, from the draft (or the values read).
    fn tabs_refresh(&self) {
        let imp = self.imp();
        let read_only = imp.read_only.get();
        let (hours, services, spns, rbcd, names, writable) = {
            let tabs = imp.tabs.borrow();
            (
                self.tabs_current(at::LOGON_HOURS, &tabs.hours),
                texts(&self.tabs_current(at::DELEGATE_TO, &tabs.services)),
                texts(&self.tabs_current(at::SPN, &tabs.spns)),
                at::rbcd_sids(&self.tabs_current(at::RBCD, &tabs.rbcd)),
                tabs.names.clone(),
                tabs.rbcd_writable,
            )
        };
        imp.logon_hours_row
            .set_subtitle(&hours_summary(&hours, local_offset_seconds()));
        let constrained = imp.delegation_services.is_active();
        imp.add_services_button
            .set_visible(!read_only && constrained);
        fill_list(
            &imp.services_list,
            &services
                .iter()
                .map(|s| (s.clone(), String::new(), s.clone()))
                .collect::<Vec<_>>(),
            (!read_only).then(|| self.remover(at::DELEGATE_TO)),
        );
        fill_list(
            &imp.spn_list,
            &spns
                .iter()
                .map(|s| (s.clone(), String::new(), s.clone()))
                .collect::<Vec<_>>(),
            (!read_only).then(|| self.remover(at::SPN)),
        );
        let rbcd_rows: Vec<(String, String, String)> = match &rbcd {
            Ok(sids) => sids
                .iter()
                .map(|sid| {
                    (
                        names.get(sid).cloned().unwrap_or_else(|| sid.to_string()),
                        sid.to_string(),
                        sid.to_string(),
                    )
                })
                .collect(),
            Err(e) => vec![(tr("Unreadable value"), e.to_string(), String::new())],
        };
        let editable = !read_only && writable;
        imp.add_rbcd_button.set_visible(editable);
        let refused = tr(
            "The domain controller declares this attribute system-only (Samba): it cannot be written over LDAP. On a Samba DC, use “samba-tool delegation add-principal”.",
        );
        imp.rbcd_group
            .set_description((!writable && !read_only).then_some(refused.as_str()));
        fill_list(
            &imp.rbcd_list,
            &rbcd_rows,
            editable.then(|| self.rbcd_remover()),
        );
    }

    fn remover(&self, attribute: &'static str) -> Box<dyn Fn(String)> {
        let weak = self.downgrade();
        Box::new(move |value: String| {
            let Some(sheet) = weak.upgrade() else { return };
            let origin = sheet.tabs_origin(attribute);
            let mut wanted = sheet.tabs_current(attribute, &origin);
            wanted.retain(|v| v != value.as_bytes());
            sheet.tabs_edit(attribute, false, origin, wanted);
        })
    }

    fn rbcd_remover(&self) -> Box<dyn Fn(String)> {
        let weak = self.downgrade();
        Box::new(move |sid: String| {
            let Some(sheet) = weak.upgrade() else { return };
            let Ok(sid) = sid.parse::<Sid>() else { return };
            let origin = sheet.tabs_origin(at::RBCD);
            let mut sids =
                at::rbcd_sids(&sheet.tabs_current(at::RBCD, &origin)).unwrap_or_default();
            sids.retain(|s| *s != sid);
            sheet.tabs_set_rbcd(&origin, &sids);
        })
    }

    fn tabs_set_rbcd(&self, origin: &Values, sids: &[Sid]) {
        match at::rbcd_value(origin, sids) {
            Ok(wanted) => self.tabs_edit(at::RBCD, true, origin.clone(), wanted),
            Err(e) => {
                self.imp()
                    .toasts
                    .add_toast(adw::Toast::new(&crate::codec_texts::codec_message(
                        &e.to_string(),
                    )))
            }
        }
    }

    fn tabs_origin(&self, attribute: &str) -> Values {
        let tabs = self.imp().tabs.borrow();
        match attribute {
            at::LOGON_HOURS => tabs.hours.clone(),
            at::DELEGATE_TO => tabs.services.clone(),
            at::SPN => tabs.spns.clone(),
            _ => tabs.rbcd.clone(),
        }
    }

    /// `protection_changed`.
    pub(super) fn protection_changed(&self) {
        let imp = self.imp();
        if imp.filling.get() {
            return;
        }
        let Some(read) = imp.tabs.borrow().protected else {
            return;
        };
        imp.last_row.set(Some(imp.protection_switch.upcast_ref()));
        let wanted = imp.protection_switch.is_active();
        imp.draft.borrow_mut().protect = (wanted != read).then_some(wanted);
        self.update_bar();
    }

    /// The choice of the « Delegation » tab: the flags of `userAccountControl` as an input,
    /// the list of services emptied when it no longer applies (as ADUC).
    pub(super) fn delegation_changed(&self) {
        let imp = self.imp();
        if imp.filling.get() || imp.record.borrow().is_none() {
            return;
        }
        let choice = if imp.delegation_any.is_active() {
            Delegation::Unconstrained
        } else if imp.delegation_services.is_active() {
            Delegation::Constrained {
                any_protocol: imp.protocol_any.is_active(),
            }
        } else {
            Delegation::None
        };
        imp.last_row.set(Some(imp.delegation_none.upcast_ref()));
        let present = imp
            .draft
            .borrow()
            .value("userAccountControl")
            .trim()
            .parse::<i64>()
            .unwrap_or(0);
        let flags = choice.uac((present & 0xFFFF_FFFF) as u32);
        let value = annuaire_codecs::uac::UserAccountControl(flags).encode();
        let _ = imp
            .draft
            .borrow_mut()
            .input("userAccountControl", &value.to_string());
        let origin = self.tabs_origin(at::DELEGATE_TO);
        let current = self.tabs_current(at::DELEGATE_TO, &origin);
        if !choice.keeps_services() && !current.is_empty() {
            self.tabs_edit(at::DELEGATE_TO, false, origin, Vec::new());
        } else if choice.keeps_services() && current.is_empty() && !origin.is_empty() {
            self.tabs_edit(at::DELEGATE_TO, false, origin.clone(), origin);
        } else {
            self.update_bar();
            self.tabs_refresh();
        }
    }

    /// « Edit… » of the logon hours: the grid in local time.
    pub(super) fn edit_logon_hours(&self) -> adw::Dialog {
        let origin = self.tabs_origin(at::LOGON_HOURS);
        let hours = LogonHours::from_attribute(&self.tabs_current(at::LOGON_HOURS, &origin))
            .unwrap_or_default();
        let weak = self.downgrade();
        let dialog = logon_hours_dialog(
            hours,
            local_offset_seconds(),
            self.imp().read_only.get(),
            Box::new(move |hours| {
                if let Some(sheet) = weak.upgrade() {
                    sheet.tabs_set_hours(&hours);
                }
            }),
        );
        dialog.present(Some(self));
        dialog
    }

    fn tabs_set_hours(&self, hours: &LogonHours) {
        self.imp()
            .last_row
            .set(Some(self.imp().logon_hours_row.upcast_ref()));
        let origin = self.tabs_origin(at::LOGON_HOURS);
        let wanted = hours_value(&origin, hours);
        self.tabs_edit(at::LOGON_HOURS, true, origin, wanted);
    }

    /// « Add Services… »: SPNs of the accounts of the directory.
    pub(super) fn add_services(&self) -> adw::Dialog {
        let weak = self.downgrade();
        let dialog = services_dialog(
            self.source().reader(&self.dn()),
            Box::new(move |chosen: Vec<String>| {
                if let Some(sheet) = weak.upgrade() {
                    sheet.tabs_add_services(&chosen);
                }
            }),
        );
        dialog.present(Some(self));
        dialog
    }

    fn tabs_add_services(&self, chosen: &[String]) {
        let origin = self.tabs_origin(at::DELEGATE_TO);
        let mut wanted = texts(&self.tabs_current(at::DELEGATE_TO, &origin));
        for spn in chosen {
            if !wanted.iter().any(|w| w.eq_ignore_ascii_case(spn)) {
                wanted.push(spn.clone());
            }
        }
        self.tabs_edit(at::DELEGATE_TO, false, origin, values_of(&wanted));
    }

    /// « Add Accounts… » of the RBCD: an account chosen, its SID read.
    pub(super) fn add_rbcd(&self) -> MembersDialog {
        let weak = self.downgrade();
        let dialog = MembersDialog::new(
            self.source(),
            Box::new(move |view| {
                if let Some(sheet) = weak.upgrade() {
                    sheet.tabs_add_rbcd(&view.dn, &view.title);
                }
            }),
        );
        dialog.present(Some(self));
        dialog
    }

    fn tabs_add_rbcd(&self, dn: &str, name: &str) {
        let (source, asked, weak, name) = (
            self.source(),
            dn.to_owned(),
            self.downgrade(),
            name.to_owned(),
        );
        self.tabs_busy(true);
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.record(&asked, &["objectSid"])).await;
            let Some(sheet) = weak.upgrade() else { return };
            sheet.tabs_busy(false);
            let sid = match read {
                Ok(Ok(Some(record))) => record
                    .entry
                    .values("objectSid")
                    .first()
                    .and_then(|v| Sid::decode(v).ok()),
                _ => None,
            };
            let Some(sid) = sid else {
                sheet.imp().toasts.add_toast(adw::Toast::new(&fill(
                    &tr("“{nom}” has no security identifier: it cannot be allowed to delegate."),
                    &[("nom", &name)],
                )));
                return;
            };
            sheet.imp().tabs.borrow_mut().names.insert(sid, name);
            let origin = sheet.tabs_origin(at::RBCD);
            let mut sids =
                at::rbcd_sids(&sheet.tabs_current(at::RBCD, &origin)).unwrap_or_default();
            if !sids.contains(&sid) {
                sids.push(sid);
            }
            sheet.tabs_set_rbcd(&origin, &sids);
        });
    }

    /// The SPN typed: its form, then its uniqueness in the forest (global catalog).
    pub(super) fn add_spn(&self) {
        let imp = self.imp();
        let entry = imp.spn_entry.clone();
        let text = entry.text().trim().to_owned();
        if text.is_empty() {
            return;
        }
        if at::check_spn(&text).is_err() {
            mark(
                &entry,
                Some(&tr(
                    "A service principal name has the form service/host, or service/host:port.",
                )),
            );
            return;
        }
        let origin = self.tabs_origin(at::SPN);
        let current = texts(&self.tabs_current(at::SPN, &origin));
        if current.iter().any(|s| s.eq_ignore_ascii_case(&text)) {
            entry.set_text("");
            mark(&entry, None);
            return;
        }
        entry.set_sensitive(false);
        let (reader, dn, weak) = (
            self.source().reader(&self.dn()),
            self.dn(),
            self.downgrade(),
        );
        let asked = text.clone();
        self.tabs_busy(true);
        glib::spawn_future_local(async move {
            let owners = gio::spawn_blocking(move || at::spn_owners(&reader, &asked, &dn)).await;
            let Some(sheet) = weak.upgrade() else { return };
            sheet.tabs_busy(false);
            let imp = sheet.imp();
            imp.spn_entry.set_sensitive(true);
            match owners {
                Ok(Ok(owners)) if !owners.is_empty() => {
                    let names: Vec<String> = owners.iter().map(|o| name_from_dn(o)).collect();
                    mark(
                        &imp.spn_entry,
                        Some(&fill(
                            &tr("“{spn}” is already used by {comptes}: two accounts with the same name break Kerberos for this service."),
                            &[("spn", &text), ("comptes", &names.join(", "))],
                        )),
                    );
                    return;
                }
                Ok(Ok(_)) => {}
                _ => imp.toasts.add_toast(adw::Toast::new(&tr(
                    "The global catalog could not be reached: the name is added without checking the forest.",
                ))),
            }
            mark(&imp.spn_entry, None);
            imp.spn_entry.set_text("");
            let origin = sheet.tabs_origin(at::SPN);
            let mut wanted = texts(&sheet.tabs_current(at::SPN, &origin));
            wanted.push(text);
            sheet.tabs_edit(at::SPN, false, origin, values_of(&wanted));
        });
    }

    fn tabs_busy(&self, started: bool) {
        let mut tabs = self.imp().tabs.borrow_mut();
        tabs.pending = if started {
            tabs.pending + 1
        } else {
            tabs.pending.saturating_sub(1)
        };
    }

    /// A reading of the tabs is in flight (trials: the inputs and « Apply » wait).
    pub fn trial_busy(&self) -> bool {
        self.imp().tabs.borrow().pending > 0
    }

    /// Inputs of a trial for the tabs (`trial_input`); false if `name` is not one of them.
    pub(super) fn tabs_trial(&self, name: &str, value: &str) -> bool {
        let imp = self.imp();
        match name {
            "heures" => {
                if let Some(hours) = local_hours(value, local_offset_seconds()) {
                    self.tabs_set_hours(&hours);
                }
            }
            "delegation" => match value {
                "toute" => imp.delegation_any.set_active(true),
                "services" => {
                    imp.delegation_services.set_active(true);
                    imp.protocol_kerberos.set_active(true);
                }
                "services-tout" => {
                    imp.delegation_services.set_active(true);
                    imp.protocol_any.set_active(true);
                }
                _ => imp.delegation_none.set_active(true),
            },
            "service+" => self.tabs_add_services(&[value.to_owned()]),
            "service-" => self.remover(at::DELEGATE_TO)(value.to_owned()),
            "spn+" => {
                imp.spn_entry.set_text(value);
                self.add_spn();
            }
            "spn-" => self.remover(at::SPN)(value.to_owned()),
            "rbcd+" => self.tabs_add_rbcd(value, &name_from_dn(value)),
            "rbcd-" => self.rbcd_remover()(value.to_owned()),
            "protection" => imp.protection_switch.set_active(value == "1"),
            "grille" => {
                let _ = self.edit_logon_hours();
            }
            "services" => {
                let _ = self.add_services();
            }
            _ => return false,
        }
        true
    }
}

/// Hours allowed in local time, as a trial gives them: `DAYS:HOURS`, days 1 (Monday) to 7
/// (Sunday) and hours of the day, each `first-last` (the last hour excluded) or one number;
/// the rest of the week denied, as the grid would make it (`1-5:8-18`).
pub fn local_hours(spec: &str, offset_seconds: i64) -> Option<LogonHours> {
    let (days, hours) = spec.split_once(':')?;
    let range = |text: &str| -> Option<(usize, usize)> {
        match text.split_once('-') {
            Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
            None => {
                let n: usize = text.trim().parse().ok()?;
                Some((n, n))
            }
        }
    };
    let ((first_day, last_day), (from, to)) = (range(days)?, range(hours)?);
    let offset = logon_hours::offset_hours(offset_seconds);
    let mut chosen = LogonHours::none();
    for iso in first_day..=last_day {
        let day = iso % 7;
        for hour in from..to.min(24) {
            chosen.set_local(day, hour, offset, true);
        }
    }
    Some(chosen)
}

/// Marks an entry as refused (`problem`), or clears the mark.
fn mark(entry: &adw::EntryRow, problem: Option<&str>) {
    match problem {
        Some(problem) => {
            entry.add_css_class("error");
            entry.set_tooltip_text(Some(problem));
        }
        None => {
            entry.remove_css_class("error");
            entry.set_tooltip_text(None);
        }
    }
}

/// Rows `(title, subtitle, key)` in a boxed list; `remove`: a button per row, given the key.
fn fill_list(
    list: &gtk::ListBox,
    rows: &[(String, String, String)],
    remove: Option<Box<dyn Fn(String)>>,
) {
    list.remove_all();
    if rows.is_empty() {
        let row = adw::ActionRow::builder().title(tr("None")).build();
        row.add_css_class("dim-label");
        list.append(&row);
        return;
    }
    let remove = remove.map(std::rc::Rc::new);
    for (title, subtitle, key) in rows {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(title).as_str())
            .subtitle(glib::markup_escape_text(subtitle).as_str())
            .subtitle_selectable(true)
            .build();
        if let Some(remove) = &remove {
            let button = gtk::Button::from_icon_name("list-remove-symbolic");
            button.set_valign(gtk::Align::Center);
            button.add_css_class("flat");
            let label = fill(&tr("Remove “{nom}”"), &[("nom", title)]);
            button.set_tooltip_text(Some(&label));
            button.update_property(&[gtk::accessible::Property::Label(&label)]);
            let (remove, key) = (remove.clone(), key.clone());
            button.connect_clicked(move |_| remove(key.clone()));
            row.add_suffix(&button);
        }
        list.append(&row);
    }
}

/// The grid of the logon hours, in local time, Monday first; `done` gets the hours chosen.
pub fn logon_hours_dialog(
    hours: LogonHours,
    offset_seconds: i64,
    read_only: bool,
    done: Box<dyn Fn(LogonHours)>,
) -> adw::Dialog {
    let offset = logon_hours::offset_hours(offset_seconds);
    let dialog = adw::Dialog::builder()
        .title(tr("Logon Hours"))
        .content_width(1080)
        .build();
    let header = adw::HeaderBar::builder()
        .show_start_title_buttons(false)
        .show_end_title_buttons(read_only)
        .build();
    let body = gtk::Box::new(gtk::Orientation::Vertical, 12);
    body.set_margin_top(12);
    body.set_margin_bottom(18);
    body.set_margin_start(18);
    body.set_margin_end(18);
    let explanation = gtk::Label::new(Some(&fill(
        &tr(
            "Hours in the local time of this computer ({offset}). The directory keeps them in UTC: seen from another time zone, the same restriction is shown shifted.",
        ),
        &[("offset", &offset_text(offset_seconds))],
    )));
    explanation.set_wrap(true);
    explanation.set_xalign(0.0);
    explanation.add_css_class("dim-label");
    body.append(&explanation);
    let grid = gtk::Grid::builder()
        .row_spacing(2)
        .column_spacing(2)
        .halign(gtk::Align::Center)
        .build();
    let cells: std::rc::Rc<Vec<(usize, usize, gtk::ToggleButton)>> = std::rc::Rc::new(
        DAYS.iter()
            .enumerate()
            .flat_map(|(row, &day)| (0..24).map(move |hour| (row, day, hour)))
            .map(|(row, day, hour)| {
                let cell = gtk::ToggleButton::builder()
                    .active(hours.local(day, hour, offset))
                    .width_request(28)
                    .height_request(28)
                    .sensitive(!read_only)
                    .build();
                // Allowed hours in the accent colour, as the blue of ADUC.
                let paint = |cell: &gtk::ToggleButton| {
                    if cell.is_active() {
                        cell.add_css_class("suggested-action");
                    } else {
                        cell.remove_css_class("suggested-action");
                    }
                };
                paint(&cell);
                cell.connect_toggled(paint);
                let label = fill(
                    &tr("{jour}, {de}:00 to {a}:00"),
                    &[
                        ("jour", &day_name(day)),
                        ("de", &format!("{hour:02}")),
                        ("a", &format!("{:02}", hour + 1)),
                    ],
                );
                cell.set_tooltip_text(Some(&label));
                cell.update_property(&[gtk::accessible::Property::Label(&label)]);
                grid.attach(
                    &cell,
                    i32::try_from(hour).unwrap_or(0) + 1,
                    i32::try_from(row).unwrap_or(0) + 1,
                    1,
                    1,
                );
                (day, hour, cell)
            })
            .collect(),
    );
    // Hours as plain labels: a button per column would make the grid too wide.
    for hour in 0..24usize {
        let label = gtk::Label::new(Some(&hour.to_string()));
        label.add_css_class("caption");
        label.add_css_class("dim-label");
        label.set_width_chars(2);
        grid.attach(&label, i32::try_from(hour).unwrap_or(0) + 1, 0, 1, 1);
    }
    for (row, &day) in DAYS.iter().enumerate() {
        let button = gtk::Button::with_label(&day_name(day));
        button.add_css_class("flat");
        button.set_halign(gtk::Align::End);
        let label = fill(&tr("All of {jour}"), &[("jour", &day_name(day))]);
        button.set_tooltip_text(Some(&label));
        button.update_property(&[gtk::accessible::Property::Label(&label)]);
        button.set_sensitive(!read_only);
        let cells = cells.clone();
        button.connect_clicked(move |_| {
            let chosen: Vec<&gtk::ToggleButton> = cells
                .iter()
                .filter(|(d, _, _)| *d == day)
                .map(|(_, _, c)| c)
                .collect();
            let on = !chosen.iter().all(|c| c.is_active());
            for c in chosen {
                c.set_active(on);
            }
        });
        grid.attach(&button, 0, i32::try_from(row).unwrap_or(0) + 1, 1, 1);
    }
    let scrolled = gtk::ScrolledWindow::builder()
        .child(&grid)
        .vscrollbar_policy(gtk::PolicyType::Never)
        .propagate_natural_width(true)
        .build();
    body.append(&scrolled);
    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    actions.set_halign(gtk::Align::Center);
    for (text, on) in [(tr("Allow All"), true), (tr("Deny All"), false)] {
        let button = gtk::Button::with_label(&text);
        button.add_css_class("pill");
        button.set_sensitive(!read_only);
        let cells = cells.clone();
        button.connect_clicked(move |_| {
            for (_, _, c) in cells.iter() {
                c.set_active(on);
            }
        });
        actions.append(&button);
    }
    body.append(&actions);
    if !read_only {
        let cancel = gtk::Button::with_label(&tr("Cancel"));
        let weak = dialog.downgrade();
        cancel.connect_clicked(move |_| {
            if let Some(d) = weak.upgrade() {
                d.close();
            }
        });
        header.pack_start(&cancel);
        let ok = gtk::Button::with_label(&tr("OK"));
        ok.add_css_class("suggested-action");
        let (weak, cells) = (dialog.downgrade(), cells.clone());
        ok.connect_clicked(move |_| {
            let mut chosen = hours;
            for (day, hour, cell) in cells.iter() {
                chosen.set_local(*day, *hour, offset, cell.is_active());
            }
            done(chosen);
            if let Some(d) = weak.upgrade() {
                d.close();
            }
        });
        header.pack_end(&ok);
    }
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.set_content(Some(&body));
    dialog.set_child(Some(&view));
    dialog
}

/// « Add Services »: the accounts whose name starts with the text typed, each SPN a row to
/// tick; `done` gets the SPNs ticked.
pub fn services_dialog(
    reader: std::sync::Arc<annuaire_core::Connection>,
    done: Box<dyn Fn(Vec<String>)>,
) -> adw::Dialog {
    let dialog = adw::Dialog::builder()
        .title(tr("Add Services"))
        .content_width(560)
        .content_height(560)
        .build();
    let header = adw::HeaderBar::builder()
        .show_start_title_buttons(false)
        .show_end_title_buttons(false)
        .build();
    let cancel = gtk::Button::with_label(&tr("Cancel"));
    let add = gtk::Button::with_label(&tr("Add"));
    add.add_css_class("suggested-action");
    add.set_sensitive(false);
    header.pack_start(&cancel);
    header.pack_end(&add);
    let body = gtk::Box::new(gtk::Orientation::Vertical, 12);
    body.set_margin_top(12);
    body.set_margin_bottom(12);
    body.set_margin_start(12);
    body.set_margin_end(12);
    let search = gtk::SearchEntry::builder()
        .placeholder_text(tr("Name of a user or computer"))
        .build();
    search.update_property(&[gtk::accessible::Property::Label(&tr(
        "Name of a user or computer",
    ))]);
    let status = gtk::Label::new(Some(&tr(
        "Type the beginning of the name of the account that offers the service.",
    )));
    status.set_wrap(true);
    status.set_xalign(0.0);
    status.add_css_class("dim-label");
    let list = gtk::ListBox::new();
    list.set_selection_mode(gtk::SelectionMode::None);
    list.add_css_class("boxed-list");
    list.update_property(&[gtk::accessible::Property::Label(&tr("Services found"))]);
    let scrolled = gtk::ScrolledWindow::builder()
        .child(&list)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    body.append(&search);
    body.append(&status);
    body.append(&scrolled);
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.set_content(Some(&body));
    dialog.set_child(Some(&view));

    type Checks = std::rc::Rc<std::cell::RefCell<Vec<(String, gtk::CheckButton)>>>;
    let checks: Checks = std::rc::Rc::default();
    let generation = std::rc::Rc::new(std::cell::Cell::new(0u64));
    {
        let (list, status, checks, add) =
            (list.clone(), status.clone(), checks.clone(), add.clone());
        search.connect_search_changed(move |entry| {
            let text = entry.text().trim().to_owned();
            let asked = generation.get() + 1;
            generation.set(asked);
            list.remove_all();
            checks.borrow_mut().clear();
            add.set_sensitive(false);
            if text.is_empty() {
                return;
            }
            status.set_label(&tr("Searching…"));
            let domain = reader.profile().domain.clone();
            let (reader, list, status, checks, add, generation) = (
                reader.clone(),
                list.clone(),
                status.clone(),
                checks.clone(),
                add.clone(),
                generation.clone(),
            );
            glib::spawn_future_local(async move {
                let found = gio::spawn_blocking(move || at::service_accounts(&reader, &text)).await;
                if generation.get() != asked {
                    return;
                }
                let accounts = match found {
                    Ok(Ok(accounts)) => accounts,
                    Ok(Err(e)) => {
                        status.set_label(&errors::membership_message(&e, &domain));
                        return;
                    }
                    Err(_) => return,
                };
                let n: usize = accounts.iter().map(|a| a.spns.len()).sum();
                status.set_label(&if n == 0 {
                    tr("No account with services matches.")
                } else {
                    tr("Tick the services, then Add.")
                });
                for account in accounts {
                    for spn in &account.spns {
                        let check = gtk::CheckButton::new();
                        check.set_valign(gtk::Align::Center);
                        let row = adw::ActionRow::builder()
                            .title(glib::markup_escape_text(spn).as_str())
                            .subtitle(glib::markup_escape_text(&account.name).as_str())
                            .activatable_widget(&check)
                            .build();
                        row.add_prefix(&check);
                        let (checks_for, add_for) = (checks.clone(), add.clone());
                        check.connect_toggled(move |_| {
                            add_for.set_sensitive(
                                checks_for.borrow().iter().any(|(_, c)| c.is_active()),
                            );
                        });
                        checks.borrow_mut().push((spn.clone(), check));
                        list.append(&row);
                    }
                }
            });
        });
    }
    let weak = dialog.downgrade();
    cancel.connect_clicked(move |_| {
        if let Some(d) = weak.upgrade() {
            d.close();
        }
    });
    let weak = dialog.downgrade();
    add.connect_clicked(move |_| {
        let chosen: Vec<String> = checks
            .borrow()
            .iter()
            .filter(|(_, c)| c.is_active())
            .map(|(s, _)| s.clone())
            .collect();
        done(chosen);
        if let Some(d) = weak.upgrade() {
            d.close();
        }
    });
    dialog
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_and_summaries() {
        assert_eq!(offset_text(-4 * 3600), "UTC−04:00");
        assert_eq!(offset_text(5 * 3600 + 1800), "UTC+05:30");
        assert_eq!(hours_summary(&[], 0), "Logon allowed at all hours");
        assert_eq!(
            hours_summary(&[LogonHours::none().encode()], 0),
            "Logon never allowed"
        );
        let mut some = LogonHours::none();
        some.0[0] = true;
        assert_eq!(
            hours_summary(&[some.encode()], -4 * 3600),
            "Logon allowed 1 hour a week (local time, UTC−04:00)"
        );
        assert_eq!(hours_summary(&[vec![0; 3]], 0), "Unreadable value");
        assert!(hours_value(&[], &LogonHours::default()).is_empty());
        assert_eq!(
            hours_value(&[some.encode()], &LogonHours::default()),
            vec![vec![0xFF; 21]]
        );
        assert_eq!(
            DAYS.iter().map(|&d| day_name(d)).next().as_deref(),
            Some("Monday")
        );
        // Monday to Friday, 08:00 to 18:00 in Martinique: 12:00 to 22:00 UTC.
        let office = local_hours("1-5:8-18", -4 * 3600).unwrap();
        assert_eq!(office.allowed(), 50);
        assert!(office.0[24 + 12] && office.0[24 + 21] && !office.0[24 + 22]);
        assert!(local_hours("7:0-24", 0).unwrap().0[..24].iter().all(|&a| a));
        assert!(local_hours("lundi", 0).is_none());
    }
}

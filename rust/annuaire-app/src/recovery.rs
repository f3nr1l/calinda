// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Find BitLocker Recovery Password » (J9.5, ADR 0025), as the tool of ADUC: the first eight
//! characters of the password ID that the recovery screen shows, looked for in the whole domain,
//! on the DC (never the local copy). Each result names its computer; the password is shown only
//! on demand, copied with the clipboard emptied after 30 s.

use std::sync::Arc;

use adw::prelude::*;
use annuaire_core::bitlocker;
use annuaire_core::cache::Source;
use gtk::{gio, glib};

use crate::errors;
use crate::i18n::{fill, tr, tr_n};
use crate::sheet::recovery_group;

/// The dialog, built in code (one entry, one list of groups).
pub fn dialog(source: Arc<dyn Source>) -> adw::Dialog {
    let dialog = adw::Dialog::builder()
        .title(tr("Find BitLocker Recovery Password"))
        .content_width(560)
        .content_height(520)
        .build();
    let toasts = adw::ToastOverlay::new();
    let page = adw::PreferencesPage::new();
    let ask = adw::PreferencesGroup::builder()
        .description(tr(
            "Type the first eight characters of the password ID shown by the BitLocker recovery screen of the computer.",
        ))
        .build();
    let entry = adw::EntryRow::builder()
        .title(tr("Password ID (first eight characters)"))
        .input_hints(gtk::InputHints::NO_SPELLCHECK | gtk::InputHints::UPPERCASE_CHARS)
        .show_apply_button(true)
        .build();
    ask.add(&entry);
    page.add(&ask);
    let results: std::rc::Rc<std::cell::RefCell<Vec<adw::PreferencesGroup>>> =
        std::rc::Rc::default();
    let header = adw::HeaderBar::new();
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    toasts.set_child(Some(&page));
    view.set_content(Some(&toasts));
    dialog.set_child(Some(&view));
    let (weak_page, weak_toasts) = (page.downgrade(), toasts.downgrade());
    entry.connect_apply(move |entry| {
        let (Some(page), Some(toasts)) = (weak_page.upgrade(), weak_toasts.upgrade()) else {
            return;
        };
        for group in results.borrow_mut().drain(..) {
            page.remove(&group);
        }
        let Some(prefix) = bitlocker::prefix(&entry.text()) else {
            entry.add_css_class("error");
            toasts.add_toast(adw::Toast::new(&tr(
                "The password ID begins with eight hexadecimal characters (0 to 9, A to F).",
            )));
            return;
        };
        entry.remove_css_class("error");
        let (source, results, page, toasts) =
            (source.clone(), results.clone(), page.clone(), toasts.clone());
        let base = source.root().unwrap_or_default();
        let domain = source.profile().domain.clone();
        glib::spawn_future_local(async move {
            let found = gio::spawn_blocking(move || {
                bitlocker::search(&source.reader(&base), &base, &prefix)
            })
            .await;
            let Ok(found) = found else { return };
            let groups: Vec<adw::PreferencesGroup> = match found {
                Err(error) => vec![
                    adw::PreferencesGroup::builder()
                        .description(glib::markup_escape_text(
                            &errors::search_problem(&error, &domain).message,
                        ))
                        .build(),
                ],
                Ok(found) if found.is_empty() => vec![
                    adw::PreferencesGroup::builder()
                        .description(tr(
                            "No recovery password of the domain has this ID, or your account cannot see it.",
                        ))
                        .build(),
                ],
                Ok(found) => {
                    let mut groups = vec![
                        adw::PreferencesGroup::builder()
                            .description(fill(
                                &tr_n(
                                    "{n} recovery password found",
                                    "{n} recovery passwords found",
                                    found.len() as u64,
                                ),
                                &[("n", &found.len().to_string())],
                            ))
                            .build(),
                    ];
                    groups.extend(found.iter().map(|r| recovery_group(r, &toasts, true)));
                    groups
                }
            };
            for group in groups {
                page.add(&group);
                results.borrow_mut().push(group);
            }
        });
    });
    dialog
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The libadwaita application and its single window (`annuaire.ui.application`).
//!
//! The shortcuts help (`Ctrl+?`, action `app.shortcuts`) is `shortcuts-dialog.blp`, at the
//! root of the resources. `adw::Application` would open it by itself, but its rows have no
//! accessible name: the action is created before the application starts, which keeps it
//! (`clavier.installer_aide`), and names each row.

use adw::prelude::*;
use gtk::{gio, glib};

use crate::config;
use crate::window::Window;

pub fn run() -> glib::ExitCode {
    let application = adw::Application::builder()
        .application_id(config::APP_ID)
        .resource_base_path(config::RESOURCE_BASE)
        .build();
    let help = gio::SimpleAction::new("shortcuts", None);
    let weak = application.downgrade();
    help.connect_activate(move |_, _| {
        if let Some(application) = weak.upgrade() {
            show_help(&application);
        }
    });
    application.add_action(&help);
    application.set_accels_for_action("app.shortcuts", &["<Control>question"]);
    application.connect_activate(|application| {
        let window = application.active_window().unwrap_or_else(|| {
            let window = Window::new(application);
            crate::trial::arm(&window);
            window.upcast()
        });
        window.present();
    });
    application.run()
}

/// The shortcuts help, each row named for assistive technologies (`montrer_aide`).
fn show_help(application: &adw::Application) {
    let builder =
        gtk::Builder::from_resource(&format!("{}/shortcuts-dialog.ui", config::RESOURCE_BASE));
    let Some(help) = builder.object::<adw::ShortcutsDialog>("shortcuts_dialog") else {
        return;
    };
    help.present(application.active_window().as_ref());
    crate::a11y::name_shortcut_rows(&help); // the rows exist only once presented
}

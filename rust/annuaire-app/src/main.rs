// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Calinda, formerly Annuaire (plan, step R4; ADR 0019, 0022): the screens of the Python application 1.0, built from
//! the same Blueprint files with English as the source language, on the Rust core
//! (`annuaire-core`).

mod a11y;
mod account_views;
mod accounts;
mod application;
mod attribute_views;
mod attributes;
mod catalog;
mod codec_texts;
mod config;
mod countries;
mod delegation;
mod dialogs;
mod dns;
mod dns_health;
mod dns_record;
mod dns_views;
mod errors;
mod feed;
mod gpo;
mod gpo_dialogs;
mod gpo_editor;
mod gpo_editor_views;
mod gpo_security;
mod gpo_security_views;
mod gpo_views;
mod health_views;
mod history;
mod home;
mod i18n;
mod inputs;
mod members;
mod objects;
mod policy;
mod policy_views;
mod preference_views;
mod preferences;
mod preview_views;
mod pso;
mod pso_views;
mod scope;
mod search;
mod security;
mod security_views;
mod settings;
mod sheet;
mod sheet_views;
mod template_views;
mod templates;
mod texts;
mod trial;
mod views;
mod window;
mod writes;

use gtk::glib;

fn main() -> glib::ExitCode {
    i18n::init();
    if let Err(message) = config::register_resources() {
        eprintln!("calinda: {message}");
        return glib::ExitCode::FAILURE;
    }
    if !config::schema_available() {
        eprintln!(
            "calinda: settings schema {} not found: install it, or run through \"meson devenv\"",
            config::SCHEMA_ID
        );
        return glib::ExitCode::FAILURE;
    }
    application::run()
}

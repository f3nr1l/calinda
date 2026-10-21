// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Names and paths of the application. meson passes the installation paths at compile time
//! (`ANNUAIRE_PKGDATADIR`, `ANNUAIRE_LOCALEDIR`); the environment overrides them for trials
//! (`ANNUAIRE_APP_RESOURCE`, `ANNUAIRE_APP_LOCALEDIR`, set by
//! `meson devenv`), as `annuaire.resources` and `annuaire.traduction` did for the Python
//! application.

use std::path::PathBuf;

use gtk::gio;

pub const APP_ID: &str = "io.github.f3nr1l.Calinda";
/// The settings schema: the keys of the application under its former name (ADR 0022).
pub const SCHEMA_ID: &str = "io.github.f3nr1l.Calinda";
/// Base of the resource paths.
pub const RESOURCE_BASE: &str = "/io/github/f3nr1l/Calinda";
pub const GETTEXT_DOMAIN: &str = "calinda";
const RESOURCE_NAME: &str = "calinda.gresource";

fn from_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

pub fn locale_dir() -> PathBuf {
    from_env("ANNUAIRE_APP_LOCALEDIR")
        .or_else(|| option_env!("ANNUAIRE_LOCALEDIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/usr/share/locale"))
}

fn resource_path() -> Option<PathBuf> {
    from_env("ANNUAIRE_APP_RESOURCE").or_else(|| {
        option_env!("ANNUAIRE_PKGDATADIR").map(|dir| PathBuf::from(dir).join(RESOURCE_NAME))
    })
}

/// Loads and registers the compiled interfaces (Blueprint) and icons.
pub fn register_resources() -> Result<(), String> {
    let path = resource_path().ok_or_else(|| {
        format!("no {RESOURCE_NAME}: build with meson, or set ANNUAIRE_APP_RESOURCE")
    })?;
    let resource = gio::Resource::load(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    gio::resources_register(&resource);
    Ok(())
}

/// True if the settings schema is installed or given by `GSETTINGS_SCHEMA_DIR` (`meson
/// devenv`), as `annuaire.ui.reglages.ouvrir_reglages` requires.
pub fn schema_available() -> bool {
    gio::SettingsSchemaSource::default().is_some_and(|s| s.lookup(SCHEMA_ID, true).is_some())
}

/// The settings of the application (schema checked by `main`).
pub fn settings() -> gio::Settings {
    gio::Settings::new(SCHEMA_ID)
}

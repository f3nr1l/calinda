// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Domain profiles in GSettings (key `profils`, type `aa{sv}`), as `annuaire.ui.profils`:
//! one dictionary per profile, the serialized form of `Profile`. An unreadable profile is
//! skipped when reading (and kept as is until the next save).

use std::collections::BTreeMap;

use annuaire_core::profile::{Field, Profile};
use gtk::prelude::*;
use gtk::{gio, glib};

const KEY: &str = "profils";

/// The profile store of the application settings.
#[derive(Debug, Clone)]
pub struct ProfileStore {
    settings: gio::Settings,
}

fn fields_of(dict: &glib::Variant) -> BTreeMap<String, Field> {
    let mut fields = BTreeMap::new();
    for entry in dict.iter() {
        let key = entry.child_value(0);
        let Some(key) = key.str() else { continue };
        let Some(value) = entry.child_value(1).as_variant() else {
            continue;
        };
        let field = if let Some(text) = value.str() {
            Field::Text(text.to_owned())
        } else if let Some(flag) = value.get::<bool>() {
            Field::Bool(flag)
        } else {
            continue; // neither string nor boolean: as an unknown key
        };
        fields.insert(key.to_owned(), field);
    }
    fields
}

fn dict_of(fields: &BTreeMap<String, Field>) -> glib::Variant {
    let dict = glib::VariantDict::new(None);
    for (key, field) in fields {
        match field {
            Field::Text(text) => dict.insert_value(key, &text.to_variant()),
            Field::Bool(flag) => dict.insert_value(key, &flag.to_variant()),
        }
    }
    dict.end()
}

impl ProfileStore {
    pub fn new(settings: gio::Settings) -> Self {
        Self { settings }
    }

    fn read(&self) -> Vec<glib::Variant> {
        self.settings.value(KEY).iter().collect()
    }

    fn write(&self, dicts: Vec<glib::Variant>) {
        let value = glib::Variant::array_from_iter_with_type(glib::VariantTy::VARDICT, dicts);
        if let Err(e) = self.settings.set_value(KEY, &value) {
            glib::g_warning!("calinda", "profiles not saved: {e}");
        }
    }

    pub fn list(&self) -> Vec<Profile> {
        self.read()
            .iter()
            .filter_map(|dict| Profile::from_fields(&fields_of(dict)).ok())
            .collect()
    }

    /// Adds the profile, or replaces the one of the same domain.
    pub fn save(&self, profile: &Profile) {
        let mut dicts = self.others(&profile.domain);
        dicts.push(dict_of(&profile.to_fields()));
        self.write(dicts);
    }

    pub fn remove(&self, domain: &str) {
        self.write(self.others(domain));
    }

    fn others(&self, domain: &str) -> Vec<glib::Variant> {
        self.read()
            .into_iter()
            .filter(|dict| fields_of(dict).get("domaine") != Some(&Field::Text(domain.to_owned())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variant_round_trip() {
        let mut p = Profile::new("lab.test");
        p.preferred_dc = Some("dc1.lab.test".into());
        p.read_only = false;
        let dict = dict_of(&p.to_fields());
        assert_eq!(dict.type_(), glib::VariantTy::VARDICT);
        assert_eq!(Profile::from_fields(&fields_of(&dict)), Ok(p));
        // As the Python application writes it: `{"domaine": <"x">, "lecture-seule": <true>}`.
        let python = glib::Variant::parse(
            Some(glib::VariantTy::VARDICT),
            "{'domaine': <'win.test'>, 'lecture-seule': <true>, 'futur': <int32 3>}",
        )
        .unwrap();
        assert_eq!(
            Profile::from_fields(&fields_of(&python)),
            Ok(Profile::new("win.test"))
        );
    }
}

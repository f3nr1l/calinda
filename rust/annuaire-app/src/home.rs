// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Home screen (J2.2, `annuaire.ui.accueil`): domain profiles and Kerberos ticket of the
//! session. Structure in `accueil.blp` and `ligne-profil.blp`. The gestures go through the
//! actions of the window (`win.ouvrir-profil`, `win.modifier-profil`…), with the domain as
//! parameter.

use std::collections::BTreeMap;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::kerberos::{self, Ticket};
use annuaire_core::profile::Profile;
use gtk::{gio, glib};

use crate::texts;

mod row {
    use adw::subclass::prelude::*;
    use gtk::glib;

    #[derive(Debug, Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/ligne-profil.ui")]
    pub struct ProfileRow {
        #[template_child]
        pub waiting: TemplateChild<gtk::Spinner>,
        #[template_child]
        pub read_only_icon: TemplateChild<gtk::Image>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ProfileRow {
        const NAME: &'static str = "AnnuaireLigneProfil";
        type Type = super::ProfileRow;
        type ParentType = adw::ActionRow;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ProfileRow {}
    impl WidgetImpl for ProfileRow {}
    impl ListBoxRowImpl for ProfileRow {}
    impl PreferencesRowImpl for ProfileRow {}
    impl ActionRowImpl for ProfileRow {}
}

glib::wrapper! {
    /// A domain profile; activating it opens the domain.
    pub struct ProfileRow(ObjectSubclass<row::ProfileRow>)
        @extends adw::ActionRow, adw::PreferencesRow, gtk::ListBoxRow, gtk::Widget,
        @implements gtk::Accessible, gtk::Actionable, gtk::Buildable, gtk::ConstraintTarget;
}

impl ProfileRow {
    pub fn new(profile: &Profile) -> Self {
        let row: Self = glib::Object::new();
        let target = profile.domain.to_variant();
        row.set_action_target_value(Some(&target));
        row.set_title(&profile.domain);
        row.set_subtitle(&texts::describe_profile(profile));
        let icon = &row.imp().read_only_icon;
        icon.set_visible(profile.read_only);
        icon.set_tooltip_text(Some(&texts::access_label(profile)));
        // Actions of the menu of the row, relayed to the window with the domain.
        let group = gio::SimpleActionGroup::new();
        for (name, action) in [
            ("modifier", "win.modifier-profil"),
            ("ticket", "win.ticket-profil"),
            ("effacer", "win.effacer-copie"),
            ("supprimer", "win.supprimer-profil"),
        ] {
            let relay = gio::SimpleAction::new(name, None);
            let (weak, target) = (row.downgrade(), target.clone());
            relay.connect_activate(move |_, _| {
                if let Some(row) = weak.upgrade() {
                    let _ = row.activate_action(action, Some(&target));
                }
            });
            group.add_action(&relay);
        }
        row.insert_action_group("profil", Some(&group));
        crate::a11y::name_menus(&row);
        row
    }

    pub fn wait(&self, active: bool) {
        let spinner = &self.imp().waiting;
        spinner.set_visible(active);
        spinner.set_spinning(active);
        self.set_sensitive(!active);
    }
}

mod imp {
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    use adw::subclass::prelude::*;
    use gtk::glib;

    #[derive(Debug, Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/accueil.ui")]
    pub struct Home {
        #[template_child]
        pub profiles_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub ticket_row: TemplateChild<adw::ActionRow>,
        pub rows: RefCell<BTreeMap<String, super::ProfileRow>>,
        pub ticket: RefCell<Option<annuaire_core::kerberos::Ticket>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Home {
        const NAME: &'static str = "AnnuaireAccueil";
        type Type = super::Home;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for Home {}
    impl WidgetImpl for Home {}
    impl BinImpl for Home {}
}

glib::wrapper! {
    /// The list of the profiles and the state of the ticket of the session.
    pub struct Home(ObjectSubclass<imp::Home>)
        @extends adw::Bin, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

impl Home {
    pub fn show_profiles(&self, profiles: &[Profile]) {
        let imp = self.imp();
        // Not `remove_all()`: the placeholder must stay.
        for row in imp.rows.borrow().values() {
            imp.profiles_list.remove(row);
        }
        let mut rows = BTreeMap::new();
        for profile in profiles {
            rows.insert(profile.domain.clone(), ProfileRow::new(profile));
        }
        for row in rows.values() {
            imp.profiles_list.append(row);
        }
        *imp.rows.borrow_mut() = rows;
    }

    /// Focus on the profile `domain` (the first one by default), back on the home screen.
    pub fn take_focus(&self, domain: Option<&str>) {
        let rows = self.imp().rows.borrow();
        let row = domain
            .and_then(|d| rows.get(d))
            .or_else(|| rows.values().next());
        if let Some(row) = row {
            row.grab_focus();
        }
    }

    pub fn wait(&self, domain: &str, active: bool) {
        if let Some(row) = self.imp().rows.borrow().get(domain) {
            row.wait(active);
        }
    }

    pub fn ticket(&self) -> Option<Ticket> {
        self.imp().ticket.borrow().clone()
    }

    /// Reads the Kerberos cache again (off the interface thread).
    pub fn refresh_ticket(&self) {
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let ticket = gio::spawn_blocking(|| kerberos::read_ticket(None))
                .await
                .unwrap_or(None); // unreadable cache: same as an empty one
            if let Some(home) = weak.upgrade() {
                let imp = home.imp();
                imp.ticket_row
                    .set_subtitle(&texts::describe_ticket(ticket.as_ref()));
                *imp.ticket.borrow_mut() = ticket;
            }
        });
    }
}

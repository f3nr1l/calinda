// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Actions on the accounts in the window (J2.6, `annuaire.ui.actions`): the `win.*` actions of
//! the menus « New » and « Actions » and of the context menu of the table, the shortcuts local
//! to the table (Delete, F2), the drag and drop of rows on a node of the tree (move). An action
//! on a selection first reads the state of the objects on the write connection (off the
//! interface thread), builds one changeset and gives it to `writes::propose`: preview, then
//! all or nothing.

use std::rc::Rc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::actions::{self, ActionError, ReadObject};
use annuaire_core::changes::{Changeset, parent_dn};
use annuaire_core::model::Kind;
use gtk::{gdk, gio, glib};

use super::Window;
use crate::account_views as av;
use crate::accounts::{
    ComputerDialog, ContactDialog, GroupDialog, MoveDialog, OuDialog, PasswordDialog, RenameDialog,
    UserDialog,
};
use crate::errors;
use crate::i18n::tr;
use crate::objects::{Node, Row};
use crate::views::RowView;
use crate::writes::{self, Options};

/// Actions that act on the selection of the table.
const ON_SELECTION: [&str; 11] = [
    "modifier-en-masse",
    "activer",
    "desactiver",
    "deverrouiller",
    "mot-de-passe",
    "reinitialiser-compte",
    "deplacer",
    "renommer",
    "supprimer",
    "proteger",
    "deproteger",
];

const CREATION: [&str; 7] = [
    "nouvel-utilisateur",
    "nouveau-groupe",
    "nouvelle-ou",
    "nouvel-ordinateur",
    "nouveau-contact",
    "importer",
    "exporter",
];

/// What builds the changeset from the objects read.
type Build = Box<dyn FnOnce(&Window, Vec<ReadObject>) -> Option<Result<Changeset, ActionError>>>;

impl Window {
    /// Once, at the construction of the window (`installer`).
    pub(super) fn setup_accounts(&self) {
        type Handler = fn(&Window);
        let handlers: [(&str, Handler); 18] = [
            ("importer", Window::import_csv),
            ("exporter", Window::export_csv),
            ("modifier-en-masse", Window::change_in_bulk),
            ("nouvel-utilisateur", Window::new_user),
            ("nouveau-groupe", Window::new_group),
            ("nouvelle-ou", Window::new_ou),
            ("nouvel-ordinateur", Window::new_computer),
            ("nouveau-contact", Window::new_contact),
            ("reinitialiser-compte", Window::reset_computers),
            ("activer", |w| w.enable(true)),
            ("desactiver", |w| w.enable(false)),
            ("deverrouiller", Window::unlock),
            ("mot-de-passe", Window::password),
            ("deplacer", Window::move_selection),
            ("renommer", Window::rename_selection),
            ("supprimer", Window::delete_selection),
            ("proteger", |w| w.protect(None)),
            ("deproteger", Window::unprotect),
        ];
        for (name, handler) in handlers {
            let action = gio::SimpleAction::new(name, None);
            let weak = self.downgrade();
            action.connect_activate(move |_, _| {
                if let Some(window) = weak.upgrade() {
                    handler(&window);
                }
            });
            self.add_action(&action);
        }
        let imp = self.imp();
        let weak = self.downgrade();
        imp.selection.connect_selection_changed(move |_, _, _| {
            if let Some(window) = weak.upgrade() {
                window.update_actions();
            }
        });
        let weak = self.downgrade();
        imp.selection.connect_items_changed(move |_, _, _, _| {
            if let Some(window) = weak.upgrade() {
                window.update_actions();
            }
        });
        self.context_menu();
        self.table_shortcuts();
        self.drag_and_drop();
        self.update_actions();
    }

    fn selected_rows(&self) -> Vec<RowView> {
        let selection = &self.imp().selection;
        let set = selection.selection();
        (0..u32::try_from(set.size()).unwrap_or(0))
            .filter_map(|i| selection.item(set.nth(i)).and_downcast::<Row>())
            .map(|r| r.view().clone())
            .collect()
    }

    /// The container of the creations: the node chosen in the tree, or the root.
    fn container(&self) -> Option<String> {
        let imp = self.imp();
        imp.tree_selection
            .selected_item()
            .and_downcast::<gtk::TreeListRow>()
            .and_then(|r| r.item().and_downcast::<Node>())
            .map(|n| n.view().dn.clone())
            .or_else(|| self.source().and_then(|s| s.root()))
    }

    /// Enabled actions after the selection (`actualiser_etat`).
    pub(super) fn update_actions(&self) {
        let writable = self.source().is_some();
        let rows = if writable {
            self.selected_rows()
        } else {
            Vec::new()
        };
        let kinds: Vec<String> = rows.iter().map(|r| r.kind.clone()).collect();
        let accounts = av::accounts_only(&kinds);
        let allowed = |name: &str| match name {
            "activer" | "desactiver" => accounts,
            "deverrouiller" => !kinds.is_empty() && kinds.iter().all(|k| k == Kind::User.name()),
            "mot-de-passe" => rows.len() == 1 && accounts,
            "reinitialiser-compte" => av::computers_only(&kinds),
            "deplacer" | "supprimer" | "modifier-en-masse" => !rows.is_empty(),
            "renommer" => rows.len() == 1,
            "proteger" | "deproteger" => av::can_protect(&kinds),
            _ => false,
        };
        for name in ON_SELECTION {
            if let Some(action) = self.lookup_action(name).and_downcast::<gio::SimpleAction>() {
                action.set_enabled(allowed(name));
            }
        }
        for name in CREATION.iter().chain(&["historique"]) {
            if let Some(action) = self.lookup_action(name).and_downcast::<gio::SimpleAction>() {
                action.set_enabled(writable);
            }
        }
    }

    // --- Menus, shortcuts, drag and drop ------------------------------------------------

    fn context_menu(&self) {
        let imp = self.imp();
        let menu = gtk::PopoverMenu::from_model(Some(&*imp.actions_menu));
        menu.set_parent(&*imp.table);
        menu.set_has_arrow(false);
        crate::a11y::name_popover(&menu);
        let click = gtk::GestureClick::new();
        click.set_button(gdk::BUTTON_SECONDARY);
        let popover = menu.clone();
        click.connect_pressed(move |_, _, x, y| {
            #[allow(clippy::cast_possible_truncation)] // pixels
            popover.set_pointing_to(Some(&gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
            popover.popup();
        });
        imp.table.add_controller(click);
        *imp.context_menu.borrow_mut() = Some(menu);
    }

    fn table_shortcuts(&self) {
        let imp = self.imp();
        let controller = gtk::ShortcutController::new();
        controller.set_scope(gtk::ShortcutScope::Local);
        for (key, action) in [("Delete", "win.supprimer"), ("F2", "win.renommer")] {
            controller.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(key),
                Some(gtk::NamedAction::new(action)),
            ));
        }
        for key in ["<Shift>F10", "Menu"] {
            let weak = self.downgrade();
            controller.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(key),
                Some(gtk::CallbackAction::new(move |_, _| {
                    if let Some(menu) = weak
                        .upgrade()
                        .and_then(|w| w.imp().context_menu.borrow().clone())
                    {
                        menu.popup();
                    }
                    glib::Propagation::Stop
                })),
            ));
        }
        imp.table.add_controller(controller);
    }

    fn drag_and_drop(&self) {
        let imp = self.imp();
        let source = gtk::DragSource::new();
        source.set_actions(gdk::DragAction::MOVE);
        let weak = self.downgrade();
        source.connect_prepare(move |_, _, _| {
            let window = weak.upgrade()?;
            let dns: Vec<String> = window.selected_rows().into_iter().map(|r| r.dn).collect();
            if dns.is_empty() || window.source().is_none() {
                return None;
            }
            Some(gdk::ContentProvider::for_value(&dns.join("\n").to_value()))
        });
        imp.table.add_controller(source);
        let target = gtk::DropTarget::new(glib::Type::STRING, gdk::DragAction::MOVE);
        let weak = self.downgrade();
        target.connect_drop(move |_, value, x, y| {
            let (Some(window), Ok(text)) = (weak.upgrade(), value.get::<String>()) else {
                return false;
            };
            let Some(target) = window.node_at(x, y) else {
                return false;
            };
            // After the end of the drag and drop.
            glib::idle_add_local_once(move || {
                let dns: Vec<String> = text.split('\n').map(str::to_owned).collect();
                window.read_then(
                    dns,
                    false,
                    Box::new(move |_, objects| Some(actions::move_to(&objects, &target))),
                );
            });
            true
        });
        imp.tree.add_controller(target);
    }

    fn node_at(&self, x: f64, y: f64) -> Option<String> {
        let mut widget = self.imp().tree.pick(x, y, gtk::PickFlags::DEFAULT);
        while let Some(w) = widget {
            if let Some(expander) = w.downcast_ref::<gtk::TreeExpander>() {
                return expander
                    .item()
                    .and_downcast::<Node>()
                    .map(|n| n.view().dn.clone());
            }
            widget = w.parent();
        }
        None
    }

    // --- Reading then proposal -----------------------------------------------------------

    /// Reads the objects on the write connection, builds the changeset and proposes it
    /// (`_lire_puis`).
    fn read_then(&self, dns: Vec<String>, descriptors: bool, build: Build) {
        let Some(context) = self.write_context() else {
            return;
        };
        if dns.is_empty() {
            return;
        }
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let connection = context.connection.clone();
            let read = gio::spawn_blocking(move || {
                if descriptors {
                    actions::read_descriptors(&connection, &dns)
                } else {
                    actions::read_objects(&connection, &dns, &actions::STATE_ATTRIBUTES)
                }
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            let objects = match read {
                Ok(Ok(objects)) => objects,
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &context.profile.domain);
                    writes::show_error(
                        &window,
                        &tr("Action not possible"),
                        &problem.message,
                        &problem.detail,
                    );
                    return;
                }
                Err(_) => return,
            };
            match build(&window, objects) {
                None => {}
                Some(Ok(changeset)) => {
                    writes::propose(&window, changeset, Options::default());
                }
                Some(Err(error)) => writes::show_error(
                    &window,
                    &tr("Action not possible"),
                    &av::action_error(&error),
                    "",
                ),
            }
        });
    }

    fn selected_dns(&self) -> Vec<String> {
        self.selected_rows().into_iter().map(|r| r.dn).collect()
    }

    fn nothing_to_do(&self, text: &str) {
        writes::show_error(self, &tr("Nothing to do"), text, "");
    }

    // --- Import, export, changes in bulk (J9.8, J9.9) -----------------------------------------

    /// The DNs of every row of the table, in its order.
    pub(crate) fn table_dns(&self) -> Vec<String> {
        let store = &self.imp().content_store;
        (0..store.n_items())
            .filter_map(|i| store.item(i).and_downcast::<Row>())
            .map(|r| r.view().dn.clone())
            .collect()
    }

    /// Every row of the table selected (trials).
    pub(crate) fn trial_select_all(&self) {
        self.imp().selection.select_all();
    }

    pub(crate) fn trial_selected_dns(&self) -> Vec<String> {
        self.selected_dns()
    }

    fn import_csv(&self) {
        if let Some(parent) = self.container() {
            crate::bulk::ImportDialog::new(&parent).present(Some(self));
        }
    }

    fn export_csv(&self) {
        let all = self.table_dns();
        if all.is_empty() {
            self.nothing_to_do(&tr("The list is empty."));
            return;
        }
        crate::bulk::ExportDialog::new(all, self.selected_dns()).present(Some(self));
    }

    fn change_in_bulk(&self) {
        let rows = self.selected_rows();
        let group = match rows.as_slice() {
            [one] if one.kind == Kind::Group.name() => Some(one.dn.clone()),
            _ => None,
        };
        let dns = rows.into_iter().map(|r| r.dn).collect();
        crate::bulk::ChangeDialog::new(dns, group).present(Some(self));
    }

    // --- Creation ------------------------------------------------------------------------------

    fn new_user(&self) {
        let (Some(parent), Some(context)) = (self.container(), self.write_context()) else {
            return;
        };
        UserDialog::new(&parent, &context.profile.domain).present(Some(self));
    }

    fn new_group(&self) {
        if let Some(parent) = self.container() {
            GroupDialog::new(&parent).present(Some(self));
        }
    }

    fn new_ou(&self) {
        let Some(parent) = self.container() else {
            return;
        };
        let weak = self.downgrade();
        let protect: Rc<dyn Fn(&str)> = Rc::new(move |dn: &str| {
            if let Some(window) = weak.upgrade() {
                window.protect(Some(dn.to_owned()));
            }
        });
        OuDialog::new(&parent, protect).present(Some(self));
    }

    fn new_computer(&self) {
        let (Some(parent), Some(source)) = (self.container(), self.source()) else {
            return;
        };
        let weak = self.downgrade();
        let allow: crate::accounts::AllowJoin = Rc::new(move |dn: &str, sid| {
            if let Some(window) = weak.upgrade() {
                window.read_then(
                    vec![dn.to_owned()],
                    true,
                    Box::new(move |_, objects| {
                        objects
                            .first()
                            .map(|o| annuaire_core::computers::allow_join(o, &sid))
                    }),
                );
            }
        });
        ComputerDialog::new(&parent, source, allow).present(Some(self));
    }

    fn new_contact(&self) {
        if let Some(parent) = self.container() {
            ContactDialog::new(&parent).present(Some(self));
        }
    }

    /// « Reset Account » of ADUC: the default password of each computer chosen, in one
    /// changeset; a random one when the DC would refuse it (its policy), said by the preview.
    fn reset_computers(&self) {
        let Some(context) = self.write_context() else {
            return;
        };
        let dns = self.selected_dns();
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let rule =
                gio::spawn_blocking(move || annuaire_core::computers::read_rule(&connection)).await;
            let Some(window) = weak.upgrade() else { return };
            let rule = match rule {
                Ok(Ok(rule)) => rule,
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &context.profile.domain);
                    writes::show_error(
                        &window,
                        &tr("Action not possible"),
                        &problem.message,
                        &problem.detail,
                    );
                    return;
                }
                Err(_) => return,
            };
            window.read_then(
                dns,
                false,
                Box::new(move |_, objects| {
                    let mut operations = Vec::new();
                    let mut random = false;
                    for object in &objects {
                        match annuaire_core::computers::reset_computer(object, &rule) {
                            Ok((c, default)) => {
                                random |= !default;
                                operations.extend(c.operations);
                            }
                            Err(e) => return Some(Err(e)),
                        }
                    }
                    let mut remarks = vec![tr(
                        "Each computer loses its secure channel with the domain until it is joined again.",
                    )];
                    if random {
                        remarks.push(tr(
                            "The domain controller would refuse the default password (the name in lower case): its password policy applies to computer accounts. A random password is set instead; the computer must be joined again with an account allowed to join it.",
                        ));
                    }
                    Some(Ok(Changeset {
                        operations,
                        remarks,
                    }))
                }),
            );
        });
    }

    // --- States --------------------------------------------------------------------------------

    fn enable(&self, active: bool) {
        self.read_then(
            self.selected_dns(),
            false,
            Box::new(move |window, objects| {
                let built = actions::enable(&objects, active);
                if built.as_ref().is_ok_and(|c| c.operations.is_empty()) {
                    window.nothing_to_do(&if active {
                        tr("The selected accounts are already enabled.")
                    } else {
                        tr("The selected accounts are already disabled.")
                    });
                    return None;
                }
                Some(built)
            }),
        );
    }

    fn unlock(&self) {
        self.read_then(
            self.selected_dns(),
            false,
            Box::new(|window, objects| {
                let built = actions::unlock(&objects);
                if built.as_ref().is_ok_and(|c| c.operations.is_empty()) {
                    window.nothing_to_do(&tr("None of the selected accounts is locked out."));
                    return None;
                }
                Some(built)
            }),
        );
    }

    fn password(&self) {
        let rows = self.selected_rows();
        let [row] = rows.as_slice() else { return };
        let name = row.name.clone();
        self.read_then(
            vec![row.dn.clone()],
            false,
            Box::new(move |window, objects| {
                if let Some(object) = objects.into_iter().next() {
                    PasswordDialog::new(object, &name).present(Some(window));
                }
                None
            }),
        );
    }

    // --- Move, rename, delete ---------------------------------------------------------------------

    fn move_selection(&self) {
        let Some(source) = self.source() else { return };
        self.read_then(
            self.selected_dns(),
            false,
            Box::new(move |window, objects| {
                if !objects.is_empty() {
                    MoveDialog::new(source, objects).present(Some(window));
                }
                None
            }),
        );
    }

    fn rename_selection(&self) {
        let rows = self.selected_rows();
        let [row] = rows.as_slice() else { return };
        let account = [Kind::User.name(), Kind::Computer.name(), Kind::Group.name()]
            .contains(&row.kind.as_str());
        self.read_then(
            vec![row.dn.clone()],
            false,
            Box::new(move |window, objects| {
                if let Some(object) = objects.into_iter().next() {
                    RenameDialog::new(object, account).present(Some(window));
                }
                None
            }),
        );
    }

    fn delete_selection(&self) {
        let rows = self.selected_rows();
        if rows.is_empty() || self.write_context().is_none() {
            return;
        }
        let names: Vec<String> = rows.iter().map(|r| r.name.clone()).collect();
        let (title, body, expected) = av::delete_confirmation(&names);
        let alert = adw::AlertDialog::new(Some(&title), Some(&body));
        let entry = gtk::Entry::new();
        entry.set_activates_default(true);
        alert.set_extra_child(Some(&entry));
        alert.add_response("annuler", &tr("Cancel"));
        alert.add_response("supprimer", &tr("Delete"));
        alert.set_response_appearance("supprimer", adw::ResponseAppearance::Destructive);
        alert.set_response_enabled("supprimer", false);
        alert.set_default_response(Some("annuler"));
        alert.set_close_response("annuler");
        let watched = alert.clone();
        entry.connect_changed(move |e| {
            watched.set_response_enabled("supprimer", e.text().trim() == expected);
        });
        let (weak, dns) = (
            self.downgrade(),
            rows.into_iter().map(|r| r.dn).collect::<Vec<_>>(),
        );
        alert.connect_response(None, move |_, response| {
            if response == "supprimer"
                && let Some(window) = weak.upgrade()
            {
                window.read_then(
                    dns.clone(),
                    false,
                    Box::new(|_, objects| Some(actions::delete(&objects))),
                );
            }
        });
        alert.present(Some(self));
        entry.grab_focus();
    }

    // --- Protection of an OU ---------------------------------------------------------------------

    fn protect(&self, dn: Option<String>) {
        let Some(dn) = dn.or_else(|| self.selected_dns().into_iter().next()) else {
            return;
        };
        let parent = parent_dn(&dn).unwrap_or_default();
        self.read_then(
            vec![dn, parent],
            true,
            Box::new(|window, objects| {
                let [ou, parent] = objects.as_slice() else {
                    return Some(Err(ActionError::Change(tr(
                        "The OU or its parent cannot be found.",
                    ))));
                };
                let built = actions::protect(ou, parent);
                if built.as_ref().is_ok_and(|c| c.operations.is_empty()) {
                    window.nothing_to_do(&tr("The OU is already protected."));
                    return None;
                }
                Some(built)
            }),
        );
    }

    fn unprotect(&self) {
        let dns: Vec<String> = self.selected_dns().into_iter().take(1).collect();
        self.read_then(
            dns,
            true,
            Box::new(|window, objects| {
                let ou = objects.first()?;
                let built = actions::unprotect(ou);
                if built.as_ref().is_ok_and(|c| c.operations.is_empty()) {
                    window.nothing_to_do(&tr("The OU is not protected."));
                    return None;
                }
                Some(built)
            }),
        );
    }
}

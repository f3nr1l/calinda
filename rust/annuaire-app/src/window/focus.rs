// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The focus is not lost from the keyboard (`clavier._Focus`, J2.9):
//!
//! - When a dialog opened from the table or the tree closes (sheet, preview), the focus goes
//!   back there, even if the row that had it disappeared meanwhile (table read again after a
//!   write): GTK would give it to the first button of the window otherwise.
//! - Lost without a dialog (list emptied to be read again), it goes to the table as soon as
//!   it has rows, or to the tree if the table stays empty.

use adw::prelude::*;
use adw::subclass::prelude::*;
use gtk::glib;

use super::Window;

impl Window {
    pub(super) fn setup_focus(&self) {
        self.connect_notify_local(Some("focus-widget"), |window, _| window.focus_changed());
        self.connect_notify_local(Some("visible-dialog"), |window, _| {
            window.dialog_changed();
        });
        let weak = self.downgrade();
        self.imp()
            .content_store
            .connect_items_changed(move |_, _, _, _| {
                if let Some(window) = weak.upgrade() {
                    window.focus_lost();
                }
            });
    }

    /// The zone (table, tree) that holds `widget`, if any.
    fn zone_of(&self, widget: Option<gtk::Widget>) -> Option<gtk::Widget> {
        let imp = self.imp();
        let table = imp.table.upcast_ref::<gtk::Widget>();
        let tree = imp.tree.upcast_ref::<gtk::Widget>();
        let mut widget = widget;
        while let Some(w) = widget {
            if &w == table || &w == tree {
                return Some(w);
            }
            widget = w.parent();
        }
        None
    }

    fn focus_changed(&self) {
        let focus = GtkWindowExt::focus(self);
        if focus.is_none() {
            let weak = self.downgrade();
            glib::idle_add_local_once(move || {
                if let Some(window) = weak.upgrade() {
                    window.focus_lost();
                }
            });
        } else if self.visible_dialog().is_none() {
            *self.imp().focus_last.borrow_mut() = self.zone_of(focus);
        }
    }

    fn dialog_changed(&self) {
        let imp = self.imp();
        if self.visible_dialog().is_some() {
            // Opened from the window, not from another dialog: at the opening, the focus is
            // already none, hence the last zone known.
            if imp.focus_zone.borrow().is_none() {
                let last = imp.focus_last.borrow().clone();
                *imp.focus_zone.borrow_mut() = last;
            }
            return;
        }
        let Some(zone) = imp.focus_zone.take() else {
            return;
        };
        let weak = self.downgrade();
        glib::idle_add_local_once(move || {
            if let Some(window) = weak.upgrade() {
                window.come_back(&zone);
            }
        });
    }

    fn come_back(&self, zone: &gtk::Widget) {
        let imp = self.imp();
        let already = self.visible_dialog().is_some()
            || self.zone_of(GtkWindowExt::focus(self)).as_ref() == Some(zone);
        let empty =
            zone == imp.table.upcast_ref::<gtk::Widget>() && imp.content_store.n_items() == 0;
        if !already && !empty {
            zone.grab_focus();
        }
    }

    fn focus_lost(&self) {
        let imp = self.imp();
        if GtkWindowExt::focus(self).is_some() || self.visible_dialog().is_some() {
            return;
        }
        if imp.stack.visible_child_name().as_deref() != Some("domaine") {
            return;
        }
        if imp.content_store.n_items() > 0 {
            imp.table.grab_focus();
        } else if imp.content_feed.borrow().is_none() {
            imp.tree.grab_focus();
        }
    }
}

// --- Trials (`trial`) ----------------------------------------------------------------

impl Window {
    /// Gives the focus to the table and opens the sheet of its first row (trials).
    pub fn trial_open_from_table(&self) -> bool {
        let imp = self.imp();
        if imp.content_store.n_items() == 0 {
            return false;
        }
        imp.table.grab_focus();
        self.row_activated(0);
        true
    }

    /// Reads the table again (F5), as after a write (trials).
    pub fn trial_refresh(&self) {
        self.refresh();
    }

    /// Where the focus is: `tableau`, `arbre`, another widget type, or `aucun` (trials).
    pub fn trial_focus(&self) -> String {
        let focus = GtkWindowExt::focus(self);
        let imp = self.imp();
        match self.zone_of(focus.clone()) {
            Some(z) if &z == imp.table.upcast_ref::<gtk::Widget>() => "tableau".into(),
            Some(_) => "arbre".into(),
            None => focus.map_or_else(|| "aucun".into(), |f| f.type_().name().to_owned()),
        }
    }
}

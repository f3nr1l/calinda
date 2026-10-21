// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Accessible names of menu entries (`clavier._nommer_menu`): GTK 4.22 labels them by their
//! label (relation « labelled by »), but the name of that label stays empty in AT-SPI, so the
//! entry has no name. The relation is replaced by the text, each time a menu is shown (its
//! sections can change). The Python application does it from an emission hook on every
//! `GtkPopoverMenu`; glib-rs has no safe emission hook, so the menu buttons of a widget tree
//! are watched instead, when the tree is built.

use gtk::prelude::*;

pub fn descendants(widget: &gtk::Widget, out: &mut Vec<gtk::Widget>) {
    let mut child = widget.first_child();
    while let Some(c) = child {
        out.push(c.clone());
        descendants(&c, out);
        child = c.next_sibling();
    }
}

fn name_entries(popover: &gtk::Popover) {
    let mut widgets = Vec::new();
    descendants(popover.upcast_ref(), &mut widgets);
    for widget in widgets
        .iter()
        .filter(|w| w.type_().name() == "GtkModelButton")
    {
        let mut inner = Vec::new();
        descendants(widget, &mut inner);
        let text = inner
            .iter()
            .filter_map(|w| w.downcast_ref::<gtk::Label>())
            .map(|l| l.text().trim().to_owned())
            .find(|t| !t.is_empty());
        if let Some(text) = text {
            widget.reset_relation(gtk::AccessibleRelation::LabelledBy); // over the text
            widget.update_property(&[gtk::accessible::Property::Label(&text)]);
        }
    }
}

/// Names the entries of a menu shown without a menu button (context menu), at each opening.
pub fn name_popover(popover: &gtk::PopoverMenu) {
    popover.connect_map(|p| name_entries(p.upcast_ref()));
}

/// Names the entries of the menus of the menu buttons under `root`, at each opening.
pub fn name_menus(root: &impl IsA<gtk::Widget>) {
    let mut widgets = vec![root.as_ref().clone()];
    descendants(root.as_ref(), &mut widgets);
    for button in widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::MenuButton>())
    {
        if let Some(popover) = button.popover() {
            popover.connect_map(name_entries);
        }
    }
}

/// Names each row of the shortcuts help (`clavier.montrer_aide`): the rows of
/// `AdwShortcutsDialog` (libadwaita 1.9) have no accessible name, a screen reader reads
/// nothing there. The title becomes the name, the keys the description.
pub fn name_shortcut_rows(dialog: &impl IsA<gtk::Widget>) {
    let mut widgets = Vec::new();
    descendants(dialog.as_ref(), &mut widgets);
    for row in widgets
        .iter()
        .filter_map(|w| w.downcast_ref::<gtk::ListBoxRow>())
    {
        let mut inner = Vec::new();
        descendants(row.upcast_ref(), &mut inner);
        let texts: Vec<String> = inner
            .iter()
            .filter_map(|w| w.downcast_ref::<gtk::Label>())
            .map(|l| l.label().trim().to_owned())
            .filter(|t| !t.is_empty())
            .collect();
        if let Some((title, keys)) = texts.split_first() {
            row.update_property(&[
                gtk::accessible::Property::Label(title),
                gtk::accessible::Property::Description(&keys.join(" ")),
            ]);
        }
    }
}

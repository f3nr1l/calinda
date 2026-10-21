// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Security » tab of the sheet (J4.2, `annuaire.ui.securite`), in reading (R4.5c):
//! structure in `securite.blp`, texts in `security_views`. The tab reads nothing until it
//! is shown: `load` reads the descriptor (`Source::security`, on the DC) and the nomenclature
//! (`Source::nomenclature`, once per source), at the same time. A delegation, a permission or
//! an entry is removed from its row; the delegation wizard and the entries typed in SDDL are
//! in `delegation`. Every write goes through the common preview, then the tab reads again.

use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::sd::Ace;
use annuaire_core::actions;
use annuaire_core::cache::Source;
use annuaire_core::security::{Nomenclature, SecurityReading};
use gtk::{gio, glib};

use crate::delegation::{self, AceDialog, DelegationDialog};
use crate::errors;
use crate::i18n::{fill, tr};
use crate::security_views::{self as sv, AceLine, RightLine, Section};

mod imp {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_core::cache::Source;
    use annuaire_core::security::{Nomenclature, SecurityReading};
    use gtk::glib;

    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/securite.ui")]
    pub struct SecurityPage {
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub delegate_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub add_ace_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub owner_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub audit_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub no_effect_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub deny_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub deny_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub delegations_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub delegations_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub explicit_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub explicit_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub inherited_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub inherited_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub audit_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub audit_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub sddl: TemplateChild<gtk::Label>,
        #[template_child]
        pub aces_list: TemplateChild<gtk::ListBox>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub dn: OnceCell<String>,
        pub up_to_date: Cell<bool>,
        pub generation: Cell<u64>,
        /// What is shown: for the writes.
        pub shown: RefCell<Option<(SecurityReading, Option<Arc<Nomenclature>>)>>,
    }

    impl std::fmt::Debug for SecurityPage {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SecurityPage")
                .field("dn", &self.dn.get())
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for SecurityPage {
        const NAME: &'static str = "AnnuairePageSecurite";
        type Type = super::SecurityPage;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::SecurityPage>(&[
                ("reload", |p, _| {
                    p.imp().up_to_date.set(false);
                    p.load();
                    None
                }),
                ("copy", |p, _| {
                    p.copy();
                    None
                }),
                ("delegate", |p, _| {
                    let _ = p.delegate();
                    None
                }),
                ("add_ace", |p, _| {
                    let _ = p.add_ace();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for SecurityPage {
        fn constructed(&self) {
            self.parent_constructed();
            // A SDDL cut at the end of a line gets no hyphen: it reads and copies as is.
            if let Ok(attributes) = gtk::pango::AttrList::from_string("0 -1 insert-hyphens false") {
                self.sddl.set_attributes(Some(&attributes));
            }
        }
    }

    impl WidgetImpl for SecurityPage {}
    impl BinImpl for SecurityPage {}
}

glib::wrapper! {
    /// « Security » tab: rights in clear, delegations, ACEs and SDDL (`AnnuairePageSecurite`).
    pub struct SecurityPage(ObjectSubclass<imp::SecurityPage>)
        @extends adw::Bin, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

fn empty(list: &gtk::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}

impl SecurityPage {
    pub fn configure(&self, source: Arc<dyn Source>, dn: &str) {
        let imp = self.imp();
        let _ = imp.source.set(source);
        let _ = imp.dn.set(dn.to_owned());
    }

    /// The next presentation reads again (« Read again » of the sheet) (`invalider`).
    pub fn invalidate(&self) {
        self.imp().up_to_date.set(false);
    }

    /// Reads and shows the security of the object, unless it is already done and up to date
    /// (`charger`).
    pub fn load(&self) {
        let imp = self.imp();
        let Some(source) = imp.source.get().cloned() else {
            return;
        };
        if imp.up_to_date.replace(true) {
            return;
        }
        let generation = imp.generation.get() + 1;
        imp.generation.set(generation);
        imp.state.set_visible_child_name("chargement");
        let dn = imp.dn.get().cloned().unwrap_or_default();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let (for_reading, for_names, asked) = (source.clone(), source.clone(), dn.clone());
            let reading = gio::spawn_blocking(move || for_reading.security(&asked));
            let nomenclature = gio::spawn_blocking(move || for_names.nomenclature());
            let (reading, nomenclature) = (reading.await, nomenclature.await);
            let Some(page) = weak.upgrade() else { return };
            let imp = page.imp();
            if imp.generation.get() != generation {
                return;
            }
            let Ok(reading) = reading else { return };
            // Without nomenclature, GUIDs and SIDs are not named, but the tab stays useful.
            let nomenclature = nomenclature.ok().and_then(Result::ok);
            match reading {
                Ok(Some(reading)) => {
                    page.show_reading(&reading, nomenclature.as_deref());
                    *page.imp().shown.borrow_mut() = Some((reading, nomenclature));
                }
                Ok(None) => {
                    imp.up_to_date.set(false);
                    imp.error.set_title(&tr("This object no longer exists."));
                    imp.error
                        .set_description(Some(&glib::markup_escape_text(&dn)));
                    imp.state.set_visible_child_name("erreur");
                }
                Err(failure) => {
                    imp.up_to_date.set(false);
                    let problem = errors::failure_problem(&failure, &source.profile().domain);
                    imp.error.set_title(&problem.message);
                    imp.error
                        .set_description(Some(&glib::markup_escape_text(&problem.detail)));
                    imp.state.set_visible_child_name("erreur");
                }
            }
        });
    }

    fn read_only(&self) -> bool {
        self.imp()
            .source
            .get()
            .is_none_or(|s| s.profile().read_only)
    }

    /// Remove button of a row (`_bouton_retirer`).
    fn remove_button(&self, aces: Vec<Ace>, what: String, name: String) -> gtk::Button {
        let button = gtk::Button::builder()
            .icon_name("list-remove-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(&what)
            .build();
        button.add_css_class("flat");
        button.update_property(&[gtk::accessible::Property::Label(&fill(
            &tr("{quoi}: {nom}"),
            &[("quoi", &what), ("nom", &name)],
        ))]);
        let weak = self.downgrade();
        button.connect_clicked(move |_| {
            if let Some(page) = weak.upgrade() {
                page.remove(aces.clone(), what.clone(), name.clone());
            }
        });
        button
    }

    /// `_ligne_droit`.
    fn right_row(&self, line: &RightLine) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&line.text).as_str())
            .subtitle(glib::markup_escape_text(&line.detail).as_str())
            .title_lines(0)
            .subtitle_lines(2)
            .build();
        if line.removable && !self.read_only() {
            let what = if line.delegation.is_empty() {
                tr("Remove the permission")
            } else {
                tr("Remove the delegation")
            };
            row.add_suffix(&self.remove_button(line.aces.clone(), what, line.text.clone()));
        }
        row
    }

    /// `_ligne_ace`.
    fn ace_row(&self, line: &AceLine) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&line.sddl).as_str())
            .subtitle(glib::markup_escape_text(&format!("{} {}.", line.text, line.detail)).as_str())
            .title_lines(0)
            .subtitle_lines(0)
            .title_selectable(true)
            .build();
        if line.removable && !self.read_only() {
            row.add_suffix(&self.remove_button(
                vec![line.ace.clone()],
                tr("Remove this entry"),
                line.sddl.clone(),
            ));
        }
        row
    }

    /// `afficher`.
    fn show_reading(&self, reading: &SecurityReading, nomenclature: Option<&Nomenclature>) {
        let imp = self.imp();
        let (name, sid) = sv::owner(reading);
        imp.owner_row
            .set_subtitle(&glib::markup_escape_text(&if sid.is_empty() {
                name
            } else {
                format!("{name} · {sid}")
            }));
        imp.audit_row.set_subtitle(&sv::sacl_state(reading));
        let view = sv::sections(reading, nomenclature);
        imp.no_effect_row.set_visible(view.without_effect > 0);
        imp.no_effect_row.set_subtitle(&fill(
            &tr("{n} inheritable permission(s) do not apply to this object (inherit only, or restricted to another class): see “ACEs and SDDL”."),
            &[("n", &view.without_effect.to_string())],
        ));
        let lists = [
            (Section::Deny, &*imp.deny_group, &*imp.deny_list),
            (
                Section::Delegations,
                &*imp.delegations_group,
                &*imp.delegations_list,
            ),
            (Section::Explicit, &*imp.explicit_group, &*imp.explicit_list),
            (
                Section::Inherited,
                &*imp.inherited_group,
                &*imp.inherited_list,
            ),
            (Section::Audit, &*imp.audit_group, &*imp.audit_list),
        ];
        for (_, group, list) in &lists {
            empty(list);
            group.set_visible(false);
        }
        for section in &view.sections {
            let Some((_, group, list)) = lists.iter().find(|(s, _, _)| *s == section.section)
            else {
                continue;
            };
            group.set_visible(!section.lines.is_empty());
            for line in &section.lines {
                list.append(&self.right_row(line));
            }
        }
        imp.delegate_button
            .set_visible(sv::can_delegate(&reading.classes) && !self.read_only());
        imp.add_ace_button.set_visible(!self.read_only());
        let domain = nomenclature.and_then(|n| n.domain_sid);
        let text = sv::descriptor_sddl(&reading.descriptor, domain.as_ref());
        imp.sddl.set_label(&text);
        empty(&imp.aces_list);
        for line in sv::ace_lines(reading, nomenclature) {
            imp.aces_list.append(&self.ace_row(&line));
        }
        imp.state.set_visible_child_name("contenu");
    }

    // --- Writes ---------------------------------------------------------------------------

    /// `_retirer`.
    fn remove(&self, aces: Vec<Ace>, what: String, name: String) {
        let Some(dn) = self
            .imp()
            .shown
            .borrow()
            .as_ref()
            .map(|(r, _)| r.dn.clone())
        else {
            return;
        };
        let weak = self.downgrade();
        delegation::prepare(
            self,
            &dn,
            tr("Cannot remove"),
            move |object| actions::remove_aces(object, &aces),
            move |changeset| {
                let (Some(page), Some(changeset)) = (weak.upgrade(), changeset) else {
                    return;
                };
                let remarks = vec![
                    fill(&tr("{quoi}: {nom}"), &[("quoi", &what), ("nom", &name)]),
                    sv::undo_remark(),
                ];
                let after = page.downgrade();
                delegation::propose(
                    &page,
                    changeset,
                    remarks,
                    Rc::new(move |_| {
                        if let Some(page) = after.upgrade() {
                            page.written();
                        }
                    }),
                );
            },
        );
    }

    fn after_write(&self) -> delegation::Written {
        let weak = self.downgrade();
        Rc::new(move || {
            if let Some(page) = weak.upgrade() {
                page.written();
            }
        })
    }

    /// `delegate`.
    fn delegate(&self) -> Option<DelegationDialog> {
        let imp = self.imp();
        let (reading, nomenclature) = imp.shown.borrow().clone()?;
        let source = imp.source.get()?.clone();
        let dialog = DelegationDialog::new(source, reading, nomenclature, self.after_write());
        dialog.present(Some(self));
        Some(dialog)
    }

    /// `add_ace`.
    fn add_ace(&self) -> Option<AceDialog> {
        let (reading, nomenclature) = self.imp().shown.borrow().clone()?;
        let dialog = AceDialog::new(reading, nomenclature, self.after_write());
        dialog.present(Some(self));
        Some(dialog)
    }

    /// `_ecrit`: the tab reads again.
    fn written(&self) {
        self.imp().up_to_date.set(false);
        self.load();
    }

    /// Delegation `wizard` (`search|template,template`), entry `ace` (SDDL), or removal of
    /// the row whose title starts with `remove` (trials).
    pub fn trial(&self, wizard: Option<&str>, ace: Option<&str>, remove: Option<&str>) {
        if let Some(spec) = wizard
            && let Some(dialog) = self.delegate()
        {
            let (search, templates) = spec.split_once('|').unwrap_or((spec, ""));
            let templates: Vec<String> = templates.split(',').map(str::to_owned).collect();
            dialog.trial(search, &templates);
        }
        if let Some(text) = ace
            && let Some(dialog) = self.add_ace()
        {
            dialog.trial(text);
        }
        if let Some(start) = remove {
            let imp = self.imp();
            for list in [
                &*imp.deny_list,
                &*imp.delegations_list,
                &*imp.explicit_list,
                &*imp.aces_list,
            ] {
                let mut i = 0;
                while let Some(row) = list.row_at_index(i) {
                    i += 1;
                    let Some(row) = row.downcast_ref::<adw::ActionRow>() else {
                        continue;
                    };
                    if !row.title().starts_with(start) {
                        continue;
                    }
                    let mut child = row.first_child();
                    while let Some(c) = child {
                        for w in crate::sheet::all_under(&c) {
                            if let Ok(button) = w.downcast::<gtk::Button>()
                                && button.icon_name().as_deref() == Some("list-remove-symbolic")
                            {
                                eprintln!("essai retrait : {}", row.title());
                                button.emit_clicked();
                                return;
                            }
                        }
                        child = c.next_sibling();
                    }
                }
            }
            eprintln!("essai retrait : aucune ligne « {start} »");
        }
    }

    fn copy(&self) {
        if let Some(display) = gtk::gdk::Display::default() {
            display.clipboard().set_text(&self.imp().sddl.label());
        }
    }

    /// Every sentence and every ACE once shown (trials).
    pub fn trial_lines(&self) -> Option<Vec<String>> {
        let imp = self.imp();
        if imp.state.visible_child_name().as_deref() != Some("contenu") {
            return None;
        }
        let mut out = vec![
            imp.owner_row.subtitle().unwrap_or_default().to_string(),
            imp.audit_row.subtitle().unwrap_or_default().to_string(),
            imp.sddl.label().to_string(),
        ];
        for list in [
            &*imp.deny_list,
            &*imp.delegations_list,
            &*imp.explicit_list,
            &*imp.inherited_list,
            &*imp.audit_list,
            &*imp.aces_list,
        ] {
            let mut i = 0;
            while let Some(row) = list.row_at_index(i) {
                if let Some(row) = row.downcast_ref::<adw::ActionRow>() {
                    out.push(format!(
                        "{}\t{}",
                        row.title(),
                        row.subtitle().unwrap_or_default()
                    ));
                }
                i += 1;
            }
        }
        Some(out)
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Policy » tab of the sheet (J5.7, `annuaire.ui.strategie`): « Which GPOs apply to this
//! account? ». Structure in `strategie.blp`; computation in `annuaire_core::gpo` (LSDOU,
//! security filtering on `tokenGroups`), texts in `policy_views`. For a user, the user
//! configuration; for a computer, the computer configuration. Nothing is read until the tab
//! is shown; the reading goes through the write connection of the window (PDC emulator), as
//! the window of the group policies (ADR 0012).

use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::connection::Connection;
use annuaire_core::gpo::{self, LoopbackError, ResultantPolicy};
use gtk::{gio, glib};

use crate::errors;
use crate::i18n::{fill, tr, tr_ctx};
use crate::policy_views as pv;

mod imp {
    use std::cell::{Cell, RefCell};

    use adw::subclass::prelude::*;
    use gtk::glib;

    use crate::scope::TemplateScope;

    #[derive(Debug, Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/strategie.ui")]
    pub struct PolicyPage {
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub summary_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub remarks_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub computer_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub loopback_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub applied_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub denied_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub denied_list: TemplateChild<gtk::ListBox>,
        pub dn: RefCell<String>,
        pub up_to_date: Cell<bool>,
        pub generation: Cell<u64>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PolicyPage {
        const NAME: &'static str = "AnnuairePageStrategie";
        type Type = super::PolicyPage;
        type ParentType = adw::Bin;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PolicyPage>(&[
                ("reload", |p, _| {
                    p.imp().up_to_date.set(false);
                    let dn = p.imp().dn.borrow().clone();
                    p.load(&dn);
                    None
                }),
                ("loopback", |p, _| {
                    p.loopback();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PolicyPage {}
    impl WidgetImpl for PolicyPage {}
    impl BinImpl for PolicyPage {}
}

glib::wrapper! {
    /// « Policy » tab: GPOs applied by priority, and the others with their reason
    /// (`AnnuairePageStrategie`).
    pub struct PolicyPage(ObjectSubclass<imp::PolicyPage>)
        @extends adw::Bin, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget;
}

fn empty(list: &gtk::ListBox) {
    while let Some(row) = list.row_at_index(0) {
        list.remove(&row);
    }
}

fn row(title: &str, subtitle: &str, alert: bool) -> adw::ActionRow {
    let row = adw::ActionRow::builder()
        .title(glib::markup_escape_text(title).as_str())
        .subtitle(glib::markup_escape_text(subtitle).as_str())
        .title_lines(0)
        .subtitle_lines(0)
        .build();
    if alert {
        let image = gtk::Image::from_icon_name("dialog-warning-symbolic");
        image.add_css_class("warning");
        image.update_property(&[gtk::accessible::Property::Label(&tr("Alert"))]);
        row.add_prefix(&image);
    }
    row
}

fn loopback_message(error: &LoopbackError, domain: &str) -> String {
    match error {
        LoopbackError::Failure(f) => errors::failure_problem(f, domain).message,
        LoopbackError::Sysvol(message) => message.clone(),
        LoopbackError::ComputerNotFound(name) => {
            fill(&tr("Computer “{nom}” not found."), &[("nom", name)])
        }
    }
}

impl PolicyPage {
    pub fn invalidate(&self) {
        self.imp().up_to_date.set(false);
    }

    /// The write connection of the window, and the domain (`contexte`).
    fn writes(&self) -> Option<(Arc<Connection>, String)> {
        let window = self.root().and_downcast::<crate::window::Window>()?;
        let domain = window.source()?.profile().domain.clone();
        Some((window.writes()?, domain))
    }

    /// Computes the policy of `dn`, unless it is already up to date for it (`charger`).
    pub fn load(&self, dn: &str) {
        let imp = self.imp();
        if imp.up_to_date.get() && *imp.dn.borrow() == dn {
            return;
        }
        *imp.dn.borrow_mut() = dn.to_owned();
        imp.up_to_date.set(true);
        let generation = imp.generation.get() + 1;
        imp.generation.set(generation);
        let Some((connection, domain)) = self.writes() else {
            self.failed(&tr("No domain open"), "");
            return;
        };
        imp.state.set_visible_child_name("chargement");
        let (asked, weak) = (dn.to_owned(), self.downgrade());
        let reading = connection.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || gpo::read_rsop(&reading, &asked)).await;
            let Some(page) = weak.upgrade() else { return };
            if page.imp().generation.get() != generation {
                return;
            }
            match read {
                Ok(Ok(data)) => {
                    let policy = data.compute(None);
                    page.show_policy(&policy, &data.directory.dns_name);
                    page.show_loopback(connection, data, &domain);
                }
                Ok(Err(failure)) => {
                    page.imp().up_to_date.set(false);
                    let problem = errors::failure_problem(&failure, &domain);
                    page.failed(&problem.message, &problem.detail);
                }
                Err(_) => page.imp().up_to_date.set(false),
            }
        });
    }

    /// Computer: its mode, read in the `Registry.pol` of the GPOs applied to it. User: the
    /// input of a computer, to compute again with its mode (`_montrer_boucle`).
    fn show_loopback(&self, connection: Arc<Connection>, data: gpo::RsopData, domain: &str) {
        let imp = self.imp();
        let computer = data.part() == gpo::Part::Computer;
        imp.computer_entry.set_visible(!computer);
        if !computer {
            imp.loopback_row.set_subtitle(&tr(
                "Without a computer: the user's own list. Enter a computer to take its loopback processing into account.",
            ));
            return;
        }
        let generation = imp.generation.get();
        imp.loopback_row.set_subtitle(&tr("Reading Registry.pol…"));
        let (weak, domain) = (self.downgrade(), domain.to_owned());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || gpo::mode_of(&connection, &data)).await;
            let Some(page) = weak.upgrade() else { return };
            if page.imp().generation.get() != generation {
                return;
            }
            let text = match read {
                Ok(Ok(mode)) => pv::loopback_text(&mode),
                Ok(Err(error)) => loopback_message(&error, &domain),
                Err(_) => return,
            };
            page.imp().loopback_row.set_subtitle(&text);
        });
    }

    /// The user part on the computer typed in (`loopback`).
    fn loopback(&self) {
        let imp = self.imp();
        let name = imp.computer_entry.text().trim().to_owned();
        let Some((connection, domain)) = self.writes() else {
            return;
        };
        let dn = imp.dn.borrow().clone();
        if name.is_empty() {
            imp.up_to_date.set(false);
            self.load(&dn);
            return;
        }
        let generation = imp.generation.get() + 1;
        imp.generation.set(generation);
        imp.loopback_row
            .set_subtitle(&fill(&tr("Computing on {nom}…"), &[("nom", &name)]));
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let read =
                gio::spawn_blocking(move || gpo::read_loopback(&connection, &dn, &name)).await;
            let Some(page) = weak.upgrade() else { return };
            if page.imp().generation.get() != generation {
                return;
            }
            match read {
                Ok(Ok(data)) => {
                    let policy = data.compute();
                    page.show_policy(&policy, &data.user.directory.dns_name);
                    page.imp().loopback_row.set_subtitle(&fill(
                        &tr("On {ordinateur}: {mode}"),
                        &[
                            ("ordinateur", &data.computer.account),
                            ("mode", &pv::loopback_text(&data.mode)),
                        ],
                    ));
                }
                Ok(Err(error)) => page
                    .imp()
                    .loopback_row
                    .set_subtitle(&loopback_message(&error, &domain)),
                Err(_) => {}
            }
        });
    }

    fn failed(&self, title: &str, detail: &str) {
        let imp = self.imp();
        imp.error.set_title(title);
        imp.error.set_description(Some(detail));
        imp.state.set_visible_child_name("erreur");
    }

    /// `_afficher`.
    fn show_policy(&self, policy: &ResultantPolicy, dns_name: &str) {
        let imp = self.imp();
        imp.summary_group.set_title(&fill(
            &tr("Resultant policy: {partie}"),
            &[("partie", &pv::part_label(policy.part).to_lowercase())],
        ));
        imp.summary_group
            .set_description(Some(&pv::summary(policy, dns_name)));
        empty(&imp.remarks_list);
        for remark in &policy.remarks {
            imp.remarks_list
                .append(&row(&tr("Not evaluated"), &pv::remark_text(remark), true));
        }
        imp.remarks_list.set_visible(!policy.remarks.is_empty());
        empty(&imp.applied_list);
        empty(&imp.denied_list);
        for line in pv::lines(policy, dns_name) {
            let mut details = vec![
                fill(&tr("linked to {lieu}"), &[("lieu", &line.link)]),
                line.state.clone(),
            ];
            if !line.remark.is_empty() {
                details.push(line.remark.clone());
            }
            let details = details.join(&tr("; "));
            match line.priority {
                Some(priority) => imp.applied_list.append(&row(
                    &fill(
                        &tr("{n}. {nom}"),
                        &[("n", &priority.to_string()), ("nom", &line.name)],
                    ),
                    &details,
                    line.alert,
                )),
                None => imp
                    .denied_list
                    .append(&row(&line.name, &details, line.alert)),
            }
        }
        if policy.applied.is_empty() {
            imp.applied_list
                .append(&row(&tr_none(), &tr("No GPO applies."), false));
        }
        imp.denied_group
            .set_visible(!policy.discarded.is_empty() || !policy.ignored.is_empty());
        imp.state.set_visible_child_name("contenu");
    }

    /// The user part on `computer`, as if typed in the entry (trials).
    pub fn trial_loopback(&self, computer: &str) {
        self.imp().computer_entry.set_text(computer);
        self.loopback();
    }

    /// Every row once shown, the loopback mode read (trials).
    pub fn trial_lines(&self) -> Option<Vec<String>> {
        let imp = self.imp();
        if imp.state.visible_child_name().as_deref() != Some("contenu")
            || imp.loopback_row.subtitle().as_deref() == Some(tr("Reading Registry.pol…").as_str())
        {
            return None;
        }
        let mut out = vec![
            imp.summary_group.title().to_string(),
            imp.summary_group
                .description()
                .unwrap_or_default()
                .to_string(),
            imp.loopback_row.subtitle().unwrap_or_default().to_string(),
        ];
        for list in [&*imp.remarks_list, &*imp.applied_list, &*imp.denied_list] {
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

/// « None » of the empty list of the applied GPOs (feminine in French: « Aucune »).
fn tr_none() -> String {
    tr_ctx("feminine", "None")
}

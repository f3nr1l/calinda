// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Effective Access » of an account or a group to a folder or file of a share (ADR 0023
//! § 6, J8.5), as the tab of Windows. Structure in `dialogue-acces-effectif.blp`, texts in
//! `access_views`, computation in `annuaire_core::effective_access::read`: the token (directory,
//! then the local groups of the server by SAMR), the descriptor of the share (`srvsvc`) and
//! the one of the element (SMB), evaluated as the server would. Everything is read in a thread;
//! the dialog only shows. Opened from « Folders and NTFS Permissions » (a folder, a file) and
//! from « Shares » (the root of a share).

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_core::cache::Source;
use annuaire_core::connection::Connection;
use annuaire_core::effective_access::{self, Effective, Target};
use annuaire_core::ntfs;
use annuaire_core::source::Item;
use annuaire_core::sysvol::Protection;
use gtk::{gio, glib};

use crate::access_views as av;
use crate::delegation::{MAX_RESULTS, candidate_row};
use crate::errors;
use crate::feed::Feed;
use crate::gpo_dialogs::count_text;
use crate::i18n::tr;
use crate::scope::TemplateScope;
use crate::security_views as sv;
use crate::share_views::Names;
use crate::sheet_views::{self as sheet, ElementView};

const DELAY: Duration = Duration::from_secs(30);

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

/// An error of the reading, in words.
fn problem(error: &effective_access::Error, server: &str, domain: &str) -> errors::Problem {
    use effective_access::Error;
    match error {
        Error::Directory(f) => errors::failure_problem(f, domain),
        Error::Share(e) => errors::share_problem(e, server),
        Error::Folder(e) => errors::file_problem(e, server),
        Error::NoPrincipal(dn) => errors::Problem {
            message: tr("This account or group no longer exists, or has no SID."),
            detail: dn.clone(),
            ticket: false,
            kerberos: false,
        },
        Error::NoFolder(path) => errors::Problem {
            message: tr("This element no longer exists on the server."),
            detail: path.clone(),
            ticket: false,
            kerberos: false,
        },
        Error::Descriptor(e) => errors::Problem {
            message: tr("Unreadable permissions"),
            detail: e.to_string(),
            ticket: false,
            kerberos: false,
        },
    }
}

mod imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-acces-effectif.ui")]
    pub struct AccessDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub principal_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub principal_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub state_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub spinner: TemplateChild<gtk::Spinner>,
        #[template_child]
        pub state_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub result_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub summary_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub rights_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub notes_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub identities_label: TemplateChild<gtk::Label>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub connection: RefCell<Option<Arc<Connection>>>,
        pub target: OnceCell<Target>,
        pub folder: Cell<bool>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<ElementView>>,
        pub generation: Cell<u64>,
        pub result: RefCell<Option<(Effective, Names)>>,
        pub done: Cell<bool>,
    }

    impl std::fmt::Debug for AccessDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("AccessDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for AccessDialog {
        const NAME: &'static str = "AnnuaireDialogueAccesEffectif";
        type Type = super::AccessDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::AccessDialog>(&[
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("close", |d, _| {
                    d.close();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for AccessDialog {}
    impl WidgetImpl for AccessDialog {}

    impl AdwDialogImpl for AccessDialog {
        fn closed(&self) {
            self.generation.set(self.generation.get() + 1);
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// The effective access of an account or a group (`AnnuaireDialogueAccesEffectif`).
    pub struct AccessDialog(ObjectSubclass<imp::AccessDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

impl AccessDialog {
    /// For `path` of the share `share` of `server` (« » for its root).
    pub fn new(
        source: Arc<dyn Source>,
        connection: Option<Arc<Connection>>,
        server: &str,
        share: &str,
        path: &str,
        folder: bool,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        imp.title
            .set_subtitle(&annuaire_core::changes::unc(server, share, path));
        imp.folder.set(folder);
        let _ = imp.target.set(Target {
            server: server.to_owned(),
            share: share.to_owned(),
            path: path.to_owned(),
        });
        let _ = imp.source.set(source);
        *imp.connection.borrow_mut() = connection;
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.choose(&row.widget_name());
            }
        });
        dialog.set_focus(Some(&*imp.principal_entry));
        dialog
    }

    fn source(&self) -> Arc<dyn Source> {
        self.imp().source.get().expect("set by new").clone()
    }

    fn target(&self) -> Target {
        self.imp().target.get().expect("set by new").clone()
    }

    fn stop(&self) {
        if let Some(feed) = self.imp().search.take() {
            feed.cancel();
        }
    }

    fn search(&self) {
        self.stop();
        let imp = self.imp();
        empty(&imp.candidates_list);
        imp.received.borrow_mut().clear();
        imp.candidates_list.set_visible(false);
        let Some(filter) = sv::delegates_filter(&imp.principal_entry.text()) else {
            imp.candidates_count.set_label("");
            return;
        };
        imp.candidates_count.set_label(&tr("Searching…"));
        let source = self.source();
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let feed = Feed::start(
            |notifier| source.search_under(filter, None, notifier).flux,
            move |items: Vec<Item>| {
                let Some(dialog) = deliver_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                for item in &items {
                    let view = sheet::element_from_item(item);
                    if imp.received.borrow().len() < MAX_RESULTS {
                        imp.candidates_list
                            .append(&candidate_row(&view, &tr("Choose")));
                    }
                    imp.received.borrow_mut().push(view);
                }
                imp.candidates_list
                    .set_visible(!imp.received.borrow().is_empty());
                let n = imp.received.borrow().len();
                imp.candidates_count.set_label(&count_text(n, false));
            },
            move |error| {
                let Some(dialog) = finish_to.upgrade() else {
                    return;
                };
                let imp = dialog.imp();
                imp.search.take();
                match error {
                    Some(error) => imp
                        .candidates_count
                        .set_label(&errors::search_problem(&error, &domain).message),
                    None => {
                        let n = imp.received.borrow().len();
                        imp.candidates_count.set_label(&count_text(n, true));
                    }
                }
            },
        );
        *imp.search.borrow_mut() = Some(feed);
    }

    /// The account or group of `dn` chosen: its access read.
    pub fn choose(&self, dn: &str) {
        let imp = self.imp();
        let title = imp
            .received
            .borrow()
            .iter()
            .find(|v| v.dn == dn)
            .map_or_else(|| dn.to_owned(), |v| v.title.clone());
        imp.principal_entry.set_text("");
        imp.principal_row
            .set_title(&glib::markup_escape_text(&title));
        imp.principal_row
            .set_subtitle(&glib::markup_escape_text(dn));
        self.compute(dn);
    }

    fn compute(&self, dn: &str) {
        let imp = self.imp();
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.done.set(false);
        imp.result_group.set_visible(false);
        imp.state_group.set_visible(true);
        imp.spinner.set_visible(true);
        imp.state_label
            .set_label(&tr("Reading the groups and the permissions…"));
        let Some(connection) = imp.connection.borrow().clone() else {
            self.failed(&errors::Problem {
                message: tr("No domain is open."),
                detail: String::new(),
                ticket: false,
                kerberos: false,
            });
            return;
        };
        let target = self.target();
        let source = self.source();
        let domain = source.profile().domain.clone();
        let protection = Protection::of_profile(source.profile().smb2_signing);
        let dn = dn.to_owned();
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let server = target.server.clone();
            let read = gio::spawn_blocking(move || {
                let e = effective_access::read(&connection, &dn, &target, protection, DELAY)?;
                let mut sids: HashSet<Sid> = e.token.sids().iter().copied().collect();
                for d in e
                    .share_descriptor
                    .iter()
                    .chain(std::iter::once(&e.folder_descriptor))
                {
                    sids.extend(ntfs::dacl_of(d).iter().filter_map(|a| a.sid()));
                    sids.extend(d.owner);
                }
                let names = crate::file_security::name_all(
                    Some(connection),
                    &target.server,
                    sids,
                    protection,
                );
                Ok::<_, effective_access::Error>((e, names))
            })
            .await;
            let Some(dialog) = weak.upgrade() else { return };
            if dialog.imp().generation.get() != generation {
                return;
            }
            match read {
                Ok(Ok((e, names))) => dialog.show(e, names),
                Ok(Err(error)) => dialog.failed(&problem(&error, &server, &domain)),
                Err(_) => {}
            }
        });
    }

    fn failed(&self, problem: &errors::Problem) {
        let imp = self.imp();
        imp.spinner.set_visible(false);
        imp.state_label
            .set_label(&format!("{}\n{}", problem.message, problem.detail));
        imp.state_label.add_css_class("error");
        imp.done.set(true);
    }

    fn show(&self, e: Effective, names: Names) {
        let imp = self.imp();
        let folder = imp.folder.get();
        imp.state_group.set_visible(false);
        imp.state_label.remove_css_class("error");
        imp.summary_row
            .set_title(&glib::markup_escape_text(&av::summary(&e, folder)));
        imp.summary_row.set_subtitle(&if e.token.is_group {
            tr("A group given in place of an account: as for one of its members.")
        } else {
            String::new()
        });
        empty(&imp.rights_list);
        for line in av::right_lines(&e, folder, &names) {
            let subtitle = format!(
                "{}\n{}",
                av::limit_text(line.limit),
                line.reasons.join("\n")
            );
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&line.name).as_str())
                .subtitle(glib::markup_escape_text(&subtitle).as_str())
                .subtitle_lines(0)
                .build();
            let icon = gtk::Image::from_icon_name(if line.granted {
                "object-select-symbolic"
            } else {
                "action-unavailable-symbolic"
            });
            icon.update_property(&[gtk::accessible::Property::Label(&av::limit_text(
                line.limit,
            ))]);
            row.add_prefix(&icon);
            imp.rights_list.append(&row);
        }
        imp.notes_label.set_label(&av::notes(&e).join("\n"));
        imp.identities_label
            .set_label(&av::identities(&e, &names).join("\n"));
        imp.result_group.set_visible(true);
        *imp.result.borrow_mut() = Some((e, names));
        imp.done.set(true);
    }

    // --- Trials ------------------------------------------------------------------------------

    /// The reading is over, shown or failed (trials).
    pub fn trial_done(&self) -> bool {
        self.imp().done.get()
    }

    /// Summary, rights granted (hex), then each right and what decides it; or the error
    /// (trials).
    pub fn trial_lines(&self) -> Vec<String> {
        let imp = self.imp();
        let Some((e, names)) = imp.result.borrow().clone() else {
            return vec![format!("erreur | {}", imp.state_label.label())];
        };
        let folder = imp.folder.get();
        let mut out = vec![
            format!("résumé | {}", av::summary(&e, folder)),
            format!(
                "masques | effectif 0x{:x} | partage {} | ntfs 0x{:x}",
                e.granted,
                e.share
                    .as_ref()
                    .map_or_else(|| "-".into(), |s| format!("0x{:x}", s.granted)),
                e.folder.granted
            ),
        ];
        for line in av::right_lines(&e, folder, &names) {
            out.push(format!(
                "{} | {} | {}",
                line.name,
                av::limit_text(line.limit),
                line.reasons.join(" | ")
            ));
        }
        out.extend(av::notes(&e).into_iter().map(|n| format!("note | {n}")));
        out
    }
}

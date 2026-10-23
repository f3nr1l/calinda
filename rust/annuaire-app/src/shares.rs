// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Shares » window (ADR 0023, J8.2) and the dialogs of a share (J8.6) and of its
//! permissions (J8.3). Structures in `partages.blp`, `dialogue-partage.blp` and
//! `dialogue-partage-droits.blp`; texts in `share_views`; reading and writing by `srvsvc`
//! in the core (`annuaire_core::srvsvc`, `share_write`). A window apart, as « DNS » and
//! « Password Policies »: a file server is a machine of the domain, not an object of the tree.
//!
//! The server is chosen among the servers of the directory (domain controllers, computers
//! whose operating system is a server, then those with a mark of a file service: see
//! `annuaire_core::file_servers`), those already opened under this profile (key
//! `serveurs-fichiers`), or typed. Each share is read again just before a dialog opens; the
//! state read is the « before » of the changeset, which the writer compares with the server
//! before writing (ADR 0006). Everything goes through the common preview (journal, Ctrl+Z).
//! Read-only profile: the list only.

use std::cell::{Cell, OnceCell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::Sid;
use annuaire_core::cache::Source;
use annuaire_core::changes::{Changeset, Operation, Report, ShareSpec};
use annuaire_core::file_servers::{self, Kind};
use annuaire_core::search::{PAGE_SIZE, Search};
use annuaire_core::session::Scope;
use annuaire_core::share_write::{self as sw, Shares};
use annuaire_core::source::Item;
use annuaire_core::srvsvc::{self, Share, flags};
use annuaire_core::sysvol::Protection;
use gtk::{gio, glib};

use crate::delegation::{MAX_RESULTS, candidate_row, object_sid};
use crate::errors;
use crate::feed::Feed;
use crate::gpo_dialogs::count_text;
use crate::i18n::{fill, tr, tr_n};
use crate::scope::TemplateScope;
use crate::security_views as sv;
use crate::share_views::{self as shv, Names, ShareEntry, ShareLevel};
use crate::sheet_views::{self as sheet, ElementView};
use crate::writes::{self, Options};

fn empty(list: &gtk::ListBox) {
    while let Some(child) = list.row_at_index(0) {
        list.remove(&child);
    }
}

/// What follows a write of a dialog (the window reads again).
type Finished = Rc<dyn Fn(Option<&Report>)>;

/// What follows a share read again.
type Then = Box<dyn FnOnce(&SharesWindow, ShareSpec)>;

/// A share of the list: as listed, with its options (`SHARE_INFO_1005`, disk shares only).
#[derive(Debug, Clone)]
pub struct Listed {
    pub share: Share,
    pub flags: u32,
}

/// A file server offered: its DNS name and what is known of it.
#[derive(Debug, Clone)]
pub struct Known {
    name: String,
    about: String,
}

impl Known {
    /// A server offered, described by why it is (`file_servers::Kind`).
    fn of(offered: file_servers::Offered) -> Self {
        let system = offered.system;
        let about = match offered.kind {
            Kind::DomainController if system.is_empty() => tr("Domain controller"),
            Kind::DomainController => {
                fill(&tr("{systeme}, domain controller"), &[("systeme", &system)])
            }
            Kind::Server => system,
            Kind::FileService if system.is_empty() => {
                tr("Domain member, operating system not declared")
            }
            Kind::FileService => system,
            Kind::Remembered => tr("Opened before"),
        };
        Self {
            name: offered.name,
            about,
        }
    }

    fn remembered(name: String) -> Self {
        Self {
            name,
            about: tr("Opened before"),
        }
    }
}

fn protection(source: &Arc<dyn Source>) -> Protection {
    Protection::of_profile(source.profile().smb2_signing)
}

/// The main window (the profile store), through the windows `window` is transient for.
fn main_window(window: &impl IsA<gtk::Window>) -> Option<crate::window::Window> {
    let mut current = Some(window.clone().upcast::<gtk::Window>());
    while let Some(w) = current {
        if let Ok(main) = w.clone().downcast::<crate::window::Window>() {
            return Some(main);
        }
        current = w.transient_for();
    }
    None
}

// --- The window -------------------------------------------------------------------------------

mod imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/partages.ui")]
    pub struct SharesWindow {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub new_button: TemplateChild<gtk::Button>,
        #[template_child]
        pub server_entry: TemplateChild<gtk::Entry>,
        #[template_child]
        pub servers_popover: TemplateChild<gtk::Popover>,
        #[template_child]
        pub servers_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub state: TemplateChild<gtk::Stack>,
        #[template_child]
        pub error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub shares_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub shares_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub none_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub special_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub special_row: TemplateChild<adw::ExpanderRow>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        pub source: OnceCell<Arc<dyn Source>>,
        /// The server whose shares are shown (or being read).
        pub server: RefCell<Option<String>>,
        pub shares: RefCell<Vec<Listed>>,
        pub names: RefCell<Names>,
        pub known: RefCell<Vec<Known>>,
        pub special_rows: RefCell<Vec<adw::ActionRow>>,
        pub generation: Cell<u64>,
        /// The server is a Samba server, whose registry configuration the account opens
        /// (J8.7): the options of the shares it holds are written, those of smb.conf kept.
        pub samba: Cell<bool>,
        pub registry: Cell<bool>,
    }

    impl std::fmt::Debug for SharesWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SharesWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for SharesWindow {
        const NAME: &'static str = "AnnuairePartages";
        type Type = super::SharesWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::SharesWindow>(&[(
                "open",
                |w, _| {
                    w.open_typed();
                    None
                },
            )]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for SharesWindow {}
    impl WidgetImpl for SharesWindow {}

    impl WindowImpl for SharesWindow {
        fn close_request(&self) -> glib::Propagation {
            self.generation.set(self.generation.get() + 1);
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for SharesWindow {}
}

glib::wrapper! {
    /// The shares of a file server of the domain (`AnnuairePartages`).
    pub struct SharesWindow(ObjectSubclass<imp::SharesWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl SharesWindow {
    pub fn new(source: Arc<dyn Source>, parent: &crate::window::Window) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = window.imp();
        imp.title.set_subtitle(&source.profile().domain);
        let remembered = parent.file_servers(&source.profile().domain);
        let _ = imp.source.set(source);
        if let Some(last) = remembered.last() {
            imp.server_entry.set_text(last);
        }
        *imp.known.borrow_mut() = remembered.into_iter().map(Known::remembered).collect();
        imp.shares_list.connect_row_activated({
            let weak = window.downgrade();
            move |_, row| {
                if let Some(window) = weak.upgrade() {
                    window.row_activated(row);
                }
            }
        });
        imp.servers_list.connect_row_activated({
            let weak = window.downgrade();
            move |_, row| {
                if let Some(window) = weak.upgrade() {
                    let name = row.widget_name().to_string();
                    window.imp().servers_popover.popdown();
                    window.imp().server_entry.set_text(&name);
                    window.open_server(&name);
                }
            }
        });
        window.install_actions();
        window.show_known();
        window.read_known();
        imp.state.set_visible_child_name("vide");
        window
    }

    pub fn source(&self) -> &Arc<dyn Source> {
        self.imp().source.get().expect("set by new")
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    fn read_only(&self) -> bool {
        self.source().profile().read_only
    }

    fn server(&self) -> Option<String> {
        self.imp().server.borrow().clone()
    }

    fn install_actions(&self) {
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&SharesWindow);
        let plain: [(&str, Handler); 3] = [
            ("actualiser", Self::reload),
            ("nouveau", Self::new_share),
            ("annuler-derniere", |w| crate::history::undo_last(w)),
        ];
        for (name, handler) in plain {
            let action = gio::SimpleAction::new(name, None);
            let weak = self.downgrade();
            action.connect_activate(move |_, _| {
                if let Some(window) = weak.upgrade().filter(|w| w.visible_dialog().is_none()) {
                    handler(&window);
                }
            });
            if name == "nouveau" {
                action.set_enabled(!self.read_only());
            }
            group.add_action(&action);
        }
        self.insert_action_group("partages", Some(&group));
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [
            ("F5", "partages.actualiser"),
            ("<Control>r", "partages.actualiser"),
            ("<Control>n", "partages.nouveau"),
        ] {
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::NamedAction::new(action)),
            ));
        }
        // Ctrl+Z undoes the last change, not while the field of the server has the focus.
        let weak = self.downgrade();
        shortcuts.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>z"),
            Some(gtk::CallbackAction::new(move |_, _| {
                let Some(window) = weak.upgrade() else {
                    return glib::Propagation::Proceed;
                };
                let free = window.visible_dialog().is_none()
                    && !GtkWindowExt::focus(&window).is_some_and(|f| {
                        f.is::<gtk::Editable>() || f.ancestor(gtk::Text::static_type()).is_some()
                    });
                if free {
                    crate::history::undo_last(&window);
                }
                free.into()
            })),
        ));
        let weak = self.downgrade();
        shortcuts.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::CallbackAction::new(move |_, _| {
                if let Some(window) = weak.upgrade() {
                    window.close();
                }
                glib::Propagation::Stop
            })),
        ));
        self.add_controller(shortcuts);
        self.imp().new_button.set_visible(!self.read_only());
        self.imp().new_button.set_sensitive(false);
    }

    // --- Servers ------------------------------------------------------------------------------

    /// The servers of the directory (`file_servers`), read on the DC of the writes; those of
    /// the profile it does not offer stay, after them.
    fn read_known(&self) {
        let Some(context) = writes::context(self) else {
            return;
        };
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || {
                let base = connection
                    .run(true, |link| {
                        Ok(link.state.root_dse.default_naming_context.clone())
                    })
                    .map_err(|e| format!("{e:?}"))?;
                let search = Search {
                    base,
                    scope: Scope::Subtree,
                    filter: file_servers::FILTER.into(),
                    attributes: file_servers::ATTRIBUTES.map(str::to_owned).to_vec(),
                    page_size: PAGE_SIZE,
                    sd_flags: None,
                    controls: Vec::new(),
                };
                let mut found = Vec::new();
                annuaire_core::source::search_blocking(&connection, search, &mut |page| {
                    for entry in page {
                        let text = |a: &str| {
                            entry
                                .values(a)
                                .first()
                                .map(|v| String::from_utf8_lossy(v).into_owned())
                                .unwrap_or_default()
                        };
                        let spns: Vec<String> = entry
                            .values("servicePrincipalName")
                            .iter()
                            .map(|v| String::from_utf8_lossy(v).into_owned())
                            .collect();
                        found.extend(file_servers::classify(
                            &text("dNSHostName"),
                            &text("operatingSystem"),
                            text("userAccountControl").parse().unwrap_or_default(),
                            &spns,
                        ));
                    }
                    true
                })
                .map(|()| found)
                .map_err(|e| format!("{e:?}"))
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            // A directory that cannot be read leaves the servers of the profile and the
            // field: the error of the server itself says more.
            if let Ok(Ok(found)) = read {
                let imp = window.imp();
                let remembered: Vec<String> =
                    imp.known.borrow().iter().map(|k| k.name.clone()).collect();
                *imp.known.borrow_mut() = file_servers::offered(found, &remembered)
                    .into_iter()
                    .map(Known::of)
                    .collect();
                window.show_known();
            }
        });
    }

    fn show_known(&self) {
        let imp = self.imp();
        empty(&imp.servers_list);
        for known in imp.known.borrow().iter() {
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&known.name).as_str())
                .subtitle(glib::markup_escape_text(&known.about).as_str())
                .activatable(true)
                .build();
            row.set_widget_name(&known.name);
            imp.servers_list.append(&row);
        }
        if imp.known.borrow().is_empty() {
            let row = adw::ActionRow::builder()
                .title(tr("No file server known yet: type its name."))
                .build();
            imp.servers_list.append(&row);
        }
    }

    fn open_typed(&self) {
        let text = self.imp().server_entry.text().trim().to_lowercase();
        if !text.is_empty() {
            self.open_server(&text);
        }
    }

    /// Lists the shares of `server`.
    pub fn open_server(&self, server: &str) {
        let server = server.trim().trim_start_matches('\\').to_lowercase();
        *self.imp().server.borrow_mut() = Some(server);
        self.reload();
    }

    // --- Reading ------------------------------------------------------------------------------

    pub fn reload(&self) {
        let imp = self.imp();
        let Some(server) = self.server() else {
            imp.state.set_visible_child_name("vide");
            return;
        };
        let Some(context) = writes::context(self) else {
            imp.error.set_title(&tr("No domain is open."));
            imp.state.set_visible_child_name("erreur");
            return;
        };
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.state.set_visible_child_name("chargement");
        imp.title.set_subtitle(&server);
        imp.new_button.set_sensitive(false);
        let protection = protection(self.source());
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        let target = server.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || {
                let mut shares = Shares::new(protection);
                let service = shares.service(&target)?;
                let mut listed = Vec::new();
                for share in service.shares()? {
                    let flags = if share.is_disk() && share.level == 502 {
                        service.share_flags(&share.name).unwrap_or(0)
                    } else {
                        0
                    };
                    listed.push(Listed { share, flags });
                }
                // A Samba server: the limit and the options of the shares of its registry
                // configuration, which srvsvc does not give (J8.7).
                let samba = shares.samba(&target).unwrap_or(false);
                let registry = samba && matches!(shares.smbconf(&target), Ok(Some(_)));
                if registry {
                    for item in listed.iter_mut().filter(|l| l.share.is_disk()) {
                        let mut spec = sw::spec_of(&item.share, item.flags);
                        if sw::complete(&mut shares, &target, &mut spec).is_ok() {
                            item.share.max_uses = spec.max_uses;
                            item.flags = spec.flags;
                        }
                    }
                }
                shares.close();
                // The SIDs named as the security tab names them; unnamed if the DC fails.
                let sids: HashSet<Sid> = listed
                    .iter()
                    .filter_map(|l| l.share.descriptor.as_deref())
                    .flat_map(descriptor_sids)
                    .collect();
                let names =
                    annuaire_core::security::name_sids(&connection, sids).unwrap_or_default();
                Ok::<_, srvsvc::Error>((listed, names, samba, registry))
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            match read {
                Ok(Ok((listed, names, samba, registry))) => {
                    imp.samba.set(samba);
                    imp.registry.set(registry);
                    *imp.shares.borrow_mut() = listed;
                    *imp.names.borrow_mut() = names;
                    window.remember(&server);
                    window.show();
                }
                Ok(Err(error)) => {
                    let problem = errors::share_problem(&error, &server);
                    imp.error.set_title(&fill(
                        &tr("The shares of {serveur} cannot be read"),
                        &[("serveur", &server)],
                    ));
                    imp.error
                        .set_description(Some(&glib::markup_escape_text(&format!(
                            "{}\n\n{}",
                            problem.message, problem.detail
                        ))));
                    imp.state.set_visible_child_name("erreur");
                }
                Err(_) => {}
            }
        });
    }

    /// A server read keeps its place in the profile and in the list offered.
    fn remember(&self, server: &str) {
        let domain = self.source().profile().domain.clone();
        if let Some(main) = main_window(self) {
            main.remember_file_server(&domain, server);
        }
        let imp = self.imp();
        if !imp.known.borrow().iter().any(|k| k.name == server) {
            imp.known
                .borrow_mut()
                .push(Known::remembered(server.to_owned()));
            self.show_known();
        }
    }

    fn show(&self) {
        let imp = self.imp();
        empty(&imp.shares_list);
        for row in imp.special_rows.take() {
            imp.special_row.remove(&row);
        }
        let listed = imp.shares.borrow().clone();
        let names = imp.names.borrow().clone();
        let mut ordinary = 0;
        let mut special = Vec::new();
        for (index, item) in listed.iter().enumerate() {
            if item.share.is_disk() && !item.share.is_special() {
                imp.shares_list.append(&self.row(index, item, &names));
                ordinary += 1;
            } else {
                special.push(item);
            }
        }
        for item in special {
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&item.share.name).as_str())
                .subtitle(glib::markup_escape_text(&special_subtitle(&item.share)).as_str())
                .subtitle_lines(0)
                .build();
            imp.special_row.add_row(&row);
            imp.special_rows.borrow_mut().push(row);
        }
        let n = imp.special_rows.borrow().len();
        imp.special_group.set_visible(n > 0);
        imp.shares_group
            .set_description(Some(&glib::markup_escape_text(&if listed
                .iter()
                .any(|l| l.share.level != 502)
            {
                tr("This account may only list the shares: paths and permissions are not shown.")
            } else {
                String::new()
            })));
        imp.shares_list.set_visible(ordinary > 0);
        imp.none_label.set_visible(ordinary == 0);
        imp.new_button.set_sensitive(!self.read_only());
        imp.state.set_visible_child_name("contenu");
    }

    fn row(&self, index: usize, item: &Listed, names: &Names) -> adw::ActionRow {
        let row = adw::ActionRow::builder()
            .title(glib::markup_escape_text(&item.share.name).as_str())
            .subtitle(glib::markup_escape_text(&share_subtitle(item, names)).as_str())
            .activatable(!self.read_only())
            .subtitle_lines(0)
            .build();
        row.set_widget_name(&index.to_string());
        // The folders and their NTFS permissions, read-only profile included (J8.4).
        let text = tr("Folders and NTFS permissions");
        let button = gtk::Button::builder()
            .icon_name("folder-open-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(text.as_str())
            .build();
        button.add_css_class("flat");
        button.update_property(&[gtk::accessible::Property::Label(&format!(
            "{text} : {}",
            item.share.name
        ))]);
        let (weak, name) = (self.downgrade(), item.share.name.clone());
        button.connect_clicked(move |_| {
            if let Some(window) = weak.upgrade() {
                window.folders(&name);
            }
        });
        row.add_suffix(&button);
        // Effective access to the root of the share (J8.5), read-only profile included.
        let text = tr("Effective Access");
        let button = gtk::Button::builder()
            .icon_name("avatar-default-symbolic")
            .valign(gtk::Align::Center)
            .tooltip_text(text.as_str())
            .build();
        button.add_css_class("flat");
        button.update_property(&[gtk::accessible::Property::Label(&format!(
            "{text} : {}",
            item.share.name
        ))]);
        let (weak, name) = (self.downgrade(), item.share.name.clone());
        button.connect_clicked(move |_| {
            if let Some(window) = weak.upgrade() {
                window.access(&name);
            }
        });
        row.add_suffix(&button);
        if !self.read_only() && item.share.level == 502 {
            type Handler = fn(&SharesWindow, String);
            let actions: [(&str, String, Handler); 3] = [
                (
                    "system-users-symbolic",
                    tr("Permissions"),
                    Self::permissions,
                ),
                ("document-edit-symbolic", tr("Edit"), Self::edit),
                ("user-trash-symbolic", tr("Delete"), Self::delete),
            ];
            for (icon, text, handler) in actions {
                let button = gtk::Button::builder()
                    .icon_name(icon)
                    .valign(gtk::Align::Center)
                    .tooltip_text(text.as_str())
                    .build();
                button.add_css_class("flat");
                button.update_property(&[gtk::accessible::Property::Label(&format!(
                    "{text} : {}",
                    item.share.name
                ))]);
                let (weak, name) = (self.downgrade(), item.share.name.clone());
                button.connect_clicked(move |_| {
                    if let Some(window) = weak.upgrade() {
                        handler(&window, name.clone());
                    }
                });
                row.add_suffix(&button);
            }
        }
        row
    }

    fn row_activated(&self, row: &gtk::ListBoxRow) {
        if self.read_only() {
            return;
        }
        let name = row
            .widget_name()
            .parse::<usize>()
            .ok()
            .and_then(|i| self.imp().shares.borrow().get(i).cloned())
            .filter(|l| l.share.level == 502)
            .map(|l| l.share.name);
        if let Some(name) = name {
            self.edit(name);
        }
    }

    // --- Writes -----------------------------------------------------------------------------

    fn finished(&self) -> Finished {
        let weak = self.downgrade();
        Rc::new(move |report: Option<&Report>| {
            if let (Some(window), Some(_)) = (weak.upgrade(), report) {
                window.reload();
            }
        })
    }

    fn others(&self, except: Option<&str>) -> Vec<String> {
        self.imp()
            .shares
            .borrow()
            .iter()
            .map(|l| l.share.name.to_lowercase())
            .filter(|n| except.is_none_or(|e| !e.eq_ignore_ascii_case(n)))
            .collect()
    }

    fn new_share(&self) {
        let Some(server) = self.server() else { return };
        if self.read_only() || writes::context(self).is_none() {
            return;
        }
        let imp = self.imp();
        ShareDialog::new(
            server,
            None,
            self.others(None),
            imp.names.borrow().clone(),
            imp.samba.get(),
            imp.samba.get() && !imp.registry.get(),
            self.finished(),
        )
        .present(Some(self));
    }

    /// The share read again just before a dialog or a deletion.
    fn read_again(&self, name: String, then: Then) {
        let Some(server) = self.server() else { return };
        let protection = protection(self.source());
        let weak = self.downgrade();
        let target = server.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || {
                let mut shares = Shares::new(protection);
                let found = sw::read_share(&mut shares, &target, &name);
                shares.close();
                found
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            match read {
                Ok(Ok(Some(spec))) => then(&window, spec),
                Ok(Ok(None)) => {
                    writes::announce(&window, &tr("This share no longer exists."), None);
                    window.reload();
                }
                Ok(Err(error)) => {
                    let problem = errors::share_problem(&error, &server);
                    writes::show_error(
                        &window,
                        &tr("Share cannot be read"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                Err(_) => {}
            }
        });
    }

    fn edit(&self, name: String) {
        self.read_again(
            name,
            Box::new(|window, spec| {
                let Some(server) = window.server() else {
                    return;
                };
                // Options kept by Samba: a share of smb.conf (one of its registry has values).
                let kept = window.imp().samba.get() && spec.registry.is_none();
                ShareDialog::new(
                    server,
                    Some(spec.clone()),
                    window.others(Some(&spec.name)),
                    window.imp().names.borrow().clone(),
                    window.imp().samba.get(),
                    kept,
                    window.finished(),
                )
                .present(Some(window));
            }),
        );
    }

    fn permissions(&self, name: String) {
        self.read_again(
            name,
            Box::new(|window, spec| {
                let Some(server) = window.server() else {
                    return;
                };
                PermissionsDialog::new(
                    window.source().clone(),
                    server,
                    spec,
                    window.imp().names.borrow().clone(),
                    window.finished(),
                )
                .present(Some(window));
            }),
        );
    }

    fn delete(&self, name: String) {
        self.read_again(
            name,
            Box::new(|window, spec| {
                let Some(server) = window.server() else { return };
                let unc = annuaire_core::changes::unc(&server, &spec.name, "");
                let remarks = vec![
                    fill(
                        &tr("Deletion of the share {partage}: the folder {chemin} and its content stay on the server."),
                        &[("partage", &unc), ("chemin", &spec.path)],
                    ),
                    tr("The open connections to the share are cut. Undoing recreates the share with its permissions and options."),
                ];
                let finished = window.finished();
                writes::propose(
                    window,
                    Changeset {
                        operations: vec![Operation::delete_share(&server, spec)],
                        remarks,
                    },
                    Options {
                        destructive: true,
                        finished: Some(Box::new(move |report| finished(report))),
                        ..Options::default()
                    },
                );
            }),
        );
    }

    /// The folders of the share `name` and their NTFS permissions, in a window of their own.
    pub fn folders(&self, name: &str) -> Option<crate::folders::FoldersWindow> {
        let server = self.server()?;
        let window = crate::folders::FoldersWindow::new(
            self.source().clone(),
            &server,
            name,
            protection(self.source()),
            self,
        );
        window.present();
        Some(window)
    }

    /// The effective access of an account to the root of the share `name`.
    pub fn access(&self, name: &str) -> Option<crate::access::AccessDialog> {
        let server = self.server()?;
        let dialog = crate::access::AccessDialog::new(
            self.source().clone(),
            writes::context(self).map(|c| c.connection.clone()),
            &server,
            name,
            "",
            true,
        );
        dialog.present(Some(self));
        Some(dialog)
    }

    /// Called by the common preview after a write (undo by the toast included).
    pub fn after_write(&self, _report: &Report) {
        if self.server().is_some() {
            self.reload();
        }
    }

    // --- Trials ------------------------------------------------------------------------------

    /// The list is shown (trials).
    pub fn trial_ready(&self) -> bool {
        self.imp().state.visible_child_name().as_deref() == Some("contenu")
    }

    /// The page shown: `contenu`, `erreur`, `chargement`, `vide` (trials).
    pub fn trial_state(&self) -> String {
        self.imp()
            .state
            .visible_child_name()
            .map(|s| s.to_string())
            .unwrap_or_default()
    }

    /// The texts shown: each share, then the special ones (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let imp = self.imp();
        let mut out = Vec::new();
        let mut i = 0;
        while let Some(row) = imp.shares_list.row_at_index(i) {
            if let Some(r) = row.downcast_ref::<adw::ActionRow>() {
                out.push(format!(
                    "{} | {}",
                    r.title(),
                    r.subtitle().unwrap_or_default()
                ));
            }
            i += 1;
        }
        for r in imp.special_rows.borrow().iter() {
            out.push(format!(
                "({}) | {}",
                r.title(),
                r.subtitle().unwrap_or_default()
            ));
        }
        out
    }

    /// The servers offered (trials).
    pub fn trial_servers(&self) -> Vec<String> {
        self.imp()
            .known
            .borrow()
            .iter()
            .map(|k| format!("{} | {}", k.name, k.about))
            .collect()
    }

    /// Opens the dialog of a new share, or the one of `name` (trials).
    pub fn trial_open(&self, name: Option<&str>) {
        match name {
            None => self.new_share(),
            Some(name) => self.edit(name.to_owned()),
        }
    }

    /// Opens the permissions of `name` (trials).
    pub fn trial_permissions(&self, name: &str) {
        self.permissions(name.to_owned());
    }

    /// Deletes `name` through the preview (trials).
    pub fn trial_delete(&self, name: &str) {
        self.delete(name.to_owned());
    }
}

/// The SIDs of the ACEs of a descriptor.
fn descriptor_sids(bytes: &[u8]) -> Vec<Sid> {
    annuaire_codecs::sd::SecurityDescriptor::decode(bytes)
        .ok()
        .and_then(|d| d.dacl)
        .map(|a| a.aces.iter().filter_map(|x| x.sid()).collect())
        .unwrap_or_default()
}

/// Path, comment, permissions and options of a share, one per line.
fn share_subtitle(item: &Listed, names: &Names) -> String {
    let share = &item.share;
    let mut lines = Vec::new();
    if !share.path.is_empty() {
        lines.push(share.path.clone());
    }
    if !share.remark.is_empty() {
        lines.push(share.remark.clone());
    }
    if share.level == 502 {
        lines.push(shv::share_permissions_summary(
            share.descriptor.as_deref(),
            Some(names),
        ));
        let mut options = Vec::new();
        if item.flags != 0 {
            options.push(shv::flags_text(item.flags));
        }
        if share.max_uses != u32::MAX {
            options.push(fill(
                &tr_n(
                    "at most {n} connection",
                    "at most {n} connections",
                    u64::from(share.max_uses),
                ),
                &[("n", &share.max_uses.to_string())],
            ));
        }
        if !options.is_empty() {
            lines.push(options.join(", "));
        }
    }
    lines.join("\n")
}

fn special_subtitle(share: &Share) -> String {
    [
        shv::kind_text(share),
        share.path.clone(),
        share.remark.clone(),
    ]
    .into_iter()
    .filter(|t| !t.is_empty())
    .collect::<Vec<_>>()
    .join(" · ")
}

// --- The dialog of a share --------------------------------------------------------------------

mod share_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-partage.ui")]
    pub struct ShareDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub name_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub path_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub remark_entry: TemplateChild<adw::EntryRow>,
        #[template_child]
        pub limit_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub limit_spin: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub options_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub caching_row: TemplateChild<adw::ComboRow>,
        #[template_child]
        pub abe_switch: TemplateChild<adw::SwitchRow>,
        #[template_child]
        pub permissions_row: TemplateChild<adw::ActionRow>,
        #[template_child]
        pub problems_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub problems: TemplateChild<gtk::Label>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub server: RefCell<String>,
        pub origin: RefCell<Option<ShareSpec>>,
        pub others: RefCell<Vec<String>>,
        pub finished: RefCell<Option<Finished>>,
        pub spec: RefCell<Option<ShareSpec>>,
        pub ready: Cell<bool>,
    }

    impl std::fmt::Debug for ShareDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ShareDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for ShareDialog {
        const NAME: &'static str = "AnnuaireDialoguePartage";
        type Type = super::ShareDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::ShareDialog>(&[
                ("changed", |d, _| {
                    d.changed();
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for ShareDialog {}
    impl WidgetImpl for ShareDialog {}
    impl AdwDialogImpl for ShareDialog {}
}

glib::wrapper! {
    /// A share, new (`origin` None) or to modify (`AnnuaireDialoguePartage`).
    pub struct ShareDialog(ObjectSubclass<share_imp::ShareDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

/// Offline caching of `SHARE_INFO_1005`, in the order of the choices of the dialog.
const CACHING: [u32; 4] = [
    flags::CSC_MANUAL,
    flags::CSC_AUTO,
    flags::CSC_VDO,
    flags::CSC_NONE,
];

impl ShareDialog {
    fn new(
        server: String,
        origin: Option<ShareSpec>,
        others: Vec<String>,
        names: Names,
        samba: bool,
        kept: bool,
        finished: Finished,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        // Samba's « access based share enum » hides the share itself (ADR 0023 § 9).
        if samba {
            imp.abe_switch.set_subtitle(&tr(
                "Samba hides the share from the accounts its permissions refuse.",
            ));
        }
        // Said only where Samba keeps the options: a share of smb.conf (J8.7).
        if kept {
            imp.options_group.set_description(Some(&tr(
                "Samba takes the options of this share from smb.conf and keeps them: a change made here is then reported as not applied.",
            )));
        }
        *imp.server.borrow_mut() = server.clone();
        *imp.others.borrow_mut() = others;
        *imp.finished.borrow_mut() = Some(finished);
        match &origin {
            Some(spec) => {
                imp.title
                    .set_subtitle(&glib::markup_escape_text(&annuaire_core::changes::unc(
                        &server, &spec.name, "",
                    )));
                imp.name_entry.set_text(&spec.name);
                imp.name_entry.set_editable(false);
                imp.name_entry.set_tooltip_text(Some(&tr(
                    "A share cannot be renamed: create another one and delete this one.",
                )));
                imp.path_entry.set_text(&spec.path);
                imp.remark_entry.set_text(&spec.remark);
                if spec.max_uses != u32::MAX {
                    imp.limit_switch.set_active(true);
                    imp.limit_spin.set_value(f64::from(spec.max_uses));
                }
                let csc = spec.flags & flags::CSC_MASK;
                let index = CACHING.iter().position(|c| *c == csc).unwrap_or(0);
                imp.caching_row.set_selected(index as u32);
                imp.abe_switch
                    .set_active(spec.flags & flags::ACCESS_BASED_DIRECTORY_ENUM != 0);
                imp.permissions_row.set_title(&glib::markup_escape_text(
                    &shv::share_permissions_summary(spec.descriptor.as_deref(), Some(&names)),
                ));
                imp.permissions_row
                    .set_subtitle(&tr("Changed with “Permissions” in the list of the shares."));
                dialog.set_focus(Some(&*imp.path_entry));
            }
            None => {
                imp.title.set_subtitle(&fill(
                    &tr("New share on {serveur}"),
                    &[("serveur", &server)],
                ));
                imp.permissions_row
                    .set_title(&shv::share_permissions_summary(None, None));
                imp.permissions_row.set_subtitle(&tr(
                    "Change them after the creation with “Permissions”. The NTFS permissions of the folder apply too.",
                ));
            }
        }
        *imp.origin.borrow_mut() = origin;
        imp.ready.set(true);
        dialog.changed();
        dialog
    }

    /// The share typed, or the reasons that prevent writing it.
    fn read(&self) -> Result<ShareSpec, Vec<String>> {
        let imp = self.imp();
        let mut errors = Vec::new();
        let origin = imp.origin.borrow().clone();
        let name = imp.name_entry.text().trim().to_owned();
        if origin.is_none() {
            if let Some(problem) = shv::share_name_problem(&name) {
                errors.push(problem);
            } else if imp.others.borrow().contains(&name.to_lowercase()) {
                errors.push(tr("A share with this name already exists on this server."));
            }
        }
        let path = imp.path_entry.text().trim().to_owned();
        if path.is_empty() {
            errors.push(tr("The folder on the server is not given."));
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        let base = origin.clone().unwrap_or(ShareSpec {
            max_uses: u32::MAX,
            ..ShareSpec::default()
        });
        let csc = CACHING
            .get(imp.caching_row.selected() as usize)
            .copied()
            .unwrap_or(flags::CSC_MANUAL);
        let abe = if imp.abe_switch.is_active() {
            flags::ACCESS_BASED_DIRECTORY_ENUM
        } else {
            0
        };
        let spec = ShareSpec {
            name: origin.as_ref().map_or(name, |o| o.name.clone()),
            path,
            remark: imp.remark_entry.text().to_string(),
            max_uses: if imp.limit_switch.is_active() {
                imp.limit_spin.value() as u32
            } else {
                u32::MAX
            },
            flags: (base.flags & !(flags::CSC_MASK | flags::ACCESS_BASED_DIRECTORY_ENUM))
                | csc
                | abe,
            descriptor: base.descriptor.clone(),
            registry: base.registry.clone(),
        };
        if origin.as_ref() == Some(&spec) {
            return Err(vec![tr("Nothing has changed.")]);
        }
        Ok(spec)
    }

    fn changed(&self) {
        let imp = self.imp();
        if !imp.ready.get() {
            return;
        }
        let read = self.read();
        let errors = read.as_ref().err().cloned().unwrap_or_default();
        imp.problems.set_label(&errors.join("\n"));
        imp.problems_group.set_visible(!errors.is_empty());
        imp.continue_button.set_sensitive(read.is_ok());
        *imp.spec.borrow_mut() = read.ok();
    }

    fn proceed(&self) {
        self.changed();
        let imp = self.imp();
        let Some(spec) = imp.spec.borrow().clone() else {
            return;
        };
        let server = imp.server.borrow().clone();
        let (operation, remarks) = match imp.origin.borrow().clone() {
            None => (
                Operation::add_share(&server, spec.clone()),
                vec![fill(
                    &tr("The folder {chemin} must exist on {serveur}: Calinda does not create it."),
                    &[("chemin", &spec.path), ("serveur", &server)],
                )],
            ),
            Some(origin) => (Operation::change_share(&server, origin, spec), Vec::new()),
        };
        let weak = self.downgrade();
        writes::propose(
            self,
            Changeset {
                operations: vec![operation],
                remarks,
            },
            Options {
                finished: Some(Box::new(move |report| {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.written(report);
                    }
                })),
                ..Options::default()
            },
        );
    }

    /// The preview closed without writing leaves the dialog open.
    fn written(&self, report: Option<&Report>) {
        if report.is_none() {
            return;
        }
        let finished = self.imp().finished.take();
        self.close();
        if let Some(finished) = finished {
            finished(report);
        }
    }

    /// Fills the dialog and continues (trials).
    pub fn trial(&self, name: Option<&str>, path: Option<&str>, remark: Option<&str>) {
        let imp = self.imp();
        if let Some(name) = name {
            imp.name_entry.set_text(name);
        }
        if let Some(path) = path {
            imp.path_entry.set_text(path);
        }
        if let Some(remark) = remark {
            imp.remark_entry.set_text(remark);
        }
        self.proceed();
    }

    /// The problems shown (trials).
    pub fn trial_problems(&self) -> String {
        self.imp().problems.label().to_string()
    }

    /// Sets the limit (0: none), the offline caching (index of the choices) and the
    /// access-based enumeration (trials, J8.7).
    pub fn trial_options(&self, limit: u32, caching: u32, abe: bool) {
        let imp = self.imp();
        imp.limit_switch.set_active(limit != 0);
        if limit != 0 {
            imp.limit_spin.set_value(f64::from(limit));
        }
        imp.caching_row.set_selected(caching);
        imp.abe_switch.set_active(abe);
    }

    /// The note of the options group: what Samba keeps, or nothing (trials, J8.7).
    pub fn trial_note(&self) -> String {
        self.imp()
            .options_group
            .description()
            .map(|d| d.to_string())
            .unwrap_or_default()
    }
}

// --- The dialog of the permissions of a share ---------------------------------------------------

mod rights_imp {
    use super::*;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dialogue-partage-droits.ui")]
    pub struct PermissionsDialog {
        #[template_child]
        pub title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub principals_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub nobody_label: TemplateChild<gtk::Label>,
        #[template_child]
        pub principal_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub candidates_list: TemplateChild<gtk::ListBox>,
        #[template_child]
        pub candidates_count: TemplateChild<gtk::Label>,
        #[template_child]
        pub problems_group: TemplateChild<adw::PreferencesGroup>,
        #[template_child]
        pub problems: TemplateChild<gtk::Label>,
        #[template_child]
        pub continue_button: TemplateChild<gtk::Button>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub server: RefCell<String>,
        pub before: RefCell<ShareSpec>,
        pub entries: RefCell<Vec<ShareEntry>>,
        pub names: RefCell<Names>,
        pub finished: RefCell<Option<Finished>>,
        pub search: RefCell<Option<Rc<Feed>>>,
        pub received: RefCell<Vec<(ElementView, Option<Sid>)>>,
        pub after: RefCell<Option<Vec<u8>>>,
    }

    impl std::fmt::Debug for PermissionsDialog {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PermissionsDialog").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for PermissionsDialog {
        const NAME: &'static str = "AnnuaireDialoguePartageDroits";
        type Type = super::PermissionsDialog;
        type ParentType = adw::Dialog;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::PermissionsDialog>(&[
                ("search", |d, _| {
                    d.search();
                    None
                }),
                ("add_everyone", |d, _| {
                    d.add_well_known("S-1-1-0");
                    None
                }),
                ("add_authenticated", |d, _| {
                    d.add_well_known("S-1-5-11");
                    None
                }),
                ("add_administrators", |d, _| {
                    d.add_well_known("S-1-5-32-544");
                    None
                }),
                ("cancel", |d, _| {
                    d.close();
                    None
                }),
                ("next", |d, _| {
                    d.proceed();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for PermissionsDialog {}
    impl WidgetImpl for PermissionsDialog {}

    impl AdwDialogImpl for PermissionsDialog {
        fn closed(&self) {
            self.obj().stop();
            self.parent_closed();
        }
    }
}

glib::wrapper! {
    /// The permissions of a share, as the « Share » tab of Windows
    /// (`AnnuaireDialoguePartageDroits`).
    pub struct PermissionsDialog(ObjectSubclass<rights_imp::PermissionsDialog>)
        @extends adw::Dialog, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::ShortcutManager;
}

/// The choices of « Allowed » and « Denied »: none, then the three levels, then « Special
/// permissions » when the mask read is none of them (kept as is).
fn level_choices(current: Option<ShareLevel>) -> Vec<(Option<ShareLevel>, String)> {
    let mut choices = vec![(None, tr("None"))];
    choices.extend(
        shv::SHARE_LEVELS
            .iter()
            .map(|l| (Some(*l), shv::share_level_text(*l))),
    );
    if current == Some(ShareLevel::Special) {
        choices.push((current, shv::share_level_text(ShareLevel::Special)));
    }
    choices
}

impl PermissionsDialog {
    fn new(
        source: Arc<dyn Source>,
        server: String,
        before: ShareSpec,
        names: Names,
        finished: Finished,
    ) -> Self {
        let dialog: Self = glib::Object::new();
        let imp = dialog.imp();
        let _ = imp.source.set(source);
        imp.title
            .set_subtitle(&glib::markup_escape_text(&annuaire_core::changes::unc(
                &server,
                &before.name,
                "",
            )));
        *imp.server.borrow_mut() = server;
        *imp.entries.borrow_mut() = shv::share_entries(before.descriptor.as_deref());
        *imp.before.borrow_mut() = before;
        *imp.names.borrow_mut() = names;
        *imp.finished.borrow_mut() = Some(finished);
        let weak = dialog.downgrade();
        imp.candidates_list.connect_row_activated(move |_, row| {
            if let Some(dialog) = weak.upgrade() {
                dialog.chosen(row);
            }
        });
        dialog.show_entries();
        dialog
    }

    fn source(&self) -> Arc<dyn Source> {
        self.imp().source.get().expect("set by new").clone()
    }

    fn show_entries(&self) {
        let imp = self.imp();
        empty(&imp.principals_list);
        let entries = imp.entries.borrow().clone();
        let names = imp.names.borrow().clone();
        for (index, entry) in entries.iter().enumerate() {
            let name = sv::sid_name(&entry.sid, Some(&names));
            let row = adw::ActionRow::builder()
                .title(glib::markup_escape_text(&name).as_str())
                .subtitle(entry.sid.to_string())
                .build();
            for (deny, label) in [(false, tr("Allowed")), (true, tr("Denied"))] {
                let current = if deny { entry.deny } else { entry.allow };
                let choices = level_choices(current);
                let texts: Vec<&str> = choices.iter().map(|(_, t)| t.as_str()).collect();
                let choice = gtk::DropDown::from_strings(&texts);
                choice.set_valign(gtk::Align::Center);
                choice.set_tooltip_text(Some(&label));
                choice.update_property(&[gtk::accessible::Property::Label(&fill(
                    &tr("{etat} for {nom}"),
                    &[("etat", &label), ("nom", &name)],
                ))]);
                let selected = choices.iter().position(|(l, _)| *l == current).unwrap_or(0);
                choice.set_selected(selected as u32);
                let box_ = gtk::Box::new(gtk::Orientation::Vertical, 2);
                let caption = gtk::Label::new(Some(&label));
                caption.add_css_class("caption");
                caption.add_css_class("dim-label");
                box_.append(&caption);
                box_.append(&choice);
                box_.set_valign(gtk::Align::Center);
                let weak = self.downgrade();
                choice.connect_selected_notify(move |d| {
                    let Some(dialog) = weak.upgrade() else { return };
                    let level = choices.get(d.selected() as usize).and_then(|(l, _)| *l);
                    if let Some(e) = dialog.imp().entries.borrow_mut().get_mut(index) {
                        if deny {
                            e.deny = level;
                        } else {
                            e.allow = level;
                        }
                    }
                    dialog.changed();
                });
                row.add_suffix(&box_);
            }
            let button = gtk::Button::builder()
                .icon_name("list-remove-symbolic")
                .valign(gtk::Align::Center)
                .tooltip_text(tr("Remove"))
                .build();
            button.add_css_class("flat");
            button.update_property(&[gtk::accessible::Property::Label(&fill(
                &tr("Remove: {nom}"),
                &[("nom", &name)],
            ))]);
            let weak = self.downgrade();
            button.connect_clicked(move |_| {
                if let Some(dialog) = weak.upgrade() {
                    let mut entries = dialog.imp().entries.borrow_mut();
                    if index < entries.len() {
                        entries.remove(index);
                    }
                    drop(entries);
                    dialog.show_entries();
                }
            });
            row.add_suffix(&button);
            imp.principals_list.append(&row);
        }
        imp.principals_list.set_visible(!entries.is_empty());
        self.changed();
    }

    fn add(&self, sid: Sid) {
        let imp = self.imp();
        let known = imp.entries.borrow().iter().any(|e| e.sid == sid);
        if !known {
            imp.entries
                .borrow_mut()
                .push(ShareEntry::new(sid, Some(ShareLevel::Read)));
        }
        self.show_entries();
    }

    fn add_well_known(&self, text: &str) {
        if let Ok(sid) = text.parse::<Sid>() {
            self.add(sid);
        }
    }

    /// The descriptor of the choices, or why it cannot be written.
    fn read(&self) -> Result<Vec<u8>, String> {
        let imp = self.imp();
        let before = imp.before.borrow();
        let entries = imp.entries.borrow();
        let Some(after) = shv::share_descriptor(before.descriptor.as_deref(), &entries) else {
            return Err(tr("These permissions cannot be encoded."));
        };
        if sw::same_share_descriptor(before.descriptor.as_deref(), Some(&after)) {
            return Err(tr("Nothing has changed."));
        }
        Ok(after)
    }

    fn changed(&self) {
        let imp = self.imp();
        let nobody = imp
            .entries
            .borrow()
            .iter()
            .all(|e| e.allow.is_none() || e.deny.is_some());
        imp.nobody_label.set_visible(nobody);
        let read = self.read();
        let error = read.as_ref().err().cloned().unwrap_or_default();
        imp.problems.set_label(&error);
        imp.problems_group.set_visible(!error.is_empty());
        imp.continue_button.set_sensitive(read.is_ok());
        *imp.after.borrow_mut() = read.ok();
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
                            .append(&candidate_row(&view, &tr("Add")));
                    }
                    imp.received.borrow_mut().push((view, object_sid(item)));
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

    fn chosen(&self, row: &gtk::ListBoxRow) {
        let imp = self.imp();
        let dn = row.widget_name().to_string();
        let found = imp
            .received
            .borrow()
            .iter()
            .find(|(v, _)| v.dn == dn)
            .cloned();
        let Some((view, sid)) = found else { return };
        imp.principal_entry.set_text("");
        let (title, target) = (view.title.clone(), view.dn.clone());
        let name = move |dialog: &Self, sid: Sid| {
            dialog.imp().names.borrow_mut().insert(
                sid,
                annuaire_core::security::SidName {
                    sid,
                    name: title.clone(),
                    dn: target.clone(),
                    classes: Vec::new(),
                },
            );
            dialog.add(sid);
        };
        if let Some(sid) = sid {
            name(self, sid);
            return;
        }
        // The local copy may not carry the SID: it is read on the DC.
        let (source, weak) = (self.source(), self.downgrade());
        let target = view.dn.clone();
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.record(&target, &["objectSid"])).await;
            let Some(dialog) = weak.upgrade() else { return };
            match read {
                Ok(Ok(Some(record))) => {
                    if let Some(sid) = record
                        .values("objectSid")
                        .first()
                        .and_then(|v| Sid::decode(v).ok())
                    {
                        name(&dialog, sid);
                    }
                }
                Ok(Err(failure)) => {
                    let domain = dialog.source().profile().domain.clone();
                    let problem = errors::failure_problem(&failure, &domain);
                    writes::show_error(
                        &dialog,
                        &tr("Unreadable SID"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                _ => {}
            }
        });
    }

    fn proceed(&self) {
        self.changed();
        let imp = self.imp();
        let Some(descriptor) = imp.after.borrow().clone() else {
            return;
        };
        let before = imp.before.borrow().clone();
        let server = imp.server.borrow().clone();
        let mut after = before.clone();
        after.descriptor = Some(descriptor);
        let unc = annuaire_core::changes::unc(&server, &before.name, "");
        let mut remarks = vec![fill(
            &tr(
                "Permissions of the share {partage}; the NTFS permissions of its folder do not change.",
            ),
            &[("partage", &unc)],
        )];
        if imp.nobody_label.is_visible() {
            remarks.push(tr("Nobody will be able to open the share."));
        }
        let weak = self.downgrade();
        writes::propose(
            self,
            Changeset {
                operations: vec![Operation::change_share(&server, before, after)],
                remarks,
            },
            Options {
                finished: Some(Box::new(move |report| {
                    if let Some(dialog) = weak.upgrade() {
                        dialog.written(report);
                    }
                })),
                ..Options::default()
            },
        );
    }

    fn written(&self, report: Option<&Report>) {
        if report.is_none() {
            return;
        }
        let finished = self.imp().finished.take();
        self.close();
        if let Some(finished) = finished {
            finished(report);
        }
    }

    /// The groups and accounts shown, with their levels (trials).
    pub fn trial_rows(&self) -> Vec<String> {
        let names = self.imp().names.borrow().clone();
        self.imp()
            .entries
            .borrow()
            .iter()
            .map(|e| {
                let level =
                    |l: Option<ShareLevel>| l.map_or_else(|| "-".into(), shv::share_level_text);
                format!(
                    "{} | {} | {}",
                    sv::sid_name(&e.sid, Some(&names)),
                    level(e.allow),
                    level(e.deny)
                )
            })
            .collect()
    }

    /// Adds a well-known identity with Read, or removes every entry of `sid`; then continues
    /// if `proceed` (trials).
    pub fn trial(&self, add: Option<&str>, remove: Option<&str>, proceed: bool) {
        if let Some(sid) = add {
            self.add_well_known(sid);
        }
        if let Some(sid) = remove.and_then(|s| s.parse::<Sid>().ok()) {
            self.imp().entries.borrow_mut().retain(|e| e.sid != sid);
            self.show_entries();
        }
        if proceed {
            self.proceed();
        }
    }
}

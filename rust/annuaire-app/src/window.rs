// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Main window (J2.1, J2.2, `annuaire.ui.fenetre`), structure in `fenetre.blp`: the home
//! screen (profiles, ticket) and the open domain, with the tree of containers and the table.
//! R4.1 and R4.2: the home screen and its dialogs; R4.3: the window of the domain, read
//! directly on the DC (`domain`).

mod accounts;
mod domain;
mod focus;

use adw::prelude::*;
use adw::subclass::prelude::*;
use gtk::{gio, glib};

use std::rc::Rc;
use std::sync::Arc;

use annuaire_core::cache::{Pages, Source};
use annuaire_core::kerberos::{Ticket, realm_of_domain};
use annuaire_core::profile::Profile;
use annuaire_core::source::Notifier;
use annuaire_core::storage;

use crate::config;
use crate::dialogs::{ProfileDialog, TicketDialog};
use crate::i18n::{fill, tr};
use crate::settings::ProfileStore;

mod imp {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;
    use std::sync::Arc;

    use adw::subclass::prelude::*;
    use annuaire_codecs::time::UtcTime;
    use annuaire_core::cache::{Source, SyncState};
    use annuaire_core::profile::Profile;
    use gtk::prelude::*;
    use gtk::{gio, glib};

    use crate::feed::Feed;
    use crate::home::Home;
    use crate::objects::Children;
    use crate::scope::TemplateScope;
    use crate::search::Search;
    use crate::settings::ProfileStore;
    use crate::views::SortedKeys;

    #[derive(Debug, Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/fenetre.ui")]
    pub struct Window {
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        #[template_child]
        pub stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub home: TemplateChild<Home>,
        #[template_child]
        pub search: TemplateChild<Search>,
        #[template_child]
        pub split_view: TemplateChild<adw::NavigationSplitView>,
        #[template_child]
        pub domain_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub tree: TemplateChild<gtk::ListView>,
        #[template_child]
        pub tree_selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub content_page: TemplateChild<adw::NavigationPage>,
        #[template_child]
        pub content_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub filter_bar: TemplateChild<gtk::SearchBar>,
        #[template_child]
        pub filter_entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub content_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub table: TemplateChild<gtk::ColumnView>,
        #[template_child]
        pub selection: TemplateChild<gtk::MultiSelection>,
        #[template_child]
        pub filter: TemplateChild<gtk::FilterListModel>,
        #[template_child]
        pub quick_filter: TemplateChild<gtk::CustomFilter>,
        #[template_child]
        pub content_store: TemplateChild<gio::ListStore>,
        #[template_child]
        pub name_column: TemplateChild<gtk::ColumnViewColumn>,
        #[template_child]
        pub location_column: TemplateChild<gtk::ColumnViewColumn>,
        #[template_child]
        pub empty_page: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub content_error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub loading: TemplateChild<gtk::Spinner>,
        #[template_child]
        pub counter: TemplateChild<gtk::Label>,
        #[template_child]
        pub freshness: TemplateChild<gtk::Label>,
        #[template_child]
        pub actions_menu: TemplateChild<gtk::gio::MenuModel>,
        /// Context menu of the table (right click, Menu, Shift+F10).
        pub context_menu: RefCell<Option<gtk::PopoverMenu>>,
        pub settings: OnceCell<gtk::gio::Settings>,
        pub store: OnceCell<ProfileStore>,
        /// The open domain: its source and its profile (`source`, `profil`).
        pub source: RefCell<Option<Arc<dyn Source>>>,
        pub profile: RefCell<Option<Profile>>,
        /// Local copy (JC.2): date of the copy that served the table (None: read on the DC),
        /// last state of the copy, timer of the deltas.
        pub shown_date: Cell<Option<UtcTime>>,
        pub sync_state: RefCell<Option<SyncState>>,
        pub timer: RefCell<Option<glib::SourceId>>,
        /// Context of the writes and of the group policies (connection to the PDC emulator,
        /// journal), opened at first need (`ContexteEcriture`, ADR 0012).
        pub writes: RefCell<Option<Arc<crate::writes::WriteContext>>>,
        /// Children models of the tree, by DN; feeds of the tree and of the table.
        pub children: RefCell<HashMap<String, Children>>,
        pub tree_feeds: RefCell<Vec<Rc<Feed>>>,
        pub content_feed: RefCell<Option<Rc<Feed>>>,
        /// What the table shows (`Contenu`).
        pub content: RefCell<Option<super::Content>>,
        pub keys: RefCell<SortedKeys>,
        /// Words of the quick filter (shared with the filter function).
        pub terms: Rc<RefCell<Vec<String>>>,
        /// Applications already read again after a write (`_relus`).
        pub reread_ids: RefCell<std::collections::HashSet<String>>,
        /// The DNS window of the open domain, one at a time (`_dns`).
        pub dns: RefCell<Option<crate::dns::DnsWindow>>,
        /// The « Group Policy » and « Password Policies » windows, one at a time each.
        pub gpo: RefCell<Option<crate::gpo::GpoWindow>>,
        pub pso: RefCell<Option<crate::pso::PsoWindow>>,
        /// Keyboard focus (`_Focus`): zone (table, tree) the visible dialog was opened from,
        /// and zone of the last focus known.
        pub focus_zone: RefCell<Option<gtk::Widget>>,
        pub focus_last: RefCell<Option<gtk::Widget>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Window {
        const NAME: &'static str = "AnnuaireFenetre";
        type Type = super::Window;
        type ParentType = adw::ApplicationWindow;

        fn class_init(klass: &mut Self::Class) {
            Home::ensure_type();
            Search::ensure_type();
            crate::objects::ensure_types();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::Window>(&[
                ("node_selected", |w, _| {
                    w.node_chosen();
                    None
                }),
                ("filter_changed", |w, _| {
                    w.filter_changed();
                    None
                }),
                ("row_activated", |w, args| {
                    if let Some(position) = args.get(1).and_then(|v| v.get::<u32>().ok()) {
                        w.row_activated(position);
                    }
                    None
                }),
                ("count", |w, _| {
                    w.count();
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for Window {
        fn constructed(&self) {
            self.parent_constructed();
            self.obj().setup();
        }
    }

    impl WidgetImpl for Window {}

    impl WindowImpl for Window {
        fn close_request(&self) -> glib::Propagation {
            self.obj().save_size();
            self.obj().close_domain();
            self.parent_close_request()
        }
    }

    impl ApplicationWindowImpl for Window {}
    impl AdwApplicationWindowImpl for Window {}
}

glib::wrapper! {
    pub struct Window(ObjectSubclass<imp::Window>)
        @extends adw::ApplicationWindow, gtk::ApplicationWindow, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

/// How a content is read: from the source of the domain, with the notifier of its flux.
pub type Read = Rc<dyn Fn(&Arc<dyn Source>, Notifier) -> Pages>;

/// What follows a reading ended without error.
pub type Finished = Rc<dyn Fn(&Window)>;

/// What the table shows (`Contenu`): a title, whether it is a search (the location column is
/// shown, the empty state says « no results »), and how to read it, again at each refresh.
#[derive(Clone)]
pub struct Content {
    pub title: String,
    pub search: bool,
    pub read: Read,
    /// Called once the reading ended without error (activity survey: the DCs that failed).
    pub finished: Option<Finished>,
    /// DN of the container whose content the table shows; None for a search.
    pub container: Option<String>,
    /// A row read again keeps its activity (survey on every DC: `ligne_relue_avec_activite`).
    pub keep_activity: bool,
}

impl std::fmt::Debug for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Content")
            .field("title", &self.title)
            .field("search", &self.search)
            .finish_non_exhaustive()
    }
}

/// What follows an obtained ticket (opening the domain again).
type Then = Box<dyn Fn(&Window)>;

impl Window {
    pub fn new(application: &adw::Application) -> Self {
        glib::Object::builder()
            .property("application", application)
            .build()
    }

    fn settings(&self) -> &gio::Settings {
        self.imp().settings.get_or_init(config::settings)
    }

    /// The settings of the application (searches saved, number of days).
    pub fn app_settings(&self) -> gio::Settings {
        self.settings().clone()
    }

    fn store(&self) -> &ProfileStore {
        self.imp()
            .store
            .get_or_init(|| ProfileStore::new(self.settings().clone()))
    }

    fn setup(&self) {
        let settings = self.settings();
        self.set_default_size(settings.int("window-width"), settings.int("window-height"));
        if settings.boolean("window-maximized") {
            self.maximize();
        }
        self.install_actions();
        self.setup_domain();
        self.setup_accounts();
        self.setup_focus();
        crate::a11y::name_menus(self);
        self.imp().search.show_saved();
        let home = &self.imp().home;
        home.show_profiles(&self.store().list());
        home.refresh_ticket();
    }

    fn install_actions(&self) {
        type Handler = fn(&Window, Option<String>);
        let actions: [(&str, bool, Handler); 16] = [
            ("rechercher", false, |w, _| w.focus_search()),
            // Menu entry « Undo the last change… » (`clavier.annuler_derniere`).
            ("annuler-derniere", false, |w, _| {
                crate::history::undo_last(w)
            }),
            ("gpo", false, |w, _| {
                w.open_gpo();
            }),
            ("pso", false, |w, _| {
                w.open_pso();
            }),
            ("historique", false, |w, _| w.show_history()),
            ("dns", false, |w, _| {
                w.open_dns();
            }),
            ("sante-dns", false, |w, _| w.open_dns_health()),
            ("ouvrir-profil", true, |w, d| {
                if let Some(p) = w.profile(d.as_deref()) {
                    w.open_domain(p);
                }
            }),
            ("changer-domaine", false, |w, _| w.close_domain()),
            ("actualiser", false, |w, _| w.refresh()),
            ("ajouter-domaine", false, |w, _| w.edit_profile(None)),
            ("obtenir-ticket", false, |w, _| w.ask_ticket(None)),
            ("modifier-profil", true, |w, d| {
                if let Some(p) = w.profile(d.as_deref()) {
                    w.edit_profile(Some(&p));
                }
            }),
            ("ticket-profil", true, |w, d| {
                if let Some(p) = w.profile(d.as_deref()) {
                    w.ask_ticket(Some(&p));
                }
            }),
            ("supprimer-profil", true, |w, d| {
                if let Some(p) = w.profile(d.as_deref()) {
                    w.delete_profile(&p);
                }
            }),
            ("effacer-copie", true, |w, d| {
                if let Some(d) = d {
                    w.erase_copy(&d);
                }
            }),
        ];
        for (name, with_domain, handler) in actions {
            let action =
                gio::SimpleAction::new(name, with_domain.then_some(glib::VariantTy::STRING));
            let weak = self.downgrade();
            action.connect_activate(move |_, parameter| {
                if let Some(window) = weak.upgrade() {
                    handler(&window, parameter.and_then(|p| p.str().map(str::to_owned)));
                }
            });
            self.add_action(&action);
        }
        // Ctrl+N on the home screen, F5 on the domain, when no dialog is shown
        // (`clavier.installer`).
        let controller = gtk::ShortcutController::new();
        controller.set_propagation_phase(gtk::PropagationPhase::Bubble);
        for (trigger, action, page) in [
            ("<Control>n", "win.ajouter-domaine", "accueil"),
            ("F5", "win.actualiser", "domaine"),
            ("<Control>h", "win.historique", "domaine"),
            ("<Control>d", "win.dns", "domaine"),
            ("<Shift><Control>d", "win.sante-dns", "domaine"),
            ("<Control>g", "win.gpo", "domaine"),
            ("<Control>m", "win.pso", "domaine"),
        ] {
            let weak = self.downgrade();
            let callback = gtk::CallbackAction::new(move |_, _| {
                weak.upgrade()
                    .is_some_and(|window| {
                        window.visible_dialog().is_none()
                            && window.imp().stack.visible_child_name().as_deref() == Some(page)
                            && WidgetExt::activate_action(&window, action, None).is_ok()
                    })
                    .into()
            });
            controller.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(callback),
            ));
        }
        // Ctrl+Z undoes the last change of the journal; not while a field has the focus, which
        // has its own Ctrl+Z (`clavier.annuler_derniere`).
        let weak = self.downgrade();
        controller.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("<Control>z"),
            Some(gtk::CallbackAction::new(move |_, _| {
                let Some(window) = weak.upgrade() else {
                    return glib::Propagation::Proceed;
                };
                let free = window.visible_dialog().is_none()
                    && window.imp().stack.visible_child_name().as_deref() == Some("domaine")
                    && !GtkWindowExt::focus(&window).is_some_and(|f| {
                        f.is::<gtk::Editable>() || f.ancestor(gtk::Text::static_type()).is_some()
                    });
                if free {
                    crate::history::undo_last(&window);
                }
                free.into()
            })),
        ));
        self.add_controller(controller);
    }

    /// « Group Policy » window of the open domain (J5.2), one at a time (`ouvrir_gpo`).
    fn open_gpo(&self) -> Option<crate::gpo::GpoWindow> {
        let source = self.source()?;
        let imp = self.imp();
        let current = imp.gpo.borrow().clone();
        let window = match current {
            Some(w) if std::ptr::addr_eq(Arc::as_ptr(w.source()), Arc::as_ptr(&source)) => w,
            other => {
                if let Some(old) = other {
                    old.close();
                }
                let w = crate::gpo::GpoWindow::new(source, self);
                let weak = self.downgrade();
                w.connect_close_request(move |closed| {
                    if let Some(window) = weak.upgrade() {
                        let mut kept = window.imp().gpo.borrow_mut();
                        if kept.as_ref() == Some(closed) {
                            kept.take();
                        }
                    }
                    glib::Propagation::Proceed
                });
                *imp.gpo.borrow_mut() = Some(w.clone());
                w
            }
        };
        window.present();
        Some(window)
    }

    /// The « Group Policy » window, if open (trials).
    pub fn imp_gpo(&self) -> Option<crate::gpo::GpoWindow> {
        self.imp().gpo.borrow().clone()
    }

    /// « Password Policies » window of the open domain, one at a time (`ouvrir_pso`).
    fn open_pso(&self) -> Option<crate::pso::PsoWindow> {
        let source = self.source()?;
        let imp = self.imp();
        let current = imp.pso.borrow().clone();
        let window = match current {
            Some(w) if std::ptr::addr_eq(Arc::as_ptr(w.source()), Arc::as_ptr(&source)) => w,
            other => {
                if let Some(old) = other {
                    old.close();
                }
                let w = crate::pso::PsoWindow::new(source, self);
                let weak = self.downgrade();
                w.connect_close_request(move |closed| {
                    if let Some(window) = weak.upgrade() {
                        let mut kept = window.imp().pso.borrow_mut();
                        if kept.as_ref() == Some(closed) {
                            kept.take();
                        }
                    }
                    glib::Propagation::Proceed
                });
                *imp.pso.borrow_mut() = Some(w.clone());
                w
            }
        };
        window.present();
        Some(window)
    }

    /// The « Password Policies » window, if open (trials).
    pub fn imp_pso(&self) -> Option<crate::pso::PsoWindow> {
        self.imp().pso.borrow().clone()
    }

    /// DNS window of the open domain (J3.3), one at a time (`ouvrir_dns`).
    fn open_dns(&self) -> Option<crate::dns::DnsWindow> {
        let source = self.source()?;
        let imp = self.imp();
        let current = imp.dns.borrow().clone();
        let window = match current {
            Some(w) if std::ptr::addr_eq(Arc::as_ptr(w.source()), Arc::as_ptr(&source)) => w,
            other => {
                if let Some(old) = other {
                    old.close();
                }
                let w = crate::dns::DnsWindow::new(source, self);
                let weak = self.downgrade();
                w.connect_close_request(move |closed| {
                    if let Some(window) = weak.upgrade() {
                        let mut kept = window.imp().dns.borrow_mut();
                        if kept.as_ref() == Some(closed) {
                            kept.take();
                        }
                    }
                    glib::Propagation::Proceed
                });
                *imp.dns.borrow_mut() = Some(w.clone());
                w
            }
        };
        window.present();
        Some(window)
    }

    /// The DNS window, if open (trials).
    pub fn imp_dns(&self) -> Option<crate::dns::DnsWindow> {
        self.imp().dns.borrow().clone()
    }

    /// « DNS health » (J3.5): it depends on the DNS window, opened first (`ouvrir_sante_dns`).
    fn open_dns_health(&self) {
        if let Some(dns) = self.open_dns() {
            dns.open_health();
        }
    }

    pub fn toast(&self, text: &str) {
        self.imp().toasts.add_toast(adw::Toast::new(text));
    }

    fn profile(&self, domain: Option<&str>) -> Option<Profile> {
        let domain = domain?;
        self.store().list().into_iter().find(|p| p.domain == domain)
    }

    fn show_profiles(&self) {
        self.imp().home.show_profiles(&self.store().list());
    }

    fn edit_profile(&self, profile: Option<&Profile>) {
        let weak = self.downgrade();
        let saved = Box::new(move |new: &Profile| {
            if let Some(window) = weak.upgrade() {
                window.show_profiles();
                window.toast(&fill(
                    &tr("Profile {domaine} saved."),
                    &[("domaine", &new.domain)],
                ));
            }
        });
        ProfileDialog::new(self.store().clone(), profile, saved).present(Some(self));
    }

    fn delete_profile(&self, profile: &Profile) {
        let alert = adw::AlertDialog::new(
            Some(&fill(
                &tr("Delete the profile {domaine}?"),
                &[("domaine", &profile.domain)],
            )),
            Some(&tr(
                "Only the profile and its local copy are deleted from this computer; the directory is not modified.",
            )),
        );
        alert.add_response("annuler", &tr("Cancel"));
        alert.add_response("supprimer", &tr("Delete"));
        alert.set_response_appearance("supprimer", adw::ResponseAppearance::Destructive);
        let (weak, domain) = (self.downgrade(), profile.domain.clone());
        alert.connect_response(None, move |_, response| {
            let Some(window) = weak.upgrade() else { return };
            if response == "supprimer" {
                window.store().remove(&domain);
                let _ = storage::erase(&storage::cache_path(&domain, None));
                window.show_profiles();
            }
        });
        alert.present(Some(self));
    }

    /// Erases the local copy of a domain (JC.4); it is made again at the next opening if the
    /// profile keeps it.
    fn erase_copy(&self, domain: &str) {
        let erased = storage::erase(&storage::cache_path(domain, None)).unwrap_or(false);
        let text = if erased {
            tr("Local copy of {domaine} erased.")
        } else {
            tr("No local copy for {domaine}.")
        };
        self.toast(&fill(&text, &[("domaine", domain)]));
    }

    /// The ticket dialog, for the realm of the profile when there is one; `then` runs once
    /// the ticket is obtained (opening the domain again).
    fn ask_ticket(&self, profile: Option<&Profile>) {
        self.ask_ticket_then(profile, None);
    }

    fn ask_ticket_then(&self, profile: Option<&Profile>, then: Option<Then>) {
        let home = &self.imp().home;
        let ticket = home.ticket();
        let realm = match (profile, &ticket) {
            (Some(p), _) => Some(realm_of_domain(&p.domain)),
            (None, Some(t)) => Some(t.realm().to_owned()),
            (None, None) => {
                let profiles = self.store().list();
                match profiles.as_slice() {
                    [only] => Some(realm_of_domain(&only.domain)),
                    _ => None,
                }
            }
        };
        let account = ticket
            .as_ref()
            .filter(|t| Some(t.realm()) == realm.as_deref())
            .and_then(|t| t.principal.rsplit_once('@'))
            .map_or("", |(user, _)| user)
            .to_owned();
        let weak = self.downgrade();
        let obtained = Box::new(move |new: &Ticket| {
            if let Some(window) = weak.upgrade() {
                window.imp().home.refresh_ticket();
                window.toast(&fill(
                    &tr("Ticket obtained for {principal}."),
                    &[("principal", &new.principal)],
                ));
                if let Some(then) = &then {
                    then(&window);
                }
            }
        });
        TicketDialog::new(realm, &account, obtained).present(Some(self));
    }

    fn save_size(&self) {
        let settings = self.settings();
        if !self.is_maximized() {
            let (width, height) = self.default_size();
            let _ = settings.set_int("window-width", width);
            let _ = settings.set_int("window-height", height);
        }
        let _ = settings.set_boolean("window-maximized", self.is_maximized());
    }
}

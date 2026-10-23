// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DNS window (J3.3, writes J3.4, `annuaire.ui.dns`). The structure lives in `dns.blp`.
//!
//! On the left, the zones (of the three places of the directory), expandable into names
//! sorted by labels (`dns_views::tree`); on the right, the records of the chosen name, **and
//! of it alone** (`dns_views::record_lines`): the zone shows those of its root `@`, the names
//! below stay in the tree, counted apart in the summary.
//!
//! A zone is read on the DC (never in the local copy, ADR 0010, 7) at the first expansion or
//! the first choice, once; « Refresh » (F5) reads everything again. The names in tombstone
//! are hidden, except through the option of the menu. A name the account sees without
//! reading its attributes is shown « unreadable with this account », without records and
//! with an explanation, instead of being hidden (`Node::unreadable`); it is not modified.
//! From the first 500 nodes received, the expanded zone shows the names they give, and the
//! whole tree replaces them at the end of the reading; a list of names fills by chunks, at
//! rest of the loop (`NameList`, J3.5).
//!
//! DNS health (J3.5): the menu or Ctrl+D opens the « DNS health » window, whose fixes go
//! through the same preview and make this window read the names touched again
//! (`after_write`).
//!
//! Writes (J3.4): « New record » (Ctrl+N, Insert), « Edit » (F2, Enter on the row) and
//! « Delete » (Delete) go through the record dialog (`dns_record`) or directly through the
//! common preview (`writes::propose`), on the write connection of the main window (PDC
//! emulator). Ctrl+Z undoes the last change of the domain, as in the main window. Read-only
//! profile: nothing is modifiable, and the window says it. After a write, the nodes touched
//! are read again on the DC that received it and held for the present state
//! (`dns_views::correct`, ADR 0009); the tree of the zone is built again and the name
//! written chosen again.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::dns_record;
use annuaire_core::cache::Source;
use annuaire_core::changes::{Operation, Report, dn_key, parent_dn};
use annuaire_core::dns::{self as core_dns, Node, ROOT, Zone};
use annuaire_core::dns_write::{self, PrepareError, Request};
use futures_util::StreamExt;
use gtk::{gio, glib};

use crate::catalog::AppCatalog;
use crate::dns_views::{self as dv, Branch, RecordLine, Written};
use crate::errors;
use crate::i18n::{fill, tr};
use crate::writes::{self, Options};

/// Names added per turn of the loop while they fall in the first 200 rows, that the view
/// creates at once (`TRANCHE_VUE`).
const VIEW_CHUNK: u32 = 50;
const VIEW_WINDOW: u32 = 200;
/// Past it, the view creates no row: the names are added by big chunks (`TRANCHE_NOMS`).
const NAMES_CHUNK: u32 = 500;
/// Nodes received from which a zone being read already shows its first names
/// (`PREMIERS_NOMS`).
const FIRST_NAMES: usize = 500;

// --- A zone or a name of the tree -------------------------------------------------------

mod node {
    use std::cell::{OnceCell, RefCell};
    use std::rc::Rc;

    use annuaire_core::dns::Zone;
    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::dns_views::Branch;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::DnsNode)]
    pub struct DnsNode {
        #[property(name = "nom", get = |n: &Self| n.obj().name(), type = String)]
        #[property(name = "sous-titre", get = |n: &Self| n.obj().subtitle(), type = String)]
        #[property(name = "a-sous-titre", get = |n: &Self| !n.obj().subtitle().is_empty(), type = bool)]
        #[property(name = "icone", get = |n: &Self| n.obj().icon().to_owned(), type = String)]
        #[property(name = "accessible", get = |n: &Self| n.obj().accessible_text(), type = String)]
        pub zone: OnceCell<Zone>,
        /// None while the zone is not read.
        pub branch: RefCell<Option<Rc<Branch>>>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for DnsNode {
        const NAME: &'static str = "AnnuaireNoeudDns";
        type Type = super::DnsNode;
    }

    #[glib::derived_properties]
    impl ObjectImpl for DnsNode {}
}

glib::wrapper! {
    /// A zone (`branch` None while it is not read) or a name of the tree (`NoeudDnsObjet`).
    pub struct DnsNode(ObjectSubclass<node::DnsNode>);
}

impl DnsNode {
    fn new(zone: &Zone, branch: Option<Rc<Branch>>) -> Self {
        let node: Self = glib::Object::new();
        let _ = node.imp().zone.set(zone.clone());
        *node.imp().branch.borrow_mut() = branch;
        node
    }

    pub fn zone(&self) -> &Zone {
        self.imp().zone.get().expect("set by new")
    }

    pub fn branch(&self) -> Option<Rc<Branch>> {
        self.imp().branch.borrow().clone()
    }

    fn set_branch(&self, branch: Rc<Branch>) {
        *self.imp().branch.borrow_mut() = Some(branch);
    }

    fn is_zone(&self) -> bool {
        self.branch().is_none_or(|b| b.is_root())
    }

    fn name(&self) -> String {
        match self.branch() {
            Some(b) if !b.is_root() => b.name().to_owned(),
            _ => self.zone().name.clone(),
        }
    }

    fn subtitle(&self) -> String {
        if self.is_zone() {
            return dv::zone_subtitle(self.zone());
        }
        match self.branch() {
            Some(b) if b.tombstone() => tr("deleted (tombstone)"),
            Some(b) if b.unreadable() => tr("unreadable with this account"),
            _ => String::new(),
        }
    }

    fn icon(&self) -> &'static str {
        self.branch().map_or(dv::ZONE_ICON, |b| b.icon())
    }

    fn accessible_text(&self) -> String {
        let name = match self.branch() {
            Some(b) if !b.is_root() => b.fqdn(),
            _ => self.zone().name.clone(),
        };
        let subtitle = self.subtitle();
        if subtitle.is_empty() {
            name
        } else {
            format!("{name}, {subtitle}")
        }
    }
}

// --- A record of the table ----------------------------------------------------------------

mod line {
    use std::cell::OnceCell;
    use std::sync::OnceLock;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::dns_views::RecordLine;

    /// Properties read by `dns.blp` (`type` is a keyword: no derive).
    const NAMES: [&str; 5] = ["type", "donnees", "ttl", "horodatage", "remarque"];

    #[derive(Debug, Default)]
    pub struct DnsLine {
        pub view: OnceCell<RecordLine>,
    }

    impl DnsLine {
        pub fn view(&self) -> &RecordLine {
            self.view.get().expect("line built by DnsLine::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for DnsLine {
        const NAME: &'static str = "AnnuaireLigneDns";
        type Type = super::DnsLine;
    }

    impl ObjectImpl for DnsLine {
        fn properties() -> &'static [glib::ParamSpec] {
            static PROPERTIES: OnceLock<Vec<glib::ParamSpec>> = OnceLock::new();
            PROPERTIES.get_or_init(|| {
                NAMES
                    .iter()
                    .map(|n| glib::ParamSpecString::builder(n).read_only().build())
                    .collect()
            })
        }

        fn property(&self, _id: usize, pspec: &glib::ParamSpec) -> glib::Value {
            let v = self.view();
            match pspec.name() {
                "type" => v.rtype.to_value(),
                "donnees" => v.data.to_value(),
                "ttl" => v.ttl.to_value(),
                "horodatage" => v.timestamp.to_value(),
                _ => v.remark.to_value(),
            }
        }
    }
}

glib::wrapper! {
    /// A record of the chosen name (`LigneDnsObjet`).
    pub struct DnsLine(ObjectSubclass<line::DnsLine>);
}

impl DnsLine {
    fn new(view: RecordLine) -> Self {
        let line: Self = glib::Object::new();
        let _ = line.imp().view.set(view);
        line
    }

    pub fn view(&self) -> &RecordLine {
        self.imp().view()
    }
}

// --- Names under a zone or a name ---------------------------------------------------------

type Load = Box<dyn FnOnce(&NameList)>;

mod names {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::collections::HashMap;
    use std::rc::Rc;

    use gtk::prelude::*;
    use gtk::subclass::prelude::*;
    use gtk::{gio, glib};

    use super::{DnsNode, Load};
    use crate::dns_views::Branch;

    #[derive(Default)]
    pub struct NameList {
        pub parent: OnceCell<DnsNode>,
        pub branches: RefCell<Vec<Rc<Branch>>>,
        pub shown: Cell<u32>,
        pub filling: Cell<u64>,
        pub objects: RefCell<HashMap<u32, DnsNode>>,
        pub load: RefCell<Option<Load>>,
    }

    impl std::fmt::Debug for NameList {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("NameList")
                .field("shown", &self.shown.get())
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for NameList {
        const NAME: &'static str = "AnnuaireListeNoms";
        type Type = super::NameList;
        type Interfaces = (gio::ListModel,);
    }

    impl ObjectImpl for NameList {}

    impl ListModelImpl for NameList {
        fn item_type(&self) -> glib::Type {
            DnsNode::static_type()
        }

        fn n_items(&self) -> u32 {
            if let Some(load) = self.load.borrow_mut().take() {
                // The reading starts in the GLib loop, outside of this call of GTK.
                let model = self.obj().clone();
                glib::idle_add_local_once(move || load(&model));
            }
            self.shown.get()
        }

        fn item(&self, position: u32) -> Option<glib::Object> {
            if position >= self.shown.get() {
                return None;
            }
            let mut objects = self.objects.borrow_mut();
            if let Some(object) = objects.get(&position) {
                return Some(object.clone().upcast());
            }
            let branch = self
                .branches
                .borrow()
                .get(usize::try_from(position).ok()?)?
                .clone();
            let object = DnsNode::new(self.parent.get()?.zone(), Some(branch));
            objects.insert(position, object.clone());
            Some(object.upcast())
        }
    }
}

glib::wrapper! {
    /// Names under a zone or a name; their object is made on demand (`ListeNoms`).
    ///
    /// `GtkListView` makes a row at once for each of the first 200 names: adding the 1,844
    /// names of the first level of lab.test in one go held the loop 50 to 60 ms (measured in
    /// J3.5). `fill` shows a first chunk of 50 at once and adds the rest at rest of
    /// the loop. For a zone not read yet (`load` given), the reading starts at the first
    /// `n_items`, that `GtkTreeListModel` only calls at the expansion (ADR 0007, 4).
    pub struct NameList(ObjectSubclass<names::NameList>)
        @implements gio::ListModel;
}

impl NameList {
    fn new(parent: &DnsNode, branches: Vec<Rc<Branch>>, load: Option<Load>) -> Self {
        let list: Self = glib::Object::new();
        let imp = list.imp();
        let _ = imp.parent.set(parent.clone());
        imp.shown
            .set(u32::try_from(branches.len()).unwrap_or(u32::MAX));
        *imp.branches.borrow_mut() = branches;
        *imp.load.borrow_mut() = load;
        list
    }

    fn parent(&self) -> &DnsNode {
        self.imp().parent.get().expect("set by new")
    }

    fn complete(&self) -> bool {
        let imp = self.imp();
        usize::try_from(imp.shown.get()).ok() == Some(imp.branches.borrow().len())
    }

    /// Replaces the names: the first chunk at once, the rest along the loop (`remplir`).
    fn fill(&self, branches: Vec<Rc<Branch>>) {
        let imp = self.imp();
        let old = imp.shown.get();
        imp.filling.set(imp.filling.get() + 1);
        let total = u32::try_from(branches.len()).unwrap_or(u32::MAX);
        *imp.branches.borrow_mut() = branches;
        imp.objects.borrow_mut().clear();
        imp.shown.set(total.min(VIEW_CHUNK));
        self.items_changed(0, old, imp.shown.get());
        if !self.complete() {
            let (weak, filling) = (self.downgrade(), imp.filling.get());
            glib::idle_add_local(move || {
                let Some(list) = weak.upgrade() else {
                    return glib::ControlFlow::Break;
                };
                list.next_chunk(filling)
            });
        }
    }

    fn next_chunk(&self, filling: u64) -> glib::ControlFlow {
        let imp = self.imp();
        if filling != imp.filling.get() {
            return glib::ControlFlow::Break; // replaced meanwhile
        }
        let start = imp.shown.get();
        let step = if start < VIEW_WINDOW {
            VIEW_CHUNK
        } else {
            NAMES_CHUNK
        };
        let total = u32::try_from(imp.branches.borrow().len()).unwrap_or(u32::MAX);
        imp.shown.set(total.min(start + step));
        self.items_changed(start, 0, imp.shown.get() - start);
        if self.complete() {
            glib::ControlFlow::Break
        } else {
            glib::ControlFlow::Continue
        }
    }

    /// Reading impossible: a new expansion starts it again (`echouer`).
    fn failed(&self, load: Load) {
        *self.imp().load.borrow_mut() = Some(load);
    }
}

// --- Window -------------------------------------------------------------------------------

/// What follows the reading of a zone: the error message and its detail, if any.
type Then = Box<dyn FnOnce(Option<(String, String)>)>;
type Progress = Rc<dyn Fn(&[Node])>;

/// A zone being read: what waits for it, what follows its progress, and how to stop it.
pub struct Loading {
    flux: core_dns::NodePages,
    cancelled: Rc<Cell<bool>>,
}

impl std::fmt::Debug for Loading {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loading").finish_non_exhaustive()
    }
}

mod imp {
    use std::cell::{Cell, OnceCell, RefCell};
    use std::collections::{HashMap, HashSet};
    use std::rc::Rc;
    use std::sync::Arc;
    use std::time::SystemTime;

    use adw::subclass::prelude::*;
    use annuaire_core::cache::Source;
    use annuaire_core::dns::{Node, Zone};
    use gtk::glib;

    use super::{Loading, Progress, Then};
    use crate::dns_views::{Branch, Written};
    use crate::scope::TemplateScope;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/dns.ui")]
    pub struct DnsWindow {
        #[template_child]
        pub split_view: TemplateChild<adw::NavigationSplitView>,
        #[template_child]
        pub domain_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub zones_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub tree: TemplateChild<gtk::ListView>,
        #[template_child]
        pub tree_selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub zones_error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub names_page: TemplateChild<adw::NavigationPage>,
        #[template_child]
        pub name_title: TemplateChild<adw::WindowTitle>,
        #[template_child]
        pub summary: TemplateChild<gtk::Label>,
        #[template_child]
        pub settings: TemplateChild<gtk::Label>,
        #[template_child]
        pub names_stack: TemplateChild<gtk::Stack>,
        #[template_child]
        pub table: TemplateChild<gtk::ColumnView>,
        #[template_child]
        pub store: TemplateChild<gtk::gio::ListStore>,
        #[template_child]
        pub empty_page: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub names_error: TemplateChild<adw::StatusPage>,
        #[template_child]
        pub freshness: TemplateChild<gtk::Label>,
        #[template_child]
        pub toasts: TemplateChild<adw::ToastOverlay>,
        #[template_child]
        pub records_selection: TemplateChild<gtk::SingleSelection>,
        #[template_child]
        pub write_state: TemplateChild<gtk::Label>,
        pub source: OnceCell<Arc<dyn Source>>,
        pub zones: RefCell<Vec<Zone>>,
        pub tombstones: Cell<bool>,
        /// By DN of zone: nodes read, date of the reading, readings going on and what waits
        /// for them.
        pub nodes: RefCell<HashMap<String, Vec<Node>>>,
        pub read_at: RefCell<HashMap<String, SystemTime>>,
        pub branches: RefCell<HashMap<String, Rc<Branch>>>,
        pub loadings: RefCell<HashMap<String, Loading>>,
        pub waiting: RefCell<HashMap<String, Vec<Then>>>,
        pub progress: RefCell<HashMap<String, Vec<Progress>>>,
        pub generation: Cell<u64>,
        /// Nodes read again on the DC of the writes after a write (ADR 0009), by key of DN.
        pub written: RefCell<HashMap<String, Written>>,
        /// Name to choose again when the tree of its zone is built again: (DN of the zone,
        /// relative name).
        pub to_choose: RefCell<Option<(String, String)>>,
        pub written_values: RefCell<HashSet<Vec<u8>>>,
        pub actions: RefCell<HashMap<&'static str, gtk::gio::SimpleAction>>,
        pub health: RefCell<Option<crate::dns_health::HealthWindow>>,
    }

    impl std::fmt::Debug for DnsWindow {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DnsWindow").finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for DnsWindow {
        const NAME: &'static str = "AnnuaireDns";
        type Type = super::DnsWindow;
        type ParentType = adw::Window;

        fn class_init(klass: &mut Self::Class) {
            <super::DnsNode as gtk::prelude::StaticTypeExt>::ensure_type();
            <super::DnsLine as gtk::prelude::StaticTypeExt>::ensure_type();
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::DnsWindow>(&[
                ("selected", |w, _| {
                    w.chosen();
                    None
                }),
                ("row_selected", |w, _| {
                    w.update_actions();
                    None
                }),
                ("activated", |w, args| {
                    if let Some(position) = args.get(1).and_then(|v| v.get::<u32>().ok()) {
                        w.row_activated(position);
                    }
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for DnsWindow {}
    impl WidgetImpl for DnsWindow {}

    impl WindowImpl for DnsWindow {
        fn close_request(&self) -> glib::Propagation {
            self.obj().stop();
            self.generation.set(self.generation.get() + 1);
            if let Some(health) = self.health.take() {
                gtk::prelude::GtkWindowExt::close(&health);
            }
            self.parent_close_request()
        }
    }

    impl AdwWindowImpl for DnsWindow {}
}

glib::wrapper! {
    /// The DNS window of the open domain (`AnnuaireDns`).
    pub struct DnsWindow(ObjectSubclass<imp::DnsWindow>)
        @extends adw::Window, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
            gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl DnsWindow {
    pub fn new(source: Arc<dyn Source>, parent: &crate::window::Window) -> Self {
        let window: Self = glib::Object::builder()
            .property("transient-for", parent)
            .build();
        let imp = window.imp();
        imp.domain_title.set_subtitle(&source.profile().domain);
        let _ = imp.source.set(source);
        window.install_actions();
        crate::a11y::name_menus(&window);
        window.read_zones();
        window
    }

    /// The source this window reads (the main window compares it with its own).
    pub fn source(&self) -> &Arc<dyn Source> {
        self.imp().source.get().expect("set by new")
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    fn install_actions(&self) {
        let imp = self.imp();
        let group = gio::SimpleActionGroup::new();
        type Handler = fn(&DnsWindow);
        let plain: [(&'static str, Handler); 6] = [
            ("actualiser", Self::read_zones),
            ("sante", Self::open_health),
            ("ajouter", Self::add_record),
            ("modifier", Self::edit_record),
            ("supprimer", Self::delete_record),
            ("annuler", |w| crate::history::undo_last(w)),
        ];
        for (name, handler) in plain {
            let action = gio::SimpleAction::new(name, None);
            let weak = self.downgrade();
            action.connect_activate(move |_, _| {
                // The shortcuts do not count while a dialog is open (`_si_libre`).
                if let Some(window) = weak.upgrade().filter(|w| w.visible_dialog().is_none()) {
                    handler(&window);
                }
            });
            group.add_action(&action);
            imp.actions.borrow_mut().insert(name, action);
        }
        let tombstones = gio::SimpleAction::new_stateful("tombstones", None, &false.to_variant());
        let weak = self.downgrade();
        tombstones.connect_change_state(move |action, value| {
            let (Some(window), Some(value)) = (weak.upgrade(), value) else {
                return;
            };
            action.set_state(value);
            window.set_tombstones(value.get::<bool>().unwrap_or(false));
        });
        group.add_action(&tombstones);
        self.insert_action_group("dns", Some(&group));
        self.update_actions();

        // Escape in the capture phase: a toast shown (« Undo ») would take it otherwise.
        let escape = gtk::ShortcutController::new();
        escape.set_propagation_phase(gtk::PropagationPhase::Capture);
        let weak = self.downgrade();
        escape.add_shortcut(gtk::Shortcut::new(
            gtk::ShortcutTrigger::parse_string("Escape"),
            Some(gtk::CallbackAction::new(move |_, _| {
                let Some(window) = weak.upgrade() else {
                    return glib::Propagation::Proceed;
                };
                if window.visible_dialog().is_some() {
                    return glib::Propagation::Proceed;
                }
                window.close();
                glib::Propagation::Stop
            })),
        ));
        self.add_controller(escape);
        let shortcuts = gtk::ShortcutController::new();
        for (trigger, action) in [
            ("F5", "dns.actualiser"),
            ("<Control>d", "dns.sante"),
            ("<Control>n", "dns.ajouter"),
            ("Insert", "dns.ajouter"),
            ("F2", "dns.modifier"),
            ("Delete", "dns.supprimer"),
            ("<Control>z", "dns.annuler"),
        ] {
            shortcuts.add_shortcut(gtk::Shortcut::new(
                gtk::ShortcutTrigger::parse_string(trigger),
                Some(gtk::NamedAction::new(action)),
            ));
        }
        self.add_controller(shortcuts);
    }

    fn action(&self, name: &str) -> Option<gio::SimpleAction> {
        self.imp().actions.borrow().get(name).cloned()
    }

    // --- Zones ------------------------------------------------------------------------

    /// (Re)reads the list of the zones; forgets the zones already read (`lire_zones`).
    fn read_zones(&self) {
        let imp = self.imp();
        self.stop();
        imp.nodes.borrow_mut().clear();
        imp.read_at.borrow_mut().clear();
        imp.branches.borrow_mut().clear();
        imp.generation.set(imp.generation.get() + 1);
        let generation = imp.generation.get();
        imp.zones_stack.set_visible_child_name("chargement");
        imp.tree_selection.set_model(None::<&gio::ListModel>);
        let (source, weak) = (self.source().clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let reading = source.clone();
            let read = gio::spawn_blocking(move || reading.dns_zones()).await;
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            if generation != imp.generation.get() {
                return;
            }
            let zones = match read {
                Ok(Ok(zones)) => zones,
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &source.profile().domain);
                    window.zones_failed(&problem.message, &problem.detail);
                    return;
                }
                Err(_) => return,
            };
            if zones.is_empty() {
                window.zones_failed(&tr("No DNS zone in the directory"), "");
                return;
            }
            *imp.zones.borrow_mut() = zones;
            window.build_tree();
            imp.tree.grab_focus();
        });
    }

    fn zones_failed(&self, title: &str, detail: &str) {
        let imp = self.imp();
        imp.zones_error.set_title(title);
        imp.zones_error.set_description(Some(detail));
        imp.zones_stack.set_visible_child_name("erreur");
    }

    fn build_tree(&self) {
        let imp = self.imp();
        let roots = gio::ListStore::new::<DnsNode>();
        let objects: Vec<DnsNode> = imp
            .zones
            .borrow()
            .iter()
            .map(|z| DnsNode::new(z, imp.branches.borrow().get(&z.dn).cloned()))
            .collect();
        roots.extend_from_slice(&objects);
        let weak = self.downgrade();
        let model = gtk::TreeListModel::new(roots, false, false, move |item| {
            let window = weak.upgrade()?;
            let node = item.downcast_ref::<DnsNode>()?;
            window.children_of(node)
        });
        imp.tree_selection.set_model(Some(&model)); // chooses the first zone
        imp.zones_stack.set_visible_child_name("arbre");
    }

    fn children_of(&self, node: &DnsNode) -> Option<gio::ListModel> {
        match node.branch() {
            None => {
                let weak = self.downgrade();
                let load: Load = Box::new(move |list: &NameList| {
                    if let Some(window) = weak.upgrade() {
                        window.expand(list);
                    }
                });
                Some(NameList::new(node, Vec::new(), Some(load)).upcast())
            }
            Some(branch) if branch.children.is_empty() => None,
            Some(branch) => Some(NameList::new(node, branch.children.clone(), None).upcast()),
        }
    }

    /// The zone expanded is read: its first names as soon as they come, the whole tree at
    /// the end (`_deplier`).
    fn expand(&self, list: &NameList) {
        let zone = list.parent().zone().clone();
        let partial = Rc::new(Cell::new(false));
        let (weak, weak_list) = (self.downgrade(), list.downgrade());
        let progress: Progress = {
            let (weak, weak_list, partial, zone) = (
                weak.clone(),
                weak_list.clone(),
                partial.clone(),
                zone.clone(),
            );
            Rc::new(move |received: &[Node]| {
                // From the first nodes (the first page has a thousand), the names they give:
                // the whole tree replaces them at the end of the reading.
                if partial.get() || received.len() < FIRST_NAMES {
                    return;
                }
                let (Some(window), Some(list)) = (weak.upgrade(), weak_list.upgrade()) else {
                    return;
                };
                partial.set(true);
                let corrected = window.corrected(&zone, received);
                let first = dv::tree(&zone.name, &corrected, window.imp().tombstones.get());
                list.fill(first.children);
            })
        };
        let then: Then = Box::new(move |error| {
            let (Some(window), Some(list)) = (weak.upgrade(), weak_list.upgrade()) else {
                return;
            };
            if error.is_some() {
                let weak = window.downgrade();
                list.failed(Box::new(move |list: &NameList| {
                    if let Some(window) = weak.upgrade() {
                        window.expand(list);
                    }
                }));
                return;
            }
            let zone = list.parent().zone().clone();
            let branch = window.branch(&zone);
            list.parent().set_branch(branch.clone());
            let generation = window.imp().generation.get();
            let fill = move || {
                // At the next turn: the tree (8 ms for lab.test) and the replacement of the
                // first names (20 ms) do not hold the loop in one go.
                if window.imp().generation.get() == generation {
                    list.fill(branch.children.clone());
                }
            };
            if partial.get() {
                glib::idle_add_local_once(fill);
            } else {
                fill();
            }
        });
        self.load_zone(&zone, then, Some(progress));
    }

    fn branch(&self, zone: &Zone) -> Rc<Branch> {
        let imp = self.imp();
        if let Some(branch) = imp.branches.borrow().get(&zone.dn) {
            return branch.clone();
        }
        let branch = Rc::new(dv::tree(
            &zone.name,
            imp.nodes.borrow().get(&zone.dn).into_iter().flatten(),
            imp.tombstones.get(),
        ));
        imp.branches
            .borrow_mut()
            .insert(zone.dn.clone(), branch.clone());
        branch
    }

    /// Reads the nodes of the zone once; `then` is called at the end, with the error if
    /// there is one; `progress`, at each chunk received, with all the nodes received so far
    /// (`_charger_zone`).
    fn load_zone(&self, zone: &Zone, then: Then, progress: Option<Progress>) {
        let imp = self.imp();
        if imp.nodes.borrow().contains_key(&zone.dn) {
            then(None);
            return;
        }
        imp.waiting
            .borrow_mut()
            .entry(zone.dn.clone())
            .or_default()
            .push(then);
        if let Some(progress) = progress {
            imp.progress
                .borrow_mut()
                .entry(zone.dn.clone())
                .or_default()
                .push(progress);
        }
        if imp.loadings.borrow().contains_key(&zone.dn) {
            return;
        }
        let (sender, mut wakes) = futures_channel::mpsc::unbounded::<()>();
        let flux = self.source().dns_nodes(
            zone,
            Box::new(move || {
                let _ = sender.unbounded_send(());
            }),
        );
        let cancelled = Rc::new(Cell::new(false));
        imp.loadings.borrow_mut().insert(
            zone.dn.clone(),
            Loading {
                flux: flux.clone(),
                cancelled: cancelled.clone(),
            },
        );
        let started = SystemTime::now();
        let (weak, zone) = (self.downgrade(), zone.clone());
        glib::spawn_future_local(async move {
            let mut received: Vec<Node> = Vec::new();
            let error = loop {
                let pages = match flux.available() {
                    Ok(pages) => pages,
                    Err(error) => break Some(error),
                };
                for page in pages {
                    received.extend(
                        page.iter()
                            .map(|e| core_dns::node_from_entry(e, &zone.name)),
                    );
                    if cancelled.get() {
                        return;
                    }
                    let Some(window) = weak.upgrade() else { return };
                    let followers: Vec<Progress> = window
                        .imp()
                        .progress
                        .borrow()
                        .get(&zone.dn)
                        .cloned()
                        .unwrap_or_default();
                    for follow in followers {
                        follow(&received);
                    }
                    glib::timeout_future(Duration::ZERO).await;
                }
                if cancelled.get() {
                    return;
                }
                if flux.finished() {
                    match flux.available() {
                        Ok(rest) => {
                            for page in rest {
                                received.extend(
                                    page.iter()
                                        .map(|e| core_dns::node_from_entry(e, &zone.name)),
                                );
                            }
                            break None;
                        }
                        Err(error) => break Some(error),
                    }
                }
                if wakes.next().await.is_none() {
                    return;
                }
            };
            if cancelled.get() {
                return;
            }
            let Some(window) = weak.upgrade() else { return };
            window.zone_loaded(&zone, received, started, error.as_deref());
        });
    }

    fn zone_loaded(
        &self,
        zone: &Zone,
        received: Vec<Node>,
        started: SystemTime,
        error: Option<&annuaire_core::search::SearchError>,
    ) {
        let imp = self.imp();
        imp.loadings.borrow_mut().remove(&zone.dn);
        imp.progress.borrow_mut().remove(&zone.dn);
        let error = error.map(|e| {
            let problem = errors::search_problem(e, &self.source().profile().domain);
            (problem.message, problem.detail)
        });
        if error.is_none() {
            let corrected = self.corrected(zone, &received);
            imp.nodes.borrow_mut().insert(zone.dn.clone(), corrected);
            imp.read_at.borrow_mut().insert(zone.dn.clone(), started);
        }
        let waiting = imp
            .waiting
            .borrow_mut()
            .remove(&zone.dn)
            .unwrap_or_default();
        for then in waiting {
            then(error.clone());
        }
    }

    fn stop(&self) {
        let imp = self.imp();
        for (_, loading) in imp.loadings.borrow_mut().drain() {
            loading.cancelled.set(true);
            loading.flux.cancel();
        }
        imp.waiting.borrow_mut().clear();
        imp.progress.borrow_mut().clear();
    }

    fn set_tombstones(&self, shown: bool) {
        let imp = self.imp();
        imp.tombstones.set(shown);
        imp.branches.borrow_mut().clear();
        if !imp.zones.borrow().is_empty() {
            self.build_tree();
        }
    }

    // --- Name chosen ---------------------------------------------------------------------

    fn choice(&self) -> Option<DnsNode> {
        self.imp()
            .tree_selection
            .selected_item()
            .and_downcast::<gtk::TreeListRow>()?
            .item()
            .and_downcast::<DnsNode>()
    }

    /// `selected`.
    fn chosen(&self) {
        let imp = self.imp();
        let Some(object) = self.choice() else { return };
        let zone = object.zone().clone();
        if let Some(branch) = object.branch() {
            self.show(&zone, &branch);
            return;
        }
        imp.name_title.set_title(&zone.name);
        imp.name_title.set_subtitle("");
        imp.summary.set_label(&tr("Reading the zone…"));
        imp.settings.set_visible(false);
        imp.names_stack.set_visible_child_name("chargement");
        let weak = self.downgrade();
        let then: Then = Box::new(move |error| {
            let Some(window) = weak.upgrade() else { return };
            if window.choice().as_ref() != Some(&object) {
                return;
            }
            let imp = window.imp();
            if let Some((title, detail)) = error {
                imp.names_error.set_title(&title);
                imp.names_error.set_description(Some(&detail));
                imp.summary.set_label("");
                imp.names_stack.set_visible_child_name("erreur");
                return;
            }
            let zone = object.zone().clone();
            let branch = window.branch(&zone);
            object.set_branch(branch.clone());
            window.show(&zone, &branch);
        });
        self.load_zone(&zone, then, None);
    }

    /// Nodes read by the source, corrected by those read again after a write in the zone
    /// (`_corriges`).
    fn corrected(&self, zone: &Zone, nodes: &[Node]) -> Vec<Node> {
        let zone_key = key(&zone.dn);
        let written: Vec<Written> = self
            .imp()
            .written
            .borrow()
            .values()
            .filter(|w| parent_dn(&w.dn).is_ok_and(|p| key(&p) == zone_key))
            .cloned()
            .collect();
        if written.is_empty() {
            nodes.to_vec()
        } else {
            dv::correct(nodes, &written, SystemTime::now())
        }
    }

    /// Records of this name, and of it alone (`_montrer`).
    fn show(&self, zone: &Zone, branch: &Branch) {
        let imp = self.imp();
        imp.name_title.set_title(&branch.fqdn());
        imp.name_title.set_subtitle(&if branch.is_root() {
            tr("root of the zone (@)")
        } else {
            fill(&tr("zone {zone}"), &[("zone", &zone.name)])
        });
        imp.names_page.set_title(branch.name());
        imp.summary.set_label(&dv::branch_summary(branch));
        imp.settings.set_visible(branch.is_root());
        if branch.is_root() {
            imp.settings
                .set_label(&dv::settings_summary(&zone.settings));
            let tooltip: Vec<String> = dv::settings_lines(&zone.settings)
                .iter()
                .map(|(n, v)| dv::setting_line(n, v))
                .collect();
            imp.settings.set_tooltip_text(Some(&tooltip.join("\n")));
        }
        let lines: Vec<DnsLine> = dv::record_lines(branch)
            .into_iter()
            .map(DnsLine::new)
            .collect();
        imp.store.remove_all();
        imp.store.extend_from_slice(&lines);
        imp.records_selection
            .set_selected(gtk::INVALID_LIST_POSITION);
        self.update_actions();
        if lines.is_empty() {
            let (title, description) = dv::empty_text(branch);
            imp.empty_page.set_title(&title);
            imp.empty_page.set_description(Some(&description));
            imp.empty_page.set_icon_name(Some(if branch.unreadable() {
                dv::UNREADABLE_ICON
            } else {
                dv::NAME_ICON
            }));
            imp.names_stack.set_visible_child_name("vide");
        } else {
            imp.names_stack.set_visible_child_name("table");
        }
        let read = imp.read_at.borrow().get(&zone.dn).copied();
        imp.freshness
            .set_label(&read.map(dv::read_text).unwrap_or_default());
    }

    // --- Writes (J3.4) ---------------------------------------------------------------

    fn context(&self) -> Option<Arc<writes::WriteContext>> {
        writes::context(self)
    }

    fn writing_possible(&self) -> bool {
        self.context().is_some_and(|c| !c.profile.read_only)
    }

    fn line(&self) -> Option<RecordLine> {
        self.imp()
            .records_selection
            .selected_item()
            .and_downcast::<DnsLine>()
            .map(|l| l.view().clone())
    }

    /// Zone and relative name chosen in the tree (`@` for the zone) (`_nom_choisi`).
    fn name_chosen(&self) -> Option<(Zone, String)> {
        let object = self.choice()?;
        if object.zone().root_hints() {
            return None;
        }
        let name = object
            .branch()
            .map_or_else(|| ROOT.to_owned(), |b| b.relative());
        Some((object.zone().clone(), name))
    }

    /// `_mettre_a_jour_actions`.
    fn update_actions(&self) {
        let imp = self.imp();
        let possible = self.writing_possible();
        let line = self.line();
        let unreadable = self
            .choice()
            .and_then(|c| c.branch())
            .is_some_and(|b| b.unreadable());
        let modifiable = possible && line.as_ref().is_some_and(|l| l.modifiable);
        for (name, enabled) in [
            (
                "ajouter",
                possible && self.name_chosen().is_some() && !unreadable,
            ),
            ("modifier", modifiable),
            ("supprimer", modifiable),
            ("annuler", possible),
        ] {
            if let Some(action) = self.action(name) {
                action.set_enabled(enabled);
            }
        }
        let text = if !possible {
            Some(if self.context().is_some() {
                tr("Read-only profile: no change possible.")
            } else {
                tr("No domain open to write to.")
            })
        } else if unreadable {
            Some(tr(
                "Name unreadable with this account: its records cannot be modified.",
            ))
        } else {
            line.filter(|l| !l.modifiable).map(|l| {
                fill(
                    &tr(
                        "This record cannot be modified by the tool (type {type}, rank or data not supported).",
                    ),
                    &[("type", &l.rtype)],
                )
            })
        };
        imp.write_state.set_visible(text.is_some());
        if let Some(text) = text {
            imp.write_state.set_label(&text);
        }
    }

    /// `activated`: Enter on a row edits it.
    fn row_activated(&self, position: u32) {
        self.imp().records_selection.set_selected(position);
        if self.action("modifier").is_some_and(|a| a.is_enabled()) {
            self.edit_record();
        }
    }

    fn zones(&self) -> Vec<Zone> {
        self.imp().zones.borrow().clone()
    }

    fn add_record(&self) {
        let Some((zone, name)) = self.name_chosen() else {
            return;
        };
        if !self.writing_possible() {
            return;
        }
        crate::dns_record::RecordDialog::new(&zone, self.zones(), &name, None).present(Some(self));
    }

    fn edit_record(&self) {
        let (Some((zone, name)), Some(line)) = (self.name_chosen(), self.line()) else {
            return;
        };
        if !line.modifiable {
            return;
        }
        crate::dns_record::RecordDialog::new(&zone, self.zones(), &name, Some(line.value))
            .present(Some(self));
    }

    fn delete_record(&self) {
        let (Some((zone, name)), Some(line), Some(context)) =
            (self.name_chosen(), self.line(), self.context())
        else {
            return;
        };
        if !line.modifiable {
            return;
        }
        let requests = vec![Request::Delete {
            zone,
            name,
            value: line.value,
        }];
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let (connection, asked) = (context.connection.clone(), requests.clone());
            let built = gio::spawn_blocking(move || {
                dns_write::build(&connection, asked, Arc::new(AppCatalog))
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            match built {
                Ok(Ok(changeset)) => {
                    writes::propose(
                        &window,
                        changeset,
                        Options {
                            retry: Some(dns_write::rebuild(requests, Arc::new(AppCatalog))),
                            ..Options::default()
                        },
                    );
                }
                Ok(Err(error)) => {
                    let (message, detail) = prepare_message(&error, &context.profile.domain);
                    writes::show_error(&window, &tr("Cannot delete"), &message, &detail);
                }
                Err(_) => {}
            }
        });
    }

    /// Reads again on the DC of the writes the nodes touched, then updates their zones
    /// (`apres_ecriture`).
    pub fn after_write(&self, report: &Report) {
        let imp = self.imp();
        let Some(context) = self.context() else {
            return;
        };
        let dns: Vec<String> = annuaire_core::reread::touched(report)
            .dns
            .into_iter()
            .filter(|d| core_dns::is_node(d))
            .collect();
        let Some(first) = dns.first().cloned() else {
            return;
        };
        let target = dns
            .iter()
            .find(|d| !d.to_uppercase().starts_with("DC=@,"))
            .cloned()
            .unwrap_or(first);
        if let (Ok(zone), Some((name, _))) = (parent_dn(&target), core_dns::node_parts(&target)) {
            *imp.to_choose.borrow_mut() = Some((zone, name));
        }
        *imp.written_values.borrow_mut() = values_added(report);
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let connection = context.connection.clone();
            let read = gio::spawn_blocking(move || core_dns::reread_nodes(&connection, &dns)).await;
            let Some(window) = weak.upgrade() else { return };
            match read {
                Ok(Ok(read)) => window.reread(read),
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &context.profile.domain);
                    writes::show_error(
                        &window,
                        &tr("Cannot read again after writing"),
                        &problem.message,
                        &problem.detail,
                    );
                }
                Err(_) => {}
            }
        });
    }

    fn reread(&self, read: Vec<(String, Option<Node>)>) {
        let imp = self.imp();
        let now = SystemTime::now();
        let written: Vec<Written> = read
            .into_iter()
            .map(|(dn, node)| Written {
                dn,
                node,
                read_at: now,
            })
            .collect();
        for w in &written {
            imp.written.borrow_mut().insert(key(&w.dn), w.clone());
        }
        for zone in self.zones() {
            let zone_key = key(&zone.dn);
            let in_zone: Vec<Written> = written
                .iter()
                .filter(|w| parent_dn(&w.dn).is_ok_and(|p| key(&p) == zone_key))
                .cloned()
                .collect();
            let replaced = imp
                .nodes
                .borrow()
                .get(&zone.dn)
                .filter(|_| !in_zone.is_empty())
                .map(|nodes| dv::replace(nodes, &in_zone));
            if let Some(nodes) = replaced {
                imp.nodes.borrow_mut().insert(zone.dn.clone(), nodes);
                imp.branches.borrow_mut().remove(&zone.dn);
                self.branch(&zone); // the tree builds again, expanded up to the name written
            }
        }
        self.build_tree();
        self.choose_after_write();
    }

    /// Expands the tree up to the name written and selects it (its zone, if it is hidden)
    /// (`_choisir_apres_ecriture`).
    fn choose_after_write(&self) {
        let imp = self.imp();
        let Some((zone_dn, relative)) = imp.to_choose.take() else {
            return;
        };
        let Some(model) = imp
            .tree_selection
            .model()
            .and_downcast::<gtk::TreeListModel>()
        else {
            return;
        };
        let path: Vec<String> = if relative == ROOT {
            Vec::new()
        } else {
            relative
                .to_lowercase()
                .split('.')
                .rev()
                .map(str::to_owned)
                .collect()
        };
        let (mut position, mut depth) = (None::<u32>, 0usize);
        let mut i = 0;
        while i < model.n_items() {
            let Some(row) = model.row(i) else { break };
            let Some(object) = row.item().and_downcast::<DnsNode>() else {
                break;
            };
            let row_depth = usize::try_from(row.depth()).unwrap_or(0);
            if row_depth == 0 && position.is_none() {
                if key(&object.zone().dn) == key(&zone_dn) {
                    position = Some(i);
                    if !path.is_empty() {
                        row.set_expanded(true);
                    }
                }
            } else if position.is_some() && row_depth == depth + 1 {
                let matches = object.branch().is_some_and(|b| {
                    path.get(depth)
                        .is_some_and(|p| b.name().to_lowercase() == *p)
                });
                if matches {
                    position = Some(i);
                    depth += 1;
                    if depth == path.len() {
                        break;
                    }
                    row.set_expanded(true);
                }
            } else if position.is_some() && row_depth <= depth {
                break; // out of the branch: the name is not (or no longer) visible
            }
            i += 1;
        }
        if let Some(position) = position {
            imp.tree_selection.set_selected(position);
        }
        // The line written is chosen: F2 and Delete apply to it at once. Without it (name
        // gone into tombstone, so hidden), the focus goes to the tree, on the zone.
        let values = imp.written_values.borrow().clone();
        let rank = (0..imp.store.n_items()).find(|&i| {
            imp.store
                .item(i)
                .and_downcast::<DnsLine>()
                .is_some_and(|l| values.contains(&l.view().value))
        });
        let weak = self.downgrade();
        let place = move || {
            let Some(window) = weak.upgrade() else { return };
            let imp = window.imp();
            match rank {
                None => {
                    imp.tree.grab_focus();
                }
                Some(rank) => {
                    imp.table.grab_focus();
                    imp.table.scroll_to(
                        rank,
                        None::<&gtk::ColumnViewColumn>,
                        gtk::ListScrollFlags::FOCUS | gtk::ListScrollFlags::SELECT,
                        None,
                    );
                }
            }
        };
        // The preview dialog, when it closes, gives the focus back to the widget that opened
        // it: this comes after it.
        if self.visible_dialog().is_none() {
            glib::idle_add_local_once(place);
            return;
        }
        let handler: Rc<RefCell<Option<glib::SignalHandlerId>>> = Rc::default();
        let (kept, place) = (handler.clone(), RefCell::new(Some(place)));
        let id = self.connect_notify_local(Some("visible-dialog"), move |window, _| {
            if window.visible_dialog().is_some() {
                return;
            }
            if let Some(id) = kept.borrow_mut().take() {
                window.disconnect(id);
            }
            if let Some(place) = place.borrow_mut().take() {
                glib::idle_add_local_once(place);
            }
        });
        *handler.borrow_mut() = Some(id);
    }

    /// The « DNS health » window, one per DNS window (`ouvrir_sante`).
    pub fn open_health(&self) {
        let imp = self.imp();
        let existing = imp.health.borrow().clone();
        let health = existing.unwrap_or_else(|| {
            let health = crate::dns_health::HealthWindow::new(self);
            let weak = self.downgrade();
            health.connect_close_request(move |closed| {
                if let Some(window) = weak.upgrade() {
                    let mut kept = window.imp().health.borrow_mut();
                    if kept.as_ref() == Some(closed) {
                        kept.take();
                    }
                }
                glib::Propagation::Proceed
            });
            *imp.health.borrow_mut() = Some(health.clone());
            health
        });
        health.present();
    }

    /// The tree's selection and expansions for the trials: selects the node at this path
    /// (`zone` or `zone/name`), and returns whether it was found.
    pub fn trial_select(&self, zone: &str, relative: &str) -> bool {
        let found = self
            .imp()
            .zones
            .borrow()
            .iter()
            .find(|z| z.name.eq_ignore_ascii_case(zone))
            .cloned();
        let Some(found) = found else { return false };
        *self.imp().to_choose.borrow_mut() = Some((found.dn.clone(), relative.to_owned()));
        self.choose_after_write();
        true
    }

    /// The zones are shown (trials).
    pub fn trial_ready(&self) -> bool {
        self.imp().zones_stack.visible_child_name().as_deref() == Some("arbre")
    }

    /// Title, summary and records shown, once read (trials).
    pub fn trial_table(&self) -> Option<(String, String, Vec<String>)> {
        let imp = self.imp();
        if imp.names_stack.visible_child_name().as_deref() == Some("chargement") {
            return None;
        }
        let lines = (0..imp.store.n_items())
            .filter_map(|i| imp.store.item(i).and_downcast::<DnsLine>())
            .map(|l| {
                let v = l.view();
                format!(
                    "{} {} ({}, {}) {}",
                    v.rtype, v.data, v.ttl, v.timestamp, v.remark
                )
            })
            .collect();
        Some((
            imp.name_title.title().to_string(),
            imp.summary.label().to_string(),
            lines,
        ))
    }

    /// Selects the record whose data is `data` (trials).
    pub fn trial_select_line(&self, data: &str) -> bool {
        let imp = self.imp();
        let found = (0..imp.store.n_items()).find(|&i| {
            imp.store
                .item(i)
                .and_downcast::<DnsLine>()
                .is_some_and(|l| l.view().data == data)
        });
        if let Some(i) = found {
            imp.records_selection.set_selected(i);
        }
        found.is_some()
    }

    /// Data of the record selected (trials).
    pub fn trial_selected(&self) -> Option<String> {
        self.line().map(|l| l.data)
    }

    pub fn trial_health(&self) -> Option<crate::dns_health::HealthWindow> {
        self.imp().health.borrow().clone()
    }
}

/// Values of `dnsRecord` the application put (to choose the line written), SOA aside: its
/// increment is not what the user wrote (`_valeurs_ajoutees`).
fn values_added(report: &Report) -> HashSet<Vec<u8>> {
    let mut values = HashSet::new();
    for a in &report.applied {
        match &a.operation {
            Operation::Add { attributes, .. } => values.extend(
                attributes
                    .iter()
                    .filter(|(k, _)| k.eq_ignore_ascii_case("dnsRecord"))
                    .flat_map(|(_, vs)| vs.iter().cloned()),
            ),
            Operation::Modify { changes, .. } => values.extend(
                changes
                    .iter()
                    .filter(|c| c.attribute.eq_ignore_ascii_case("dnsRecord"))
                    .flat_map(|c| c.added.iter().cloned()),
            ),
            _ => {}
        }
    }
    values.retain(|v| core_dns::value_type(v) != i32::from(dns_record::SOA));
    values
}

fn key(dn_text: &str) -> String {
    dn_key(dn_text).unwrap_or_else(|_| dn_text.to_lowercase())
}

/// Message and detail of a request that could not be prepared.
pub fn prepare_message(error: &PrepareError, domain: &str) -> (String, String) {
    match error {
        PrepareError::Dns(e) => (dv::dns_error(e), dv::dns_error_detail(e)),
        PrepareError::Failure(failure) => {
            let problem = errors::failure_problem(failure, domain);
            (problem.message, problem.detail)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_added_leave_the_soa_out() {
        use annuaire_codecs::dns_record::{Record, RecordData};
        use annuaire_core::changes::{Applied, Change, Changeset, Issue};
        let a = Record::new(
            dns_record::A,
            RecordData::Address("192.0.2.1".parse().unwrap()),
        )
        .encode()
        .unwrap();
        let soa = Record::new(
            dns_record::SOA,
            RecordData::Soa {
                serial: 2,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 1,
                primary_server: "a".into(),
                responsible: "b".into(),
            },
        )
        .encode()
        .unwrap();
        let op = Operation::Modify {
            dn: "DC=@,DC=z,CN=MicrosoftDNS,DC=x".into(),
            changes: vec![Change::new("dnsRecord", vec![], vec![soa, a.clone()]).unwrap()],
            read: None,
        };
        let report = Report {
            id: String::new(),
            timestamp: String::new(),
            domain: String::new(),
            dc: String::new(),
            user: String::new(),
            changeset: Changeset::default(),
            applied: vec![Applied {
                operation: op,
                after: None,
                before: None,
            }],
            issue: Issue::Applied,
            error: None,
            rollback: None,
            origins: Vec::new(),
            rollback_applied: Vec::new(),
            rollback_error: None,
            doubtful: None,
            doubtful_rollback: None,
            resumes: None,
            resumed_by: None,
        };
        assert_eq!(values_added(&report), HashSet::from([a]));
    }
}

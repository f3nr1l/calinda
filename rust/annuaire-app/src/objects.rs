// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! GObjects of the lists (`annuaire.ui.objets`): rows of the table (`AnnuaireLigne`), nodes of
//! the tree (`AnnuaireNoeud`) and the children of a node, loaded the first time the tree asks
//! for them. A row or a node only exposes, as read-only properties, the fields of a value
//! computed by `views`; the Blueprint files bind to them by expression
//! (`item as <$AnnuaireLigne>.nom`), so the property names are those of the Python objects
//! (`type` aside: no Blueprint reads it). Dates become text when a cell asks for them.

use gtk::prelude::*;
use gtk::subclass::prelude::*;
use gtk::{gio, glib};

use crate::sheet_views::ElementView;
use crate::views::{NodeView, RowView};

mod node {
    use std::cell::{Cell, OnceCell};

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::views::NodeView;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::Node)]
    pub struct Node {
        #[property(name = "dn", get = |n: &Self| n.view().dn.clone(), type = String)]
        #[property(name = "nom", get = |n: &Self| n.view().name.clone(), type = String)]
        #[property(name = "icone", get = |n: &Self| n.view().icon.clone(), type = String)]
        pub view: OnceCell<NodeView>,
        /// True once loaded and empty: no expander any more.
        pub childless: Cell<bool>,
    }

    impl Node {
        pub fn view(&self) -> &NodeView {
            self.view.get().expect("node built by Node::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Node {
        const NAME: &'static str = "AnnuaireNoeud";
        type Type = super::Node;
    }

    #[glib::derived_properties]
    impl ObjectImpl for Node {}
}

glib::wrapper! {
    /// A node of the tree of containers (`NoeudVue`).
    pub struct Node(ObjectSubclass<node::Node>);
}

impl Node {
    pub fn new(view: NodeView) -> Self {
        let node: Self = glib::Object::new();
        let _ = node.imp().view.set(view);
        node
    }

    pub fn view(&self) -> &NodeView {
        self.imp().view()
    }

    pub fn childless(&self) -> bool {
        self.imp().childless.get()
    }
}

mod row {
    use std::cell::OnceCell;

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::views::RowView;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::Row)]
    pub struct Row {
        #[property(name = "dn", get = |r: &Self| r.view().dn.clone(), type = String)]
        #[property(name = "icone", get = |r: &Self| r.view().icon.clone(), type = String)]
        #[property(name = "nom", get = |r: &Self| r.view().name.clone(), type = String)]
        #[property(name = "type-libelle", get = |r: &Self| r.view().kind_label.clone(), type = String)]
        #[property(name = "identifiant", get = |r: &Self| r.view().id.clone(), type = String)]
        #[property(name = "description", get = |r: &Self| r.view().description.clone(), type = String)]
        #[property(name = "courriel", get = |r: &Self| r.view().mail.clone(), type = String)]
        #[property(name = "etat", get = |r: &Self| r.view().state.clone(), type = String)]
        #[property(name = "activite", get = |r: &Self| r.view().activity_text(), type = String)]
        #[property(name = "activite-tri", get = |r: &Self| r.view().activity_sort, type = i64)]
        #[property(name = "modifie", get = |r: &Self| r.view().modified_text(), type = String)]
        #[property(name = "modifie-tri", get = |r: &Self| r.view().modified_sort, type = i64)]
        #[property(name = "emplacement", get = |r: &Self| r.view().location(), type = String)]
        pub view: OnceCell<RowView>,
    }

    impl Row {
        pub fn view(&self) -> &RowView {
            self.view.get().expect("row built by Row::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Row {
        const NAME: &'static str = "AnnuaireLigne";
        type Type = super::Row;
    }

    #[glib::derived_properties]
    impl ObjectImpl for Row {}
}

glib::wrapper! {
    /// A row of the central table (`LigneVue`).
    pub struct Row(ObjectSubclass<row::Row>);
}

impl Row {
    pub fn new(view: RowView) -> Self {
        let row: Self = glib::Object::new();
        let _ = row.imp().view.set(view);
        row
    }

    pub fn view(&self) -> &RowView {
        self.imp().view()
    }
}

// --- Items of the lists of a sheet ----------------------------------------------------

mod element {
    use std::cell::{OnceCell, RefCell};

    use gtk::glib;
    use gtk::glib::prelude::*;
    use gtk::glib::subclass::prelude::*;

    use crate::sheet_views::ElementView;

    #[derive(Debug, Default, glib::Properties)]
    #[properties(wrapper_type = super::Element)]
    pub struct Element {
        #[property(name = "dn", get = |e: &Self| e.view().dn.clone(), type = String)]
        #[property(name = "titre", get = |e: &Self| e.view().title.clone(), type = String)]
        #[property(name = "sous-titre", get = |e: &Self| e.view().subtitle.clone(), type = String)]
        #[property(name = "icone", get = |e: &Self| e.view().icon.clone(), type = String)]
        pub view: OnceCell<ElementView>,
        /// Pending change (« to add », « to remove »).
        #[property(get, set)]
        pub etat: RefCell<String>,
    }

    impl Element {
        pub fn view(&self) -> &ElementView {
            self.view.get().expect("element built by Element::new")
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Element {
        const NAME: &'static str = "AnnuaireElementFiche";
        type Type = super::Element;
    }

    #[glib::derived_properties]
    impl ObjectImpl for Element {}
}

glib::wrapper! {
    /// A row of a list of a sheet: group, member (`ElementFiche`).
    pub struct Element(ObjectSubclass<element::Element>);
}

impl Element {
    pub fn new(view: ElementView) -> Self {
        let element: Self = glib::Object::new();
        let _ = element.imp().view.set(view);
        element
    }

    pub fn view(&self) -> &ElementView {
        self.imp().view()
    }
}

// --- Children of a node ---------------------------------------------------------------

type Load = Box<dyn Fn(&Children)>;

mod children {
    use std::cell::{Cell, OnceCell, RefCell};

    use gtk::prelude::*;
    use gtk::subclass::prelude::*;
    use gtk::{gio, glib};

    use super::{Load, Node};

    #[derive(Default)]
    pub struct Children {
        pub node: OnceCell<Node>,
        pub nodes: RefCell<Vec<Node>>,
        pub to_load: Cell<bool>,
        pub load: OnceCell<Load>,
    }

    impl std::fmt::Debug for Children {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Children")
                .field("nodes", &self.nodes.borrow().len())
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Children {
        const NAME: &'static str = "AnnuaireEnfantsNoeud";
        type Type = super::Children;
        type Interfaces = (gio::ListModel,);
    }

    impl ObjectImpl for Children {}

    impl ListModelImpl for Children {
        fn item_type(&self) -> glib::Type {
            Node::static_type()
        }

        fn n_items(&self) -> u32 {
            if self.to_load.replace(false) {
                // The loading starts in the GLib loop, outside of this call of GTK.
                let model = self.obj().clone();
                glib::idle_add_local_once(move || {
                    if let Some(load) = model.imp().load.get() {
                        load(&model);
                    }
                });
            }
            u32::try_from(self.nodes.borrow().len()).unwrap_or(u32::MAX)
        }

        fn item(&self, position: u32) -> Option<glib::Object> {
            let index = usize::try_from(position).ok()?;
            self.nodes
                .borrow()
                .get(index)
                .map(|n| n.clone().upcast::<glib::Object>())
        }
    }
}

glib::wrapper! {
    /// Children of a node, loaded when the tree asks for them the first time
    /// (`EnfantsNoeud`): `GtkTreeListModel` only reads them when the node is expanded, so the
    /// loading of a level starts there (plan, J2.1).
    pub struct Children(ObjectSubclass<children::Children>)
        @implements gio::ListModel;
}

impl Children {
    pub fn new(node: &Node, load: Load) -> Self {
        let model: Self = glib::Object::new();
        let imp = model.imp();
        let _ = imp.node.set(node.clone());
        let _ = imp.load.set(load);
        imp.to_load.set(true);
        model
    }

    pub fn node(&self) -> Option<&Node> {
        self.imp().node.get()
    }

    pub fn fill(&self, nodes: Vec<Node>) {
        let imp = self.imp();
        let old = u32::try_from(imp.nodes.borrow().len()).unwrap_or(0);
        let new = u32::try_from(nodes.len()).unwrap_or(0);
        if let Some(node) = imp.node.get() {
            node.imp().childless.set(nodes.is_empty());
        }
        *imp.nodes.borrow_mut() = nodes;
        self.items_changed(0, old, new);
    }

    /// Whether the loading of this level started (the node was expanded once).
    pub fn loaded(&self) -> bool {
        !self.imp().to_load.get()
    }

    /// A failed loading: asked again at the next expansion.
    pub fn failed(&self) {
        self.imp().to_load.set(true);
    }
}

/// Registers the types that the Blueprint files name, before a template uses them.
pub fn ensure_types() {
    Node::ensure_type();
    Row::ensure_type();
    Element::ensure_type();
}

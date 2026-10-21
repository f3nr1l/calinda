// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The open domain (`AnnuaireFenetre`, J2.1 to J2.3): opening on a DC, tree of the containers,
//! contents of the chosen container in the table, by pages, quick filter, sort by column,
//! status bar. Read from the local copy when the profile keeps one (R4.4, JC.2), otherwise
//! directly on the DC: the copy is kept up to date by a delta every minute and at each
//! refresh; the status bar dates what the copy served.

use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;

use futures_util::StreamExt;

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_core::cache::{self, Source, SyncPhase, SyncState};
use annuaire_core::profile::Profile;
use annuaire_core::source::Item;
use annuaire_core::store::raw_parent;
use annuaire_core::sync::SYNC_INTERVAL;
use gtk::{gio, glib};

use super::{Content, Window};
use crate::errors::{self, Problem};
use crate::feed::Feed;
use crate::i18n::{fill, tr};
use crate::objects::{Children, Node, Row};
use crate::texts;
use crate::views::{self, Change, SortOrder};

/// Columns that the user shows or hides (`colonnes` key), with the name always shown and the
/// location shown for searches only.
/// Beyond this number of rows touched by a write, the table is rebuilt at once rather than
/// row by row (`RELECTURE_SUR_PLACE`).
const REREAD_IN_PLACE: usize = 50;

const OPTIONAL_COLUMNS: [&str; 8] = [
    "type",
    "identifiant",
    "description",
    "courriel",
    "etat",
    "activite",
    "modifie",
    "dn",
];

impl Window {
    fn advanced(&self) -> bool {
        self.settings().boolean("mode-avance")
    }

    /// Stateful actions (advanced mode, columns), the quick filter and the sort: once, at
    /// the construction of the window.
    pub(super) fn setup_domain(&self) {
        let imp = self.imp();
        let settings = self.settings();

        let advanced = gio::SimpleAction::new_stateful(
            "mode-avance",
            None,
            &settings.boolean("mode-avance").to_variant(),
        );
        let weak = self.downgrade();
        advanced.connect_change_state(move |action, value| {
            let (Some(window), Some(value)) = (weak.upgrade(), value) else {
                return;
            };
            action.set_state(value);
            let _ = window
                .settings()
                .set_boolean("mode-avance", value.get::<bool>().unwrap_or(false));
            if window.imp().source.borrow().is_some() {
                window.build_tree();
            }
        });
        self.add_action(&advanced);

        let visible = settings.strv("colonnes");
        let columns = imp.table.columns();
        for column in (0..columns.n_items())
            .filter_map(|i| columns.item(i).and_downcast::<gtk::ColumnViewColumn>())
        {
            let Some(id) = column.id().map(|id| id.to_string()) else {
                continue;
            };
            if !OPTIONAL_COLUMNS.contains(&id.as_str()) {
                continue;
            }
            let shown = visible.iter().any(|v| v.as_str() == id);
            column.set_visible(shown);
            let toggle = gio::SimpleAction::new_stateful(
                &format!("colonne-{id}"),
                None,
                &shown.to_variant(),
            );
            let weak = self.downgrade();
            toggle.connect_change_state(move |action, value| {
                let (Some(window), Some(value)) = (weak.upgrade(), value) else {
                    return;
                };
                action.set_state(value);
                let on = value.get::<bool>().unwrap_or(false);
                column.set_visible(on);
                let settings = window.settings();
                let mut shown: Vec<String> = settings
                    .strv("colonnes")
                    .iter()
                    .map(|s| s.to_string())
                    .filter(|s| *s != id)
                    .collect();
                if on {
                    shown.push(id.clone());
                }
                let refs: Vec<&str> = shown.iter().map(String::as_str).collect();
                let _ = settings.set_strv("colonnes", refs);
            });
            self.add_action(&toggle);
        }

        // Sort by column (headers of the table), name ascending at first, as the Windows
        // console: the rows are inserted at their place, not sorted by a `SortListModel`.
        if let Some(sorter) = imp.table.sorter() {
            let weak = self.downgrade();
            sorter.connect_changed(move |sorter, _| {
                if let Some(window) = weak.upgrade() {
                    window.order_changed(sorter);
                }
            });
        }
        imp.table
            .sort_by_column(Some(&*imp.name_column), gtk::SortType::Ascending);
        let terms = imp.terms.clone();
        imp.quick_filter.set_filter_func(move |item| {
            item.downcast_ref::<Row>()
                .is_some_and(|row| views::matches(&row.view().filter_key, &terms.borrow()))
        });
        // Typing in the contents opens the quick filter (key-capture-widget).
        imp.filter_bar.connect_entry(&*imp.filter_entry);
        if let Some(application) = self.application() {
            application.set_accels_for_action("win.rechercher", &["<Control>f"]);
        }
    }

    // --- Opening -------------------------------------------------------------------

    /// Opens the source of the domain (off the interface thread), then shows it.
    pub(super) fn open_domain(&self, profile: Profile) {
        let home = &self.imp().home;
        home.wait(&profile.domain, true);
        let source = cache::source_for(profile.clone());
        let weak = self.downgrade();
        glib::spawn_future_local(async move {
            let opening = source.clone();
            let opened = gio::spawn_blocking(move || opening.open()).await;
            let Some(window) = weak.upgrade() else { return };
            window.imp().home.wait(&profile.domain, false);
            match opened {
                Ok(Ok(root)) => window.show_domain(source, profile, &root),
                Ok(Err(failure)) => {
                    source.close();
                    let problem = errors::failure_problem(&failure, &profile.domain);
                    window.opening_failed(&profile, &problem);
                }
                Err(_) => source.close(),
            }
        });
    }

    fn opening_failed(&self, profile: &Profile, problem: &Problem) {
        if problem.ticket {
            let again = profile.clone();
            self.ask_ticket_then(
                Some(profile),
                Some(Box::new(move |window: &Window| {
                    window.open_domain(again.clone())
                })),
            );
            return;
        }
        self.report(
            problem,
            &fill(
                &tr("Cannot connect to {domaine}"),
                &[("domaine", &profile.domain)],
            ),
        );
        if problem.kerberos {
            self.imp().home.refresh_ticket();
        }
    }

    /// A blocking error: a dialog with the message and the technical detail (`signaler`).
    pub(crate) fn report(&self, problem: &Problem, title: &str) {
        let body = if problem.detail.is_empty() {
            problem.message.clone()
        } else {
            format!("{}\n\n{}", problem.message, problem.detail)
        };
        let alert = adw::AlertDialog::new(Some(title), Some(&body));
        alert.add_response("fermer", &tr("Close"));
        alert.present(Some(self));
    }

    fn show_domain(&self, source: Arc<dyn Source>, profile: Profile, root: &str) {
        self.close_domain();
        let imp = self.imp();
        imp.domain_title.set_title(&profile.domain);
        // The state of access stays visible all the time (plan, 0.1).
        imp.domain_title
            .set_subtitle(&texts::access_label(&profile));
        *imp.source.borrow_mut() = Some(source.clone());
        *imp.profile.borrow_mut() = Some(profile.clone());
        self.build_tree_with_root(&profile.domain, root);
        imp.stack.set_visible_child_name("domaine");
        imp.tree.grab_focus(); // J2.9: the keyboard path starts from the tree
        self.follow_copy(&source);
        self.update_actions();
        crate::history::propose_resume(self);
    }

    /// History of the changes of the open domain (`historique`).
    pub(super) fn show_history(&self) {
        if self.source().is_none() {
            return;
        }
        if let Some(context) = self.write_context() {
            crate::history::HistoryDialog::new(context).present(Some(self));
        }
    }

    // --- Local copy (JC.2) -------------------------------------------------------------

    /// The states of the copy, heard from the thread of the synchronization, go to the loop
    /// of the interface by a channel; a delta every minute.
    fn follow_copy(&self, source: &Arc<dyn Source>) {
        let (sender, mut states) = futures_channel::mpsc::unbounded::<SyncState>();
        source.listen(Box::new(move |state| {
            let _ = sender.unbounded_send(state);
        }));
        let (weak, heard) = (self.downgrade(), Arc::downgrade(source));
        glib::spawn_future_local(async move {
            while let Some(state) = states.next().await {
                let (Some(window), Some(source)) = (weak.upgrade(), heard.upgrade()) else {
                    return;
                };
                window.sync_received(&source, state);
            }
        });
        let weak = self.downgrade();
        let timer = glib::timeout_add_seconds_local(
            u32::try_from(SYNC_INTERVAL.as_secs()).unwrap_or(60),
            move || {
                let source = weak.upgrade().and_then(|w| w.source());
                match source {
                    Some(source) => {
                        source.synchronize();
                        glib::ControlFlow::Continue
                    }
                    None => glib::ControlFlow::Break,
                }
            },
        );
        *self.imp().timer.borrow_mut() = Some(timer);
    }

    fn show_copy(&self) {
        let imp = self.imp();
        let domain = imp
            .profile
            .borrow()
            .as_ref()
            .map(|p| p.domain.clone())
            .unwrap_or_default();
        let state = imp.sync_state.borrow();
        let error = state
            .as_ref()
            .and_then(|s| s.error.as_deref())
            .map(|e| errors::sync_message(e, &domain))
            .unwrap_or_default();
        let (text, tooltip) = texts::describe_copy(imp.shown_date.get(), state.as_ref(), &error);
        imp.freshness.set_label(&text);
        imp.freshness
            .set_tooltip_text((!tooltip.is_empty()).then_some(tooltip.as_str()));
    }

    /// A step of a synchronization: the status bar, then the display brought up to date
    /// from what the copy received (`_synchro_recue`): the rows changed are updated in place
    /// as after a write (J2.11).
    fn sync_received(&self, source: &Arc<dyn Source>, state: SyncState) {
        let imp = self.imp();
        let current = imp.source.borrow().clone();
        if !current.is_some_and(|c| std::ptr::addr_eq(Arc::as_ptr(&c), Arc::as_ptr(source))) {
            return; // domain closed meanwhile
        }
        let shown = imp.shown_date.get().is_some();
        let (complete, changes) = (state.complete, state.changes.clone());
        let up_to_date = state.phase == SyncPhase::UpToDate && state.date.is_some();
        let date = state.date;
        *imp.sync_state.borrow_mut() = Some(state);
        if up_to_date {
            if complete {
                // Copy made anew: everything is read again, from it.
                self.reload_tree(None);
                self.read_again();
            } else if let (Some(changes), true) = (changes, shown) {
                imp.shown_date.set(date);
                self.apply_delta(source, &changes);
                // The levels of the tree where an object appeared, left or moved.
                let parents: HashSet<String> = changes
                    .objects
                    .values()
                    .filter(|(before, after)| before != after)
                    .flat_map(|(before, after)| [before, after])
                    .flatten()
                    .map(|dn| raw_parent(dn))
                    .collect();
                if !parents.is_empty() {
                    self.reload_tree(Some(&parents));
                }
            } else if shown {
                imp.shown_date.set(date);
            }
        }
        self.show_copy();
    }

    /// What a delta changed, read from the copy, then applied as a reading again after a
    /// write (`_appliquer_delta`); an object that appeared may satisfy a search: it is then
    /// read again.
    fn apply_delta(&self, source: &Arc<dyn Source>, changes: &annuaire_core::store::Changes) {
        let (source, changes, weak) = (source.clone(), changes.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let read = gio::spawn_blocking(move || source.delta_reread(&changes)).await;
            let Some(window) = weak.upgrade() else { return };
            let Ok(Some(reread)) = read else {
                window.read_again();
                return;
            };
            let search = window
                .imp()
                .content
                .borrow()
                .as_ref()
                .is_some_and(|c| c.search);
            if search && !reread.appeared.is_empty() {
                window.read_again();
            } else {
                window.apply_reread(&reread);
            }
        });
    }

    /// Reads the levels of the tree already loaded again: all, or those of these DN (keys).
    fn reload_tree(&self, parents: Option<&HashSet<String>>) {
        let levels: Vec<_> = self
            .imp()
            .children
            .borrow()
            .iter()
            .filter(|(dn, children)| {
                children.loaded() && parents.is_none_or(|p| p.contains(&dn.to_lowercase()))
            })
            .map(|(_, children)| children.clone())
            .collect();
        for children in levels {
            self.load_children(&children);
        }
    }

    /// The table read again, without asking a delta.
    fn read_again(&self) {
        let content = self.imp().content.borrow().clone();
        if let Some(content) = content {
            self.show(content);
        }
    }

    /// Ctrl+F: the search bar of the domain (sidebar).
    pub(super) fn focus_search(&self) {
        let imp = self.imp();
        if imp.source.borrow().is_none() {
            return;
        }
        imp.split_view.set_show_content(false);
        imp.search.focus_input();
    }

    /// Closes the domain and goes back to the home screen (`fermer_domaine`).
    pub(super) fn close_domain(&self) {
        let imp = self.imp();
        if let Some(dns) = imp.dns.take() {
            dns.close();
        }
        if let Some(gpo) = imp.gpo.take() {
            gpo.close();
        }
        if let Some(pso) = imp.pso.take() {
            pso.close();
        }
        self.stop_contents();
        imp.search.forget_domain();
        *imp.content.borrow_mut() = None;
        for feed in imp.tree_feeds.take() {
            feed.cancel();
        }
        imp.children.borrow_mut().clear();
        imp.tree_selection.set_model(None::<&gio::ListModel>);
        imp.content_store.remove_all();
        imp.keys.borrow_mut().clear();
        if let Some(timer) = imp.timer.take() {
            timer.remove();
        }
        if let Some(writes) = imp.writes.take() {
            writes.close();
        }
        imp.sync_state.take();
        imp.shown_date.set(None);
        imp.freshness.set_label("");
        imp.freshness.set_tooltip_text(None);
        if let Some(source) = imp.source.take() {
            source.close();
        }
        let domain = imp.profile.take().map(|p| p.domain);
        self.update_actions();
        if imp.stack.visible_child_name().as_deref() != Some("accueil") {
            imp.stack.set_visible_child_name("accueil");
            imp.home.take_focus(domain.as_deref());
            imp.home.refresh_ticket();
        }
    }

    // --- Tree ----------------------------------------------------------------------

    fn build_tree(&self) {
        let (domain, root) = {
            let imp = self.imp();
            let profile = imp.profile.borrow();
            let source = imp.source.borrow();
            match (profile.as_ref(), source.as_ref().and_then(|s| s.root())) {
                (Some(p), Some(root)) => (p.domain.clone(), root),
                _ => return,
            }
        };
        self.build_tree_with_root(&domain, &root);
    }

    fn build_tree_with_root(&self, domain: &str, root: &str) {
        let imp = self.imp();
        for feed in imp.tree_feeds.take() {
            feed.cancel();
        }
        imp.children.borrow_mut().clear();
        let roots = gio::ListStore::new::<Node>();
        roots.append(&Node::new(views::root_node(domain, root)));
        let weak = self.downgrade();
        let model = gtk::TreeListModel::new(roots, false, false, move |item| {
            let window = weak.upgrade()?;
            let node = item.downcast_ref::<Node>()?;
            window.children_of(node).map(|c| c.upcast())
        });
        // Selects the root: its contents are shown.
        imp.tree_selection.set_model(Some(&model));
        if let Some(row) = model.row(0) {
            row.set_expanded(true);
        }
    }

    /// Model of the children of a node (`GtkTreeListModel`); loads nothing by itself.
    fn children_of(&self, node: &Node) -> Option<Children> {
        if node.childless() {
            return None;
        }
        let dn = node.view().dn.clone();
        let mut children = self.imp().children.borrow_mut();
        let model = children.entry(dn).or_insert_with(|| {
            let weak = self.downgrade();
            Children::new(
                node,
                Box::new(move |children| {
                    if let Some(window) = weak.upgrade() {
                        window.load_children(children);
                    }
                }),
            )
        });
        Some(model.clone())
    }

    /// A level of the tree: the containers directly under the node.
    fn load_children(&self, children: &Children) {
        let Some(source) = self.imp().source.borrow().clone() else {
            return;
        };
        let Some(dn) = children.node().map(|n| n.view().dn.clone()) else {
            return;
        };
        let advanced = self.advanced();
        let received = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let (into, weak, model) = (received.clone(), self.downgrade(), children.clone());
        let domain = source.profile().domain.clone();
        let feed = Feed::start(
            |notifier| source.containers(&dn, advanced, notifier).flux,
            move |items: Vec<Item>| {
                into.borrow_mut()
                    .extend(items.iter().map(views::node_from_item));
            },
            move |error| {
                let Some(window) = weak.upgrade() else { return };
                window.forget_finished_feeds();
                if let Some(error) = error {
                    model.failed();
                    window.toast(&errors::search_problem(&error, &domain).message);
                    return;
                }
                let mut nodes = received.take();
                views::sort_nodes(&mut nodes);
                model.fill(nodes.into_iter().map(Node::new).collect());
            },
        );
        self.imp().tree_feeds.borrow_mut().push(feed);
    }

    fn forget_finished_feeds(&self) {
        self.imp().tree_feeds.borrow_mut().retain(|f| !f.finished());
    }

    pub(super) fn node_chosen(&self) {
        let imp = self.imp();
        let Some(row) = imp
            .tree_selection
            .selected_item()
            .and_downcast::<gtk::TreeListRow>()
        else {
            return;
        };
        let Some(node) = row.item().and_downcast::<Node>() else {
            return;
        };
        if imp.source.borrow().is_none() {
            return;
        }
        let (dn, advanced) = (node.view().dn.clone(), self.advanced());
        let container = Some(dn.clone());
        self.show(Content {
            title: node.view().name.clone(),
            search: false,
            read: Rc::new(move |source, notifier| source.contents(&dn, advanced, notifier)),
            finished: None,
            container,
            keep_activity: false,
        });
        imp.split_view.set_show_content(true);
    }

    // --- Table ---------------------------------------------------------------------

    fn stop_contents(&self) {
        let imp = self.imp();
        if let Some(feed) = imp.content_feed.take() {
            feed.cancel();
        }
        imp.loading.set_spinning(false);
    }

    /// Fills the table with what `content` reads, page by page (`afficher`).
    pub fn show(&self, content: Content) {
        let imp = self.imp();
        let Some(source) = imp.source.borrow().clone() else {
            return;
        };
        self.stop_contents();
        imp.content_store.remove_all();
        imp.keys.borrow_mut().clear();
        imp.content_title.set_title(&content.title);
        imp.content_page.set_title(&content.title);
        imp.location_column.set_visible(content.search);
        imp.empty_page.set_title(&if content.search {
            tr("No results")
        } else {
            tr("Empty container")
        });
        imp.content_stack.set_visible_child_name("table");
        imp.loading.set_spinning(true);
        let domain = source.profile().domain.clone();
        let (deliver_to, finish_to) = (self.downgrade(), self.downgrade());
        let (read, finished) = (content.read.clone(), content.finished.clone());
        *imp.content.borrow_mut() = Some(content);
        let mut copy_date = None;
        let feed = Feed::start(
            |notifier| {
                let pages = read(&source, notifier);
                copy_date = pages.copy_date;
                pages.flux
            },
            move |items: Vec<Item>| {
                if let Some(window) = deliver_to.upgrade() {
                    window.receive(&items);
                }
            },
            move |error| {
                if let Some(window) = finish_to.upgrade() {
                    let ok = error.is_none();
                    window.contents_finished(error.map(|e| errors::search_problem(&e, &domain)));
                    if let (true, Some(finished)) = (ok, finished) {
                        finished(&window);
                    }
                }
            },
        );
        *imp.content_feed.borrow_mut() = Some(feed);
        // Local copy: date of the copy shown; nothing for a reading on the DC.
        imp.shown_date.set(copy_date);
        self.show_copy();
        self.count();
    }

    /// Whether the table shows `content` (the same reading, not only the same title).
    pub fn shows(&self, content: &Content) -> bool {
        self.imp()
            .content
            .borrow()
            .as_ref()
            .is_some_and(|c| Rc::ptr_eq(&c.read, &content.read))
    }

    /// The write context of the open domain (connection to the PDC emulator, journal),
    /// opened at first need.
    pub fn write_context(&self) -> Option<Arc<crate::writes::WriteContext>> {
        let imp = self.imp();
        let profile = imp.profile.borrow().clone()?;
        Some(
            imp.writes
                .borrow_mut()
                .get_or_insert_with(|| Arc::new(crate::writes::WriteContext::new(profile)))
                .clone(),
        )
    }

    /// The connection to the PDC emulator of the open domain: group policies and writes.
    pub fn writes(&self) -> Option<Arc<annuaire_core::connection::Connection>> {
        self.write_context().map(|c| c.connection.clone())
    }

    /// After a write (`_apres_ecriture`, J2.11): the objects touched are read again on the
    /// DC of the writes (the connection of the write context), the source holds them for
    /// their present state until its DC has them (and the local copy takes them), the rows of
    /// the table are updated in place and the levels of the tree of the parents read again.
    pub fn after_write(&self, report: &annuaire_core::changes::Report) {
        let imp = self.imp();
        let (Some(source), Some(context)) = (self.source(), self.write_context()) else {
            return;
        };
        if !imp.reread_ids.borrow_mut().insert(report.id.clone()) {
            return; // already read again (the toast and the sheet both ask)
        }
        let mut parents: HashSet<String> = HashSet::new();
        let rollback = report.rollback.iter().flat_map(|c| c.operations.iter());
        for op in report.changeset.operations.iter().chain(rollback) {
            parents.insert(raw_parent(op.dn()));
            if let annuaire_core::changes::Operation::Rename {
                parent: Some(parent),
                ..
            } = op
            {
                parents.insert(parent.to_lowercase());
            }
        }
        let touched = annuaire_core::reread::touched(report);
        let (connection, weak) = (context.connection.clone(), self.downgrade());
        glib::spawn_future_local(async move {
            let for_source = source.clone();
            let read = gio::spawn_blocking(move || {
                let reread = annuaire_core::reread::reread(&connection, &touched)?;
                for_source.note_written(&reread, connection);
                Ok::<_, annuaire_core::connection::Failure>(reread)
            })
            .await;
            let Some(window) = weak.upgrade() else { return };
            let current = window.source();
            if !current.is_some_and(|c| std::ptr::addr_eq(Arc::as_ptr(&c), Arc::as_ptr(&source))) {
                return; // domain closed meanwhile
            }
            window.reload_tree(Some(&parents));
            match read {
                Ok(Ok(reread)) => window.apply_reread(&reread),
                Ok(Err(failure)) => {
                    let problem = errors::failure_problem(&failure, &source.profile().domain);
                    if std::env::var_os("ANNUAIRE_ESSAI_ETAPES").is_some() {
                        eprintln!("essai relecture impossible : {}", problem.message);
                    }
                    window.toast(&fill(
                        &tr("Cannot read again on the write DC ({message}): list read again."),
                        &[("message", &problem.message)],
                    ));
                    window.read_again();
                }
                Err(_) => window.read_again(),
            }
        });
    }

    /// The rows touched updated in place, from the objects read again, without starting the
    /// reading again (`appliquer_relecture`, J2.11).
    pub fn apply_reread(&self, reread: &annuaire_core::reread::Reread) {
        let imp = self.imp();
        let Some(content) = imp.content.borrow().clone() else {
            return;
        };
        if imp.content_feed.borrow().is_some() {
            self.read_again(); // reading in progress, started before the write: done again
            return;
        }
        if std::env::var_os("ANNUAIRE_ESSAI_ETAPES").is_some() {
            eprintln!(
                "essai relecture : {} objet(s) relu(s), {} ligne(s)",
                reread.objects.len(),
                imp.content_store.n_items()
            );
        }
        let rows: Vec<Row> = (0..imp.content_store.n_items())
            .filter_map(|i| imp.content_store.item(i).and_downcast::<Row>())
            .collect();
        let dns: Vec<String> = rows.iter().map(|r| r.view().dn.clone()).collect();
        let update = views::update(&dns, reread, content.container.as_deref());
        if update.is_empty() {
            return;
        }
        if std::env::var_os("ANNUAIRE_ESSAI_ETAPES").is_some() {
            eprintln!(
                "essai relecture : {} remplacée(s), {} retirée(s), {} ajoutée(s)",
                update.replace.len(),
                update.remove.len(),
                update.add.len()
            );
        }
        // The selection is on the filtered rows: it is found again by DN.
        let chosen: HashSet<String> = (0..imp.selection.n_items())
            .filter(|&i| imp.selection.is_selected(i))
            .filter_map(|i| imp.selection.item(i).and_downcast::<Row>())
            .map(|r| r.view().dn.clone())
            .collect();
        let read_again = |old: Option<&Row>, item: &Item| -> Row {
            let mut view = views::row_from_item(item);
            if let (true, Some(old)) = (content.keep_activity, old) {
                view.activity_sort = old.view().activity_sort;
            }
            Row::new(view)
        };
        let new: Vec<(usize, Row)> = update
            .replace
            .iter()
            .map(|(p, item)| (*p, read_again(rows.get(*p), item)))
            .collect();
        let added: Vec<Row> = update.add.iter().map(|i| read_again(None, i)).collect();
        let mut reselect: HashSet<String> = new
            .iter()
            .filter(|(p, _)| rows.get(*p).is_some_and(|r| chosen.contains(&r.view().dn)))
            .map(|(_, r)| r.view().dn.clone())
            .collect();
        let mut leaving: Vec<usize> = update
            .remove
            .iter()
            .copied()
            .chain(new.iter().map(|(p, _)| *p))
            .collect();
        leaving.sort_unstable();
        leaving.dedup();
        if leaving.len() + added.len() <= REREAD_IN_PLACE {
            let mut keys = imp.keys.borrow_mut();
            for &position in leaving.iter().rev() {
                imp.content_store
                    .remove(u32::try_from(position).unwrap_or(u32::MAX));
                keys.remove(position);
            }
            for row in new.iter().map(|(_, r)| r).chain(&added) {
                let position = keys.insert(row.view());
                imp.content_store
                    .insert(u32::try_from(position).unwrap_or(u32::MAX), row);
            }
        } else {
            // Many rows (a batch disabled): one « items-changed » and one sort.
            reselect.extend(chosen);
            let replaced: std::collections::HashMap<usize, Row> = new.into_iter().collect();
            let mut all: Vec<Row> = rows
                .iter()
                .enumerate()
                .filter(|(p, _)| !update.remove.contains(p))
                .map(|(p, r)| replaced.get(&p).cloned().unwrap_or_else(|| r.clone()))
                .collect();
            all.extend(added);
            let views: Vec<_> = all.iter().map(Row::view).collect();
            let order = imp.keys.borrow().order.clone();
            let ranks = imp.keys.borrow_mut().sort(&views, order);
            let sorted: Vec<glib::Object> = ranks
                .into_iter()
                .filter_map(|i| all.get(i).map(|r| r.clone().upcast()))
                .collect();
            imp.content_store
                .splice(0, imp.content_store.n_items(), &sorted);
        }
        if !reselect.is_empty() {
            self.reselect(reselect);
        }
        self.count();
    }

    /// Selects the rows of these DN, once the quick filter (incremental) has passed
    /// (`_reselectionner`).
    fn reselect(&self, dns: HashSet<String>) {
        let weak = self.downgrade();
        let attempt = move || {
            let Some(window) = weak.upgrade() else {
                return glib::ControlFlow::Break;
            };
            let imp = window.imp();
            if imp.filter.pending() > 0 {
                return glib::ControlFlow::Continue;
            }
            for position in 0..imp.selection.n_items() {
                let row = imp.selection.item(position).and_downcast::<Row>();
                if row.is_some_and(|r| dns.contains(&r.view().dn)) {
                    imp.selection.select_item(position, false);
                }
            }
            glib::ControlFlow::Break
        };
        glib::timeout_add_local(std::time::Duration::from_millis(20), attempt);
    }

    pub fn add_toast(&self, toast: adw::Toast) {
        self.imp().toasts.add_toast(toast);
    }

    pub fn source(&self) -> Option<Arc<dyn Source>> {
        self.imp().source.borrow().clone()
    }

    pub fn show_content(&self) {
        self.imp().split_view.set_show_content(true);
    }

    fn receive(&self, items: &[Item]) {
        let imp = self.imp();
        let mut keys = imp.keys.borrow_mut();
        for item in items {
            let row = Row::new(views::row_from_item(item));
            let position = keys.insert(row.view());
            imp.content_store
                .insert(u32::try_from(position).unwrap_or(u32::MAX), &row);
        }
    }

    fn contents_finished(&self, problem: Option<Problem>) {
        let imp = self.imp();
        imp.content_feed.take();
        imp.loading.set_spinning(false);
        self.count();
        let empty = imp.content_store.n_items() == 0;
        match problem {
            None if empty => imp.content_stack.set_visible_child_name("vide"),
            None => {}
            Some(problem) if empty => {
                imp.content_error.set_title(&problem.message);
                imp.content_error.set_description(Some(&problem.detail));
                imp.content_stack.set_visible_child_name("erreur");
            }
            Some(problem) => self.toast(&fill(
                &tr("Incomplete list: {message}"),
                &[("message", &problem.message)],
            )),
        }
    }

    pub(super) fn refresh(&self) {
        let content = self.imp().content.borrow().clone();
        if let (Some(content), Some(source)) = (content, self.source()) {
            self.show(content);
            source.synchronize();
        }
    }

    /// The sheet of the object of an activated row (`row_activated`).
    pub(super) fn row_activated(&self, position: u32) {
        let imp = self.imp();
        let (Some(row), Some(source)) = (
            imp.selection.item(position).and_downcast::<Row>(),
            self.source(),
        ) else {
            return;
        };
        crate::sheet::Sheet::new(source, &row.view().dn).present(Some(self));
    }

    pub(super) fn count(&self) {
        let imp = self.imp();
        let loading = imp.content_feed.borrow().is_some();
        imp.counter.set_label(&views::describe_count(
            u64::from(imp.selection.n_items()),
            u64::from(imp.content_store.n_items()),
            loading,
        ));
    }

    pub(super) fn filter_changed(&self) {
        let imp = self.imp();
        let terms = views::filter_terms(&imp.filter_entry.text());
        let change = views::filter_change(&imp.terms.borrow(), &terms);
        *imp.terms.borrow_mut() = terms;
        let change = match change {
            Change::Same => return,
            Change::MoreStrict => gtk::FilterChange::MoreStrict,
            Change::LessStrict => gtk::FilterChange::LessStrict,
            Change::Different => gtk::FilterChange::Different,
        };
        imp.quick_filter.changed(change);
    }

    fn order_changed(&self, sorter: &gtk::Sorter) {
        let Some(sorter) = sorter.downcast_ref::<gtk::ColumnViewSorter>() else {
            return;
        };
        let Some(id) = sorter.primary_sort_column().and_then(|c| c.id()) else {
            return;
        };
        let order = SortOrder {
            column: id.to_string(),
            descending: sorter.primary_sort_order() == gtk::SortType::Descending,
        };
        let imp = self.imp();
        if order == imp.keys.borrow().order {
            return;
        }
        let rows: Vec<Row> = (0..imp.content_store.n_items())
            .filter_map(|i| imp.content_store.item(i).and_downcast::<Row>())
            .collect();
        let views: Vec<_> = rows.iter().map(Row::view).collect();
        let ranks = imp.keys.borrow_mut().sort(&views, order);
        let sorted: Vec<glib::Object> = ranks
            .into_iter()
            .filter_map(|i| rows.get(i).map(|r| r.clone().upcast()))
            .collect();
        imp.content_store
            .splice(0, imp.content_store.n_items(), &sorted);
    }

    // --- Trials (`trial`) ----------------------------------------------------------

    /// Selects the node of the tree at `path` (names separated by `/`, from a child of the
    /// root), expanding the nodes on the way; true once selected, false to try again later.
    pub fn trial_select(&self, path: &str) -> bool {
        let selection = &self.imp().tree_selection;
        let names: Vec<&str> = path.split('/').collect();
        // Depth 1: under the root.
        for (depth, (index, name)) in (1..).zip(names.iter().enumerate()) {
            let row = (0..selection.n_items())
                .filter_map(|p| Some((p, selection.item(p).and_downcast::<gtk::TreeListRow>()?)))
                .find(|(_, row)| {
                    row.depth() == depth
                        && row
                            .item()
                            .and_downcast::<Node>()
                            .is_some_and(|n| n.view().name == *name)
                });
            let Some((position, row)) = row else {
                return false;
            };
            if index + 1 == names.len() {
                selection.set_selected(position);
                return true;
            }
            row.set_expanded(true);
        }
        false
    }

    /// Title of what the table shows (trials).
    pub fn trial_title(&self) -> Option<String> {
        self.imp()
            .content
            .borrow()
            .as_ref()
            .map(|c| c.title.clone())
    }

    /// Rows of the table once its reading is over; None while it runs.
    pub fn trial_rows(&self) -> Option<u32> {
        let imp = self.imp();
        imp.content_feed
            .borrow()
            .is_none()
            .then(|| imp.content_store.n_items())
    }

    /// The search bar of the window (trials).
    pub fn search_bar(&self) -> crate::search::Search {
        self.imp().search.get()
    }

    /// Rows of the table, read or not (trials: time of the first rows).
    pub fn trial_shown_rows(&self) -> u32 {
        self.imp().content_store.n_items()
    }
}

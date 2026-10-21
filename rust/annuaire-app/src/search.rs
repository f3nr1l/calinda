// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Global search bar and saved queries (J2.3, `annuaire.ui.recherche` and
//! `annuaire.vue.recherche`), structure in `recherche.blp`. The filters come from
//! `annuaire_core::queries`; the results fill the central table as the contents of an OU
//! (`Window::show`), with the location column. The searches the user saves go to the
//! GSettings key `recherches`: text, kind and state of a search of the bar, or a ready query
//! with its parameters; the number of days of the inactive accounts is kept
//! (`jours-inactivite`).

use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex, PoisonError};

use adw::prelude::*;
use adw::subclass::prelude::*;
use annuaire_codecs::time;
use annuaire_core::cache::{Pages, Source};
use annuaire_core::connection::Failure;
use annuaire_core::model::Object;
use annuaire_core::queries::{self, Execution, Kind, Query, State};
use annuaire_core::search::SearchError;
use annuaire_core::source::{CAPACITY, Item, Notifier, ObjectFlux, SurveyError};
use gtk::{gio, glib};

use crate::errors;
use crate::i18n::{fill, tr, tr_n};
use crate::views::normalize;
use crate::window::{Content, Window};

const KEY: &str = "recherches";
const DAYS_KEY: &str = "jours-inactivite";
/// Proposed for "inactive for N days" (six months), then the last number chosen.
pub const INACTIVE_DAYS: i64 = 180;
const MAX_DAYS: i64 = 3650;
const NTTIME_PER_DAY: i64 = 86_400 * 10_000_000;

fn kind_label(kind: Kind) -> String {
    match kind {
        Kind::All => tr("All types"),
        Kind::User => tr("Users"),
        Kind::Computer => tr("Computers"),
        Kind::Group => tr("Groups"),
        Kind::Contact => tr("Contacts"),
        Kind::Ou => tr("Organizational units"),
    }
}

fn state_label(state: State) -> String {
    match state {
        State::All => tr("All states"),
        State::Enabled => tr("Enabled accounts"),
        State::Disabled => tr("Disabled accounts"),
    }
}

fn with_details(title: String, kind: Kind, state: State) -> String {
    let mut parts = Vec::new();
    if kind != Kind::All {
        parts.push(kind_label(kind).to_lowercase());
    }
    if state != State::All {
        parts.push(state_label(state).to_lowercase());
    }
    if parts.is_empty() {
        title
    } else {
        format!("{title} ({})", parts.join(", "))
    }
}

fn joined(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Title of the table for a search: « Search “dupont” (users) » (`titre_recherche`).
pub fn search_title(input: &str, kind: Kind, state: State) -> String {
    let text = joined(input);
    let title = if text.is_empty() {
        tr("All objects in the domain")
    } else {
        fill(&tr("Search “{texte}”"), &[("texte", &text)])
    };
    with_details(title, kind, state)
}

/// Title of a ready query (`titre_requete`).
pub fn query_title(query: Query, kind: Kind, state: State, days: i64) -> String {
    let title = match query {
        Query::Inactive => fill(
            &tr_n(
                "Inactive for {n} day",
                "Inactive for {n} days",
                days.unsigned_abs(),
            ),
            &[("n", &days.to_string())],
        ),
        Query::Disabled => tr("Disabled accounts"),
        Query::Locked => tr("Locked-out accounts"),
        Query::PasswordNeverExpires => tr("Password that never expires"),
        Query::Administrators => tr("Administrators (recursive)"),
        Query::NeverLoggedOn => tr("Accounts that never logged on"),
        Query::Conflicts => tr("Conflicting objects (CNF)"),
    };
    with_details(title, kind, state)
}

/// Now, as NTTIME.
fn now_nttime() -> i64 {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(0));
    time::unix_to_nttime(seconds).unwrap_or(0)
}

/// A search kept by the user under a name (`RechercheEnregistree`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Saved {
    pub name: String,
    pub text: String,
    pub kind: Kind,
    pub state: State,
    pub query: Option<Query>,
    pub days: i64,
}

impl Saved {
    fn to_fields(&self) -> BTreeMap<&'static str, String> {
        let mut fields = BTreeMap::new();
        fields.insert("nom", self.name.clone());
        fields.insert("texte", self.text.clone());
        fields.insert("type", self.kind.name().into());
        fields.insert("etat", self.state.name().into());
        if let Some(query) = self.query {
            fields.insert("requete", query.name().into());
            if query == Query::Inactive {
                fields.insert("jours", self.days.to_string());
            }
        }
        fields
    }

    /// Inverse of `to_fields`; None if the name is missing or a value unknown.
    fn from_fields(fields: &BTreeMap<String, String>) -> Option<Self> {
        let get = |k: &str| fields.get(k).map(String::as_str);
        let name = get("nom")?.trim().to_owned();
        if name.is_empty() {
            return None;
        }
        let days = match get("jours") {
            Some(d) => d.parse().ok()?,
            None => INACTIVE_DAYS,
        };
        if !(0..=MAX_DAYS).contains(&days) {
            return None;
        }
        let query = match get("requete").filter(|q| !q.is_empty()) {
            Some(q) => Some(Query::from_name(q)?),
            None => None,
        };
        Some(Self {
            name,
            text: get("texte").unwrap_or_default().to_owned(),
            kind: Kind::from_name(get("type").unwrap_or("tous"))?,
            state: State::from_name(get("etat").unwrap_or("tous"))?,
            query,
            days,
        })
    }

    /// Name proposed when saving: the input, or the title of the query.
    fn proposed_name(&self) -> String {
        match self.query {
            None => joined(&self.text),
            Some(query) => query_title(query, self.kind, self.state, self.days),
        }
    }
}

/// List where `new` replaces the search of the same name, sorted by name.
fn with_saved(list: Vec<Saved>, new: Saved) -> Vec<Saved> {
    let mut list: Vec<Saved> = list.into_iter().filter(|s| s.name != new.name).collect();
    list.push(new);
    list.sort_by_cached_key(|s| (normalize(&s.name), s.name.clone()));
    list
}

/// What starts the last search again, when the kind or state change.
type Relaunch = Rc<dyn Fn(&Search)>;

/// The search error of a failure to connect or to read (a survey that did not end).
fn search_error(failure: Failure) -> SearchError {
    match failure {
        Failure::Connect(f) => SearchError::Connect(f),
        Failure::Ldap { dc, error } => SearchError::Ldap { dc, error },
    }
}

mod imp {
    use std::cell::{OnceCell, RefCell};

    use adw::subclass::prelude::*;
    use annuaire_core::model::DomainPolicy;
    use gtk::{gio, glib};

    use crate::scope::TemplateScope;
    use crate::window::Content;

    #[derive(Default, gtk::CompositeTemplate)]
    #[template(resource = "/io/github/f3nr1l/Calinda/ui/recherche.ui")]
    pub struct Search {
        #[template_child]
        pub entry: TemplateChild<gtk::SearchEntry>,
        #[template_child]
        pub type_combo: TemplateChild<gtk::DropDown>,
        #[template_child]
        pub state_dropdown: TemplateChild<gtk::DropDown>,
        #[template_child]
        pub queries_menu: TemplateChild<gio::Menu>,
        #[template_child]
        pub inactive_dialog: TemplateChild<adw::AlertDialog>,
        #[template_child]
        pub days: TemplateChild<adw::SpinRow>,
        #[template_child]
        pub save_dialog: TemplateChild<adw::AlertDialog>,
        #[template_child]
        pub search_name: TemplateChild<adw::EntryRow>,
        pub personal: OnceCell<gio::Menu>,
        /// The last content started from here: started again if the kind or state change.
        pub content: RefCell<Option<Content>>,
        pub relaunch: RefCell<Option<super::Relaunch>>,
        /// What the last content started from here looked for: what « Save » keeps.
        pub last: RefCell<Option<super::Saved>>,
        pub to_save: RefCell<Option<super::Saved>>,
        pub policy: RefCell<Option<DomainPolicy>>,
    }

    impl std::fmt::Debug for Search {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("Search")
                .field("content", &self.content)
                .field("last", &self.last)
                .finish_non_exhaustive()
        }
    }

    #[glib::object_subclass]
    impl ObjectSubclass for Search {
        const NAME: &'static str = "AnnuaireRecherche";
        type Type = super::Search;
        type ParentType = gtk::Box;

        fn class_init(klass: &mut Self::Class) {
            klass.bind_template();
            klass.set_template_scope(&TemplateScope::new::<super::Search>(&[
                ("run", |s, _| {
                    s.launch();
                    None
                }),
                ("filters_changed", |s, _| {
                    s.filters_changed();
                    None
                }),
                ("inactive_answered", |s, values| {
                    let response = values.get(1).and_then(|v| v.get::<String>().ok());
                    s.days_answered(response.as_deref());
                    None
                }),
                ("save_answered", |s, values| {
                    let response = values.get(1).and_then(|v| v.get::<String>().ok());
                    s.save_answered(response.as_deref());
                    None
                }),
            ]));
        }

        fn instance_init(obj: &glib::subclass::InitializingObject<Self>) {
            obj.init_template();
        }
    }

    impl ObjectImpl for Search {
        fn constructed(&self) {
            self.parent_constructed();
            self.obj().setup();
        }
    }

    impl WidgetImpl for Search {}
    impl BoxImpl for Search {}
}

glib::wrapper! {
    pub struct Search(ObjectSubclass<imp::Search>)
        @extends gtk::Box, gtk::Widget,
        @implements gtk::Accessible, gtk::Buildable, gtk::ConstraintTarget, gtk::Orientable;
}

impl Search {
    fn setup(&self) {
        let imp = self.imp();
        let kinds: Vec<String> = Kind::ALL.into_iter().map(kind_label).collect();
        let states: Vec<String> = State::ALL.into_iter().map(state_label).collect();
        fn refs(v: &[String]) -> Vec<&str> {
            v.iter().map(String::as_str).collect()
        }
        imp.type_combo
            .set_model(Some(&gtk::StringList::new(&refs(&kinds))));
        imp.state_dropdown
            .set_model(Some(&gtk::StringList::new(&refs(&states))));
        imp.days.set_value(180.0);
        let personal = gio::Menu::new();
        imp.queries_menu
            .append_section(Some(&tr("My searches")), &personal);
        let _ = imp.personal.set(personal);

        type Handler = fn(&Search, Option<String>);
        let actions: [(&str, bool, Handler); 5] = [
            ("requete", true, |s, q| {
                if let Some(query) = q.as_deref().and_then(Query::from_name) {
                    s.run_query(query, INACTIVE_DAYS);
                }
            }),
            ("inactifs", false, |s, _| s.ask_days()),
            ("enregistrer", false, |s, _| s.ask_name()),
            ("perso", true, |s, name| {
                if let Some(name) = name {
                    s.run_saved(&name);
                }
            }),
            ("oublier", true, |s, name| {
                if let Some(name) = name {
                    s.forget(&name);
                }
            }),
        ];
        let group = gio::SimpleActionGroup::new();
        for (name, parameter, handler) in actions {
            let action = gio::SimpleAction::new(name, parameter.then_some(glib::VariantTy::STRING));
            let weak = self.downgrade();
            action.connect_activate(move |_, value| {
                if let Some(search) = weak.upgrade() {
                    handler(&search, value.and_then(|v| v.str().map(str::to_owned)));
                }
            });
            group.add_action(&action);
        }
        self.insert_action_group("recherche", Some(&group));
    }

    fn window(&self) -> Option<Window> {
        self.root().and_downcast::<Window>()
    }

    fn kind(&self) -> Kind {
        let index = usize::try_from(self.imp().type_combo.selected()).unwrap_or(0);
        Kind::ALL.get(index).copied().unwrap_or(Kind::All)
    }

    fn state(&self) -> State {
        let index = usize::try_from(self.imp().state_dropdown.selected()).unwrap_or(0);
        State::ALL.get(index).copied().unwrap_or(State::All)
    }

    /// At the closing of the domain: the policy read is no longer the right one.
    pub fn forget_domain(&self) {
        let imp = self.imp();
        imp.policy.take();
        imp.content.take();
        imp.relaunch.take();
    }

    /// Ctrl+F: the input takes the focus.
    pub fn focus_input(&self) {
        self.imp().entry.grab_focus();
    }

    fn show(&self, content: Content) {
        let Some(window) = self.window() else { return };
        if window.source().is_none() {
            return;
        }
        *self.imp().content.borrow_mut() = Some(content.clone());
        window.show(content);
        window.show_content();
    }

    fn shown(&self) -> bool {
        match (self.window(), self.imp().content.borrow().as_ref()) {
            (Some(window), Some(content)) => window.shows(content),
            _ => false,
        }
    }

    // --- Search by text ------------------------------------------------------------

    fn launch(&self) {
        let text = self.imp().entry.text().to_string();
        self.search(&text, self.kind(), self.state());
    }

    /// A search of the bar with these criteria (also used by the trials, `trial`).
    pub fn search(&self, text: &str, kind: Kind, state: State) {
        let imp = self.imp();
        let filter = queries::search_filter(text, kind, state);
        // With the text of the input at that time.
        *imp.relaunch.borrow_mut() = Some(Rc::new(Search::launch));
        *imp.last.borrow_mut() = Some(Saved {
            name: String::new(),
            text: joined(text),
            kind,
            state,
            query: None,
            days: INACTIVE_DAYS,
        });
        self.show(Content {
            title: search_title(text, kind, state),
            search: true,
            read: Rc::new(move |source, notifier| {
                source.search_under(filter.clone(), None, notifier)
            }),
            finished: None,
            container: None,
            keep_activity: false,
        });
    }

    /// Kind or state changed: the last search started from here runs again, if it is still
    /// shown.
    fn filters_changed(&self) {
        let relaunch = self.imp().relaunch.borrow().clone();
        if let (Some(relaunch), true) = (relaunch, self.shown()) {
            relaunch(self);
        }
    }

    // --- Ready queries ---------------------------------------------------------------

    fn settings(&self) -> Option<gio::Settings> {
        self.window().map(|w| w.app_settings())
    }

    fn ask_days(&self) {
        let imp = self.imp();
        if let Some(settings) = self.settings() {
            imp.days.set_value(f64::from(settings.int(DAYS_KEY)));
        }
        imp.inactive_dialog.present(self.root().as_ref());
    }

    fn days_answered(&self, response: Option<&str>) {
        if response != Some("rechercher") {
            return;
        }
        // A spin row of whole days, between 0 and 3650.
        #[allow(clippy::cast_possible_truncation)]
        let days = self.imp().days.value().round() as i32;
        if let Some(settings) = self.settings() {
            let _ = settings.set_int(DAYS_KEY, days);
        }
        self.run_query(Query::Inactive, i64::from(days));
    }

    pub fn run_query(&self, query: Query, days: i64) {
        let imp = self.imp();
        let (kind, state) = (self.kind(), self.state());
        // IN_CHAIN queries sent to the DC are not started again by a change of kind or state:
        // one page, which Samba takes up to 30 s to give, keeps the connection busy even when
        // abandoned. A survey of activity stops at the next page.
        let slow = query.slow(false);
        *imp.relaunch.borrow_mut() = if slow {
            None
        } else {
            Some(Rc::new(move |s: &Search| s.run_query(query, days)))
        };
        *imp.last.borrow_mut() = Some(Saved {
            name: String::new(),
            text: String::new(),
            kind,
            state,
            query: Some(query),
            days,
        });
        let title = query_title(query, kind, state, days);
        match query.execution() {
            Execution::Activity => self.run_survey(query, title, kind, state, days),
            Execution::Policy => self.run_with_policy(query, title, kind, state),
            Execution::Filter => {
                let Some(filter) = query.filter(kind, state, None) else {
                    return;
                };
                if let (true, Some(window)) = (slow, self.window()) {
                    window.toast(&tr(
                        "Recursive membership computed by the DC: up to 30 s with Samba.",
                    ));
                }
                self.show(Content {
                    title,
                    search: true,
                    read: Rc::new(move |source, notifier| {
                        source.search_under(filter.clone(), None, notifier)
                    }),
                    finished: None,
                    container: None,
                    keep_activity: false,
                });
            }
        }
    }

    /// Inactive or never logged on: a survey on every DC (in a thread), then a selection;
    /// the rows show the activity on every DC (`ligne_avec_activite`).
    fn run_survey(&self, query: Query, title: String, kind: Kind, state: State, days: i64) {
        let Some(filter) = query.filter(kind, state, None) else {
            return;
        };
        let failures: Arc<Mutex<Vec<String>>> = Arc::default();
        let found = failures.clone();
        let read = move |source: &Arc<dyn Source>, notifier: Notifier| {
            let flux = ObjectFlux::new(CAPACITY, Some(notifier));
            let (source, filter, out) = (source.clone(), filter.clone(), flux.clone());
            let failures = found.clone();
            std::thread::spawn(move || {
                // Threshold computed at each reading (refresh included).
                let now = now_nttime();
                let watched = out.clone();
                let cancelled = move || watched.cancelled();
                match source.survey(&filter, &cancelled) {
                    Ok(survey) => {
                        failures
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .extend(survey.failures.iter().map(|f| f.dc.clone()));
                        let accounts = survey.accounts();
                        let chosen = if query == Query::Inactive {
                            queries::select_inactive(accounts, now - days * NTTIME_PER_DAY)
                        } else {
                            queries::select_never(accounts)
                        };
                        let items: Vec<Item> = chosen
                            .into_iter()
                            .map(|(mut object, activity)| {
                                // The column « last logon » shows the activity on every DC,
                                // not the replicated `lastLogonTimestamp` alone.
                                if let Object::User { account, .. }
                                | Object::Computer { account, .. } = &mut object
                                {
                                    account.last_logon_timestamp =
                                        (activity.nttime != 0).then_some(activity.nttime);
                                }
                                Item::Object(Box::new(object))
                            })
                            .collect();
                        out.put(items, None);
                    }
                    Err(SurveyError::Cancelled) => out.finish(None),
                    Err(SurveyError::Search(error)) => out.finish(Some(error)),
                    Err(SurveyError::Failure(failure)) => out.finish(Some(search_error(failure))),
                }
            });
            // Always read on the DCs.
            Pages {
                flux,
                copy_date: None,
            }
        };
        self.show(Content {
            title,
            search: true,
            read: Rc::new(read),
            finished: Some(Rc::new(move |window: &Window| {
                let dcs: Vec<String> = failures
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .drain(..)
                    .collect();
                for dc in dcs {
                    window.toast(&fill(
                        &tr("{dc} unreachable: activity dates may be too old."),
                        &[("dc", &dc)],
                    ));
                }
            })),
            container: None,
            keep_activity: true,
        });
    }

    /// Locked out: the policy of the domain first (read once per domain).
    fn run_with_policy(&self, query: Query, title: String, kind: Kind, state: State) {
        let policy = *self.imp().policy.borrow();
        let Some(policy) = policy else {
            let Some(window) = self.window() else { return };
            let Some(source) = window.source() else {
                return;
            };
            let domain = source.profile().domain.clone();
            let weak = self.downgrade();
            glib::spawn_future_local(async move {
                let read = gio::spawn_blocking(move || source.policy()).await;
                let Some(search) = weak.upgrade() else { return };
                match read {
                    Ok(Ok(policy)) => {
                        *search.imp().policy.borrow_mut() = Some(policy);
                        search.run_with_policy(query, title, kind, state);
                    }
                    Ok(Err(failure)) => {
                        if let Some(window) = search.window() {
                            window.report(
                                &errors::failure_problem(&failure, &domain),
                                &tr("Unreadable domain policy"),
                            );
                        }
                    }
                    Err(_) => {}
                }
            });
            return;
        };
        self.show(Content {
            title,
            search: true,
            read: Rc::new(move |source, notifier| {
                // End of lockout judged at the instant of each reading (refresh included).
                let filter = query
                    .filter(kind, state, Some((&policy, now_nttime())))
                    .unwrap_or_default();
                source.search_under(filter, None, notifier)
            }),
            finished: None,
            container: None,
            keep_activity: false,
        });
    }

    // --- Searches of the user ------------------------------------------------------

    fn saved(&self) -> Vec<Saved> {
        let Some(settings) = self.settings() else {
            return Vec::new();
        };
        settings
            .value(KEY)
            .iter()
            .filter_map(|dict| {
                let fields: BTreeMap<String, String> = dict
                    .iter()
                    .filter_map(|entry| {
                        Some((
                            entry.child_value(0).str()?.to_owned(),
                            entry.child_value(1).str()?.to_owned(),
                        ))
                    })
                    .collect();
                Saved::from_fields(&fields)
            })
            .collect()
    }

    fn write(&self, list: &[Saved]) {
        let Some(settings) = self.settings() else {
            return;
        };
        let maps: Vec<std::collections::HashMap<String, String>> = list
            .iter()
            .map(|s| {
                s.to_fields()
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v))
                    .collect()
            })
            .collect();
        let _ = settings.set_value(KEY, &maps.to_variant());
        self.show_saved();
    }

    /// Menu « My searches »: an entry per search, and a submenu to forget them.
    pub fn show_saved(&self) {
        let Some(personal) = self.imp().personal.get() else {
            return;
        };
        personal.remove_all();
        let list = self.saved();
        let forget = gio::Menu::new();
        for saved in &list {
            let target = saved.name.to_variant();
            let item = gio::MenuItem::new(Some(&saved.name), None);
            item.set_action_and_target_value(Some("recherche.perso"), Some(&target));
            personal.append_item(&item);
            let item = gio::MenuItem::new(Some(&saved.name), None);
            item.set_action_and_target_value(Some("recherche.oublier"), Some(&target));
            forget.append_item(&item);
        }
        if !list.is_empty() {
            personal.append_submenu(Some(&tr("Forget a search")), &forget);
        }
    }

    /// Saves what is shown if it was started from here (search or query with its
    /// parameters), otherwise the search the bar describes.
    fn ask_name(&self) {
        let imp = self.imp();
        let last = imp.last.borrow().clone();
        let saved = match last {
            Some(last) if self.shown() => last,
            _ => Saved {
                name: String::new(),
                text: joined(&imp.entry.text()),
                kind: self.kind(),
                state: self.state(),
                query: None,
                days: INACTIVE_DAYS,
            },
        };
        imp.search_name.set_text(&saved.proposed_name());
        *imp.to_save.borrow_mut() = Some(saved);
        imp.save_dialog.present(self.root().as_ref());
    }

    fn save_answered(&self, response: Option<&str>) {
        let imp = self.imp();
        let name = imp.search_name.text().trim().to_owned();
        let pending = imp.to_save.borrow().clone();
        let (Some("enregistrer"), false, Some(pending)) = (response, name.is_empty(), pending)
        else {
            return;
        };
        let new = Saved {
            name: name.clone(),
            ..pending
        };
        self.write(&with_saved(self.saved(), new));
        if let Some(window) = self.window() {
            window.toast(&fill(&tr("Search “{nom}” saved."), &[("nom", &name)]));
        }
    }

    fn run_saved(&self, name: &str) {
        let Some(saved) = self.saved().into_iter().find(|s| s.name == name) else {
            return;
        };
        let imp = self.imp();
        // Changing the lists must not start the old search again.
        imp.relaunch.take();
        let index = |i: Option<usize>| u32::try_from(i.unwrap_or(0)).unwrap_or(0);
        imp.type_combo
            .set_selected(index(Kind::ALL.iter().position(|&k| k == saved.kind)));
        imp.state_dropdown
            .set_selected(index(State::ALL.iter().position(|&s| s == saved.state)));
        if let Some(query) = saved.query {
            self.run_query(query, saved.days);
            return;
        }
        imp.entry.set_text(&saved.text);
        self.search(&saved.text, saved.kind, saved.state);
    }

    fn forget(&self, name: &str) {
        let list: Vec<Saved> = self
            .saved()
            .into_iter()
            .filter(|s| s.name != name)
            .collect();
        self.write(&list);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn titles() {
        assert_eq!(
            search_title(" dupont  jean ", Kind::User, State::All),
            "Search “dupont jean” (users)"
        );
        assert_eq!(
            search_title("", Kind::All, State::All),
            "All objects in the domain"
        );
        assert_eq!(
            query_title(Query::Inactive, Kind::All, State::Disabled, 1),
            "Inactive for 1 day (disabled accounts)"
        );
    }

    #[test]
    fn saved_round_trip() {
        let saved = Saved {
            name: "Inactifs".into(),
            text: String::new(),
            kind: Kind::User,
            state: State::Enabled,
            query: Some(Query::Inactive),
            days: 90,
        };
        let fields: BTreeMap<String, String> = saved
            .to_fields()
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect();
        assert_eq!(fields.get("jours").map(String::as_str), Some("90"));
        assert_eq!(Saved::from_fields(&fields), Some(saved.clone()));
        let mut bad = fields.clone();
        bad.insert("jours".into(), "9999".into());
        assert_eq!(Saved::from_fields(&bad), None);
        let other = Saved {
            name: "b".into(),
            ..saved.clone()
        };
        let first = Saved {
            name: "A".into(),
            ..saved
        };
        let list = with_saved(vec![other], first);
        assert_eq!(
            list.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(),
            ["A", "b"]
        );
    }
}

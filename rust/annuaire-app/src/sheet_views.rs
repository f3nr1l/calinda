// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! What the sheet of an object shows (J2.4, J2.5, `annuaire.vue.fiche`, reading part):
//! location, items of the lists (groups, members), state of an account, expiration, last
//! activity on each DC, type and scope of a group; and the **draft** of the changes made in
//! place: values typed, options of the account, expiration, members added or removed, changes
//! of the attribute editor. The draft becomes a changeset by `prepare_changeset`, that reads the
//! object again on the DC (`writer::prepare_modification`, ADR 0006): the preview shows the
//! real state, not the one of the sheet. Pure, apart from the catalogue, the local time zone
//! and `prepare_changeset` (blocking).

use annuaire_codecs::time::{self, UtcTime};
use annuaire_codecs::uac::{GroupType, Scope, UserAccountControl};
use annuaire_core::changes::{AttributeMap, Change, Changeset, Operation, Values};
use annuaire_core::connection::Connection;
use annuaire_core::dn;
use annuaire_core::model::{Account, ActivitySource, DomainPolicy, LastActivity, Object};
use annuaire_core::search;
use annuaire_core::source::{Item, Survey, name_from_dn};
use annuaire_core::writer::{self, PrepareError};
use gtk::glib;

use crate::countries::{self, Country};
use crate::i18n::{fill, tr, tr_ctx};
use crate::views::{self, GROUP_ICON};

/// Attributes that the sheet can change in place (`EDITABLES`), in lower case.
pub const EDITABLE: [&str; 31] = [
    "givenname",
    "initials",
    "sn",
    "displayname",
    "description",
    "physicaldeliveryofficename",
    "mail",
    "telephonenumber",
    "mobile",
    "wwwhomepage",
    "streetaddress",
    "postalcode",
    "l",
    "st",
    "title",
    "department",
    "company",
    "userprincipalname",
    "samaccountname",
    "profilepath",
    "scriptpath",
    "homedirectory",
    "homedrive",
    "info",
    "location",
    "c",
    "co",
    "countrycode",
    "useraccountcontrol",
    "accountexpires",
    "pwdlastset",
];

pub fn editable(attribute: &str) -> bool {
    EDITABLE.contains(&attribute.to_lowercase().as_str())
}

/// Flags of `userAccountControl` shown as switches (« Account » tab), by row name
/// (`OPTIONS_COMPTE`).
pub const OPTIONS: [(&str, u32); 5] = [
    ("uac:ACCOUNTDISABLE", UserAccountControl::ACCOUNTDISABLE),
    (
        "uac:DONT_EXPIRE_PASSWD",
        UserAccountControl::DONT_EXPIRE_PASSWD,
    ),
    (
        "uac:SMARTCARD_REQUIRED",
        UserAccountControl::SMARTCARD_REQUIRED,
    ),
    ("uac:NOT_DELEGATED", UserAccountControl::NOT_DELEGATED),
    (
        "uac:DONT_REQUIRE_PREAUTH",
        UserAccountControl::DONT_REQUIRE_PREAUTH,
    ),
];

const FORBIDDEN_SAM: &str = "\"/\\[]:;|=,+*?<>@";

// --- Location ----------------------------------------------------------------------------

/// Canonical form of a DN: `lab.test/Labo/Utilisateurs/alice` (unreadable DN: as is)
/// (`chemin_lisible`).
pub fn readable_path(dn_text: &str) -> String {
    let Ok(components) = dn::split(dn_text) else {
        return dn_text.to_owned();
    };
    let domain: Vec<&str> = components
        .iter()
        .filter(|c| c.attribute.eq_ignore_ascii_case("dc"))
        .map(|c| c.value.as_str())
        .collect();
    let mut parts = vec![domain.join(".")];
    parts.extend(
        components
            .iter()
            .filter(|c| !c.attribute.eq_ignore_ascii_case("dc"))
            .rev()
            .map(|c| c.value.clone()),
    );
    parts.join("/")
}

/// Container of the object, in canonical form (`emplacement`).
pub fn location(dn_text: &str) -> String {
    let path = readable_path(dn_text);
    match path.rsplit_once('/') {
        Some((parent, _)) if !parent.is_empty() => parent.to_owned(),
        _ => path,
    }
}

// --- Items of the lists ------------------------------------------------------------------

/// A row of a list in a sheet: an object named by its DN (`ElementVue`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ElementView {
    pub dn: String,
    pub title: String,
    pub subtitle: String,
    pub icon: String,
}

/// Item known by its DN only (groups of an object): name and location.
pub fn element_from_dn(dn_text: &str) -> ElementView {
    ElementView {
        dn: dn_text.to_owned(),
        title: name_from_dn(dn_text),
        subtitle: location(dn_text),
        icon: GROUP_ICON.to_owned(),
    }
}

/// Item of an object read (members): name, type and location.
pub fn element_from_item(item: &Item) -> ElementView {
    let row = views::row_from_item(item);
    let name = if row.name.is_empty() {
        name_from_dn(&row.dn)
    } else {
        row.name.clone()
    };
    ElementView {
        subtitle: format!("{} · {}", row.kind_label, location(&row.dn)),
        title: name,
        icon: row.icon.clone(),
        dn: row.dn,
    }
}

pub fn sort_elements(elements: &mut [ElementView]) {
    elements.sort_by_cached_key(|e| (glib::casefold(&e.title), glib::casefold(&e.dn)));
}

// --- Account -----------------------------------------------------------------------------

/// Summed-up state: « Enabled », « Disabled, locked out »… (`etat_compte`).
pub fn account_state(account: &Account, policy: Option<&DomainPolicy>, now: UtcTime) -> String {
    let mut parts = vec![if account.active() {
        tr_ctx("state", "Enabled")
    } else {
        tr("Disabled")
    }];
    if policy.is_some_and(|p| account.locked(p, now)) {
        parts.push(tr("locked out"));
    }
    if account.expired(now) {
        parts.push(tr("expired"));
    }
    if account.must_change_password() {
        parts.push(tr("password must be changed"));
    }
    parts.join(", ")
}

fn is_never(nttime: i64) -> bool {
    time::is_never(nttime).unwrap_or(true)
}

/// Last day of validity, as the Windows console (« End of: »), or None: never
/// (`fin_de_compte`). `accountExpires` is the instant the account stops working, midnight at
/// the start of the next day, local time.
pub fn end_of_account(account_expires: Option<i64>) -> Option<glib::DateTime> {
    let nttime = account_expires.filter(|&n| !is_never(n))?;
    let seconds = time::nttime_to_unix(nttime).ok().flatten()?;
    glib::DateTime::from_unix_local(seconds - 1).ok()
}

/// A password that never expires cannot have to be changed (the Windows console then
/// unticks the box and says so) (`changement_exige_possible`).
pub fn change_possible(uac: u32) -> bool {
    !annuaire_codecs::uac::UserAccountControl(uac)
        .contains(annuaire_codecs::uac::UserAccountControl::DONT_EXPIRE_PASSWD)
}

/// `userAccountControl` (signed value, as written) with `flag` set or removed (`uac_avec`).
pub fn uac_with(value: i64, flag: u32, set: bool) -> i64 {
    // The low 32 bits, as Python's `valeur & 0xFFFF_FFFF`.
    let flags = (value & 0xFFFF_FFFF) as u32;
    let flags = if set { flags | flag } else { flags & !flag };
    i64::from(UserAccountControl(flags).encode())
}

/// `pwdLastSet` to write for « must change the password at next logon »
/// (`valeur_changement_exige`): 0 if the change is required. Otherwise: -1 (« now », the only
/// other value the DC accepts) if the origin required it, the origin itself in the other case
/// (nothing to write).
pub fn change_required_value(origin: &str, required: bool) -> String {
    if required {
        "0".to_owned()
    } else if origin.trim() == "0" {
        "-1".to_owned()
    } else {
        origin.to_owned()
    }
}

/// A day of the calendar: year, month, day of the month.
pub type Day = (i32, i32, i32);

pub fn day_of(date: &glib::DateTime) -> Day {
    (date.year(), date.month(), date.day_of_month())
}

/// `accountExpires` for a last day of validity (None: never) (`expiration_depuis_fin`):
/// midnight at the start of the next day, local time.
pub fn expiration_from_end(end: Option<Day>) -> i64 {
    let Some((year, month, day)) = end else {
        return time::NTTIME_NEVER;
    };
    glib::DateTime::from_local(year, month, day, 0, 0, 0.0)
        .and_then(|d| d.add_days(1))
        .ok()
        .and_then(|d| time::unix_to_nttime(d.to_unix()).ok())
        .unwrap_or(time::NTTIME_NEVER)
}

/// `accountExpires` to write for the last day `end` (None: never); the origin if it already
/// says the same (« never » is written 0 or the maximum, the hour may differ)
/// (`valeur_expiration`).
pub fn expiration_value(origin: &str, end: Option<Day>) -> String {
    let present = origin.trim().parse::<i64>().ok();
    if end_of_account(present).as_ref().map(day_of) == end {
        return origin.to_owned();
    }
    expiration_from_end(end).to_string()
}

/// Day typed as DD/MM/YYYY (`analyser_jour`).
pub fn parse_day(text: &str) -> Result<Day, String> {
    let error = || tr("Date expected in the DD/MM/YYYY format.");
    let parts: Vec<&str> = text.trim().split('/').collect();
    let [day, month, year] = parts.as_slice() else {
        return Err(error());
    };
    let number = |part: &str, max: usize| -> Result<i32, String> {
        if part.is_empty() || part.len() > max || !part.chars().all(|c| c.is_ascii_digit()) {
            return Err(error());
        }
        part.parse().map_err(|_| error())
    };
    let (day, month, year) = (number(day, 2)?, number(month, 2)?, number(year, 4)?);
    if year < 1 || glib::DateTime::from_local(year, month, day, 0, 0, 0.0).is_err() {
        return Err(error());
    }
    Ok((year, month, day))
}

/// Error message if the input is refused beforehand (`verifier_saisie`).
pub fn check_input(attribute: &str, text: &str) -> Option<String> {
    let (lower, text) = (attribute.to_lowercase(), text.trim());
    if lower == "samaccountname" {
        if text.is_empty() {
            return Some(tr("The logon name cannot be empty."));
        }
        if text.chars().count() > 20 {
            return Some(tr(
                "The logon name (pre-Windows 2000) is at most 20 characters long.",
            ));
        }
        if text.chars().any(|c| FORBIDDEN_SAM.contains(c)) || text.ends_with('.') {
            return Some(tr(
                "Forbidden characters in the logon name: \" / \\ [ ] : ; | = , + * ? < > @",
            ));
        }
    }
    if lower == "userprincipalname" && !text.is_empty() {
        let valid = text.split_once('@').is_some_and(|(name, suffix)| {
            !name.is_empty() && !suffix.is_empty() && !suffix.contains('@')
        });
        if !valid {
            return Some(tr("The user logon name has the form name@domain."));
        }
    }
    None
}

/// A day as DD/MM/YYYY (`texte_jour`); empty without a day.
pub fn day_text(day: Option<&glib::DateTime>) -> String {
    day.and_then(|d| d.format(&tr("%d/%m/%Y")).ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// A date of the directory, or « Never » (`texte_nttime`).
pub fn nttime_text(value: Option<i64>) -> String {
    match value {
        Some(n) if !is_never(n) => time::nttime_to_unix(n)
            .ok()
            .flatten()
            .map(views::format_unix)
            .unwrap_or_default(),
        _ => tr("Never"),
    }
}

/// A date of the model (creation, change), or an em dash.
pub fn date_text(date: Option<UtcTime>) -> String {
    date.map(|d| views::format_unix(d.unix_seconds()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "—".to_owned())
}

// --- Last activity on each DC ------------------------------------------------------------

/// A source of the last activity: a DC (`lastLogon`) or a replicated attribute
/// (`LigneActivite`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityLine {
    pub title: String,
    pub text: String,
    /// It is the most recent value, the one that makes the last activity.
    pub chosen: bool,
}

/// `libelle_source`.
pub fn source_label(activity: &LastActivity) -> String {
    match activity.source {
        Some(ActivitySource::LastLogon) => fill(
            &tr("lastLogon on {dc}"),
            &[("dc", activity.dc.as_deref().unwrap_or(""))],
        ),
        Some(ActivitySource::LastLogonTimestamp) => {
            tr("lastLogonTimestamp (replicated, up to 14 days late)")
        }
        Some(ActivitySource::PwdLastSet) => tr("machine password renewal"),
        None => String::new(),
    }
}

/// « 13/10/2026 09:12 (lastLogon on dc2.lab.test) », or « Never » (`resume_activite`).
pub fn activity_summary(survey: &Survey, dn_text: &str) -> String {
    match survey.activities.get(dn_text) {
        Some(activity) if activity.nttime != 0 => fill(
            &tr("{date} ({source})"),
            &[
                ("date", &nttime_text(Some(activity.nttime))),
                ("source", &source_label(activity)),
            ],
        ),
        _ => tr("Never"),
    }
}

/// Expandable detail: `lastLogon` of each DC read, then the replicated attributes; a DC that
/// did not answer is reported (the date may then be too old) (`lignes_activite`).
pub fn activity_lines(
    survey: &Survey,
    object: &Object,
    message: &dyn Fn(&annuaire_core::search::SearchError) -> String,
) -> Vec<ActivityLine> {
    let Some(account) = object.account() else {
        return Vec::new();
    };
    let dn_text = &object.common().dn;
    let chosen = survey.activities.get(dn_text);
    let by_dc = survey.last_logons.get(dn_text);
    let is_chosen = |source: ActivitySource, value: Option<i64>, dc: Option<&str>| {
        chosen.is_some_and(|c| {
            c.nttime != 0
                && c.source == Some(source)
                && c.dc.as_deref() == dc
                && Some(c.nttime) == value
        })
    };
    let mut lines: Vec<ActivityLine> = survey
        .dcs
        .iter()
        .map(|dc| {
            let value = by_dc.and_then(|v| v.get(dc)).copied();
            ActivityLine {
                title: dc.clone(),
                text: nttime_text(value),
                chosen: is_chosen(ActivitySource::LastLogon, value, Some(dc)),
            }
        })
        .collect();
    lines.extend(survey.failures.iter().map(|f| ActivityLine {
        title: f.dc.clone(),
        text: fill(
            &tr("Unreachable: {message}"),
            &[("message", &message(&f.error))],
        ),
        chosen: false,
    }));
    lines.push(ActivityLine {
        title: "lastLogonTimestamp".into(),
        text: nttime_text(account.last_logon_timestamp),
        chosen: is_chosen(
            ActivitySource::LastLogonTimestamp,
            account.last_logon_timestamp,
            None,
        ),
    });
    if matches!(object, Object::Computer { .. }) {
        lines.push(ActivityLine {
            title: "pwdLastSet".into(),
            text: nttime_text(account.pwd_last_set),
            chosen: is_chosen(ActivitySource::PwdLastSet, account.pwd_last_set, None),
        });
    }
    lines
}

// --- Group -------------------------------------------------------------------------------

/// `libelle_categorie`.
pub fn category_label(group_type: Option<&GroupType>) -> String {
    match group_type {
        None => String::new(),
        Some(t) if t.security => tr("Security"),
        Some(_) => tr("Distribution"),
    }
}

/// `libelle_portee`.
pub fn scope_label(group_type: Option<&GroupType>) -> String {
    match group_type.and_then(|t| t.scope) {
        None => tr("Unknown"),
        Some(Scope::Global) => tr("Global"),
        Some(Scope::DomainLocal) => tr("Domain local"),
        Some(Scope::Universal) => tr("Universal"),
        Some(Scope::Builtin) => tr("Built-in (Builtin)"),
    }
}

/// The policy that applies to an account (`msDS-ResultantPSO`), without the list of the PSO
/// of the domain (`resultante_en_clair` as the sheet calls it).
pub fn resultant_policy(dn_text: Option<&str>) -> String {
    match dn_text {
        None => tr("Domain policy (no fine-grained password policy applies)"),
        Some(dn_text) => fill(
            &tr("Fine-grained password policy “{nom}”"),
            &[("nom", &name_from_dn(dn_text))],
        ),
    }
}

/// Search of the members to add: users, groups, computers, contacts whose name, logon name,
/// display name or email starts with the input (`filtre_candidats`).
pub fn candidates_filter(input: &str) -> Option<String> {
    let text = input.trim();
    if text.is_empty() {
        return None;
    }
    let classes: Vec<String> = ["user", "group", "contact"]
        .iter()
        .filter_map(|c| search::eq("objectClass", search::Value::Text(c)).ok())
        .collect();
    let names: Vec<String> = ["name", "sAMAccountName", "displayName", "mail"]
        .iter()
        .filter_map(|a| search::starts_with(a, text).ok())
        .collect();
    search::and(&[search::or(&classes).ok()?, search::or(&names).ok()?]).ok()
}

// --- Draft of the changes ----------------------------------------------------------------

/// Change of an attribute made in the editor, waiting for the preview (`EditionAttribut`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributeEdit {
    pub attribute: String,
    pub single: bool,
    /// Values read when the editor was filled.
    pub origin: Values,
    pub wanted: Values,
}

impl AttributeEdit {
    /// Multi-valued attribute: only the values removed and added in the editor, never the
    /// whole list (a value added elsewhere in the meantime stays) (`changement`).
    pub fn change(&self) -> Option<Change> {
        let removed: Values = self
            .origin
            .iter()
            .filter(|v| !self.wanted.contains(v))
            .cloned()
            .collect();
        let mut added: Values = Vec::new();
        for v in &self.wanted {
            if !self.origin.contains(v) && !added.contains(v) {
                added.push(v.clone());
            }
        }
        if removed.is_empty() && added.is_empty() {
            return None;
        }
        Change::new(&self.attribute, removed, added).ok()
    }
}

/// Why a change cannot go in the draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DraftError {
    /// The attribute is not changed from the sheet.
    NotEditable(String),
    /// The attribute already has a change pending in another tab.
    ElsewhereChanged(String),
}

impl DraftError {
    pub fn message(&self) -> String {
        match self {
            Self::NotEditable(a) => fill(
                &tr("{attribut} cannot be changed from the properties"),
                &[("attribut", a)],
            ),
            Self::ElsewhereChanged(a) => fill(
                &tr(
                    "“{attribut}” is already modified in another tab: apply or discard that change first.",
                ),
                &[("attribut", a)],
            ),
        }
    }
}

/// Changes in progress in a sheet, before the preview (`Brouillon`). `origin`: value shown of
/// each attribute that can be changed at the opening (text, one value). An input back to the
/// origin is no longer a change. The lists keep the order of the inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Draft {
    pub origin: Vec<(String, String)>,
    pub inputs: Vec<(String, String)>,
    /// Members to add.
    pub additions: Vec<ElementView>,
    /// Members to remove.
    pub removals: Vec<ElementView>,
    /// Changes of the attribute editor (J4.4), by name in lower case.
    pub edits: Vec<AttributeEdit>,
}

fn remove_dn(list: &mut Vec<ElementView>, dn_text: &str) -> bool {
    let before = list.len();
    list.retain(|e| e.dn != dn_text);
    list.len() != before
}

impl Draft {
    pub fn new(origin: Vec<(String, String)>) -> Self {
        Self {
            origin,
            ..Self::default()
        }
    }

    fn origin_of(&self, attribute: &str) -> &str {
        self.origin
            .iter()
            .find(|(a, _)| a == attribute)
            .map_or("", |(_, v)| v.as_str())
    }

    /// Input of a tab of the sheet; it replaces a change of the same attribute made in the
    /// editor (the last one wins) (`saisir`).
    pub fn input(&mut self, attribute: &str, text: &str) -> Result<(), DraftError> {
        if !editable(attribute) {
            return Err(DraftError::NotEditable(attribute.to_owned()));
        }
        let lower = attribute.to_lowercase();
        self.edits.retain(|e| e.attribute.to_lowercase() != lower);
        let same = text.trim() == self.origin_of(attribute).trim();
        match self.inputs.iter_mut().find(|(a, _)| a == attribute) {
            Some(_) if same => self.inputs.retain(|(a, _)| a != attribute),
            Some((_, value)) => *value = text.to_owned(),
            None if same => {}
            None => self.inputs.push((attribute.to_owned(), text.to_owned())),
        }
        Ok(())
    }

    /// The attribute has an input pending in a tab of the sheet (or the country, or the
    /// members): the editor does not change it at the same time (`saisi_ailleurs`).
    pub fn changed_elsewhere(&self, attribute: &str) -> bool {
        let lower = attribute.to_lowercase();
        self.inputs.iter().any(|(a, _)| a.to_lowercase() == lower)
            || (lower == "member" && !(self.additions.is_empty() && self.removals.is_empty()))
    }

    /// Change from the attribute editor; back to the origin, it is cleared (`editer`).
    pub fn edit(&mut self, edit: AttributeEdit) -> Result<(), DraftError> {
        if self.changed_elsewhere(&edit.attribute) {
            return Err(DraftError::ElsewhereChanged(edit.attribute));
        }
        let lower = edit.attribute.to_lowercase();
        let position = self
            .edits
            .iter()
            .position(|e| e.attribute.to_lowercase() == lower);
        match (position, edit.wanted == edit.origin) {
            (Some(i), true) => {
                self.edits.remove(i);
            }
            (Some(i), false) => {
                if let Some(slot) = self.edits.get_mut(i) {
                    *slot = edit;
                }
            }
            (None, true) => {}
            (None, false) => self.edits.push(edit),
        }
        Ok(())
    }

    /// The three attributes of the country together (`saisir_pays`).
    pub fn input_country(&mut self, country: Option<&Country>) {
        for (attribute, text) in countries::values(country) {
            // The three are editable: no error.
            let _ = self.input(attribute, &text);
        }
    }

    /// Present value in the sheet (input, else origin) (`valeur`).
    pub fn value(&self, attribute: &str) -> String {
        self.inputs
            .iter()
            .find(|(a, _)| a == attribute)
            .map_or_else(|| self.origin_of(attribute).to_owned(), |(_, v)| v.clone())
    }

    pub fn add_member(&mut self, element: ElementView) {
        if !remove_dn(&mut self.removals, &element.dn) {
            remove_dn(&mut self.additions, &element.dn);
            self.additions.push(element);
        }
    }

    pub fn remove_member(&mut self, element: ElementView) {
        if !remove_dn(&mut self.additions, &element.dn) {
            remove_dn(&mut self.removals, &element.dn);
            self.removals.push(element);
        }
    }

    /// Changes pending; the country (three attributes) counts for one (`nombre`).
    pub fn count(&self) -> usize {
        let mut attributes: Vec<&str> = self
            .inputs
            .iter()
            .map(|(a, _)| {
                if countries::ATTRIBUTES.contains(&a.as_str()) {
                    "c"
                } else {
                    a.as_str()
                }
            })
            .collect();
        attributes.sort_unstable();
        attributes.dedup();
        attributes.len() + self.additions.len() + self.removals.len() + self.edits.len()
    }

    pub fn clear(&mut self) {
        self.inputs.clear();
        self.additions.clear();
        self.removals.clear();
        self.edits.clear();
    }

    /// For `prepare_modification`: a single value, or an empty list (clear)
    /// (`valeurs_voulues`).
    pub fn wanted_values(&self) -> AttributeMap {
        self.inputs
            .iter()
            .map(|(a, t)| {
                let t = t.trim();
                let values = if t.is_empty() {
                    Vec::new()
                } else {
                    vec![t.as_bytes().to_vec()]
                };
                (a.clone(), values)
            })
            .collect()
    }

    /// Additions and removals of members, without reading `member` again (ADR 0006, §1)
    /// (`changement_membres`).
    pub fn members_change(&self) -> Option<Change> {
        if self.additions.is_empty() && self.removals.is_empty() {
            return None;
        }
        let values = |list: &[ElementView]| -> Values {
            list.iter().map(|e| e.dn.as_bytes().to_vec()).collect()
        };
        Change::new("member", values(&self.removals), values(&self.additions)).ok()
    }
}

/// Reads the object again on the DC and builds the changeset of the draft (None: nothing
/// changes) (`preparer_changeset`). A single `Modify` operation: the request is atomic on the
/// object. `PrepareError::Missing` if the object no longer exists. An attribute of one value
/// changed in the editor is read again on the DC as the inputs (the preview shows the real
/// value); a multi-valued attribute only carries the values removed and added. Blocking.
pub fn prepare_changeset(
    connection: &Connection,
    dn_text: &str,
    draft: &Draft,
) -> Result<Option<Changeset>, PrepareError> {
    let mut wanted = draft.wanted_values();
    let mut explicit: Vec<Change> = Vec::new();
    for edit in &draft.edits {
        if edit.single {
            wanted.retain(|(a, _)| a != &edit.attribute);
            wanted.push((edit.attribute.clone(), edit.wanted.clone()));
        } else if let Some(change) = edit.change() {
            explicit.push(change);
        }
    }
    explicit.extend(draft.members_change());
    let modification = if wanted.is_empty() {
        None
    } else {
        writer::prepare_modification(connection, dn_text, wanted)?
    };
    let (mut changes, mut read) = match modification {
        Some(Operation::Modify { changes, read, .. }) => (changes, read),
        _ => (Vec::new(), None),
    };
    if !explicit.is_empty() {
        changes.extend(explicit);
        if read.is_none() {
            read = Some(
                writer::read_version(connection, dn_text)
                    .map_err(PrepareError::Failure)?
                    .ok_or_else(|| PrepareError::Missing(dn_text.to_owned()))?,
            );
        }
    }
    if changes.is_empty() {
        return Ok(None);
    }
    // A class added goes before the attributes it allows (Samba checks each addition against
    // the classes already set).
    changes.sort_by_key(|c| !c.adds_class());
    let operation = Operation::modify(dn_text, changes, read)
        .map_err(|e| PrepareError::Unsupported(e.to_string()))?;
    Ok(Some(Changeset {
        operations: vec![operation],
        remarks: Vec::new(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let dn_text = "CN=alice,OU=Utilisateurs,OU=Labo,DC=lab,DC=test";
        assert_eq!(readable_path(dn_text), "lab.test/Labo/Utilisateurs/alice");
        assert_eq!(location(dn_text), "lab.test/Labo/Utilisateurs");
        assert_eq!(location("DC=lab,DC=test"), "lab.test");
        assert_eq!(readable_path("pas un DN"), "pas un DN");
        let group = element_from_dn("CN=G1,OU=Groupes,DC=lab,DC=test");
        assert_eq!(
            (group.title.as_str(), group.subtitle.as_str()),
            ("G1", "lab.test/Groupes")
        );
    }

    #[test]
    fn sorted_without_case() {
        let mut elements = vec![
            element_from_dn("CN=b,DC=x"),
            element_from_dn("CN=A,DC=x"),
            element_from_dn("CN=a,DC=y"),
        ];
        sort_elements(&mut elements);
        let dns: Vec<&str> = elements.iter().map(|e| e.dn.as_str()).collect();
        assert_eq!(dns, ["CN=A,DC=x", "CN=a,DC=y", "CN=b,DC=x"]);
    }

    #[test]
    fn group_labels() {
        let global = GroupType::decode(-2_147_483_646);
        assert_eq!(category_label(Some(&global)), "Security");
        assert_eq!(scope_label(Some(&global)), "Global");
        assert_eq!(scope_label(None), "Unknown");
        assert_eq!(category_label(None), "");
    }

    #[test]
    fn never() {
        assert_eq!(nttime_text(None), "Never");
        assert_eq!(nttime_text(Some(0)), "Never");
        assert_eq!(nttime_text(Some(time::NTTIME_NEVER)), "Never");
        assert!(end_of_account(Some(0)).is_none());
        assert!(end_of_account(Some(time::NTTIME_NEVER)).is_none());
    }
    #[test]
    fn draft() {
        let mut draft = Draft::new(vec![
            ("description".into(), "a".into()),
            ("c".into(), String::new()),
            ("co".into(), String::new()),
            ("countryCode".into(), "0".into()),
        ]);
        draft.input("description", " a ").unwrap();
        assert_eq!(draft.count(), 0);
        draft.input("description", "b").unwrap();
        assert!(draft.input("member", "x").is_err());
        draft.input_country(countries::by_code("FR").as_ref());
        assert_eq!(draft.count(), 2);
        assert_eq!(draft.value("countryCode"), "250");
        let member = element_from_dn("CN=x,DC=lab,DC=test");
        draft.add_member(member.clone());
        draft.remove_member(member.clone());
        assert_eq!(draft.count(), 2);
        draft.remove_member(member);
        assert!(draft.changed_elsewhere("Member"));
        let change = draft.members_change().unwrap();
        assert_eq!(change.removed, vec![b"CN=x,DC=lab,DC=test".to_vec()]);
        assert!(
            draft
                .edit(AttributeEdit {
                    attribute: "Description".into(),
                    single: true,
                    origin: vec![b"a".to_vec()],
                    wanted: vec![b"c".to_vec()],
                })
                .is_err()
        );
        assert_eq!(
            draft.wanted_values().first().unwrap().1,
            vec![b"b".to_vec()]
        );
        draft.clear();
        assert_eq!(draft.count(), 0);
    }

    #[test]
    fn account_values() {
        let disabled = uac_with(512, UserAccountControl::ACCOUNTDISABLE, true);
        assert_eq!(disabled, 514);
        assert_eq!(
            uac_with(disabled, UserAccountControl::ACCOUNTDISABLE, false),
            512
        );
        assert_eq!(change_required_value("0", false), "-1");
        assert_eq!(change_required_value("123", false), "123");
        assert_eq!(change_required_value("123", true), "0");
        assert_eq!(parse_day(" 31/12/2026 "), Ok((2026, 12, 31)));
        assert!(parse_day("31/02/2026").is_err());
        assert!(parse_day("2026-12-31").is_err());
        let nttime = expiration_from_end(Some((2026, 12, 31)));
        let end = end_of_account(Some(nttime)).unwrap();
        assert_eq!(day_of(&end), (2026, 12, 31));
        assert_eq!(
            expiration_value(&nttime.to_string(), Some((2026, 12, 31))),
            nttime.to_string()
        );
        assert_eq!(expiration_value("0", None), "0");
        assert_eq!(
            expiration_value("0", Some((2026, 12, 31))),
            nttime.to_string()
        );
        assert!(check_input("sAMAccountName", "a.").is_some());
        assert!(check_input("userPrincipalName", "a@b@c").is_some());
        assert!(check_input("userPrincipalName", "a@b").is_none());
        assert!(candidates_filter(" ").is_none());
        assert_eq!(
            candidates_filter("lé").unwrap(),
            "(&(|(objectClass=user)(objectClass=group)(objectClass=contact))(|(name=lé*)(sAMAccountName=lé*)(displayName=lé*)(mail=lé*)))"
        );
    }
}

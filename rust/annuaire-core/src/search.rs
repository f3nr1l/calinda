// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Searches: escaped filters, controls, value ranges, the paged flux.
//!
//! Port of `annuaire/core/filtre.py` and `annuaire/core/requetes.py`. Three ways to read,
//! none blocking the caller: [`search`] fills a [`Flux`] of pages (RFC 2696), produced on
//! the connection thread one at a time, so that other jobs run between two pages, and
//! never more than `capacity` pages ahead of the consumer; [`read_entry`] reads one object
//! inside a job; [`read_ranges`] reads every value of a large attribute (`member`) by
//! explicit windows; [`Burst`] sends several reads together, one round trip for all.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::connection::{ConnectFailure, Job, Link, Outcome, Submitter, outcome_of};
use crate::error::{LdapError, categorize, code};
use crate::session::{Attributes, Control, Entry, MsgId, Response, Scope, SearchRequest, Session};

pub const OID_PAGES: &str = "1.2.840.113556.1.4.319";
pub const OID_SD_FLAGS: &str = "1.2.840.113556.1.4.801";
/// `LDAP_MATCHING_RULE_IN_CHAIN`.
pub const OID_IN_CHAIN: &str = "1.2.840.113556.1.4.1941";

/// True if `filter` uses the IN_CHAIN rule: its pages are then awaited for
/// [`Delays::chain`](crate::profile::Delays::chain) instead of the operation timeout.
pub fn uses_in_chain(filter: &str) -> bool {
    filter.contains(OID_IN_CHAIN)
}
pub const OID_BIT_AND: &str = "1.2.840.113556.1.4.803";
pub const OID_BIT_OR: &str = "1.2.840.113556.1.4.804";

/// `MaxPageSize` of AD and Samba.
pub const PAGE_SIZE: i32 = 1000;
/// `MaxValRange` of AD; Samba splits on any explicit upper bound.
pub const RANGE_SIZE: u64 = 1500;

pub const SD_OWNER: i64 = 0x1;
pub const SD_GROUP: i64 = 0x2;
pub const SD_DACL: i64 = 0x4;
/// Needs `SeSecurityPrivilege`: never by default.
pub const SD_SACL: i64 = 0x8;
pub const SD_WITHOUT_SACL: i64 = SD_OWNER | SD_GROUP | SD_DACL;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Filters (RFC 4515)

/// A filter that cannot be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    /// Not an attribute name nor an OID.
    InvalidAttribute(String),
    /// `and` or `or` of nothing.
    Empty(&'static str),
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAttribute(name) => write!(f, "invalid attribute name: {name:?}"),
            Self::Empty(operator) => write!(f, "{operator} without filter"),
        }
    }
}

impl std::error::Error for FilterError {}

/// Escapes `\`, `*`, `(`, `)` and NUL; everything else (UTF-8 included) stays.
pub fn escape_filter(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => escaped.push_str("\\5c"),
            '*' => escaped.push_str("\\2a"),
            '(' => escaped.push_str("\\28"),
            ')' => escaped.push_str("\\29"),
            '\0' => escaped.push_str("\\00"),
            c => escaped.push(c),
        }
    }
    escaped
}

/// Every byte as `\xx` (search by `objectGUID`, `objectSid`).
pub fn escape_filter_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

/// `name` if it is an attribute name (`[A-Za-z][A-Za-z0-9-]*`) or an OID (`1.2.3`).
pub fn verify_attribute(name: &str) -> Result<&str, FilterError> {
    let mut chars = name.chars();
    let valid = match chars.next() {
        Some(c) if c.is_ascii_alphabetic() => chars.all(|c| c.is_ascii_alphanumeric() || c == '-'),
        Some(c) if c.is_ascii_digit() => {
            let parts: Vec<&str> = name.split('.').collect();
            parts.len() >= 2
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        }
        _ => false,
    };
    if valid {
        Ok(name)
    } else {
        Err(FilterError::InvalidAttribute(name.to_owned()))
    }
}

/// A value in a filter: text, or bytes written byte by byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
}

impl Value<'_> {
    fn escaped(self) -> String {
        match self {
            Value::Text(t) => escape_filter(t),
            Value::Bytes(b) => escape_filter_bytes(b),
        }
    }
}

/// `(attribute=value)`, value escaped.
pub fn eq(attribute: &str, value: Value<'_>) -> Result<String, FilterError> {
    Ok(format!(
        "({}={})",
        verify_attribute(attribute)?,
        value.escaped()
    ))
}

/// `(attribute=*)`.
pub fn present(attribute: &str) -> Result<String, FilterError> {
    Ok(format!("({}=*)", verify_attribute(attribute)?))
}

/// `(attribute=start*)`, start escaped.
pub fn starts_with(attribute: &str, start: &str) -> Result<String, FilterError> {
    Ok(format!(
        "({}={}*)",
        verify_attribute(attribute)?,
        escape_filter(start)
    ))
}

/// Extensible match `(attribute:oid:=value)` (bits of UAC, recursive membership).
pub fn rule(attribute: &str, oid: &str, value: Value<'_>) -> Result<String, FilterError> {
    Ok(format!(
        "({}:{}:={})",
        verify_attribute(attribute)?,
        verify_attribute(oid)?,
        value.escaped()
    ))
}

fn combine(operator: char, name: &'static str, filters: &[String]) -> Result<String, FilterError> {
    match filters {
        [] => Err(FilterError::Empty(name)),
        [one] => Ok(one.clone()),
        many => Ok(format!("({operator}{})", many.concat())),
    }
}

pub fn and(filters: &[String]) -> Result<String, FilterError> {
    combine('&', "et()", filters)
}

pub fn or(filters: &[String]) -> Result<String, FilterError> {
    combine('|', "ou()", filters)
}

pub fn not(filter: &str) -> String {
    format!("(!{filter})")
}

// ---------------------------------------------------------------------------
// Controls

/// BER INTEGER in two's complement, of the length `requetes._entier_ber` gives:
/// `max(1, (bit_length + 8) // 8)` bytes, where Python's `bit_length` is the one of the
/// absolute value (one byte more than minimal for -2^(8k-1), as the Python core sends it).
fn ber_integer(n: i64) -> Vec<u8> {
    let bit_length = 64 - n.unsigned_abs().leading_zeros() as usize;
    let length = ((bit_length + 8) / 8).clamp(1, 8);
    let bytes = n.to_be_bytes();
    let content = bytes.get(8 - length..).unwrap_or_default();
    let mut encoded = vec![0x02, length as u8];
    encoded.extend_from_slice(content);
    encoded
}

fn ber_length(length: usize, out: &mut Vec<u8>) {
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

/// Value of the SD flags control: `SEQUENCE { INTEGER flags }` ([MS-ADTS] 3.1.1.3.4.1.11).
pub fn sd_flags_value(flags: i64) -> Vec<u8> {
    let integer = ber_integer(flags);
    let mut value = vec![0x30];
    ber_length(integer.len(), &mut value);
    value.extend_from_slice(&integer);
    value
}

/// SD flags control, critical.
pub fn sd_flags_control(flags: i64) -> Control {
    Control {
        oid: OID_SD_FLAGS.into(),
        critical: true,
        value: Some(sd_flags_value(flags)),
    }
}

/// Paged results control (RFC 2696), critical: `SEQUENCE { INTEGER size, OCTET STRING
/// cookie }`, as python-ldap encodes it.
pub fn paged_control(size: i32, cookie: &[u8]) -> Control {
    let mut content = ber_integer(i64::from(size));
    content.push(0x04);
    ber_length(cookie.len(), &mut content);
    content.extend_from_slice(cookie);
    let mut value = vec![0x30];
    ber_length(content.len(), &mut value);
    value.extend_from_slice(&content);
    Control {
        oid: OID_PAGES.into(),
        critical: true,
        value: Some(value),
    }
}

/// Reads a BER tag and length; returns (tag, content, rest).
fn ber_read(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let (digits, rest) = rest.split_at_checked(n)?;
        (
            digits
                .iter()
                .fold(0usize, |a, &b| (a << 8) | usize::from(b)),
            rest,
        )
    };
    let (content, rest) = rest.split_at_checked(length)?;
    Some((tag, content, rest))
}

/// Cookie of the paged results control of a response; empty: last page.
pub fn paged_cookie(response: &Response) -> Vec<u8> {
    let Some(value) = response.control(OID_PAGES).and_then(|c| c.value.as_deref()) else {
        return Vec::new();
    };
    let cookie = (|| {
        let (0x30, sequence, _) = ber_read(value)? else {
            return None;
        };
        let (0x02, _, rest) = ber_read(sequence)? else {
            return None;
        };
        let (0x04, cookie, _) = ber_read(rest)? else {
            return None;
        };
        Some(cookie.to_vec())
    })();
    cookie.unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Value ranges (member;range=…)

/// The server answered a range request with bounds that do not follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeError {
    pub attribute: String,
    pub detail: String,
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "inconsistent ranges of {}: {}",
            self.attribute, self.detail
        )
    }
}

impl std::error::Error for RangeError {}

/// Attribute with an explicit window: `member;range=0-1499`. The upper bound is always
/// explicit: Samba returns everything on `0-*` (ADR 0001, finding 6).
pub fn range_request(attribute: &str, start: u64, size: u64) -> String {
    format!(
        "{attribute};range={start}-{}",
        (start + size).saturating_sub(1)
    )
}

fn decimal(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Reads the answer to a range request: (values received, next start or None at the end).
/// The server may return less than asked (Windows caps at `MaxValRange`): the next start
/// follows the bound it announces. `*` marks the last window; the attribute without range
/// holds every value.
pub fn parse_range(
    attributes: &Attributes,
    attribute: &str,
    start: u64,
) -> Result<(Vec<Vec<u8>>, Option<u64>), RangeError> {
    let lower = attribute.to_lowercase();
    let prefix = format!("{lower};range=");
    for (name, values) in attributes {
        let name_lower = name.to_lowercase();
        if name_lower == lower {
            return Ok((values.clone(), None));
        }
        let Some(bounds) = name_lower.strip_prefix(&prefix) else {
            continue;
        };
        let (first, last) = bounds.split_once('-').unwrap_or((bounds, ""));
        if decimal(first) != Some(start) {
            return Err(RangeError {
                attribute: attribute.to_owned(),
                detail: format!("demandé à partir de {start}, reçu {name}"),
            });
        }
        if last == "*" {
            return Ok((values.clone(), None));
        }
        return match decimal(last) {
            Some(last) if last >= start => Ok((values.clone(), Some(last + 1))),
            _ => Err(RangeError {
                attribute: attribute.to_owned(),
                detail: format!("borne {name}"),
            }),
        };
    }
    Ok((Vec::new(), None))
}

// ---------------------------------------------------------------------------
// Flux of pages

/// Request of the next page.
pub type Next = Box<dyn FnOnce() + Send>;

struct FluxState<T, E> {
    pages: VecDeque<T>,
    finished: bool,
    error: Option<Arc<E>>,
    next: Option<Next>,
    cancelled: bool,
}

struct FluxInner<T, E> {
    state: Mutex<FluxState<T, E>>,
    ready: Condvar,
    capacity: usize,
    notifier: Option<Box<dyn Fn() + Send + Sync>>,
}

/// Bounded queue of pages (`T`: a page) produced on the thread of a connection.
///
/// Consumed by [`Flux::next_page`] (blocking: not on the thread of the interface), or by
/// [`Flux::available`] when the notifier fires (it runs on the producing thread: it must
/// only relay). A production error is returned after the pages already received. The next
/// page is asked for only when there is room in the queue.
pub struct Flux<T, E> {
    inner: Arc<FluxInner<T, E>>,
}

impl<T, E> Clone for Flux<T, E> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<T, E> fmt::Debug for Flux<T, E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Flux")
            .field("capacity", &self.inner.capacity)
            .finish_non_exhaustive()
    }
}

impl<T, E> FluxState<T, E> {
    /// Under the lock: resumes the production if there is room (or on cancellation).
    fn release_next(&mut self, capacity: usize) -> Option<Next> {
        if self.next.is_some() && (self.cancelled || self.pages.len() < capacity) {
            self.next.take()
        } else {
            None
        }
    }
}

impl<T, E> Flux<T, E> {
    pub fn new(capacity: usize, notifier: Option<Box<dyn Fn() + Send + Sync>>) -> Self {
        Self {
            inner: Arc::new(FluxInner {
                state: Mutex::new(FluxState {
                    pages: VecDeque::new(),
                    finished: false,
                    error: None,
                    next: None,
                    cancelled: false,
                }),
                ready: Condvar::new(),
                capacity: capacity.max(1),
                notifier,
            }),
        }
    }

    fn notify(&self) {
        if let Some(notifier) = &self.inner.notifier {
            notifier();
        }
    }

    /// The next page, waiting for it; None at the end, the error once the pages are given.
    pub fn next_page(&self) -> Option<Result<T, Arc<E>>> {
        let (page, next, error) = {
            let mut state = lock(&self.inner.state);
            while state.pages.is_empty() && !state.finished {
                state = self
                    .inner
                    .ready
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            let page = state.pages.pop_front();
            let next = state.release_next(self.inner.capacity);
            (page, next, state.error.clone())
        };
        if let Some(next) = next {
            next();
        }
        match (page, error) {
            (Some(page), _) => Some(Ok(page)),
            (None, Some(error)) => Some(Err(error)),
            (None, None) => None,
        }
    }

    /// Pages arrived since the last call, without waiting; the production error once every
    /// page is given.
    pub fn available(&self) -> Result<Vec<T>, Arc<E>> {
        let (pages, next, error) = {
            let mut state = lock(&self.inner.state);
            let pages: Vec<T> = state.pages.drain(..).collect();
            let next = state.release_next(self.inner.capacity);
            let error = if state.finished && pages.is_empty() {
                state.error.clone()
            } else {
                None
            };
            (pages, next, error)
        };
        if let Some(next) = next {
            next();
        }
        match error {
            Some(error) => Err(error),
            None => Ok(pages),
        }
    }

    /// The production is over and every page given.
    pub fn finished(&self) -> bool {
        let state = lock(&self.inner.state);
        state.finished && state.pages.is_empty()
    }

    /// Stops the production; waiting pages are dropped.
    pub fn cancel(&self) {
        let next = {
            let mut state = lock(&self.inner.state);
            state.cancelled = true;
            state.pages.clear();
            state.release_next(self.inner.capacity)
        };
        if let Some(next) = next {
            next(); // the production sees the cancellation and frees the cursor
        }
    }

    pub fn cancelled(&self) -> bool {
        lock(&self.inner.state).cancelled
    }

    /// Adds a page. `next` asks for the following one (None: it was the last); run at once
    /// if there is room, otherwise when a page is consumed.
    pub fn put(&self, page: T, next: Option<Next>) {
        let next = {
            let mut state = lock(&self.inner.state);
            if !state.cancelled {
                state.pages.push_back(page);
            }
            let next = match next {
                None => {
                    state.finished = true;
                    None
                }
                Some(next) => {
                    state.next = Some(next);
                    state.release_next(self.inner.capacity)
                }
            };
            self.inner.ready.notify_all();
            next
        };
        self.notify();
        if let Some(next) = next {
            next();
        }
    }

    /// End of the production, normal or on error (ignored once cancelled).
    pub fn finish(&self, error: Option<E>) {
        {
            let mut state = lock(&self.inner.state);
            state.finished = true;
            if !state.cancelled {
                state.error = error.map(Arc::new);
            }
            self.inner.ready.notify_all();
        }
        self.notify();
    }
}

// ---------------------------------------------------------------------------
// Paged search on a connection

/// Why a search stopped.
#[derive(Clone, Debug)]
pub enum SearchError {
    Ldap {
        dc: String,
        error: LdapError,
    },
    Connect(ConnectFailure),
    /// The connection was bound again between two pages: the cursor is gone.
    Reconnected {
        from: u64,
        to: u64,
    },
    /// The connection was closed between two pages.
    Closed,
}

/// Where the pages of a search go.
pub trait Pages: Send + Sync + 'static {
    /// A page, and the request of the following one (None: it was the last).
    fn deliver(&self, entries: Vec<Entry>, next: Option<Next>);
    fn fail(&self, error: SearchError);
    fn finish(&self);
    fn cancelled(&self) -> bool;
    /// What an error means for the link; default: the category of the error.
    fn outcome(&self, _dc: &str, error: &LdapError) -> Option<Outcome> {
        outcome_of(categorize(error))
    }
}

impl Pages for Flux<Vec<Entry>, SearchError> {
    fn deliver(&self, entries: Vec<Entry>, next: Option<Next>) {
        self.put(entries, next);
    }
    fn fail(&self, error: SearchError) {
        Flux::finish(self, Some(error));
    }
    fn finish(&self) {
        Flux::finish(self, None);
    }
    fn cancelled(&self) -> bool {
        Flux::cancelled(self)
    }
}

/// A paged search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Search {
    pub base: String,
    pub scope: Scope,
    pub filter: String,
    /// Explicit (never `*`); `["1.1"]`: DNs only.
    pub attributes: Vec<String>,
    pub page_size: i32,
    pub sd_flags: Option<i64>,
    /// Added to the paging control (extended DN, show deleted).
    pub controls: Vec<Control>,
}

#[derive(Default)]
struct Cursor {
    cookie: Vec<u8>,
    /// Generation of the link that holds the cursor.
    generation: Option<u64>,
}

struct PageJob {
    search: Arc<Search>,
    cursor: Arc<Mutex<Cursor>>,
    pages: Arc<dyn Pages>,
    submitter: Submitter,
    /// Error kept until the outcome is handled (`Job::settle`).
    pending: Option<SearchError>,
}

impl PageJob {
    fn request(&self, size: i32, cookie: &[u8], attributes: Vec<String>) -> SearchRequest {
        let mut controls = vec![paged_control(size, cookie)];
        controls.extend(self.search.controls.iter().cloned());
        if let Some(flags) = self.search.sd_flags {
            controls.push(sd_flags_control(flags));
        }
        SearchRequest {
            base: self.search.base.clone(),
            scope: self.search.scope,
            filter: self.search.filter.clone(),
            attributes,
            controls,
            size_limit: 0,
        }
    }

    fn launch(
        search: Arc<Search>,
        cursor: Arc<Mutex<Cursor>>,
        pages: Arc<dyn Pages>,
        submitter: Submitter,
    ) {
        let replayable = lock(&cursor).generation.is_none();
        let job = Box::new(Self {
            search,
            cursor,
            pages: pages.clone(),
            submitter: submitter.clone(),
            pending: None,
        });
        if submitter.submit(job, replayable).is_err() {
            pages.fail(SearchError::Closed);
        }
    }
}

impl Job for PageJob {
    fn run(&mut self, link: &mut Link, last_attempt: bool) -> Outcome {
        let (cookie, generation) = {
            let cursor = lock(&self.cursor);
            (cursor.cookie.clone(), cursor.generation)
        };
        if let Some(generation) = generation.filter(|&g| g != link.state.generation) {
            self.pages.fail(SearchError::Reconnected {
                from: generation,
                to: link.state.generation,
            });
            return Outcome::Done;
        }
        let dc = link.state.dc.clone();
        let failed = |job: &mut Self, error: LdapError| {
            let outcome = job.pages.outcome(&dc, &error);
            let retry = matches!(outcome, Some(Outcome::Lost { retry: true, .. }));
            if !retry || last_attempt {
                job.pending = Some(SearchError::Ldap {
                    dc: dc.clone(),
                    error,
                });
            }
            outcome.unwrap_or(Outcome::Done)
        };
        if self.pages.cancelled() {
            if !cookie.is_empty() {
                // Frees the cursor on the server (RFC 2696, 3).
                let request = self.request(0, &cookie, vec!["1.1".into()]);
                let timeout = link.timeout_for(&self.search.filter);
                if let Err(error) = link.session.search_wait(request, Some(timeout)) {
                    return failed(self, error);
                }
            }
            self.pages.finish();
            return Outcome::Done;
        }
        let request = self.request(
            self.search.page_size,
            &cookie,
            self.search.attributes.clone(),
        );
        let timeout = link.timeout_for(&self.search.filter);
        match link.session.search_wait(request, Some(timeout)) {
            Ok(response) => {
                let cookie = paged_cookie(&response);
                {
                    let mut cursor = lock(&self.cursor);
                    cursor.generation = Some(link.state.generation);
                    cursor.cookie.clone_from(&cookie);
                }
                let next: Option<Next> = if cookie.is_empty() {
                    None
                } else {
                    let (search, cursor) = (self.search.clone(), self.cursor.clone());
                    let (pages, submitter) = (self.pages.clone(), self.submitter.clone());
                    Some(Box::new(move || {
                        Self::launch(search, cursor, pages, submitter)
                    }))
                };
                self.pages.deliver(response.into_entries(), next);
                Outcome::Done
            }
            Err(error) => failed(self, error),
        }
    }

    fn settle(&mut self) {
        if let Some(error) = self.pending.take() {
            self.pages.fail(error);
        }
    }

    fn fail(&mut self, failure: ConnectFailure) {
        self.pages.fail(SearchError::Connect(failure));
    }
}

/// Starts a paged search; its pages go to `pages`. If the DC falls during the first page,
/// it is asked again on another; later, the search stops on the loss (the cursor exists on
/// the first DC only).
pub fn search(submitter: &Submitter, search: Search, pages: Arc<dyn Pages>) {
    PageJob::launch(
        Arc::new(search),
        Arc::new(Mutex::new(Cursor::default())),
        pages,
        submitter.clone(),
    );
}

// ---------------------------------------------------------------------------
// Reads inside a job

/// Reads one object by its DN, inside a job; None if it does not exist or does not match
/// `filter` (checked by the server, with its matching rules).
pub fn read_entry(
    session: &mut dyn Session,
    dn: &str,
    attributes: &[String],
    filter: &str,
    sd_flags: Option<i64>,
    timeout: Option<Duration>,
) -> Result<Option<Entry>, LdapError> {
    let request = SearchRequest {
        base: dn.to_owned(),
        scope: Scope::Base,
        filter: filter.to_owned(),
        attributes: attributes.to_vec(),
        controls: sd_flags.map(sd_flags_control).into_iter().collect(),
        size_limit: 0,
    };
    match session.search_wait(request, timeout) {
        Ok(response) => Ok(response.into_entries().into_iter().next()),
        Err(e) if e.code == code::NO_SUCH_OBJECT && !e.foreign => Ok(None),
        Err(e) => Err(e),
    }
}

/// Failure of [`read_ranges`].
#[derive(Debug, Clone)]
pub enum RangesError {
    Ldap(LdapError),
    Range(RangeError),
}

/// Every value of `attribute` of the object `dn`, by windows of `size`.
pub fn read_ranges(
    session: &mut dyn Session,
    dn: &str,
    attribute: &str,
    size: u64,
    timeout: Option<Duration>,
) -> Result<Vec<Vec<u8>>, RangesError> {
    let mut values = Vec::new();
    let mut start = Some(0);
    while let Some(first) = start {
        let request = SearchRequest {
            base: dn.to_owned(),
            scope: Scope::Base,
            filter: "(objectClass=*)".into(),
            attributes: vec![range_request(attribute, first, size)],
            controls: Vec::new(),
            size_limit: 0,
        };
        let response = session
            .search_wait(request, timeout)
            .map_err(RangesError::Ldap)?;
        let Some(entry) = response.into_entries().into_iter().next() else {
            break;
        };
        let (received, next) =
            parse_range(&entry.attributes, attribute, first).map_err(RangesError::Range)?;
        values.extend(received);
        start = next;
    }
    Ok(values)
}

/// What a request of a [`Burst`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurstAnswer {
    /// The entries; empty if the object does not exist or does not match the filter.
    Entries(Vec<Entry>),
    /// Size limit exceeded.
    TooMany,
}

/// Reads sent together inside a job: every request leaves before the first answer, and
/// the whole costs one round trip instead of one per request (RFC 4511, 4.1.1). Used by the
/// checks before a write and the reading back after it, where each round trip costs
/// 127 ms from a remote host.
#[derive(Debug, Default)]
pub struct Burst {
    ids: Vec<MsgId>,
}

impl Burst {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Sends a search; returns the rank of its answer.
    #[allow(clippy::too_many_arguments)]
    pub fn search(
        &mut self,
        session: &mut dyn Session,
        base: &str,
        scope: Scope,
        filter: &str,
        attributes: &[String],
        size_limit: i32,
        sd_flags: Option<i64>,
    ) -> Result<usize, LdapError> {
        let id = session.search(SearchRequest {
            base: base.to_owned(),
            scope,
            filter: filter.to_owned(),
            attributes: attributes.to_vec(),
            controls: sd_flags.map(sd_flags_control).into_iter().collect(),
            size_limit,
        })?;
        self.ids.push(id);
        Ok(self.ids.len() - 1)
    }

    /// Waits for every answer, in order. Any error other than "no such object" and "size
    /// limit" is returned once every answer is in; a timeout abandons the rest at once.
    pub fn receive(
        &mut self,
        session: &mut dyn Session,
        timeout: Option<Duration>,
    ) -> Result<Vec<BurstAnswer>, LdapError> {
        let ids = std::mem::take(&mut self.ids);
        let mut answers = Vec::with_capacity(ids.len());
        let mut first_error = None;
        for (rank, &id) in ids.iter().enumerate() {
            match session.result(id, timeout) {
                Ok(response) => answers.push(BurstAnswer::Entries(response.into_entries())),
                Err(e) if e.foreign => return Err(e),
                Err(e) if e.code == code::NO_SUCH_OBJECT => {
                    answers.push(BurstAnswer::Entries(Vec::new()));
                }
                Err(e) if e.code == code::SIZELIMIT_EXCEEDED => answers.push(BurstAnswer::TooMany),
                Err(e) if e.code == code::TIMEOUT => {
                    for &rest in ids.get(rank + 1..).unwrap_or_default() {
                        let _ = session.abandon(rest);
                    }
                    return Err(e);
                }
                Err(e) => {
                    first_error.get_or_insert(e);
                    answers.push(BurstAnswer::Entries(Vec::new()));
                }
            }
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(answers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters() {
        assert_eq!(escape_filter("a*(b)\\\0é"), "a\\2a\\28b\\29\\5c\\00é");
        assert_eq!(escape_filter_bytes(&[0, 0xAB]), "\\00\\ab");
        assert_eq!(eq("cn", Value::Text("x*")).unwrap(), "(cn=x\\2a)");
        assert_eq!(
            eq("objectGUID", Value::Bytes(&[1])).unwrap(),
            "(objectGUID=\\01)"
        );
        assert_eq!(present("mail").unwrap(), "(mail=*)");
        assert_eq!(starts_with("cn", "Du(").unwrap(), "(cn=Du\\28*)");
        assert_eq!(
            rule("userAccountControl", OID_BIT_AND, Value::Text("2")).unwrap(),
            "(userAccountControl:1.2.840.113556.1.4.803:=2)"
        );
        let both = and(&["(a=1)".into(), "(b=2)".into()]).unwrap();
        assert_eq!(both, "(&(a=1)(b=2))");
        assert_eq!(or(&["(a=1)".into()]).unwrap(), "(a=1)");
        assert_eq!(not("(a=1)"), "(!(a=1))");
        assert_eq!(and(&[]), Err(FilterError::Empty("et()")));
        for bad in ["", "1", "a b", "-a", "1.", "1..2", "a_b", "é"] {
            assert!(verify_attribute(bad).is_err(), "{bad}");
        }
        for good in ["cn", "msDS-User-Account-Control-Computed", "1.2", "2.5.4.3"] {
            assert!(verify_attribute(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn controls() {
        assert_eq!(sd_flags_value(7), [0x30, 0x03, 0x02, 0x01, 0x07]);
        assert_eq!(sd_flags_value(0x80), [0x30, 0x04, 0x02, 0x02, 0x00, 0x80]);
        assert_eq!(sd_flags_value(-1), [0x30, 0x03, 0x02, 0x01, 0xFF]);
        assert_eq!(
            sd_flags_value(-(1 << 31)),
            [0x30, 0x07, 0x02, 0x05, 0xFF, 0x80, 0x00, 0x00, 0x00]
        );
        // As python-ldap: SimplePagedResultsControl(True, size=5, cookie=b"abc").
        let paged = paged_control(5, b"abc");
        assert_eq!(
            paged.value.as_deref().unwrap(),
            b"0\x08\x02\x01\x05\x04\x03abc"
        );
        let response = Response {
            kind: crate::session::ResultKind::Search,
            items: Vec::new(),
            controls: vec![paged],
        };
        assert_eq!(paged_cookie(&response), b"abc");
        let long = paged_control(1000, &[7; 300]);
        let response = Response {
            controls: vec![long],
            ..response
        };
        assert_eq!(paged_cookie(&response), vec![7; 300]);
    }

    fn attributes(name: &str, n: usize) -> Attributes {
        vec![(name.to_owned(), (0..n).map(|i| vec![i as u8]).collect())]
    }

    #[test]
    fn ranges() {
        assert_eq!(range_request("member", 0, 1500), "member;range=0-1499");
        assert_eq!(
            parse_range(&attributes("member;range=0-1499", 3), "member", 0)
                .unwrap()
                .1,
            Some(1500)
        );
        assert_eq!(
            parse_range(&attributes("Member;Range=1500-*", 2), "member", 1500).unwrap(),
            (vec![vec![0], vec![1]], None)
        );
        assert_eq!(
            parse_range(&attributes("member", 4), "member", 0)
                .unwrap()
                .1,
            None
        );
        assert_eq!(
            parse_range(&Vec::new(), "member", 0).unwrap(),
            (Vec::new(), None)
        );
        assert!(parse_range(&attributes("member;range=10-20", 1), "member", 0).is_err());
        assert!(parse_range(&attributes("member;range=0-x", 1), "member", 0).is_err());
    }

    #[test]
    fn flux_bounds_the_production() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let flux: Flux<Vec<u32>, String> = Flux::new(2, None);
        let asked = Arc::new(AtomicUsize::new(0));
        let next = |asked: &Arc<AtomicUsize>| -> Next {
            let asked = asked.clone();
            Box::new(move || {
                asked.fetch_add(1, Ordering::SeqCst);
            })
        };
        flux.put(vec![1], Some(next(&asked)));
        assert_eq!(asked.load(Ordering::SeqCst), 1); // room: asked at once
        flux.put(vec![2], Some(next(&asked)));
        assert_eq!(asked.load(Ordering::SeqCst), 1); // full: waits
        assert_eq!(flux.next_page().unwrap().unwrap(), [1]);
        assert_eq!(asked.load(Ordering::SeqCst), 2);
        flux.put(vec![3], None);
        assert_eq!(flux.available().unwrap(), [vec![2], vec![3]]);
        assert!(flux.finished());
        assert!(flux.next_page().is_none());

        let failing: Flux<Vec<u32>, String> = Flux::new(1, None);
        failing.put(vec![1], Some(Box::new(|| {})));
        failing.finish(Some("lost".into()));
        assert_eq!(failing.next_page().unwrap().unwrap(), [1]);
        assert_eq!(*failing.next_page().unwrap().unwrap_err(), "lost");
        assert_eq!(*failing.available().unwrap_err(), "lost");

        let cancelled: Flux<Vec<u32>, String> = Flux::new(1, None);
        cancelled.put(vec![1], Some(Box::new(|| {})));
        cancelled.cancel();
        cancelled.finish(Some("ignored".into()));
        assert!(cancelled.next_page().is_none());
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Connection to a domain: a worker thread, the order of the DCs, failover.
//!
//! Port of `annuaire.core.connexion.Connexion` (ADR 0005, ADR 0016 § 3). Each connection
//! owns one thread, which holds the bound session and runs the submitted jobs one by one.
//! The connection binds on first need: the PDC emulator first for a write connection (or
//! only the DC the profile imposes on writes), the preferred DC, then the DCs announced by
//! DNS, the one that just fell last. A job that loses the DC is run once more on another DC
//! if it is replayable (a read); a timeout drops the connection without replay.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::error::{Category, LdapError, Origin, categorize};
use crate::profile::{Delays, Profile};
use crate::rootdse::{ROOT_DSE_ATTRIBUTES, RootDse, RootDseError};
use crate::session::{Scope, SearchRequest, Session};
use crate::sysvol::Protection;

/// Minimum strength of the SASL layer without TLS: sealing (ADR 0001, decision 2).
pub const SSF_MIN: u32 = 56;

/// Opens bound sessions with DCs.
pub trait Dialer: Send + Sync {
    /// Connects to `dc` and binds; returns the session, whether it runs over TLS, and the
    /// strength of its SASL layer.
    fn dial(&self, dc: &str) -> Result<(Box<dyn Session>, bool, u32), LdapError>;
}

/// Finds the DCs of a domain.
pub trait Resolver: Send + Sync {
    /// DCs announced for the domain, in the order of the attempts.
    fn dcs(&self, domain: &str) -> Result<Vec<String>, ResolveError>;
    /// The PDC emulator, if announced.
    fn pdc(&self, domain: &str) -> Result<Option<String>, ResolveError>;
}

/// Failure of a discovery.
#[derive(Clone, Debug)]
pub struct ResolveError {
    /// The DNS did not answer (rather than: no DC announced).
    pub unreachable: bool,
    pub detail: String,
    pub origin: Option<Origin>,
}

/// The resolver of the host: SRV records through `/etc/resolv.conf`.
#[derive(Debug, Clone, Copy, Default)]
pub struct DnsResolver;

impl From<crate::srv::SrvError> for ResolveError {
    fn from(error: crate::srv::SrvError) -> Self {
        let unreachable = matches!(error, crate::srv::SrvError::Unreachable { .. });
        let detail = match error {
            crate::srv::SrvError::NotFound { name } => name,
            crate::srv::SrvError::Unreachable { detail } => detail,
        };
        Self {
            unreachable,
            detail,
            origin: None,
        }
    }
}

impl Resolver for DnsResolver {
    fn dcs(&self, domain: &str) -> Result<Vec<String>, ResolveError> {
        let conf = crate::srv::ResolvConf::system();
        Ok(crate::srv::find_dcs(&conf, domain)?
            .into_iter()
            .map(|r| r.target)
            .collect())
    }

    fn pdc(&self, domain: &str) -> Result<Option<String>, ResolveError> {
        let conf = crate::srv::ResolvConf::system();
        Ok(crate::srv::find_pdc(&conf, domain)?.map(|r| r.target))
    }
}

/// Description of an established connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub dc: String,
    pub root_dse: RootDse,
    pub tls: bool,
    /// Strength of the SASL layer (0 over TLS, where Samba accepts none).
    pub ssf: u32,
    /// Incremented at every new bind: a paged search does not survive a change.
    pub generation: u64,
}

impl State {
    /// Sensitive writes (passwords) are allowed (ADR 0001, decision 4).
    pub fn encrypted(&self) -> bool {
        self.tls || self.ssf >= SSF_MIN
    }
}

/// What a job receives: the bound session, its state, the operation timeouts.
pub struct Link {
    pub session: Box<dyn Session>,
    pub state: Arc<State>,
    pub timeout: Duration,
    /// Timeout of a search using the IN_CHAIN rule ([`Delays::chain`]).
    pub chain_timeout: Duration,
    /// Protection of the SYSVOL sessions opened for the job (profile option, ADR 0021).
    pub sysvol: Protection,
}

impl Link {
    /// The timeout of a search with `filter`: [`Delays::chain`] for the IN_CHAIN rule.
    pub fn timeout_for(&self, filter: &str) -> Duration {
        if crate::search::uses_in_chain(filter) {
            self.chain_timeout
        } else {
            self.timeout
        }
    }
}

impl std::fmt::Debug for Link {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Link")
            .field("state", &self.state)
            .field("timeout", &self.timeout)
            .field("chain_timeout", &self.chain_timeout)
            .field("sysvol", &self.sysvol)
            .finish_non_exhaustive()
    }
}

/// Why no session could be established.
#[derive(Clone, Debug)]
pub enum ConnectFailure {
    /// Every candidate DC was unreachable.
    NoDc {
        domain: String,
        failures: Vec<(String, LdapError)>,
    },
    /// The bind with `dc` failed for a reason another DC would not change (ticket,
    /// security, Kerberos…).
    Bind { dc: String, error: LdapError },
    /// TLS mode, the port answers but the negotiation failed: the certificate, not the
    /// network (the other DCs have the same CA).
    Tls { dc: String, error: LdapError },
    /// The SASL layer is weaker than sealing.
    NotEncrypted { dc: String, ssf: u32 },
    /// The RootDSE is not the one of an AD DC.
    RootDse { dc: String, error: RootDseError },
    /// The DNS discovery failed with no DC to try.
    Resolve(ResolveError),
    /// The connection was closed before the job ran.
    Closed,
}

/// What became of a job run on a link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Done,
    /// The link is no longer usable: dropped, the DC marked as fallen if `fallen`, and the
    /// job run again on another DC if `retry` (and it was not the last attempt).
    Lost {
        fallen: bool,
        retry: bool,
    },
}

/// A unit of work for the connection thread.
pub trait Job: Send {
    /// Called once before anything; false: the job was cancelled meanwhile.
    fn start(&mut self) -> bool {
        true
    }
    /// Runs on the link. `last_attempt`: no other attempt follows, the job must deliver
    /// its result or its error (in `settle`).
    fn run(&mut self, link: &mut Link, last_attempt: bool) -> Outcome;
    /// Called once the outcome is handled (the link dropped if it was lost), when no other
    /// attempt follows: a job that keeps its error delivers it here, so that the caller
    /// sees the connection already in its new state, as with the Python connection.
    fn settle(&mut self) {}
    /// No link could be established: deliver this failure.
    fn fail(&mut self, failure: ConnectFailure);
}

/// Outcome of an error met by a job: whether the link is lost, the DC fallen, the job
/// worth retrying elsewhere.
pub fn outcome_of(category: Category) -> Option<Outcome> {
    match category {
        c if c.unreachable() => Some(Outcome::Lost {
            fallen: true,
            retry: true,
        }),
        Category::Timeout => Some(Outcome::Lost {
            fallen: false,
            retry: false,
        }),
        _ => None,
    }
}

enum Message {
    Job(Box<dyn Job>, bool),
    Close,
}

struct Inner {
    profile: Profile,
    to_pdc: bool,
    delays: Delays,
    dialer: Box<dyn Dialer>,
    resolver: Box<dyn Resolver>,
    state: Mutex<Option<Arc<State>>>,
    fallen: Mutex<Option<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Inner {
    /// DCs to try: the PDC for a write, the preferred DC, those of DNS; the one that just
    /// fell last, unless it is the PDC of a write (a DC closes an idle connection by itself,
    /// and the next write must find the PDC again, not slide to another DC). A write to the
    /// DC imposed by the profile goes to it only.
    fn candidates(&self) -> Result<Vec<String>, ResolveError> {
        if self.to_pdc {
            if let Some(dc) = &self.profile.write_dc {
                return Ok(vec![dc.clone()]);
            }
        }
        let mut seen: Vec<String> = Vec::new();
        let mut fallen = lock(&self.fallen).clone();
        if self.to_pdc {
            if let Ok(Some(pdc)) = self.resolver.pdc(&self.profile.domain) {
                if fallen.as_deref() == Some(pdc.as_str()) {
                    fallen = None;
                }
                seen.push(pdc);
            }
        }
        if let Some(preferred) = &self.profile.preferred_dc {
            if !seen.contains(preferred) {
                seen.push(preferred.clone());
            }
        }
        let announced = match self.resolver.dcs(&self.profile.domain) {
            Ok(dcs) => dcs,
            Err(e) if seen.is_empty() => return Err(e),
            Err(_) => Vec::new(),
        };
        for dc in announced {
            if !seen.contains(&dc) {
                seen.push(dc);
            }
        }
        let mut order: Vec<String> = seen
            .iter()
            .filter(|dc| Some(dc.as_str()) != fallen.as_deref())
            .cloned()
            .collect();
        if let Some(f) = fallen.filter(|f| seen.contains(f)) {
            order.push(f);
        }
        Ok(order)
    }

    fn port_open(&self, dc: &str) -> bool {
        let Ok(addresses) = (dc, self.profile.mode.port()).to_socket_addrs() else {
            return false;
        };
        addresses
            .into_iter()
            .any(|a| TcpStream::connect_timeout(&a, self.delays.connect).is_ok())
    }

    /// Opens and binds a session with `dc`, reads the RootDSE.
    fn bind(&self, dc: &str, generation: u64) -> Result<Link, ConnectFailure> {
        let mode = self.profile.mode;
        let ldap_failure = |error: LdapError| {
            let category = categorize(&error);
            if category.unreachable() && mode.tls() && self.port_open(dc) {
                ConnectFailure::Tls {
                    dc: dc.to_owned(),
                    error,
                }
            } else {
                ConnectFailure::Bind {
                    dc: dc.to_owned(),
                    error,
                }
            }
        };
        let (mut session, tls, ssf) = self.dialer.dial(dc).map_err(ldap_failure)?;
        let ssf = if mode.tls() { 0 } else { ssf };
        if !mode.tls() && ssf < SSF_MIN {
            session.unbind();
            return Err(ConnectFailure::NotEncrypted {
                dc: dc.to_owned(),
                ssf,
            });
        }
        let request = SearchRequest {
            base: String::new(),
            scope: Scope::Base,
            filter: "(objectClass=*)".into(),
            attributes: ROOT_DSE_ATTRIBUTES.iter().map(|&a| a.to_owned()).collect(),
            controls: Vec::new(),
            size_limit: 0,
        };
        let root_dse = match session.search_wait(request, Some(self.delays.operation)) {
            Ok(response) => {
                let attributes = response
                    .into_entries()
                    .into_iter()
                    .next()
                    .map(|e| e.attributes)
                    .unwrap_or_default();
                RootDse::parse(&attributes)
            }
            Err(e) => {
                session.unbind();
                return Err(ldap_failure(e));
            }
        };
        let root_dse = match root_dse {
            Ok(dse) => dse,
            Err(error) => {
                session.unbind();
                return Err(ConnectFailure::RootDse {
                    dc: dc.to_owned(),
                    error,
                });
            }
        };
        Ok(Link {
            session,
            state: Arc::new(State {
                dc: dc.to_owned(),
                root_dse,
                tls: tls || mode.tls(),
                ssf,
                generation,
            }),
            timeout: self.delays.operation,
            chain_timeout: self.delays.chain,
            sysvol: Protection::of_profile(self.profile.smb2_signing),
        })
    }
}

struct Worker {
    inner: Arc<Inner>,
    link: Option<Link>,
    generation: u64,
}

impl Worker {
    fn connect(&mut self) -> Result<Link, ConnectFailure> {
        let candidates = self.inner.candidates().map_err(ConnectFailure::Resolve)?;
        let mut failures = Vec::new();
        for dc in candidates {
            match self.inner.bind(&dc, self.generation + 1) {
                Ok(link) => {
                    self.generation += 1;
                    *lock(&self.inner.state) = Some(link.state.clone());
                    *lock(&self.inner.fallen) = None;
                    return Ok(link);
                }
                Err(ConnectFailure::Bind { dc, error }) if categorize(&error).unreachable() => {
                    failures.push((dc, error));
                }
                Err(other) => return Err(other),
            }
        }
        Err(ConnectFailure::NoDc {
            domain: self.inner.profile.domain.clone(),
            failures,
        })
    }

    fn disconnect(&mut self, fallen: bool) {
        *lock(&self.inner.state) = None;
        if let Some(mut link) = self.link.take() {
            if fallen {
                *lock(&self.inner.fallen) = Some(link.state.dc.clone());
            }
            link.session.unbind();
        }
    }

    fn execute(&mut self, mut job: Box<dyn Job>, replayable: bool) {
        if !job.start() {
            return;
        }
        let attempts = if replayable { 2 } else { 1 };
        for attempt in 0..attempts {
            let last = attempt + 1 == attempts;
            let link = match self.link.take() {
                Some(link) => link,
                None => match self.connect() {
                    Ok(link) => link,
                    Err(failure) => {
                        job.fail(failure);
                        return;
                    }
                },
            };
            let link = self.link.insert(link);
            match job.run(link, last) {
                Outcome::Done => {
                    job.settle();
                    return;
                }
                Outcome::Lost { fallen, retry } => {
                    self.disconnect(fallen);
                    if !(retry && !last) {
                        job.settle();
                        return;
                    }
                }
            }
        }
    }

    fn serve(mut self, receiver: mpsc::Receiver<Message>) {
        while let Ok(Message::Job(job, replayable)) = receiver.recv() {
            self.execute(job, replayable);
        }
        self.disconnect(false);
    }
}

/// Connection to a domain, served by its own thread. Usable from any thread.
pub struct Connection {
    inner: Arc<Inner>,
    sender: Submitter,
    thread: Mutex<Option<JoinHandle<()>>>,
}

/// Submits jobs to a connection; a clone outlives a borrow of the connection (the next
/// page of a search is submitted by the previous one). Refuses jobs once it is closed.
#[derive(Clone)]
pub struct Submitter(Arc<Mutex<Option<mpsc::Sender<Message>>>>);

impl std::fmt::Debug for Submitter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Submitter").finish_non_exhaustive()
    }
}

impl Submitter {
    /// Submits a job to the thread. `replayable`: it may be run again on another DC if
    /// the first one falls (true for a read, false for a write or a page of a paged
    /// search, whose cursor belongs to the DC). Err(job) once the connection is closed.
    pub fn submit(&self, job: Box<dyn Job>, replayable: bool) -> Result<(), Box<dyn Job>> {
        match lock(&self.0).as_ref() {
            Some(sender) => sender
                .send(Message::Job(job, replayable))
                .map_err(|e| match e.0 {
                    Message::Job(job, _) => job,
                    Message::Close => unreachable!("only jobs are sent here"),
                }),
            None => Err(job),
        }
    }

    pub fn closed(&self) -> bool {
        lock(&self.0).is_none()
    }

    fn close(&self) {
        if let Some(sender) = lock(&self.0).take() {
            let _ = sender.send(Message::Close);
        }
    }
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("profile", &self.inner.profile)
            .field("to_pdc", &self.inner.to_pdc)
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Starts the thread; the bind happens on first need. `to_pdc`: the PDC emulator comes
    /// before any other DC (writes).
    pub fn new(
        profile: Profile,
        delays: Delays,
        to_pdc: bool,
        dialer: Box<dyn Dialer>,
        resolver: Box<dyn Resolver>,
    ) -> Self {
        let name = format!("ldap {}", profile.domain);
        let inner = Arc::new(Inner {
            profile,
            to_pdc,
            delays,
            dialer,
            resolver,
            state: Mutex::new(None),
            fallen: Mutex::new(None),
        });
        let (sender, receiver) = mpsc::channel();
        let worker = Worker {
            inner: inner.clone(),
            link: None,
            generation: 0,
        };
        let thread = std::thread::Builder::new()
            .name(name)
            .spawn(move || worker.serve(receiver))
            .expect("connection thread");
        Self {
            inner,
            sender: Submitter(Arc::new(Mutex::new(Some(sender)))),
            thread: Mutex::new(Some(thread)),
        }
    }

    pub fn profile(&self) -> &Profile {
        &self.inner.profile
    }

    pub fn to_pdc(&self) -> bool {
        self.inner.to_pdc
    }

    pub fn delays(&self) -> Delays {
        self.inner.delays
    }

    /// Last established link (None before the first one and after a loss).
    pub fn state(&self) -> Option<Arc<State>> {
        lock(&self.inner.state).clone()
    }

    /// The DCs the next bind would try, in order.
    pub fn candidates(&self) -> Result<Vec<String>, ResolveError> {
        self.inner.candidates()
    }

    /// See [`Submitter::submit`].
    pub fn submit(&self, job: Box<dyn Job>, replayable: bool) -> Result<(), Box<dyn Job>> {
        self.sender.submit(job, replayable)
    }

    pub fn submitter(&self) -> Submitter {
        self.sender.clone()
    }

    pub fn closed(&self) -> bool {
        self.sender.closed()
    }

    /// Ends the thread after the jobs already submitted; frees the session.
    pub fn close(&self) {
        self.sender.close();
    }

    /// Closes and waits for the thread (tests, end of a command).
    pub fn join(&self) {
        self.close();
        if let Some(thread) = lock(&self.thread).take() {
            let _ = thread.join();
        }
    }

    /// Runs `operation` on the thread and waits for its result (Rust callers and tests;
    /// the Python module has its own jobs).
    pub fn run<T, F>(&self, replayable: bool, operation: F) -> Result<T, Failure>
    where
        T: Send + 'static,
        F: FnMut(&mut Link) -> Result<T, LdapError> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel();
        let job = OperationJob {
            operation,
            reply: Some(sender),
            pending: None,
        };
        if self.submit(Box::new(job), replayable).is_err() {
            return Err(Failure::Connect(ConnectFailure::Closed));
        }
        receiver
            .recv()
            .unwrap_or(Err(Failure::Connect(ConnectFailure::Closed)))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.close();
    }
}

/// Failure of an operation run by [`Connection::run`].
#[derive(Clone, Debug)]
pub enum Failure {
    Connect(ConnectFailure),
    Ldap { dc: String, error: LdapError },
}

struct OperationJob<T, F> {
    operation: F,
    reply: Option<mpsc::Sender<Result<T, Failure>>>,
    pending: Option<Failure>,
}

impl<T, F> OperationJob<T, F> {
    fn deliver(&mut self, result: Result<T, Failure>) {
        if let Some(reply) = self.reply.take() {
            let _ = reply.send(result);
        }
    }
}

impl<T, F> Job for OperationJob<T, F>
where
    T: Send + 'static,
    F: FnMut(&mut Link) -> Result<T, LdapError> + Send + 'static,
{
    fn run(&mut self, link: &mut Link, last_attempt: bool) -> Outcome {
        match (self.operation)(link) {
            Ok(value) => {
                self.deliver(Ok(value));
                Outcome::Done
            }
            Err(error) => {
                let outcome = outcome_of(categorize(&error));
                let retry = matches!(outcome, Some(Outcome::Lost { retry: true, .. }));
                if !retry || last_attempt {
                    let dc = link.state.dc.clone();
                    self.pending = Some(Failure::Ldap { dc, error });
                }
                outcome.unwrap_or(Outcome::Done)
            }
        }
    }

    fn settle(&mut self) {
        if let Some(failure) = self.pending.take() {
            self.deliver(Err(failure));
        }
    }

    fn fail(&mut self, failure: ConnectFailure) {
        self.deliver(Err(Failure::Connect(failure)));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::error::code;
    use crate::session::{
        Attributes, Control, Entry, Modification, MsgId, Response, ResultKind, SearchItem,
    };

    /// Test DCs: who answers, what the RootDSE says, how many sessions were opened.
    #[derive(Default)]
    pub(crate) struct World {
        pub unreachable: Mutex<HashSet<String>>,
        /// SERVER_DOWN on the next search.
        pub fall_next: Mutex<HashSet<String>>,
        pub dials: AtomicUsize,
        pub ssf: Mutex<u32>,
        pub objects: Mutex<HashMap<String, Attributes>>,
    }

    pub(crate) struct FakeSession {
        dc: String,
        world: Arc<World>,
        answers: HashMap<MsgId, Result<Response, LdapError>>,
        next: MsgId,
    }

    impl Session for FakeSession {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn search(&mut self, request: SearchRequest) -> Result<MsgId, LdapError> {
            if lock(&self.world.fall_next).remove(&self.dc) {
                return Err(LdapError::server_down(""));
            }
            self.next += 1;
            let answer = if request.base.is_empty() {
                Ok(vec![SearchItem::Entry(Entry {
                    dn: String::new(),
                    attributes: vec![
                        (
                            "defaultNamingContext".into(),
                            vec![b"DC=lab,DC=test".to_vec()],
                        ),
                        (
                            "dnsHostName".into(),
                            vec![self.dc.to_uppercase().into_bytes()],
                        ),
                    ],
                })])
            } else {
                match lock(&self.world.objects).get(&request.base) {
                    Some(a) => Ok(vec![SearchItem::Entry(Entry {
                        dn: request.base.clone(),
                        attributes: a.clone(),
                    })]),
                    None => Err(LdapError::new(code::NO_SUCH_OBJECT, "")),
                }
            };
            self.answers.insert(
                self.next,
                answer.map(|items| Response {
                    kind: ResultKind::Search,
                    items,
                    controls: Vec::new(),
                }),
            );
            Ok(self.next)
        }
        fn modify(
            &mut self,
            _: &str,
            _: Vec<Modification>,
            _: Vec<Control>,
        ) -> Result<MsgId, LdapError> {
            unimplemented!()
        }
        fn add(&mut self, _: &str, _: Attributes, _: Vec<Control>) -> Result<MsgId, LdapError> {
            unimplemented!()
        }
        fn delete(&mut self, _: &str, _: Vec<Control>) -> Result<MsgId, LdapError> {
            unimplemented!()
        }
        fn rename(
            &mut self,
            _: &str,
            _: &str,
            _: Option<&str>,
            _: bool,
            _: Vec<Control>,
        ) -> Result<MsgId, LdapError> {
            unimplemented!()
        }
        fn result(&mut self, id: MsgId, _: Option<Duration>) -> Result<Response, LdapError> {
            self.answers.remove(&id).expect("pending")
        }
        fn abandon(&mut self, _: MsgId) -> Result<(), LdapError> {
            Ok(())
        }
        fn whoami(&mut self, _: Option<Duration>) -> Result<String, LdapError> {
            Ok("u:LAB\\Administrator".into())
        }
        fn unbind(&mut self) {}
    }

    pub(crate) struct FakeDialer(pub Arc<World>);

    impl Dialer for FakeDialer {
        fn dial(&self, dc: &str) -> Result<(Box<dyn Session>, bool, u32), LdapError> {
            self.0.dials.fetch_add(1, Ordering::Relaxed);
            if lock(&self.0.unreachable).contains(dc) {
                return Err(LdapError::server_down(""));
            }
            let session = FakeSession {
                dc: dc.to_owned(),
                world: self.0.clone(),
                answers: HashMap::new(),
                next: 0,
            };
            Ok((Box::new(session), false, *lock(&self.0.ssf)))
        }
    }

    pub(crate) struct FakeResolver {
        pub dcs: Option<Vec<String>>,
        pub pdc: Option<String>,
    }

    impl Resolver for FakeResolver {
        fn dcs(&self, _: &str) -> Result<Vec<String>, ResolveError> {
            self.dcs.clone().ok_or(ResolveError {
                unreachable: false,
                detail: "no DC".into(),
                origin: None,
            })
        }
        fn pdc(&self, _: &str) -> Result<Option<String>, ResolveError> {
            Ok(self.pdc.clone())
        }
    }

    fn strings(names: &[&str]) -> Vec<String> {
        names.iter().map(|&n| n.to_owned()).collect()
    }

    pub(crate) fn connection(
        world: &Arc<World>,
        preferred: Option<&str>,
        dcs: Option<&[&str]>,
        pdc: Option<&str>,
        to_pdc: bool,
    ) -> Connection {
        {
            let mut ssf = lock(&world.ssf);
            *ssf = (*ssf).max(256);
        }
        let mut profile = Profile::new("lab.test");
        profile.preferred_dc = preferred.map(str::to_owned);
        Connection::new(
            profile,
            Delays::default(),
            to_pdc,
            Box::new(FakeDialer(world.clone())),
            Box::new(FakeResolver {
                dcs: dcs.map(strings),
                pdc: pdc.map(str::to_owned),
            }),
        )
    }

    fn read(c: &Connection, dn: &'static str) -> Result<String, Failure> {
        c.run(true, move |link| {
            let request = SearchRequest {
                base: dn.into(),
                scope: Scope::Base,
                filter: "(objectClass=*)".into(),
                attributes: vec!["cn".into()],
                controls: Vec::new(),
                size_limit: 0,
            };
            link.session.search_wait(request, None)?;
            Ok(link.state.dc.clone())
        })
    }

    #[test]
    fn binds_and_reads_root_dse() {
        let world = Arc::new(World::default());
        let c = connection(
            &world,
            None,
            Some(&["dc1.lab.test", "dc2.lab.test"]),
            None,
            false,
        );
        let state = c.run(true, |link| Ok(link.state.clone())).unwrap();
        assert_eq!(state.dc, "dc1.lab.test");
        assert_eq!(state.root_dse.dns_host_name, "dc1.lab.test");
        assert!(state.encrypted() && state.generation == 1);
        assert_eq!(c.state().unwrap().dc, "dc1.lab.test");
        c.join();
        assert!(c.run(true, |_| Ok(())).is_err());
    }

    #[test]
    fn in_chain_searches_wait_longer() {
        let world = Arc::new(World::default());
        let c = connection(&world, None, Some(&["dc1.lab.test"]), None, false);
        let in_chain = "(memberOf:1.2.840.113556.1.4.1941:=CN=G,DC=lab,DC=test)";
        let (chain, plain) = c
            .run(true, move |link| {
                Ok((link.timeout_for(in_chain), link.timeout_for("(cn=a)")))
            })
            .unwrap();
        assert_eq!(chain, Delays::default().chain);
        assert_eq!(plain, Delays::default().operation);
        assert!(chain > plain);
        c.join();
    }

    #[test]
    fn fails_over_to_the_next_dc() {
        let world = Arc::new(World::default());
        lock(&world.unreachable).insert("dc1.lab.test".into());
        let c = connection(
            &world,
            None,
            Some(&["dc1.lab.test", "dc2.lab.test"]),
            None,
            false,
        );
        lock(&world.objects).insert("CN=x".into(), Vec::new());
        assert_eq!(read(&c, "CN=x").unwrap(), "dc2.lab.test");
        // dc2 falls during a read: replayed on dc1, back again; dc2 goes last.
        lock(&world.unreachable).clear();
        lock(&world.fall_next).insert("dc2.lab.test".into());
        assert_eq!(read(&c, "CN=x").unwrap(), "dc1.lab.test");
        assert_eq!(
            c.candidates().unwrap(),
            strings(&["dc1.lab.test", "dc2.lab.test"])
        );
        // An LDAP error is delivered as it is, without failover.
        match read(&c, "CN=absent") {
            Err(Failure::Ldap { dc, error }) => {
                assert_eq!(
                    (dc.as_str(), error.code),
                    ("dc1.lab.test", code::NO_SUCH_OBJECT)
                );
            }
            other => panic!("{other:?}"),
        }
        c.join();
    }

    #[test]
    fn no_dc_answers() {
        let world = Arc::new(World::default());
        lock(&world.unreachable).extend(strings(&["dc1.lab.test", "dc2.lab.test"]));
        let c = connection(
            &world,
            None,
            Some(&["dc1.lab.test", "dc2.lab.test"]),
            None,
            false,
        );
        match c.run(true, |_| Ok(())) {
            Err(Failure::Connect(ConnectFailure::NoDc { failures, .. })) => {
                assert_eq!(failures.len(), 2);
            }
            other => panic!("{other:?}"),
        }
        c.join();
    }

    #[test]
    fn weak_layer_is_refused() {
        let world = Arc::new(World::default());
        let c = connection(&world, Some("dc1.lab.test"), None, None, false);
        *lock(&world.ssf) = 1;
        assert!(matches!(
            c.run(true, |_| Ok(())),
            Err(Failure::Connect(ConnectFailure::NotEncrypted {
                ssf: 1,
                ..
            }))
        ));
        c.join();
    }

    #[test]
    fn order_of_the_candidates() {
        let world = Arc::new(World::default());
        let all = ["dc1.lab.test", "dc2.lab.test"];
        let c = connection(&world, Some("dc2.lab.test"), Some(&all), None, false);
        assert_eq!(
            c.candidates().unwrap(),
            strings(&["dc2.lab.test", "dc1.lab.test"])
        );
        // A write goes to the PDC first, the preferred DC next.
        let w = connection(
            &world,
            Some("dc2.lab.test"),
            Some(&all),
            Some("dc1.lab.test"),
            true,
        );
        assert_eq!(
            w.candidates().unwrap(),
            strings(&["dc1.lab.test", "dc2.lab.test"])
        );
        // Without SRV records for the DCs, the PDC suffices; without any, the error.
        let p = connection(&world, None, None, Some("dc1.lab.test"), true);
        assert_eq!(p.candidates().unwrap(), strings(&["dc1.lab.test"]));
        assert!(
            connection(&world, None, None, None, false)
                .candidates()
                .is_err()
        );
        // The DC imposed on writes, alone.
        let mut profile = Profile::new("lab.test");
        profile.write_dc = Some("dc3.lab.test".into());
        let imposed = Connection::new(
            profile,
            Delays::default(),
            true,
            Box::new(FakeDialer(world.clone())),
            Box::new(FakeResolver {
                dcs: Some(strings(&all)),
                pdc: None,
            }),
        );
        assert_eq!(imposed.candidates().unwrap(), strings(&["dc3.lab.test"]));
    }
}

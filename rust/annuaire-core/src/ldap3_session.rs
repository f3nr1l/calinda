// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The [`Session`] on the `ldap3` crate: GSSAPI bind (sealed, or over LDAPS / StartTLS with
//! the domain CA and channel binding), requests run as tokio tasks.
//!
//! One tokio runtime with two worker threads carries every connection of the process; the
//! thread of a connection waits for an answer with `block_on` (ADR 0016, § 3).

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ldap3::asn1::{PL, StructureTag};
use ldap3::controls::RawControl;
use ldap3::{Ldap, LdapConnAsync, LdapConnSettings, Mod, SearchOptions};
use tokio::runtime::Runtime;
use tokio::task::JoinHandle;

use crate::error::{LdapError, code};
use crate::profile::{Delays, Mode, Profile};
use crate::session::{
    Attributes, Control, Entry, Modification, MsgId, Response, ResultKind, SearchItem,
    SearchRequest, Session,
};

/// SSF reported for the Kerberos confidentiality layer: what cyrus-sasl reports on these
/// DCs (ADR 0016, "Faisabilité"). `ldap3` requires that layer or fails the bind.
pub const SEALED_SSF: u32 = 256;

/// The runtime shared by every connection.
pub fn runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("annuaire-ldap")
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// Error of `ldap3` while a request runs.
fn operation_error(error: ldap3::LdapError) -> LdapError {
    use ldap3::LdapError as E;
    match error {
        E::Timeout { .. } => LdapError::timeout(),
        E::FilterParsing => LdapError::new(code::FILTER_ERROR, ""),
        E::LdapResult { result } => result_error(&result),
        E::Io { source } => LdapError::server_down(source.to_string()),
        e @ (E::OpSend { .. } | E::ResultRecv { .. } | E::IdScrubSend { .. } | E::EndOfStream) => {
            LdapError::server_down(e.to_string())
        }
        E::NativeTLS { source } => LdapError::new(code::CONNECT_ERROR, source.to_string()),
        E::GssapiOperationError(message) => LdapError::gssapi(&message),
        e @ E::NoGssapiToken => LdapError::gssapi(&e.to_string()),
        E::DecodingUTF8 => LdapError::new(code::DECODING_ERROR, "utf8 decoding error"),
        e => LdapError::new(code::LOCAL_ERROR, e.to_string()),
    }
}

/// Error while connecting: a timeout means the DC is silent, not that an operation was slow.
fn connect_error(error: ldap3::LdapError) -> LdapError {
    match error {
        ldap3::LdapError::Timeout { elapsed } => {
            LdapError::server_down(format!("connection timeout ({elapsed})"))
        }
        e => operation_error(e),
    }
}

fn result_error(result: &ldap3::LdapResult) -> LdapError {
    let mut e = LdapError::new(
        i32::try_from(result.rc).unwrap_or(code::OTHER),
        &result.text,
    );
    e.matched.clone_from(&result.matched);
    e
}

fn check(result: ldap3::LdapResult) -> Result<ldap3::LdapResult, LdapError> {
    if result.rc == 0 {
        Ok(result)
    } else {
        Err(result_error(&result))
    }
}

fn raw_controls(controls: Vec<Control>) -> Vec<RawControl> {
    controls
        .into_iter()
        .map(|c| RawControl {
            ctype: c.oid,
            crit: c.critical,
            val: c.value,
        })
        .collect()
}

fn response_controls(result: &ldap3::LdapResult) -> Vec<Control> {
    result
        .ctrls
        .iter()
        .map(|c| Control {
            oid: c.1.ctype.clone(),
            critical: c.1.crit,
            value: c.1.val.clone(),
        })
        .collect()
}

fn primitive(tag: &StructureTag) -> Option<&[u8]> {
    match &tag.payload {
        PL::P(bytes) => Some(bytes),
        PL::C(_) => None,
    }
}

fn constructed(tag: &StructureTag) -> Option<&[StructureTag]> {
    match &tag.payload {
        PL::C(tags) => Some(tags),
        PL::P(_) => None,
    }
}

/// A `SearchResultEntry` (RFC 4511, 4.5.2) with its raw values, attributes in the order of
/// the server. `ldap3::SearchEntry` is not used: it splits the values by UTF-8 validity
/// into two maps and panics on malformed data.
pub fn decode_entry(tag: &StructureTag) -> Result<Entry, LdapError> {
    let malformed = || LdapError::new(code::DECODING_ERROR, "malformed search entry");
    let parts = constructed(tag).ok_or_else(malformed)?;
    let [dn, attributes] = parts else {
        return Err(malformed());
    };
    let dn = String::from_utf8(primitive(dn).ok_or_else(malformed)?.to_vec())
        .map_err(|_| malformed())?;
    let mut decoded: Attributes = Vec::new();
    for attribute in constructed(attributes).ok_or_else(malformed)? {
        let [name, values] = constructed(attribute).ok_or_else(malformed)? else {
            return Err(malformed());
        };
        let name = String::from_utf8(primitive(name).ok_or_else(malformed)?.to_vec())
            .map_err(|_| malformed())?;
        let values = constructed(values)
            .ok_or_else(malformed)?
            .iter()
            .map(|v| primitive(v).map(<[u8]>::to_vec).ok_or_else(malformed))
            .collect::<Result<Vec<_>, _>>()?;
        decoded.push((name, values));
    }
    Ok(Entry {
        dn,
        attributes: decoded,
    })
}

type Pending = JoinHandle<Result<Response, LdapError>>;

struct Shared {
    ldap: Ldap,
    pending: Mutex<HashMap<MsgId, Pending>>,
    next: AtomicI32,
}

/// A session bound with `ldap3`. Cheap to clone: the clones share the connection and the
/// requests in flight (the Python `LdapObject` keeps one).
#[derive(Clone)]
pub struct Ldap3Session {
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Ldap3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ldap3Session").finish_non_exhaustive()
    }
}

impl Ldap3Session {
    fn spawn<F>(&self, task: F) -> MsgId
    where
        F: Future<Output = Result<Response, LdapError>> + Send + 'static,
    {
        let id = self.shared.next.fetch_add(1, Ordering::Relaxed);
        let handle = runtime().spawn(task);
        self.pending().insert(id, handle);
        id
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<MsgId, Pending>> {
        self.shared
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn handle(&self) -> Ldap {
        self.shared.ldap.clone()
    }
}

fn done(kind: ResultKind, result: ldap3::LdapResult) -> Result<Response, LdapError> {
    let result = check(result)?;
    Ok(Response {
        kind,
        items: Vec::new(),
        controls: response_controls(&result),
    })
}

impl Session for Ldap3Session {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn search(&mut self, request: SearchRequest) -> Result<MsgId, LdapError> {
        let mut ldap = self.handle();
        Ok(self.spawn(async move {
            let scope = match request.scope {
                crate::session::Scope::Base => ldap3::Scope::Base,
                crate::session::Scope::OneLevel => ldap3::Scope::OneLevel,
                crate::session::Scope::Subtree => ldap3::Scope::Subtree,
            };
            let result = ldap
                .with_controls(raw_controls(request.controls))
                .with_search_options(SearchOptions::new().sizelimit(request.size_limit))
                .search(&request.base, scope, &request.filter, request.attributes)
                .await
                .map_err(operation_error)?;
            let ldap3::SearchResult(entries, result) = result;
            let result = check(result)?;
            let mut items = Vec::with_capacity(entries.len() + result.refs.len());
            for entry in &entries {
                items.push(SearchItem::Entry(decode_entry(&entry.0)?));
            }
            if !result.refs.is_empty() {
                items.push(SearchItem::Reference(result.refs.clone()));
            }
            Ok(Response {
                kind: ResultKind::Search,
                items,
                controls: response_controls(&result),
            })
        }))
    }

    fn modify(
        &mut self,
        dn: &str,
        changes: Vec<Modification>,
        controls: Vec<Control>,
    ) -> Result<MsgId, LdapError> {
        let mut ldap = self.handle();
        let dn = dn.to_owned();
        let mods: Vec<Mod<Vec<u8>>> = changes
            .into_iter()
            .map(|m| match m {
                Modification::Add(a, v) => Mod::Add(a.into_bytes(), v.into_iter().collect()),
                Modification::Delete(a, v) => Mod::Delete(a.into_bytes(), v.into_iter().collect()),
                Modification::Replace(a, v) => {
                    Mod::Replace(a.into_bytes(), v.into_iter().collect())
                }
            })
            .collect();
        Ok(self.spawn(async move {
            let result = ldap
                .with_controls(raw_controls(controls))
                .modify(&dn, mods)
                .await
                .map_err(operation_error)?;
            done(ResultKind::Modify, result)
        }))
    }

    fn add(
        &mut self,
        dn: &str,
        attributes: Attributes,
        controls: Vec<Control>,
    ) -> Result<MsgId, LdapError> {
        let mut ldap = self.handle();
        let dn = dn.to_owned();
        let attributes: Vec<(Vec<u8>, std::collections::HashSet<Vec<u8>>)> = attributes
            .into_iter()
            .map(|(a, v)| (a.into_bytes(), v.into_iter().collect()))
            .collect();
        Ok(self.spawn(async move {
            let result = ldap
                .with_controls(raw_controls(controls))
                .add(&dn, attributes)
                .await
                .map_err(operation_error)?;
            done(ResultKind::Add, result)
        }))
    }

    fn delete(&mut self, dn: &str, controls: Vec<Control>) -> Result<MsgId, LdapError> {
        let mut ldap = self.handle();
        let dn = dn.to_owned();
        Ok(self.spawn(async move {
            let result = ldap
                .with_controls(raw_controls(controls))
                .delete(&dn)
                .await
                .map_err(operation_error)?;
            done(ResultKind::Delete, result)
        }))
    }

    fn rename(
        &mut self,
        dn: &str,
        new_rdn: &str,
        new_superior: Option<&str>,
        delete_old: bool,
        controls: Vec<Control>,
    ) -> Result<MsgId, LdapError> {
        let mut ldap = self.handle();
        let (dn, rdn) = (dn.to_owned(), new_rdn.to_owned());
        let superior = new_superior.map(str::to_owned);
        Ok(self.spawn(async move {
            let result = ldap
                .with_controls(raw_controls(controls))
                .modifydn(&dn, &rdn, delete_old, superior.as_deref())
                .await
                .map_err(operation_error)?;
            done(ResultKind::Rename, result)
        }))
    }

    fn result(&mut self, id: MsgId, timeout: Option<Duration>) -> Result<Response, LdapError> {
        let Some(mut handle) = self.pending().remove(&id) else {
            return Err(LdapError::new(
                code::PARAM_ERROR,
                format!("no request {id} in flight"),
            ));
        };
        let outcome = runtime().block_on(async {
            match timeout {
                Some(t) => tokio::time::timeout(t, &mut handle).await.ok(),
                None => Some((&mut handle).await),
            }
        });
        match outcome {
            None => {
                handle.abort();
                Err(LdapError::timeout())
            }
            Some(Ok(result)) => result,
            Some(Err(e)) => Err(LdapError::new(code::LOCAL_ERROR, e.to_string())),
        }
    }

    fn abandon(&mut self, id: MsgId) -> Result<(), LdapError> {
        if let Some(handle) = self.pending().remove(&id) {
            handle.abort();
        }
        Ok(())
    }

    fn whoami(&mut self, timeout: Option<Duration>) -> Result<String, LdapError> {
        let mut ldap = self.handle();
        if let Some(t) = timeout {
            ldap.with_timeout(t);
        }
        let result = runtime()
            .block_on(ldap.extended(ldap3::exop::WhoAmI))
            .map_err(operation_error)?;
        let ldap3::result::ExopResult(exop, result) = result;
        check(result)?;
        Ok(String::from_utf8_lossy(&exop.val.unwrap_or_default()).into_owned())
    }

    fn unbind(&mut self) {
        for (_, handle) in self.pending().drain() {
            handle.abort();
        }
        let mut ldap = self.handle();
        let _ = runtime()
            .block_on(async { tokio::time::timeout(Duration::from_secs(2), ldap.unbind()).await });
    }
}

/// The certificates of a PEM file, one block each: like `OPT_X_TLS_CACERTFILE`, a file may
/// hold several CAs (Samba generates one per DC). `Certificate::from_pem` reads the first.
pub fn pem_certificates(pem: &[u8]) -> Vec<&[u8]> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let find =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).position(|w| w == needle);
    let mut blocks = Vec::new();
    let mut rest = pem;
    while let Some(start) = find(rest, BEGIN) {
        let Some(tail) = rest.get(start..) else { break };
        let Some(end) = find(tail, END) else { break };
        let Some(block) = tail.get(..end + END.len()) else {
            break;
        };
        blocks.push(block);
        rest = tail.get(end + END.len()..).unwrap_or_default();
    }
    blocks
}

/// Opens bound sessions with the DCs of a profile.
#[derive(Debug, Clone)]
pub struct Ldap3Dialer {
    pub profile: Profile,
    pub delays: Delays,
}

/// A bound session and what the bind established.
#[derive(Debug)]
pub struct Dialed {
    pub session: Ldap3Session,
    pub tls: bool,
    pub ssf: u32,
}

impl Ldap3Dialer {
    /// Connects to `dc`, protects the connection as the profile says and binds by GSSAPI
    /// with the ticket cache of the session.
    pub fn connect(&self, dc: &str) -> Result<Dialed, LdapError> {
        let mode = self.profile.mode;
        let mut settings = LdapConnSettings::new().set_conn_timeout(self.delays.connect);
        if mode.tls() {
            let Some(ca) = &self.profile.ca else {
                return Err(LdapError::new(
                    code::CONNECT_ERROR,
                    "TLS mode without a CA certificate",
                ));
            };
            let pem = std::fs::read(ca).map_err(|e| {
                LdapError::new(code::CONNECT_ERROR, format!("CA certificate {ca:?}: {e}"))
            })?;
            let certificates = pem_certificates(&pem);
            if certificates.is_empty() {
                return Err(LdapError::new(
                    code::CONNECT_ERROR,
                    format!("CA certificate {ca:?}: no certificate"),
                ));
            }
            let mut builder = native_tls::TlsConnector::builder();
            builder.disable_built_in_roots(true);
            for block in certificates {
                let certificate = native_tls::Certificate::from_pem(block).map_err(|e| {
                    LdapError::new(code::CONNECT_ERROR, format!("CA certificate {ca:?}: {e}"))
                })?;
                builder.add_root_certificate(certificate);
            }
            let connector = builder
                .build()
                .map_err(|e| LdapError::new(code::CONNECT_ERROR, e.to_string()))?;
            settings = settings
                .set_connector(connector)
                .set_starttls(mode == Mode::StartTls);
        }
        let scheme = if mode == Mode::Ldaps { "ldaps" } else { "ldap" };
        let url = format!("{scheme}://{dc}:{}", mode.port());
        // `ldap/<dc>@<REALM>`: a Kerberos name, never canonicalized (ADR 0016).
        let service = format!("{dc}@{}", self.profile.realm());
        let operation = self.delays.operation;
        let ldap = runtime().block_on(async move {
            let (connection, mut ldap) = LdapConnAsync::with_settings(settings, &url)
                .await
                .map_err(connect_error)?;
            tokio::spawn(async move {
                let _ = connection.drive().await;
            });
            let result = ldap
                .with_timeout(operation)
                .sasl_gssapi_bind(&service)
                .await
                .map_err(operation_error)?;
            check(result)?;
            Ok::<Ldap, LdapError>(ldap)
        })?;
        Ok(Dialed {
            session: Ldap3Session {
                shared: Arc::new(Shared {
                    ldap,
                    pending: Mutex::new(HashMap::new()),
                    next: AtomicI32::new(1),
                }),
            },
            tls: mode.tls(),
            ssf: if mode.tls() { 0 } else { SEALED_SSF },
        })
    }
}

impl crate::connection::Dialer for Ldap3Dialer {
    fn dial(&self, dc: &str) -> Result<(Box<dyn Session>, bool, u32), LdapError> {
        let dialed = self.connect(dc)?;
        Ok((Box::new(dialed.session), dialed.tls, dialed.ssf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_a_pem_bundle() {
        let bundle = b"junk\n-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\
-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n";
        let blocks = pem_certificates(bundle);
        assert_eq!(blocks.len(), 2);
        assert!(blocks[1].starts_with(b"-----BEGIN") && blocks[1].ends_with(b"CERTIFICATE-----"));
        assert!(pem_certificates(b"nothing").is_empty());
    }
}

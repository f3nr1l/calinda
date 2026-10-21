// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A bound LDAP session with one domain controller.
//!
//! The model is the one of python-ldap, which the rest of the core is written against
//! (ADR 0016, § 3): a request is sent and gets an identifier, its result is awaited later,
//! several requests may be in flight (`Rafale`: one round trip for many reads).

use std::time::Duration;

use crate::error::LdapError;

/// Identifier of a request in flight on a session.
pub type MsgId = i32;

/// Search scope (protocol values, RFC 4511).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Scope {
    Base = 0,
    OneLevel = 1,
    Subtree = 2,
}

impl Scope {
    pub fn from_i64(value: i64) -> Option<Self> {
        match value {
            0 => Some(Self::Base),
            1 => Some(Self::OneLevel),
            2 => Some(Self::Subtree),
            _ => None,
        }
    }
}

/// A request or response control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Control {
    pub oid: String,
    pub critical: bool,
    pub value: Option<Vec<u8>>,
}

/// Raw attributes of an entry, in the order of the server, values as bytes.
pub type Attributes = Vec<(String, Vec<Vec<u8>>)>;

/// One object returned by a search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub dn: String,
    pub attributes: Attributes,
}

impl Entry {
    /// Values of an attribute, name compared without case; empty if absent.
    pub fn values(&self, name: &str) -> &[Vec<u8>] {
        self.attributes
            .iter()
            .find(|(n, _)| n == name)
            .or_else(|| {
                self.attributes
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case(name))
            })
            .map_or(&[], |(_, v)| v.as_slice())
    }
}

/// An element of a search result: an entry or a continuation reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SearchItem {
    Entry(Entry),
    Reference(Vec<String>),
}

/// Kind of a result, with the message type python-ldap returns from `result3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultKind {
    Search = 101,
    Modify = 103,
    Add = 105,
    Delete = 107,
    Rename = 109,
}

/// The complete answer to a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub kind: ResultKind,
    pub items: Vec<SearchItem>,
    pub controls: Vec<Control>,
}

impl Response {
    /// The entries of a search result, continuation references left out.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.items.iter().filter_map(|i| match i {
            SearchItem::Entry(e) => Some(e),
            SearchItem::Reference(_) => None,
        })
    }

    pub fn into_entries(self) -> Vec<Entry> {
        self.items
            .into_iter()
            .filter_map(|i| match i {
                SearchItem::Entry(e) => Some(e),
                SearchItem::Reference(_) => None,
            })
            .collect()
    }

    /// The response control of this type, if the server sent it.
    pub fn control(&self, oid: &str) -> Option<&Control> {
        self.controls.iter().find(|c| c.oid == oid)
    }
}

/// One change of a modify request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modification {
    Add(String, Vec<Vec<u8>>),
    /// No value: delete the attribute.
    Delete(String, Vec<Vec<u8>>),
    Replace(String, Vec<Vec<u8>>),
}

/// A search request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRequest {
    pub base: String,
    pub scope: Scope,
    pub filter: String,
    pub attributes: Vec<String>,
    pub controls: Vec<Control>,
    /// 0: no limit.
    pub size_limit: i32,
}

/// A bound session with one DC. Every method returns at once except `result` and
/// `whoami`, which wait for the server.
pub trait Session: Send {
    /// The concrete session (the Python module gives Python operations the object behind it).
    fn as_any(&self) -> &dyn std::any::Any;
    fn search(&mut self, request: SearchRequest) -> Result<MsgId, LdapError>;
    fn modify(
        &mut self,
        dn: &str,
        changes: Vec<Modification>,
        controls: Vec<Control>,
    ) -> Result<MsgId, LdapError>;
    fn add(
        &mut self,
        dn: &str,
        attributes: Attributes,
        controls: Vec<Control>,
    ) -> Result<MsgId, LdapError>;
    fn delete(&mut self, dn: &str, controls: Vec<Control>) -> Result<MsgId, LdapError>;
    fn rename(
        &mut self,
        dn: &str,
        new_rdn: &str,
        new_superior: Option<&str>,
        delete_old: bool,
        controls: Vec<Control>,
    ) -> Result<MsgId, LdapError>;
    /// Waits for the complete answer to `id`; an LDAP result other than success is an
    /// error. Past `timeout`, the request is abandoned and `TIMEOUT` returned.
    fn result(&mut self, id: MsgId, timeout: Option<Duration>) -> Result<Response, LdapError>;
    fn abandon(&mut self, id: MsgId) -> Result<(), LdapError>;
    /// Identity bound (`u:DOMAIN\user`).
    fn whoami(&mut self, timeout: Option<Duration>) -> Result<String, LdapError>;
    /// Closes the session; errors are ignored.
    fn unbind(&mut self);

    /// Sends a search and waits for its answer.
    fn search_wait(
        &mut self,
        request: SearchRequest,
        timeout: Option<Duration>,
    ) -> Result<Response, LdapError> {
        let id = self.search(request)?;
        self.result(id, timeout)
    }
}

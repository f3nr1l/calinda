// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Core of Annuaire: connection to the domain controllers of an Active Directory domain,
//! paged searches, object model, changesets and journal (R2), and the SYSVOL over SMB (R3).
//!
//! Rust port of the corresponding modules of `annuaire/core/` of the Python version 1.0 (plan,
//! steps R2 to R4; ADR 0016, 0017 and 0019). The lab tests are `tests/labo_*.rs` (ADR 0020).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod actions;
#[cfg(feature = "gpo-content")]
pub mod admx;
#[cfg(feature = "gpo-content")]
pub mod admx_store;
#[cfg(feature = "local-copy")]
pub mod cache;
pub mod changes;
pub mod connection;
pub mod dn;
pub mod dns;
pub mod dns_health;
pub mod dns_write;
pub mod error;
pub mod gpo;
#[cfg(feature = "gpo-backup")]
pub mod gpo_backup;
#[cfg(feature = "gpo-content")]
pub mod gpo_content;
#[cfg(feature = "gpo-content")]
pub mod gpo_preferences;
pub mod gpo_write;
#[cfg(feature = "gpo-content")]
pub mod gpp;
pub mod journal;
pub mod kerberos;
pub mod ldap3_session;
pub mod membership;
pub mod messages;
pub mod model;
#[cfg(feature = "gpo-content")]
pub mod policies;
pub mod profile;
pub mod pso;
pub mod queries;
pub mod reread;
pub mod rootdse;
pub mod schema;
pub mod search;
pub mod security;
#[cfg(feature = "gpo-content")]
pub mod security_policy;
pub mod session;
pub mod smb;
pub mod source;
#[cfg(feature = "local-copy")]
pub mod sql_filter;
pub mod srv;
pub mod storage;
#[cfg(feature = "local-copy")]
pub mod store;
#[cfg(feature = "local-copy")]
pub mod sync;
pub mod sysvol;
pub mod sysvol_write;
pub mod writer;
#[cfg(feature = "gpo-content")]
pub mod xml;

pub use connection::{Connection, Link, State};
pub use error::{Category, LdapError, categorize};
pub use profile::{Delays, Mode, Profile};

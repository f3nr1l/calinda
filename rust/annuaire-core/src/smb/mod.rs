// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A reduced SMB 2/3 client: what the SYSVOL needs, Kerberos on the credential cache,
//! signing and SMB 3 encryption, compound requests in batches (ADR 0017).

pub mod auth;
pub mod client;
pub mod crypto;
#[cfg(test)]
pub(crate) mod fake_server;
pub mod msg;
pub mod pipe;
pub mod spnego;
mod wire;

pub use auth::{AuthError, Authenticator, Kerberos};
pub use client::{Client, ErrorKind, Negotiated, Options, Response, SmbError};

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Pure codecs for the formats of Active Directory: bytes ⇄ structures ⇄ bytes.
//!
//! Rust port of `annuaire/core/codecs/` of the Python version 1.0 (plan, step R1). Standard
//! library only, no I/O. Every codec reads the shared vectors of `tests/vecteurs/` and gives
//! back the same bytes as the Python implementation did (differential tests until the switch,
//! ADR 0020). Errors are typed per codec.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod condition;
pub mod dns_property;
pub mod dns_record;
pub mod extensions;
pub mod gplink;
pub mod gpt_tmpl;
pub mod guid;
pub mod integer;
mod pytext;
mod read;
pub mod registry_pol;
pub mod sd;
pub mod sddl;
pub mod sid;
pub mod time;
pub mod uac;

pub use guid::{Guid, GuidError};
pub use sid::{Sid, SidError};

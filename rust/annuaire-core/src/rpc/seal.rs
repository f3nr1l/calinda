// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Sealing of DCE/RPC PDUs under packet privacy (C706 13.2.6, MS-RPCE 3.3.4.2). The GSS
//! mechanism does the cryptography; here is only the DCE layout it expects. A sealed PDU is
//!
//! ```text
//! [ common header 16 ] [ body ] [ pad ] [ sec-trailer head 8 ] [ GSS token ]
//! ```
//!
//! and `gss_wrap_iov` in DCE style takes the buffers as `SIGN_ONLY | DATA | SIGN_ONLY | HEADER`:
//! the common header and the sec-trailer head are signed but left in clear, the body (with its
//! padding to a 16-byte boundary) is the DATA encrypted in place, and the token it produces
//! goes after the sec-trailer head. The body carries a response/request header of its own; the
//! caller keeps or strips those bytes.

use libgssapi::context::SecurityContext;
use libgssapi::error::{Error as GssError, MajorFlags};
use libgssapi::util::{GssIov, GssIovFake, GssIovType};

use super::authn::{SEC_TRAILER_HEAD, SecTrailer};
use super::{PFC_FIRST_FRAG, PFC_LAST_FRAG, ptype};

/// The request/response header between the common header and the encrypted stub (alloc_hint,
/// presentation context, opnum/cancel): signed in clear, not encrypted (MS-RPCE 3.3.4.2.3).
const PREFIX_LEN: usize = 8;

const HEADER_LEN: usize = 16;
/// AES block size: the DATA buffer is padded up to a multiple of it before sealing.
const BLOCK: usize = 16;
/// Little-endian, ASCII, IEEE — the data representation of every PDU here.
const DREP: [u8; 4] = [0x10, 0, 0, 0];

/// Bytes of padding to add to a body of `body_len` so the sealed DATA is block-aligned.
fn pad_len(body_len: usize) -> usize {
    (BLOCK - body_len % BLOCK) % BLOCK
}

/// The 16-byte common header (C706 12.6.1): version 5.0, `ptype`, `flags`, the data
/// representation, `frag_length`, `auth_length`, and `call_id`.
fn common_header(ptype: u8, flags: u8, call_id: u32, frag: u16, auth: u16) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0] = 5;
    h[2] = ptype;
    h[3] = flags;
    h[4..8].copy_from_slice(&DREP);
    h[8..10].copy_from_slice(&frag.to_le_bytes());
    h[10..12].copy_from_slice(&auth.to_le_bytes());
    h[12..16].copy_from_slice(&call_id.to_le_bytes());
    h
}

/// The 8-byte head of the security trailer, without the token.
fn trailer_head(auth_type: u8, pad: u8, context_id: u32) -> [u8; SEC_TRAILER_HEAD] {
    let mut t = [0u8; SEC_TRAILER_HEAD];
    t[0] = auth_type;
    t[1] = super::authn::AUTH_LEVEL_PKT_PRIVACY;
    t[2] = pad;
    t[4..8].copy_from_slice(&context_id.to_le_bytes());
    t
}

/// Asks the mechanism how long the token of a sealed PDU of this shape will be, so the header
/// can carry the right `auth_length` before the signed region is frozen. `signed` is the whole
/// clear SIGN_ONLY region (common header and the request/response header).
/// The buffer type for the clear header and trailer: included in the integrity when header
/// signing was negotiated (`sign_only`), otherwise left out (`empty`), as the reference client.
fn clear_type(sign_header: bool) -> GssIovType {
    if sign_header {
        GssIovType::SignOnly
    } else {
        GssIovType::Empty
    }
}

fn token_len(
    ctx: &mut dyn SecurityContext,
    signed_len: usize,
    data_len: usize,
    trailer: &[u8; SEC_TRAILER_HEAD],
    sign_header: bool,
) -> Result<usize, GssError> {
    let clear = clear_type(sign_header);
    let mut s = vec![0u8; signed_len];
    let mut d = vec![0u8; data_len];
    let mut t = *trailer;
    let mut fakes = [
        GssIov::new(clear, &mut s[..]).as_fake(),
        GssIov::new(GssIovType::Data, &mut d[..]).as_fake(),
        GssIov::new(clear, &mut t[..]).as_fake(),
        GssIovFake::new(GssIovType::Header),
    ];
    ctx.wrap_iov_length(true, &mut fakes)?;
    Ok(fakes.last().map_or(0, GssIovFake::len))
}

/// Seals a request `stub` into a whole PDU under packet privacy. The 8-byte request header
/// (alloc_hint, presentation context, opnum) is built here and signed in clear with the common
/// header; only the stub (padded to a block) is encrypted. `auth_type` and `context_id` go in
/// the security trailer. Blocking only on the mechanism.
pub fn seal(
    ctx: &mut dyn SecurityContext,
    call_id: u32,
    context_id: u32,
    opnum: u16,
    stub: &[u8],
    auth_type: u8,
    sign_header: bool,
) -> Result<Vec<u8>, GssError> {
    let pad = pad_len(stub.len());
    let mut data = Vec::with_capacity(stub.len() + pad);
    data.extend_from_slice(stub);
    data.resize(stub.len() + pad, 0);

    // Request header, signed in clear: alloc_hint over the (padded) stub, presentation context,
    // opnum. alloc_hint carries the padded length, as the reference client sends it.
    let alloc_hint = u32::try_from(data.len()).unwrap_or(0);
    let mut prefix = [0u8; PREFIX_LEN];
    prefix[0..4].copy_from_slice(&alloc_hint.to_le_bytes());
    prefix[4..6].copy_from_slice(&context_id_as_u16(context_id).to_le_bytes());
    prefix[6..8].copy_from_slice(&opnum.to_le_bytes());

    let flags = PFC_FIRST_FRAG | PFC_LAST_FRAG;
    let signed_len = HEADER_LEN + PREFIX_LEN;
    let probe_trailer = trailer_head(auth_type, pad as u8, context_id);
    let tok_len = token_len(ctx, signed_len, data.len(), &probe_trailer, sign_header)?;
    let clear = clear_type(sign_header);

    let frag =
        u16::try_from(signed_len + data.len() + SEC_TRAILER_HEAD + tok_len).unwrap_or(u16::MAX);
    let mut signed = Vec::with_capacity(signed_len);
    signed.extend_from_slice(&common_header(
        ptype::REQUEST,
        flags,
        call_id,
        frag,
        u16::try_from(tok_len).unwrap_or(u16::MAX),
    ));
    signed.extend_from_slice(&prefix);
    let mut trailer = trailer_head(auth_type, pad as u8, context_id);
    let mut token = vec![0u8; tok_len];
    {
        let mut iov = [
            GssIov::new(clear, &mut signed[..]),
            GssIov::new(GssIovType::Data, &mut data[..]),
            GssIov::new(clear, &mut trailer[..]),
            GssIov::new(GssIovType::Header, &mut token[..]),
        ];
        ctx.wrap_iov(true, &mut iov)?;
    }

    let mut pdu = Vec::with_capacity(usize::from(frag));
    pdu.extend_from_slice(&signed);
    pdu.extend_from_slice(&data);
    pdu.extend_from_slice(&trailer);
    pdu.extend_from_slice(&token);
    Ok(pdu)
}

/// The presentation context fits a u16 in the request header.
fn context_id_as_u16(context_id: u32) -> u16 {
    u16::try_from(context_id).unwrap_or(0)
}

/// Unseals a received response PDU, returning its stub in clear (padding removed). The common
/// header and the 8-byte response header are signed in clear; the stub after them is decrypted
/// in place; the token checks the lot.
pub fn unseal(
    ctx: &mut dyn SecurityContext,
    pdu: &[u8],
    sign_header: bool,
) -> Result<Vec<u8>, GssError> {
    let defective = || GssError {
        major: MajorFlags::GSS_S_DEFECTIVE_TOKEN,
        minor: 0,
    };
    let parts = super::authn::split(pdu).ok_or_else(defective)?;
    let SecTrailer {
        auth_type,
        pad_length,
        context_id,
        mut token,
        ..
    } = parts.trailer;

    // The common header and the response header (the first 8 bytes of the body) are signed in
    // clear when header signing was negotiated; the encrypted stub is what follows.
    let signed_len = HEADER_LEN + PREFIX_LEN;
    let mut signed = pdu.get(..signed_len).ok_or_else(defective)?.to_vec();
    let mut data = parts.body.get(PREFIX_LEN..).ok_or_else(defective)?.to_vec();
    let mut trailer = trailer_head(auth_type, pad_length, context_id);
    let clear = clear_type(sign_header);
    {
        let mut iov = [
            GssIov::new(clear, &mut signed[..]),
            GssIov::new(GssIovType::Data, &mut data[..]),
            GssIov::new(clear, &mut trailer[..]),
            GssIov::new(GssIovType::Header, &mut token[..]),
        ];
        ctx.unwrap_iov(&mut iov)?;
    }
    let keep = data.len().saturating_sub(usize::from(pad_length));
    data.truncate(keep);
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_fills_up_to_a_block() {
        assert_eq!(pad_len(0), 0);
        assert_eq!(pad_len(16), 0);
        assert_eq!(pad_len(1), 15);
        assert_eq!(pad_len(15), 1);
        assert_eq!(pad_len(17), 15);
    }

    #[test]
    fn the_common_header_carries_its_lengths() {
        let h = common_header(0, 0x03, 7, 120, 60);
        assert_eq!(h[0], 5);
        assert_eq!(&h[4..8], &DREP);
        assert_eq!(u16::from_le_bytes([h[8], h[9]]), 120);
        assert_eq!(u16::from_le_bytes([h[10], h[11]]), 60);
        assert_eq!(u32::from_le_bytes([h[12], h[13], h[14], h[15]]), 7);
    }

    #[test]
    fn the_trailer_head_names_privacy() {
        let t = trailer_head(super::super::authn::AUTH_TYPE_GSS_NEGOTIATE, 5, 0);
        assert_eq!(t[0], super::super::authn::AUTH_TYPE_GSS_NEGOTIATE);
        assert_eq!(t[1], super::super::authn::AUTH_LEVEL_PKT_PRIVACY);
        assert_eq!(t[2], 5);
        assert_eq!(t[3], 0);
    }
}

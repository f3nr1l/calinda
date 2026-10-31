// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Authenticated DCE/RPC (C706 chapter 13, MS-RPCE 2.2.2.11): the security trailer that rides
//! at the end of every PDU under packet privacy, and the extra PDU types of the handshake.
//! This module is the framing only — how a trailer and its token sit in a PDU, and how to take
//! them back out — plus `AuthConn`, the authenticated connection that binds with Kerberos and
//! seals its calls. The cryptography itself is in `seal`.

use std::time::Duration;

use libgssapi::context::{ClientCtx, SecurityContext};
use libgssapi::error::Error as GssError;

use super::tcp::TcpTransport;
use super::{
    HEADER_LEN, PFC_FIRST_FRAG, PFC_LAST_FRAG, PFC_SUPPORT_HEADER_SIGN, RpcError, Syntax,
    Transport, bind_body, ptype, seal,
};
use crate::smb::auth::{AuthError, rpc_context};

/// `RPC_C_AUTHN_GSS_NEGOTIATE`: SPNEGO, the same wrapping the SMB sessions negotiate.
pub const AUTH_TYPE_GSS_NEGOTIATE: u8 = 9;
/// `RPC_C_AUTHN_GSS_KERBEROS`: Kerberos directly, with no SPNEGO envelope; what the
/// authenticated path uses, the GSS token being the krb5 context token as it stands.
pub const AUTH_TYPE_GSS_KERBEROS: u8 = 16;
/// `RPC_C_AUTHN_LEVEL_PKT_PRIVACY`: the bodies are sealed, not only signed.
pub const AUTH_LEVEL_PKT_PRIVACY: u8 = 6;

/// The fixed head of the security trailer, before the token (C706 13.2.6.1).
pub const SEC_TRAILER_HEAD: usize = 8;
/// `auth_length` sits at this offset in the common header.
const AUTH_LENGTH_AT: usize = 10;

/// A security trailer: its 8-byte head and the auth token that follows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecTrailer {
    pub auth_type: u8,
    pub auth_level: u8,
    /// Bytes of padding added to the body so the sealed part is block-aligned.
    pub pad_length: u8,
    pub context_id: u32,
    pub token: Vec<u8>,
}

impl SecTrailer {
    /// Writes the 8-byte head then the token.
    pub fn write(&self, out: &mut Vec<u8>) {
        out.push(self.auth_type);
        out.push(self.auth_level);
        out.push(self.pad_length);
        out.push(0); // auth-reserved
        out.extend_from_slice(&self.context_id.to_le_bytes());
        out.extend_from_slice(&self.token);
    }
}

/// A PDU taken apart: the body between the header and the trailer (padding included), and the
/// trailer itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts {
    pub body: Vec<u8>,
    pub trailer: SecTrailer,
}

fn u16_at(pdu: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(pdu.get(at..at + 2)?.try_into().ok()?))
}

/// Splits an authenticated PDU into its body and its trailer. `auth_length` (in the header) is
/// the token length alone; the trailer head is the 8 bytes just before the token. `None` if
/// the PDU carries no trailer or does not have the expected shape.
pub fn split(pdu: &[u8]) -> Option<Parts> {
    let frag = usize::from(u16_at(pdu, 8)?);
    let auth_len = usize::from(u16_at(pdu, AUTH_LENGTH_AT)?);
    if auth_len == 0 || frag != pdu.len() {
        return None;
    }
    let trailer_start = frag.checked_sub(auth_len + SEC_TRAILER_HEAD)?;
    if trailer_start < HEADER_LEN {
        return None;
    }
    let head = pdu.get(trailer_start..trailer_start + SEC_TRAILER_HEAD)?;
    let token = pdu.get(trailer_start + SEC_TRAILER_HEAD..frag)?.to_vec();
    let body = pdu.get(HEADER_LEN..trailer_start)?.to_vec();
    let trailer = SecTrailer {
        auth_type: *head.first()?,
        auth_level: *head.get(1)?,
        pad_length: *head.get(2)?,
        context_id: u32::from_le_bytes(head.get(4..8)?.try_into().ok()?),
        token,
    };
    Some(Parts { body, trailer })
}

fn gss(e: GssError) -> RpcError {
    RpcError::Auth(e.to_string())
}

fn from_auth(e: AuthError) -> RpcError {
    RpcError::Auth(e.to_string())
}

/// Lays out a BIND or ALTER_CONTEXT PDU: the common header (offering header signing), the body
/// before the auth verifier (the bind body), then the security trailer carrying `token` in
/// clear (the Kerberos token is not sealed, only the call bodies are).
fn verifier_pdu(ptype: u8, call_id: u32, body: &[u8], token: &[u8], context_id: u32) -> Vec<u8> {
    let trailer = SecTrailer {
        auth_type: AUTH_TYPE_GSS_KERBEROS,
        auth_level: AUTH_LEVEL_PKT_PRIVACY,
        pad_length: 0,
        context_id,
        token: token.to_vec(),
    };
    let mut tail = Vec::new();
    trailer.write(&mut tail);
    let frag = u16::try_from(HEADER_LEN + body.len() + tail.len()).unwrap_or(u16::MAX);
    let auth_len = u16::try_from(token.len()).unwrap_or(u16::MAX);
    let flags = PFC_FIRST_FRAG | PFC_LAST_FRAG | PFC_SUPPORT_HEADER_SIGN;
    let mut pdu = Vec::with_capacity(usize::from(frag));
    pdu.extend_from_slice(&[5, 0, ptype, flags]);
    pdu.extend_from_slice(&[0x10, 0, 0, 0]); // data representation
    pdu.extend_from_slice(&frag.to_le_bytes());
    pdu.extend_from_slice(&auth_len.to_le_bytes());
    pdu.extend_from_slice(&call_id.to_le_bytes());
    pdu.extend_from_slice(body);
    pdu.extend_from_slice(&tail);
    pdu
}

/// An authenticated DCE/RPC connection: bound to one interface with Kerberos, every call
/// sealed under packet privacy. One request and one response per call fit in a single
/// fragment, which `GetKey` (J9.7) does.
#[derive(Debug)]
pub struct AuthConn<T: Transport> {
    transport: T,
    ctx: ClientCtx,
    call_id: u32,
    context_id: u32,
    /// Whether the server echoed PFC_SUPPORT_HEADER_SIGN, so the PDU headers are signed.
    sign_header: bool,
}

impl AuthConn<TcpTransport> {
    /// Resolves the interface's TCP port through the endpoint mapper, connects, and binds with
    /// Kerberos for `service/server@realm` (e.g. `host`). Blocking.
    pub fn connect_tcp(
        host: &str,
        interface: Syntax,
        transfer: Syntax,
        service: &str,
        server: &str,
        realm: &str,
        timeout: Duration,
    ) -> Result<Self, RpcError> {
        let port = super::epm::resolve_tcp_port(host, interface, timeout)?;
        let transport = TcpTransport::connect(host, port, timeout)?;
        Self::bind(transport, interface, transfer, service, server, realm)
    }
}

impl<T: Transport> AuthConn<T> {
    /// Binds `interface` (with `transfer` as transfer syntax) on `transport` with a Kerberos AP
    /// exchange carried in the bind PDUs.
    pub fn bind(
        mut transport: T,
        interface: Syntax,
        transfer: Syntax,
        service: &str,
        server: &str,
        realm: &str,
    ) -> Result<Self, RpcError> {
        let mut ctx = rpc_context(service, server, realm).map_err(from_auth)?;
        let token1 = ctx
            .step(None, None)
            .map_err(gss)?
            .ok_or_else(|| RpcError::Auth("no initial Kerberos token".into()))?;
        let call_id = 1;
        let bind = verifier_pdu(
            ptype::BIND,
            call_id,
            &bind_body(interface, transfer),
            &token1,
            0,
        );
        let answer = transport.transceive(&bind)?;
        match answer.get(2) {
            Some(&ptype::BIND_ACK) => {}
            Some(&ptype::BIND_NAK) => return Err(RpcError::BindRefused(0)),
            Some(p) => return Err(RpcError::Protocol(format!("bind answered by PDU type {p}"))),
            None => return Err(RpcError::Protocol("short bind_ack".into())),
        }
        // Header signing is used only if the server echoed the flag in its bind_ack.
        let sign_header = answer
            .get(3)
            .is_some_and(|f| f & PFC_SUPPORT_HEADER_SIGN != 0);
        let parts = split(&answer)
            .ok_or_else(|| RpcError::Auth("bind_ack without an auth verifier".into()))?;
        // DCE style completes over further legs carried in ALTER_CONTEXT PDUs: step with the
        // server's token, send the client's next token, read the server's, until complete.
        let mut in_token = parts.trailer.token;
        while !ctx.is_complete() {
            let Some(out) = ctx.step(Some(&in_token), None).map_err(gss)? else {
                break;
            };
            if out.is_empty() {
                break;
            }
            let alter = verifier_pdu(
                ptype::ALTER_CONTEXT,
                call_id,
                &bind_body(interface, transfer),
                &out,
                0,
            );
            let resp = transport.transceive(&alter)?;
            match resp.get(2) {
                Some(&ptype::ALTER_CONTEXT_RESP) => {}
                Some(&ptype::BIND_NAK) => return Err(RpcError::BindRefused(0)),
                Some(p) => {
                    return Err(RpcError::Protocol(format!("alter_context answered by {p}")));
                }
                None => return Err(RpcError::Protocol("short alter_context response".into())),
            }
            in_token = split(&resp).map(|p| p.trailer.token).unwrap_or_default();
        }
        if !ctx.is_complete() {
            return Err(RpcError::Auth(
                "Kerberos context incomplete after bind".into(),
            ));
        }
        Ok(Self {
            transport,
            ctx,
            call_id,
            context_id: 0,
            sign_header,
        })
    }

    /// Calls `opnum` with the NDR `stub`, sealed; returns the response stub in clear. A
    /// `verification_trailer` (MS-RPCE 2.2.2.13), which MS-GKDI requires, is appended to the
    /// stub (4-byte aligned) inside the sealed data.
    pub fn call(
        &mut self,
        opnum: u16,
        stub: &[u8],
        verification_trailer: Option<&[u8]>,
    ) -> Result<Vec<u8>, RpcError> {
        self.call_id += 1;
        let call_id = self.call_id;
        let mut stub_data = stub.to_vec();
        if let Some(trailer) = verification_trailer {
            let pad = stub_data.len().next_multiple_of(4) - stub_data.len();
            stub_data.resize(stub_data.len() + pad, 0);
            stub_data.extend_from_slice(trailer);
        }
        let pdu = seal::seal(
            &mut self.ctx,
            call_id,
            self.context_id,
            opnum,
            &stub_data,
            AUTH_TYPE_GSS_KERBEROS,
            self.sign_header,
        )
        .map_err(gss)?;
        let answer = self.transport.transceive(&pdu)?;
        match answer.get(2) {
            Some(&ptype::RESPONSE) => {}
            Some(&ptype::FAULT) => {
                let code = answer
                    .get(HEADER_LEN + 8..HEADER_LEN + 12)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, u32::from_le_bytes);
                return Err(RpcError::Fault(code));
            }
            Some(p) => return Err(RpcError::Protocol(format!("call answered by PDU type {p}"))),
            None => return Err(RpcError::Protocol("short response".into())),
        }
        seal::unseal(&mut self.ctx, &answer, self.sign_header).map_err(gss)
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lays out header + body + trailer the way the authenticated path will, setting
    /// frag_length and auth_length, so `split` can be checked against it.
    fn frame(body: &[u8], trailer: &SecTrailer) -> Vec<u8> {
        let mut tail = Vec::new();
        trailer.write(&mut tail);
        let frag = (HEADER_LEN + body.len() + tail.len()) as u16;
        let auth_len = trailer.token.len() as u16;
        let mut pdu = vec![5, 0, 0, 0x06, 0x10, 0, 0, 0];
        pdu.extend_from_slice(&frag.to_le_bytes());
        pdu.extend_from_slice(&auth_len.to_le_bytes());
        pdu.extend_from_slice(&7u32.to_le_bytes()); // call_id
        pdu.extend_from_slice(body);
        pdu.extend_from_slice(&tail);
        pdu
    }

    #[test]
    fn a_trailer_round_trips_through_a_pdu() {
        let trailer = SecTrailer {
            auth_type: AUTH_TYPE_GSS_NEGOTIATE,
            auth_level: AUTH_LEVEL_PKT_PRIVACY,
            pad_length: 3,
            context_id: 0,
            token: vec![0xAA; 60],
        };
        let body = vec![0x11; 40];
        let pdu = frame(&body, &trailer);
        let parts = split(&pdu).unwrap();
        assert_eq!(parts.body, body);
        assert_eq!(parts.trailer, trailer);
    }

    #[test]
    fn a_pdu_without_a_token_has_no_parts() {
        let mut pdu = vec![5, 0, 0, 0, 0x10, 0, 0, 0];
        pdu.extend_from_slice(&16u16.to_le_bytes()); // frag_length = header only
        pdu.extend_from_slice(&0u16.to_le_bytes()); // auth_length 0
        pdu.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(split(&pdu), None);
    }

    #[test]
    fn an_inconsistent_length_is_rejected() {
        let trailer = SecTrailer {
            auth_type: 9,
            auth_level: 6,
            pad_length: 0,
            context_id: 0,
            token: vec![1, 2, 3, 4],
        };
        let mut pdu = frame(&[9, 9], &trailer);
        pdu.push(0); // frag_length no longer matches the real length
        assert_eq!(split(&pdu), None);
    }
}

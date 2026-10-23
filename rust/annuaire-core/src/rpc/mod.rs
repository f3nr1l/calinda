// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DCE/RPC, connection-oriented (C706 chapter 12, MS-RPCE), over a named pipe of `IPC$`
//! (ADR 0023 § 1): bind to one interface with NDR 2.0, then calls whose stubs `ndr` writes
//! and reads. No DCE/RPC authentication: on `ncacn_np` the SMB session authenticates and
//! protects (encryption), as with Windows and Samba.

pub mod ndr;

use crate::smb::SmbError;
use crate::smb::pipe::Pipe;

/// Packet types (C706 12.6.4).
mod ptype {
    pub const REQUEST: u8 = 0;
    pub const RESPONSE: u8 = 2;
    pub const FAULT: u8 = 3;
    pub const BIND: u8 = 11;
    pub const BIND_ACK: u8 = 12;
    pub const BIND_NAK: u8 = 13;
}
const PFC_FIRST_FRAG: u8 = 0x01;
const PFC_LAST_FRAG: u8 = 0x02;
/// Little-endian integers, ASCII, IEEE floats.
const DREP: [u8; 4] = [0x10, 0, 0, 0];
const HEADER_LEN: usize = 16;
/// Fragment sizes offered at bind; the server may lower them.
const MAX_FRAG: u16 = 4280;

/// An interface or a transfer syntax: UUID and version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Syntax {
    pub uuid: [u8; 16],
    pub major: u16,
    pub minor: u16,
}

impl Syntax {
    /// From the usual text form `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, encoded as NDR does
    /// (the first three fields little-endian).
    pub const fn new(uuid: u128, major: u16, minor: u16) -> Self {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = uuid.to_be_bytes();
        Self {
            uuid: [d, c, b, a, f, e, h, g, i, j, k, l, m, n, o, p],
            major,
            minor,
        }
    }

    fn write(&self, w: &mut Vec<u8>) {
        w.extend_from_slice(&self.uuid);
        w.extend_from_slice(&self.major.to_le_bytes());
        w.extend_from_slice(&self.minor.to_le_bytes());
    }
}

/// NDR 2.0, the transfer syntax of every interface used here.
pub const NDR: Syntax = Syntax::new(0x8a88_5d04_1ceb_11c9_9fe8_0800_2b10_4860, 2, 0);

/// What went wrong in a call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    /// The SMB transport (connection, ticket, refusal of the pipe…).
    Smb(SmbError),
    /// The server refused the bind (`bind_nak` reason, or result of the context).
    BindRefused(u16),
    /// The server answered with a fault (`nca_s_*` or a Win32/NTSTATUS code).
    Fault(u32),
    /// A PDU or a stub that does not have its expected shape.
    Protocol(String),
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Smb(e) => write!(f, "{e}"),
            Self::BindRefused(r) => write!(f, "RPC bind refused (reason {r})"),
            Self::Fault(s) => write!(f, "RPC fault 0x{s:08X}"),
            Self::Protocol(d) => write!(f, "RPC protocol: {d}"),
        }
    }
}

impl std::error::Error for RpcError {}

impl From<SmbError> for RpcError {
    fn from(e: SmbError) -> Self {
        Self::Smb(e)
    }
}

impl From<ndr::Short> for RpcError {
    fn from(e: ndr::Short) -> Self {
        Self::Protocol(e.to_string())
    }
}

/// How PDUs travel: a pipe, or a fake server in the tests.
pub trait Transport {
    /// Writes a fragment that has no answer of its own.
    fn write(&mut self, pdu: &[u8]) -> Result<(), SmbError>;
    /// Writes a fragment and returns the first fragment of the answer.
    fn transceive(&mut self, pdu: &[u8]) -> Result<Vec<u8>, SmbError>;
    /// The next fragment of an answer.
    fn read(&mut self) -> Result<Vec<u8>, SmbError>;
}

impl Transport for Pipe {
    fn write(&mut self, pdu: &[u8]) -> Result<(), SmbError> {
        Pipe::write(self, pdu)
    }
    fn transceive(&mut self, pdu: &[u8]) -> Result<Vec<u8>, SmbError> {
        Pipe::transceive(self, pdu)
    }
    fn read(&mut self) -> Result<Vec<u8>, SmbError> {
        Pipe::read(self)
    }
}

/// The common header of a PDU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    ptype: u8,
    flags: u8,
    frag_length: u16,
    call_id: u32,
}

fn header(pdu: &[u8]) -> Result<Header, RpcError> {
    let short = || RpcError::Protocol(format!("PDU of {} bytes", pdu.len()));
    if pdu.len() < HEADER_LEN {
        return Err(short());
    }
    let r = ndr::Reader::new(pdu);
    let version = r.u8_at(0).ok_or_else(short)?;
    if version != 5 {
        return Err(RpcError::Protocol(format!("RPC version {version}")));
    }
    if r.u8_at(4).ok_or_else(short)? & 0xF0 != 0x10 {
        return Err(RpcError::Protocol("big-endian PDU".into()));
    }
    let h = Header {
        ptype: r.u8_at(2).ok_or_else(short)?,
        flags: r.u8_at(3).ok_or_else(short)?,
        frag_length: r.u16_at(8).ok_or_else(short)?,
        call_id: r.u32_at(12).ok_or_else(short)?,
    };
    if usize::from(h.frag_length) != pdu.len() {
        return Err(RpcError::Protocol(format!(
            "fragment of {} bytes announced, {} received",
            h.frag_length,
            pdu.len()
        )));
    }
    Ok(h)
}

fn pdu(ptype: u8, flags: u8, call_id: u32, body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(HEADER_LEN + body.len()).unwrap_or(u16::MAX);
    let mut w = Vec::with_capacity(HEADER_LEN + body.len());
    w.extend_from_slice(&[5, 0, ptype, flags]);
    w.extend_from_slice(&DREP);
    w.extend_from_slice(&length.to_le_bytes());
    w.extend_from_slice(&0u16.to_le_bytes());
    w.extend_from_slice(&call_id.to_le_bytes());
    w.extend_from_slice(body);
    w
}

/// A bound connection to one interface.
#[derive(Debug)]
pub struct Rpc<T: Transport> {
    transport: T,
    call_id: u32,
    max_xmit: usize,
}

impl<T: Transport> Rpc<T> {
    /// Binds `interface` (presentation context 0, NDR 2.0) on `transport`.
    pub fn bind(mut transport: T, interface: Syntax) -> Result<Self, RpcError> {
        let mut body = Vec::new();
        body.extend_from_slice(&MAX_FRAG.to_le_bytes());
        body.extend_from_slice(&MAX_FRAG.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes()); // new association group
        body.extend_from_slice(&[1, 0, 0, 0]); // one context element
        body.extend_from_slice(&0u16.to_le_bytes()); // context id
        body.extend_from_slice(&[1, 0]); // one transfer syntax
        interface.write(&mut body);
        NDR.write(&mut body);
        let call_id = 1;
        let answer = transport.transceive(&pdu(
            ptype::BIND,
            PFC_FIRST_FRAG | PFC_LAST_FRAG,
            call_id,
            &body,
        ))?;
        let h = header(&answer)?;
        let r = ndr::Reader::new(&answer);
        match h.ptype {
            ptype::BIND_ACK => {}
            ptype::BIND_NAK => {
                return Err(RpcError::BindRefused(r.u16_at(HEADER_LEN).unwrap_or(0)));
            }
            p => return Err(RpcError::Protocol(format!("bind answered by PDU type {p}"))),
        }
        let short = || RpcError::Protocol("bind_ack too short".into());
        let max_xmit = r.u16_at(HEADER_LEN).ok_or_else(short)?;
        // Secondary address: length, string, then alignment to 4 from the PDU start.
        let address = usize::from(r.u16_at(HEADER_LEN + 8).ok_or_else(short)?);
        let mut at = HEADER_LEN + 10 + address;
        at = at.div_ceil(4) * 4;
        let results = r.u8_at(at).ok_or_else(short)?;
        if results == 0 {
            return Err(short());
        }
        let result = r.u16_at(at + 4).ok_or_else(short)?;
        if result != 0 {
            return Err(RpcError::BindRefused(r.u16_at(at + 6).unwrap_or(result)));
        }
        Ok(Self {
            transport,
            call_id,
            max_xmit: usize::from(max_xmit).clamp(HEADER_LEN + 8 + 8, usize::from(MAX_FRAG)),
        })
    }

    /// Calls `opnum` with the stub `input`; returns the stub of the response, fragments put
    /// together.
    pub fn call(&mut self, opnum: u16, input: &[u8]) -> Result<Vec<u8>, RpcError> {
        self.call_id += 1;
        let call_id = self.call_id;
        // Request fragments: alloc hint, context, opnum, then the stub piece.
        let room = self.max_xmit - HEADER_LEN - 8;
        let pieces: Vec<&[u8]> = if input.is_empty() {
            vec![input]
        } else {
            input.chunks(room).collect()
        };
        let mut answer = Vec::new();
        for (i, piece) in pieces.iter().enumerate() {
            let mut flags = 0;
            if i == 0 {
                flags |= PFC_FIRST_FRAG;
            }
            let last = i + 1 == pieces.len();
            if last {
                flags |= PFC_LAST_FRAG;
            }
            let mut body = Vec::with_capacity(8 + piece.len());
            body.extend_from_slice(&u32::try_from(input.len()).unwrap_or(0).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            body.extend_from_slice(&opnum.to_le_bytes());
            body.extend_from_slice(piece);
            let fragment = pdu(ptype::REQUEST, flags, call_id, &body);
            if last {
                answer = self.transport.transceive(&fragment)?;
            } else {
                self.transport.write(&fragment)?;
            }
        }
        let mut stub = Vec::new();
        loop {
            let h = header(&answer)?;
            if h.call_id != call_id {
                return Err(RpcError::Protocol(format!(
                    "answer to call {}, {call_id} expected",
                    h.call_id
                )));
            }
            let r = ndr::Reader::new(&answer);
            match h.ptype {
                ptype::RESPONSE => {}
                ptype::FAULT => {
                    return Err(RpcError::Fault(r.u32_at(HEADER_LEN + 8).unwrap_or(0)));
                }
                p => return Err(RpcError::Protocol(format!("call answered by PDU type {p}"))),
            }
            stub.extend_from_slice(answer.get(HEADER_LEN + 8..).unwrap_or_default());
            if h.flags & PFC_LAST_FRAG != 0 {
                return Ok(stub);
            }
            answer = self.transport.read()?;
        }
    }

    pub fn into_transport(self) -> T {
        self.transport
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Answers in order, and keeps what was written.
    #[derive(Default)]
    struct Script {
        answers: VecDeque<Vec<u8>>,
        written: Vec<Vec<u8>>,
    }

    impl Transport for Script {
        fn write(&mut self, pdu: &[u8]) -> Result<(), SmbError> {
            self.written.push(pdu.to_vec());
            Ok(())
        }
        fn transceive(&mut self, pdu: &[u8]) -> Result<Vec<u8>, SmbError> {
            self.written.push(pdu.to_vec());
            Ok(self.answers.pop_front().unwrap_or_default())
        }
        fn read(&mut self) -> Result<Vec<u8>, SmbError> {
            Ok(self.answers.pop_front().unwrap_or_default())
        }
    }

    const SRVSVC: Syntax = Syntax::new(0x4b32_4fc8_1670_01d3_1278_5a47_bf6e_e188, 3, 0);

    fn bind_ack(max_xmit: u16, result: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&max_xmit.to_le_bytes());
        b.extend_from_slice(&max_xmit.to_le_bytes());
        b.extend_from_slice(&0x1234u32.to_le_bytes());
        b.extend_from_slice(&13u16.to_le_bytes());
        b.extend_from_slice(b"\\PIPE\\srvsvc\0");
        while (HEADER_LEN + b.len()) % 4 != 0 {
            b.push(0);
        }
        b.extend_from_slice(&[1, 0, 0, 0]);
        b.extend_from_slice(&result.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        NDR.write(&mut b);
        pdu(ptype::BIND_ACK, 3, 1, &b)
    }

    fn response(call_id: u32, flags: u8, stub: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b.extend_from_slice(stub);
        pdu(ptype::RESPONSE, flags, call_id, &b)
    }

    #[test]
    fn uuid_is_encoded_as_ndr_does() {
        // 8a885d04-1ceb-11c9-9fe8-08002b104860, as captured in any bind.
        let mut b = Vec::new();
        NDR.write(&mut b);
        assert_eq!(
            b,
            [
                0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
                0x48, 0x60, 2, 0, 0, 0
            ]
        );
    }

    #[test]
    fn bind_then_call_with_fragmented_answer() {
        let mut script = Script::default();
        script.answers.push_back(bind_ack(4280, 0));
        script
            .answers
            .push_back(response(2, PFC_FIRST_FRAG, b"abc"));
        script.answers.push_back(response(2, PFC_LAST_FRAG, b"def"));
        let mut rpc = Rpc::bind(script, SRVSVC).unwrap();
        assert_eq!(rpc.call(15, b"in").unwrap(), b"abcdef");
        let script = rpc.into_transport();
        let bind = &script.written[0];
        assert_eq!(bind[2], ptype::BIND);
        assert_eq!(
            usize::from(u16::from_le_bytes([bind[8], bind[9]])),
            bind.len()
        );
        let request = &script.written[1];
        assert_eq!(request[2], ptype::REQUEST);
        assert_eq!(
            &request[HEADER_LEN + 6..HEADER_LEN + 8],
            &15u16.to_le_bytes()
        );
        assert_eq!(&request[HEADER_LEN + 8..], b"in");
    }

    #[test]
    fn long_request_goes_in_fragments() {
        let mut script = Script::default();
        script.answers.push_back(bind_ack(100, 0));
        script.answers.push_back(response(2, 3, b"ok"));
        let mut rpc = Rpc::bind(script, SRVSVC).unwrap();
        let input = vec![7u8; 200];
        assert_eq!(rpc.call(16, &input).unwrap(), b"ok");
        let script = rpc.into_transport();
        let fragments = &script.written[1..];
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0][3], PFC_FIRST_FRAG);
        assert_eq!(fragments[1][3], 0);
        assert_eq!(fragments[2][3], PFC_LAST_FRAG);
        let total: usize = fragments.iter().map(|f| f.len() - HEADER_LEN - 8).sum();
        assert_eq!(total, 200);
        assert!(fragments.iter().all(|f| f.len() <= 100));
    }

    #[test]
    fn refusals_are_errors() {
        let mut script = Script::default();
        script.answers.push_back(bind_ack(4280, 2));
        assert!(matches!(
            Rpc::bind(script, SRVSVC),
            Err(RpcError::BindRefused(_))
        ));

        let mut script = Script::default();
        script.answers.push_back(bind_ack(4280, 0));
        let mut fault = vec![0u8; 8];
        fault.extend_from_slice(&0x1C01_0002u32.to_le_bytes());
        fault.extend_from_slice(&[0; 4]);
        script.answers.push_back(pdu(ptype::FAULT, 3, 2, &fault));
        let mut rpc = Rpc::bind(script, SRVSVC).unwrap();
        assert_eq!(rpc.call(99, b""), Err(RpcError::Fault(0x1C01_0002)));
    }

    #[test]
    fn malformed_pdus_are_refused() {
        let mut script = Script::default();
        let mut ack = bind_ack(4280, 0);
        ack.pop();
        script.answers.push_back(ack);
        assert!(matches!(
            Rpc::bind(script, SRVSVC),
            Err(RpcError::Protocol(_))
        ));
    }
}

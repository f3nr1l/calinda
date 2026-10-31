// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! `ncacn_ip_tcp` transport for DCE/RPC (C706 chapter 12): a plain TCP connection that carries
//! whole PDUs, one fragment at a time. Unlike the named pipe (`ncacn_np`), the session is not
//! protected by SMB, so an interface that needs confidentiality seals its own PDUs (J9.6). The
//! endpoint mapper (port 135) and the port it hands back are both reached this way.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use super::Transport;
use crate::smb::{ErrorKind, SmbError};

const HEADER_LEN: usize = 16;

fn io_error(e: &io::Error) -> SmbError {
    let kind = match e.kind() {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => ErrorKind::Timeout,
        _ => ErrorKind::Unreachable,
    };
    SmbError::new(kind, e.to_string())
}

/// Reads one whole PDU from `r`: the 16-byte common header, then the rest of `frag_length`
/// (a little-endian u16 at offset 8, C706 12.6.1).
fn read_pdu_from(r: &mut impl Read) -> Result<Vec<u8>, SmbError> {
    let mut head = [0u8; HEADER_LEN];
    r.read_exact(&mut head).map_err(|e| io_error(&e))?;
    let frag = usize::from(u16::from_le_bytes([head[8], head[9]]));
    if frag < HEADER_LEN {
        return Err(SmbError::new(
            ErrorKind::Protocol,
            format!("RPC fragment of {frag} bytes announced"),
        ));
    }
    let mut pdu = Vec::with_capacity(frag);
    pdu.extend_from_slice(&head);
    pdu.resize(frag, 0);
    if let Some(rest) = pdu.get_mut(HEADER_LEN..) {
        r.read_exact(rest).map_err(|e| io_error(&e))?;
    }
    Ok(pdu)
}

/// A TCP connection to one endpoint, carrying DCE/RPC PDUs.
#[derive(Debug)]
pub struct TcpTransport {
    stream: TcpStream,
}

impl TcpTransport {
    /// Connects to `host:port`, with `timeout` for the connection and for each read and write.
    pub fn connect(host: &str, port: u16, timeout: Duration) -> Result<Self, SmbError> {
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|e| SmbError::new(ErrorKind::Unreachable, format!("{host}: {e}")))?;
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("{host}: no address"));
        let mut stream = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = e,
            }
        }
        let stream = stream.ok_or_else(|| io_error(&last))?;
        stream.set_nodelay(true).map_err(|e| io_error(&e))?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|e| io_error(&e))?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|e| io_error(&e))?;
        Ok(Self { stream })
    }
}

impl Transport for TcpTransport {
    fn write(&mut self, pdu: &[u8]) -> Result<(), SmbError> {
        self.stream.write_all(pdu).map_err(|e| io_error(&e))
    }
    fn transceive(&mut self, pdu: &[u8]) -> Result<Vec<u8>, SmbError> {
        self.write(pdu)?;
        read_pdu_from(&mut self.stream)
    }
    fn read(&mut self) -> Result<Vec<u8>, SmbError> {
        read_pdu_from(&mut self.stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A PDU with `frag_length` at offset 8 and `body` after the 16-byte header.
    fn pdu(body: &[u8]) -> Vec<u8> {
        let frag = (HEADER_LEN + body.len()) as u16;
        let mut p = vec![5, 0, 2, 3, 0x10, 0, 0, 0];
        p.extend_from_slice(&frag.to_le_bytes());
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(body);
        p
    }

    #[test]
    fn reads_one_whole_pdu_and_stops_at_its_end() {
        let first = pdu(b"abc");
        let second = pdu(b"defgh");
        let mut both = first.clone();
        both.extend_from_slice(&second);
        let mut cursor = Cursor::new(both);
        assert_eq!(read_pdu_from(&mut cursor).unwrap(), first);
        assert_eq!(read_pdu_from(&mut cursor).unwrap(), second);
    }

    #[test]
    fn a_fragment_shorter_than_the_header_is_refused() {
        let mut head = pdu(b"");
        head[8] = 8; // frag_length below HEADER_LEN
        let mut cursor = Cursor::new(head);
        assert!(matches!(
            read_pdu_from(&mut cursor),
            Err(SmbError {
                kind: ErrorKind::Protocol,
                ..
            })
        ));
    }

    #[test]
    fn a_truncated_body_is_an_error() {
        let mut p = pdu(b"abcdef");
        p.truncate(HEADER_LEN + 2);
        let mut cursor = Cursor::new(p);
        assert!(read_pdu_from(&mut cursor).is_err());
    }
}

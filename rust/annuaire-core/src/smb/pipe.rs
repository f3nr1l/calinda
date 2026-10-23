// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A named pipe of `IPC$`, the transport of DCE/RPC (`ncacn_np`, ADR 0023 § 1): one message
//! written and its answer read in one IOCTL (`FSCTL_PIPE_TRANSCEIVE`), the rest of a long
//! message by READ while the server says `STATUS_BUFFER_OVERFLOW`.

use super::client::{Client, ErrorKind, Options, SmbError};
use super::msg::{self, Create, FSCTL_PIPE_TRANSCEIVE, status};
use super::{Authenticator, Kerberos};

/// Bytes asked for each answer: the fragment size Windows and Samba negotiate.
pub const MAX_MESSAGE: u32 = 4280;

// Access of the open: read and write data, attributes and EA, read control, synchronize.
const PIPE_ACCESS: u32 = 0x0012_019F;
const SHARE_READ_WRITE: u32 = 0x3;
const OPEN: u32 = 1;
const NON_DIRECTORY_FILE: u32 = 0x0000_0040;

/// A pipe open on `\\<server>\IPC$`, closed with its session.
#[derive(Debug)]
pub struct Pipe {
    client: Client,
    file_id: [u8; 16],
}

impl Pipe {
    /// Session on `IPC$` of `server` with the Kerberos ticket of the user, then the pipe
    /// `name` (`srvsvc`, `samr`…). Blocking.
    pub fn open(server: &str, name: &str, options: &Options) -> Result<Pipe, SmbError> {
        let realm = crate::sysvol::realm_of(server);
        let mut auth = Kerberos::new(server, &realm)?;
        Self::open_with(server, name, options, &mut auth)
    }

    pub fn open_with(
        server: &str,
        name: &str,
        options: &Options,
        auth: &mut dyn Authenticator,
    ) -> Result<Pipe, SmbError> {
        let mut client = Client::connect(server, "IPC$", options, auth)?;
        let response = client.request(msg::create(&Create {
            path: name,
            access: PIPE_ACCESS,
            share: SHARE_READ_WRITE,
            disposition: OPEN,
            options: NON_DIRECTORY_FILE,
            ..Create::default()
        }))?;
        response.ok()?;
        let file_id = msg::parse_create(&response.msg)?.file_id;
        Ok(Pipe { client, file_id })
    }

    pub fn negotiated(&self) -> super::Negotiated {
        self.client.negotiated()
    }

    /// Writes `message` without waiting for an answer (fragments before the last one).
    pub fn write(&mut self, message: &[u8]) -> Result<(), SmbError> {
        let response = self.client.request(msg::write(&self.file_id, 0, message))?;
        response.ok()?;
        let written = msg::parse_write(&response.msg)? as usize;
        if written == message.len() {
            Ok(())
        } else {
            Err(SmbError::new(
                ErrorKind::Protocol,
                format!("pipe took {written} bytes of {}", message.len()),
            ))
        }
    }

    /// Writes `message` and returns the whole answer message.
    pub fn transceive(&mut self, message: &[u8]) -> Result<Vec<u8>, SmbError> {
        let response = self.client.request(msg::ioctl(
            &self.file_id,
            FSCTL_PIPE_TRANSCEIVE,
            message,
            MAX_MESSAGE,
        ))?;
        let mut answer = match response.status() {
            status::SUCCESS => return Ok(msg::parse_ioctl(&response.msg)?),
            status::BUFFER_OVERFLOW => msg::parse_ioctl(&response.msg)?,
            _ => {
                response.ok()?;
                Vec::new()
            }
        };
        self.read_rest(&mut answer)?;
        Ok(answer)
    }

    /// The next message the server writes (fragments after the first one).
    pub fn read(&mut self) -> Result<Vec<u8>, SmbError> {
        let mut message = Vec::new();
        let response = self
            .client
            .request(msg::read(&self.file_id, 0, MAX_MESSAGE))?;
        match response.status() {
            status::SUCCESS => return Ok(msg::parse_read(&response.msg)?),
            status::BUFFER_OVERFLOW => message.extend(msg::parse_read(&response.msg)?),
            _ => {
                response.ok()?;
            }
        }
        self.read_rest(&mut message)?;
        Ok(message)
    }

    /// Reads the end of a message the server could not answer in one piece.
    fn read_rest(&mut self, message: &mut Vec<u8>) -> Result<(), SmbError> {
        loop {
            let response = self
                .client
                .request(msg::read(&self.file_id, 0, MAX_MESSAGE))?;
            let last = match response.status() {
                status::SUCCESS => true,
                status::BUFFER_OVERFLOW => false,
                _ => {
                    response.ok()?;
                    true
                }
            };
            message.extend(msg::parse_read(&response.msg)?);
            if last {
                return Ok(());
            }
        }
    }

    pub fn close(mut self) {
        let _ = self.client.request(msg::close(&self.file_id));
        self.client.close();
    }
}

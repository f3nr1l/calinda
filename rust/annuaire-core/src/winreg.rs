// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The registry configuration of a Samba server, through the Windows Remote Registry Protocol
//! (MS-RRP), on the pipe `winreg` of `IPC$` (ADR 0023 § 9, J8.7).
//!
//! Samba keeps the shares that `net conf` writes under `HKLM\Software\Samba\smbconf\<share>`,
//! one `REG_SZ` value per parameter, and reads them at the next enumeration or connection.
//! Two layers: the calls of the protocol (`Winreg`, private to this module, and the stubs,
//! public for the vectors), and `SmbConf`, the only way out of the module, which reaches the
//! key of one share and nothing else (never `global`, never another key) and changes only the
//! parameters of `PARAMETERS`. A key is created whole (a share made, or put back by an undo,
//! with the values it had) and deleted whole.

use crate::rpc::ndr::{Reader, Short, Writer};
use crate::rpc::{Rpc, Syntax};
use crate::smb::client::Options;
use crate::smb::pipe::Pipe;

/// `winreg` v1.0 (MS-RRP 1.9).
pub const INTERFACE: Syntax = Syntax::new(0x338c_d001_2244_31f1_aaaa_9000_3800_1003, 1, 0);

pub mod opnum {
    pub const OPEN_LOCAL_MACHINE: u16 = 2;
    pub const CLOSE_KEY: u16 = 5;
    pub const CREATE_KEY: u16 = 6;
    pub const DELETE_KEY: u16 = 7;
    pub const DELETE_VALUE: u16 = 8;
    pub const ENUM_KEY: u16 = 9;
    pub const ENUM_VALUE: u16 = 10;
    pub const OPEN_KEY: u16 = 15;
    pub const QUERY_VALUE: u16 = 17;
    pub const SET_VALUE: u16 = 22;
}

/// Access asked: whatever the account is granted (Samba grants all on its configuration to an
/// account with `SeDiskOperatorPrivilege`, nothing to the others).
pub const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// Value types (MS-RRP 2.2.5).
pub mod kind {
    pub const SZ: u32 = 1;
    pub const EXPAND_SZ: u32 = 2;
    pub const DWORD: u32 = 4;
}

/// Win32 errors of the registry.
pub mod werror {
    pub const FILE_NOT_FOUND: u32 = 2;
    pub const ACCESS_DENIED: u32 = 5;
    pub const INVALID_PARAMETER: u32 = 87;
    pub const INVALID_NAME: u32 = 123;
    pub const MORE_DATA: u32 = 234;
    pub const NO_MORE_ITEMS: u32 = 259;
    pub const ALREADY_EXISTS: u32 = 183;
}

/// `REG_CREATED_NEW_KEY`: the disposition of a key `BaseRegCreateKey` made.
pub const CREATED_NEW_KEY: u32 = 1;

/// Where Samba keeps its registry configuration, from `HKLM`.
pub const SMBCONF: &str = "Software\\Samba\\smbconf";

/// The parameters of a share Calinda changes (ADR 0023 § 9): what the share dialog edits,
/// and what `net conf addshare` writes to create a share.
pub const PARAMETERS: [&str; 7] = [
    "path",
    "comment",
    "read only",
    "guest ok",
    "max connections",
    "csc policy",
    "access based share enum",
];

/// Sections of Samba that are not shares: never written.
const RESERVED: [&str; 3] = ["global", "homes", "printers"];

/// Same errors as the share service: a Win32 error of the server, or the transport.
pub type Error = crate::srvsvc::Error;
pub type Result<T> = std::result::Result<T, Error>;

pub type Handle = [u8; 20];

/// A value as the registry gives it: its type and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    pub kind: u32,
    pub data: Vec<u8>,
}

impl Value {
    pub fn sz(text: &str) -> Self {
        let data = text
            .encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(u16::to_le_bytes)
            .collect();
        Self {
            kind: kind::SZ,
            data,
        }
    }

    /// The value as Samba reads it into its configuration: strings without their final null,
    /// a number in decimal (`smbconf_reg_format_registry_value`).
    pub fn text(&self) -> Option<String> {
        match self.kind {
            kind::SZ | kind::EXPAND_SZ => {
                let mut units: Vec<u16> = self
                    .data
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes(c.try_into().unwrap_or([0, 0])))
                    .collect();
                while units.last() == Some(&0) {
                    units.pop();
                }
                String::from_utf16(&units).ok()
            }
            kind::DWORD => {
                let b: [u8; 4] = self.data.get(..4)?.try_into().ok()?;
                Some(u32::from_le_bytes(b).to_string())
            }
            _ => None,
        }
    }
}

fn refused(op: &'static str, code: u32) -> Error {
    Error::Refused { op, code }
}

/// The key of `share` under `smbconf`, or a refusal: the guard of ADR 0023 § 9. No empty
/// name, no separator (another key), no control character, nothing longer than Samba takes,
/// not `global`, `homes` nor `printers`.
pub fn share_key(share: &str) -> Result<String> {
    let bad = share.is_empty()
        || share.chars().count() > 80
        || share.contains(['\\', '/'])
        || share.chars().any(char::is_control)
        || share.trim() != share
        || RESERVED.iter().any(|r| r.eq_ignore_ascii_case(share));
    if bad {
        return Err(refused("winreg (garde)", werror::INVALID_NAME));
    }
    Ok(format!("{SMBCONF}\\{share}"))
}

/// A parameter Calinda may change: one of `PARAMETERS`, as `net conf` names it.
pub fn allowed(parameter: &str) -> bool {
    PARAMETERS.contains(&parameter)
}

// --- Calls -----------------------------------------------------------------------------------

/// A bound connection to the registry of a server, with its `HKLM` handle. Private: only
/// `SmbConf` uses it, so that the guard cannot be gone around.
#[derive(Debug)]
struct Winreg {
    rpc: Rpc<Pipe>,
    hklm: Handle,
}

impl Winreg {
    fn open(server: &str, options: &Options) -> Result<Self> {
        let pipe = Pipe::open(server, "winreg", options)?;
        let mut rpc = Rpc::bind(pipe, INTERFACE)?;
        let stub = rpc.call(
            opnum::OPEN_LOCAL_MACHINE,
            &open_local_machine_request(MAXIMUM_ALLOWED),
        )?;
        let hklm = parse_handle(&stub, "OpenLocalMachine")?;
        Ok(Self { rpc, hklm })
    }

    fn close(mut self) {
        let hklm = self.hklm;
        self.close_key(&hklm);
        self.rpc.into_transport().close();
    }

    fn open_key(&mut self, parent: &Handle, path: &str) -> Result<Handle> {
        let stub = self.rpc.call(
            opnum::OPEN_KEY,
            &open_key_request(parent, path, MAXIMUM_ALLOWED),
        )?;
        parse_handle(&stub, "BaseRegOpenKey")
    }

    /// The key and whether it was made by this call.
    fn create_key(&mut self, parent: &Handle, path: &str) -> Result<(Handle, bool)> {
        let stub = self.rpc.call(
            opnum::CREATE_KEY,
            &create_key_request(parent, path, MAXIMUM_ALLOWED),
        )?;
        let (key, disposition) = parse_create_key(&stub)?;
        Ok((key, disposition == Some(CREATED_NEW_KEY)))
    }

    fn close_key(&mut self, key: &Handle) {
        if let Ok(stub) = self.rpc.call(opnum::CLOSE_KEY, &handle_request(key)) {
            let _ = parse_handle(&stub, "BaseRegCloseKey");
        }
    }

    fn delete_key(&mut self, parent: &Handle, name: &str) -> Result<()> {
        let stub = self
            .rpc
            .call(opnum::DELETE_KEY, &name_request(parent, name))?;
        parse_status(&stub, "BaseRegDeleteKey")
    }

    fn set_value(&mut self, key: &Handle, name: &str, value: &Value) -> Result<()> {
        let stub = self
            .rpc
            .call(opnum::SET_VALUE, &set_value_request(key, name, value))?;
        parse_status(&stub, "BaseRegSetValue")
    }

    fn delete_value(&mut self, key: &Handle, name: &str) -> Result<()> {
        let stub = self
            .rpc
            .call(opnum::DELETE_VALUE, &name_request(key, name))?;
        parse_status(&stub, "BaseRegDeleteValue")
    }

    /// One value; `None` if the key does not have it.
    fn query_value(&mut self, key: &Handle, name: &str) -> Result<Option<Value>> {
        let mut size = BUFFER;
        loop {
            let stub = self
                .rpc
                .call(opnum::QUERY_VALUE, &query_value_request(key, name, size))?;
            match parse_query_value(&stub) {
                Ok(v) => return Ok(Some(v)),
                Err(Error::Refused {
                    code: werror::FILE_NOT_FOUND,
                    ..
                }) => return Ok(None),
                Err(Error::Refused {
                    code: werror::MORE_DATA,
                    ..
                }) if size < MAX_BUFFER => size = MAX_BUFFER,
                Err(e) => return Err(e),
            }
        }
    }

    /// The names of the subkeys.
    fn subkeys(&mut self, key: &Handle) -> Result<Vec<String>> {
        let mut names = Vec::new();
        for index in 0.. {
            let stub = self
                .rpc
                .call(opnum::ENUM_KEY, &enum_key_request(key, index))?;
            match parse_enum_key(&stub)? {
                Some(name) => names.push(name),
                None => break,
            }
        }
        Ok(names)
    }

    /// The values of a key, in the order the server gives them.
    fn values(&mut self, key: &Handle) -> Result<Vec<(String, Value)>> {
        let mut values = Vec::new();
        for index in 0.. {
            let stub = self
                .rpc
                .call(opnum::ENUM_VALUE, &enum_value_request(key, index, BUFFER))?;
            match parse_enum_value(&stub)? {
                Some(v) => values.push(v),
                None => break,
            }
        }
        Ok(values)
    }
}

/// Bytes offered for a value, then the most taken if the server asks more.
const BUFFER: u32 = 0x2000;
const MAX_BUFFER: u32 = 0x10000;
/// Bytes offered for a name (a key name has 255 characters at most).
const NAME_BUFFER: u16 = 0x400;

// --- Samba's configuration --------------------------------------------------------------------

/// The registry configuration of a Samba server, opened at `HKLM\Software\Samba\smbconf`.
#[derive(Debug)]
pub struct SmbConf {
    reg: Winreg,
    root: Handle,
}

/// The values of a share key, as `net conf showshare` lists them: name and text.
pub type Values = Vec<(String, String)>;

impl SmbConf {
    /// Opens the registry of `server` and its `smbconf` key. Blocking.
    pub fn open(server: &str, options: &Options) -> Result<Self> {
        let mut reg = Winreg::open(server, options)?;
        let hklm = reg.hklm;
        match reg.open_key(&hklm, SMBCONF) {
            Ok(root) => Ok(Self { reg, root }),
            Err(e) => {
                reg.close();
                Err(e)
            }
        }
    }

    pub fn close(mut self) {
        let root = self.root;
        self.reg.close_key(&root);
        self.reg.close();
    }

    /// The shares that have a key (and `global` if the configuration is all in the registry).
    pub fn sections(&mut self) -> Result<Vec<String>> {
        let root = self.root;
        self.reg.subkeys(&root)
    }

    /// The values of the key of `share`; `None` when it has no key (a share of smb.conf).
    pub fn values(&mut self, share: &str) -> Result<Option<Values>> {
        share_key(share)?;
        let Some(key) = self.open_share(share)? else {
            return Ok(None);
        };
        let read = self.reg.values(&key);
        self.reg.close_key(&key);
        Ok(Some(
            read?
                .into_iter()
                .filter_map(|(name, value)| value.text().map(|t| (name, t)))
                .collect(),
        ))
    }

    fn open_share(&mut self, share: &str) -> Result<Option<Handle>> {
        let root = self.root;
        match self.reg.open_key(&root, share) {
            Ok(key) => Ok(Some(key)),
            Err(Error::Refused {
                code: werror::FILE_NOT_FOUND,
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Creates the key of `share` with `values`, in this order: a share made (the parameters
    /// of `PARAMETERS`) or put back by an undo (the values it had, whatever they are). Refused
    /// if the key exists: nothing of another share is overwritten.
    pub fn create(&mut self, share: &str, values: &[(String, String)]) -> Result<()> {
        share_key(share)?;
        let root = self.root;
        let (key, created) = self.reg.create_key(&root, share)?;
        if !created {
            self.reg.close_key(&key);
            return Err(refused("BaseRegCreateKey", werror::ALREADY_EXISTS));
        }
        let mut written = Ok(());
        for (name, text) in values {
            written = self.reg.set_value(&key, name, &Value::sz(text));
            if written.is_err() {
                break;
            }
        }
        self.reg.close_key(&key);
        written
    }

    /// Sets (`Some`) or removes (`None`) parameters of the key of `share`, which must exist;
    /// parameters outside `PARAMETERS` are refused before anything is written.
    pub fn change(&mut self, share: &str, changes: &[(String, Option<String>)]) -> Result<()> {
        share_key(share)?;
        if changes.iter().any(|(name, _)| !allowed(name)) {
            return Err(refused("winreg (garde)", werror::INVALID_PARAMETER));
        }
        let Some(key) = self.open_share(share)? else {
            return Err(refused("BaseRegOpenKey", werror::FILE_NOT_FOUND));
        };
        let mut written = Ok(());
        for (name, value) in changes {
            written = match value {
                Some(text) => self.reg.set_value(&key, name, &Value::sz(text)),
                None => match self.reg.query_value(&key, name) {
                    Ok(Some(_)) => self.reg.delete_value(&key, name),
                    Ok(None) => Ok(()),
                    Err(e) => Err(e),
                },
            };
            if written.is_err() {
                break;
            }
        }
        self.reg.close_key(&key);
        written
    }

    /// Puts back the values a key had, read from it earlier (the undo of a deletion, after the
    /// « add share command » of the server made the key again): each of `values` set, the
    /// others removed.
    pub fn restore(&mut self, share: &str, values: &[(String, String)]) -> Result<()> {
        share_key(share)?;
        let Some(key) = self.open_share(share)? else {
            return Err(refused("BaseRegOpenKey", werror::FILE_NOT_FOUND));
        };
        let written = (|| {
            let current: Vec<(String, Option<String>)> = self
                .reg
                .values(&key)?
                .into_iter()
                .map(|(n, v)| (n, v.text()))
                .collect();
            for (name, text) in values {
                let same = current
                    .iter()
                    .any(|(n, v)| n.eq_ignore_ascii_case(name) && v.as_deref() == Some(text));
                if !same {
                    self.reg.set_value(&key, name, &Value::sz(text))?;
                }
            }
            for (name, _) in &current {
                if !values.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)) {
                    self.reg.delete_value(&key, name)?;
                }
            }
            Ok(())
        })();
        self.reg.close_key(&key);
        written
    }

    /// Deletes the key of `share` and its values.
    pub fn delete(&mut self, share: &str) -> Result<()> {
        share_key(share)?;
        let root = self.root;
        self.reg.delete_key(&root, share)
    }
}

// --- Stubs -----------------------------------------------------------------------------------

fn handle(w: &mut Writer, h: &Handle) {
    w.align(4);
    w.buf.extend_from_slice(h);
}

fn read_handle(r: &mut Reader<'_>) -> Result<Handle> {
    r.u32("handle")?;
    let start = r.at - 4;
    let mut h = [0u8; 20];
    for (i, b) in h.iter_mut().enumerate() {
        *b = r.u8_at(start + i).ok_or(Short("handle"))?;
    }
    r.at = start + 20;
    Ok(h)
}

fn status(r: &mut Reader<'_>, op: &'static str) -> Result<()> {
    match r.u32("WERROR")? {
        0 => Ok(()),
        code => Err(refused(op, code)),
    }
}

/// `RRP_UNICODE_STRING` of a name sent: lengths in bytes with the final null, then the string
/// (top-level parameter: its data follows at once).
fn name(w: &mut Writer, text: &str) {
    let bytes = (text.encode_utf16().count() + 1) * 2;
    let bytes = u16::try_from(bytes).unwrap_or(u16::MAX);
    w.u16(bytes).u16(bytes).pointer();
    w.string(text);
}

/// `RRP_UNICODE_STRING` of a buffer the server fills: empty, `size` bytes offered.
fn buffer(w: &mut Writer, size: u16) {
    w.u16(0).u16(size).pointer();
    w.u32(u32::from(size / 2)).u32(0).u32(0);
}

/// An `RRP_UNICODE_STRING` answered: lengths, then the string if its pointer is not null.
fn read_name(r: &mut Reader<'_>) -> Result<String> {
    r.u16("name length")?;
    r.u16("name size")?;
    if r.pointer("name")? {
        Ok(r.string("name")?)
    } else {
        Ok(String::new())
    }
}

/// `OpenLocalMachine`: no server name (ignored by the server), access.
pub fn open_local_machine_request(access: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.null().u32(access);
    w.buf
}

/// A handle then the status (`OpenLocalMachine`, `BaseRegOpenKey`, `BaseRegCloseKey`).
pub fn parse_handle(stub: &[u8], op: &'static str) -> Result<Handle> {
    let mut r = Reader::new(stub);
    let h = read_handle(&mut r)?;
    status(&mut r, op)?;
    Ok(h)
}

pub fn parse_status(stub: &[u8], op: &'static str) -> Result<()> {
    status(&mut Reader::new(stub), op)
}

pub fn handle_request(key: &Handle) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, key);
    w.buf
}

/// `BaseRegOpenKey`: parent, path, options 0, access.
pub fn open_key_request(parent: &Handle, path: &str, access: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, parent);
    name(&mut w, path);
    w.u32(0).u32(access);
    w.buf
}

/// `BaseRegCreateKey`: parent, path, no class, options 0 (kept), access, no security
/// attributes, disposition asked.
pub fn create_key_request(parent: &Handle, path: &str, access: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, parent);
    name(&mut w, path);
    w.u16(0).u16(0).null();
    w.u32(0).u32(access);
    w.null();
    w.pointer().u32(0);
    w.buf
}

/// The new key and its disposition (1: made, 2: there already).
pub fn parse_create_key(stub: &[u8]) -> Result<(Handle, Option<u32>)> {
    let mut r = Reader::new(stub);
    let h = read_handle(&mut r)?;
    let disposition = if r.pointer("disposition")? {
        Some(r.u32("disposition")?)
    } else {
        None
    };
    status(&mut r, "BaseRegCreateKey")?;
    Ok((h, disposition))
}

/// `BaseRegDeleteKey`, `BaseRegDeleteValue`: a key and a name.
pub fn name_request(key: &Handle, text: &str) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, key);
    name(&mut w, text);
    w.buf
}

/// `BaseRegSetValue`: key, name, type, data (reference pointer: the array alone), size.
pub fn set_value_request(key: &Handle, value_name: &str, value: &Value) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, key);
    name(&mut w, value_name);
    w.u32(value.kind);
    w.bytes(&value.data);
    w.u32(u32::try_from(value.data.len()).unwrap_or(u32::MAX));
    w.buf
}

/// `BaseRegQueryValue`: key, name, type, a buffer of `size` bytes, its size, no length.
pub fn query_value_request(key: &Handle, value_name: &str, size: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, key);
    name(&mut w, value_name);
    data_buffer(&mut w, size);
    w.buf
}

/// Type, data, size and length asked (`BaseRegQueryValue`, `BaseRegEnumValue`).
fn data_buffer(w: &mut Writer, size: u32) {
    w.pointer().u32(0);
    w.pointer().u32(size).u32(0).u32(0);
    w.pointer().u32(size);
    w.pointer().u32(0);
}

/// Type, data, size and length answered.
fn read_data(r: &mut Reader<'_>, op: &'static str) -> Result<Value> {
    let kind = if r.pointer("type")? {
        r.u32("type")?
    } else {
        0
    };
    let mut data = Vec::new();
    if r.pointer("data")? {
        let _max = r.u32("data max")?;
        let offset = r.u32("data offset")?;
        let len = r.u32("data length")? as usize;
        if offset != 0 || len > r.remaining() {
            return Err(Short("data").into());
        }
        for i in 0..len {
            data.push(r.u8_at(r.at + i).ok_or(Short("data"))?);
        }
        r.at += len;
    }
    let size = if r.pointer("size")? {
        Some(r.u32("size")?)
    } else {
        None
    };
    let length = if r.pointer("length")? {
        Some(r.u32("length")?)
    } else {
        None
    };
    status(r, op)?;
    // The length says how much of the data is the value.
    if let Some(n) = length.or(size) {
        data.truncate(n as usize);
    }
    Ok(Value { kind, data })
}

pub fn parse_query_value(stub: &[u8]) -> Result<Value> {
    read_data(&mut Reader::new(stub), "BaseRegQueryValue")
}

/// `BaseRegEnumKey`: key, index, a name buffer, a class buffer and a time (Samba refuses the
/// call without the class: `WERR_INVALID_PARAMETER`).
pub fn enum_key_request(key: &Handle, index: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, key);
    w.u32(index);
    buffer(&mut w, NAME_BUFFER);
    w.pointer();
    buffer(&mut w, NAME_BUFFER);
    w.pointer().u32(0).u32(0);
    w.buf
}

/// The name of the subkey; `None` past the last one.
pub fn parse_enum_key(stub: &[u8]) -> Result<Option<String>> {
    let mut r = Reader::new(stub);
    let key = read_name(&mut r)?;
    if r.pointer("class")? {
        read_name(&mut r)?;
    }
    if r.pointer("time")? {
        r.u32("time low")?;
        r.u32("time high")?;
    }
    match status(&mut r, "BaseRegEnumKey") {
        Ok(()) => Ok(Some(key)),
        Err(Error::Refused {
            code: werror::NO_MORE_ITEMS,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

/// `BaseRegEnumValue`: key, index, a name buffer, then type, data, size, length.
pub fn enum_value_request(key: &Handle, index: u32, size: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, key);
    w.u32(index);
    buffer(&mut w, NAME_BUFFER);
    data_buffer(&mut w, size);
    w.buf
}

/// The name and the value; `None` past the last one.
pub fn parse_enum_value(stub: &[u8]) -> Result<Option<(String, Value)>> {
    let mut r = Reader::new(stub);
    let value_name = read_name(&mut r)?;
    match read_data(&mut r, "BaseRegEnumValue") {
        Ok(v) => Ok(Some((value_name, v))),
        Err(Error::Refused {
            code: werror::NO_MORE_ITEMS,
            ..
        }) => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_uuid() {
        // 338cd001-2244-31f1-aaaa-900038001003
        assert_eq!(
            INTERFACE.uuid,
            [
                0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31, 0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00,
                0x10, 0x03
            ]
        );
        assert_eq!((INTERFACE.major, INTERFACE.minor), (1, 0));
    }

    #[test]
    fn the_guard_keeps_to_one_share() {
        assert_eq!(
            share_key("Essai-Calinda").unwrap(),
            "Software\\Samba\\smbconf\\Essai-Calinda"
        );
        assert_eq!(
            share_key("Vecteurs-Été").unwrap(),
            "Software\\Samba\\smbconf\\Vecteurs-Été"
        );
        for bad in [
            "",
            "global",
            "GLOBAL",
            "homes",
            "Printers",
            "a\\b",
            "..\\..\\Microsoft",
            "a/b",
            " a",
            "a\tb",
            &"x".repeat(81),
        ] {
            assert_eq!(
                share_key(bad),
                Err(Error::Refused {
                    op: "winreg (garde)",
                    code: werror::INVALID_NAME
                }),
                "{bad:?}"
            );
        }
        for p in PARAMETERS {
            assert!(allowed(p));
        }
        for p in [
            "Path",
            "root preexec",
            "vfs objects",
            "include",
            "writeable",
            "",
        ] {
            assert!(!allowed(p), "{p}");
        }
    }

    #[test]
    fn values_as_samba_reads_them() {
        let v = Value::sz("Été");
        assert_eq!(v.data, [0xc9, 0, b't', 0, 0xe9, 0, 0, 0]);
        assert_eq!(v.text().as_deref(), Some("Été"));
        let n = Value {
            kind: kind::DWORD,
            data: 25u32.to_le_bytes().to_vec(),
        };
        assert_eq!(n.text().as_deref(), Some("25"));
        let b = Value {
            kind: 3,
            data: vec![1],
        };
        assert_eq!(b.text(), None);
    }

    #[test]
    fn request_layouts() {
        let h = [7u8; 20];
        assert_eq!(
            open_local_machine_request(MAXIMUM_ALLOWED),
            [0, 0, 0, 0, 0, 0, 0, 2]
        );
        let stub = open_key_request(&h, "ab", MAXIMUM_ALLOWED);
        let mut r = Reader::new(&stub);
        assert_eq!(read_handle(&mut r).unwrap(), h);
        assert_eq!(r.u16("len").unwrap(), 6);
        assert_eq!(r.u16("size").unwrap(), 6);
        assert!(r.pointer("name").unwrap());
        assert_eq!(r.string("name").unwrap(), "ab");
        assert_eq!(r.u32("options").unwrap(), 0);
        assert_eq!(r.u32("access").unwrap(), MAXIMUM_ALLOWED);
        assert_eq!(r.remaining(), 0);

        let stub = set_value_request(&h, "path", &Value::sz("/srv"));
        let mut r = Reader::new(&stub);
        read_handle(&mut r).unwrap();
        read_name(&mut r).unwrap();
        assert_eq!(r.u32("type").unwrap(), kind::SZ);
        assert_eq!(r.bytes("data").unwrap(), Value::sz("/srv").data);
        assert_eq!(r.u32("size").unwrap(), 10);
        assert_eq!(r.remaining(), 0);

        let stub = enum_value_request(&h, 3, BUFFER);
        let mut r = Reader::new(&stub);
        read_handle(&mut r).unwrap();
        assert_eq!(r.u32("index").unwrap(), 3);
        assert_eq!(r.u16("len").unwrap(), 0);
        assert_eq!(r.u16("size").unwrap(), NAME_BUFFER);
        assert!(r.pointer("name").unwrap());
        assert_eq!(r.u32("max").unwrap(), u32::from(NAME_BUFFER / 2));
        assert_eq!(r.u32("offset").unwrap(), 0);
        assert_eq!(r.u32("actual").unwrap(), 0);
        assert!(r.pointer("type").unwrap());
        assert_eq!(r.u32("type").unwrap(), 0);
        assert!(r.pointer("data").unwrap());
        assert_eq!(r.u32("max").unwrap(), BUFFER);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn handle_of(s: &str) -> Handle {
        unhex(s).try_into().unwrap()
    }

    /// Stubs of Samba (fs1, dc1), `tests/vecteurs/winreg.json`: each answer read as a
    /// separate Python decoder of the lab (not published) reads it, each request written again as it was sent.
    #[test]
    fn vectors_of_samba() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vecteurs/winreg.json");
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = file["vecteurs"].as_array().unwrap();
        assert_eq!(vectors.len(), 41);
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let call = v["provenance"]["appel"].as_str().unwrap();
            let q = &v["requete"];
            let e = &v["attendu"];
            let stub = unhex(v["hex"].as_str().unwrap());
            let werror = e["werror"].as_u64().unwrap() as u32;
            let refused = |r: Error| match r {
                Error::Refused { code, .. } => code,
                other => panic!("{id}: {other:?}"),
            };
            let key = || handle_of(q["cle"].as_str().unwrap());
            let text = |k: &str| q[k].as_str().unwrap().to_owned();
            let number = |k: &str| q[k].as_u64().unwrap() as u32;
            let request = match call {
                "OpenLocalMachine" | "BaseRegOpenKey" | "BaseRegCloseKey" => {
                    match parse_handle(&stub, "x") {
                        Ok(h) => {
                            assert_eq!(werror, 0, "{id}");
                            assert_eq!(h, handle_of(e["poignee"].as_str().unwrap()), "{id}");
                        }
                        Err(r) => assert_eq!(refused(r), werror, "{id}"),
                    }
                    match call {
                        "OpenLocalMachine" => open_local_machine_request(number("acces")),
                        "BaseRegOpenKey" => open_key_request(&key(), &text("nom"), number("acces")),
                        _ => handle_request(&key()),
                    }
                }
                "BaseRegCreateKey" => {
                    let (h, disposition) = parse_create_key(&stub).unwrap();
                    assert_eq!(h, handle_of(e["poignee"].as_str().unwrap()), "{id}");
                    assert_eq!(disposition, Some(CREATED_NEW_KEY), "{id}");
                    create_key_request(&key(), &text("nom"), number("acces"))
                }
                "BaseRegEnumKey" => {
                    let name = parse_enum_key(&stub).unwrap();
                    if werror == 0 {
                        assert_eq!(name.as_deref(), e["nom"].as_str(), "{id}");
                    } else {
                        assert_eq!((name, werror), (None, NO_MORE), "{id}");
                    }
                    enum_key_request(&key(), number("index"))
                }
                "BaseRegEnumValue" => {
                    let read = parse_enum_value(&stub).unwrap();
                    if werror == 0 {
                        let (name, value) = read.unwrap();
                        assert_eq!(name, e["nom"].as_str().unwrap(), "{id}");
                        assert_eq!(u64::from(value.kind), e["type"].as_u64().unwrap(), "{id}");
                        assert_eq!(
                            value.data,
                            unhex(e["donnees_hex"].as_str().unwrap()),
                            "{id}"
                        );
                        assert_eq!(value.text().as_deref(), e["texte"].as_str(), "{id}");
                    } else {
                        assert_eq!((read, werror), (None, NO_MORE), "{id}");
                    }
                    enum_value_request(&key(), number("index"), number("taille"))
                }
                "BaseRegQueryValue" => {
                    match parse_query_value(&stub) {
                        Ok(value) => {
                            assert_eq!(werror, 0, "{id}");
                            assert_eq!(value.text().as_deref(), e["texte"].as_str(), "{id}");
                        }
                        Err(r) => assert_eq!(refused(r), werror, "{id}"),
                    }
                    query_value_request(&key(), &text("nom"), number("taille"))
                }
                "BaseRegSetValue" => {
                    assert_eq!(parse_status(&stub, "x"), Ok(()), "{id}");
                    set_value_request(&key(), &text("nom"), &Value::sz(&text("valeur")))
                }
                "BaseRegDeleteValue" | "BaseRegDeleteKey" => {
                    assert_eq!(parse_status(&stub, "x"), Ok(()), "{id}");
                    name_request(&key(), &text("nom"))
                }
                other => panic!("{other}"),
            };
            assert_eq!(request, unhex(v["requete_hex"].as_str().unwrap()), "{id}");
        }
    }

    const NO_MORE: u32 = werror::NO_MORE_ITEMS;

    /// An answer of `BaseRegEnumValue` as a server lays it out.
    fn enum_value_answer(value_name: &str, value: &Value, status: u32) -> Vec<u8> {
        let mut w = Writer::new();
        let bytes = ((value_name.encode_utf16().count() + 1) * 2) as u16;
        w.u16(bytes).u16(NAME_BUFFER).pointer();
        w.string(value_name);
        w.pointer().u32(value.kind);
        let n = value.data.len() as u32;
        w.pointer().u32(BUFFER).u32(0).u32(n);
        w.buf.extend_from_slice(&value.data);
        w.pointer().u32(n);
        w.pointer().u32(n);
        w.u32(status);
        w.buf
    }

    #[test]
    fn answers_are_read() {
        let v = Value::sz("/srv/partages/Commun");
        assert_eq!(
            parse_enum_value(&enum_value_answer("path", &v, 0)).unwrap(),
            Some(("path".into(), v.clone()))
        );
        assert_eq!(
            parse_enum_value(&enum_value_answer(
                "",
                &Value {
                    kind: 0,
                    data: vec![]
                },
                259
            ))
            .unwrap(),
            None
        );
        assert_eq!(
            parse_enum_value(&enum_value_answer("x", &v, 5)),
            Err(Error::Refused {
                op: "BaseRegEnumValue",
                code: 5
            })
        );
        // A length beyond the stub.
        let mut bad = enum_value_answer("path", &v, 0);
        bad.truncate(bad.len() - 30);
        assert!(parse_enum_value(&bad).is_err());
    }
}

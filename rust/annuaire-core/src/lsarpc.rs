// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Names of SIDs as a server knows them, through the Local Security Authority (Translation
//! Methods) Remote Protocol (MS-LSAT), on the pipe `lsarpc` of `IPC$` (ADR 0023 § 5): the
//! accounts and groups local to a file server (`FS1\J84-Local`, `BUILTIN\Users`) are not in
//! the directory, the « Security » tab names them by the server. `LsarOpenPolicy2`,
//! `LsarLookupSids2`, `LsarClose`; nothing else.

use std::collections::HashMap;

use annuaire_codecs::Sid;

use crate::rpc::ndr::{Reader, Short, Writer};
use crate::rpc::{Rpc, RpcError, Syntax};
use crate::smb::client::Options;
use crate::smb::pipe::Pipe;

/// `lsarpc` v0.0 (MS-LSAT 1.9).
pub const INTERFACE: Syntax = Syntax::new(0x1234_5778_1234_abcd_ef00_0123_4567_89ab, 0, 0);

pub mod opnum {
    pub const CLOSE: u16 = 0;
    pub const OPEN_POLICY2: u16 = 44;
    pub const LOOKUP_SIDS2: u16 = 57;
}

/// `POLICY_LOOKUP_NAMES` (MS-LSAD 2.2.1.1.2).
pub const POLICY_LOOKUP_NAMES: u32 = 0x0000_0800;
/// `LsapLookupWksta`: the names the server itself knows, its domain and the trusted ones.
pub const LOOKUP_WKSTA: u16 = 1;
pub const CLIENT_REVISION: u32 = 1;

pub mod status {
    pub const SUCCESS: u32 = 0;
    pub const SOME_NOT_MAPPED: u32 = 0x0000_0107;
    pub const NONE_MAPPED: u32 = 0xC000_0073;
}

/// `SID_NAME_USE` values that name nothing.
const USE_UNKNOWN: u16 = 8;
const USE_INVALID: u16 = 7;
const USE_DELETED: u16 = 6;
const USE_WELL_KNOWN: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Rpc(RpcError),
    Refused { op: &'static str, code: u32 },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => write!(f, "{e}"),
            Self::Refused { op, code } => write!(f, "{op} refused: NTSTATUS 0x{code:08X}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<RpcError> for Error {
    fn from(e: RpcError) -> Self {
        Self::Rpc(e)
    }
}

impl From<Short> for Error {
    fn from(e: Short) -> Self {
        Self::Rpc(e.into())
    }
}

impl From<crate::smb::SmbError> for Error {
    fn from(e: crate::smb::SmbError) -> Self {
        Self::Rpc(e.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub type Handle = [u8; 20];

/// A bound connection to the LSA of a server, with its policy handle.
#[derive(Debug)]
pub struct Lsa {
    rpc: Rpc<Pipe>,
    policy: Handle,
}

impl Lsa {
    /// Opens `\\server\IPC$`, the pipe `lsarpc`, binds and opens the policy. Blocking.
    pub fn open(server: &str, options: &Options) -> Result<Self> {
        let pipe = Pipe::open(server, "lsarpc", options)?;
        let mut rpc = Rpc::bind(pipe, INTERFACE)?;
        let stub = rpc.call(
            opnum::OPEN_POLICY2,
            &open_policy2_request(&format!("\\\\{server}"), POLICY_LOOKUP_NAMES),
        )?;
        let policy = parse_handle(&stub, "LsarOpenPolicy2")?;
        Ok(Self { rpc, policy })
    }

    pub fn close(mut self) {
        let policy = self.policy;
        if let Ok(stub) = self.rpc.call(opnum::CLOSE, &close_request(&policy)) {
            let _ = parse_handle(&stub, "LsarClose");
        }
        self.rpc.into_transport().close();
    }

    /// The names of `sids` the server knows (`DOMAIN\name`, or the name alone for a
    /// well-known group); the others are left out.
    pub fn names(&mut self, sids: &[Sid]) -> Result<HashMap<Sid, String>> {
        if sids.is_empty() {
            return Ok(HashMap::new());
        }
        let stub = self.rpc.call(
            opnum::LOOKUP_SIDS2,
            &lookup_sids2_request(&self.policy, sids),
        )?;
        let names = parse_lookup_sids2(&stub)?;
        Ok(sids
            .iter()
            .zip(names)
            .filter_map(|(s, n)| n.map(|n| (*s, n)))
            .collect())
    }
}

/// The names of `sids` on `server`, in one session: open, look up, close. Blocking.
pub fn name_sids(server: &str, sids: &[Sid], options: &Options) -> Result<HashMap<Sid, String>> {
    let mut lsa = Lsa::open(server, options)?;
    let names = lsa.names(sids);
    lsa.close();
    names
}

// -- NDR pieces -----------------------------------------------------------------------------

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

fn sid(w: &mut Writer, sid: &Sid) {
    w.u32(sid.sub_authorities().len() as u32);
    w.buf.extend_from_slice(&sid.encode());
}

fn skip_sid(r: &mut Reader<'_>) -> Result<()> {
    let count = r.u32("SID count")? as usize;
    let len = 8 + 4 * count;
    if count > 15 || r.remaining() < len {
        return Err(Short("SID").into());
    }
    r.at += len;
    Ok(())
}

/// The header of an `RPC_UNICODE_STRING` in a structure: lengths, and whether its buffer
/// follows (deferred). The structure holds a pointer: it is aligned on 4.
fn string_header(r: &mut Reader<'_>) -> Result<bool> {
    r.at = r.at.div_ceil(4) * 4;
    r.u16("length")?;
    r.u16("maximum length")?;
    Ok(r.pointer("buffer")?)
}

fn check(r: &mut Reader<'_>, op: &'static str) -> Result<u32> {
    match r.u32("NTSTATUS")? {
        code @ (status::SUCCESS | status::SOME_NOT_MAPPED) => Ok(code),
        status::NONE_MAPPED if op == "LsarLookupSids2" => Ok(status::NONE_MAPPED),
        code => Err(Error::Refused { op, code }),
    }
}

// -- Stubs ----------------------------------------------------------------------------------

/// `LsarOpenPolicy2`: system name, `LSAPR_OBJECT_ATTRIBUTES` (length 24, all null, which the
/// server ignores), access.
pub fn open_policy2_request(unc: &str, access: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.unique_string(Some(unc));
    w.u32(24).null().null().u32(0).null().null();
    w.u32(access);
    w.buf
}

/// A handle then the status (`LsarOpenPolicy2`, `LsarClose`).
pub fn parse_handle(stub: &[u8], op: &'static str) -> Result<Handle> {
    let mut r = Reader::new(stub);
    let h = read_handle(&mut r)?;
    check(&mut r, op)?;
    Ok(h)
}

pub fn close_request(h: &Handle) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, h);
    w.buf
}

/// `LsarLookupSids2`: `LSAPR_SID_ENUM_BUFFER` (count, array of pointers to the SIDs, deferred),
/// an empty `LSAPR_TRANSLATED_NAMES_EX`, the level, the mapped count (`[in, out]`, 0), options
/// 0, client revision 1.
pub fn lookup_sids2_request(policy: &Handle, sids: &[Sid]) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, policy);
    let count = sids.len() as u32;
    w.u32(count).pointer_if(!sids.is_empty());
    if !sids.is_empty() {
        w.u32(count);
        for _ in sids {
            w.pointer();
        }
        for s in sids {
            sid(&mut w, s);
        }
    }
    w.u32(0).null();
    w.u16(LOOKUP_WKSTA);
    w.u32(0).u32(0).u32(CLIENT_REVISION);
    w.buf
}

/// Per SID asked, in order: its name, `DOMAIN\name` (the name alone for a well-known group
/// or a domain without a name), or `None` if the server does not know it.
pub fn parse_lookup_sids2(stub: &[u8]) -> Result<Vec<Option<String>>> {
    let mut r = Reader::new(stub);
    // LSAPR_REFERENCED_DOMAIN_LIST
    let mut domains: Vec<String> = Vec::new();
    if r.pointer("domains")? {
        let entries = r.u32("domain entries")? as usize;
        let present = r.pointer("domain array")?;
        let _max_entries = r.u32("max entries")?;
        if present {
            let max = r.u32("domain array")? as usize;
            if entries > max || entries > r.remaining() / 12 {
                return Err(Short("domain count").into());
            }
            let mut members = Vec::with_capacity(entries);
            for _ in 0..entries {
                let name = string_header(&mut r)?;
                let sid = r.pointer("domain sid")?;
                members.push((name, sid));
            }
            for (name, sid) in members {
                domains.push(if name {
                    r.string("domain name")?
                } else {
                    String::new()
                });
                if sid {
                    skip_sid(&mut r)?;
                }
            }
        }
    }
    // LSAPR_TRANSLATED_NAMES_EX
    let entries = r.u32("name entries")? as usize;
    let mut names = Vec::new();
    if r.pointer("name array")? {
        let max = r.u32("name array")? as usize;
        if entries > max || entries > r.remaining() / 20 {
            return Err(Short("name count").into());
        }
        let mut members = Vec::with_capacity(entries);
        for _ in 0..entries {
            let kind = r.u16("use")?;
            let name = string_header(&mut r)?;
            let index = r.u32("domain index")? as i32;
            let _flags = r.u32("flags")?;
            members.push((kind, name, index));
        }
        for (kind, name, index) in members {
            let text = if name {
                r.string("name")?
            } else {
                String::new()
            };
            let known =
                !matches!(kind, USE_UNKNOWN | USE_INVALID | USE_DELETED) && !text.is_empty();
            let domain = usize::try_from(index)
                .ok()
                .and_then(|i| domains.get(i))
                .filter(|d| !d.is_empty() && kind != USE_WELL_KNOWN);
            names.push(known.then(|| match domain {
                Some(d) => format!("{d}\\{text}"),
                None => text,
            }));
        }
    }
    let _mapped = r.u32("mapped count")?;
    check(&mut r, "LsarLookupSids2")?;
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Sid {
        text.parse().unwrap()
    }

    fn unicode(w: &mut Writer, text: &str) {
        let units: Vec<u16> = text.encode_utf16().collect();
        let n = units.len() as u32;
        w.u32(n).u32(0).u32(n);
        for u in units {
            w.buf.extend_from_slice(&u.to_le_bytes());
        }
    }

    #[test]
    fn interface_uuid() {
        // 12345778-1234-abcd-ef00-0123456789ab
        assert_eq!(
            INTERFACE.uuid,
            [
                0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xab
            ]
        );
    }

    #[test]
    fn open_policy_layout() {
        let stub = open_policy2_request("\\\\fs1", POLICY_LOOKUP_NAMES);
        let mut r = Reader::new(&stub);
        assert!(r.pointer("name").unwrap());
        assert_eq!(r.string("name").unwrap(), "\\\\fs1");
        assert_eq!(r.u32("length").unwrap(), 24);
        for _ in 0..5 {
            assert_eq!(r.u32("field").unwrap(), 0);
        }
        assert_eq!(r.u32("access").unwrap(), POLICY_LOOKUP_NAMES);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn lookup_request_layout() {
        let h = [3u8; 20];
        let stub = lookup_sids2_request(&h, &[s("S-1-5-21-1-2-3-1000"), s("S-1-5-32-545")]);
        let mut r = Reader::new(&stub);
        assert_eq!(read_handle(&mut r).unwrap(), h);
        assert_eq!(r.u32("entries").unwrap(), 2);
        assert!(r.pointer("array").unwrap());
        assert_eq!(r.u32("max").unwrap(), 2);
        assert!(r.pointer("p1").unwrap());
        assert!(r.pointer("p2").unwrap());
        skip_sid(&mut r).unwrap();
        skip_sid(&mut r).unwrap();
        assert_eq!(r.u32("names").unwrap(), 0);
        assert!(!r.pointer("names").unwrap());
        assert_eq!(r.u16("level").unwrap(), LOOKUP_WKSTA);
        assert_eq!(r.u32("mapped count").unwrap(), 0);
        assert_eq!(r.u32("options").unwrap(), 0);
        assert_eq!(r.u32("revision").unwrap(), CLIENT_REVISION);
        assert_eq!(r.remaining(), 0);
    }

    /// A response as a server builds it: two domains, three names, one of them unknown.
    #[test]
    fn lookup_response() {
        let mut w = Writer::new();
        // Referenced domains: FS1 and BUILTIN.
        w.pointer().u32(2).pointer().u32(32).u32(2);
        for name in ["FS1", "BUILTIN"] {
            let n = (name.len() * 2) as u16;
            w.u16(n).u16(n).pointer().pointer();
        }
        for (name, domain) in [("FS1", "S-1-5-21-1-2-3"), ("BUILTIN", "S-1-5-32")] {
            unicode(&mut w, name);
            sid(&mut w, &s(domain));
        }
        // Names: an alias of FS1, a well-known group, an unknown SID.
        w.u32(3).pointer().u32(3);
        for (kind, name, index) in [
            (4u16, "J84-Local", 0u32),
            (5, "Everyone", u32::MAX),
            (8, "", u32::MAX),
        ] {
            let n = (name.len() * 2) as u16;
            w.u16(kind)
                .align(4)
                .u16(n)
                .u16(n)
                .pointer_if(!name.is_empty());
            w.u32(index).u32(0);
        }
        unicode(&mut w, "J84-Local");
        unicode(&mut w, "Everyone");
        w.u32(2).u32(status::SOME_NOT_MAPPED);
        let names = parse_lookup_sids2(&w.buf).unwrap();
        assert_eq!(
            names,
            [Some("FS1\\J84-Local".into()), Some("Everyone".into()), None]
        );
        // None mapped: names unknown, not an error.
        let mut w = Writer::new();
        w.null().u32(1).pointer().u32(1);
        w.u16(8).align(4).u16(0).u16(0).null().u32(u32::MAX).u32(0);
        w.u32(0).u32(status::NONE_MAPPED);
        assert_eq!(parse_lookup_sids2(&w.buf).unwrap(), [None]);
        // Refused.
        let mut w = Writer::new();
        w.null().u32(0).null().u32(0).u32(0xC000_0022);
        assert_eq!(
            parse_lookup_sids2(&w.buf),
            Err(Error::Refused {
                op: "LsarLookupSids2",
                code: 0xC000_0022
            })
        );
    }
}

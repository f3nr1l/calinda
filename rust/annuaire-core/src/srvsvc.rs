// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The shares of a file server through the Server Service Remote Protocol (MS-SRVS), on the
//! pipe `srvsvc` of `IPC$` (ADR 0023 § 1 and 3): list, read, add, change (descriptor,
//! options, path and comment) and delete.

use crate::rpc::ndr::{Reader, Short, Writer};
use crate::rpc::{Rpc, RpcError, Syntax};
use crate::smb::client::Options;
use crate::smb::pipe::Pipe;

/// `srvsvc` v3.0 (MS-SRVS 1.9).
pub const INTERFACE: Syntax = Syntax::new(0x4b32_4fc8_1670_01d3_1278_5a47_bf6e_e188, 3, 0);

mod opnum {
    pub const SHARE_ADD: u16 = 14;
    pub const SHARE_ENUM_ALL: u16 = 15;
    pub const SHARE_GET_INFO: u16 = 16;
    pub const SHARE_SET_INFO: u16 = 17;
    pub const SHARE_DEL: u16 = 18;
    pub const SERVER_GET_INFO: u16 = 21;
}

/// Server types of `SERVER_INFO_101` (MS-SRVS 2.2.2.7): Samba announces itself a Unix server
/// (`SV_TYPE_SERVER_UNIX`), Windows never does.
pub mod sv_type {
    pub const SERVER_UNIX: u32 = 0x0000_0800;
}

/// Share types (MS-SRVS 2.2.2.4).
pub mod stype {
    pub const DISKTREE: u32 = 0x0000_0000;
    pub const PRINTQ: u32 = 0x0000_0001;
    pub const DEVICE: u32 = 0x0000_0002;
    pub const IPC: u32 = 0x0000_0003;
    pub const BASE: u32 = 0x0000_00FF;
    pub const TEMPORARY: u32 = 0x4000_0000;
    pub const SPECIAL: u32 = 0x8000_0000;
}

/// Share flags of `SHARE_INFO_1005` (MS-SRVS 2.2.4.29).
pub mod flags {
    /// Offline caching (`CSC_MASK`): 0 manual, 0x10 documents, 0x20 programs, 0x30 none.
    pub const CSC_MASK: u32 = 0x0000_0030;
    pub const CSC_MANUAL: u32 = 0x0000_0000;
    pub const CSC_AUTO: u32 = 0x0000_0010;
    pub const CSC_VDO: u32 = 0x0000_0020;
    pub const CSC_NONE: u32 = 0x0000_0030;
    pub const ACCESS_BASED_DIRECTORY_ENUM: u32 = 0x0000_0800;
    pub const ENCRYPT_DATA: u32 = 0x0000_8000;
}

/// Win32 errors the server returns (`WERROR`, `NET_API_STATUS`).
pub mod werror {
    pub const ACCESS_DENIED: u32 = 5;
    pub const NOT_SUPPORTED: u32 = 50;
    /// What Samba answers to a share that already exists (Windows: 2118).
    pub const FILE_EXISTS: u32 = 80;
    pub const INVALID_PARAMETER: u32 = 87;
    /// What Samba answers to a share that does not exist (Windows: 2310).
    pub const INVALID_NAME: u32 = 123;
    pub const INVALID_LEVEL: u32 = 124;
    pub const MORE_DATA: u32 = 234;
    pub const FILE_NOT_FOUND: u32 = 2;
    pub const PATH_NOT_FOUND: u32 = 3;
    pub const BAD_PATHNAME: u32 = 161;
    pub const NERR_UNKNOWN_DEVICE_DIR: u32 = 2116;
    pub const NERR_DUPLICATE_SHARE: u32 = 2118;
    pub const NERR_NET_NAME_NOT_FOUND: u32 = 2310;
}

/// What a call to the service gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Transport or protocol.
    Rpc(RpcError),
    /// The server refused the operation (`op`) with a Win32 error.
    Refused { op: &'static str, code: u32 },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rpc(e) => write!(f, "{e}"),
            Self::Refused { op, code } => write!(f, "{op} refused: Win32 error {code}"),
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

/// A share as `SHARE_INFO_502` describes it; fields of level 1 only when the account may not
/// read more (`path` empty, `descriptor` absent).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Share {
    pub name: String,
    pub kind: u32,
    pub remark: String,
    /// Maximum connections; `u32::MAX` for no limit.
    pub max_uses: u32,
    pub current_uses: u32,
    /// Local path on the server (`C:\Partages\Commun`, `/srv/partages/Commun`).
    pub path: String,
    /// Self-relative security descriptor of the share; absent when the share has none (all
    /// allowed) or when it was not read.
    pub descriptor: Option<Vec<u8>>,
    /// Level the share was read at (1 or 502).
    pub level: u32,
}

impl Share {
    /// A disk share of the user (not `IPC$`, an administrative `C$`, a printer…).
    pub fn is_disk(&self) -> bool {
        self.kind & stype::BASE == stype::DISKTREE
    }

    pub fn is_special(&self) -> bool {
        self.kind & stype::SPECIAL != 0
    }
}

/// A bound connection to the service of one server.
#[derive(Debug)]
pub struct Srvsvc {
    rpc: Rpc<Pipe>,
    /// `\\server`, as every call names it.
    unc: String,
}

impl Srvsvc {
    /// Opens `\\server\IPC$`, the pipe `srvsvc`, and binds. Blocking.
    pub fn open(server: &str, options: &Options) -> Result<Self> {
        let pipe = Pipe::open(server, "srvsvc", options)?;
        Self::on(pipe, server)
    }

    pub fn on(pipe: Pipe, server: &str) -> Result<Self> {
        Ok(Self {
            rpc: Rpc::bind(pipe, INTERFACE)?,
            unc: format!("\\\\{server}"),
        })
    }

    pub fn close(self) {
        self.rpc.into_transport().close();
    }

    /// The type of the server (`SERVER_INFO_101`, `sv101_type`).
    pub fn server_type(&mut self) -> Result<u32> {
        let stub = self
            .rpc
            .call(opnum::SERVER_GET_INFO, &server_info_request(&self.unc))?;
        parse_server_info_101(&stub)
    }

    /// Every share at level 502, or at level 1 when the server refuses 502 to the account.
    pub fn shares(&mut self) -> Result<Vec<Share>> {
        match self.enumerate(502) {
            Err(Error::Refused {
                code: werror::ACCESS_DENIED,
                ..
            }) => self.enumerate(1),
            other => other,
        }
    }

    /// The names and kinds of the shares (level 1). Samba loads again the shares of its
    /// registry configuration on an enumeration only: a share changed by `net conf` is read
    /// as it was by `NetrShareGetInfo` until then.
    pub fn names(&mut self) -> Result<Vec<Share>> {
        self.enumerate(1)
    }

    fn enumerate(&mut self, level: u32) -> Result<Vec<Share>> {
        let stub = self
            .rpc
            .call(opnum::SHARE_ENUM_ALL, &enum_request(&self.unc, level))?;
        parse_enum(&stub)
    }

    /// One share at level 502.
    pub fn share(&mut self, name: &str) -> Result<Share> {
        let stub = self
            .rpc
            .call(opnum::SHARE_GET_INFO, &get_request(&self.unc, name, 502))?;
        parse_get_502(&stub)
    }

    /// Flags of `SHARE_INFO_1005` (offline caching, access-based enumeration).
    pub fn share_flags(&mut self, name: &str) -> Result<u32> {
        let stub = self
            .rpc
            .call(opnum::SHARE_GET_INFO, &get_request(&self.unc, name, 1005))?;
        parse_get_1005(&stub)
    }

    /// Replaces the descriptor of a share (`SHARE_INFO_1501`).
    pub fn set_descriptor(&mut self, name: &str, descriptor: &[u8]) -> Result<()> {
        let mut w = set_header(&self.unc, name, 1501);
        w.pointer();
        w.u32(len32(descriptor)).pointer();
        w.bytes(descriptor);
        w.pointer().u32(0);
        let stub = self.rpc.call(opnum::SHARE_SET_INFO, &w.buf)?;
        parse_parm_error(&stub, "NetrShareSetInfo")
    }

    /// Replaces the flags of a share (`SHARE_INFO_1005`).
    pub fn set_flags(&mut self, name: &str, flags: u32) -> Result<()> {
        let mut w = set_header(&self.unc, name, 1005);
        w.pointer();
        w.u32(flags);
        w.pointer().u32(0);
        let stub = self.rpc.call(opnum::SHARE_SET_INFO, &w.buf)?;
        parse_parm_error(&stub, "NetrShareSetInfo")
    }

    /// Changes path, comment, maximum connections and descriptor (`SHARE_INFO_502`).
    pub fn set_share(&mut self, share: &Share) -> Result<()> {
        let mut w = set_header(&self.unc, &share.name, 502);
        w.pointer();
        write_502(&mut w, share);
        w.pointer().u32(0);
        let stub = self.rpc.call(opnum::SHARE_SET_INFO, &w.buf)?;
        parse_parm_error(&stub, "NetrShareSetInfo")
    }

    /// Creates a share; the folder must exist on the server.
    pub fn add(&mut self, share: &Share) -> Result<()> {
        let mut w = Writer::new();
        w.unique_string(Some(&self.unc));
        w.u32(502).u32(502).pointer();
        write_502(&mut w, share);
        w.pointer().u32(0);
        let stub = self.rpc.call(opnum::SHARE_ADD, &w.buf)?;
        parse_parm_error(&stub, "NetrShareAdd")
    }

    /// Deletes a share; the folder stays.
    pub fn delete(&mut self, name: &str) -> Result<()> {
        let mut w = Writer::new();
        w.unique_string(Some(&self.unc));
        w.string(name).u32(0);
        let stub = self.rpc.call(opnum::SHARE_DEL, &w.buf)?;
        status(&mut Reader::new(&stub), "NetrShareDel")
    }
}

fn len32(b: &[u8]) -> u32 {
    u32::try_from(b.len()).unwrap_or(u32::MAX)
}

fn status(r: &mut Reader<'_>, op: &'static str) -> Result<()> {
    match r.u32("WERROR")? {
        0 => Ok(()),
        code => Err(Error::Refused { op, code }),
    }
}

// -- Stubs ----------------------------------------------------------------------------------

/// `NetrShareEnum`: server, `SHARE_ENUM_STRUCT` with an empty container of `level`, no
/// maximum, resume handle 0.
pub fn enum_request(unc: &str, level: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.unique_string(Some(unc));
    w.u32(level).u32(level).pointer();
    w.u32(0).null();
    w.u32(u32::MAX);
    w.pointer().u32(0);
    w.buf
}

pub fn parse_enum(stub: &[u8]) -> Result<Vec<Share>> {
    let mut r = Reader::new(stub);
    let level = r.u32("level")?;
    let _switch = r.u32("switch")?;
    let mut shares = Vec::new();
    if r.pointer("container")? {
        let count = r.u32("count")? as usize;
        if r.pointer("buffer")? {
            let max = r.u32("array")? as usize;
            if count > max || count > r.remaining() / 12 {
                return Err(Short("share count").into());
            }
            let mut present = Vec::with_capacity(count);
            for _ in 0..count {
                present.push(scalars(&mut r, level)?);
            }
            for (share, pointers) in present {
                shares.push(deferred(&mut r, share, pointers)?);
            }
        }
    }
    let _total = r.u32("total")?;
    if r.pointer("resume")? {
        r.u32("resume handle")?;
    }
    status(&mut r, "NetrShareEnum")?;
    Ok(shares)
}

/// Which pointers of a structure are not null: name, remark, path, password, descriptor.
type Present = [bool; 5];

fn scalars(r: &mut Reader<'_>, level: u32) -> Result<(Share, Present)> {
    let mut share = Share {
        level,
        max_uses: u32::MAX,
        ..Share::default()
    };
    let name = r.pointer("name")?;
    share.kind = r.u32("type")?;
    let remark = r.pointer("remark")?;
    let (mut path, mut password, mut descriptor) = (false, false, false);
    if level == 502 {
        let _permissions = r.u32("permissions")?;
        share.max_uses = r.u32("max uses")?;
        share.current_uses = r.u32("current uses")?;
        path = r.pointer("path")?;
        password = r.pointer("password")?;
        let _reserved = r.u32("reserved")?;
        descriptor = r.pointer("descriptor")?;
    }
    let p = [name, remark, path, password, descriptor];
    Ok((share, p))
}

fn deferred(r: &mut Reader<'_>, mut share: Share, p: Present) -> Result<Share> {
    let [name, remark, path, password, descriptor] = p;
    if name {
        share.name = r.string("name")?;
    }
    if remark {
        share.remark = r.string("remark")?;
    }
    if path {
        share.path = r.string("path")?;
    }
    if password {
        r.string("password")?;
    }
    if descriptor {
        let sd = r.bytes("descriptor")?;
        if !sd.is_empty() {
            share.descriptor = Some(sd);
        }
    }
    Ok(share)
}

/// `NetrServerGetInfo` at level 101: server, level.
pub fn server_info_request(unc: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.unique_string(Some(unc));
    w.u32(101);
    w.buf
}

/// The type of `SERVER_INFO_101`: platform, name, version, type, comment.
pub fn parse_server_info_101(stub: &[u8]) -> Result<u32> {
    let mut r = Reader::new(stub);
    let _switch = r.u32("switch")?;
    let mut kind = None;
    if r.pointer("info")? {
        let _platform = r.u32("platform")?;
        let name = r.pointer("name")?;
        let _major = r.u32("major")?;
        let _minor = r.u32("minor")?;
        kind = Some(r.u32("type")?);
        let comment = r.pointer("comment")?;
        if name {
            r.string("name")?;
        }
        if comment {
            r.string("comment")?;
        }
    }
    status(&mut r, "NetrServerGetInfo")?;
    kind.ok_or_else(|| Short("server info").into())
}

/// `NetrShareGetInfo`: server, share name, level.
pub fn get_request(unc: &str, name: &str, level: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.unique_string(Some(unc));
    w.string(name).u32(level);
    w.buf
}

pub fn parse_get_502(stub: &[u8]) -> Result<Share> {
    let mut r = Reader::new(stub);
    let _switch = r.u32("switch")?;
    let share = if r.pointer("info")? {
        let (share, p) = scalars(&mut r, 502)?;
        Some(deferred(&mut r, share, p)?)
    } else {
        None
    };
    status(&mut r, "NetrShareGetInfo")?;
    share.ok_or_else(|| Short("share info").into())
}

pub fn parse_get_1005(stub: &[u8]) -> Result<u32> {
    let mut r = Reader::new(stub);
    let _switch = r.u32("switch")?;
    let flags = if r.pointer("info")? {
        Some(r.u32("flags")?)
    } else {
        None
    };
    status(&mut r, "NetrShareGetInfo")?;
    flags.ok_or_else(|| Short("share flags").into())
}

/// Start of `NetrShareSetInfo`: server, name, level and the union's switch; the caller
/// writes the arm pointer, the structure and `ParmErr`.
fn set_header(unc: &str, name: &str, level: u32) -> Writer {
    let mut w = Writer::new();
    w.unique_string(Some(unc));
    w.string(name).u32(level).u32(level);
    w
}

fn write_502(w: &mut Writer, share: &Share) {
    let sd = share.descriptor.as_deref().unwrap_or_default();
    w.pointer().u32(share.kind).pointer();
    w.u32(0).u32(share.max_uses).u32(0);
    w.pointer().null();
    w.u32(len32(sd)).pointer_if(!sd.is_empty());
    w.string(&share.name)
        .string(&share.remark)
        .string(&share.path);
    if !sd.is_empty() {
        w.bytes(sd);
    }
}

fn parse_parm_error(stub: &[u8], op: &'static str) -> Result<()> {
    let mut r = Reader::new(stub);
    if r.pointer("parm_err")? {
        r.u32("parm_err value")?;
    }
    status(&mut r, op)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Name, type, remark, path, descriptor.
    type Row<'a> = (&'a str, u32, &'a str, &'a str, Option<&'a [u8]>);

    /// A response of `NetrShareEnum` at level 502, laid out as NDR does.
    fn enum_502(shares: &[Row<'_>], status: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32(502).u32(502).pointer();
        w.u32(len32(&vec![0u8; shares.len()])).pointer();
        w.u32(len32(&vec![0u8; shares.len()]));
        for (_, kind, _, _, sd) in shares {
            w.pointer().u32(*kind).pointer();
            w.u32(0).u32(u32::MAX).u32(1);
            w.pointer().null();
            w.u32(sd.map_or(0, len32)).pointer_if(sd.is_some());
        }
        for (name, _, remark, path, sd) in shares {
            w.string(name).string(remark).string(path);
            if let Some(sd) = sd {
                w.bytes(sd);
            }
        }
        w.u32(len32(&vec![0u8; shares.len()]));
        w.pointer().u32(0);
        w.u32(status);
        w.buf
    }

    #[test]
    fn enum_502_is_read_with_deferred_data() {
        let sd = [
            1u8, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let stub = enum_502(
            &[
                (
                    "Commun",
                    stype::DISKTREE,
                    "Partage commun",
                    "/srv/partages/Commun",
                    Some(&sd),
                ),
                ("IPC$", stype::IPC | stype::SPECIAL, "IPC Service", "", None),
            ],
            0,
        );
        let shares = parse_enum(&stub).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].name, "Commun");
        assert_eq!(shares[0].remark, "Partage commun");
        assert_eq!(shares[0].path, "/srv/partages/Commun");
        assert_eq!(shares[0].descriptor.as_deref(), Some(&sd[..]));
        assert_eq!(shares[0].current_uses, 1);
        assert!(shares[0].is_disk() && !shares[0].is_special());
        assert_eq!(shares[1].name, "IPC$");
        assert!(!shares[1].is_disk() && shares[1].is_special());
        assert_eq!(shares[1].descriptor, None);
    }

    #[test]
    fn refusal_is_the_win32_error() {
        let stub = enum_502(&[], werror::ACCESS_DENIED);
        assert_eq!(
            parse_enum(&stub),
            Err(Error::Refused {
                op: "NetrShareEnum",
                code: werror::ACCESS_DENIED
            })
        );
    }

    #[test]
    fn enum_request_layout() {
        let stub = enum_request("\\\\fs1", 502);
        let mut r = Reader::new(&stub);
        assert!(r.pointer("server").unwrap());
        assert_eq!(r.string("server").unwrap(), "\\\\fs1");
        assert_eq!(r.u32("level").unwrap(), 502);
        assert_eq!(r.u32("switch").unwrap(), 502);
        assert!(r.pointer("container").unwrap());
        assert_eq!(r.u32("count").unwrap(), 0);
        assert!(!r.pointer("buffer").unwrap());
        assert_eq!(r.u32("max").unwrap(), u32::MAX);
        assert!(r.pointer("resume").unwrap());
        assert_eq!(r.u32("resume").unwrap(), 0);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn share_502_written_then_read_back() {
        let share = Share {
            name: "Été".into(),
            kind: stype::DISKTREE,
            remark: "commentaire".into(),
            max_uses: 10,
            current_uses: 0,
            path: "C:\\Partages\\Été".into(),
            descriptor: Some(vec![1, 0, 4, 0x80, 1, 2, 3]),
            level: 502,
        };
        let mut w = Writer::new();
        w.u32(502).pointer();
        write_502(&mut w, &share);
        w.u32(0);
        let back = parse_get_502(&w.buf).unwrap();
        assert_eq!(back, share);
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Stubs of Samba (fs1, dc1) and Windows (wdc1), `tests/vecteurs/srvsvc.json`.
    #[test]
    fn vectors_of_samba_and_windows() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vecteurs/srvsvc.json");
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = file["vecteurs"].as_array().unwrap();
        assert_eq!(vectors.len(), 22);
        let check = |share: &Share, expected: &serde_json::Value, id: &str| {
            assert_eq!(share.name, expected["nom"].as_str().unwrap(), "{id}");
            assert_eq!(
                share.kind,
                expected["type"].as_u64().unwrap() as u32,
                "{id}"
            );
            assert_eq!(
                share.remark,
                expected["commentaire"].as_str().unwrap(),
                "{id}"
            );
            if share.level == 502 {
                assert_eq!(share.path, expected["chemin"].as_str().unwrap(), "{id}");
                assert_eq!(
                    share.max_uses,
                    expected["max"].as_u64().unwrap() as u32,
                    "{id}"
                );
                assert_eq!(
                    share
                        .descriptor
                        .as_deref()
                        .map(|d| d.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                    expected["descripteur_hex"].as_str().map(str::to_owned),
                    "{id}"
                );
            }
        };
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let p = &v["provenance"];
            let unc = format!("\\\\{}", p["serveur"].as_str().unwrap());
            let level = p["niveau"].as_u64().unwrap() as u32;
            let stub = unhex(v["hex"].as_str().unwrap());
            let expected = &v["attendu"];
            let request = if p["opnum"] == 15 {
                let shares = parse_enum(&stub).unwrap();
                let listed = expected["partages"].as_array().unwrap();
                assert_eq!(shares.len(), listed.len(), "{id}");
                for (share, e) in shares.iter().zip(listed) {
                    check(share, e, id);
                }
                enum_request(&unc, level)
            } else {
                let name = p["partage"].as_str().unwrap();
                if level == 1005 {
                    assert_eq!(
                        parse_get_1005(&stub).unwrap(),
                        expected["drapeaux"].as_u64().unwrap() as u32,
                        "{id}"
                    );
                } else {
                    check(&parse_get_502(&stub).unwrap(), &expected["partage"], id);
                }
                get_request(&unc, name, level)
            };
            // Requests are written as they were sent to the server.
            assert_eq!(request, unhex(v["requete_hex"].as_str().unwrap()), "{id}");
        }
    }

    /// `NetrServerGetInfo` 101 as servers answer it: `0x809b03` from Samba (fs1, `Unx`),
    /// `0x80102b` from Windows Server 2025 (wdc1), as `rpcclient srvinfo` shows them.
    #[test]
    fn server_type_tells_samba() {
        for (kind, samba) in [(0x0080_9b03u32, true), (0x0080_102b, false)] {
            let mut w = Writer::new();
            w.u32(101).pointer();
            w.u32(500).pointer().u32(6).u32(1).u32(kind).pointer();
            w.string("FS1").string("Samba 4.22");
            w.u32(0);
            let read = parse_server_info_101(&w.buf).unwrap();
            assert_eq!(read, kind);
            assert_eq!(read & sv_type::SERVER_UNIX != 0, samba);
        }
        let mut w = Writer::new();
        w.u32(101).null().u32(werror::ACCESS_DENIED);
        assert!(parse_server_info_101(&w.buf).is_err());
        let request = server_info_request("\\\\fs1");
        let mut r = Reader::new(&request);
        assert!(r.pointer("server").unwrap());
        assert_eq!(r.string("server").unwrap(), "\\\\fs1");
        assert_eq!(r.u32("level").unwrap(), 101);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn short_or_lying_stubs_are_errors() {
        let mut stub = enum_502(&[("a", 0, "", "", None)], 0);
        stub.truncate(stub.len() - 6);
        assert!(parse_enum(&stub).is_err());
        // A count far beyond what the stub holds.
        let mut w = Writer::new();
        w.u32(1)
            .u32(1)
            .pointer()
            .u32(1_000_000)
            .pointer()
            .u32(1_000_000);
        assert!(parse_enum(&w.buf).is_err());
    }
}

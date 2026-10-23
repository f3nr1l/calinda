// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The local groups of a server through the Security Account Manager Remote Protocol
//! (MS-SAMR), on the pipe `samr` of `IPC$` (ADR 0023 § 6): which aliases of the domain
//! `Builtin` and of the account domain of the server (the local groups of a member server, the
//! domain local groups of a DC) hold one of the SIDs of a token.
//!
//! As a server builds a token (Samba, `finalize_local_nt_token`): the aliases of the account
//! domain that hold a SID of the token, then those of `Builtin` that hold one of these SIDs or
//! of these aliases; no deeper. An alias of the account domain held by another one gives
//! nothing (measured on fs1, J8.5), as Windows forbids that nesting on a member server.

use annuaire_codecs::Sid;

use crate::rpc::ndr::{Reader, Short, Writer};
use crate::rpc::{Rpc, RpcError, Syntax};
use crate::smb::client::Options;
use crate::smb::pipe::Pipe;

/// `samr` v1.0 (MS-SAMR 1.9).
pub const INTERFACE: Syntax = Syntax::new(0x1234_5778_1234_abcd_ef00_0123_4567_89ac, 1, 0);

pub mod opnum {
    pub const CLOSE_HANDLE: u16 = 1;
    pub const LOOKUP_DOMAIN: u16 = 5;
    pub const ENUMERATE_DOMAINS: u16 = 6;
    pub const OPEN_DOMAIN: u16 = 7;
    pub const GET_ALIAS_MEMBERSHIP: u16 = 16;
    pub const CONNECT5: u16 = 64;
}

/// Access asked of the server object: connect, enumerate and look up domains (MS-SAMR
/// 2.2.1.3).
pub const SERVER_ACCESS: u32 = 0x0000_0031;
/// Access asked of a domain: `DOMAIN_GET_ALIAS_MEMBERSHIP | DOMAIN_LOOKUP` (2.2.1.4).
pub const DOMAIN_ACCESS: u32 = 0x0000_0280;

/// NTSTATUS codes the server returns.
pub mod status {
    pub const SUCCESS: u32 = 0;
    pub const MORE_ENTRIES: u32 = 0x0000_0105;
    pub const ACCESS_DENIED: u32 = 0xC000_0022;
    pub const NO_SUCH_DOMAIN: u32 = 0xC000_00DF;
}

/// What a call to the service gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Transport or protocol.
    Rpc(RpcError),
    /// The server refused the operation (`op`) with an NTSTATUS.
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

/// A context handle (`SAMPR_HANDLE`): 20 opaque bytes.
pub type Handle = [u8; 20];

/// `Builtin`, S-1-5-32.
pub fn builtin() -> Sid {
    Sid::new(5, &[32]).expect("S-1-5-32 is a valid SID")
}

/// A bound connection to the service of one server, with its server handle.
#[derive(Debug)]
pub struct Samr {
    rpc: Rpc<Pipe>,
    server: Handle,
}

impl Samr {
    /// Opens `\\server\IPC$`, the pipe `samr`, binds and connects (`SamrConnect5`). Blocking.
    pub fn open(server: &str, options: &Options) -> Result<Self> {
        let pipe = Pipe::open(server, "samr", options)?;
        Self::on(pipe, server)
    }

    pub fn on(pipe: Pipe, server: &str) -> Result<Self> {
        let mut rpc = Rpc::bind(pipe, INTERFACE)?;
        let stub = rpc.call(
            opnum::CONNECT5,
            &connect5_request(&format!("\\\\{server}"), SERVER_ACCESS),
        )?;
        let server = parse_connect5(&stub)?;
        Ok(Self { rpc, server })
    }

    pub fn close(mut self) {
        let server = self.server;
        let _ = self.close_handle(&server);
        self.rpc.into_transport().close();
    }

    /// Names of the domains of the server: `Builtin` and its account domain.
    pub fn domains(&mut self) -> Result<Vec<String>> {
        let mut names = Vec::new();
        let mut context = 0;
        loop {
            let stub = self.rpc.call(
                opnum::ENUMERATE_DOMAINS,
                &enumerate_domains_request(&self.server, context),
            )?;
            let (next, page, more) = parse_enumerate_domains(&stub)?;
            names.extend(page);
            if !more || next == context {
                return Ok(names);
            }
            context = next;
        }
    }

    /// SID of a domain of the server, by its name.
    pub fn lookup_domain(&mut self, name: &str) -> Result<Sid> {
        let stub = self.rpc.call(
            opnum::LOOKUP_DOMAIN,
            &lookup_domain_request(&self.server, name),
        )?;
        parse_lookup_domain(&stub)
    }

    /// A handle on a domain of the server, to be closed by `close_handle`.
    pub fn open_domain(&mut self, sid: &Sid) -> Result<Handle> {
        let stub = self.rpc.call(
            opnum::OPEN_DOMAIN,
            &open_domain_request(&self.server, sid, DOMAIN_ACCESS),
        )?;
        parse_handle(&stub, "SamrOpenDomain")
    }

    /// RIDs, in the domain `domain`, of the aliases that hold one of `sids` directly.
    pub fn alias_membership(&mut self, domain: &Handle, sids: &[Sid]) -> Result<Vec<u32>> {
        let stub = self.rpc.call(
            opnum::GET_ALIAS_MEMBERSHIP,
            &alias_membership_request(domain, sids),
        )?;
        parse_alias_membership(&stub)
    }

    pub fn close_handle(&mut self, handle: &Handle) -> Result<()> {
        let stub = self.rpc.call(opnum::CLOSE_HANDLE, &close_request(handle))?;
        parse_handle(&stub, "SamrCloseHandle").map(|_| ())
    }

    /// The aliases of the account domain of the server that hold one of `sids`, then those of
    /// `Builtin` that hold one of `sids` or of these aliases; in that order, without `sids`
    /// themselves.
    pub fn local_groups(&mut self, sids: &[Sid]) -> Result<Vec<Sid>> {
        let domains = self.account_domains()?;
        self.local_groups_of(&domains, sids)
    }

    /// The SIDs of the account domains of the server (`Builtin` left out): its own on a member
    /// server, the domain it serves on a DC.
    pub fn account_domains(&mut self) -> Result<Vec<Sid>> {
        let mut domains = Vec::new();
        for name in self.domains()? {
            if !name.eq_ignore_ascii_case("Builtin") {
                let sid = self.lookup_domain(&name)?;
                if sid != builtin() && !domains.contains(&sid) {
                    domains.push(sid);
                }
            }
        }
        Ok(domains)
    }

    /// [`Self::local_groups`], the account domains already known.
    pub fn local_groups_of(&mut self, account_domains: &[Sid], sids: &[Sid]) -> Result<Vec<Sid>> {
        let mut domains = account_domains.to_vec();
        domains.push(builtin());
        let mut token = sids.to_vec();
        let mut found = Vec::new();
        for domain in &domains {
            let handle = self.open_domain(domain)?;
            let rids = self.alias_membership(&handle, &token);
            let _ = self.close_handle(&handle);
            for rid in rids? {
                let alias = domain
                    .with_rid(rid)
                    .or_else(|_| child(domain, rid))
                    .map_err(|_| Short("alias SID"))?;
                if !token.contains(&alias) {
                    token.push(alias);
                    found.push(alias);
                }
            }
        }
        Ok(found)
    }
}

/// `S-1-5-32` + RID: `with_rid` takes only the SIDs of domains `S-1-5-21-a-b-c`.
fn child(domain: &Sid, rid: u32) -> std::result::Result<Sid, annuaire_codecs::sid::SidError> {
    let mut subs = domain.sub_authorities().to_vec();
    subs.push(rid);
    Sid::new(domain.authority(), &subs)
}

fn check(r: &mut Reader<'_>, op: &'static str) -> Result<u32> {
    match r.u32("NTSTATUS")? {
        status::SUCCESS => Ok(status::SUCCESS),
        status::MORE_ENTRIES if op == "SamrEnumerateDomainsInSamServer" => Ok(status::MORE_ENTRIES),
        code => Err(Error::Refused { op, code }),
    }
}

// -- NDR pieces -----------------------------------------------------------------------------

fn handle(w: &mut Writer, h: &Handle) {
    w.align(4);
    w.buf.extend_from_slice(h);
}

fn read_handle(r: &mut Reader<'_>) -> Result<Handle> {
    r.u32("handle")?; // aligns and checks the first word
    let start = r.at - 4;
    let mut h = [0u8; 20];
    for (i, b) in h.iter_mut().enumerate() {
        *b = r.u8_at(start + i).ok_or(Short("handle"))?;
    }
    r.at = start + 20;
    Ok(h)
}

/// `RPC_SID`: the conformance (sub-authority count) first, then the structure.
fn sid(w: &mut Writer, sid: &Sid) {
    w.u32(sid.sub_authorities().len() as u32);
    w.buf.extend_from_slice(&sid.encode());
}

fn read_sid(r: &mut Reader<'_>) -> Result<Sid> {
    let count = r.u32("SID count")? as usize;
    let len = 8 + 4 * count;
    let mut bytes = Vec::with_capacity(len);
    for i in 0..len {
        bytes.push(r.u8_at(r.at + i).ok_or(Short("SID"))?);
    }
    let sid = Sid::decode(&bytes).map_err(|_| Short("SID"))?;
    if sid.sub_authorities().len() != count {
        return Err(Short("SID count").into());
    }
    r.at += len;
    Ok(sid)
}

/// `RPC_UNICODE_STRING` (a top-level `[in]` one): lengths in bytes without a terminating
/// null, a pointer, then the conformant and varying units.
fn unicode_string(w: &mut Writer, text: &str) {
    let units: Vec<u16> = text.encode_utf16().collect();
    let bytes = u16::try_from(units.len() * 2).unwrap_or(u16::MAX);
    w.u16(bytes).u16(bytes).pointer();
    let count = u32::from(bytes / 2);
    w.u32(count).u32(0).u32(count);
    for u in units {
        w.buf.extend_from_slice(&u.to_le_bytes());
    }
}

// -- Stubs ----------------------------------------------------------------------------------

/// `SamrConnect5`: server name, access, revision 1 asked (`SAMPR_REVISION_INFO_V1` of
/// revision 3, no feature).
pub fn connect5_request(unc: &str, access: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.unique_string(Some(unc));
    w.u32(access);
    w.u32(1).u32(1).u32(3).u32(0);
    w.buf
}

pub fn parse_connect5(stub: &[u8]) -> Result<Handle> {
    let mut r = Reader::new(stub);
    let _version = r.u32("out version")?;
    let _switch = r.u32("switch")?;
    let _revision = r.u32("revision")?;
    let _features = r.u32("features")?;
    let h = read_handle(&mut r)?;
    check(&mut r, "SamrConnect5")?;
    Ok(h)
}

pub fn enumerate_domains_request(server: &Handle, context: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, server);
    w.u32(context).u32(u32::MAX);
    w.buf
}

/// Next enumeration context, names of this page, and whether more remain.
pub fn parse_enumerate_domains(stub: &[u8]) -> Result<(u32, Vec<String>, bool)> {
    let mut r = Reader::new(stub);
    let context = r.u32("context")?;
    let mut names = Vec::new();
    if r.pointer("buffer")? {
        let count = r.u32("entries")? as usize;
        if r.pointer("array")? {
            let max = r.u32("array")? as usize;
            if count > max || count > r.remaining() / 12 {
                return Err(Short("domain count").into());
            }
            let mut present = Vec::with_capacity(count);
            for _ in 0..count {
                let _rid = r.u32("rid")?;
                let _length = r.u16("length")?;
                let _max = r.u16("maximum length")?;
                present.push(r.pointer("name")?);
            }
            for p in present {
                if p {
                    names.push(r.string("name")?);
                }
            }
        }
    }
    let _returned = r.u32("count returned")?;
    let more = check(&mut r, "SamrEnumerateDomainsInSamServer")? == status::MORE_ENTRIES;
    Ok((context, names, more))
}

pub fn lookup_domain_request(server: &Handle, name: &str) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, server);
    unicode_string(&mut w, name);
    w.buf
}

pub fn parse_lookup_domain(stub: &[u8]) -> Result<Sid> {
    let mut r = Reader::new(stub);
    let sid = if r.pointer("domain id")? {
        Some(read_sid(&mut r)?)
    } else {
        None
    };
    check(&mut r, "SamrLookupDomainInSamServer")?;
    sid.ok_or_else(|| Short("domain id").into())
}

pub fn open_domain_request(server: &Handle, domain: &Sid, access: u32) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, server);
    w.u32(access);
    sid(&mut w, domain);
    w.buf
}

/// A handle then the status (`SamrOpenDomain`, `SamrCloseHandle`).
pub fn parse_handle(stub: &[u8], op: &'static str) -> Result<Handle> {
    let mut r = Reader::new(stub);
    let h = read_handle(&mut r)?;
    check(&mut r, op)?;
    Ok(h)
}

/// `SamrGetAliasMembership`: `SAMPR_PSID_ARRAY`, its array of pointers deferred, then the
/// SIDs they point to.
pub fn alias_membership_request(domain: &Handle, sids: &[Sid]) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, domain);
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
    w.buf
}

pub fn parse_alias_membership(stub: &[u8]) -> Result<Vec<u32>> {
    let mut r = Reader::new(stub);
    let count = r.u32("count")? as usize;
    let mut rids = Vec::new();
    if r.pointer("elements")? {
        let max = r.u32("array")? as usize;
        if count > max || count > r.remaining() / 4 {
            return Err(Short("alias count").into());
        }
        for _ in 0..count {
            rids.push(r.u32("rid")?);
        }
    }
    check(&mut r, "SamrGetAliasMembership")?;
    Ok(rids)
}

pub fn close_request(h: &Handle) -> Vec<u8> {
    let mut w = Writer::new();
    handle(&mut w, h);
    w.buf
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> Sid {
        text.parse().unwrap()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn interface_uuid() {
        // 12345778-1234-abcd-ef00-0123456789ac, as in any bind to samr.
        assert_eq!(
            INTERFACE.uuid,
            [
                0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23, 0x45, 0x67,
                0x89, 0xac
            ]
        );
    }

    #[test]
    fn sid_round_trip() {
        let mut w = Writer::new();
        w.u16(7);
        sid(&mut w, &s("S-1-5-21-1-2-3"));
        let mut r = Reader::new(&w.buf);
        r.u16("x").unwrap();
        assert_eq!(read_sid(&mut r).unwrap(), s("S-1-5-21-1-2-3"));
        assert_eq!(r.remaining(), 0);
        // A count that does not match the SID.
        let mut bytes = w.buf.clone();
        bytes[4] = 3;
        assert!(read_sid(&mut Reader::new(&bytes[4..])).is_err());
    }

    #[test]
    fn alias_membership_request_layout() {
        let h = [7u8; 20];
        let stub = alias_membership_request(&h, &[s("S-1-5-21-1-2-3-1104"), s("S-1-1-0")]);
        let mut r = Reader::new(&stub);
        assert_eq!(read_handle(&mut r).unwrap(), h);
        assert_eq!(r.u32("count").unwrap(), 2);
        assert!(r.pointer("sids").unwrap());
        assert_eq!(r.u32("max").unwrap(), 2);
        assert!(r.pointer("p1").unwrap());
        assert!(r.pointer("p2").unwrap());
        assert_eq!(read_sid(&mut r).unwrap(), s("S-1-5-21-1-2-3-1104"));
        assert_eq!(read_sid(&mut r).unwrap(), s("S-1-1-0"));
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn alias_membership_response() {
        let mut w = Writer::new();
        w.u32(2).pointer().u32(2).u32(544).u32(545).u32(0);
        assert_eq!(parse_alias_membership(&w.buf).unwrap(), [544, 545]);
        let mut w = Writer::new();
        w.u32(0).null().u32(0);
        assert_eq!(parse_alias_membership(&w.buf).unwrap(), Vec::<u32>::new());
        let mut w = Writer::new();
        w.u32(0).null().u32(status::ACCESS_DENIED);
        assert_eq!(
            parse_alias_membership(&w.buf),
            Err(Error::Refused {
                op: "SamrGetAliasMembership",
                code: status::ACCESS_DENIED
            })
        );
        let mut w = Writer::new();
        w.u32(1_000_000).pointer().u32(1_000_000);
        assert!(parse_alias_membership(&w.buf).is_err());
    }

    #[test]
    fn enumerate_domains_response() {
        let mut w = Writer::new();
        w.u32(2).pointer().u32(2).pointer().u32(2);
        for name in ["FS1", "Builtin"] {
            let n = (name.len() * 2) as u16;
            w.u32(0).u16(n).u16(n).pointer();
        }
        for name in ["FS1", "Builtin"] {
            let units: Vec<u16> = name.encode_utf16().collect();
            let n = units.len() as u32;
            w.u32(n).u32(0).u32(n);
            for u in units {
                w.buf.extend_from_slice(&u.to_le_bytes());
            }
        }
        w.u32(2).u32(0);
        let (context, names, more) = parse_enumerate_domains(&w.buf).unwrap();
        assert_eq!((context, more), (2, false));
        assert_eq!(names, ["FS1", "Builtin"]);
    }

    #[test]
    fn unicode_string_has_no_terminator() {
        let mut w = Writer::new();
        unicode_string(&mut w, "Été");
        let mut r = Reader::new(&w.buf);
        assert_eq!(r.u16("len").unwrap(), 6);
        assert_eq!(r.u16("max").unwrap(), 6);
        assert!(r.pointer("p").unwrap());
        assert_eq!(r.string("s").unwrap(), "Été");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn child_of_builtin() {
        assert_eq!(child(&builtin(), 544).unwrap(), s("S-1-5-32-544"));
        assert_eq!(
            s("S-1-5-21-1-2-3").with_rid(1000).unwrap(),
            s("S-1-5-21-1-2-3-1000")
        );
    }

    /// Stubs of Samba (fs1, dc1) and Windows (wdc1), `tests/vecteurs/samr.json`.
    #[test]
    fn vectors_of_samba_and_windows() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/vecteurs/samr.json");
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let vectors = file["vecteurs"].as_array().unwrap();
        assert!(!vectors.is_empty());
        let mut seen = std::collections::BTreeSet::new();
        for v in vectors {
            let id = v["id"].as_str().unwrap();
            let p = &v["provenance"];
            let opnum = p["opnum"].as_u64().unwrap() as u16;
            seen.insert(opnum);
            let request = unhex(v["requete_hex"].as_str().unwrap());
            let stub = unhex(v["hex"].as_str().unwrap());
            let expected = &v["attendu"];
            let status = expected["statut"].as_u64().unwrap() as u32;
            // Handles in requests come from earlier responses: compare the rest.
            let request_handle: Handle = request[..20].try_into().unwrap_or([0; 20]);
            match opnum {
                opnum::CONNECT5 => {
                    let unc = format!("\\\\{}", p["serveur"].as_str().unwrap());
                    assert_eq!(connect5_request(&unc, SERVER_ACCESS), request, "{id}");
                    let h = parse_connect5(&stub).unwrap();
                    assert_eq!(hex(&h), expected["poignee"].as_str().unwrap(), "{id}");
                }
                opnum::ENUMERATE_DOMAINS => {
                    assert_eq!(
                        enumerate_domains_request(&request_handle, 0),
                        request,
                        "{id}"
                    );
                    let (_, names, more) = parse_enumerate_domains(&stub).unwrap();
                    assert!(!more, "{id}");
                    let want: Vec<&str> = expected["domaines"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|d| d.as_str().unwrap())
                        .collect();
                    assert_eq!(names, want, "{id}");
                }
                opnum::LOOKUP_DOMAIN => {
                    let name = p["domaine"].as_str().unwrap();
                    assert_eq!(
                        lookup_domain_request(&request_handle, name),
                        request,
                        "{id}"
                    );
                    assert_eq!(
                        parse_lookup_domain(&stub).unwrap().to_string(),
                        expected["sid"].as_str().unwrap(),
                        "{id}"
                    );
                }
                opnum::OPEN_DOMAIN => {
                    let domain = s(p["sid"].as_str().unwrap());
                    assert_eq!(
                        open_domain_request(&request_handle, &domain, DOMAIN_ACCESS),
                        request,
                        "{id}"
                    );
                    let h = parse_handle(&stub, "SamrOpenDomain").unwrap();
                    assert_eq!(hex(&h), expected["poignee"].as_str().unwrap(), "{id}");
                }
                opnum::GET_ALIAS_MEMBERSHIP => {
                    let sids: Vec<Sid> = p["sids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|t| s(t.as_str().unwrap()))
                        .collect();
                    assert_eq!(
                        alias_membership_request(&request_handle, &sids),
                        request,
                        "{id}"
                    );
                    let rids: Vec<u64> = expected["rids"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| r.as_u64().unwrap())
                        .collect();
                    match parse_alias_membership(&stub) {
                        Ok(got) => {
                            assert_eq!(status, 0, "{id}");
                            let got: Vec<u64> = got.into_iter().map(u64::from).collect();
                            assert_eq!(got, rids, "{id}");
                        }
                        Err(Error::Refused { code, .. }) => assert_eq!(code, status, "{id}"),
                        Err(e) => panic!("{id}: {e}"),
                    }
                }
                opnum::CLOSE_HANDLE => {
                    assert_eq!(close_request(&request_handle), request, "{id}");
                    assert_eq!(
                        parse_handle(&stub, "SamrCloseHandle").unwrap(),
                        [0; 20],
                        "{id}"
                    );
                }
                other => panic!("{id}: opnum {other}"),
            }
        }
        assert_eq!(seen.len(), 6, "every operation has vectors");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

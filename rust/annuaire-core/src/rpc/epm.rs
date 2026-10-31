// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Endpoint mapper (MS-RPCE 2.2.1.2.5, C706 appendix L): `ept_map` on the fixed port 135
//! resolves the dynamic TCP port of an interface served over `ncacn_ip_tcp`. MS-GKDI (J9.7)
//! is reached this way, as the directory interfaces of J8 were reached on their named pipe.
//!
//! A "protocol tower" describes one binding as a list of floors (an interface, the transfer
//! syntax, the RPC protocol, the port, the host). Its internal integers are little-endian but
//! unaligned, unlike the NDR of the call that carries it, so the tower itself is built and
//! read byte by byte.

use std::time::Duration;

use super::gkdi::NDR64;
use super::tcp::TcpTransport;
use super::{NDR, Rpc, RpcError, Syntax};

/// `ept` v3.0, the endpoint mapper interface.
pub const EPM: Syntax = Syntax::new(0xe1af_8308_5d1f_11c9_91a4_0800_2b14_a0fa, 3, 0);
/// `ept_map`.
const MAP: u16 = 3;
/// The endpoint mapper always listens here.
pub const EPM_PORT: u16 = 135;

/// Floor protocol identifiers (C706 appendix L, table of protocol towers).
mod floor_id {
    pub const UUID: u8 = 0x0d;
    pub const RPC_CO: u8 = 0x0b;
    pub const TCP_PORT: u8 = 0x07;
    pub const IP_HOST: u8 = 0x09;
}

/// One floor: a little-endian length then the left-hand side, the same for the right-hand side.
fn floor(out: &mut Vec<u8>, lhs: &[u8], rhs: &[u8]) {
    let lhs_len = u16::try_from(lhs.len()).unwrap_or(u16::MAX);
    let rhs_len = u16::try_from(rhs.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&lhs_len.to_le_bytes());
    out.extend_from_slice(lhs);
    out.extend_from_slice(&rhs_len.to_le_bytes());
    out.extend_from_slice(rhs);
}

/// The lhs of an interface floor: the uuid protocol id, the UUID as on the wire, the major.
fn interface_lhs(syntax: Syntax) -> Vec<u8> {
    let mut lhs = vec![floor_id::UUID];
    lhs.extend_from_slice(&syntax.uuid);
    lhs.extend_from_slice(&syntax.major.to_le_bytes());
    lhs
}

/// The tower that looks `interface` up over `ncacn_ip_tcp`: the port and host floors are left
/// empty, which is what asks the mapper to fill them in.
fn build_tower(interface: Syntax) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&5u16.to_le_bytes());
    floor(
        &mut t,
        &interface_lhs(interface),
        &interface.minor.to_le_bytes(),
    );
    floor(&mut t, &interface_lhs(NDR), &NDR.minor.to_le_bytes());
    floor(&mut t, &[floor_id::RPC_CO], &[0, 0]);
    // The lookup tower carries port 135 (big-endian) and a null address, as the reference client
    // does; the mapper returns the registered dynamic port.
    floor(&mut t, &[floor_id::TCP_PORT], &135u16.to_be_bytes());
    floor(&mut t, &[floor_id::IP_HOST], &[0, 0, 0, 0]);
    t
}

/// The TCP port of the first `ncacn_ip_tcp` floor of a tower, read as the network order it is
/// stored in; `None` if there is no such floor or the tower ends early.
fn port_from_tower(tower: &[u8]) -> Option<u16> {
    let count = u16::from_le_bytes([*tower.first()?, *tower.get(1)?]);
    let mut at = 2usize;
    for _ in 0..count {
        let lhs_len = usize::from(u16::from_le_bytes([*tower.get(at)?, *tower.get(at + 1)?]));
        at += 2;
        let lhs = tower.get(at..at.checked_add(lhs_len)?)?;
        at += lhs_len;
        let rhs_len = usize::from(u16::from_le_bytes([*tower.get(at)?, *tower.get(at + 1)?]));
        at += 2;
        let rhs = tower.get(at..at.checked_add(rhs_len)?)?;
        at += rhs_len;
        if lhs.first() == Some(&floor_id::TCP_PORT) {
            if let [hi, lo] = rhs {
                // The port is big-endian (network order), not little-endian like the lengths.
                return Some(u16::from_be_bytes([*hi, *lo]));
            }
        }
    }
    None
}

/// The `ept_map` request stub in NDR64 (what Windows' endpoint mapper expects for a tower that
/// carries an NDR64 interface): an object pointer (referent 1, a null GUID), the tower looked up
/// (referent 2, its 8-byte conformant size then 4-byte length), padding to 8, a null lookup
/// handle, and one tower wanted.
fn map_request(tower: &[u8]) -> Vec<u8> {
    let len = tower.len();
    let mut w = Vec::new();
    w.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0, 0]); // object referent id 1
    w.extend_from_slice(&[0u8; 16]); // object GUID, null
    w.extend_from_slice(&[2, 0, 0, 0, 0, 0, 0, 0]); // tower referent id 2
    w.extend_from_slice(&(len as u64).to_le_bytes()); // conformant size
    w.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes()); // tower_length
    w.extend_from_slice(tower);
    let pad = (8 - (len + 4) % 8) % 8;
    w.resize(w.len() + pad, 0);
    w.extend_from_slice(&[0u8; 20]); // entry_handle, null for the first call
    w.extend_from_slice(&4u32.to_le_bytes()); // max_towers
    w
}

fn u64_at(stub: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(stub.get(at..at + 8)?.try_into().ok()?))
}

/// The port carried by the first tower of an NDR64 `ept_map` response, or an error. `status`
/// (the final field) says whether the interface is registered.
fn parse_map_response(stub: &[u8]) -> Result<u16, RpcError> {
    let short = || RpcError::Protocol("ept_map response too short".into());
    // status is the final error_status_t; a non-zero one (e.g. EPT_S_NOT_REGISTERED) means no
    // usable binding was returned.
    let status = stub
        .len()
        .checked_sub(4)
        .and_then(|at| stub.get(at..at + 4))
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(short)?;
    if status != 0 {
        return Err(RpcError::Fault(status));
    }
    // After the 20-byte entry handle: num_towers (4), max_count (8), offset (8), then the actual
    // tower count (8) at offset 40, then one 8-byte referent id per tower, then the towers.
    let count = u64_at(stub, 40).ok_or_else(short)? as usize;
    if count == 0 {
        return Err(RpcError::Protocol("no endpoint returned".into()));
    }
    let base = 48usize
        .checked_add(8usize.checked_mul(count).ok_or_else(short)?)
        .ok_or_else(short)?;
    let tower_len = u64_at(stub, base).ok_or_else(short)? as usize;
    // The tower octet string (floor count then floors) sits after the 8-byte conformant size and
    // the 4-byte length.
    let start = base.checked_add(12).ok_or_else(short)?;
    let tower = stub
        .get(start..start.checked_add(tower_len).ok_or_else(short)?)
        .ok_or_else(short)?;
    port_from_tower(tower).ok_or_else(|| RpcError::Protocol("no TCP port floor in tower".into()))
}

/// Resolves the `ncacn_ip_tcp` port of `interface` on `host` through its endpoint mapper.
/// Blocking.
pub fn resolve_tcp_port(host: &str, interface: Syntax, timeout: Duration) -> Result<u16, RpcError> {
    let transport = TcpTransport::connect(host, EPM_PORT, timeout)?;
    // The endpoint mapper is bound with NDR64, so the tower's NDR64 encoding is understood.
    let mut rpc = Rpc::bind_transfer(transport, EPM, NDR64)?;
    let stub = rpc.call(MAP, &map_request(&build_tower(interface)))?;
    parse_map_response(&stub)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MS-GKDI `ISDKey` v1.0, used as a realistic interface to look up.
    const ISDKEY: Syntax = Syntax::new(0xb978_5960_524f_11df_8b6d_83dc_6201_16b1, 1, 0);

    #[test]
    fn the_tower_has_five_floors_with_the_interface_first() {
        let t = build_tower(ISDKEY);
        assert_eq!(u16::from_le_bytes([t[0], t[1]]), 5);
        // First floor lhs: 0x0d, the 16-byte UUID as on the wire, then the major version.
        let lhs_len = usize::from(u16::from_le_bytes([t[2], t[3]]));
        assert_eq!(lhs_len, 1 + 16 + 2);
        assert_eq!(t[4], floor_id::UUID);
        assert_eq!(&t[5..21], &ISDKEY.uuid);
    }

    #[test]
    fn a_built_tower_round_trips_its_port() {
        // The lookup tower carries port 135 in its TCP floor.
        let mut t = build_tower(ISDKEY);
        assert_eq!(port_from_tower(&t), Some(135));
        // Now craft a response-style tower with port 389.
        let mut floors = Vec::new();
        floors.extend_from_slice(&1u16.to_le_bytes());
        floor(&mut floors, &[floor_id::TCP_PORT], &389u16.to_be_bytes());
        assert_eq!(port_from_tower(&floors), Some(389));
        t.clear();
    }

    /// Builds an NDR64 `ept_map` response around `tower`, as the mapper would encode it.
    fn map_response(tower: &[u8], status: u32) -> Vec<u8> {
        let count: u64 = if tower.is_empty() { 0 } else { 1 };
        let mut w = Vec::new();
        w.extend_from_slice(&[0u8; 20]); // entry_handle
        w.extend_from_slice(&(count as u32).to_le_bytes()); // num_towers
        w.extend_from_slice(&count.to_le_bytes()); // max_tower_count
        w.extend_from_slice(&0u64.to_le_bytes()); // tower offset
        w.extend_from_slice(&count.to_le_bytes()); // tower_count
        if count == 1 {
            w.extend_from_slice(&3u64.to_le_bytes()); // one tower referent id
            let len = tower.len();
            w.extend_from_slice(&(len as u64).to_le_bytes()); // conformant size
            w.extend_from_slice(&(len as u32).to_le_bytes()); // tower_length
            w.extend_from_slice(tower);
            let pad = (4 - len % 4) % 4;
            w.resize(w.len() + pad, 0);
        }
        w.extend_from_slice(&status.to_le_bytes());
        w
    }

    #[test]
    fn a_response_yields_the_registered_port() {
        let mut tower = Vec::new();
        tower.extend_from_slice(&1u16.to_le_bytes());
        floor(&mut tower, &[floor_id::TCP_PORT], &49_666u16.to_be_bytes());
        let stub = map_response(&tower, 0);
        assert_eq!(parse_map_response(&stub).unwrap(), 49_666);
    }

    #[test]
    fn an_unregistered_interface_is_a_fault() {
        let stub = map_response(&[], 0x16c9_a0d6); // EPT_S_NOT_REGISTERED
        assert!(matches!(
            parse_map_response(&stub),
            Err(RpcError::Fault(0x16c9_a0d6))
        ));
    }

    #[test]
    fn the_map_request_carries_the_tower_length_twice() {
        let tower = build_tower(ISDKEY);
        let req = map_request(&tower);
        // NDR64: object referent (8) + object GUID (16) + tower referent (8), then the
        // 8-byte conformant size and the 4-byte tower_length.
        let max_count = u64::from_le_bytes(req[32..40].try_into().unwrap());
        let tower_length = u32::from_le_bytes(req[40..44].try_into().unwrap());
        assert_eq!(max_count as usize, tower.len());
        assert_eq!(tower_length as usize, tower.len());
    }
}

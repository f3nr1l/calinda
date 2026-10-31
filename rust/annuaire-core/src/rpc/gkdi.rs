// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! MS-GKDI, the Group Key Distribution Service (`ISDKey`, one method `GetKey`, opnum 0). The DC
//! hands back the seed keys a holder of the protection descriptor needs to derive the key that
//! unwraps a DPAPI-NG blob (J9.7, the encrypted LAPS password). The interface is served over
//! `ncacn_ip_tcp` and, unlike the directory interfaces of J8, its stub is NDR64: 8-byte
//! alignment, 8-byte referents and counts. The GetKey stub is simple enough to lay out by hand.

use std::time::Duration;

use super::authn::AuthConn;
use super::{RpcError, Syntax, Transport};

/// The identity of a group key: an optional root key id (16 bytes in little-endian wire form)
/// and the L0/L1/L2 indices. A `-1` index (`CURRENT`) asks for the most recent key.
#[derive(Debug, Clone)]
pub struct KeyId {
    pub root_key_id: Option<[u8; 16]>,
    pub l0: i32,
    pub l1: i32,
    pub l2: i32,
}

/// `ISDKey` v1.0.
pub const ISD_KEY: Syntax = Syntax::new(0xb978_5960_524f_11df_8b6d_83dc_ded7_2085, 1, 0);
/// NDR64 transfer syntax, which MS-GKDI requires.
pub const NDR64: Syntax = Syntax::new(0x7171_0533_beba_4937_8319_b5db_ef9c_cc36, 1, 0);
/// `GetKey`.
const GET_KEY: u16 = 0;
/// SPN service class for the DC's RPC endpoint.
const SERVICE: &str = "host";
/// A key index of -1 asks for the most recent key at that level.
pub const CURRENT: i32 = -1;

/// The GetKey request stub in NDR64 (MS-GKDI 3.1.4.1): the target security descriptor, an
/// optional root key id, and the L0/L1/L2 indices.
fn get_key_request(target_sd: &[u8], key: &KeyId) -> Vec<u8> {
    let len = u64::try_from(target_sd.len()).unwrap_or(0);
    let mut w = Vec::new();
    w.extend_from_slice(&len.to_le_bytes()); // cbTargetSD (4 bytes, but 8-byte aligned in NDR64)
    w.extend_from_slice(&len.to_le_bytes()); // pbTargetSD conformant max_count
    w.extend_from_slice(target_sd);
    let pad = (8 - target_sd.len() % 8) % 8;
    w.resize(w.len() + pad, 0);
    match &key.root_key_id {
        Some(guid) => {
            w.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]); // unique pointer referent id
            w.extend_from_slice(guid);
        }
        None => w.extend_from_slice(&[0u8; 8]),
    }
    w.extend_from_slice(&key.l0.to_le_bytes());
    w.extend_from_slice(&key.l1.to_le_bytes());
    w.extend_from_slice(&key.l2.to_le_bytes());
    w
}

/// The GroupKeyEnvelope blob carried by a GetKey response, or the HRESULT as a fault. The
/// response is `[pcbOut u32][pad 4][referent 8][max_count 8][blob][HRESULT u32]`.
fn parse_get_key_response(stub: &[u8]) -> Result<Vec<u8>, RpcError> {
    let short = || RpcError::Protocol("GetKey response too short".into());
    let hresult = stub
        .len()
        .checked_sub(4)
        .and_then(|at| stub.get(at..at + 4))
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(short)?;
    if hresult != 0 {
        return Err(RpcError::Fault(hresult));
    }
    let key_length = stub
        .get(0..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(short)? as usize;
    stub.get(24..24usize.checked_add(key_length).ok_or_else(short)?)
        .map(<[u8]>::to_vec)
        .ok_or_else(short)
}

/// The verification trailer MS-GKDI requires (MS-RPCE 2.2.2.13): the signature, then a PCONTEXT
/// command (ended) binding the call to the ISDKey interface and the NDR64 transfer syntax, which
/// stops a bind from being redirected to another interface.
fn verification_trailer() -> Vec<u8> {
    let mut v = vec![0x8a, 0xe3, 0x13, 0x71, 0x02, 0xf4, 0x36, 0x71]; // SEC_VT signature
    v.extend_from_slice(&0x4002u16.to_le_bytes()); // SEC_VT_COMMAND_PCONTEXT | SEC_VT_COMMAND_END
    v.extend_from_slice(&40u16.to_le_bytes()); // length of the two syntaxes
    for s in [ISD_KEY, NDR64] {
        v.extend_from_slice(&s.uuid);
        v.extend_from_slice(&s.major.to_le_bytes());
        v.extend_from_slice(&s.minor.to_le_bytes());
    }
    v
}

/// Calls GetKey on an already-bound connection, returning the GroupKeyEnvelope blob.
pub fn get_key<T: Transport>(
    conn: &mut AuthConn<T>,
    target_sd: &[u8],
    key: &KeyId,
) -> Result<Vec<u8>, RpcError> {
    let stub = get_key_request(target_sd, key);
    let response = conn.call(GET_KEY, &stub, Some(&verification_trailer()))?;
    parse_get_key_response(&response)
}

/// Connects to `host`'s MS-GKDI over TCP, binds with Kerberos in DCE style, and fetches the
/// group key blob for `target_sd` and the given key identity. Blocking.
pub fn fetch_group_key(
    host: &str,
    realm: &str,
    target_sd: &[u8],
    key: &KeyId,
    timeout: Duration,
) -> Result<Vec<u8>, RpcError> {
    let mut conn = AuthConn::connect_tcp(host, ISD_KEY, NDR64, SERVICE, host, realm, timeout)?;
    get_key(&mut conn, target_sd, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_without_a_root_key_lays_out_in_ndr64() {
        let req = get_key_request(
            &[1, 2, 3],
            &KeyId {
                root_key_id: None,
                l0: 1,
                l1: 2,
                l2: 3,
            },
        );
        assert_eq!(&req[0..8], &3u64.to_le_bytes()); // cbTargetSD
        assert_eq!(&req[8..16], &3u64.to_le_bytes()); // conformant max_count
        assert_eq!(&req[16..19], &[1, 2, 3]); // target_sd
        assert_eq!(&req[19..24], &[0, 0, 0, 0, 0]); // padding to 8
        assert_eq!(&req[24..32], &[0u8; 8]); // null root key id
        assert_eq!(&req[32..36], &1i32.to_le_bytes());
        assert_eq!(&req[36..40], &2i32.to_le_bytes());
        assert_eq!(&req[40..44], &3i32.to_le_bytes());
    }

    #[test]
    fn a_request_with_a_root_key_carries_its_referent_and_guid() {
        let guid = [9u8; 16];
        let req = get_key_request(
            &[0xAA; 8],
            &KeyId {
                root_key_id: Some(guid),
                l0: -1,
                l1: -1,
                l2: -1,
            },
        );
        // target_sd is already 8-aligned: no padding.
        assert_eq!(&req[16..24], &[0xAA; 8]);
        assert_eq!(&req[24..32], &[0, 0, 2, 0, 0, 0, 0, 0]); // referent id
        assert_eq!(&req[32..48], &guid);
        assert_eq!(&req[48..52], &(-1i32).to_le_bytes());
    }

    #[test]
    fn a_response_yields_the_blob() {
        let blob = [0x7u8; 40];
        let mut stub = Vec::new();
        stub.extend_from_slice(&(blob.len() as u32).to_le_bytes()); // pcbOut
        stub.extend_from_slice(&[0, 0, 0, 0]); // padding
        stub.extend_from_slice(&[0, 0, 2, 0, 0, 0, 0, 0]); // referent
        stub.extend_from_slice(&(blob.len() as u64).to_le_bytes()); // max_count
        stub.extend_from_slice(&blob);
        stub.extend_from_slice(&0u32.to_le_bytes()); // HRESULT
        assert_eq!(parse_get_key_response(&stub).unwrap(), blob);
    }

    #[test]
    fn a_nonzero_hresult_is_a_fault() {
        let mut stub = vec![0u8; 24];
        stub.extend_from_slice(&0x8007_0005u32.to_le_bytes()); // E_ACCESSDENIED-like
        assert!(matches!(
            parse_get_key_response(&stub),
            Err(RpcError::Fault(0x8007_0005))
        ));
    }
}

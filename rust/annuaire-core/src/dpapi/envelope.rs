// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The two MS-GKDI structures that describe a group key: the `GroupKeyEnvelope` the DC returns
//! (MS-GKDI 2.2.4), which carries the L1/L2 seed keys, and the `KeyIdentifier` stored in a
//! DPAPI-NG blob (the key context). From the seeds and the identifier, `kek` derives the
//! key-encryption key for the common LAPS case (a holder of the protection descriptor, not the
//! public-key case). Both structures are little-endian with a `KDSK` magic.

use openssl::hash::MessageDigest;

use super::DpapiError;
use super::kdf::{kdf_context, kds_service_label, sp800_108_ctr};

const MAGIC: &[u8; 4] = b"KDSK";

/// A little cursor over a byte slice, reading the little-endian fields of these structures.
struct Cursor<'a> {
    data: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, at: 0 }
    }

    fn u32(&mut self) -> Result<u32, DpapiError> {
        let b = self
            .data
            .get(self.at..self.at + 4)
            .ok_or_else(|| DpapiError::Malformed("truncated field".into()))?;
        self.at += 4;
        Ok(u32::from_le_bytes(b.try_into().unwrap_or([0; 4])))
    }

    fn bytes(&mut self, n: usize) -> Result<&'a [u8], DpapiError> {
        let end = self.at.checked_add(n).ok_or_else(short)?;
        let b = self.data.get(self.at..end).ok_or_else(short)?;
        self.at = end;
        Ok(b)
    }

    fn guid(&mut self) -> Result<[u8; 16], DpapiError> {
        let b = self.bytes(16)?;
        Ok(b.try_into().unwrap_or([0; 16]))
    }
}

fn short() -> DpapiError {
    DpapiError::Malformed("structure ends early".into())
}

/// A UTF-16LE string that includes a trailing null, as these structures store names: the length
/// counts the null, which is dropped.
fn utf16_name(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap_or([0, 0])))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The hash algorithm named by a `KDFParameters` blob (MS-GKDI 2.2.1).
fn kdf_hash(parameters: &[u8]) -> Result<MessageDigest, DpapiError> {
    // magic: 00000000 01000000, then hash_length (4), then 00000000, then the UTF-16LE name.
    let head = parameters.get(0..8).ok_or_else(short)?;
    if head != [0, 0, 0, 0, 1, 0, 0, 0] || parameters.get(12..16) != Some(&[0, 0, 0, 0]) {
        return Err(DpapiError::Malformed("KDF parameters magic".into()));
    }
    let len = parameters
        .get(8..12)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as usize)
        .ok_or_else(short)?;
    let name = parameters
        .get(16..16usize.checked_add(len).ok_or_else(short)?)
        .ok_or_else(short)?;
    match utf16_name(name).as_str() {
        "SHA1" => Ok(MessageDigest::sha1()),
        "SHA256" => Ok(MessageDigest::sha256()),
        "SHA384" => Ok(MessageDigest::sha384()),
        "SHA512" => Ok(MessageDigest::sha512()),
        other => Err(DpapiError::Unsupported(format!("hash {other}"))),
    }
}

/// The key identifier stored in a DPAPI-NG blob: which group key, and the KDF context the key
/// was derived with.
#[derive(Debug, Clone)]
pub struct KeyIdentifier {
    pub flags: u32,
    pub l0: i32,
    pub l1: i32,
    pub l2: i32,
    pub root_key_id: [u8; 16],
    pub key_info: Vec<u8>,
    pub domain_name: String,
    pub forest_name: String,
}

impl KeyIdentifier {
    pub fn is_public_key(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Parses a key identifier blob (the structure mirrors `GroupKeyEnvelope`, without seeds).
    pub fn parse(data: &[u8]) -> Result<Self, DpapiError> {
        let mut c = Cursor::new(data);
        let _version = c.u32()?;
        if c.bytes(4)? != MAGIC {
            return Err(DpapiError::Malformed("KeyIdentifier magic".into()));
        }
        let flags = c.u32()?;
        let l0 = c.u32()? as i32;
        let l1 = c.u32()? as i32;
        let l2 = c.u32()? as i32;
        let root_key_id = c.guid()?;
        let key_info_len = c.u32()? as usize;
        let domain_len = c.u32()? as usize;
        let forest_len = c.u32()? as usize;
        let key_info = c.bytes(key_info_len)?.to_vec();
        let domain_name = utf16_name(c.bytes(domain_len)?);
        let forest_name = utf16_name(c.bytes(forest_len)?);
        Ok(Self {
            flags,
            l0,
            l1,
            l2,
            root_key_id,
            key_info,
            domain_name,
            forest_name,
        })
    }
}

/// The group key envelope returned by GetKey: the L1 and L2 seed keys, and what is needed to
/// derive from them.
#[derive(Debug, Clone)]
pub struct GroupKeyEnvelope {
    pub flags: u32,
    pub l0: i32,
    pub l1: i32,
    pub l2: i32,
    pub root_key_id: [u8; 16],
    pub kdf_parameters: Vec<u8>,
    /// The secret-agreement algorithm (`DH`, `ECDH_P256`…), for the public-key case.
    pub secret_algorithm: String,
    /// The private key length in bits, for the public-key case.
    pub private_key_length: u32,
    pub l1_key: Vec<u8>,
    pub l2_key: Vec<u8>,
}

impl GroupKeyEnvelope {
    pub fn is_public_key(&self) -> bool {
        self.flags & 1 != 0
    }

    /// Parses a GroupKeyEnvelope blob (MS-GKDI 2.2.4).
    pub fn parse(data: &[u8]) -> Result<Self, DpapiError> {
        let mut c = Cursor::new(data);
        let _version = c.u32()?;
        if c.bytes(4)? != MAGIC {
            return Err(DpapiError::Malformed("GroupKeyEnvelope magic".into()));
        }
        let flags = c.u32()?;
        let l0 = c.u32()? as i32;
        let l1 = c.u32()? as i32;
        let l2 = c.u32()? as i32;
        let root_key_id = c.guid()?;
        let kdf_algo_len = c.u32()? as usize;
        let kdf_para_len = c.u32()? as usize;
        let sec_algo_len = c.u32()? as usize;
        let sec_para_len = c.u32()? as usize;
        let private_key_length = c.u32()?;
        let _publ_key_len = c.u32()?;
        let l1_key_len = c.u32()? as usize;
        let l2_key_len = c.u32()? as usize;
        let domain_len = c.u32()? as usize;
        let forest_len = c.u32()? as usize;
        let _kdf_algo = c.bytes(kdf_algo_len)?;
        let kdf_parameters = c.bytes(kdf_para_len)?.to_vec();
        let secret_algorithm = utf16_name(c.bytes(sec_algo_len)?);
        let _sec_para = c.bytes(sec_para_len)?;
        let _domain = c.bytes(domain_len)?;
        let _forest = c.bytes(forest_len)?;
        let l1_key = c.bytes(l1_key_len)?.to_vec();
        let l2_key = c.bytes(l2_key_len)?.to_vec();
        Ok(Self {
            flags,
            l0,
            l1,
            l2,
            root_key_id,
            kdf_parameters,
            secret_algorithm,
            private_key_length,
            l1_key,
            l2_key,
        })
    }

    /// The hash algorithm of this envelope's KDF.
    pub fn hash(&self) -> Result<MessageDigest, DpapiError> {
        kdf_hash(&self.kdf_parameters)
    }

    /// The L2 seed key at the requested L1/L2 indices, derived from this envelope's seeds
    /// (MS-GKDI 2.2.4). Reseeds down the L1 then the L2 chain as needed.
    fn l2_seed(
        &self,
        digest: MessageDigest,
        request_l1: i32,
        request_l2: i32,
    ) -> Result<Vec<u8>, DpapiError> {
        let mut l1 = self.l1;
        let mut l1_key = self.l1_key.clone();
        let mut l2 = self.l2;
        let mut l2_key = self.l2_key.clone();
        let mut reseed_l2 = l2 == 31 || self.l1 != request_l1;

        if l2 != 31 && l1 != request_l1 {
            l1 -= 1;
        }
        while l1 != request_l1 {
            reseed_l2 = true;
            l1 -= 1;
            l1_key = sp800_108_ctr(
                digest,
                &l1_key,
                &kds_service_label(),
                &kdf_context(&self.root_key_id, self.l0, l1, -1),
                64,
            )?;
        }
        if reseed_l2 {
            l2 = 31;
            l2_key = sp800_108_ctr(
                digest,
                &l1_key,
                &kds_service_label(),
                &kdf_context(&self.root_key_id, self.l0, l1, l2),
                64,
            )?;
        }
        while l2 != request_l2 {
            l2 -= 1;
            l2_key = sp800_108_ctr(
                digest,
                &l2_key,
                &kds_service_label(),
                &kdf_context(&self.root_key_id, self.l0, l1, l2),
                64,
            )?;
        }
        Ok(l2_key)
    }

    /// The key-encryption key for `key_id`. The reader must be authorized to get the seed keys
    /// (so this envelope, from GetKey, is not itself public-key). Two cases for the blob: a
    /// public key stored at encryption time (the normal LAPS case, key agreement), or a derived
    /// KDF context (an authorized encryptor).
    pub fn kek(&self, key_id: &KeyIdentifier) -> Result<Vec<u8>, DpapiError> {
        if self.is_public_key() {
            return Err(DpapiError::Unsupported(
                "the reader is not authorized to retrieve the group key seeds".into(),
            ));
        }
        if self.l0 != key_id.l0 {
            return Err(DpapiError::Malformed("L0 index mismatch".into()));
        }
        let digest = self.hash()?;
        let l2 = self.l2_seed(digest, key_id.l1, key_id.l2)?;
        if key_id.is_public_key() {
            let private_key_len = (self.private_key_length as usize).div_ceil(8);
            super::agreement::compute_kek_public(
                digest,
                &l2,
                &self.secret_algorithm,
                &key_id.key_info,
                private_key_len,
            )
        } else {
            Ok(sp800_108_ctr(
                digest,
                &l2,
                &kds_service_label(),
                &key_id.key_info,
                32,
            )?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
            .collect()
    }

    // Synthetic envelope, identifier and expected KEK built with dpapi-ng (see the generator in
    // the J9.7 notes). SHA512 KDF, flags 0, L0=361, envelope L1/L2 = 20/31, request L1/L2 = 20/7.
    const GKE_HEX: &str = "010000004b44534b0000000069010000140000001f00000067452301ab89efcd0123456789abcdef260000001e0000000600000000000000000800000008000040000000400000001200000012000000530050003800300030005f003100300038005f004300540052005f0048004d0041004300000000000000010000000e000000000000005300480041003500310032000000440048000000770069006e002e0074006500730074000000770069006e002e007400650073007400000000070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b903080d12171c21262b30353a3f44494e53585d62676c71767b80858a8f94999ea3a8adb2b7bcc1c6cbd0d5dadfe4e9eef3f8fd02070c11161b20252a2f34393e";
    const KID_HEX: &str = "010000004b44534b0000000069010000140000000700000067452301ab89efcd0123456789abcdef2000000012000000120000000104070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e770069006e002e0074006500730074000000770069006e002e0074006500730074000000";
    const KEK_HEX: &str = "7b60c18e29279a5bae07ba13fb0adec7025970188369449ecec955c38b178d8a";

    #[test]
    fn kek_matches_the_reference() {
        let gke = GroupKeyEnvelope::parse(&hex(GKE_HEX)).unwrap();
        let kid = KeyIdentifier::parse(&hex(KID_HEX)).unwrap();
        assert_eq!(gke.kek(&kid).unwrap(), hex(KEK_HEX));
    }
}

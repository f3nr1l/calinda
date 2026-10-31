// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The public-key path of DPAPI-NG (MS-GKDI 2.2.3, the common LAPS case): the blob stores a
//! Diffie-Hellman or ECDH public key, and the group key's seed yields the matching private key.
//! Their agreement, run through a SP800-56A concat KDF and then the group KDF, is the
//! key-encryption key. The encryptor (a computer applying LAPS) only ever holds the public key,
//! so a normal `msLAPS-EncryptedPassword` is a public-key blob; an authorized reader derives the
//! private side from the seed it gets from `GetKey`.

use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::{Hasher, MessageDigest};
use openssl::nid::Nid;

use super::DpapiError;
use super::kdf::{kds_service_label, sp800_108_ctr};

/// `"KDS public key\0"` in UTF-16LE, the context of the public-key KDF steps.
fn kds_public_key_label() -> Vec<u8> {
    "KDS public key\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Big-endian bytes of `n`, left-padded to `len`.
fn to_fixed(n: &BigNum, len: usize) -> Vec<u8> {
    let raw = n.to_vec();
    if raw.len() >= len {
        raw
    } else {
        let mut out = vec![0u8; len - raw.len()];
        out.extend_from_slice(&raw);
        out
    }
}

/// SP800-56A concat KDF: `hash(counter || Z || algorithm_id || party_u || party_v)`, blocks
/// concatenated and truncated to `length`.
fn concat_kdf(
    digest: MessageDigest,
    z: &[u8],
    algorithm_id: &[u8],
    party_u: &[u8],
    party_v: &[u8],
    length: usize,
) -> Result<Vec<u8>, DpapiError> {
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut h = Hasher::new(digest)?;
        h.update(&counter.to_be_bytes())?;
        h.update(z)?;
        h.update(algorithm_id)?;
        h.update(party_u)?;
        h.update(party_v)?;
        out.extend_from_slice(&h.finish()?);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}

/// The shared secret and the hash SP800-56A uses, from the peer public key blob and our private
/// key (big-endian scalar), for the secret-agreement algorithm named by `secret_algorithm`.
fn agree(
    secret_algorithm: &str,
    private_key: &[u8],
    public_key: &[u8],
) -> Result<(Vec<u8>, MessageDigest), DpapiError> {
    if secret_algorithm == "DH" {
        let key = FfcDhKey::parse(public_key)?;
        let mut ctx = BigNumContext::new()?;
        let y = BigNum::from_slice(&key.public_key)?;
        let x = BigNum::from_slice(private_key)?;
        let p = BigNum::from_slice(&key.field_order)?;
        let mut shared = BigNum::new()?;
        shared.mod_exp(&y, &x, &p, &mut ctx)?;
        Ok((to_fixed(&shared, key.key_length), MessageDigest::sha256()))
    } else if let Some(curve) = secret_algorithm.strip_prefix("ECDH_") {
        let key = EcdhKey::parse(public_key)?;
        let (nid, digest) = match curve {
            "P256" => (Nid::X9_62_PRIME256V1, MessageDigest::sha256()),
            "P384" => (Nid::SECP384R1, MessageDigest::sha384()),
            "P521" => (Nid::SECP521R1, MessageDigest::sha512()),
            other => return Err(DpapiError::Unsupported(format!("courbe {other}"))),
        };
        let group = EcGroup::from_curve_name(nid)?;
        let mut ctx = BigNumContext::new()?;
        let px = BigNum::from_slice(&key.x)?;
        let py = BigNum::from_slice(&key.y)?;
        let peer = EcKey::from_public_key_affine_coordinates(&group, &px, &py)?;
        let scalar = BigNum::from_slice(private_key)?;
        // ECDH shared secret: the x-coordinate of scalar × peer-point.
        let mut shared_point = EcPoint::new(&group)?;
        shared_point.mul2(&group, peer.public_key(), &scalar, &mut ctx)?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        shared_point.affine_coordinates_gfp(&group, &mut x, &mut y, &mut ctx)?;
        let field_len = (group.degree() as usize).div_ceil(8);
        Ok((to_fixed(&x, field_len), digest))
    } else {
        Err(DpapiError::Unsupported(format!(
            "accord de clés {secret_algorithm}"
        )))
    }
}

/// The key-encryption key for a public-key blob: derive the group private key from the L2 seed,
/// agree with the blob's public key, then two KDF steps (MS-GKDI 3.1.4.1.2).
pub fn compute_kek_public(
    digest: MessageDigest,
    l2_seed: &[u8],
    secret_algorithm: &str,
    public_key: &[u8],
    private_key_len: usize,
) -> Result<Vec<u8>, DpapiError> {
    let private_key = sp800_108_ctr(
        digest,
        l2_seed,
        &kds_service_label(),
        &utf16(&format!("{secret_algorithm}\0")),
        private_key_len,
    )?;
    let (shared, secret_hash) = agree(secret_algorithm, &private_key, public_key)?;
    let secret = concat_kdf(
        secret_hash,
        &shared,
        &utf16("SHA512\0"),
        &kds_public_key_label(),
        &kds_service_label(),
        secret_hash.size(),
    )?;
    Ok(sp800_108_ctr(
        digest,
        &secret,
        &kds_service_label(),
        &kds_public_key_label(),
        32,
    )?)
}

/// A parsed FFC DH public key (`DHPB`, MS-GKDI 2.2.3.1): the field order, generator and peer
/// public key, each `key_length` bytes big-endian.
struct FfcDhKey {
    key_length: usize,
    field_order: Vec<u8>,
    public_key: Vec<u8>,
}

impl FfcDhKey {
    fn parse(data: &[u8]) -> Result<Self, DpapiError> {
        let short = || DpapiError::Malformed("FFC DH key too short".into());
        if data.get(0..4) != Some(b"DHPB") {
            return Err(DpapiError::Malformed("FFC DH key magic".into()));
        }
        let key_length = data
            .get(4..8)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as usize)
            .ok_or_else(short)?;
        let field_order = data.get(8..8 + key_length).ok_or_else(short)?.to_vec();
        // generator is skipped (not needed to agree); the peer public key follows it.
        let at = 8 + 2 * key_length;
        let public_key = data.get(at..at + key_length).ok_or_else(short)?.to_vec();
        Ok(Self {
            key_length,
            field_order,
            public_key,
        })
    }
}

/// A parsed ECDH public key (`ECK1/3/5`, MS-GKDI 2.2.3.2): the affine coordinates of the peer
/// public point, each `key_length` bytes big-endian.
struct EcdhKey {
    x: Vec<u8>,
    y: Vec<u8>,
}

impl EcdhKey {
    fn parse(data: &[u8]) -> Result<Self, DpapiError> {
        let short = || DpapiError::Malformed("ECDH key too short".into());
        let key_length = data
            .get(4..8)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap_or([0; 4])) as usize)
            .ok_or_else(short)?;
        let x = data.get(8..8 + key_length).ok_or_else(short)?.to_vec();
        let y = data
            .get(8 + key_length..8 + 2 * key_length)
            .ok_or_else(short)?
            .to_vec();
        Ok(Self { x, y })
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

    // Vector from dpapi-ng's compute_kek_from_public_key over ECDH P256 (SHA512, 32-byte private
    // key), the branch the live lab test (DH) does not exercise.
    #[test]
    fn ecdh_p256_kek_matches_the_reference() {
        let seed = hex(
            "01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3ba",
        );
        let pub_blob = hex(
            "45434b31200000007d90f3bbe13f717aa71b0168baef9e49c67fee6cb7737cec51f70da0fce9a67a8ee0fbceb48710fe8fb0e90c56406f2d7e472de3ef52c84443570c72c71b1c43",
        );
        let kek =
            compute_kek_public(MessageDigest::sha512(), &seed, "ECDH_P256", &pub_blob, 32).unwrap();
        assert_eq!(
            kek,
            hex("33ec7fbc9c8ff1db0ce2b23e6729cadcb7d52ccdddba969dec8f3c5387448f04")
        );
    }
}

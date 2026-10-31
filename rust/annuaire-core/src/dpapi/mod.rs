// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! DPAPI-NG and MS-GKDI key derivation (J9.7): reading an encrypted LAPS password
//! (`msLAPS-EncryptedPassword`). A holder of the protection descriptor gets the group key seeds
//! from the DC (`rpc::gkdi`), derives the key-encryption key with SP800-108, unwraps the
//! content-encryption key and decrypts the content. This module gathers the pieces that do not
//! talk to the network: the KDF, the envelope and blob parsers, and the final decryption.

pub mod agreement;
pub mod asn1;
pub mod blob;
pub mod envelope;
pub mod kdf;
pub mod security_descriptor;

use std::time::Duration;

use openssl::aes::{AesKey, unwrap_key};
use openssl::symm::{Cipher, decrypt_aead};

use crate::rpc::{RpcError, gkdi};

/// The 16-byte header before the DPAPI-NG blob in a LAPS encrypted attribute (update time,
/// buffer size, flags).
const LAPS_HEADER: usize = 16;
/// The AES-GCM tag appended to the ciphertext.
const GCM_TAG: usize = 16;

/// Unwraps the content-encryption key (RFC 3394 AES key unwrap with the default IV) and
/// decrypts the content (AES-256-GCM, the tag appended to the ciphertext).
fn unwrap_and_decrypt(
    kek: &[u8],
    enc_cek: &[u8],
    iv: &[u8],
    enc_content: &[u8],
) -> Result<Vec<u8>, DpapiError> {
    let aes = AesKey::new_decrypt(kek).map_err(|_| DpapiError::Crypto("invalid KEK".into()))?;
    let unwrapped_len = enc_cek
        .len()
        .checked_sub(8)
        .ok_or_else(|| DpapiError::Malformed("wrapped key too short".into()))?;
    let mut cek = vec![0u8; unwrapped_len];
    unwrap_key(&aes, None, &mut cek, enc_cek)
        .map_err(|_| DpapiError::Crypto("CEK unwrap failed".into()))?;
    let split = enc_content
        .len()
        .checked_sub(GCM_TAG)
        .ok_or_else(|| DpapiError::Malformed("GCM content too short".into()))?;
    let (ciphertext, tag) = enc_content.split_at(split);
    decrypt_aead(Cipher::aes_256_gcm(), &cek, Some(iv), &[], ciphertext, tag)
        .map_err(|_| DpapiError::Crypto("GCM decryption failed".into()))
}

/// Decrypts the content of a parsed blob with the group key envelope fetched for it.
pub fn decrypt_content(
    blob: &blob::DpapiBlob,
    envelope: &envelope::GroupKeyEnvelope,
) -> Result<Vec<u8>, DpapiError> {
    let kek = envelope.kek(&blob.key_identifier)?;
    unwrap_and_decrypt(&kek, &blob.enc_cek, &blob.gcm_iv, &blob.enc_content)
}

/// Reads an encrypted LAPS attribute value (`msLAPS-EncryptedPassword` and friends): strips the
/// 16-byte header, parses the DPAPI-NG blob, asks the DC `host` (in `realm`) for the group key,
/// and decrypts. Returns the plaintext — for Windows LAPS, the same JSON as the clear
/// `msLAPS-Password`. Blocking (one RPC round trip to the DC).
pub fn decrypt_laps_value(
    value: &[u8],
    host: &str,
    realm: &str,
    timeout: Duration,
) -> Result<Vec<u8>, DpapiError> {
    let body = value
        .get(LAPS_HEADER..)
        .ok_or_else(|| DpapiError::Malformed("LAPS value shorter than its header".into()))?;
    let blob = blob::DpapiBlob::parse(body)?;
    let id = &blob.key_identifier;
    let key = gkdi::KeyId {
        root_key_id: Some(id.root_key_id),
        l0: id.l0,
        l1: id.l1,
        l2: id.l2,
    };
    let envelope_bytes = gkdi::fetch_group_key(host, realm, &blob.target_sd, &key, timeout)?;
    let envelope = envelope::GroupKeyEnvelope::parse(&envelope_bytes)?;
    decrypt_content(&blob, &envelope)
}

/// What went wrong reading an encrypted LAPS password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpapiError {
    /// A blob or envelope that does not have its expected shape.
    Malformed(String),
    /// A value the reader does not implement (an algorithm, a descriptor type).
    Unsupported(String),
    /// OpenSSL refused a cryptographic step.
    Crypto(String),
    /// The GetKey call to the DC failed.
    Rpc(RpcError),
}

impl std::fmt::Display for DpapiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(d) => write!(f, "malformed DPAPI-NG data: {d}"),
            Self::Unsupported(d) => write!(f, "unsupported by the DPAPI-NG reader: {d}"),
            Self::Crypto(d) => write!(f, "DPAPI-NG cryptography: {d}"),
            Self::Rpc(e) => write!(f, "MS-GKDI: {e}"),
        }
    }
}

impl std::error::Error for DpapiError {}

impl From<openssl::error::ErrorStack> for DpapiError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::Crypto(e.to_string())
    }
}

impl From<RpcError> for DpapiError {
    fn from(e: RpcError) -> Self {
        Self::Rpc(e)
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

    // Vector from the cryptography library: AES key wrap of a CEK, then AES-256-GCM of a JSON.
    #[test]
    fn unwrap_then_gcm_recovers_the_plaintext() {
        let kek = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let enc_cek =
            hex("e6e56a81984621ff3319d5ad3ee131a57513cf9891dc8eeb0b4d5c4b51eaaad164df652d5a2001e1");
        let iv = hex("000102030405060708090a0b");
        let enc = hex("eb345255fdf16c60fadeb3d1647fada8b2428ba78f2194b0003f43f1926790");
        assert_eq!(
            unwrap_and_decrypt(&kek, &enc_cek, &iv, &enc).unwrap(),
            br#"{"p":"S3cret!"}"#
        );
    }

    #[test]
    fn a_tampered_tag_is_refused() {
        let kek = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let enc_cek =
            hex("e6e56a81984621ff3319d5ad3ee131a57513cf9891dc8eeb0b4d5c4b51eaaad164df652d5a2001e1");
        let iv = hex("000102030405060708090a0b");
        let mut enc = hex("eb345255fdf16c60fadeb3d1647fada8b2428ba78f2194b0003f43f1926790");
        if let Some(last) = enc.last_mut() {
            *last ^= 0xFF;
        }
        assert!(unwrap_and_decrypt(&kek, &enc_cek, &iv, &enc).is_err());
    }
}

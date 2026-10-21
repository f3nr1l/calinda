// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Keys, signatures and encryption of SMB 3, and the signatures of SMB 2.x (MS-SMB2 3.1.4),
//! by the system OpenSSL.

use openssl::cipher::{Cipher as Aead, CipherRef};
use openssl::cipher_ctx::CipherCtx;
use openssl::error::ErrorStack;
use openssl::hash::{Hasher, MessageDigest};
use openssl::pkey::PKey;
use openssl::sign::Signer;
use openssl::symm::Cipher;

use super::msg::{SIGNATURE_AT, TRANSFORM_ID, TRANSFORM_LEN, cipher, dialect, signing};
use super::wire::{Writer, bytes_at, to_u32, u64_at};

pub type Key = [u8; 16];

/// CANCEL, whose signature nonce differs under AES-GMAC.
const CANCEL: u16 = 0x0C;

/// SP800-108 key derivation in counter mode with HMAC-SHA256, one block, L = 128
/// (MS-SMB2 3.1.4.2). `label` and `context` as the specification writes them, terminating
/// zero included.
pub fn kdf(key: &Key, label: &[u8], context: &[u8]) -> Result<Key, ErrorStack> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
    signer.update(&1u32.to_be_bytes())?;
    signer.update(label)?;
    signer.update(&[0])?;
    signer.update(context)?;
    signer.update(&128u32.to_be_bytes())?;
    let full = signer.sign_to_vec()?;
    let mut out = [0u8; 16];
    out.copy_from_slice(full.get(..16).unwrap_or(&[0; 16]));
    Ok(out)
}

/// The three keys of a session.
#[derive(Clone, PartialEq, Eq)]
pub struct SessionKeys {
    pub signing: Key,
    /// Client to server.
    pub encryption: Key,
    /// Server to client.
    pub decryption: Key,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKeys(..)")
    }
}

/// Keys derived from the session key of the authentication (its first 16 bytes, zero padded
/// if shorter), for the dialect and, in 3.1.1, the preauthentication hash of the session.
/// In SMB 2.x the session key is the signing key and the two others are unused.
pub fn session_keys(
    dialect_: u16,
    session_key: &[u8],
    preauth: &[u8; 64],
) -> Result<SessionKeys, ErrorStack> {
    let mut key = [0u8; 16];
    for (slot, byte) in key.iter_mut().zip(session_key) {
        *slot = *byte;
    }
    if dialect::is_smb2(dialect_) {
        // 2.0.2 and 2.1: the session key signs as it is (MS-SMB2 3.2.5.3.1); nothing to
        // encrypt with.
        Ok(SessionKeys {
            signing: key,
            encryption: key,
            decryption: key,
        })
    } else if dialect_ == dialect::SMB311 {
        Ok(SessionKeys {
            signing: kdf(&key, b"SMBSigningKey\0", preauth)?,
            encryption: kdf(&key, b"SMBC2SCipherKey\0", preauth)?,
            decryption: kdf(&key, b"SMBS2CCipherKey\0", preauth)?,
        })
    } else {
        Ok(SessionKeys {
            signing: kdf(&key, b"SMB2AESCMAC\0", b"SmbSign\0")?,
            encryption: kdf(&key, b"SMB2AESCCM\0", b"ServerIn \0")?,
            decryption: kdf(&key, b"SMB2AESCCM\0", b"ServerOut\0")?,
        })
    }
}

/// Preauthentication integrity hash (3.1.1): SHA-512 of the previous value and a message.
pub fn preauth_next(previous: &[u8; 64], message: &[u8]) -> Result<[u8; 64], ErrorStack> {
    let mut h = Hasher::new(MessageDigest::sha512())?;
    h.update(previous)?;
    h.update(message)?;
    let digest = h.finish()?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    Ok(out)
}

/// The signature of one message (signature field taken as zero), by the negotiated
/// algorithm. `message` is the whole message, padding to the next one of a compound
/// included.
pub fn signature(algorithm: u16, key: &Key, message: &[u8]) -> Result<[u8; 16], ErrorStack> {
    let mut zeroed = message.to_vec();
    if let Some(field) = zeroed.get_mut(SIGNATURE_AT..SIGNATURE_AT + 16) {
        field.fill(0);
    }
    let mut out = [0u8; 16];
    match algorithm {
        signing::AES_GMAC => {
            // Nonce: message id, then a 32-bit word whose bit 0 marks a response and bit 1
            // a CANCEL request (MS-SMB2 3.1.4.1).
            let id = u64_at(&zeroed, 24).unwrap_or(0);
            let flags = super::wire::u32_at(&zeroed, 16).unwrap_or(0);
            let command = super::wire::u16_at(&zeroed, 12).unwrap_or(0);
            let mut word = flags & super::msg::flag::SERVER_TO_REDIR;
            if command == CANCEL {
                word |= 2;
            }
            let mut nonce = Writer::new();
            nonce.u64(id).u32(word);
            out = seal(Aead::aes_128_gcm(), key, &nonce.buf, &zeroed, &[])?.1;
        }
        signing::HMAC_SHA256 => {
            let pkey = PKey::hmac(key)?;
            let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
            signer.update(&zeroed)?;
            out.copy_from_slice(signer.sign_to_vec()?.get(..16).unwrap_or(&[0; 16]));
        }
        _ => {
            let pkey = PKey::cmac(&Cipher::aes_128_cbc(), key)?;
            let mut signer = Signer::new_without_digest(&pkey)?;
            signer.update(&zeroed)?;
            out.copy_from_slice(signer.sign_to_vec()?.get(..16).unwrap_or(&[0; 16]));
        }
    }
    Ok(out)
}

/// Writes the signature into the message.
pub fn sign(algorithm: u16, key: &Key, message: &mut [u8]) -> Result<(), ErrorStack> {
    let sig = signature(algorithm, key, message)?;
    if let Some(field) = message.get_mut(SIGNATURE_AT..SIGNATURE_AT + 16) {
        field.copy_from_slice(&sig);
    }
    Ok(())
}

/// Whether the signature in the message is the right one.
pub fn verify(algorithm: u16, key: &Key, message: &[u8]) -> Result<bool, ErrorStack> {
    let expected = signature(algorithm, key, message)?;
    Ok(bytes_at(message, SIGNATURE_AT, 16)
        .is_some_and(|found| openssl::memcmp::eq(&expected, found)))
}

/// The AEAD cipher of an SMB cipher id, and its nonce length.
fn aead(cipher_: u16) -> (&'static CipherRef, usize) {
    if cipher_ == cipher::AES_128_CCM {
        (Aead::aes_128_ccm(), 11)
    } else {
        (Aead::aes_128_gcm(), 12)
    }
}

fn is_ccm(c: &CipherRef) -> bool {
    c.nid() == openssl::nid::Nid::AES_128_CCM
}

/// Encrypts `data` and authenticates it with `aad`: (ciphertext, tag). CCM wants its
/// lengths (nonce, tag, data) before the key, which `symm::encrypt_aead` does not do.
fn seal(
    c: &'static CipherRef,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    data: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), ErrorStack> {
    let mut ctx = CipherCtx::new()?;
    ctx.encrypt_init(Some(c), None, None)?;
    ctx.set_iv_length(nonce.len())?;
    if is_ccm(c) {
        ctx.set_tag_length(16)?;
    }
    ctx.encrypt_init(None, Some(key), Some(nonce))?;
    if is_ccm(c) {
        ctx.set_data_len(data.len())?;
    }
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)?;
    }
    let mut out = Vec::with_capacity(data.len() + 16);
    ctx.cipher_update_vec(data, &mut out)?;
    ctx.cipher_final_vec(&mut out)?;
    let mut tag = [0u8; 16];
    ctx.tag(&mut tag)?;
    Ok((out, tag))
}

/// Decrypts and checks `sealed`; an error if the tag does not match.
fn open(
    c: &'static CipherRef,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    sealed: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let mut ctx = CipherCtx::new()?;
    ctx.decrypt_init(Some(c), None, None)?;
    ctx.set_iv_length(nonce.len())?;
    let ccm = is_ccm(c);
    if ccm {
        ctx.set_tag(tag)?;
    }
    ctx.decrypt_init(None, Some(key), Some(nonce))?;
    if ccm {
        ctx.set_data_len(sealed.len())?;
    }
    if !aad.is_empty() {
        ctx.cipher_update(aad, None)?;
    }
    let mut out = Vec::with_capacity(sealed.len() + 16);
    // CCM checks the tag in this update; GCM in the final step.
    ctx.cipher_update_vec(sealed, &mut out)?;
    if !ccm {
        ctx.set_tag(tag)?;
        ctx.cipher_final_vec(&mut out)?;
    }
    Ok(out)
}

/// A transform message carrying `plain` encrypted (MS-SMB2 3.1.4.3). `nonce` holds at least
/// the bytes the cipher uses (12 for GCM, 11 for CCM); the rest of the field stays zero.
pub fn encrypt(
    cipher_: u16,
    key: &Key,
    session_id: u64,
    nonce: &[u8; 16],
    plain: &[u8],
) -> Result<Vec<u8>, ErrorStack> {
    let (c, nonce_len) = aead(cipher_);
    let mut field = [0u8; 16];
    for (slot, byte) in field.iter_mut().zip(nonce).take(nonce_len) {
        *slot = *byte;
    }
    let mut w = Writer::new();
    w.bytes(&TRANSFORM_ID)
        .bytes(&[0; 16])
        .bytes(&field)
        .u32(to_u32(plain.len()))
        .u16(0)
        .u16(1) // encrypted
        .u64(session_id);
    let aad = w.buf.get(20..TRANSFORM_LEN).unwrap_or(&[]).to_vec();
    let iv = field.get(..nonce_len).unwrap_or(&field);
    let (sealed, tag) = seal(c, key, iv, &aad, plain)?;
    if let Some(slot) = w.buf.get_mut(4..20) {
        slot.copy_from_slice(&tag);
    }
    w.bytes(&sealed);
    Ok(w.buf)
}

/// Session id of a transform message, `None` if it is not one.
pub fn transform_session(frame: &[u8]) -> Option<u64> {
    if bytes_at(frame, 0, 4)? != TRANSFORM_ID {
        return None;
    }
    u64_at(frame, 44)
}

/// The plaintext of a transform message; `None` if the tag does not match (altered or not
/// for this key) or the message is cut short.
pub fn decrypt(cipher_: u16, key: &Key, frame: &[u8]) -> Option<Vec<u8>> {
    let (c, nonce_len) = aead(cipher_);
    let tag = bytes_at(frame, 4, 16)?;
    let nonce = bytes_at(frame, 20, nonce_len)?;
    let size = super::wire::u32_at(frame, 36)? as usize;
    let aad = bytes_at(frame, 20, 32)?;
    let sealed = bytes_at(frame, TRANSFORM_LEN, size)?;
    open(c, key, nonce, aad, sealed, tag).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Vectors computed with smbprotocol 1.17.0 (`smbprotocol.session._smb3kdf` and the
    // signing and encryption code of `smbprotocol.connection`), from the inputs below:
    // `rust/vecteurs_smb.py` writes them into `vectors.rs`.
    const KEY: [u8; 16] = *b"0123456789abcdef";

    #[test]
    fn kdf_matches_smbprotocol() {
        let preauth = [0x5Au8; 64];
        let keys = session_keys(dialect::SMB311, &KEY, &preauth).unwrap();
        assert_eq!(keys.signing.to_vec(), hex(SIGNING_311));
        assert_eq!(keys.encryption.to_vec(), hex(ENCRYPTION_311));
        assert_eq!(keys.decryption.to_vec(), hex(DECRYPTION_311));
        let keys = session_keys(dialect::SMB300, &KEY, &preauth).unwrap();
        assert_eq!(keys.signing.to_vec(), hex(SIGNING_300));
        assert_eq!(keys.encryption.to_vec(), hex(ENCRYPTION_300));
        assert_eq!(keys.decryption.to_vec(), hex(DECRYPTION_300));
        let keys = session_keys(dialect::SMB210, &KEY, &preauth).unwrap();
        assert_eq!(keys.signing, KEY);
    }

    fn message() -> Vec<u8> {
        let mut w = Writer::new();
        super::super::msg::Header {
            command: 5,
            message_id: 42,
            session_id: 7,
            tree_id: 3,
            flags: super::super::msg::flag::SIGNED,
            ..Default::default()
        }
        .write(&mut w);
        w.bytes(b"body of the message");
        w.buf
    }

    #[test]
    fn signatures_match_smbprotocol() {
        let m = message();
        assert_eq!(
            signature(signing::AES_CMAC, &KEY, &m).unwrap().to_vec(),
            hex(CMAC)
        );
        assert_eq!(
            signature(signing::AES_GMAC, &KEY, &m).unwrap().to_vec(),
            hex(GMAC)
        );
        assert_eq!(
            signature(signing::HMAC_SHA256, &KEY, &m).unwrap().to_vec(),
            hex(HMAC)
        );
        let mut signed = m.clone();
        sign(signing::AES_CMAC, &KEY, &mut signed).unwrap();
        assert!(verify(signing::AES_CMAC, &KEY, &signed).unwrap());
        signed[70] ^= 1;
        assert!(!verify(signing::AES_CMAC, &KEY, &signed).unwrap());
    }

    #[test]
    fn encryption_matches_smbprotocol_and_round_trips() {
        let m = message();
        let nonce = [0x11u8; 16];
        for (c, expected) in [(cipher::AES_128_GCM, GCM), (cipher::AES_128_CCM, CCM)] {
            let frame = encrypt(c, &KEY, 7, &nonce, &m).unwrap();
            assert_eq!(frame, hex(expected), "cipher {c}");
            assert_eq!(transform_session(&frame), Some(7));
            assert_eq!(decrypt(c, &KEY, &frame), Some(m.clone()));
            let mut altered = frame.clone();
            *altered.last_mut().unwrap() ^= 1;
            assert_eq!(decrypt(c, &KEY, &altered), None);
            assert_eq!(decrypt(c, &KEY, &frame[..60]), None);
        }
    }

    #[test]
    fn preauth_chains() {
        let h = preauth_next(&[0; 64], b"negotiate").unwrap();
        assert_eq!(h.to_vec(), hex(PREAUTH));
    }

    include!("vectors.rs");
}

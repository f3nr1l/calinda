// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The KDF MS-GKDI uses everywhere (MS-GKDI 3.1.4.1.1, `SP800_108_CTR_HMAC`): SP800-108 in
//! counter mode with HMAC, counter before the fixed input, 4-byte counter and 4-byte length.
//! The same construction as the SMB 3 key derivation of `smb::crypto`, generalised to any
//! output length and digest. OpenSSL (already linked) provides the HMAC.

use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

/// Derives `length` bytes from `key` with label and context, as MS-GKDI's KDF. The fixed input
/// is `label || 0x00 || context || (length-in-bits, 4-byte big-endian)`; each block is
/// `HMAC(key, counter_be32 || fixed)`, counter from 1, concatenated and truncated.
pub fn sp800_108_ctr(
    digest: MessageDigest,
    key: &[u8],
    label: &[u8],
    context: &[u8],
    length: usize,
) -> Result<Vec<u8>, ErrorStack> {
    let pkey = PKey::hmac(key)?;
    let l_bits = u32::try_from(length.saturating_mul(8)).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(length);
    let mut counter: u32 = 1;
    while out.len() < length {
        let mut signer = Signer::new(digest, &pkey)?;
        signer.update(&counter.to_be_bytes())?;
        signer.update(label)?;
        signer.update(&[0])?;
        signer.update(context)?;
        signer.update(&l_bits.to_be_bytes())?;
        out.extend_from_slice(&signer.sign_to_vec()?);
        counter = counter.wrapping_add(1);
    }
    out.truncate(length);
    Ok(out)
}

/// The KDF context of a group key (MS-GKDI): the root key GUID in little-endian wire form, then
/// the L0/L1/L2 indices as signed 4-byte little-endian.
pub fn kdf_context(root_key_id: &[u8; 16], l0: i32, l1: i32, l2: i32) -> Vec<u8> {
    let mut c = Vec::with_capacity(28);
    c.extend_from_slice(root_key_id);
    c.extend_from_slice(&l0.to_le_bytes());
    c.extend_from_slice(&l1.to_le_bytes());
    c.extend_from_slice(&l2.to_le_bytes());
    c
}

/// `"KDS service\0"` in UTF-16LE, the label MS-GKDI passes to the KDF.
pub fn kds_service_label() -> Vec<u8> {
    "KDS service\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Vectors from dpapi-ng's _crypto.kdf (the same SP800-108 construction), synthetic inputs.
    #[test]
    fn kdf_matches_the_reference() {
        let out =
            sp800_108_ctr(MessageDigest::sha512(), &[1u8; 64], b"abc", &[2u8; 10], 32).unwrap();
        assert_eq!(
            out,
            hex("7549eb597b53fdd99f3347778a7941ad0584d6c6c24162f7a9805302f7e55ad5")
        );
        let out = sp800_108_ctr(MessageDigest::sha256(), &[3u8; 32], b"label", b"ctx", 48).unwrap();
        assert_eq!(
            out,
            hex(
                "b1e753fbf1a1f0e059dc6b4cf81617a3cfa42b674884be133218b9500d2f3993c0da7880ddc749f5c4b8806724e6a89c"
            )
        );
    }

    #[test]
    fn the_label_is_kds_service_in_utf16() {
        assert_eq!(
            kds_service_label(),
            b"K\x00D\x00S\x00 \x00s\x00e\x00r\x00v\x00i\x00c\x00e\x00\x00\x00"
        );
    }

    #[test]
    fn the_context_concatenates_guid_and_indices() {
        let c = kdf_context(&[0xAB; 16], 361, 20, -1);
        assert_eq!(&c[0..16], &[0xAB; 16]);
        assert_eq!(&c[16..20], &361i32.to_le_bytes());
        assert_eq!(&c[20..24], &20i32.to_le_bytes());
        assert_eq!(&c[24..28], &(-1i32).to_le_bytes());
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
            .collect()
    }
}

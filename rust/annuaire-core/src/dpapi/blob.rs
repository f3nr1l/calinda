// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A DPAPI-NG blob (the body of `msLAPS-EncryptedPassword` after its 16-byte header): a CMS
//! `EnvelopedData` with one `KEKRecipientInfo`. It gives the key identifier (which group key),
//! the protection descriptor (whose holder may decrypt), the wrapped content-encryption key and
//! the AES-GCM encrypted content. The LAPS variant appends the encrypted content after the
//! structure rather than inside it.

use super::DpapiError;
use super::asn1::Reader;
use super::envelope::KeyIdentifier;
use super::security_descriptor::target_sd_for_sid;

const OID_ENVELOPED_DATA: &str = "1.2.840.113549.1.7.3";
const OID_MS_SOFTWARE: &str = "1.3.6.1.4.1.311.74.1";
const OID_SID_DESCRIPTOR: &str = "1.3.6.1.4.1.311.74.1.1";
const OID_AES256_WRAP: &str = "2.16.840.1.101.3.4.1.45";
const OID_AES256_GCM: &str = "2.16.840.1.101.3.4.1.46";

/// Context tags used in the structure.
const EXPLICIT_0: u8 = 0xA0;
const IMPLICIT_0: u8 = 0x80;
const KEK_RECIPIENT: u8 = 0xA2;
const GENERALIZED_TIME: u8 = 0x18;

/// Everything a DPAPI-NG blob yields for decryption.
#[derive(Debug, Clone)]
pub struct DpapiBlob {
    pub key_identifier: KeyIdentifier,
    /// The target security descriptor built from the protection-descriptor SID.
    pub target_sd: Vec<u8>,
    /// The wrapped content-encryption key (AES key wrap, RFC 3394).
    pub enc_cek: Vec<u8>,
    /// The AES-256-GCM nonce.
    pub gcm_iv: Vec<u8>,
    /// The encrypted content (a UTF-16 JSON for Windows LAPS).
    pub enc_content: Vec<u8>,
}

impl DpapiBlob {
    pub fn parse(data: &[u8]) -> Result<Self, DpapiError> {
        let mut top = Reader::new(data);
        let mut content_info = top.sequence()?;
        // For the LAPS variant the encrypted content is appended after the ContentInfo.
        let appended = top.rest();

        if content_info.oid()? != OID_ENVELOPED_DATA {
            return Err(DpapiError::Unsupported("CMS content type".into()));
        }
        let enveloped = content_info.context(EXPLICIT_0)?;
        let mut ed = Reader::new(enveloped).sequence()?;
        if ed.integer()? != 2 {
            return Err(DpapiError::Malformed("EnvelopedData version".into()));
        }

        let mut recipients = ed.set()?;
        let mut kek = Reader::new(recipients.context(KEK_RECIPIENT)?);
        if kek.integer()? != 4 {
            return Err(DpapiError::Malformed("KEKRecipientInfo version".into()));
        }

        // KEKIdentifier: keyIdentifier OCTET STRING, optional date, optional OtherKeyAttribute.
        let mut kekid = kek.sequence()?;
        let key_identifier = KeyIdentifier::parse(kekid.octet_string()?)?;
        if kekid.peek_tag() == Some(GENERALIZED_TIME) {
            kekid.skip()?;
        }
        let mut other = kekid.sequence()?;
        if other.oid()? != OID_MS_SOFTWARE {
            return Err(DpapiError::Unsupported("KEK attribute id".into()));
        }
        let sid = parse_sid_descriptor(other.rest())?;
        let target_sd = target_sd_for_sid(&sid)?;

        // keyEncryptionAlgorithm then encryptedKey.
        let mut cek_algo = kek.sequence()?;
        if cek_algo.oid()? != OID_AES256_WRAP {
            return Err(DpapiError::Unsupported("CEK wrap algorithm".into()));
        }
        let enc_cek = kek.octet_string()?.to_vec();

        // EncryptedContentInfo: contentType, algorithm (AES-GCM + iv), optional [0] content.
        let mut eci = ed.sequence()?;
        eci.oid()?; // content type
        let mut content_algo = eci.sequence()?;
        if content_algo.oid()? != OID_AES256_GCM {
            return Err(DpapiError::Unsupported("content algorithm".into()));
        }
        let gcm_iv = Reader::new(content_algo.rest())
            .sequence()?
            .octet_string()?
            .to_vec();
        let enc_content = if eci.peek_tag() == Some(IMPLICIT_0) {
            eci.context(IMPLICIT_0)?.to_vec()
        } else {
            appended.to_vec()
        };
        if enc_content.is_empty() {
            return Err(DpapiError::Malformed("no encrypted content".into()));
        }

        Ok(Self {
            key_identifier,
            target_sd,
            enc_cek,
            gcm_iv,
            enc_content,
        })
    }
}

/// The SID string of a SID protection descriptor (MS-GKDI 2.2.1 OID 1.3.6.1.4.1.311.74.1.1):
/// `SEQUENCE { OID, SEQUENCE { SEQUENCE { SEQUENCE { UTF8String "SID", UTF8String <sid> } } } }`.
fn parse_sid_descriptor(der: &[u8]) -> Result<String, DpapiError> {
    let mut outer = Reader::new(der).sequence()?;
    if outer.oid()? != OID_SID_DESCRIPTOR {
        return Err(DpapiError::Unsupported("protection descriptor type".into()));
    }
    let mut inner = outer.sequence()?.sequence()?.sequence()?;
    let kind = inner.utf8()?;
    let value = inner.utf8()?;
    if kind != "SID" {
        return Err(DpapiError::Unsupported(format!("descriptor '{kind}'")));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOB_HEX: &str = "3082013806092a864886f70d010703a0820129308201250201023181f5a281f20201043081b50478010000004b44534b0000000069010000140000000700000067452301ab89efcd0123456789abcdef2000000012000000120000000104070a0d101316191c1f2225282b2e3134373a3d404346494c4f5255585b5e770069006e002e0074006500730074000000770069006e002e0074006500730074000000303906092b0601040182374a01302c060a2b0601040182374a0101301e301c301a0c035349440c13532d312d352d32312d312d322d332d31303030300b060960864801650304012d0428cececececececececececececececececececececececececececececececececececececececece302806092a864886f70d010701301b060960864801650304012e300e040c000102030405060708090a0b7468652d656e637279707465642d636f6e74656e74";
    const SID: &str = "S-1-5-21-1-2-3-1000";

    #[test]
    fn parses_a_laps_style_blob() {
        let blob = DpapiBlob::parse(&hex(BLOB_HEX)).unwrap();
        assert_eq!(blob.gcm_iv.len(), 12);
        assert_eq!(blob.enc_content, b"the-encrypted-content");
        assert_eq!(blob.enc_cek, vec![0xCEu8; 40]);
        assert_eq!(blob.target_sd, target_sd_for_sid(SID).unwrap());
        assert_eq!(blob.key_identifier.l0, 361);
    }

    fn hex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .filter_map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
            .collect()
    }
}

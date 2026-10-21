// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The SPNEGO wrapping of the Kerberos tokens (RFC 4178), with Kerberos as the only
//! mechanism offered: the client cannot fall back to NTLM (ADR 0017, § 2).

/// OID of SPNEGO, 1.3.6.1.5.5.2.
const SPNEGO: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// OID of Kerberos V5, 1.2.840.113554.1.2.2.
const KRB5: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];

fn length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|b| **b == 0).count();
        let significant = bytes.get(skip..).unwrap_or(&[]);
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
}

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    length(content.len(), &mut out);
    out.extend_from_slice(content);
    out
}

/// `NegTokenInit` offering Kerberos alone, with its first token.
pub fn init(mech_token: &[u8]) -> Vec<u8> {
    let mech_types = tlv(0xA0, &tlv(0x30, &tlv(0x06, KRB5)));
    let token = tlv(0xA2, &tlv(0x04, mech_token));
    let neg_token_init = tlv(0x30, &[mech_types, token].concat());
    let inner = [tlv(0x06, SPNEGO), tlv(0xA0, &neg_token_init)].concat();
    tlv(0x60, &inner)
}

/// A TLV read from `b`: (tag, content, rest).
fn read(b: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = b.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7F) as usize;
        if n == 0 || n > 4 {
            return None;
        }
        let digits = rest.get(..n)?;
        let len = digits.iter().fold(0usize, |acc, d| acc << 8 | *d as usize);
        (len, rest.get(n..)?)
    };
    Some((tag, rest.get(..len)?, rest.get(len..)?))
}

/// What the server answers (`NegTokenResp`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    /// 0 accept-completed, 1 accept-incomplete, 2 reject, 3 request-mic.
    pub state: Option<u8>,
    pub token: Option<Vec<u8>>,
}

pub const REJECT: u8 = 2;

/// Reads a `NegTokenResp`; `None` if it is not one.
pub fn response(b: &[u8]) -> Option<Response> {
    let (tag, content, _) = read(b)?;
    if tag != 0xA1 {
        return None;
    }
    let (tag, mut fields, _) = read(content)?;
    if tag != 0x30 {
        return None;
    }
    let mut r = Response::default();
    while !fields.is_empty() {
        let (tag, value, rest) = read(fields)?;
        match tag {
            0xA0 => {
                let (t, v, _) = read(value)?;
                if t != 0x0A || v.len() != 1 {
                    return None;
                }
                r.state = v.first().copied();
            }
            0xA2 => {
                let (t, v, _) = read(value)?;
                if t != 0x04 {
                    return None;
                }
                r.token = Some(v.to_vec());
            }
            _ => {} // supportedMech, mechListMIC
        }
        fields = rest;
    }
    Some(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_wraps_the_token() {
        let t = init(&[1, 2, 3]);
        assert_eq!(
            t,
            [
                0x60, 0x22, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02, 0xA0, 0x18, 0x30, 0x16,
                0xA0, 0x0D, 0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02,
                0x02, 0xA2, 0x05, 0x04, 0x03, 1, 2, 3
            ]
        );
        let long = init(&[7; 300]);
        assert_eq!(&long[..2], &[0x60, 0x82]);
        let (tag, content, rest) = read(&long).unwrap();
        assert_eq!((tag, content.len() + 4, rest.len()), (0x60, long.len(), 0));
    }

    #[test]
    fn reads_responses() {
        // accept-completed, supportedMech krb5, responseToken, mechListMIC
        let mut fields = tlv(0xA0, &[0x0A, 0x01, 0x00]);
        fields.extend(tlv(0xA1, &tlv(0x06, KRB5)));
        fields.extend(tlv(0xA2, &tlv(0x04, &[9; 200])));
        fields.extend(tlv(0xA3, &tlv(0x04, &[8; 4])));
        let resp = tlv(0xA1, &tlv(0x30, &fields));
        assert_eq!(
            response(&resp),
            Some(Response {
                state: Some(0),
                token: Some(vec![9; 200])
            })
        );
        let reject = tlv(0xA1, &tlv(0x30, &tlv(0xA0, &[0x0A, 0x01, 0x02])));
        assert_eq!(response(&reject).unwrap().state, Some(REJECT));
        assert_eq!(response(&init(&[1])), None);
        assert_eq!(response(&resp[..10]), None);
    }
}

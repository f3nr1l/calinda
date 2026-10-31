// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A minimal DER reader, enough for the CMS `EnvelopedData` of a DPAPI-NG blob: definite-length
//! TLVs with single-byte tags (the structures use no high tag numbers), read in sequence. Only
//! what the blob needs — sequence, set, octet string, object identifier, integer, UTF-8 string
//! and context-tagged values.

use super::DpapiError;

fn err(what: &str) -> DpapiError {
    DpapiError::Malformed(format!("DER: {what}"))
}

/// A cursor over a DER-encoded slice.
#[derive(Clone, Debug)]
pub struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// The bytes not yet read (an `ANY` field, or content appended after a structure).
    pub fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.data.first().copied()
    }

    /// Reads one TLV, returning `(tag, content)` and advancing past it.
    fn tlv(&mut self) -> Result<(u8, &'a [u8]), DpapiError> {
        let tag = *self.data.first().ok_or_else(|| err("end of data"))?;
        let first_len = *self.data.get(1).ok_or_else(|| err("missing length"))?;
        let (length, header) = if first_len < 0x80 {
            (usize::from(first_len), 2)
        } else {
            let n = usize::from(first_len & 0x7F);
            if n == 0 || n > 4 {
                return Err(err("unsupported length form"));
            }
            let mut l = 0usize;
            for i in 0..n {
                let byte = *self
                    .data
                    .get(2 + i)
                    .ok_or_else(|| err("truncated length"))?;
                l = (l << 8) | usize::from(byte);
            }
            (l, 2 + n)
        };
        let end = header
            .checked_add(length)
            .ok_or_else(|| err("length overflow"))?;
        let content = self
            .data
            .get(header..end)
            .ok_or_else(|| err("truncated value"))?;
        self.data = self.data.get(end..).unwrap_or(&[]);
        Ok((tag, content))
    }

    /// Reads a TLV whose tag must be `tag`, returning its content.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], DpapiError> {
        let (got, content) = self.tlv()?;
        if got != tag {
            return Err(DpapiError::Malformed(format!(
                "DER: expected tag 0x{tag:02X}, found 0x{got:02X}"
            )));
        }
        Ok(content)
    }

    /// A SEQUENCE's content as its own reader.
    pub fn sequence(&mut self) -> Result<Reader<'a>, DpapiError> {
        Ok(Reader::new(self.expect(0x30)?))
    }

    /// A SET's content as its own reader.
    pub fn set(&mut self) -> Result<Reader<'a>, DpapiError> {
        Ok(Reader::new(self.expect(0x31)?))
    }

    pub fn octet_string(&mut self) -> Result<&'a [u8], DpapiError> {
        self.expect(0x04)
    }

    /// The content of a context-tagged value (e.g. 0xA0 for `[0]`, 0x80 for `[0]` primitive).
    pub fn context(&mut self, tag: u8) -> Result<&'a [u8], DpapiError> {
        self.expect(tag)
    }

    /// A small non-negative INTEGER.
    pub fn integer(&mut self) -> Result<u64, DpapiError> {
        let b = self.expect(0x02)?;
        if b.is_empty() || b.len() > 8 {
            return Err(err("integer out of range"));
        }
        Ok(b.iter()
            .fold(0u64, |acc, &byte| (acc << 8) | u64::from(byte)))
    }

    pub fn utf8(&mut self) -> Result<String, DpapiError> {
        let b = self.expect(0x0C)?;
        String::from_utf8(b.to_vec()).map_err(|_| err("invalid UTF-8 string"))
    }

    /// An OBJECT IDENTIFIER as its dotted decimal form.
    pub fn oid(&mut self) -> Result<String, DpapiError> {
        let b = self.expect(0x06)?;
        let (&first, rest) = b.split_first().ok_or_else(|| err("empty OID"))?;
        let mut out = format!("{}.{}", first / 40, first % 40);
        let mut value: u64 = 0;
        for &byte in rest {
            value = (value << 7) | u64::from(byte & 0x7F);
            if byte & 0x80 == 0 {
                out.push('.');
                out.push_str(&value.to_string());
                value = 0;
            }
        }
        Ok(out)
    }

    /// Skips the next TLV whatever it is.
    pub fn skip(&mut self) -> Result<(), DpapiError> {
        self.tlv()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_nested_sequence() {
        // SEQUENCE { INTEGER 2, OCTET STRING "ab", OID 2.16.840.1.101.3.4.1.46 }
        let der = [
            0x30, 0x12, 0x02, 0x01, 0x02, 0x04, 0x02, b'a', b'b', 0x06, 0x09, 0x60, 0x86, 0x48,
            0x01, 0x65, 0x03, 0x04, 0x01, 0x2E,
        ];
        let mut seq = Reader::new(&der).sequence().unwrap();
        assert_eq!(seq.integer().unwrap(), 2);
        assert_eq!(seq.octet_string().unwrap(), b"ab");
        assert_eq!(seq.oid().unwrap(), "2.16.840.1.101.3.4.1.46");
        assert!(seq.is_empty());
    }

    #[test]
    fn a_wrong_tag_is_an_error() {
        let der = [0x02, 0x01, 0x05];
        assert!(Reader::new(&der).sequence().is_err());
    }

    #[test]
    fn a_long_form_length_is_read() {
        let mut content = vec![0x04, 0x82, 0x01, 0x00]; // OCTET STRING, length 256
        content.extend(std::iter::repeat_n(0x41u8, 256));
        let got = Reader::new(&content).octet_string().unwrap();
        assert_eq!(got.len(), 256);
    }
}

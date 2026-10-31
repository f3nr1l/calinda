// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Export of a list or of the results of a query to a CSV file (J9.8, ADR 0026 § 5).
//!
//! The objects are those of the table (its DNs), read again on the DC with the attributes of
//! the columns chosen (`read`, requests sent together by `CHUNK`). A column is an attribute;
//! its header is the LDAP name, which the import reads back, or the label the interface gives.
//! The values of a multivalued attribute are joined by a separator of their own (`|` by
//! default), distinct from the one of the fields. Two forms:
//!
//! - **readable**: SID and GUID as text, dates (large integers of `DATE_ATTRIBUTES`,
//!   generalized and UTC times) by the formatter of the caller (local time in the interface,
//!   UTC here), « never » and 0 as an empty field, security descriptors in SDDL, other bytes in
//!   base64;
//! - **raw**: the values as stored, bytes that are not text in base64.
//!
//! An attribute returned by ranges (`member;range=0-1499`, beyond 1,500 values on Windows) is
//! exported with the first range and named in `Exported::truncated`. Pure, apart from `read`.

use annuaire_codecs::time::{self, UtcTime};
use annuaire_codecs::{Guid, Sid, csv, integer};

use crate::changes::{base64_encode, text_value};
use crate::connection::{Connection, Failure};
use crate::schema::{self, AttributeDescription, Schema, Syntax};
use crate::search::{Burst, BurstAnswer};
use crate::session::{Entry, Scope};

/// Objects read per burst of requests.
pub const CHUNK: usize = 200;

/// Separator of the values of a multivalued attribute, by default.
pub const VALUES_SEPARATOR: &str = "|";

/// A column of the file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub attribute: String,
    pub header: String,
}

impl Column {
    pub fn named(attribute: &str) -> Self {
        Self {
            attribute: attribute.to_owned(),
            header: attribute.to_owned(),
        }
    }
}

/// How the file is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Options {
    pub separator: char,
    pub values_separator: String,
    pub readable: bool,
    /// Byte order mark, for Excel.
    pub bom: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            separator: ';',
            values_separator: VALUES_SEPARATOR.to_owned(),
            readable: true,
            bom: true,
        }
    }
}

/// A date as the caller writes it.
pub type Dates<'a> = dyn Fn(UtcTime) -> String + 'a;

/// `AAAA-MM-JJ hh:mm:ss`, UTC.
pub fn utc_date(time: UtcTime) -> String {
    let c = time.civil();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        c.year, c.month, c.day, c.hour, c.minute, c.second
    )
}

fn binary(value: &[u8]) -> String {
    text_value(value).map_or_else(|| base64_encode(value), str::to_owned)
}

/// One value in the readable form.
pub fn readable_value(
    description: Option<&AttributeDescription>,
    value: &[u8],
    dates: &Dates<'_>,
) -> String {
    let Some(d) = description else {
        return binary(value);
    };
    match d.syntax {
        Syntax::Sid => Sid::decode(value).map_or_else(|_| base64_encode(value), |s| s.to_string()),
        Syntax::Octets if schema::is_guid(d) && value.len() == 16 => {
            Guid::decode(value).map_or_else(|_| base64_encode(value), |g| g.to_string())
        }
        Syntax::LargeInteger if schema::is_date(d) => {
            let n = text_value(value).and_then(|t| t.trim().parse::<i64>().ok());
            match n {
                Some(0) => String::new(),
                Some(n) => match time::nttime_to_utc(n) {
                    Ok(Some(t)) => dates(t),
                    Ok(None) => String::new(),
                    Err(_) => binary(value),
                },
                None => binary(value),
            }
        }
        Syntax::GeneralizedTime | Syntax::UtcTime => text_value(value)
            .and_then(|t| time::decode_generalized_time(t).ok())
            .map_or_else(|| binary(value), dates),
        Syntax::Descriptor => annuaire_codecs::sd::SecurityDescriptor::decode(value)
            .ok()
            .and_then(|sd| annuaire_codecs::sddl::sd_to_sddl(&sd, None).ok())
            .unwrap_or_else(|| base64_encode(value)),
        Syntax::Boolean => text_value(value).unwrap_or_default().to_owned(),
        Syntax::Integer | Syntax::Enumeration => {
            // As stored: a signed decimal.
            text_value(value)
                .and_then(|t| integer::decode(t.as_bytes(), integer::Width::Bits32).ok())
                .map_or_else(|| binary(value), |n| n.to_string())
        }
        _ => binary(value),
    }
}

/// The field of an attribute: its values joined.
pub fn field(
    description: Option<&AttributeDescription>,
    values: &[Vec<u8>],
    options: &Options,
    dates: &Dates<'_>,
) -> String {
    values
        .iter()
        .map(|v| {
            if options.readable {
                readable_value(description, v, dates)
            } else {
                binary(v)
            }
        })
        .collect::<Vec<_>>()
        .join(&options.values_separator)
}

/// What an export gives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exported {
    pub text: String,
    pub rows: usize,
    /// (DN, attribute) returned by ranges: the file has the first range only.
    pub truncated: Vec<(String, String)>,
}

/// The values of `attribute` in `entry`, and whether they come by ranges.
fn values_of<'a>(entry: &'a Entry, attribute: &str) -> (&'a [Vec<u8>], bool) {
    let prefix = format!("{};range=", attribute.to_lowercase());
    for (name, values) in &entry.attributes {
        if name.eq_ignore_ascii_case(attribute) {
            return (values, false);
        }
        if name.to_lowercase().starts_with(&prefix) {
            return (values, true);
        }
    }
    (&[], false)
}

/// The file of `entries` with `columns`. `dn` and `distinguishedName` are the DN of the entry.
pub fn write(
    entries: &[Entry],
    columns: &[Column],
    schema: &Schema,
    options: &Options,
    dates: &Dates<'_>,
) -> Exported {
    let header: Vec<&str> = columns.iter().map(|c| c.header.as_str()).collect();
    let mut rows = Vec::with_capacity(entries.len());
    let mut truncated = Vec::new();
    for entry in entries {
        let row = columns
            .iter()
            .map(|c| {
                if c.attribute.eq_ignore_ascii_case("dn")
                    || c.attribute.eq_ignore_ascii_case("distinguishedName")
                {
                    return entry.dn.clone();
                }
                let (values, ranged) = values_of(entry, &c.attribute);
                if ranged {
                    truncated.push((entry.dn.clone(), c.attribute.clone()));
                }
                field(schema.attribute(&c.attribute), values, options, dates)
            })
            .collect();
        rows.push(row);
    }
    Exported {
        text: csv::write(&header, &rows, options.separator, options.bom),
        rows: entries.len(),
        truncated,
    }
}

/// Reads `dns` with `attributes` on the DC of `connection`, `CHUNK` requests sent together at a
/// time; the objects that no longer exist are left out, the order is kept. Blocking.
pub fn read(
    connection: &Connection,
    dns: &[String],
    attributes: &[String],
) -> Result<Vec<Entry>, Failure> {
    let (dns, attributes) = (dns.to_vec(), attributes.to_vec());
    connection.run(true, move |link| {
        let mut out = Vec::with_capacity(dns.len());
        for chunk in dns.chunks(CHUNK) {
            let mut burst = Burst::new();
            for dn in chunk {
                burst.search(
                    link.session.as_mut(),
                    dn,
                    Scope::Base,
                    "(objectClass=*)",
                    &attributes,
                    0,
                    None,
                )?;
            }
            for answer in burst.receive(link.session.as_mut(), Some(link.timeout))? {
                if let BurstAnswer::Entries(entries) = answer {
                    out.extend(entries);
                }
            }
        }
        Ok(out)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::AttributeDescription;

    fn description(name: &str, syntax: Syntax, single: bool) -> AttributeDescription {
        AttributeDescription {
            name: name.into(),
            syntax,
            single,
            lower: None,
            upper: None,
            system: false,
            constructed: false,
            link: None,
            guid: Vec::new(),
        }
    }

    fn schema() -> Schema {
        let mut s = Schema::default();
        for d in [
            description("objectSid", Syntax::Sid, true),
            description("objectGUID", Syntax::Octets, true),
            description("accountExpires", Syntax::LargeInteger, true),
            description("whenCreated", Syntax::GeneralizedTime, true),
            description("otherTelephone", Syntax::Unicode, false),
            description("cn", Syntax::Unicode, true),
        ] {
            s.attributes.insert(d.name.to_lowercase(), d);
        }
        s
    }

    #[test]
    fn readable_and_raw() {
        let sid = "S-1-5-21-1-2-3-1104".parse::<Sid>().unwrap().encode();
        let guid = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let entry = Entry {
            dn: "CN=Alice; M,OU=X,DC=x".into(),
            attributes: vec![
                ("cn".into(), vec![b"Alice; M".to_vec()]),
                ("objectSid".into(), vec![sid.clone()]),
                ("objectGUID".into(), vec![guid.to_vec()]),
                // 2026-01-01T00:00:00Z.
                (
                    "accountExpires".into(),
                    vec![b"134116992000000000".to_vec()],
                ),
                ("whenCreated".into(), vec![b"20261028183000.0Z".to_vec()]),
                (
                    "otherTelephone".into(),
                    vec![b"01".to_vec(), b"02".to_vec()],
                ),
            ],
        };
        let columns: Vec<Column> = [
            "dn",
            "cn",
            "objectSid",
            "objectGUID",
            "accountExpires",
            "whenCreated",
            "otherTelephone",
            "absent",
        ]
        .iter()
        .map(|a| Column::named(a))
        .collect();
        let out = write(
            std::slice::from_ref(&entry),
            &columns,
            &schema(),
            &Options::default(),
            &utc_date,
        );
        assert!(out.text.starts_with(csv::BOM));
        let table = csv::read(out.text.as_bytes(), Some(';')).unwrap();
        let row = &table.records.get(1).unwrap().fields;
        assert_eq!(
            row,
            &vec![
                "CN=Alice; M,OU=X,DC=x".to_owned(),
                "Alice; M".into(),
                "S-1-5-21-1-2-3-1104".into(),
                "04030201-0605-0807-090a-0b0c0d0e0f10".into(),
                "2026-01-01 00:00:00".into(),
                "2026-10-28 18:30:00".into(),
                "01|02".into(),
                String::new(),
            ]
        );
        let raw = write(
            &[entry],
            &columns,
            &schema(),
            &Options {
                readable: false,
                bom: false,
                separator: ',',
                ..Options::default()
            },
            &utc_date,
        );
        assert!(!raw.text.starts_with(csv::BOM));
        let row = csv::read(raw.text.as_bytes(), Some(',')).unwrap().records;
        let row = &row.get(1).unwrap().fields;
        assert_eq!(row.get(2).unwrap(), &base64_encode(&sid));
        assert_eq!(row.get(4).unwrap(), "134116992000000000");
    }

    #[test]
    fn never_is_empty_and_ranges_are_named() {
        let d = description("accountExpires", Syntax::LargeInteger, true);
        assert_eq!(readable_value(Some(&d), b"0", &utc_date), "");
        assert_eq!(
            readable_value(Some(&d), b"9223372036854775807", &utc_date),
            ""
        );
        let entry = Entry {
            dn: "CN=G,DC=x".into(),
            attributes: vec![("member;range=0-1499".into(), vec![b"CN=a".to_vec()])],
        };
        let out = write(
            &[entry],
            &[Column::named("member")],
            &Schema::default(),
            &Options::default(),
            &utc_date,
        );
        assert_eq!(out.truncated, vec![("CN=G,DC=x".into(), "member".into())]);
    }
}

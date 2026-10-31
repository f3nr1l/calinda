// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! CSV files of the export and of the import (J9.8, ADR 0026): RFC 4180 with the habits of
//! Excel. A field is quoted when it holds the separator, a quote, a line break or a space at
//! an end; a quote inside is doubled. Lines end with CRLF. Written in UTF-8, with a byte order
//! mark if asked (Excel takes a file without it for the code page of the system).
//!
//! The reading accepts what Excel and LibreOffice write: a byte order mark or not, CRLF or LF,
//! quoted fields over several lines, the separator `;`, `,` or a tab, found from the first line
//! when not given (the one that cuts it into the most fields, outside quotes). A file that is
//! not UTF-8 is refused with the position of the first wrong byte: Calinda does not guess a
//! code page. Pure.

use std::fmt;

/// The byte order mark of UTF-8.
pub const BOM: &str = "\u{feff}";

/// Separators tried when the file does not say.
pub const SEPARATORS: [char; 3] = [';', ',', '\t'];

/// Why a file cannot be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CsvError {
    /// Byte `offset` starts a sequence that is not UTF-8.
    NotUtf8 { offset: usize },
    /// A quoted field opened on line `line` is never closed.
    UnclosedQuote { line: usize },
    /// Text after the closing quote of a field, on line `line`.
    AfterQuote { line: usize },
}

impl fmt::Display for CsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotUtf8 { offset } => write!(f, "not UTF-8 at byte {offset}"),
            Self::UnclosedQuote { line } => write!(f, "quote opened on line {line} not closed"),
            Self::AfterQuote { line } => write!(f, "text after a closing quote on line {line}"),
        }
    }
}

impl std::error::Error for CsvError {}

/// A record of the file and the line where it starts (1 for the first line of the file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub line: usize,
    pub fields: Vec<String>,
}

/// A file read: the separator used and its records, the header first. Empty lines are left
/// out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub separator: char,
    pub records: Vec<Record>,
}

/// The separator of a text whose first line is `first`: the one that gives the most fields
/// outside quotes, `;` if none is there (the habit of a French Excel).
pub fn guess_separator(first: &str) -> char {
    let mut counts = [0usize; SEPARATORS.len()];
    let mut quoted = false;
    for c in first.chars() {
        if c == '"' {
            quoted = !quoted;
        } else if !quoted {
            for (n, s) in counts.iter_mut().zip(SEPARATORS) {
                if c == s {
                    *n += 1;
                }
            }
        }
    }
    SEPARATORS
        .iter()
        .zip(counts)
        .fold(
            (';', 0),
            |best, (&s, n)| if n > best.1 { (s, n) } else { best },
        )
        .0
}

/// Reads `bytes` (a whole file); `separator` None: guessed from the first line.
pub fn read(bytes: &[u8], separator: Option<char>) -> Result<Table, CsvError> {
    let text = std::str::from_utf8(bytes).map_err(|e| CsvError::NotUtf8 {
        offset: e.valid_up_to(),
    })?;
    let text = text.strip_prefix(BOM).unwrap_or(text);
    let separator =
        separator.unwrap_or_else(|| guess_separator(text.lines().next().unwrap_or_default()));
    let mut records = Vec::new();
    let mut fields: Vec<String> = Vec::new();
    let mut field = String::new();
    let (mut line, mut start) = (1usize, 1usize);
    // The field began with a quote; it is inside its quotes; it was closed.
    let (mut quoted, mut inside, mut closed) = (false, false, false);
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if inside {
            match c {
                '"' if chars.peek() == Some(&'"') => {
                    chars.next();
                    field.push('"');
                }
                '"' => {
                    inside = false;
                    closed = true;
                }
                '\n' => {
                    line += 1;
                    field.push('\n');
                }
                // CRLF inside a field is kept as LF, as Excel writes it back.
                '\r' if chars.peek() == Some(&'\n') => {}
                _ => field.push(c),
            }
            continue;
        }
        match c {
            '"' if field.is_empty() && !quoted => {
                quoted = true;
                inside = true;
            }
            c if c == separator => {
                fields.push(std::mem::take(&mut field));
                (quoted, closed) = (false, false);
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                fields.push(std::mem::take(&mut field));
                (quoted, closed) = (false, false);
                push_record(&mut records, start, std::mem::take(&mut fields));
                line += 1;
                start = line;
            }
            // Spaces after a closing quote are tolerated, as by LibreOffice.
            ' ' | '\t' if closed => {}
            _ if closed => return Err(CsvError::AfterQuote { line }),
            _ => field.push(c),
        }
    }
    if inside {
        return Err(CsvError::UnclosedQuote { line: start });
    }
    if !field.is_empty() || !fields.is_empty() || quoted {
        fields.push(field);
        push_record(&mut records, start, fields);
    }
    Ok(Table { separator, records })
}

fn push_record(records: &mut Vec<Record>, line: usize, fields: Vec<String>) {
    if fields.iter().all(String::is_empty) {
        return;
    }
    records.push(Record { line, fields });
}

/// A field as written: quoted if it must be.
pub fn field(value: &str, separator: char) -> String {
    let must = value.contains(separator)
        || value.contains(['"', '\n', '\r'])
        || value.starts_with([' ', '\t'])
        || value.ends_with([' ', '\t']);
    if must {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_owned()
    }
}

/// One line, CRLF included.
pub fn line<S: AsRef<str>>(fields: &[S], separator: char) -> String {
    let mut out = fields
        .iter()
        .map(|f| field(f.as_ref(), separator))
        .collect::<Vec<_>>()
        .join(&separator.to_string());
    out.push_str("\r\n");
    out
}

/// A whole file: the header, then the rows; the byte order mark first if `bom`.
pub fn write<S: AsRef<str>>(
    header: &[S],
    rows: &[Vec<String>],
    separator: char,
    bom: bool,
) -> String {
    let mut out = String::new();
    if bom {
        out.push_str(BOM);
    }
    out.push_str(&line(header, separator));
    for row in rows {
        out.push_str(&line(row, separator));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(table: &Table) -> Vec<Vec<&str>> {
        table
            .records
            .iter()
            .map(|r| r.fields.iter().map(String::as_str).collect())
            .collect()
    }

    #[test]
    fn excel_file_with_bom_and_semicolons() {
        let bytes =
            "\u{feff}name;description\r\nAlice;\"Paris; 2e\"\r\n\r\n\"Bob \"\"B\"\"\";x\r\n";
        let table = read(bytes.as_bytes(), None).unwrap();
        assert_eq!(table.separator, ';');
        assert_eq!(
            fields(&table),
            [
                vec!["name", "description"],
                vec!["Alice", "Paris; 2e"],
                vec!["Bob \"B\"", "x"]
            ]
        );
        assert_eq!(table.records.get(2).map(|r| r.line), Some(4));
    }

    #[test]
    fn line_breaks_inside_quotes_and_last_line_without_end() {
        let table = read(b"a,b\n\"one\r\ntwo\",3\n4,\"\"", None).unwrap();
        assert_eq!(table.separator, ',');
        assert_eq!(
            fields(&table),
            [vec!["a", "b"], vec!["one\ntwo", "3"], vec!["4", ""]]
        );
        // The record after a field over two lines starts on line 4.
        assert_eq!(table.records.get(2).map(|r| r.line), Some(4));
    }

    #[test]
    fn separator_guessed_outside_quotes() {
        assert_eq!(guess_separator("\"a;b\",c,d"), ',');
        assert_eq!(guess_separator("a\tb\tc"), '\t');
        assert_eq!(guess_separator("seul"), ';');
    }

    #[test]
    fn refused_files() {
        assert_eq!(
            read(b"a;b\n\"x;y\n", None),
            Err(CsvError::UnclosedQuote { line: 2 })
        );
        assert_eq!(
            read(b"a;b\n\"x\"y;z\n", None),
            Err(CsvError::AfterQuote { line: 2 })
        );
        assert_eq!(
            read(b"a;\xe9t\xe9\n", None),
            Err(CsvError::NotUtf8 { offset: 2 })
        );
    }

    #[test]
    fn written_then_read_again() {
        let rows = vec![
            vec![
                "Jérôme; Dupont".to_owned(),
                "dit \"JD\"".into(),
                " espace".into(),
            ],
            vec!["deux\nlignes".into(), String::new(), "simple".into()],
        ];
        let text = write(&["cn", "description", "info"], &rows, ';', true);
        assert!(text.starts_with(BOM));
        assert!(text.contains("\"Jérôme; Dupont\";\"dit \"\"JD\"\"\";\" espace\"\r\n"));
        let table = read(text.as_bytes(), Some(';')).unwrap();
        let back: Vec<Vec<String>> = table
            .records
            .into_iter()
            .skip(1)
            .map(|r| r.fields)
            .collect();
        assert_eq!(back, rows);
    }
}

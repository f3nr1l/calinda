// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Conditional ACEs and resource attributes (MS-DTYP 2.4.4.17, 2.4.10.1).
//!
//! A callback ACE (`XA`, `XD`, `ZA`, `XU`) carries a conditional expression after its SID:
//! the `artx` signature then postfix tokens (literals, attributes, operators), padded with
//! zeros to a multiple of four bytes. A resource attribute ACE (`RA`, in the SACL) carries a
//! `CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1`: name, type, flags and values, located by offsets
//! relative to its start.
//!
//! [`read_condition`] builds a tree ([`Node`]); [`condition_to_sddl`] writes it **in the form
//! of Samba 4.22** (`security.descriptor.as_sddl`, recorded against the lab oracle,
//! `tests/vecteurs/sddl_conditionnel.json`): every operator in parentheses, operands
//! separated by one space; `@USER.`, `@DEVICE.`, `@RESOURCE.` in upper case, a local
//! attribute without prefix; integers in their base and with their sign when it is noted;
//! strings in double quotes without escaping; bytes `#0102FF`; lists `{1, 2, 3}`; SIDs
//! `SID(BA)` or `SID(S-1-5-21-…)` (no domain-relative abbreviation, as in Samba).
//!
//! The reverse path ([`condition_from_sddl`], [`encode_condition`],
//! [`resource_attribute_from_sddl`]) reads both Samba's form and Windows' form: keywords and
//! prefixes in any case, lower-case bytes, `TU` without `+`, `SID(DA)` (replaced by the full
//! SID, which gives the same bytes). `&&` binds tighter than `||`, every operator is
//! left-associative, integers are 64-bit tokens with their sign and base. Two known
//! differences: a lone `0` is decimal for Samba and octal for Windows (Samba is followed),
//! and Samba stores a `TB` resource attribute as `TU` and a `TD` SID as text (`samba = true`
//! reproduces those bytes; otherwise those of Windows and MS-DTYP).
//!
//! Port of `annuaire/core/codecs/condition.py`.

use std::fmt;

use crate::pytext::{self, PyInt, at, from, sub};
use crate::sddl::{DOMAIN_ABBREVIATIONS, sid_from_sddl, sid_to_sddl};
use crate::sid::{Sid, SidError};

/// Why a condition or a resource attribute was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionError {
    /// Binary form: missing signature, unknown token, truncated value, inconsistent stack.
    Malformed(String),
    /// SDDL text, with the position (in characters) where it goes wrong.
    Invalid { message: String, position: usize },
    /// A value that the binary form cannot hold (flags or integer beyond their width);
    /// Python raises a plain `ValueError` there.
    OutOfRange(String),
}

impl fmt::Display for ConditionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(m) | Self::OutOfRange(m) => f.write_str(m),
            Self::Invalid { message, position } => write!(f, "{message} (at {position})"),
        }
    }
}

impl std::error::Error for ConditionError {}

impl From<SidError> for ConditionError {
    fn from(e: SidError) -> Self {
        Self::Malformed(e.to_string())
    }
}

type Result<T> = std::result::Result<T, ConditionError>;

pub const SIGNATURE: &[u8] = b"artx";

// Tokens (MS-DTYP 2.4.4.17.4 to 2.4.4.17.8).
const STRING: u8 = 0x10;
const OCTETS: u8 = 0x18;
const COMPOSITE: u8 = 0x50;
const SID_TOKEN: u8 = 0x51;
pub const LOCAL_ATTRIBUTE: u8 = 0xF8;
pub const AND: u8 = 0xA0;
pub const OR: u8 = 0xA1;
pub const NOT: u8 = 0xA2;

fn is_integer_token(t: u8) -> bool {
    (0x01..=0x04).contains(&t)
}

/// Attribute token → prefix.
pub fn attribute_prefix(token: u8) -> Option<&'static str> {
    match token {
        0xF8 => Some(""),
        0xF9 => Some("@USER."),
        0xFA => Some("@RESOURCE."),
        0xFB => Some("@DEVICE."),
        _ => None,
    }
}

pub const BINARY: [(u8, &str); 10] = [
    (0x80, "=="),
    (0x81, "!="),
    (0x82, "<"),
    (0x83, "<="),
    (0x84, ">"),
    (0x85, ">="),
    (0x86, "Contains"),
    (0x88, "Any_of"),
    (0x8E, "Not_Contains"),
    (0x8F, "Not_Any_of"),
];

pub const UNARY: [(u8, &str); 10] = [
    (0x87, "Exists"),
    (0x8D, "Not_Exists"),
    (0x89, "Member_of"),
    (0x8A, "Device_Member_of"),
    (0x8B, "Member_of_any"),
    (0x8C, "Device_Member_of_Any"),
    (0x90, "Not_Member_of"),
    (0x91, "Not_Device_Member_of"),
    (0x92, "Not_Member_of_Any"),
    (0x93, "Not_Device_Member_of_Any"),
];

fn binary_name(code: u8) -> Option<&'static str> {
    BINARY.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

fn unary_name(code: u8) -> Option<&'static str> {
    UNARY.iter().find(|(c, _)| *c == code).map(|(_, n)| *n)
}

fn logical_name(code: u8) -> Option<&'static str> {
    match code {
        AND => Some("&&"),
        OR => Some("||"),
        _ => None,
    }
}

/// A node of a conditional expression.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Node {
    /// `sign`: 1 `+` noted, 2 `-`, 3 none. `base`: 1 octal, 2 decimal, 3 hexadecimal.
    /// `token`: 0x01 to 0x04 (8 to 64 bits); Samba and Windows write 0x04.
    Integer {
        value: i64,
        sign: u8,
        base: u8,
        token: u8,
    },
    String(String),
    Octets(Vec<u8>),
    Sid(Sid),
    Composite(Vec<Node>),
    /// `scope`: attribute token, 0xF8 local, 0xF9 user, 0xFA resource, 0xFB device.
    Attribute {
        scope: u8,
        name: String,
    },
    Operation {
        code: u8,
        operands: Vec<Node>,
    },
}

/// Deepest tree of nodes accepted, read from bytes or from SDDL: the codec walks trees
/// recursively. Python has the same bound (`PROFONDEUR_MAX`); real conditions hold a handful.
pub const MAX_DEPTH: usize = 500;

/// Deepest nesting of parentheses, `!` and lists accepted in SDDL: the parser descends
/// several functions per level. Python has the same bound (`IMBRICATION_MAX`).
pub const MAX_NESTING: usize = 128;

fn deeper(depth: usize) -> Result<usize> {
    if depth >= MAX_DEPTH {
        return Err(malformed("condition nested too deeply"));
    }
    Ok(depth + 1)
}

fn malformed(m: &str) -> ConditionError {
    ConditionError::Malformed(m.to_string())
}

fn with_length(bytes: &[u8], position: usize) -> Result<(&[u8], usize)> {
    let truncated = || malformed("truncated condition");
    let n = crate::read::le_u32(bytes, position).ok_or_else(truncated)? as usize;
    let start = position + 4;
    let end = start.checked_add(n).ok_or_else(truncated)?;
    Ok((bytes.get(start..end).ok_or_else(truncated)?, end))
}

fn utf16(bytes: &[u8]) -> Result<String> {
    let bad = || malformed("unreadable string in a condition");
    if bytes.len() % 2 != 0 {
        return Err(bad());
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes(c.try_into().unwrap_or_default()))
        .collect();
    String::from_utf16(&units).map_err(|_| bad())
}

/// A literal (integer, string, bytes, SID, list) at token `position`, its end and the depth
/// of its tree; `depth`: that of the enclosing list.
fn literal(bytes: &[u8], position: usize, depth: usize) -> Result<(Node, usize, usize)> {
    let token = *bytes
        .get(position)
        .ok_or_else(|| malformed("truncated condition"))?;
    let position = position + 1;
    if is_integer_token(token) {
        let Some([v0, v1, v2, v3, v4, v5, v6, v7, sign, base]) = bytes.get(position..position + 10)
        else {
            return Err(malformed("truncated condition"));
        };
        let value = i64::from_le_bytes([*v0, *v1, *v2, *v3, *v4, *v5, *v6, *v7]);
        let node = Node::Integer {
            value,
            sign: *sign,
            base: *base,
            token,
        };
        return Ok((node, position + 10, 1));
    }
    let (body, position) = with_length(bytes, position)?;
    match token {
        STRING => Ok((Node::String(utf16(body)?), position, 1)),
        OCTETS => Ok((Node::Octets(body.to_vec()), position, 1)),
        SID_TOKEN => {
            let (sid, end) = Sid::read(body, 0)?;
            if end != body.len() {
                return Err(malformed("malformed SID in a condition"));
            }
            Ok((Node::Sid(sid), position, 1))
        }
        COMPOSITE => {
            let depth = deeper(depth)?;
            let mut elements = Vec::new();
            let mut deepest = depth;
            let mut i = 0;
            while i < body.len() {
                let (element, next, d) = literal(body, i, depth)?;
                elements.push(element);
                deepest = deepest.max(d);
                i = next;
            }
            Ok((Node::Composite(elements), position, deepest))
        }
        _ => Err(malformed(&format!(
            "unknown token in a condition: 0x{token:02x}"
        ))),
    }
}

/// The expression of a callback ACE (what follows its SID). `Error::Invalid` if it is
/// malformed (missing signature, unknown token, inconsistent stack).
pub fn read_condition(data: &[u8]) -> Result<Node> {
    if !data.starts_with(SIGNATURE) {
        return Err(malformed("condition without the \"artx\" signature"));
    }
    // Each node with the depth of its tree, kept below MAX_DEPTH.
    let mut stack: Vec<(Node, usize)> = Vec::new();
    let mut position = SIGNATURE.len();
    while let Some(&token) = data.get(position) {
        if token == 0x00 {
            // padding
            position += 1;
            continue;
        }
        if attribute_prefix(token).is_some() {
            let (name, next) = with_length(data, position + 1)?;
            let name = utf16(name)?;
            stack.push((Node::Attribute { scope: token, name }, 1));
            position = next;
        } else if binary_name(token).is_some() || logical_name(token).is_some() {
            let (Some((right, d_right)), Some((left, d_left))) = (stack.pop(), stack.pop()) else {
                return Err(malformed(
                    "operator without its two operands in a condition",
                ));
            };
            let depth = deeper(d_left.max(d_right))?;
            stack.push((
                Node::Operation {
                    code: token,
                    operands: vec![left, right],
                },
                depth,
            ));
            position += 1;
        } else if unary_name(token).is_some() || token == NOT {
            let Some((operand, d)) = stack.pop() else {
                return Err(malformed("operator without operand in a condition"));
            };
            stack.push((
                Node::Operation {
                    code: token,
                    operands: vec![operand],
                },
                deeper(d)?,
            ));
            position += 1;
        } else {
            let (node, next, depth) = literal(data, position, 0)?;
            stack.push((node, depth));
            position = next;
        }
    }
    match (stack.pop(), stack.is_empty()) {
        (Some((node, _)), true) => Ok(node),
        (popped, _) => Err(malformed(&format!(
            "incomplete condition ({} terms left)",
            stack.len() + usize::from(popped.is_some())
        ))),
    }
}

// ---------------------------------------------------------------------------
// SDDL (Samba's form)

fn digits(magnitude: u128, base: u8) -> String {
    match base {
        1 => format!("0{magnitude:o}"),
        3 => format!("0x{magnitude:x}"),
        _ => magnitude.to_string(),
    }
}

/// As Samba 4.22: without a noted sign, octal and hexadecimal are written unsigned
/// (`-1` → `0xffffffffffffffff`), decimal signed; `00` for an octal zero. `Error::Invalid`
/// if the noted sign contradicts the value (`+` on a negative), which Samba refuses too.
pub fn integer_to_sddl(value: i64, sign: u8, base: u8) -> Result<String> {
    match sign {
        1 => {
            if value < 0 {
                return Err(malformed("negative integer noted \"+\" in a condition"));
            }
            Ok(format!("+{}", digits(value as u128, base)))
        }
        2 => {
            if value > 0 {
                return Err(malformed("positive integer noted \"-\" in a condition"));
            }
            Ok(format!("-{}", digits(value.unsigned_abs() as u128, base)))
        }
        _ if base == 2 => Ok(value.to_string()),
        _ => Ok(digits(value as u64 as u128, base)),
    }
}

pub fn node_to_sddl(node: &Node) -> Result<String> {
    Ok(match node {
        Node::Integer {
            value, sign, base, ..
        } => integer_to_sddl(*value, *sign, *base)?,
        Node::String(text) => format!("\"{text}\""),
        Node::Octets(octets) => {
            let hex: String = octets.iter().map(|b| format!("{b:02X}")).collect();
            format!("#{hex}")
        }
        Node::Sid(sid) => format!("SID({})", sid_to_sddl(sid, None)),
        Node::Composite(elements) => {
            let parts = elements
                .iter()
                .map(node_to_sddl)
                .collect::<Result<Vec<_>>>()?;
            format!("{{{}}}", parts.join(", "))
        }
        Node::Attribute { scope, name } => {
            let prefix = attribute_prefix(*scope).ok_or_else(|| malformed("unknown scope"))?;
            format!("{prefix}{name}")
        }
        Node::Operation { code, operands } => match operands.as_slice() {
            [single] if *code == NOT => format!("(!{})", node_to_sddl(single)?),
            [single] => {
                let name = unary_name(*code).ok_or_else(|| malformed("unknown operator"))?;
                format!("({name} {})", node_to_sddl(single)?)
            }
            [left, right] => {
                let symbol = binary_name(*code)
                    .or_else(|| logical_name(*code))
                    .ok_or_else(|| malformed("unknown operator"))?;
                format!(
                    "({} {symbol} {})",
                    node_to_sddl(left)?,
                    node_to_sddl(right)?
                )
            }
            _ => return Err(malformed("operation with a wrong number of operands")),
        },
    })
}

/// The condition field of a callback ACE in SDDL, parentheses included.
pub fn condition_to_sddl(data: &[u8]) -> Result<String> {
    let text = node_to_sddl(&read_condition(data)?)?;
    Ok(if text.starts_with('(') {
        text
    } else {
        format!("({text})")
    })
}

// ---------------------------------------------------------------------------
// SDDL → bytes

fn condition_error(message: String, position: usize) -> ConditionError {
    ConditionError::Invalid { message, position }
}

/// Keyword (lower case) → operator code.
fn keyword(word: &str) -> Option<u8> {
    let lower = word.to_lowercase();
    BINARY
        .iter()
        .chain(UNARY.iter())
        .find(|(_, name)| name.to_lowercase() == lower)
        .map(|(code, _)| *code)
}

fn prefix_scope(prefix: &str) -> Option<u8> {
    match prefix {
        "@user." => Some(0xF9),
        "@resource." => Some(0xFA),
        "@device." => Some(0xFB),
        _ => None,
    }
}

fn symbol_code(symbol: &str) -> Option<u8> {
    BINARY
        .iter()
        .find(|(_, n)| *n == symbol)
        .map(|(c, _)| *c)
        .or(match symbol {
            "&&" => Some(AND),
            "||" => Some(OR),
            _ => None,
        })
}

/// Characters of an attribute name (MS-DTYP 2.5.1.1, `attr-char1` and `attr-char2`).
fn is_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || ":./_%@".contains(c)
}

/// Python's `str.isdigit()` and `str.isalnum()`, restricted to what matters here.
fn is_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn is_alnum(c: char) -> bool {
    c.is_alphanumeric()
}

/// An integer as written in SDDL: value as Python computes it (it may leave 64 bits in a
/// resource attribute, where Python's `int` takes a second sign), sign and base.
struct ParsedInteger {
    value: PyInt,
    sign: u8,
    base: u8,
}

const MASK64: u128 = u64::MAX as u128;

/// A condition integer, sign and base included (`+5`, `-0x10`, `017`, `00`).
fn parse_integer(text: &[char], position: usize) -> Result<ParsedInteger> {
    let shown = pytext::string(text);
    let sign = match text.first() {
        Some('+') => 1,
        Some('-') => 2,
        _ => 3,
    };
    let number = if sign != 3 { from(text, 1) } else { text };
    let parsed = if pytext::head2_lower(number) == "0x" {
        pytext::py_int(from(number, 2), 16).map(|v| (3, v))
    } else if number.len() > 1 && number.first() == Some(&'0') {
        // "00": octal zero; "0": decimal.
        pytext::py_int(from(number, 1), 8).map(|v| (1, v))
    } else {
        pytext::py_int(number, 10).map(|v| (2, v))
    };
    let (base, magnitude) = parsed
        .ok_or_else(|| condition_error(format!("malformed number: \"{shown}\""), position))?;
    let limit: u128 = match sign {
        2 => 1 << 63,
        1 => (1 << 63) - 1,
        _ => MASK64,
    };
    if magnitude.gt(limit) {
        return Err(condition_error(
            format!("number beyond 64 bits: \"{shown}\""),
            position,
        ));
    }
    let value = if sign == 2 {
        magnitude.neg()
    } else if magnitude.gt((1 << 63) - 1) {
        // Without a sign, a number above 2^63 - 1 is read modulo 2^64 (Windows; this is also
        // how Samba writes a negative octal or hexadecimal number).
        PyInt::from_i128(magnitude.to_i128().unwrap_or(0) - (1i128 << 64))
    } else {
        magnitude
    };
    Ok(ParsedInteger { value, sign, base })
}

fn sid_text(text: &[char], domain: Option<&Sid>, position: usize) -> Result<Sid> {
    let stripped = pytext::string(pytext::strip(text));
    sid_from_sddl(&stripped, domain).map_err(|e| {
        condition_error(
            format!("unknown SID: \"{}\" ({e})", pytext::string(text)),
            position,
        )
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Open,
    Close,
    OpenBrace,
    CloseBrace,
    Comma,
    Bang,
    Op,
    Word,
    Node,
}

impl Kind {
    fn shown(self) -> &'static str {
        match self {
            Kind::Open => "(",
            Kind::Close => ")",
            Kind::OpenBrace => "{",
            Kind::CloseBrace => "}",
            Kind::Comma => ",",
            Kind::Bang => "!",
            Kind::Op => "op",
            Kind::Word => "word",
            Kind::Node => "node",
        }
    }
}

#[derive(Debug, Clone)]
struct Token {
    kind: Kind,
    text: String,
    position: usize,
    node: Option<Node>,
}

fn token(kind: Kind, text: &[char], position: usize, node: Option<Node>) -> Token {
    Token {
        kind,
        text: pytext::string(text),
        position,
        node,
    }
}

fn tokens(text: &[char], domain: Option<&Sid>) -> Result<Vec<Token>> {
    let mut out = Vec::new();
    let n = text.len();
    let mut i = 0;
    while i < n {
        let Some(c) = at(text, i) else { break };
        if pytext::is_space(c) {
            i += 1;
            continue;
        }
        let start = i;
        let single = match c {
            '(' => Some(Kind::Open),
            ')' => Some(Kind::Close),
            '{' => Some(Kind::OpenBrace),
            '}' => Some(Kind::CloseBrace),
            ',' => Some(Kind::Comma),
            _ => None,
        };
        if let Some(kind) = single {
            out.push(token(kind, sub(text, i, i + 1), start, None));
            i += 1;
            continue;
        }
        let double: String = sub(text, i, i + 2).iter().collect();
        if ["==", "!=", "<=", ">=", "&&", "||"].contains(&double.as_str()) {
            out.push(token(Kind::Op, sub(text, i, i + 2), start, None));
            i += 2;
            continue;
        }
        if c == '<' || c == '>' {
            out.push(token(Kind::Op, sub(text, i, i + 1), start, None));
            i += 1;
            continue;
        }
        if c == '!' {
            out.push(token(Kind::Bang, sub(text, i, i + 1), start, None));
            i += 1;
            continue;
        }
        if c == '"' {
            let Some(end) = pytext::find(text, '"', i + 1) else {
                return Err(condition_error(
                    "string without a closing quote".into(),
                    start,
                ));
            };
            let node = Node::String(pytext::string(sub(text, i + 1, end)));
            out.push(token(Kind::Node, sub(text, i, end + 1), start, Some(node)));
            i = end + 1;
            continue;
        }
        if c == '#' {
            let mut end = i + 1;
            while at(text, end).is_some_and(|c| c.is_ascii_hexdigit()) {
                end += 1;
            }
            let hex = sub(text, i + 1, end);
            if hex.len() % 2 != 0 {
                return Err(condition_error(
                    "odd number of hexadecimal digits".into(),
                    start,
                ));
            }
            let octets = pytext::from_hex(hex).unwrap_or_default();
            out.push(token(
                Kind::Node,
                sub(text, i, end),
                start,
                Some(Node::Octets(octets)),
            ));
            i = end;
            continue;
        }
        if c == '+' || c == '-' || is_digit(c) {
            let mut end = i + 1;
            while at(text, end).is_some_and(is_alnum) {
                end += 1;
            }
            let word = sub(text, i, end);
            let parsed = parse_integer(word, start)?;
            let value = parsed.value.to_i128().and_then(|v| i64::try_from(v).ok());
            let value = value.ok_or_else(|| {
                condition_error(
                    format!("number beyond 64 bits: \"{}\"", pytext::string(word)),
                    start,
                )
            })?;
            let node = Node::Integer {
                value,
                sign: parsed.sign,
                base: parsed.base,
                token: 0x04,
            };
            out.push(token(Kind::Node, word, start, Some(node)));
            i = end;
            continue;
        }
        if c == '@' {
            let point = pytext::find(text, '.', i);
            let prefix = match point {
                Some(p) if p > 0 => pytext::string(sub(text, i, p + 1)).to_lowercase(),
                _ => String::new(),
            };
            let Some(scope) = prefix_scope(&prefix) else {
                let shown = pytext::string(sub(text, i, n.min(i + 12)));
                return Err(condition_error(
                    format!("unknown attribute: \"{shown}\" (@User., @Device. or @Resource.)"),
                    start,
                ));
            };
            let point = point.unwrap_or(i);
            let mut end = point + 1;
            while at(text, end).is_some_and(is_name_char) {
                end += 1;
            }
            let name = pytext::string(sub(text, point + 1, end));
            if name.is_empty() {
                return Err(condition_error("empty attribute name".into(), start));
            }
            let node = Node::Attribute { scope, name };
            out.push(token(Kind::Node, sub(text, i, end), start, Some(node)));
            i = end;
            continue;
        }
        if is_name_char(c) {
            let mut end = i + 1;
            while at(text, end).is_some_and(is_name_char) {
                end += 1;
            }
            let word = pytext::string(sub(text, i, end));
            if word.to_lowercase() == "sid" && text.get(end) == Some(&'(') {
                let Some(close) = pytext::find(text, ')', end) else {
                    return Err(condition_error(
                        "SID(…) without a closing parenthesis".into(),
                        start,
                    ));
                };
                let sid = sid_text(sub(text, end + 1, close), domain, start)?;
                out.push(token(
                    Kind::Node,
                    sub(text, i, close + 1),
                    start,
                    Some(Node::Sid(sid)),
                ));
                i = close + 1;
                continue;
            }
            if keyword(&word).is_some() {
                out.push(token(Kind::Word, sub(text, i, end), start, None));
            } else {
                let node = Node::Attribute {
                    scope: LOCAL_ATTRIBUTE,
                    name: word,
                };
                out.push(token(Kind::Node, sub(text, i, end), start, Some(node)));
            }
            i = end;
            continue;
        }
        return Err(condition_error(
            format!("unexpected character: \"{c}\""),
            start,
        ));
    }
    Ok(out)
}

/// Recursive descent: `||` < `&&` < `!` < term; every operator left-associative.
///
/// Every method returns the node and the depth of its tree; `nesting` counts the open
/// parentheses, `!` and lists, so that they stay below [`MAX_DEPTH`] and [`MAX_NESTING`].
struct Parser {
    tokens: Vec<Token>,
    i: usize,
    length: usize,
    nesting: usize,
}

type Parsed = Result<(Node, usize)>;

impl Parser {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.i)
    }

    fn take(&mut self) -> Result<Token> {
        let t = self
            .tokens
            .get(self.i)
            .cloned()
            .ok_or_else(|| condition_error("incomplete condition".into(), self.length))?;
        self.i += 1;
        Ok(t)
    }

    fn expect(&mut self, kind: Kind) -> Result<Token> {
        let t = self.take()?;
        if t.kind != kind {
            return Err(condition_error(
                format!("\"{}\" expected, \"{}\" found", kind.shown(), t.text),
                t.position,
            ));
        }
        Ok(t)
    }

    fn too_deep(&self) -> ConditionError {
        let position = self.peek().map_or(self.length, |t| t.position);
        condition_error("condition nested too deeply".into(), position)
    }

    fn operation(&self, code: u8, operands: Vec<(Node, usize)>) -> Parsed {
        let depth = operands.iter().map(|(_, d)| *d).max().unwrap_or(0);
        let depth = deeper(depth).map_err(|_| self.too_deep())?;
        let operands = operands.into_iter().map(|(n, _)| n).collect();
        Ok((Node::Operation { code, operands }, depth))
    }

    /// Enters a parenthesis, a `!` or a list.
    fn enter(&mut self) -> Result<()> {
        self.nesting += 1;
        if self.nesting > MAX_NESTING {
            let position = self.peek().map_or(self.length, |t| t.position);
            return Err(condition_error(
                "condition nested too deeply".into(),
                position,
            ));
        }
        Ok(())
    }

    fn expression(&mut self) -> Parsed {
        self.logical(OR)
    }

    fn logical(&mut self, code: u8) -> Parsed {
        let symbol = if code == OR { "||" } else { "&&" };
        let next = |p: &mut Self| if code == OR { p.logical(AND) } else { p.not() };
        let mut left = next(self)?;
        while self
            .peek()
            .is_some_and(|t| t.kind == Kind::Op && t.text == symbol)
        {
            self.i += 1;
            let right = next(self)?;
            left = self.operation(code, vec![left, right])?;
        }
        Ok(left)
    }

    fn not(&mut self) -> Parsed {
        if self.peek().is_some_and(|t| t.kind == Kind::Bang) {
            self.i += 1;
            self.enter()?;
            let operand = self.not()?;
            self.nesting -= 1;
            return self.operation(NOT, vec![operand]);
        }
        self.primary()
    }

    fn primary(&mut self) -> Parsed {
        if self.peek().is_some_and(|t| t.kind == Kind::Open) {
            self.i += 1;
            self.enter()?;
            let node = self.expression()?;
            self.expect(Kind::Close)?;
            self.nesting -= 1;
            return Ok(node);
        }
        self.term()
    }

    fn operand(&mut self) -> Parsed {
        let t = self.take()?;
        if let (Kind::Node, Some(node)) = (t.kind, &t.node) {
            return Ok((node.clone(), 1));
        }
        if t.kind == Kind::OpenBrace {
            if self.peek().is_some_and(|t| t.kind == Kind::CloseBrace) {
                self.i += 1;
                return Ok((Node::Composite(Vec::new()), 1));
            }
            self.enter()?;
            let mut elements = Vec::new();
            let mut depth = 0;
            loop {
                let (element, d) = self.operand()?;
                elements.push(element);
                depth = depth.max(d);
                let end = self.take()?;
                if end.kind == Kind::CloseBrace {
                    self.nesting -= 1;
                    let depth = deeper(depth).map_err(|_| self.too_deep())?;
                    return Ok((Node::Composite(elements), depth));
                }
                if end.kind != Kind::Comma {
                    return Err(condition_error(
                        "\",\" or \"}\" expected in a list".into(),
                        end.position,
                    ));
                }
            }
        }
        Err(condition_error(
            format!("value or attribute expected, \"{}\" found", t.text),
            t.position,
        ))
    }

    fn term(&mut self) -> Parsed {
        if let Some(t) = self.peek().filter(|t| t.kind == Kind::Word).cloned() {
            let code = keyword(&t.text).unwrap_or(0);
            if unary_name(code).is_none() {
                return Err(condition_error(
                    format!("\"{}\" goes between two operands", t.text),
                    t.position,
                ));
            }
            self.i += 1;
            let operand = self.operand()?;
            return self.operation(code, vec![operand]);
        }
        let left = self.operand()?;
        if let Some(next) = self.peek() {
            let code = match next.kind {
                Kind::Op => symbol_code(&next.text),
                Kind::Word => keyword(&next.text),
                _ => None,
            };
            if let Some(code) = code.filter(|&c| binary_name(c).is_some()) {
                self.i += 1;
                let right = self.operand()?;
                return self.operation(code, vec![left, right]);
            }
        }
        Ok(left)
    }
}

/// The condition of an ACE in SDDL (seventh field, parentheses included), Samba's or
/// Windows' form. `SID(DA)` and the other domain-relative abbreviations need `domain`.
pub fn condition_from_sddl(text: &str, domain: Option<&Sid>) -> Result<Node> {
    let chars = pytext::chars(text);
    let tokens = tokens(&chars, domain)?;
    if tokens.first().is_none_or(|t| t.kind != Kind::Open) {
        return Err(condition_error(
            "a condition is written in parentheses".into(),
            0,
        ));
    }
    let mut parser = Parser {
        tokens,
        i: 0,
        length: chars.len(),
        nesting: 0,
    };
    let (node, _) = parser.primary()?;
    if let Some(rest) = parser.peek() {
        return Err(condition_error(
            format!("text after the condition: \"{}\"", rest.text),
            rest.position,
        ));
    }
    Ok(node)
}

fn push_with_length(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let n = u32::try_from(bytes.len()).map_err(|_| malformed("value too long"))?;
    out.extend(n.to_le_bytes());
    out.extend(bytes);
    Ok(())
}

fn utf16_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn encode_node(node: &Node, out: &mut Vec<u8>) -> Result<()> {
    match node {
        Node::Integer {
            value,
            sign,
            base,
            token,
        } => {
            out.push(*token);
            out.extend(value.to_le_bytes());
            out.push(*sign);
            out.push(*base);
        }
        Node::String(text) => {
            out.push(STRING);
            push_with_length(out, &utf16_bytes(text))?;
        }
        Node::Octets(octets) => {
            out.push(OCTETS);
            push_with_length(out, octets)?;
        }
        Node::Sid(sid) => {
            out.push(SID_TOKEN);
            push_with_length(out, &sid.encode())?;
        }
        Node::Composite(elements) => {
            let mut body = Vec::new();
            for e in elements {
                encode_node(e, &mut body)?;
            }
            out.push(COMPOSITE);
            push_with_length(out, &body)?;
        }
        Node::Attribute { scope, name } => {
            out.push(*scope);
            push_with_length(out, &utf16_bytes(name))?;
        }
        Node::Operation { code, operands } => {
            for o in operands {
                encode_node(o, out)?;
            }
            out.push(*code);
        }
    }
    Ok(())
}

fn pad(mut bytes: Vec<u8>) -> Vec<u8> {
    let n = bytes.len().next_multiple_of(4);
    bytes.resize(n, 0);
    bytes
}

/// The bytes of a condition (signature, postfix tokens, padding to four bytes), as Samba and
/// Windows write them.
pub fn encode_condition(node: &Node) -> Result<Vec<u8>> {
    let mut out = SIGNATURE.to_vec();
    encode_node(node, &mut out)?;
    Ok(pad(out))
}

/// The `SID(XX)` of a condition that cite a domain-relative abbreviation (`DA`, `DU`…),
/// outside strings: Samba 4.22 crashes (SIGSEGV) reading those forms in SDDL; the encoder
/// writes them as full SIDs, the same bytes as Windows.
pub fn domain_abbreviations(text: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for piece in text.split('"').step_by(2) {
        let chars = pytext::chars(piece);
        let lower: Vec<char> = chars.iter().map(|c| c.to_ascii_lowercase()).collect();
        let mut i = 0;
        while let Some(at) =
            (i..lower.len()).find(|&j| pytext::starts_with(from(&lower, j), "sid("))
        {
            let code = match pytext::find(&chars, ')', at) {
                Some(end) if end > 0 => {
                    pytext::string(pytext::strip(sub(&chars, at + 4, end))).to_uppercase()
                }
                _ => String::new(),
            };
            if DOMAIN_ABBREVIATIONS.iter().any(|(c, _)| *c == code) && !found.contains(&code) {
                found.push(code);
            }
            i = at + 4;
        }
    }
    found
}

// ---------------------------------------------------------------------------
// Resource attribute (`RA` ACE)

pub const RESOURCE_TYPES: [(u16, &str); 6] = [
    (0x01, "TI"),
    (0x02, "TU"),
    (0x03, "TS"),
    (0x05, "TD"),
    (0x06, "TB"),
    (0x10, "TX"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResourceValue {
    Integer(PyInt),
    String(String),
    Sid(Sid),
    Octets(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAttribute {
    pub name: String,
    pub attr_type: u16,
    pub flags: u32,
    pub values: Vec<ResourceValue>,
}

impl ResourceAttribute {
    pub fn type_code(&self) -> String {
        RESOURCE_TYPES
            .iter()
            .find(|(t, _)| *t == self.attr_type)
            .map_or_else(|| format!("0x{:x}", self.attr_type), |(_, c)| c.to_string())
    }
}

fn terminated_string(bytes: &[u8], position: usize) -> Result<String> {
    let mut end = position;
    loop {
        match bytes.get(end..end + 2) {
            None => return Err(malformed("truncated resource attribute")),
            Some([0, 0]) => break,
            Some(_) => end += 2,
        }
    }
    utf16(bytes.get(position..end).unwrap_or_default())
}

/// The `CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1` of an `RA` ACE (what follows its SID).
pub fn read_resource_attribute(data: &[u8]) -> Result<ResourceAttribute> {
    let truncated = || malformed("truncated resource attribute");
    let u32_at = |p: usize| crate::read::le_u32(data, p);
    let u64_at = |p: usize| crate::read::le_u64(data, p);
    let Some([_, _, _, _, t0, t1, ..]) = data.get(..16) else {
        return Err(truncated());
    };
    let name_position = u32_at(0).ok_or_else(truncated)? as usize;
    let attr_type = u16::from_le_bytes([*t0, *t1]);
    let flags = u32_at(8).ok_or_else(truncated)?;
    let count = u32_at(12).ok_or_else(truncated)? as usize;
    if count
        .checked_mul(4)
        .and_then(|n| n.checked_add(16))
        .is_none_or(|end| end > data.len())
    {
        return Err(truncated());
    }
    let mut values = Vec::with_capacity(count);
    for k in 0..count {
        let p = u32_at(16 + 4 * k).ok_or_else(truncated)? as usize;
        let value = match attr_type {
            0x01 => ResourceValue::Integer(PyInt::from_i128(
                u64_at(p).ok_or_else(truncated)? as i64 as i128,
            )),
            0x02 | 0x06 => {
                ResourceValue::Integer(PyInt::from_i128(u64_at(p).ok_or_else(truncated)? as i128))
            }
            0x03 => ResourceValue::String(terminated_string(data, p)?),
            0x05 | 0x10 => {
                let (body, _) = with_length(data, p)?;
                if attr_type == 0x10 {
                    ResourceValue::Octets(body.to_vec())
                } else if body.starts_with(b"S-") {
                    // Samba 4.22 stores the SID as text.
                    let text = std::str::from_utf8(body)
                        .ok()
                        .filter(|t| t.is_ascii())
                        .ok_or_else(|| malformed("non-ASCII SID text"))?;
                    ResourceValue::Sid(text.parse::<Sid>()?)
                } else {
                    ResourceValue::Sid(Sid::read(body, 0)?.0)
                }
            }
            t => return Err(malformed(&format!("unknown resource attribute type: {t}"))),
        };
        values.push(value);
    }
    Ok(ResourceAttribute {
        name: terminated_string(data, name_position)?,
        attr_type,
        flags,
        values,
    })
}

/// A value of a resource attribute in SDDL (`valeur_ressource_vers_sddl`).
pub fn resource_value_to_sddl(attribute: &ResourceAttribute, value: &ResourceValue) -> String {
    match value {
        ResourceValue::String(s) => format!("\"{s}\""),
        ResourceValue::Octets(o) => o.iter().map(|b| format!("{b:02X}")).collect(),
        ResourceValue::Integer(v) => {
            let text = v.to_i128().map(|v| v.to_string()).unwrap_or_default();
            if attribute.attr_type == 0x02 {
                format!("+{text}")
            } else {
                text
            }
        }
        ResourceValue::Sid(sid) => sid_to_sddl(sid, None),
    }
}

pub fn resource_attribute_to_sddl(data: &[u8]) -> Result<String> {
    let attribute = read_resource_attribute(data)?;
    let mut fields = vec![
        format!("\"{}\"", attribute.name),
        attribute.type_code(),
        format!("0x{:x}", attribute.flags),
    ];
    fields.extend(
        attribute
            .values
            .iter()
            .map(|v| resource_value_to_sddl(&attribute, v)),
    );
    Ok(format!("({})", fields.join(",")))
}

/// Fields separated by commas outside quotes, with their position.
fn fields(text: &[char]) -> Result<Vec<(&[char], usize)>> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut quote = false;
    for (i, &c) in text.iter().enumerate() {
        if c == '"' {
            quote = !quote;
        } else if c == ',' && !quote {
            out.push((pytext::strip(sub(text, start, i)), start));
            start = i + 1;
        }
    }
    if quote {
        return Err(condition_error(
            "string without a closing quote".into(),
            text.len(),
        ));
    }
    out.push((pytext::strip(from(text, start)), start));
    Ok(out)
}

/// `field[1:-1]`.
fn unquote(field: &[char]) -> &[char] {
    sub(field, 1, field.len().saturating_sub(1))
}

fn is_quoted(field: &[char]) -> bool {
    field.len() >= 2 && field.first() == Some(&'"') && field.last() == Some(&'"')
}

/// `("Project",TS,0x0,"Alpha","Beta")` (Samba's or Windows' form) into a structure.
pub fn resource_attribute_from_sddl(text: &str, domain: Option<&Sid>) -> Result<ResourceAttribute> {
    let chars = pytext::chars(text);
    let body = pytext::strip(&chars);
    if body.first() != Some(&'(') || body.last() != Some(&')') {
        return Err(condition_error(
            "a resource attribute is written in parentheses".into(),
            0,
        ));
    }
    let inner = sub(body, 1, body.len().saturating_sub(1));
    let fields = fields(inner)?;
    if fields.len() < 3 {
        return Err(condition_error(
            "resource attribute: name, type and flags expected".into(),
            0,
        ));
    }
    let [
        (name, p_name),
        (code, p_code),
        (flags_text, p_flags),
        value_fields @ ..,
    ] = fields.as_slice()
    else {
        return Err(condition_error(
            "resource attribute: name, type and flags expected".into(),
            0,
        ));
    };
    let (name, p_name, code, p_code, flags_text, p_flags) =
        (*name, *p_name, *code, *p_code, *flags_text, *p_flags);
    if !is_quoted(name) {
        return Err(condition_error(
            "the name of a resource attribute is in double quotes".into(),
            p_name,
        ));
    }
    let code_text = pytext::string(code);
    let attr_type = RESOURCE_TYPES
        .iter()
        .find(|(_, c)| *c == code_text.to_uppercase())
        .map(|(t, _)| *t)
        .ok_or_else(|| {
            condition_error(format!("unknown attribute type: \"{code_text}\""), p_code)
        })?;
    let flags = pytext::py_int(flags_text, 0).ok_or_else(|| {
        condition_error(
            format!("malformed flags: \"{}\"", pytext::string(flags_text)),
            p_flags,
        )
    })?;
    let mut values = Vec::new();
    for &(value, position) in value_fields {
        let v = match attr_type {
            0x03 => {
                if !is_quoted(value) {
                    return Err(condition_error(
                        format!("string expected: \"{}\"", pytext::string(value)),
                        position,
                    ));
                }
                ResourceValue::String(pytext::string(unquote(value)))
            }
            0x05 => ResourceValue::Sid(sid_text(value, domain, position)?),
            0x10 => ResourceValue::Octets(pytext::from_hex(value).ok_or_else(|| {
                condition_error(
                    format!("malformed bytes: \"{}\"", pytext::string(value)),
                    position,
                )
            })?),
            _ => {
                let integer = parse_integer(value, position)?;
                if attr_type != 0x01 && integer.value.is_negative() && integer.sign == 2 {
                    return Err(condition_error(
                        "negative value for an unsigned type".into(),
                        position,
                    ));
                }
                ResourceValue::Integer(integer.value)
            }
        };
        values.push(v);
    }
    // Checked after the values, as in Python: a malformed value is reported first.
    let flags = flags
        .to_i128()
        .and_then(|f| u32::try_from(f).ok())
        .ok_or_else(|| {
            ConditionError::OutOfRange("resource attribute flags beyond 32 bits".into())
        })?;
    Ok(ResourceAttribute {
        name: pytext::string(unquote(name)),
        attr_type,
        flags,
        values,
    })
}

/// `CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1`: header, value offsets, name, values in a row,
/// padding to four bytes. `samba`: a `TB` stored as `TU` and a `TD` SID as text, as Samba
/// 4.22 does (Windows and MS-DTYP: boolean, binary SID).
pub fn encode_resource_attribute(attribute: &ResourceAttribute, samba: bool) -> Result<Vec<u8>> {
    let attr_type = if samba && attribute.attr_type == 0x06 {
        0x02
    } else {
        attribute.attr_type
    };
    let count = attribute.values.len();
    let mut position = 16 + 4 * count;
    let name = utf16_bytes(&format!("{}\0", attribute.name));
    position += name.len();
    let mut pieces = vec![name];
    let mut positions = Vec::with_capacity(count);
    for value in &attribute.values {
        let bytes = match value {
            ResourceValue::String(s) => utf16_bytes(&format!("{s}\0")),
            ResourceValue::Octets(o) => {
                let mut b = Vec::new();
                push_with_length(&mut b, o)?;
                b
            }
            ResourceValue::Sid(sid) => {
                let raw = if samba {
                    sid.to_string().into_bytes()
                } else {
                    sid.encode()
                };
                let mut b = Vec::new();
                push_with_length(&mut b, &raw)?;
                b
            }
            ResourceValue::Integer(v) => {
                if attr_type == 0x01 {
                    let v = v
                        .to_i128()
                        .and_then(|v| i64::try_from(v).ok())
                        .ok_or_else(|| {
                            ConditionError::OutOfRange("integer beyond 64 bits".into())
                        })?;
                    v.to_le_bytes().to_vec()
                } else {
                    v.mask64().to_le_bytes().to_vec()
                }
            }
        };
        positions.push(position);
        position += bytes.len();
        pieces.push(bytes);
    }
    let too_long = || ConditionError::OutOfRange("resource attribute too long".into());
    let mut out = Vec::with_capacity(position);
    out.extend(
        u32::try_from(16 + 4 * count)
            .map_err(|_| too_long())?
            .to_le_bytes(),
    );
    out.extend(attr_type.to_le_bytes());
    out.extend([0, 0]);
    out.extend(attribute.flags.to_le_bytes());
    out.extend(u32::try_from(count).map_err(|_| too_long())?.to_le_bytes());
    for p in positions {
        out.extend(u32::try_from(p).map_err(|_| too_long())?.to_le_bytes());
    }
    for piece in pieces {
        out.extend(piece);
    }
    Ok(pad(out))
}

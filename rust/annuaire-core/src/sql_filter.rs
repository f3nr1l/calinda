// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! LDAP search filters (RFC 4515) translated into SQL conditions on the local copy
//! (`annuaire.core.filtre_sql`, JC.3). What translates: `&`, `|`, `!`; equality, presence,
//! substring, `>=` and `<=`; the attributes of the columns, `objectClass`, `objectGUID`,
//! `distinguishedName`, `member` and `memberOf` through the links (equality on a DN,
//! presence); the IN_CHAIN rule on `member` and `memberOf` walked by a recursive query;
//! `objectCategory` for the usual categories; the bitwise rules on integers. Everything
//! else is `Untranslatable`, and the search goes to the DC.
//!
//! As the DC, texts compare without case: `COLLATE NOCASE` and `LIKE` for ASCII, the
//! function `plier` (Unicode lower case) as soon as a value holds other characters. An
//! absent attribute makes the comparison false and its negation true: each elementary
//! condition is wrapped in `COALESCE(…, 0)`.

use annuaire_codecs::time;
use annuaire_codecs::{Guid, Sid};
use rusqlite::types::Value;

use crate::search::{OID_BIT_AND, OID_BIT_OR, OID_IN_CHAIN};
use crate::store::{Kind, closure, column_of, escape_like, short_category};

/// Categories whose name is the one of the class (and of its `defaultObjectCategory`).
const CATEGORIES: [&str; 5] = [
    "person",
    "computer",
    "group",
    "organizationalunit",
    "container",
];

/// The filter does not evaluate on the local copy: the search goes to the DC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Untranslatable(pub String);

type Result<T> = std::result::Result<T, Untranslatable>;

fn refuse<T>(reason: impl Into<String>) -> Result<T> {
    Err(Untranslatable(reason.into()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Node {
    Composed(char, Vec<Node>),
    Term(Term),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Term {
    attribute: String,
    /// "=", ">=", "<=", "~=", "*" (presence), "sub" (substring), ":" (rule)
    operator: &'static str,
    value: Vec<u8>,
    pieces: Vec<Vec<u8>>,
    rule: String,
}

fn valid_attribute(name: &str) -> bool {
    let mut chars = name.chars();
    chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ';' | '-'))
}

/// Assertion value: the escapes `\xx` replaced by their bytes.
fn unescape(text: &str) -> Result<Vec<u8>> {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while let Some(&b) = raw.get(i) {
        if b == b'\\' {
            let hex = raw
                .get(i + 1..i + 3)
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match hex {
                Some(v) => out.push(v),
                None => return refuse(format!("invalid escape: {text:?}")),
            }
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

fn parse(filter: &str) -> Result<Node> {
    let (node, rest) = node(filter.trim())?;
    if !rest.trim().is_empty() {
        return refuse(format!("malformed filter: {filter:?}"));
    }
    Ok(node)
}

fn node(text: &str) -> Result<(Node, &str)> {
    if !text.starts_with('(') {
        return refuse(format!("malformed filter: {text:?}"));
    }
    let after = text.get(1..).unwrap_or("");
    if let Some(op) = after
        .chars()
        .next()
        .filter(|c| matches!(c, '&' | '|' | '!'))
    {
        let mut rest = after.get(1..).unwrap_or("").trim_start();
        let mut terms = Vec::new();
        while rest.starts_with('(') {
            let (term, tail) = node(rest)?;
            terms.push(term);
            rest = tail.trim_start();
        }
        if !rest.starts_with(')') || terms.is_empty() || (op == '!' && terms.len() != 1) {
            return refuse(format!("malformed filter: {text:?}"));
        }
        return Ok((Node::Composed(op, terms), rest.get(1..).unwrap_or("")));
    }
    // The parentheses of a value are escaped (\28, \29).
    let Some(end) = after.find(')') else {
        return refuse(format!("malformed filter: {text:?}"));
    };
    Ok((
        Node::Term(term(after.get(..end).unwrap_or(""))?),
        after.get(end + 1..).unwrap_or(""),
    ))
}

fn term(text: &str) -> Result<Term> {
    let empty = |attribute: &str, operator| Term {
        attribute: attribute.to_owned(),
        operator,
        value: Vec::new(),
        pieces: Vec::new(),
        rule: String::new(),
    };
    if let Some((left, right)) = text.split_once(":=") {
        let parts: Vec<&str> = left.split(':').collect();
        let [attribute, rule] = parts.as_slice() else {
            return refuse(format!("matching rule not handled: {text:?}"));
        };
        if !valid_attribute(attribute) {
            return refuse(format!("matching rule not handled: {text:?}"));
        }
        return Ok(Term {
            value: unescape(right)?,
            rule: (*rule).to_owned(),
            ..empty(attribute, ":")
        });
    }
    let (operator, attribute, value) = [">=", "<=", "~="]
        .into_iter()
        .find_map(|op| text.split_once(op).map(|(a, v)| (op, a, v)))
        .or_else(|| text.split_once('=').map(|(a, v)| ("=", a, v)))
        .ok_or_else(|| Untranslatable(format!("malformed term: {text:?}")))?;
    if !valid_attribute(attribute) {
        return refuse(format!("malformed term: {text:?}"));
    }
    if operator == "=" && value == "*" {
        return Ok(empty(attribute, "*"));
    }
    if operator == "=" && value.contains('*') {
        let pieces = value.split('*').map(unescape).collect::<Result<Vec<_>>>()?;
        return Ok(Term {
            pieces,
            ..empty(attribute, "sub")
        });
    }
    Ok(Term {
        value: unescape(value)?,
        ..empty(attribute, operator)
    })
}

/// SQL condition on the table `objets` (alias `o`) and its parameters (`Condition`).
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    pub sql: String,
    pub parameters: Vec<Value>,
}

/// SQL condition equivalent to the filter (`traduire`).
pub fn translate(filter: &str) -> Result<Condition> {
    let mut parameters = Vec::new();
    let sql = sql(&parse(filter)?, &mut parameters)?;
    Ok(Condition { sql, parameters })
}

fn sql(node: &Node, p: &mut Vec<Value>) -> Result<String> {
    match node {
        Node::Composed(op, terms) => {
            let parts = terms
                .iter()
                .map(|t| sql(t, p))
                .collect::<Result<Vec<_>>>()?;
            if *op == '!' {
                return Ok(format!("NOT ({})", parts.concat()));
            }
            let joint = if *op == '&' { " AND " } else { " OR " };
            Ok(format!("({})", parts.join(joint)))
        }
        Node::Term(t) => Ok(format!("COALESCE(({}), 0)", leaf(t, p)?)),
    }
}

fn text_of(value: &[u8]) -> Result<String> {
    String::from_utf8(value.to_vec()).or_else(|_| refuse("value that is not text"))
}

fn leaf(t: &Term, p: &mut Vec<Value>) -> Result<String> {
    let low = t.attribute.to_lowercase();
    match low.as_str() {
        "objectclass" => return class(t, p),
        "distinguishedname" => {
            if t.operator != "=" {
                return refuse("distinguishedName: equality only");
            }
            p.push(Value::Text(text_of(&t.value)?));
            return Ok("o.dn = ?".into());
        }
        "objectguid" => {
            if t.operator == "*" {
                return Ok("1".into());
            }
            if t.operator != "=" || t.value.len() != 16 {
                return refuse("objectGUID: equality on 16 bytes only");
            }
            p.push(Value::Blob(t.value.clone()));
            return Ok("o.guid = ?".into());
        }
        "member" | "memberof" => return link(&low, t, p),
        _ => {}
    }
    let Some(column) = column_of(&low) else {
        return refuse(format!("{} is not in the local copy", t.attribute));
    };
    let field = format!("o.{}", column.name);
    if t.operator == "*" {
        return Ok(format!("{field} IS NOT NULL"));
    }
    match column.kind {
        Kind::Integer => integer(&field, t, p),
        Kind::Bytes => {
            if t.operator != "=" {
                return refuse(format!("{}: equality only", t.attribute));
            }
            let mut value = t.value.clone();
            if column.attribute == "objectSid"
                && value
                    .get(..4)
                    .is_some_and(|v| v.eq_ignore_ascii_case(b"S-1-"))
            {
                value = text_of(&value)?
                    .parse::<Sid>()
                    .map_err(|_| Untranslatable("malformed SID".into()))?
                    .encode();
            }
            p.push(Value::Blob(value));
            Ok(format!("{field} = ?"))
        }
        Kind::Category => {
            if t.operator != "=" {
                return refuse("objectCategory: equality only");
            }
            let category = short_category(&text_of(&t.value)?);
            if !CATEGORIES.contains(&category.as_str()) {
                return refuse(format!("category {category}: only the DC translates it"));
            }
            p.push(Value::Text(category));
            Ok(format!("{field} = ?"))
        }
        Kind::Boolean => {
            let value = text_of(&t.value)?.to_uppercase();
            if t.operator != "=" || !matches!(value.as_str(), "TRUE" | "FALSE") {
                return refuse(format!("{}: TRUE or FALSE", t.attribute));
            }
            p.push(Value::Integer(i64::from(value == "TRUE")));
            Ok(format!("{field} = ?"))
        }
        Kind::Text => string(&field, column.name, t, p),
    }
}

fn class(t: &Term, p: &mut Vec<Value>) -> Result<String> {
    if t.operator == "*" {
        return Ok("1".into());
    }
    if t.operator != "=" {
        return refuse("objectClass: equality or presence only");
    }
    let value = text_of(&t.value)?;
    if !value.is_ascii() {
        return refuse("objectClass: unexpected class name");
    }
    p.push(Value::Text(format!("% {} %", escape_like(&value))));
    Ok("(' ' || o.classes || ' ') LIKE ? ESCAPE '\\'".into())
}

/// `memberOf` (deduced from `member`) and `member`, through the links kept by GUID.
fn link(low: &str, t: &Term, p: &mut Vec<Value>) -> Result<String> {
    let (own, other) = if low == "memberof" {
        ("membre", "groupe")
    } else {
        ("groupe", "membre")
    };
    if t.operator == ":" {
        if t.rule != OID_IN_CHAIN {
            return refuse(format!("rule {} on {}", t.rule, t.attribute));
        }
        return in_chain(low, &text_of(&t.value)?, p);
    }
    if t.operator == "*" {
        return Ok(format!("o.guid IN (SELECT {own} FROM liens)"));
    }
    if t.operator != "=" {
        return refuse(format!("{}: equality or presence only", t.attribute));
    }
    let dn = text_of(&t.value)?;
    if dn.starts_with('<') {
        return refuse(format!("{}: extended DN", t.attribute));
    }
    if low == "member" {
        // A member out of the copy (another domain) is only known by its DN.
        p.push(Value::Text(dn.clone()));
        p.push(Value::Text(dn));
        return Ok(
            "o.guid IN (SELECT groupe FROM liens WHERE dn = ? COLLATE NOCASE \
                   OR membre IN (SELECT guid FROM objets WHERE dn = ?))"
                .into(),
        );
    }
    p.push(Value::Text(dn));
    Ok(format!(
        "o.guid IN (SELECT {own} FROM liens WHERE {other} IN (SELECT guid FROM objets WHERE dn = ?))"
    ))
}

/// Subquery of the GUID of the object named by a DN, or by an extended DN.
fn named(value: &str, p: &mut Vec<Value>) -> Result<String> {
    if !value.starts_with('<') {
        p.push(Value::Text(value.to_owned()));
        return Ok("SELECT guid FROM objets WHERE dn = ?".into());
    }
    let inner = value
        .get(1..value.find('>').unwrap_or(value.len()))
        .unwrap_or("");
    let (key, text) = inner.split_once('=').unwrap_or((inner, ""));
    let malformed = || Untranslatable(format!("malformed extended DN: {value:?}"));
    if key.eq_ignore_ascii_case("GUID") {
        p.push(Value::Blob(
            text.parse::<Guid>().map_err(|_| malformed())?.encode(),
        ));
        return Ok("SELECT guid FROM objets WHERE guid = ?".into());
    }
    if key.eq_ignore_ascii_case("SID") {
        p.push(Value::Blob(
            text.parse::<Sid>().map_err(|_| malformed())?.encode(),
        ));
        return Ok("SELECT guid FROM objets WHERE sid = ?".into());
    }
    refuse(format!("extended DN not handled: {value:?}"))
}

/// IN_CHAIN: `memberOf` (members of G at any depth) or `member` (groups containing X at any
/// depth), on the links of the copy.
fn in_chain(low: &str, value: &str, p: &mut Vec<Value>) -> Result<String> {
    if low == "memberof" {
        return Ok(format!("o.guid IN ({})", closure(&named(value, p)?, true)));
    }
    let mut start = named(value, p)?;
    if !value.starts_with('<') {
        // A member out of the copy: known by the DN of the link.
        p.push(Value::Text(value.to_owned()));
        start = format!("{start} UNION SELECT membre FROM liens WHERE dn = ? COLLATE NOCASE");
    }
    Ok(format!("o.guid IN ({})", closure(&start, false)))
}

fn integer(field: &str, t: &Term, p: &mut Vec<Value>) -> Result<String> {
    let value: i64 = text_of(&t.value)?
        .trim()
        .parse()
        .map_err(|_| Untranslatable(format!("{}: integer expected", t.attribute)))?;
    if t.operator == ":" {
        if t.rule == OID_BIT_AND {
            p.push(Value::Integer(value));
            p.push(Value::Integer(value));
            return Ok(format!("({field} & ?) = ?"));
        }
        if t.rule == OID_BIT_OR {
            p.push(Value::Integer(value));
            return Ok(format!("({field} & ?) != 0"));
        }
        return refuse(format!("rule {} not handled", t.rule));
    }
    if !matches!(t.operator, "=" | ">=" | "<=") {
        return refuse(format!("{}: operator {}", t.attribute, t.operator));
    }
    p.push(Value::Integer(value));
    Ok(format!("{field} {} ?", t.operator))
}

fn string(field: &str, name: &str, t: &Term, p: &mut Vec<Value>) -> Result<String> {
    match t.operator {
        ":" => refuse(format!("rule {} on a text", t.rule)),
        ">=" | "<=" => {
            if !matches!(name, "modifie" | "cree") {
                return refuse(format!("{}: order on a text", t.attribute));
            }
            // Canonical form, the one the DC gives: the order of the strings is the one of
            // the dates.
            let date = time::decode_generalized_time(&text_of(&t.value)?)
                .map_err(|_| Untranslatable(format!("{}: malformed date", t.attribute)))?;
            p.push(Value::Text(time::encode_generalized_time(date)));
            Ok(format!("{field} {} ?", t.operator))
        }
        "~=" => refuse("approximate match"),
        "sub" => {
            let pieces = t
                .pieces
                .iter()
                .map(|m| text_of(m))
                .collect::<Result<Vec<_>>>()?;
            let pattern = pieces
                .iter()
                .map(|m| escape_like(m))
                .collect::<Vec<_>>()
                .join("%");
            if pieces.iter().all(|m| m.is_ascii()) {
                p.push(Value::Text(pattern));
                Ok(format!("{field} LIKE ? ESCAPE '\\'"))
            } else {
                p.push(Value::Text(pattern.to_lowercase()));
                Ok(format!("plier({field}) LIKE ? ESCAPE '\\'"))
            }
        }
        _ => {
            let value = text_of(&t.value)?;
            if value.is_ascii() {
                p.push(Value::Text(value));
                Ok(format!("{field} = ? COLLATE NOCASE"))
            } else {
                p.push(Value::Text(value.to_lowercase()));
                Ok(format!("plier({field}) = ?"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translations() {
        let c = translate("(&(objectCategory=person)(objectClass=user))").unwrap();
        assert_eq!(
            c.sql,
            "(COALESCE((o.categorie = ?), 0) AND COALESCE(((' ' || o.classes || ' ') LIKE ? ESCAPE '\\'), 0))"
        );
        assert_eq!(
            c.parameters,
            vec![Value::Text("person".into()), Value::Text("% user %".into())]
        );
        let c = translate("(userAccountControl:1.2.840.113556.1.4.803:=2)").unwrap();
        assert_eq!(c.sql, "COALESCE(((o.uac & ?) = ?), 0)");
        let c = translate("(name=*du\\2a*)").unwrap();
        assert_eq!(c.parameters, vec![Value::Text("%du*%".into())]);
        let c = translate("(name=Élo*)").unwrap();
        assert!(c.sql.contains("plier(o.nom) LIKE"));
        assert!(translate("(memberOf:1.2.840.113556.1.4.1941:=<SID=S-1-5-32-544>)").is_ok());
        assert!(translate("(lastLogon>=1)").is_err());
        assert!(translate("(objectCategory=foo)").is_err());
        assert!(translate("(name~=x)").is_err());
        assert!(translate("(!(showInAdvancedViewOnly=TRUE))").is_ok());
    }

    #[test]
    fn queries_of_the_search_bar_translate() {
        use crate::queries::{self, Kind, Query, State};
        assert!(translate(&queries::search_filter("du* x", Kind::User, State::Enabled)).is_ok());
        for query in [
            Query::Disabled,
            Query::PasswordNeverExpires,
            Query::Administrators,
            Query::Conflicts,
        ] {
            let filter = query.filter(Kind::All, State::All, None).unwrap();
            assert!(translate(&filter).is_ok(), "{filter}");
        }
    }

    /// SQL printed by `filtre_sql.traduire` (Python) for the same filters.
    #[test]
    fn same_sql_as_python() {
        let cases = [
            (
                "(|(memberOf:1.2.840.113556.1.4.1941:=<SID=S-1-5-32-544>)(primaryGroupID=512)(primaryGroupID=519))",
                "(COALESCE((o.guid IN (WITH RECURSIVE chaine(g) AS (SELECT membre FROM liens WHERE groupe IN (SELECT guid FROM objets WHERE sid = ?) UNION SELECT l.membre FROM liens l JOIN chaine c ON l.groupe = c.g) SELECT g FROM chaine)), 0) OR COALESCE((o.groupe_principal = ?), 0) OR COALESCE((o.groupe_principal = ?), 0))",
            ),
            (
                "(member:1.2.840.113556.1.4.1941:=CN=U,DC=lab,DC=test)",
                "COALESCE((o.guid IN (WITH RECURSIVE chaine(g) AS (SELECT groupe FROM liens WHERE membre IN (SELECT guid FROM objets WHERE dn = ? UNION SELECT membre FROM liens WHERE dn = ? COLLATE NOCASE) UNION SELECT l.groupe FROM liens l JOIN chaine c ON l.membre = c.g) SELECT g FROM chaine)), 0)",
            ),
            (
                "(&(whenChanged>=20261015000000.0Z)(name=Élo*)(description=Été))",
                "(COALESCE((o.modifie >= ?), 0) AND COALESCE((plier(o.nom) LIKE ? ESCAPE '\\'), 0) AND COALESCE((plier(o.description) = ?), 0))",
            ),
            (
                "(name=*\\0aCNF:*)",
                "COALESCE((o.nom LIKE ? ESCAPE '\\'), 0)",
            ),
        ];
        for (filter, expected) in cases {
            assert_eq!(translate(filter).unwrap().sql, expected, "{filter}");
        }
        let c =
            translate("(&(whenChanged>=20261015000000.0Z)(name=Élo*)(description=Été))").unwrap();
        assert_eq!(
            c.parameters,
            vec![
                Value::Text("20261015000000.0Z".into()),
                Value::Text("élo%".into()),
                Value::Text("été".into())
            ]
        );
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Messages of the codecs and of the core in the language of the interface (R4.10). The
//! codecs of `annuaire-codecs`, and the parts of the core that build their errors as text,
//! write them in English, with what went wrong in the text (`malformed ACE: "(A;;"`); the
//! Python codecs wrote them in French, untranslated. The interface reads the English message
//! against the known forms, translates the form and puts back what it held, itself
//! translated when it is a nested message (`ACE of type 9: truncated ACE`). A message of no
//! known form stays as it is.
//!
//! Covered (R4.10b, R4.10f): every message of the codecs (SDDL, conditions, descriptor,
//! SID, GUID, integer, times, `sAMAccountType`, DNS records and properties, `gPLink`, GPO
//! extensions, Registry.pol, GptTmpl.inf), of the administrative templates, and of the
//! changesets, the journal, the DNs, the filters and the RootDSE in the core. A test reads
//! these sources and fails on a message without a form here (`every_message_has_a_form`).
//! Not translated, as in the Python application: what comes from a server, the system or
//! another library (LDAP diagnostic text, I/O errors, XML parser, Kerberos).

use crate::i18n::{fill, tr};

/// English forms (`{}` for each part kept) and their translation (`{a}`, `{b}`…), the most
/// specific first.
fn forms() -> Vec<(&'static str, String)> {
    vec![
        // sddl.rs
        (
            "abbreviation {} without a domain SID",
            tr("abbreviation {a} without a domain SID"),
        ),
        ("invalid SID: {}", tr("invalid SID: {a}")),
        ("invalid mask: {}", tr("invalid mask: {a}")),
        ("unknown right: {}", tr("unknown right: {a}")),
        (
            "flags not representable: 0x{}",
            tr("flags not representable: 0x{a}"),
        ),
        ("unknown flag in {}", tr("unknown flag in {a}")),
        (
            "ACE of type {}: no SDDL form",
            tr("ACE of type {a}: no SDDL form"),
        ),
        ("ACE of type {}: {}", tr("ACE of type {a}: {b}")),
        ("ACE with a malformed SID", tr("ACE with a malformed SID")),
        ("malformed ACE: {}", tr("malformed ACE: {a}")),
        ("unknown ACE type: {}", tr("unknown ACE type: {a}")),
        ("condition {}: {}", tr("condition {a}: {b}")),
        ("missing", tr("missing")),
        ("unexpected", tr("unexpected")),
        ("invalid GUID in {}", tr("invalid GUID in {a}")),
        (
            "GUID in an ACE without object: {}",
            tr("GUID in an ACE without object: {a}"),
        ),
        ("GUID in a simple ACE: {}", tr("GUID in a simple ACE: {a}")),
        (
            "extra closing parenthesis: {}",
            tr("extra closing parenthesis: {a}"),
        ),
        (
            "text before the first section: {}",
            tr("text before the first section: {a}"),
        ),
        (
            "unclosed parenthesis or quote: {}",
            tr("unclosed parenthesis or quote: {a}"),
        ),
        ("no section: {}", tr("no section: {a}")),
        ("duplicate section: {}", tr("duplicate section: {a}")),
        ("text outside an ACE: {}", tr("text outside an ACE: {a}")),
        // condition.rs
        (
            "condition nested too deeply",
            tr("condition nested too deeply"),
        ),
        ("truncated condition", tr("truncated condition")),
        (
            "unreadable string in a condition",
            tr("unreadable string in a condition"),
        ),
        (
            "malformed SID in a condition",
            tr("malformed SID in a condition"),
        ),
        (
            "unknown token in a condition: 0x{}",
            tr("unknown token in a condition: 0x{a}"),
        ),
        (
            "condition without the \"artx\" signature",
            tr("condition without the \"artx\" signature"),
        ),
        (
            "operator without its two operands in a condition",
            tr("operator without its two operands in a condition"),
        ),
        (
            "operator without operand in a condition",
            tr("operator without operand in a condition"),
        ),
        (
            "incomplete condition ({} terms left)",
            tr("incomplete condition ({a} terms left)"),
        ),
        (
            "negative integer noted \"+\" in a condition",
            tr("negative integer noted \"+\" in a condition"),
        ),
        (
            "positive integer noted \"-\" in a condition",
            tr("positive integer noted \"-\" in a condition"),
        ),
        ("unknown scope", tr("unknown scope")),
        ("unknown operator", tr("unknown operator")),
        (
            "operation with a wrong number of operands",
            tr("operation with a wrong number of operands"),
        ),
        ("malformed number: \"{}\"", tr("malformed number: \"{a}\"")),
        (
            "number beyond 64 bits: \"{}\"",
            tr("number beyond 64 bits: \"{a}\""),
        ),
        ("unknown SID: \"{}\" ({})", tr("unknown SID: \"{a}\" ({b})")),
        (
            "string without a closing quote",
            tr("string without a closing quote"),
        ),
        (
            "odd number of hexadecimal digits",
            tr("odd number of hexadecimal digits"),
        ),
        (
            "unknown attribute: \"{}\" (@User., @Device. or @Resource.)",
            tr("unknown attribute: \"{a}\" (@User., @Device. or @Resource.)"),
        ),
        ("empty attribute name", tr("empty attribute name")),
        (
            "SID(…) without a closing parenthesis",
            tr("SID(…) without a closing parenthesis"),
        ),
        (
            "unexpected character: \"{}\"",
            tr("unexpected character: \"{a}\""),
        ),
        ("incomplete condition", tr("incomplete condition")),
        (
            "\"{}\" expected, \"{}\" found",
            tr("\"{a}\" expected, \"{b}\" found"),
        ),
        (
            "\",\" or \"}\" expected in a list",
            tr("\",\" or \"}\" expected in a list"),
        ),
        (
            "value or attribute expected, \"{}\" found",
            tr("value or attribute expected, \"{a}\" found"),
        ),
        (
            "\"{}\" goes between two operands",
            tr("\"{a}\" goes between two operands"),
        ),
        (
            "a condition is written in parentheses",
            tr("a condition is written in parentheses"),
        ),
        (
            "text after the condition: \"{}\"",
            tr("text after the condition: \"{a}\""),
        ),
        ("value too long", tr("value too long")),
        (
            "truncated resource attribute",
            tr("truncated resource attribute"),
        ),
        ("non-ASCII SID text", tr("non-ASCII SID text")),
        (
            "unknown resource attribute type: {}",
            tr("unknown resource attribute type: {a}"),
        ),
        (
            "a resource attribute is written in parentheses",
            tr("a resource attribute is written in parentheses"),
        ),
        (
            "resource attribute: name, type and flags expected",
            tr("resource attribute: name, type and flags expected"),
        ),
        (
            "the name of a resource attribute is in double quotes",
            tr("the name of a resource attribute is in double quotes"),
        ),
        (
            "unknown attribute type: \"{}\"",
            tr("unknown attribute type: \"{a}\""),
        ),
        ("malformed flags: \"{}\"", tr("malformed flags: \"{a}\"")),
        ("string expected: \"{}\"", tr("string expected: \"{a}\"")),
        ("malformed bytes: \"{}\"", tr("malformed bytes: \"{a}\"")),
        (
            "negative value for an unsigned type",
            tr("negative value for an unsigned type"),
        ),
        (
            "resource attribute flags beyond 32 bits",
            tr("resource attribute flags beyond 32 bits"),
        ),
        ("integer beyond 64 bits", tr("integer beyond 64 bits")),
        (
            "resource attribute too long",
            tr("resource attribute too long"),
        ),
        ("{} (at {})", tr("{a} (at {b})")),
        // sd.rs
        ("descriptor too short", tr("descriptor too short")),
        (
            "descriptor not self-relative or of unknown revision",
            tr("descriptor not self-relative or of unknown revision"),
        ),
        ("truncated ACL", tr("truncated ACL")),
        (
            "ACL longer than the descriptor",
            tr("ACL longer than the descriptor"),
        ),
        ("truncated ACE", tr("truncated ACE")),
        ("invalid ACE size", tr("invalid ACE size")),
        ("truncated object ACE", tr("truncated object ACE")),
        (
            "not a simple ACE type: {}",
            tr("not a simple ACE type: {a}"),
        ),
        (
            "not an object ACE type: {}",
            tr("not an object ACE type: {a}"),
        ),
        ("descriptor without DACL", tr("descriptor without DACL")),
        (
            "an added ACE must be explicit",
            tr("an added ACE must be explicit"),
        ),
        ("ACE or ACL too long", tr("ACE or ACL too long")),
        // sid.rs, guid.rs, integer.rs, time.rs, uac.rs
        (
            "truncated SID: incomplete header",
            tr("truncated SID: incomplete header"),
        ),
        (
            "truncated SID: {} sub-authorities announced",
            tr("truncated SID: {a} sub-authorities announced"),
        ),
        ("invalid SID revision: {}", tr("invalid SID revision: {a}")),
        (
            "too many sub-authorities: {}",
            tr("too many sub-authorities: {a}"),
        ),
        (
            "SID followed by {} extra bytes",
            tr("SID followed by {a} extra bytes"),
        ),
        (
            "SID authority out of range",
            tr("SID authority out of range"),
        ),
        (
            "SID sub-authority out of range",
            tr("SID sub-authority out of range"),
        ),
        ("malformed SID text: {}", tr("malformed SID text: {a}")),
        ("SID without sub-authority", tr("SID without sub-authority")),
        ("not a domain SID: {}", tr("not a domain SID: {a}")),
        (
            "GUID of {} bytes instead of {}",
            tr("GUID of {a} bytes instead of {b}"),
        ),
        ("malformed GUID text: {}", tr("malformed GUID text: {a}")),
        (
            "LDAP integer: non-ASCII character",
            tr("LDAP integer: non-ASCII character"),
        ),
        (
            "malformed LDAP integer: {}",
            tr("malformed LDAP integer: {a}"),
        ),
        (
            "{} out of the bounds of a signed {}-bit integer",
            tr("{a} out of the bounds of a signed {b}-bit integer"),
        ),
        ("unsupported width: {}", tr("unsupported width: {a}")),
        (
            "FILETIME out of range: {}",
            tr("FILETIME out of range: {a}"),
        ),
        (
            "FILETIME beyond the year 9999: {}",
            tr("FILETIME beyond the year 9999: {a}"),
        ),
        (
            "the date 1601-01-01T00:00:00Z is the same as never",
            tr("the date 1601-01-01T00:00:00Z is the same as never"),
        ),
        (
            "date out of the FILETIME range",
            tr("date out of the FILETIME range"),
        ),
        (
            "invalid AD duration (must be negative or zero): {}",
            tr("invalid AD duration (must be negative or zero): {a}"),
        ),
        ("negative duration: {} s", tr("negative duration: {a} s")),
        (
            "malformed GeneralizedTime: {}",
            tr("malformed GeneralizedTime: {a}"),
        ),
        (
            "invalid GeneralizedTime: {}",
            tr("invalid GeneralizedTime: {a}"),
        ),
        ("invalid date", tr("invalid date")),
        (
            "unknown sAMAccountType: {}",
            tr("unknown sAMAccountType: {a}"),
        ),
        (
            "a Builtin group is always a security group",
            tr("a Builtin group is always a security group"),
        ),
        // dns_record.rs, dns_property.rs
        ("truncated DNS name", tr("truncated DNS name")),
        (
            "DNS name longer than the data",
            tr("DNS name longer than the data"),
        ),
        (
            "DNS label outside the name",
            tr("DNS label outside the name"),
        ),
        (
            "DNS label of invalid length",
            tr("DNS label of invalid length"),
        ),
        (
            "DNS name without final zero",
            tr("DNS name without final zero"),
        ),
        (
            "{} extra bytes after the name",
            tr("{a} extra bytes after the name"),
        ),
        ("truncated TXT string", tr("truncated TXT string")),
        ("text is not UTF-8", tr("text is not UTF-8")),
        (
            "DNS label of {} bytes in {}",
            tr("DNS label of {a} bytes in {b}"),
        ),
        ("DNS name too long: {}", tr("DNS name too long: {a}")),
        (
            "TXT string longer than 255 bytes",
            tr("TXT string longer than 255 bytes"),
        ),
        (
            "form not reproducible byte for byte",
            tr("form not reproducible byte for byte"),
        ),
        (
            "dnsRecord of {} bytes, header of {}",
            tr("dnsRecord of {a} bytes, header of {b}"),
        ),
        (
            "dnsRecord: {} bytes of data announced, {} received",
            tr("dnsRecord: {a} bytes of data announced, {b} received"),
        ),
        (
            "DNS data of {} bytes, more than 65 535",
            tr("DNS data of {a} bytes, more than 65 535"),
        ),
        ("truncated {}", tr("truncated {a}")),
        ("{} of length {}", tr("{a} of length {b}")),
        (
            "dNSProperty of {} bytes, header of {}",
            tr("dNSProperty of {a} bytes, header of {b}"),
        ),
        (
            "dNSProperty: {} bytes announced, {} received",
            tr("dNSProperty: {a} bytes announced, {b} received"),
        ),
        ("dNSProperty data too long", tr("dNSProperty data too long")),
        // gplink.rs, extensions.rs
        ("gPLink is not UTF-8", tr("gPLink is not UTF-8")),
        ("no link at position {}", tr("no link at position {a}")),
        ("gPOptions: {}", tr("gPOptions: {a}")),
        ("LDAP:// prefix missing", tr("LDAP:// prefix missing")),
        ("options missing", tr("options missing")),
        ("unreadable options", tr("unreadable options")),
        ("bracket not closed", tr("bracket not closed")),
        ("text outside a link", tr("text outside a link")),
        (
            "GPO extension list is not UTF-8",
            tr("GPO extension list is not UTF-8"),
        ),
        (
            "GPO extension list unreadable at position {}: {}",
            tr("GPO extension list unreadable at position {a}: {b}"),
        ),
        // registry_pol.rs, gpt_tmpl.rs
        (
            "Registry.pol: no PReg signature",
            tr("Registry.pol: no PReg signature"),
        ),
        (
            "Registry.pol: unknown version {}",
            tr("Registry.pol: unknown version {a}"),
        ),
        (
            "Registry.pol: {} expected at byte {}",
            tr("Registry.pol: {a} expected at byte {b}"),
        ),
        (
            "Registry.pol: string not terminated",
            tr("Registry.pol: string not terminated"),
        ),
        (
            "Registry.pol: truncated entry",
            tr("Registry.pol: truncated entry"),
        ),
        (
            "Registry.pol: unreadable text",
            tr("Registry.pol: unreadable text"),
        ),
        (
            "Registry.pol: empty key, or NUL in a key or a name",
            tr("Registry.pol: empty key, or NUL in a key or a name"),
        ),
        (
            "Registry.pol: NUL character in a text",
            tr("Registry.pol: NUL character in a text"),
        ),
        (
            "Registry.pol: integer out of range: {}",
            tr("Registry.pol: integer out of range: {a}"),
        ),
        (
            "Registry.pol: data too long",
            tr("Registry.pol: data too long"),
        ),
        (
            "Registry.pol: {} expected",
            tr("Registry.pol: {a} expected"),
        ),
        ("an integer", tr("an integer")),
        ("a text", tr("a text")),
        ("a list of texts", tr("a list of texts")),
        ("bytes", tr("bytes")),
        (
            "GptTmpl.inf: unreadable text",
            tr("GptTmpl.inf: unreadable text"),
        ),
        (
            "GptTmpl.inf: {} has no Windows-1252 byte",
            tr("GptTmpl.inf: {a} has no Windows-1252 byte"),
        ),
        (
            "GptTmpl.inf: {} is not an integer ({})",
            tr("GptTmpl.inf: {a} is not an integer ({b})"),
        ),
        // admx.rs, admx_store.rs
        ("{}: unreadable XML ({}).", tr("{a}: unreadable XML ({b}).")),
        ("{}: not an ADMX file.", tr("{a}: not an ADMX file.")),
        ("{}: no namespace.", tr("{a}: no namespace.")),
        (
            "{}: no ADML file, texts missing.",
            tr("{a}: no ADML file, texts missing."),
        ),
        (
            "policy {}: unknown class “{}”.",
            tr("policy {a}: unknown class “{b}”."),
        ),
        ("value kind {}", tr("value kind {a}")),
        ("text expected", tr("text expected")),
        ("element kind", tr("element kind")),
        ("{}: boolean expected", tr("{a}: boolean expected")),
        ("{}: integer expected", tr("{a}: integer expected")),
        ("unknown field {}", tr("unknown field {a}")),
        ("control kind", tr("control kind")),
        (
            "cache of the templates of another version",
            tr("cache of the templates of another version"),
        ),
        (
            "{}: unreadable on the SYSVOL.",
            tr("{a}: unreadable on the SYSVOL."),
        ),
        // changes.rs, dn.rs, search.rs, rootdse.rs
        ("empty DN", tr("empty DN")),
        ("empty change on {}", tr("empty change on {a}")),
        ("duplicate value on {}", tr("duplicate value on {a}")),
        (
            "value both removed and added on {}",
            tr("value both removed and added on {a}"),
        ),
        (
            "creation without attribute",
            tr("creation without attribute"),
        ),
        (
            "missing or non-binary values for {}",
            tr("missing or non-binary values for {a}"),
        ),
        (
            "modification without change",
            tr("modification without change"),
        ),
        ("rename without effect", tr("rename without effect")),
        ("value not shown: {}", tr("value not shown: {a}")),
        ("journaled form: {}", tr("journaled form: {a}")),
        (
            "no continuation: failure, rollback or doubtful operation",
            tr("no continuation: failure, rollback or doubtful operation"),
        ),
        ("memberOf: invalid UTF-8", tr("memberOf: invalid UTF-8")),
        ("invalid base64: {}", tr("invalid base64: {a}")),
        ("unreadable value: {}", tr("unreadable value: {a}")),
        (
            "attributes: object expected",
            tr("attributes: object expected"),
        ),
        ("share: object expected", tr("share: object expected")),
        ("share: registry", tr("share: registry")),
        ("backup: {}", tr("backup: {a}")),
        ("propagation: direction", tr("propagation: direction")),
        ("propagation: owner", tr("propagation: owner")),
        (
            "share: {} is not a number",
            tr("share: {a} is not a number"),
        ),
        ("array expected: {}", tr("array expected: {a}")),
        ("missing key {}", tr("missing key {a}")),
        ("integer expected: {}", tr("integer expected: {a}")),
        ("version expected: {}", tr("version expected: {a}")),
        ("missing journaled value", tr("missing journaled value")),
        (
            "unknown operation type: {}",
            tr("unknown operation type: {a}"),
        ),
        (
            "operation: object expected",
            tr("operation: object expected"),
        ),
        ("change: object expected", tr("change: object expected")),
        ("one RDN expected: {}", tr("one RDN expected: {a}")),
        (
            "changeset: object expected",
            tr("changeset: object expected"),
        ),
        ("error expected: {}", tr("error expected: {a}")),
        ("applied: object expected", tr("applied: object expected")),
        ("report: object expected", tr("report: object expected")),
        (
            "unknown journal version: {}",
            tr("unknown journal version: {a}"),
        ),
        (
            "doubtful operation out of range",
            tr("doubtful operation out of range"),
        ),
        (
            "doubtful rollback operation out of range",
            tr("doubtful rollback operation out of range"),
        ),
        ("unknown issue: {}", tr("unknown issue: {a}")),
        ("DN without `=`: {}", tr("DN without `=`: {a}")),
        (
            "invalid attribute type {} in {}",
            tr("invalid attribute type {a} in {b}"),
        ),
        (
            "invalid attribute type: {}",
            tr("invalid attribute type: {a}"),
        ),
        (
            "BER value (`#…`) not supported: {}",
            tr("BER value (`#…`) not supported: {a}"),
        ),
        (
            "invalid escape at position {}: {}",
            tr("invalid escape at position {a}: {b}"),
        ),
        (
            "multi-valued RDN not supported: {}",
            tr("multi-valued RDN not supported: {a}"),
        ),
        (
            "unescaped character {}: {}",
            tr("unescaped character {a}: {b}"),
        ),
        (
            "hexadecimal escapes outside UTF-8: {}",
            tr("hexadecimal escapes outside UTF-8: {a}"),
        ),
        (
            "invalid attribute name: {}",
            tr("invalid attribute name: {a}"),
        ),
        ("{} without filter", tr("{a} without filter")),
        (
            "inconsistent ranges of {}: {}",
            tr("inconsistent ranges of {a}: {b}"),
        ),
        (
            "demandé à partir de {}, reçu {}",
            tr("requested from {a}, received {b}"),
        ),
        ("borne {}", tr("bound {a}")),
        (
            "RootDSE sans defaultNamingContext",
            tr("RootDSE without defaultNamingContext"),
        ),
        (
            "invalid integer for {}: {}",
            tr("invalid integer for {a}: {b}"),
        ),
    ]
}

/// The parts of `text` held by the holes of `form`, if it has this form. Each literal is
/// looked for after the previous one; the last one ends the text.
fn parts<'t>(form: &str, text: &'t str) -> Option<Vec<&'t str>> {
    let literals: Vec<&str> = form.split("{}").collect();
    let (first, rest) = literals.split_first()?;
    if rest.is_empty() {
        return (text == *first).then(Vec::new);
    }
    let mut position = text.strip_prefix(first).map(|_| first.len())?;
    let mut holes = Vec::new();
    for (i, literal) in rest.iter().enumerate() {
        let found = if i + 1 == rest.len() {
            (text.len() >= position + literal.len() && text.ends_with(literal))
                .then(|| text.len() - literal.len())
        } else if literal.is_empty() {
            None
        } else {
            text[position..].find(literal).map(|at| position + at)
        }?;
        holes.push(&text[position..found]);
        position = found + literal.len();
    }
    Some(holes)
}

/// `text`, an English message of a codec or of the core, in the language of the interface.
pub fn codec_message(text: &str) -> String {
    for (form, translated) in forms() {
        if let Some(holes) = parts(form, text) {
            let holes: Vec<String> = holes.into_iter().map(codec_message).collect();
            let fields: Vec<(&str, &str)> = ["a", "b", "c", "d"]
                .into_iter()
                .zip(holes.iter().map(String::as_str))
                .collect();
            return fill(&translated, &fields);
        }
    }
    // `A: B`, a message put after a name or before the text it is about (`{message}: {:?}`
    // of the SDDL, `{file}: {error}` of the templates): the first split where one side is a
    // known message. A long text (server diagnostic) is not cut up.
    if text.matches(": ").count() > 4 {
        return text.to_owned();
    }
    for (at, _) in text.match_indices(": ") {
        let (left, right) = (&text[..at], &text[at + 2..]);
        let (left_t, right_t) = (codec_message(left), codec_message(right));
        if left_t != left || right_t != right {
            return fill(
                &tr("{message}: {texte}"),
                &[("message", &left_t), ("texte", &right_t)],
            );
        }
    }
    text.to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use super::*;

    #[test]
    fn parts_of_forms() {
        assert_eq!(
            parts("malformed ACE: {}", "malformed ACE: \"(A;;\""),
            Some(vec!["\"(A;;\""])
        );
        assert_eq!(
            parts("ACE of type {}: {}", "ACE of type 9: truncated ACE"),
            Some(vec!["9", "truncated ACE"])
        );
        assert_eq!(
            parts(
                "\"{}\" expected, \"{}\" found",
                "\")\" expected, \"x\" found"
            ),
            Some(vec![")", "x"])
        );
        assert_eq!(parts("truncated ACL", "truncated ACL"), Some(vec![]));
        assert_eq!(parts("truncated ACL", "truncated ACLs"), None);
        assert_eq!(parts("no section: {}", "malformed ACE: x"), None);
    }

    #[test]
    fn untranslated_messages_keep_their_parts() {
        // Without a catalogue, the translation is the English form: same text back.
        for text in [
            "malformed ACE: \"(A;;\"",
            "ACE of type 9: truncated ACE",
            "incomplete condition: \"(@User.x ==\"",
            "\")\" expected, \"x\" found (at 4)",
            "Registry.pol: an integer expected",
            "Default.admx: policy P: unknown class “Both”.",
            "something else entirely",
            "a: b: c: d: e: f: g",
        ] {
            assert_eq!(codec_message(text), text);
        }
    }

    /// String literals of a source file, outside of its tests and comments, that hold a
    /// space, as the format strings of messages do: `\"` and `\\` read, each `{…}` made `{}`.
    fn literals(source: &str) -> Vec<String> {
        let code = source.split("#[cfg(test)]").next().unwrap_or_default();
        let mut out = Vec::new();
        for line in code.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("#[") {
                continue;
            }
            let mut chars = line.chars();
            while chars.any(|c| c == '"') {
                let mut text = String::new();
                let mut closed = false;
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => match chars.next() {
                            Some('n') => text.push('\n'),
                            Some(other) => text.push(other),
                            None => {}
                        },
                        '"' => {
                            closed = true;
                            break;
                        }
                        c => text.push(c),
                    }
                }
                if closed && text.contains(' ') {
                    out.push(normalize(&text));
                }
            }
        }
        out
    }

    fn normalize(text: &str) -> String {
        let mut out = String::new();
        let mut hole = false;
        for c in text.chars() {
            match c {
                '{' => hole = true,
                '}' if hole => {
                    hole = false;
                    out.push_str("{}");
                }
                _ if hole => {}
                c => out.push(c),
            }
        }
        out
    }

    /// Sources whose messages can reach the interface as text.
    const SOURCES: [&str; 20] = [
        "annuaire-codecs/src/condition.rs",
        "annuaire-codecs/src/dns_property.rs",
        "annuaire-codecs/src/dns_record.rs",
        "annuaire-codecs/src/extensions.rs",
        "annuaire-codecs/src/gplink.rs",
        "annuaire-codecs/src/gpt_tmpl.rs",
        "annuaire-codecs/src/guid.rs",
        "annuaire-codecs/src/integer.rs",
        "annuaire-codecs/src/registry_pol.rs",
        "annuaire-codecs/src/sd.rs",
        "annuaire-codecs/src/sddl.rs",
        "annuaire-codecs/src/sid.rs",
        "annuaire-codecs/src/time.rs",
        "annuaire-codecs/src/uac.rs",
        "annuaire-core/src/admx.rs",
        "annuaire-core/src/admx_store.rs",
        "annuaire-core/src/changes.rs",
        "annuaire-core/src/dn.rs",
        "annuaire-core/src/rootdse.rs",
        "annuaire-core/src/search.rs",
    ];

    /// Literals of these sources that are not messages: text written out (records,
    /// preview lines, INF sections, SDDL), expectations, and the two compositions `{}: {}`,
    /// handled by `codec_message` itself.
    const NOT_MESSAGES: [&str; 36] = [
        ", ",
        "; ",
        " ",
        "', ",
        "({} {})",
        "({} {} {})",
        "') && field.last() == Some(&'",
        "{} {}",
        "{} {} {} {}",
        "{} {} {} {} {} {} {}",
        "entry just made",
        "Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf",
        "System Access",
        "Kerberos Policy",
        "Privilege Rights",
        "Group Membership",
        "Event Audit",
        "Registry Values",
        "Service General Setting",
        "Registry Keys",
        "File Security",
        "{} = {}{}",
        "S-1-1-0 is a valid SID",
        "{}: {}",
        "{}-{}-{} {}:{} UTC",
        "{} {} ({})",
        "[{}] {} = {} ({})",
        "− {}",
        "+ {}",
        "{} → {}",
        "LDAP operations are handled by operation_lines",
        "only operations on shares",
        "{} = {}",
        "{}. {}",
        "     {}",
        "  - {}",
    ];

    /// Ignored also: the escaped characters of the DN module and the input of the cache key
    /// of the templates.
    const NOT_MESSAGES_TOO: [&str; 3] = [" \"#+,;<=>\\", "\\ ", "admx {}\n"];

    /// Messages of the core still written in French (kept identical to the Python core);
    /// their `msgid` is English.
    const FRENCH_IN_CORE: [&str; 3] = [
        "demandé à partir de {}, reçu {}",
        "borne {}",
        "RootDSE sans defaultNamingContext",
    ];

    #[test]
    fn every_message_has_a_form() {
        let rust = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let known: HashSet<&str> = forms().iter().map(|(f, _)| *f).collect();
        let ignored: HashSet<&str> = NOT_MESSAGES
            .iter()
            .chain(&NOT_MESSAGES_TOO)
            .copied()
            .collect();
        let mut missing = Vec::new();
        for source in SOURCES {
            let text = std::fs::read_to_string(rust.join(source)).expect(source);
            for literal in literals(&text) {
                if !known.contains(literal.as_str()) && !ignored.contains(literal.as_str()) {
                    missing.push(format!("{source}: {literal:?}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "messages without a form in codec_texts::forms: {missing:#?}"
        );
    }

    /// Each form is translated through the `msgid` that names its holes `{a}`, `{b}`…, and
    /// `fr.po` has that message.
    #[test]
    fn every_form_is_translated() {
        let po =
            std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../po/fr.po"))
                .expect("fr.po");
        let translated = po_messages(&po);
        let mut problems = Vec::new();
        for (form, msgid) in forms() {
            let mut names = ["a", "b", "c", "d"].into_iter();
            let mut expected = String::new();
            for (i, piece) in form.split("{}").enumerate() {
                if i > 0 {
                    expected.push_str(&format!("{{{}}}", names.next().unwrap_or("?")));
                }
                expected.push_str(piece);
            }
            if msgid != expected && !FRENCH_IN_CORE.contains(&form) {
                problems.push(format!("{form:?}: msgid {msgid:?}"));
            }
            if !translated.contains(&msgid) {
                problems.push(format!("{msgid:?}: not translated in fr.po"));
            }
        }
        assert!(problems.is_empty(), "{problems:#?}");
    }

    /// `msgid` of `po` that have a non-empty `msgstr`.
    fn po_messages(po: &str) -> HashSet<String> {
        let mut out = HashSet::new();
        let (mut msgid, mut msgstr, mut field) = (String::new(), String::new(), 0);
        let read = |line: &str| -> String {
            let line = line.trim();
            let inner = line.strip_prefix('"').unwrap_or(line);
            let inner = inner.strip_suffix('"').unwrap_or(inner);
            inner.replace("\\\"", "\"").replace("\\\\", "\\")
        };
        for line in po.lines().chain(std::iter::once("")) {
            if let Some(rest) = line.strip_prefix("msgid ") {
                (msgid, field) = (read(rest), 1);
            } else if let Some(rest) = line.strip_prefix("msgstr ") {
                (msgstr, field) = (read(rest), 2);
            } else if line.starts_with('"') {
                match field {
                    1 => msgid.push_str(&read(line)),
                    2 => msgstr.push_str(&read(line)),
                    _ => {}
                }
            } else {
                if field == 2 && !msgstr.is_empty() {
                    out.insert(std::mem::take(&mut msgid));
                }
                field = 0;
                msgstr.clear();
            }
        }
        out
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Translations (ADR 0019, section 4): English is the source language, French the catalogue
//! `po/fr.po` of the domain `annuaire`. Messages keep the `{name}` fields of the Python
//! catalogue, filled by [`fill`]. Keywords for xgettext: `tr`, `tr_ctx:1c,2`, `tr_n:1,2`; xgettext
//! reads string literals only (`every_call_has_a_literal`).

use gettextrs::{bind_textdomain_codeset, bindtextdomain, textdomain};

use crate::config;

/// Binds the domain for Rust and for GtkBuilder (Blueprint), before any window. The locale
/// itself is set by GTK at its initialisation (`setlocale` is unsafe in gettext-rs, and the
/// crate forbids unsafe code), before any text is translated.
pub fn init() {
    // Without catalogue or locale, the interface stays in English: not an error.
    let _ = bindtextdomain(config::GETTEXT_DOMAIN, config::locale_dir());
    let _ = bind_textdomain_codeset(config::GETTEXT_DOMAIN, "UTF-8");
    let _ = textdomain(config::GETTEXT_DOMAIN);
}

pub fn tr(msgid: &str) -> String {
    gettextrs::gettext(msgid)
}

/// A message marked elsewhere by `N_` (a table), translated when shown.
pub fn tr_marked(msgid: &str) -> String {
    gettextrs::gettext(msgid)
}

#[allow(dead_code)] // first contexts: the screens of R4.2 and later
pub fn tr_ctx(context: &str, msgid: &str) -> String {
    gettextrs::pgettext(context, msgid)
}

#[allow(dead_code)] // first plurals: the status bar of the domain (R4.3)
pub fn tr_n(singular: &str, plural: &str, n: u64) -> String {
    gettextrs::ngettext(singular, plural, u32::try_from(n).unwrap_or(u32::MAX))
}

/// Replaces each `{name}` of `template` by its value, as `str.format` with keywords; a field
/// without value stays as is.
pub fn fill(template: &str, fields: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        let (before, after) = rest.split_at(start);
        out.push_str(before);
        let replaced = after.find('}').and_then(|end| {
            let name = after.get(1..end)?;
            let value = fields.iter().find(|(key, _)| *key == name)?.1;
            Some((value, end + 1))
        });
        match replaced {
            Some((value, consumed)) => {
                out.push_str(value);
                rest = after.get(consumed..).unwrap_or("");
            }
            None => {
                out.push('{');
                rest = after.get(1..).unwrap_or("");
            }
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::fill;

    /// The positions of the calls of `tr`, `tr_ctx` and `tr_n` in `text` whose first argument
    /// is not a string literal (definitions excepted).
    fn calls_without_literal(text: &str) -> Vec<usize> {
        let mut found = Vec::new();
        for name in ["tr(", "tr_ctx(", "tr_n("] {
            for (at, _) in text.match_indices(name) {
                let before = text.get(..at).and_then(|b| b.chars().next_back());
                if before.is_some_and(|c| c.is_alphanumeric() || c == '_') {
                    continue;
                }
                let line_start = text
                    .get(..at)
                    .and_then(|b| b.rfind('\n'))
                    .map_or(0, |i| i + 1);
                if text
                    .get(line_start..at)
                    .is_some_and(|l| l.trim_end().ends_with("fn"))
                {
                    continue;
                }
                let rest = text.get(at + name.len()..).unwrap_or("");
                if !rest.trim_start().starts_with('"') {
                    found.push(text.get(..at).map_or(0, |b| b.matches('\n').count() + 1));
                }
            }
        }
        found
    }

    fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("src").flatten() {
            let path = entry.path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// xgettext only extracts literal messages: a call with anything else would never be
    /// translated. This module, which defines them and tests the scan, is left out.
    #[test]
    fn every_call_has_a_literal() {
        let mut files = Vec::new();
        sources(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut files,
        );
        let mut faults = Vec::new();
        for file in files.iter().filter(|f| !f.ends_with("i18n.rs")) {
            let text = std::fs::read_to_string(file).expect("source");
            for line in calls_without_literal(&text) {
                faults.push(format!("{}:{line}", file.display()));
            }
        }
        assert!(faults.is_empty(), "tr() without a literal: {faults:?}");
        assert_eq!(calls_without_literal("x = tr(name);"), [1]);
        assert!(
            calls_without_literal("pub fn tr(msgid: &str)\nlet y = attr(x) + tr(\"a\");")
                .is_empty()
        );
    }

    #[test]
    fn fields() {
        assert_eq!(fill("{a} and {b}", &[("a", "1"), ("b", "2")]), "1 and 2");
        assert_eq!(fill("{a}{a}", &[("a", "x")]), "xx");
        assert_eq!(fill("{unknown} {", &[("a", "x")]), "{unknown} {");
        assert_eq!(
            fill("valid until {fin}.", &[("fin", "é")]),
            "valid until é."
        );
    }
}

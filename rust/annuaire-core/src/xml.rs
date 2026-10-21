// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! A small element tree (R4.9), what `xml.etree.ElementTree` gives the Python modules: tag,
//! attributes in document order (values decoded), text before the first child, children.
//! Comments, processing instructions and the text after a child (`tail`) are not kept, as
//! with the default parser of ElementTree. Read by `roxmltree` (no DTD).

/// An element (`ET.Element`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Node {
    /// Local name, `{namespace}name` for a qualified one (as ElementTree).
    pub tag: String,
    pub attributes: Vec<(String, String)>,
    /// Text before the first child element (`text`), comments skipped.
    pub text: String,
    pub children: Vec<Node>,
}

/// The tag of an element, as ElementTree writes it.
pub fn tag_of(node: roxmltree::Node<'_, '_>) -> String {
    let name = node.tag_name();
    match name.namespace() {
        Some(ns) if !ns.is_empty() => format!("{{{ns}}}{}", name.name()),
        _ => name.name().to_owned(),
    }
}

impl Node {
    pub fn new(tag: &str) -> Self {
        Self {
            tag: tag.to_owned(),
            ..Self::default()
        }
    }

    /// The tree of an element read by `roxmltree`.
    pub fn from_roxml(node: roxmltree::Node<'_, '_>) -> Self {
        let attributes = node
            .attributes()
            .map(|a| {
                let name = match a.namespace() {
                    Some(ns) if !ns.is_empty() => format!("{{{ns}}}{}", a.name()),
                    _ => a.name().to_owned(),
                };
                (name, a.value().to_owned())
            })
            .collect();
        let mut text = String::new();
        let mut children = Vec::new();
        for child in node.children() {
            if child.is_element() {
                children.push(Self::from_roxml(child));
            } else if child.is_text() && children.is_empty() {
                text.push_str(child.text().unwrap_or_default());
            }
        }
        Self {
            tag: tag_of(node),
            attributes,
            text,
            children,
        }
    }

    /// Parses one element (`ET.fromstring`), without DTD.
    pub fn parse(text: &str) -> Result<Self, roxmltree::Error> {
        let doc = roxmltree::Document::parse_with_options(text, options())?;
        Ok(Self::from_roxml(doc.root_element()))
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn get_or<'a>(&'a self, name: &str, default: &'a str) -> &'a str {
        self.get(name).unwrap_or(default)
    }

    pub fn has(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    /// Sets an attribute: in place if it exists, at the end otherwise (`set`).
    pub fn set(&mut self, name: &str, value: &str) {
        match self.attributes.iter_mut().find(|(k, _)| k == name) {
            Some((_, v)) => value.clone_into(v),
            None => self.attributes.push((name.to_owned(), value.to_owned())),
        }
    }

    pub fn remove_attribute(&mut self, name: &str) {
        self.attributes.retain(|(k, _)| k != name);
    }

    /// The first child of this tag (`find`).
    pub fn find(&self, tag: &str) -> Option<&Self> {
        self.children.iter().find(|c| c.tag == tag)
    }

    pub fn find_mut(&mut self, tag: &str) -> Option<&mut Self> {
        self.children.iter_mut().find(|c| c.tag == tag)
    }

    pub fn position(&self, tag: &str) -> Option<usize> {
        self.children.iter().position(|c| c.tag == tag)
    }

    /// This element and every descendant, in document order (`iter`).
    pub fn iter(&self) -> Vec<&Self> {
        let mut out = vec![self];
        for c in &self.children {
            out.extend(c.iter());
        }
        out
    }

    /// Visits this element and every descendant, mutably.
    pub fn walk_mut(&mut self, f: &mut dyn FnMut(&mut Self)) {
        f(self);
        for c in &mut self.children {
            c.walk_mut(f);
        }
    }

    /// Concatenated texts of the element and its descendants (`itertext`), tails not kept.
    pub fn all_text(&self) -> String {
        let mut out = self.text.clone();
        for c in &self.children {
            out.push_str(&c.all_text());
        }
        out
    }
}

/// Parsing options: no DTD (an entity could expand without bound).
pub fn options() -> roxmltree::ParsingOptions {
    roxmltree::ParsingOptions {
        allow_dtd: false,
        ..roxmltree::ParsingOptions::default()
    }
}

/// Escapes a text or an attribute value, as the GPMC writes them.
pub fn escape(text: &str, attribute: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            '\r' if attribute => out.push_str("&#xD;"),
            '\n' if attribute => out.push_str("&#xA;"),
            '\t' if attribute => out.push_str("&#x9;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn element_tree() {
        let n =
            Node::parse(r#"<a x="1" y="&lt;2"> t <!-- c --> u<b/>tail<c k="v">z</c></a>"#).unwrap();
        assert_eq!(n.tag, "a");
        assert_eq!(
            n.attributes,
            [("x".into(), "1".into()), ("y".into(), "<2".into())]
        );
        assert_eq!(n.text, " t  u");
        assert_eq!(n.children.len(), 2);
        assert_eq!(n.find("c").unwrap().text, "z");
        assert_eq!(n.iter().len(), 3);
        assert!(Node::parse(r#"<!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>"#).is_err());
    }

    #[test]
    fn escapes() {
        assert_eq!(escape("a<\"&\n", true), "a&lt;&quot;&amp;&#xA;");
        assert_eq!(escape("a<\"&\n", false), "a&lt;\"&amp;\n");
    }
}

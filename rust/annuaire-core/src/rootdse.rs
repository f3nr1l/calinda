// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The RootDSE: what the DC says about itself and the domain, read after the bind.

use crate::session::Attributes;

/// Attributes asked for (`connexion.ATTRIBUTS_ROOT_DSE`).
pub const ROOT_DSE_ATTRIBUTES: [&str; 10] = [
    "defaultNamingContext",
    "configurationNamingContext",
    "schemaNamingContext",
    "rootDomainNamingContext",
    "dnsHostName",
    "supportedControl",
    "domainFunctionality",
    "forestFunctionality",
    "domainControllerFunctionality",
    "vendorName",
];

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RootDse {
    pub default_naming_context: String,
    pub configuration_naming_context: String,
    pub schema_naming_context: String,
    pub root_domain_naming_context: String,
    /// In lower case.
    pub dns_host_name: String,
    /// In the order of the server.
    pub supported_controls: Vec<String>,
    pub domain_functionality: i64,
    pub forest_functionality: i64,
    pub dc_functionality: i64,
    /// `Samba Team (https://www.samba.org)` on Samba; empty on Windows.
    pub vendor_name: String,
}

/// Why a RootDSE was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootDseError {
    /// No `defaultNamingContext`: not an Active Directory DC.
    NotADirectory,
    /// A functional level that is not an integer.
    InvalidInteger { name: &'static str, value: String },
}

impl std::fmt::Display for RootDseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Detail of the Python error, kept as is (technical text).
            Self::NotADirectory => f.write_str("RootDSE sans defaultNamingContext"),
            Self::InvalidInteger { name, value } => {
                write!(f, "invalid integer for {name}: {value:?}")
            }
        }
    }
}

impl std::error::Error for RootDseError {}

impl RootDse {
    /// From the raw attributes (names compared without case), like `analyser_root_dse`.
    pub fn parse(attributes: &Attributes) -> Result<Self, RootDseError> {
        let values = |name: &str| {
            attributes
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map_or(&[][..], |(_, v)| v.as_slice())
        };
        let text = |name: &str| {
            values(name)
                .first()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .unwrap_or_default()
        };
        // Empty: 0; otherwise `int()` of the Python version.
        let integer = |name: &'static str| {
            let value = text(name);
            if value.is_empty() {
                return Ok(0);
            }
            value
                .trim()
                .parse::<i64>()
                .map_err(|_| RootDseError::InvalidInteger { name, value })
        };
        if text("defaultNamingContext").is_empty() {
            return Err(RootDseError::NotADirectory);
        }
        Ok(Self {
            default_naming_context: text("defaultNamingContext"),
            configuration_naming_context: text("configurationNamingContext"),
            schema_naming_context: text("schemaNamingContext"),
            root_domain_naming_context: text("rootDomainNamingContext"),
            dns_host_name: text("dnsHostName").to_lowercase(),
            supported_controls: values("supportedControl")
                .iter()
                .map(|v| String::from_utf8_lossy(v).into_owned())
                .collect(),
            domain_functionality: integer("domainFunctionality")?,
            forest_functionality: integer("forestFunctionality")?,
            dc_functionality: integer("domainControllerFunctionality")?,
            vendor_name: text("vendorName"),
        })
    }

    pub fn samba(&self) -> bool {
        self.vendor_name.to_lowercase().starts_with("samba")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &[&str])]) -> Attributes {
        pairs
            .iter()
            .map(|(n, v)| {
                (
                    (*n).to_owned(),
                    v.iter().map(|s| s.as_bytes().to_vec()).collect(),
                )
            })
            .collect()
    }

    #[test]
    fn parses_samba_root_dse() {
        let dse = RootDse::parse(&attrs(&[
            ("defaultNamingContext", &["DC=lab,DC=test"]),
            ("dnsHostName", &["DC1.lab.test"]),
            (
                "supportedcontrol",
                &["1.2.840.113556.1.4.319", "1.2.840.113556.1.4.801"],
            ),
            ("domainFunctionality", &["7"]),
            ("vendorName", &["Samba Team (https://www.samba.org)"]),
        ]))
        .unwrap();
        assert_eq!(dse.dns_host_name, "dc1.lab.test");
        assert_eq!(dse.supported_controls.len(), 2);
        assert_eq!(dse.domain_functionality, 7);
        assert_eq!(dse.forest_functionality, 0);
        assert!(dse.samba());
        assert_eq!(
            RootDse::parse(&attrs(&[("dnsHostName", &["x"])])),
            Err(RootDseError::NotADirectory)
        );
        assert!(matches!(
            RootDse::parse(&attrs(&[
                ("defaultNamingContext", &["x"]),
                ("domainFunctionality", &["sept"])
            ])),
            Err(RootDseError::InvalidInteger { .. })
        ));
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! What a connection needs to know about a domain: `annuaire.core.profils.ProfilDomaine`
//! (validation and serialized form included, for the Rust interface, R4.1) and
//! `connexion.Delais`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// Protection of the connection (ADR 0001).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    /// GSSAPI signed and sealed on port 389 (default).
    Sealed,
    /// TLS on port 636, GSSAPI for authentication only.
    Ldaps,
    /// StartTLS on port 389, GSSAPI for authentication only.
    StartTls,
}

impl Mode {
    pub fn tls(self) -> bool {
        !matches!(self, Self::Sealed)
    }

    /// Value of `ModeChiffrement` in profiles.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "gssapi-scelle" => Some(Self::Sealed),
            "ldaps" => Some(Self::Ldaps),
            "starttls" => Some(Self::StartTls),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Sealed => "gssapi-scelle",
            Self::Ldaps => "ldaps",
            Self::StartTls => "starttls",
        }
    }

    /// Port of the LDAP service in this mode.
    pub fn port(self) -> u16 {
        match self {
            Self::Ldaps => 636,
            Self::Sealed | Self::StartTls => 389,
        }
    }
}

/// The domain and the DCs to use. Names are DNS names in lower case ([`Profile::validate`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub domain: String,
    pub preferred_dc: Option<String>,
    pub mode: Mode,
    /// PEM file of the CA, required by the TLS modes.
    pub ca: Option<PathBuf>,
    /// True by default: every profile outside the lab starts so.
    pub read_only: bool,
    /// DC imposed on writes; none: the PDC emulator.
    pub write_dc: Option<String>,
    /// Keep a local copy of the objects (JC.2); true by default.
    pub cache: bool,
    /// Read and write the SYSVOL of a DC that knows SMB 2.x only (Windows Server 2008 R2 and
    /// earlier) with signing only, unencrypted; false by default (ADR 0021).
    pub smb2_signing: bool,
}

/// A field of the serialized form of a profile (a GVariant `a{sv}` in GSettings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    Text(String),
    Bool(bool),
}

/// Why a profile is invalid; the interface words it (same messages as `profils.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileError {
    /// `nom de domaine invalide : {domaine}`
    InvalidDomain(String),
    /// `nom de DC invalide : {dc}`
    InvalidDc(String),
    /// `le mode TLS exige le certificat de la CA du domaine`
    TlsWithoutCa,
    /// `profil sans domaine`
    NoDomain,
    /// `champ {cle} : chaîne attendue`
    NotText(String),
    /// `champ lecture-seule : booléen attendu`, `champ cache : booléen attendu`
    NotBool(String),
    /// Unknown value of `mode`.
    UnknownMode(String),
}

/// Why a certificate fingerprint cannot be computed (`empreinte_certificat`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintError {
    /// `aucun certificat PEM`
    NoCertificate,
    /// `certificat PEM illisible`
    Unreadable,
}

/// SHA-256 fingerprint of the first certificate of a PEM file, as `AB:CD:…`: what is compared,
/// when a TLS profile is added, with the fingerprint read on the DC
/// (`openssl x509 -fingerprint -sha256`).
pub fn certificate_fingerprint(pem: &[u8]) -> Result<String, FingerprintError> {
    const BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
    const END: &[u8] = b"-----END CERTIFICATE-----";
    let find =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).position(|w| w == needle);
    let start = find(pem, BEGIN).ok_or(FingerprintError::NoCertificate)? + BEGIN.len();
    let body = pem.get(start..).ok_or(FingerprintError::NoCertificate)?;
    let end = find(body, END).ok_or(FingerprintError::NoCertificate)?;
    let text: String = body
        .get(..end)
        .ok_or(FingerprintError::NoCertificate)?
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|&b| char::from(b))
        .collect();
    let valid = !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    if !valid {
        return Err(FingerprintError::Unreadable);
    }
    let der = openssl::base64::decode_block(&text).map_err(|_| FingerprintError::Unreadable)?;
    let digest = openssl::sha::sha256(&der);
    Ok(digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"))
}

/// Absolute DNS name in lower case, without the final dot (RFC 1123), as `nom_dns_valide`.
pub fn valid_dns_name(name: &str) -> bool {
    let label = |l: &str| {
        (1..=63).contains(&l.len())
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    !name.is_empty() && name.len() <= 253 && name.split('.').all(label)
}

impl Profile {
    pub fn new(domain: impl Into<String>) -> Self {
        Self {
            domain: domain.into(),
            preferred_dc: None,
            mode: Mode::Sealed,
            ca: None,
            read_only: true,
            write_dc: None,
            cache: true,
            smb2_signing: false,
        }
    }

    /// Kerberos realm of the domain: the DNS name in upper case, always so for AD.
    pub fn realm(&self) -> String {
        self.domain.to_uppercase()
    }

    /// The checks of `ProfilDomaine.__post_init__`.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if !valid_dns_name(&self.domain) {
            return Err(ProfileError::InvalidDomain(self.domain.clone()));
        }
        for dc in [&self.preferred_dc, &self.write_dc].into_iter().flatten() {
            if !valid_dns_name(dc) {
                return Err(ProfileError::InvalidDc(dc.clone()));
            }
        }
        if self.mode.tls() && self.ca.is_none() {
            return Err(ProfileError::TlsWithoutCa);
        }
        Ok(())
    }

    /// Serialized form (`profil_vers_dict`): empty fields are left out.
    pub fn to_fields(&self) -> BTreeMap<String, Field> {
        let mut fields = BTreeMap::new();
        fields.insert("domaine".into(), Field::Text(self.domain.clone()));
        fields.insert("mode".into(), Field::Text(self.mode.name().into()));
        fields.insert("lecture-seule".into(), Field::Bool(self.read_only));
        fields.insert("cache".into(), Field::Bool(self.cache));
        fields.insert(
            "smb2-signature-seule".into(),
            Field::Bool(self.smb2_signing),
        );
        let optional = [
            ("dc-prefere", self.preferred_dc.clone()),
            ("dc-ecriture", self.write_dc.clone()),
            (
                "ca",
                self.ca.as_ref().map(|c| c.to_string_lossy().into_owned()),
            ),
        ];
        for (key, value) in optional {
            if let Some(value) = value.filter(|v| !v.is_empty()) {
                fields.insert(key.into(), Field::Text(value));
            }
        }
        fields
    }

    /// Inverse of [`Profile::to_fields`] (`profil_depuis_dict`); unknown keys are ignored.
    pub fn from_fields(fields: &BTreeMap<String, Field>) -> Result<Self, ProfileError> {
        let text = |key: &str| match fields.get(key) {
            None => Ok(None),
            Some(Field::Text(t)) if t.is_empty() => Ok(None),
            Some(Field::Text(t)) => Ok(Some(t.clone())),
            Some(Field::Bool(_)) => Err(ProfileError::NotText(key.into())),
        };
        let flag = |key: &str, default: bool| match fields.get(key) {
            None => Ok(default),
            Some(Field::Bool(b)) => Ok(*b),
            Some(Field::Text(_)) => Err(ProfileError::NotBool(key.into())),
        };
        let domain = text("domaine")?.ok_or(ProfileError::NoDomain)?;
        let read_only = flag("lecture-seule", true)?;
        let cache = flag("cache", true)?;
        // Absent from the profiles written before it: off.
        let smb2_signing = flag("smb2-signature-seule", false)?;
        let mode = match text("mode")? {
            None => Mode::Sealed,
            Some(name) => Mode::from_name(&name).ok_or(ProfileError::UnknownMode(name))?,
        };
        let profile = Self {
            domain,
            preferred_dc: text("dc-prefere")?,
            mode,
            ca: text("ca")?.map(PathBuf::from),
            read_only,
            write_dc: text("dc-ecriture")?,
            cache,
            smb2_signing,
        };
        profile.validate()?;
        Ok(profile)
    }
}

/// Timeouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delays {
    /// TCP (and TLS) establishment with one DC, before trying the next.
    pub connect: Duration,
    /// Wait for an answer (a page of a search, a bind).
    pub operation: Duration,
    /// Wait for a page of a search using the IN_CHAIN matching rule
    /// (`1.2.840.113556.1.4.1941`): the DC walks the chain over the whole domain before the
    /// first entry, close to 30 s on Samba for 20,000 objects (ADR 0017, R3.6).
    pub chain: Duration,
}

impl Default for Delays {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(5),
            operation: Duration::from_secs(30),
            chain: Duration::from_secs(180),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_names() {
        for good in ["lab.test", "a", "x-1.example.org", "example.local"] {
            assert!(valid_dns_name(good), "{good}");
        }
        for bad in [
            "", "Lab.test", "-a.test", "a-.test", "a..b", "a.", "é.test", "a_b",
        ] {
            assert!(!valid_dns_name(bad), "{bad}");
        }
        assert!(!valid_dns_name(&"a".repeat(64)));
    }

    #[test]
    fn validation() {
        let mut p = Profile::new("lab.test");
        assert_eq!(p.validate(), Ok(()));
        p.preferred_dc = Some("DC1".into());
        assert_eq!(p.validate(), Err(ProfileError::InvalidDc("DC1".into())));
        p.preferred_dc = None;
        p.mode = Mode::Ldaps;
        assert_eq!(p.validate(), Err(ProfileError::TlsWithoutCa));
        assert_eq!(
            Profile::new("LAB").validate(),
            Err(ProfileError::InvalidDomain("LAB".into()))
        );
    }

    /// Throw-away self-signed certificate of `test_kerberos.py`, fingerprint read by
    /// `openssl x509 -noout -fingerprint -sha256`.
    const PEM: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIBiDCCAS+gAwIBAgIUDXNHuLz2YW8/ePz1Xz6Q3n96KOkwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPY2EuZXhlbXBsZS50ZXN0MB4XDTI2MTAxMzE5NDkxOVoXDTM2
MTAxMDE5NDkxOVowGjEYMBYGA1UEAwwPY2EuZXhlbXBsZS50ZXN0MFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEqFDfVPGEhbFx+O7OjxXnowEf+ms1VdMHmA3KGL/e
PZVmRRWNIayiucBZtVL77Msn646cCie5teRF5P3LP/j1HKNTMFEwHQYDVR0OBBYE
FGOTjuOEiUiJikn0oBdB4fDuGsDdMB8GA1UdIwQYMBaAFGOTjuOEiUiJikn0oBdB
4fDuGsDdMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgaTcW4z8e
a5PtRWdY9n4H/hvd7MzsrpF7Jn7tm+pPsYACIHoJ9jElAthrhnHHOiaDogaQjLv0
T39+3r2LE06AhAdk
-----END CERTIFICATE-----
";

    #[test]
    fn fingerprint() {
        let expected = "32:F8:F5:D1:2E:9D:D5:4E:3B:D4:DC:30:48:B1:31:6A:\
                        67:FF:B7:09:D5:A1:DC:13:0F:2C:C2:6A:BF:21:C4:3C";
        assert_eq!(certificate_fingerprint(PEM).as_deref(), Ok(expected));
        let mut two = b"subject=CN = ca.exemple.test\n".to_vec();
        two.extend_from_slice(PEM);
        two.extend_from_slice(PEM);
        assert_eq!(certificate_fingerprint(&two).as_deref(), Ok(expected));
        assert_eq!(
            certificate_fingerprint(b"pas de certificat"),
            Err(FingerprintError::NoCertificate)
        );
        assert_eq!(
            certificate_fingerprint(b"-----BEGIN CERTIFICATE-----\n@@@\n-----END CERTIFICATE-----"),
            Err(FingerprintError::Unreadable)
        );
    }

    #[test]
    fn serialized_form_round_trip() {
        let mut p = Profile::new("lab.test");
        p.preferred_dc = Some("dc1.lab.test".into());
        p.mode = Mode::StartTls;
        p.ca = Some(PathBuf::from("/etc/ca.pem"));
        p.read_only = false;
        p.cache = false;
        p.smb2_signing = true;
        let fields = p.to_fields();
        assert_eq!(
            fields.keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "ca",
                "cache",
                "dc-prefere",
                "domaine",
                "lecture-seule",
                "mode",
                "smb2-signature-seule"
            ]
        );
        assert_eq!(Profile::from_fields(&fields), Ok(p));
        // As `profil_depuis_dict`: defaults, unknown keys, wrong types.
        let mut minimal = BTreeMap::new();
        minimal.insert("domaine".to_owned(), Field::Text("lab.test".into()));
        minimal.insert("futur".to_owned(), Field::Bool(true));
        assert_eq!(Profile::from_fields(&minimal), Ok(Profile::new("lab.test")));
        minimal.insert("cache".to_owned(), Field::Text("oui".into()));
        assert_eq!(
            Profile::from_fields(&minimal),
            Err(ProfileError::NotBool("cache".into()))
        );
        assert_eq!(
            Profile::from_fields(&BTreeMap::new()),
            Err(ProfileError::NoDomain)
        );
    }
}

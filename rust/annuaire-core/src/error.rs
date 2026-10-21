// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! LDAP errors and their categories.
//!
//! An [`LdapError`] has the shape of a python-ldap exception: a result code (the LDAP result
//! code from the server, or a negative code of the OpenLDAP API for local failures), the
//! OpenLDAP description of that code, and the text the server or the local library gave.
//! [`categorize`] sorts it the way `annuaire.core.erreurs.traduire` does, which decides what
//! the caller can do: try another DC, ask for a ticket, review the profile, or just show it.
//! The Python module turns an `LdapError` into the python-ldap exception of the same code,
//! so that `traduire` and its messages apply unchanged (ADR 0016, § 4 and 6).

use std::any::Any;
use std::fmt;
use std::sync::Arc;

/// Codes of the OpenLDAP client API (negative) and LDAP result codes (RFC 4511, 4.1.9).
pub mod code {
    pub const SERVER_DOWN: i32 = -1;
    pub const LOCAL_ERROR: i32 = -2;
    pub const ENCODING_ERROR: i32 = -3;
    pub const DECODING_ERROR: i32 = -4;
    pub const TIMEOUT: i32 = -5;
    pub const FILTER_ERROR: i32 = -7;
    pub const PARAM_ERROR: i32 = -9;
    pub const CONNECT_ERROR: i32 = -11;

    pub const SUCCESS: i32 = 0;
    pub const OPERATIONS_ERROR: i32 = 1;
    pub const PROTOCOL_ERROR: i32 = 2;
    pub const TIMELIMIT_EXCEEDED: i32 = 3;
    pub const SIZELIMIT_EXCEEDED: i32 = 4;
    pub const STRONG_AUTH_REQUIRED: i32 = 8;
    pub const REFERRAL: i32 = 10;
    pub const NO_SUCH_ATTRIBUTE: i32 = 16;
    pub const CONSTRAINT_VIOLATION: i32 = 19;
    pub const TYPE_OR_VALUE_EXISTS: i32 = 20;
    pub const INVALID_SYNTAX: i32 = 21;
    pub const NO_SUCH_OBJECT: i32 = 32;
    pub const INVALID_CREDENTIALS: i32 = 49;
    pub const INSUFFICIENT_ACCESS: i32 = 50;
    pub const BUSY: i32 = 51;
    pub const UNAVAILABLE: i32 = 52;
    pub const UNWILLING_TO_PERFORM: i32 = 53;
    pub const NAMING_VIOLATION: i32 = 64;
    pub const OBJECT_CLASS_VIOLATION: i32 = 65;
    pub const NOT_ALLOWED_ON_NONLEAF: i32 = 66;
    pub const ALREADY_EXISTS: i32 = 68;
    pub const OTHER: i32 = 80;
}

/// `ldap_err2string` of OpenLDAP 2.6: the `desc` of a python-ldap exception.
pub fn description(code: i32) -> &'static str {
    match code {
        -18 => "Connecting (X)",
        -17 => "Referral Limit Exceeded",
        -16 => "Client Loop",
        -15 => "More results to return",
        -14 => "No results returned",
        -13 => "Control not found",
        -12 => "Not Supported",
        -11 => "Connect error",
        -10 => "Out of memory",
        -9 => "Bad parameter to an ldap routine",
        -8 => "User cancelled operation",
        -7 => "Bad search filter",
        -6 => "Unknown authentication method",
        -5 => "Timed out",
        -4 => "Decoding error",
        -3 => "Encoding error",
        -2 => "Local error",
        -1 => "Can't contact LDAP server",
        0 => "Success",
        1 => "Operations error",
        2 => "Protocol error",
        3 => "Time limit exceeded",
        4 => "Size limit exceeded",
        5 => "Compare False",
        6 => "Compare True",
        7 => "Authentication method not supported",
        8 => "Strong(er) authentication required",
        9 => "Partial results and referral received",
        10 => "Referral",
        11 => "Administrative limit exceeded",
        12 => "Critical extension is unavailable",
        13 => "Confidentiality required",
        14 => "SASL bind in progress",
        16 => "No such attribute",
        17 => "Undefined attribute type",
        18 => "Inappropriate matching",
        19 => "Constraint violation",
        20 => "Type or value exists",
        21 => "Invalid syntax",
        32 => "No such object",
        33 => "Alias problem",
        34 => "Invalid DN syntax",
        35 => "Entry is a leaf",
        36 => "Alias dereferencing problem",
        47 => "Proxy Authorization Failure (X)",
        48 => "Inappropriate authentication",
        49 => "Invalid credentials",
        50 => "Insufficient access",
        51 => "Server is busy",
        52 => "Server is unavailable",
        53 => "Server is unwilling to perform",
        54 => "Loop detected",
        64 => "Naming violation",
        65 => "Object class violation",
        66 => "Operation not allowed on non-leaf",
        67 => "Operation not allowed on RDN",
        68 => "Already exists",
        69 => "Cannot modify object class",
        70 => "Results too large",
        71 => "Operation affects multiple DSAs",
        76 => "Virtual List View error",
        80 => "Other (e.g., implementation specific) error",
        113 => "LCUP Resources Exhausted",
        114 => "LCUP Security Violation",
        115 => "LCUP Invalid Data",
        116 => "LCUP Unsupported Scheme",
        117 => "LCUP Reload Required",
        118 => "Cancelled",
        119 => "No Operation to Cancel",
        120 => "Too Late to Cancel",
        121 => "Cannot Cancel",
        122 => "Assertion Failed",
        4096 => "Content Sync Refresh Required",
        16640 => "Content Sync Refresh Required (X)",
        c if (-20..=-1).contains(&c) => "Unknown API error",
        c if (0..=122).contains(&c) => "Unknown error",
        c if (16641..=16644).contains(&c) => "Unknown (private extension) error",
        _ => "Unknown (extension) error",
    }
}

/// Opaque value kept with an error that came from elsewhere (the Python module keeps the
/// original exception, raised again unchanged).
pub type Origin = Arc<dyn Any + Send + Sync>;

/// An LDAP error, as python-ldap would raise it.
#[derive(Clone)]
pub struct LdapError {
    /// Result code: LDAP result code, or negative code of the client API.
    pub code: i32,
    /// Text of the server (`diagnosticMessage`) or of the local library.
    pub info: String,
    /// `matchedDN` of the server, if any.
    pub matched: String,
    /// Where the error came from when it was not produced here.
    pub origin: Option<Origin>,
    /// Not an LDAP error at all (an exception of a test double, for instance): never
    /// categorized as unreachable, always handed back as it is.
    pub foreign: bool,
}

impl LdapError {
    pub fn new(code: i32, info: impl Into<String>) -> Self {
        Self {
            code,
            info: info.into(),
            matched: String::new(),
            origin: None,
            foreign: false,
        }
    }

    /// The server is not reachable, or the connection dropped.
    pub fn server_down(info: impl Into<String>) -> Self {
        Self::new(code::SERVER_DOWN, info)
    }

    /// No answer within the operation timeout.
    pub fn timeout() -> Self {
        Self::new(code::TIMEOUT, "")
    }

    /// A GSSAPI failure, worded like cyrus-sasl so that the same fragments are found in it.
    pub fn gssapi(message: &str) -> Self {
        Self::new(
            code::LOCAL_ERROR,
            format!("SASL(-1): generic failure: GSSAPI Error: {message}"),
        )
    }

    /// OpenLDAP description of the code.
    pub fn desc(&self) -> &'static str {
        description(self.code)
    }

    /// `desc : info` as `traduire` builds the detail shown to the user.
    pub fn detail(&self) -> String {
        if self.info.is_empty() {
            self.desc().to_owned()
        } else {
            format!("{} : {}", self.desc(), self.info)
        }
    }
}

impl fmt::Debug for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LdapError")
            .field("code", &self.code)
            .field("info", &self.info)
            .field("matched", &self.matched)
            .field("origin", &self.origin.is_some())
            .field("foreign", &self.foreign)
            .finish()
    }
}

impl PartialEq for LdapError {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
            && self.info == other.info
            && self.matched == other.matched
            && self.foreign == other.foreign
    }
}

impl fmt::Display for LdapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.detail())
    }
}

impl std::error::Error for LdapError {}

/// What an error means for the caller; same order of tests as `erreurs.traduire`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    /// No valid Kerberos ticket: get one (`ErreurTicket`).
    Ticket,
    /// TLS channel binding refused by the DC (`ErreurSecurite`).
    ChannelBinding,
    /// The DC demands another protection level (`ErreurSecurite`).
    StrongerAuth,
    /// No encrypted connection could be negotiated (`ErreurSecurite`).
    TooWeak,
    /// Kerberos does not know the LDAP service of the DC (`ErreurKerberos`).
    UnknownService,
    /// Clocks too far apart (`ErreurKerberos`).
    ClockSkew,
    /// Certificate of the DC not verified (`ErreurSecurite`).
    Certificate,
    /// DC silent or connection lost: another DC may do (`ErreurInjoignable`).
    Unreachable,
    /// Operation timeout: the connection is dropped (`ErreurDelai`).
    Timeout,
    /// DC busy or unavailable (`ErreurInjoignable`).
    Unavailable,
    /// Other Kerberos failure (`ErreurKerberos`).
    Kerberos,
    /// Any other result: shown with its code (`ErreurLDAP`).
    Ldap,
}

impl Category {
    /// The DC may be replaced by another: the connection fails over.
    pub fn unreachable(self) -> bool {
        matches!(self, Self::Unreachable | Self::Unavailable)
    }
}

/// Fragments (lower case) of MIT krb5 and cyrus-sasl messages meaning "no ticket".
const NO_TICKET: [&str; 6] = [
    "no kerberos credentials",
    "no credentials cache",
    "credentials cache file",
    "ticket expired",
    "matching credential not found",
    "no credentials were supplied",
];

/// Category of an error, as `erreurs.traduire` would choose its class.
pub fn categorize(error: &LdapError) -> Category {
    if error.foreign {
        return Category::Ldap;
    }
    let info = error.info.to_lowercase();
    let has = |fragment: &str| info.contains(fragment);
    let c = error.code;
    if NO_TICKET.iter().any(|f| has(f)) {
        return Category::Ticket;
    }
    if has("data 35b") || has("80090346") {
        return Category::ChannelBinding;
    }
    if c == code::STRONG_AUTH_REQUIRED || has("sign or seal") {
        return Category::StrongerAuth;
    }
    if has("too weak") || has("ssf") {
        return Category::TooWeak;
    }
    if has("server not found in kerberos database") {
        return Category::UnknownService;
    }
    if has("clock skew") {
        return Category::ClockSkew;
    }
    if c == code::SERVER_DOWN || c == code::CONNECT_ERROR {
        if has("certificate") || has("cert ") || has("tls") {
            return Category::Certificate;
        }
        return Category::Unreachable;
    }
    if c == code::TIMEOUT || c == code::TIMELIMIT_EXCEEDED {
        return Category::Timeout;
    }
    if c == code::UNAVAILABLE || c == code::BUSY {
        return Category::Unavailable;
    }
    if (c == code::LOCAL_ERROR || c == code::OTHER || c == code::INVALID_CREDENTIALS)
        && (has("gssapi") || has("kerberos") || has("sasl"))
    {
        return Category::Kerberos;
    }
    Category::Ldap
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat(code: i32, info: &str) -> Category {
        categorize(&LdapError::new(code, info))
    }

    #[test]
    fn descriptions() {
        assert_eq!(description(-1), "Can't contact LDAP server");
        assert_eq!(description(32), "No such object");
        assert_eq!(description(25), "Unknown error");
        assert_eq!(description(-19), "Unknown API error");
        assert_eq!(description(9999), "Unknown (extension) error");
        assert_eq!(
            LdapError::new(32, "0000208D: NameErr").detail(),
            "No such object : 0000208D: NameErr"
        );
        assert_eq!(LdapError::timeout().detail(), "Timed out");
    }

    #[test]
    fn categories() {
        let gss = |m: &str| categorize(&LdapError::gssapi(m));
        assert_eq!(
            gss("No Kerberos credentials available (default cache: FILE:/x)"),
            Category::Ticket
        );
        assert_eq!(gss("Ticket expired"), Category::Ticket);
        assert_eq!(
            gss(
                "Unspecified GSS failure.  Minor code may provide more information (Server not found in Kerberos database)"
            ),
            Category::UnknownService
        );
        assert_eq!(gss("Clock skew too great"), Category::ClockSkew);
        assert_eq!(gss("Decrypt integrity check failed"), Category::Kerberos);
        assert_eq!(
            cat(49, "80090346: LdapErr: DSID-0C09056D, data 35b"),
            Category::ChannelBinding
        );
        assert_eq!(cat(8, ""), Category::StrongerAuth);
        assert_eq!(cat(-2, "SASL(-15): mechanism too weak"), Category::TooWeak);
        assert_eq!(cat(-1, ""), Category::Unreachable);
        assert_eq!(cat(-11, "certificate verify failed"), Category::Certificate);
        assert_eq!(cat(-5, ""), Category::Timeout);
        assert_eq!(cat(3, ""), Category::Timeout);
        assert_eq!(cat(51, ""), Category::Unavailable);
        assert!(Category::Unavailable.unreachable());
        assert_eq!(cat(32, ""), Category::Ldap);
        assert_eq!(cat(-2, "out of memory"), Category::Ldap);
        let mut foreign = LdapError::server_down("");
        foreign.foreign = true;
        assert_eq!(categorize(&foreign), Category::Ldap);
    }
}

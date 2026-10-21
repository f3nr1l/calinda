// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! « Security » tab (J4.2, `annuaire.vue.securite`, reading part), without GTK: the rights
//! in clear. An ACE reads as one sentence: who, can or cannot, what, on what. « Support
//! informatique peut réinitialiser le mot de passe pour les objets Utilisateur de cette
//! OU. » The names come, in order: from the directory (object that carries the SID, name of
//! the schema or of `CN=Extended-Rights`), from tables for what is well known (well-known
//! SIDs, usual extended rights and property sets, common classes), otherwise from the raw
//! SID or GUID.
//!
//! `sections` groups the ACEs into readable rights, denials first: recognised delegations
//! (templates of the wizard), other explicit permissions, then inherited ones, sorted by
//! origin. `ace_lines` gives the detail ACE by ACE with its SDDL. The delegation wizard and
//! the entries typed in SDDL are read here (`delegation_preview`, `ace_input`).

use std::collections::HashMap;

use annuaire_codecs::condition::{self, Node, ResourceValue};
use annuaire_codecs::sd::{self, Ace, SecurityDescriptor};
use annuaire_codecs::{Guid, Sid, sddl};
use annuaire_core::changes::dn_key;
use annuaire_core::security::{
    self as s, GuidName, Kind, Nomenclature, SecurityReading, SidName, Template,
};
use annuaire_core::source::name_from_dn;

use crate::codec_texts::codec_message;
use crate::i18n::{fill, tr};

type Names = HashMap<Sid, SidName>;

/// Well-known SIDs, without an object in the directory or named there in English
/// (`SID_CONNUS`).
pub(crate) fn known_sid(text: &str) -> Option<String> {
    Some(match text {
        "S-1-1-0" => tr("Everyone"),
        "S-1-3-0" => tr("Creator Owner"),
        "S-1-3-1" => tr("Creator Group"),
        "S-1-3-4" => tr("Owner Rights"),
        "S-1-5-2" => tr("Network"),
        "S-1-5-4" => tr("Interactive"),
        "S-1-5-6" => tr("SERVICE"),
        "S-1-5-7" => tr("Anonymous Logon"),
        "S-1-5-9" => tr("Enterprise Domain Controllers"),
        "S-1-5-10" => tr("Self"),
        "S-1-5-11" => tr("Authenticated Users"),
        "S-1-5-12" => tr("Restricted"),
        "S-1-5-18" => tr("SYSTEM"),
        "S-1-5-19" => tr("Local Service"),
        "S-1-5-20" => tr("Network Service"),
        "S-1-5-32-544" => tr("Administrators"),
        "S-1-5-32-545" => tr("Users"),
        "S-1-5-32-546" => tr("Guests"),
        "S-1-5-32-548" => tr("Account Operators"),
        "S-1-5-32-549" => tr("Server Operators"),
        "S-1-5-32-550" => tr("Print Operators"),
        "S-1-5-32-551" => tr("Backup Operators"),
        "S-1-5-32-552" => tr("Replicator"),
        "S-1-5-32-554" => tr("Pre-Windows 2000 Compatible Access"),
        "S-1-5-32-555" => tr("Remote Desktop Users"),
        "S-1-5-32-556" => tr("Network Configuration Operators"),
        "S-1-5-32-557" => tr("Incoming Forest Trust Builders"),
        "S-1-5-32-558" => tr("Performance Monitor Users"),
        "S-1-5-32-559" => tr("Performance Log Users"),
        "S-1-5-32-560" => tr("Windows Authorization Access Group"),
        "S-1-5-32-561" => tr("Terminal Server License Servers"),
        "S-1-5-32-562" => tr("Distributed COM Users"),
        "S-1-5-32-568" => tr("IIS_IUSRS"),
        "S-1-5-32-569" => tr("Cryptographic Operators"),
        "S-1-5-32-573" => tr("Event Log Readers"),
        "S-1-5-32-574" => tr("Certificate Service DCOM Access"),
        _ => return None,
    })
}

/// Accounts and groups of the domain whose RID is fixed (MS-DTYP 2.4.2.4) (`RID_CONNUS`).
fn known_rid(rid: u32) -> Option<String> {
    Some(match rid {
        498 => tr("Enterprise Read-only Domain Controllers"),
        500 => tr("Administrator"),
        501 => tr("Guest"),
        502 => tr("krbtgt"),
        512 => tr("Domain Admins"),
        513 => tr("Domain Users"),
        514 => tr("Domain Guests"),
        515 => tr("Domain Computers"),
        516 => tr("Domain controllers"),
        517 => tr("Cert Publishers"),
        518 => tr("Schema Admins"),
        519 => tr("Enterprise Admins"),
        520 => tr("Group Policy Creator Owners"),
        521 => tr("Read-only Domain Controllers"),
        522 => tr("Cloneable Domain Controllers"),
        525 => tr("Protected Users"),
        526 => tr("Key Admins"),
        527 => tr("Enterprise Key Admins"),
        553 => tr("RAS and IAS Servers"),
        _ => return None,
    })
}

/// Extended rights and validated writes by `cn` (the `displayName` is in English)
/// (`DROITS_ETENDUS`).
fn extended_right(cn: &str) -> Option<String> {
    Some(match cn {
        "User-Force-Change-Password" => tr("reset the password"),
        "User-Change-Password" => tr("change the password"),
        "Send-As" => tr("send as"),
        "Receive-As" => tr("receive as"),
        "Allowed-To-Authenticate" => tr("authenticate to the object"),
        "Apply-Group-Policy" => tr("apply group policy"),
        "Generate-RSoP-Planning" => tr("generate resultant set of policy (planning)"),
        "Generate-RSoP-Logging" => tr("generate resultant set of policy (logging)"),
        "DS-Replication-Get-Changes" => tr("replicate directory changes"),
        "DS-Replication-Get-Changes-All" => tr("replicate all directory changes, secrets included"),
        "DS-Replication-Get-Changes-In-Filtered-Set" => {
            tr("replicate directory changes in the filtered set")
        }
        "DS-Replication-Manage-Topology" => tr("manage the replication topology"),
        "DS-Replication-Synchronize" => tr("synchronize replication"),
        "DS-Replication-Monitor-Topology" => tr("monitor the replication topology"),
        "DS-Install-Replica" => tr("add a domain controller"),
        "Unexpire-Password" => tr("unexpire a password"),
        "Enable-Per-User-Reversibly-Encrypted-Password" => {
            tr("enable reversibly encrypted password")
        }
        "Update-Password-Not-Required-Bit" => tr("update the “password not required” option"),
        "Change-PDC" => tr("transfer the PDC emulator role"),
        "Change-Rid-Master" => tr("transfer the RID master role"),
        "Change-Infrastructure-Master" => tr("transfer the infrastructure master role"),
        "Change-Schema-Master" => tr("transfer the schema master role"),
        "Change-Domain-Master" => tr("transfer the domain naming master role"),
        "Self-Membership" => tr("add or remove themselves as a member"),
        "Validated-DNS-Host-Name" => tr("write the DNS host name (validated write)"),
        "Validated-SPN" => tr("write the service principal names (validated write)"),
        "Validated-MS-DS-Additional-DNS-Host-Name" => {
            tr("write the additional DNS host names (validated write)")
        }
        "Validated-MS-DS-Behavior-Version" => tr("write the behavior version (validated write)"),
        "DS-Validated-Write-Computer" => tr("write the computer attributes (validated write)"),
        _ => return None,
    })
}

/// Property sets by `cn` (`ENSEMBLES`).
fn property_set(cn: &str) -> Option<String> {
    Some(match cn {
        "User-Account-Restrictions" => tr("Account Restrictions"),
        "User-Logon" => tr("Logon Information"),
        "General-Information" => tr("General Information"),
        "Personal-Information" => tr("Personal Information"),
        "Public-Information" => tr("Public Information"),
        "Private-Information" => tr("Private Information"),
        "Web-Information" => tr("Web Information"),
        "Email-Information" => tr("Phone and Mail Options"),
        "Membership" => tr("Group Membership"),
        "RAS-Information" => tr("Remote Access Information"),
        "DNS-Host-Name-Attributes" => tr("DNS Host Name Attributes"),
        "Domain-Password" => tr("Domain Password & Lockout Policies"),
        "Domain-Other-Parameters" => tr("Other Domain Parameters"),
        "Terminal-Server-License-Server" => tr("Terminal Server License Server"),
        _ => return None,
    })
}

/// Common classes; the others keep their `lDAPDisplayName` (`CLASSES`, `nom_classe`).
pub fn class_name(name: &str) -> String {
    match name {
        "user" => tr("User"),
        "group" => tr("Group"),
        "computer" => tr("Computer"),
        "contact" => tr("Contact"),
        "organizationalUnit" => tr("Organizational unit"),
        "container" => tr("Container"),
        "domainDNS" => tr("Domain"),
        "inetOrgPerson" => tr("inetOrgPerson"),
        "printQueue" => tr("Printer"),
        "groupPolicyContainer" => tr("Group Policy"),
        "msDS-ManagedServiceAccount" => tr("Managed Service Account"),
        "msDS-GroupManagedServiceAccount" => tr("Group Managed Service Account"),
        "msTPM-InformationObject" => tr("TPM Information"),
        "dnsNode" => tr("DNS node"),
        "dnsZone" => tr("DNS zone"),
        "site" => tr("Site"),
        "subnet" => tr("Subnet"),
        _ => name.to_owned(),
    }
}

// Rights without a GUID, in the order they are said.
fn simple_actions() -> [(u32, String); 8] {
    [
        (sd::ADS_RIGHT_ACTRL_DS_LIST, tr("list contents")),
        (sd::ADS_RIGHT_DS_LIST_OBJECT, tr("list the object")),
        (sd::READ_CONTROL, tr("read permissions")),
        (sd::WRITE_DAC, tr("modify permissions")),
        (sd::WRITE_OWNER, tr("change the owner")),
        (sd::DELETE, tr("delete the object")),
        (sd::ADS_RIGHT_DS_DELETE_TREE, tr("delete the subtree")),
        (
            sd::ACCESS_SYSTEM_SECURITY,
            tr("read and modify auditing (SACL)"),
        ),
    ]
}

const CC_DC: u32 = sd::ADS_RIGHT_DS_CREATE_CHILD | sd::ADS_RIGHT_DS_DELETE_CHILD;
const RP_WP: u32 = sd::ADS_RIGHT_DS_READ_PROP | sd::ADS_RIGHT_DS_WRITE_PROP;
const SW_CR: u32 = sd::ADS_RIGHT_DS_SELF | sd::ADS_RIGHT_DS_CONTROL_ACCESS;
const COVERED: u32 = CC_DC
    | RP_WP
    | sd::ADS_RIGHT_DS_SELF
    | sd::ADS_RIGHT_DS_CONTROL_ACCESS
    | sd::ADS_RIGHT_ACTRL_DS_LIST
    | sd::ADS_RIGHT_DS_LIST_OBJECT
    | sd::READ_CONTROL
    | sd::WRITE_DAC
    | sd::WRITE_OWNER
    | sd::DELETE
    | sd::ADS_RIGHT_DS_DELETE_TREE
    | sd::ACCESS_SYSTEM_SECURITY;

// --- Names --------------------------------------------------------------------------------

/// Name of a SID: the one of the object that carries it in the directory (as in the tree),
/// else the name of a well-known SID, else the SID. A foreign principal carries its SID as
/// name: it does not count (`nom_sid`).
pub fn sid_name(sid: &Sid, names: Option<&Names>) -> String {
    let text = sid.to_string();
    if let Some(found) = names.and_then(|n| n.get(sid))
        && !found.name.is_empty()
        && found.name != text
    {
        return found.name.clone();
    }
    if let Some(name) = known_sid(&text) {
        return name;
    }
    if let Some(name) = sid.rid().and_then(known_rid) {
        return name;
    }
    text
}

/// Without a nomenclature, or when the DC does not know them: a few GUIDs (`_GUID_CONNUS`).
fn known_guid(guid: &Guid) -> Option<GuidName> {
    let known = [
        (s::class_user(), GuidName::new("user", Kind::Class, "")),
        (s::class_group(), GuidName::new("group", Kind::Class, "")),
        (
            s::class_computer(),
            GuidName::new("computer", Kind::Class, ""),
        ),
        (
            s::class_ou(),
            GuidName::new("organizationalUnit", Kind::Class, ""),
        ),
        (
            s::class_inetorgperson(),
            GuidName::new("inetOrgPerson", Kind::Class, ""),
        ),
        (
            s::attribute_pwdlastset(),
            GuidName::new("pwdLastSet", Kind::Attribute, ""),
        ),
        (
            s::attribute_member(),
            GuidName::new("member", Kind::Attribute, ""),
        ),
        (
            s::right_reset_password(),
            GuidName::new(
                "Reset Password",
                Kind::ExtendedRight,
                "User-Force-Change-Password",
            ),
        ),
        (
            s::write_spn(),
            GuidName::new(
                "Validated write to SPN",
                Kind::ValidatedWrite,
                "Validated-SPN",
            ),
        ),
        (
            s::set_account_restrictions(),
            GuidName::new(
                "Account Restrictions",
                Kind::PropertySet,
                "User-Account-Restrictions",
            ),
        ),
        (
            "9b026da6-0d3c-465c-8bee-5199d7165cba"
                .parse()
                .unwrap_or(Guid::from_bytes([0; 16])),
            GuidName::new(
                "Validated write to computer attributes",
                Kind::ValidatedWrite,
                "DS-Validated-Write-Computer",
            ),
        ),
    ];
    known
        .into_iter()
        .find(|(g, _)| g == guid)
        .map(|(_, name)| name)
}

fn guid_name(guid: &Guid, mask: u32, nomenclature: Option<&Nomenclature>) -> Option<GuidName> {
    let found = nomenclature.and_then(|n| n.name(Some(guid), mask)).cloned();
    if let Some(known) = known_guid(guid)
        && (found.is_none()
            || found
                .as_ref()
                .is_some_and(|f| f.cn.is_empty() && !known.cn.is_empty() && mask & SW_CR != 0))
    {
        return Some(known);
    }
    if *guid == s::write_dns_name() && found.is_none() {
        if mask & sd::ADS_RIGHT_DS_SELF != 0 {
            return Some(GuidName::new(
                "",
                Kind::ValidatedWrite,
                "Validated-DNS-Host-Name",
            ));
        }
        return Some(GuidName::new("dNSHostName", Kind::Attribute, ""));
    }
    found
}

fn class_of(guid: Option<&Guid>, nomenclature: Option<&Nomenclature>) -> String {
    let Some(guid) = guid else {
        return String::new();
    };
    match guid_name(guid, CC_DC, nomenclature) {
        Some(found) if found.kind == Kind::Class => class_name(&found.name),
        _ => guid.to_string(),
    }
}

/// A right said in clear: a head (« read the properties ») and what it aims at; two facts of
/// the same head are said together (`_Fait`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fact {
    head: String,
    head_plural: String,
    element: String,
}

impl Fact {
    fn new(head: String) -> Self {
        Self {
            head,
            head_plural: String::new(),
            element: String::new(),
        }
    }

    fn with(head: String, head_plural: String, element: String) -> Self {
        Self {
            head,
            head_plural,
            element,
        }
    }
}

impl std::fmt::Display for Fact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.element.is_empty() {
            write!(f, "{}", self.head)
        } else {
            write!(f, "{} {}", self.head, self.element)
        }
    }
}

fn quoted(name: &str) -> String {
    fill(&tr("“{nom}”"), &[("nom", name)])
}

fn property_facts(guid: Option<&Guid>, rp_wp: u32, nomenclature: Option<&Nomenclature>) -> Fact {
    let verb = match rp_wp {
        RP_WP => tr("read and write"),
        sd::ADS_RIGHT_DS_READ_PROP => tr("read"),
        _ => tr("write"),
    };
    let Some(guid) = guid else {
        return Fact::new(fill(&tr("{verbe} all properties"), &[("verbe", &verb)]));
    };
    let found = guid_name(guid, rp_wp, nomenclature);
    if let Some(found) = found.as_ref().filter(|f| f.kind == Kind::PropertySet) {
        let name = property_set(&found.cn).unwrap_or_else(|| found.name.clone());
        let head = fill(&tr("{verbe} the properties in"), &[("verbe", &verb)]);
        return Fact::with(head.clone(), head, quoted(&name));
    }
    let name = found.map_or_else(|| guid.to_string(), |f| f.name);
    Fact::with(
        fill(&tr("{verbe} the attribute"), &[("verbe", &verb)]),
        fill(&tr("{verbe} the attributes"), &[("verbe", &verb)]),
        name,
    )
}

/// An extended right (CR) or a validated write (SW) named by their GUID (`_fait_droit`).
fn right_fact(guid: &Guid, right: u32, nomenclature: Option<&Nomenclature>) -> Fact {
    let found = guid_name(guid, right, nomenclature);
    if let Some(text) = found.as_ref().and_then(|f| extended_right(&f.cn)) {
        return Fact::new(text);
    }
    if let (Some(found), sd::ADS_RIGHT_DS_CONTROL_ACCESS) = (found.as_ref(), right) {
        if found.kind == Kind::PropertySet {
            let name = property_set(&found.cn).unwrap_or_else(|| found.name.clone());
            let head = tr("access the confidential properties");
            return Fact::with(head.clone(), head, quoted(&name));
        }
        if found.kind == Kind::Attribute {
            return Fact::with(
                tr("access the confidential attribute"),
                tr("access the confidential attributes"),
                found.name.clone(),
            );
        }
    }
    let name = found.map_or_else(|| guid.to_string(), |f| f.name);
    if right == sd::ADS_RIGHT_DS_SELF {
        return Fact::with(
            tr("perform the validated write"),
            tr("perform the validated writes"),
            name,
        );
    }
    Fact::with(
        tr("exercise the right"),
        tr("exercise the rights"),
        quoted(&name),
    )
}

fn facts(ace: &Ace, nomenclature: Option<&Nomenclature>) -> Vec<Fact> {
    let mask = sd::translate_generic(ace.mask());
    let guid = ace.object_type();
    let mut out = Vec::new();
    let cc_dc = mask & CC_DC;
    if cc_dc != 0 {
        let verb = match cc_dc {
            CC_DC => tr("create and delete"),
            sd::ADS_RIGHT_DS_CREATE_CHILD => tr("create"),
            _ => tr("delete"),
        };
        if guid.is_some() {
            let head = fill(&tr("{verbe} objects of class"), &[("verbe", &verb)]);
            out.push(Fact::with(
                head.clone(),
                head,
                class_of(guid.as_ref(), nomenclature),
            ));
        } else {
            out.push(Fact::new(fill(
                &tr("{verbe} child objects of any type"),
                &[("verbe", &verb)],
            )));
        }
    }
    if mask & RP_WP != 0 {
        out.push(property_facts(guid.as_ref(), mask & RP_WP, nomenclature));
    }
    for (right, without_guid) in [
        (sd::ADS_RIGHT_DS_SELF, tr("perform all validated writes")),
        (
            sd::ADS_RIGHT_DS_CONTROL_ACCESS,
            tr("exercise all extended rights"),
        ),
    ] {
        if mask & right != 0 {
            out.push(match &guid {
                Some(guid) => right_fact(guid, right, nomenclature),
                None => Fact::new(without_guid),
            });
        }
    }
    out.extend(
        simple_actions()
            .into_iter()
            .filter(|(bit, _)| mask & bit != 0)
            .map(|(_, name)| Fact::new(name)),
    );
    let rest = mask & !COVERED;
    if rest != 0 {
        out.push(Fact::new(fill(
            &tr("rights 0x{masque:x}"),
            &[("masque:x", &format!("{rest:x}"))],
        )));
    }
    out
}

fn list(elements: &[String]) -> String {
    match elements {
        [] => String::new(),
        [one] => one.clone(),
        [start @ .., end] => fill(
            &tr("{debut} and {fin}"),
            &[("debut", &start.join(", ")), ("fin", end)],
        ),
    }
}

/// The facts as an enumeration, those of the same head together; in negation, « ni … ni … »
/// (`_dire`).
fn say(facts: &[Fact], negation: bool) -> String {
    let mut by_head: Vec<(String, Vec<&Fact>)> = Vec::new();
    for fact in facts {
        if fact.element.is_empty() {
            let key = fact.to_string();
            if !by_head.iter().any(|(k, _)| *k == key) {
                by_head.push((key, vec![fact]));
            }
        } else {
            let key = if fact.head_plural.is_empty() {
                fact.head.clone()
            } else {
                fact.head_plural.clone()
            };
            match by_head.iter_mut().find(|(k, _)| *k == key) {
                Some((_, group)) => group.push(fact),
                None => by_head.push((key, vec![fact])),
            }
        }
    }
    let pieces: Vec<String> = by_head
        .iter()
        .map(|(head, group)| {
            let mut elements: Vec<String> = Vec::new();
            for f in group.iter().filter(|f| !f.element.is_empty()) {
                if !elements.contains(&f.element) {
                    elements.push(f.element.clone());
                }
            }
            if elements.len() <= 1 {
                group.first().map(ToString::to_string).unwrap_or_default()
            } else {
                format!("{head} {}", list(&elements))
            }
        })
        .collect();
    if negation && pieces.len() > 1 {
        return pieces
            .iter()
            .map(|m| fill(&tr("{fait}"), &[("fait", m)]))
            .collect::<Vec<_>>()
            .join(", ");
    }
    list(&pieces)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Place {
    Domain,
    Ou,
    Container,
    Object,
}

fn place(classes: &[String]) -> Place {
    let lower: Vec<String> = classes.iter().map(|c| c.to_lowercase()).collect();
    let has = |c: &str| lower.iter().any(|l| l == c);
    if has("domaindns") {
        Place::Domain
    } else if has("organizationalunit") {
        Place::Ou
    } else if [
        "container",
        "builtindomain",
        "configuration",
        "dmd",
        "lostandfound",
    ]
    .iter()
    .any(|c| has(c))
    {
        Place::Container
    } else {
        Place::Object
    }
}

fn place_text(place: Place) -> String {
    match place {
        Place::Domain => tr("this domain"),
        Place::Ou => tr("this OU"),
        Place::Container => tr("this container"),
        Place::Object => tr("this object"),
    }
}

/// An object whose transmitted rights are shown too (OU, container, domain); unknown class:
/// shown too (`est_conteneur`).
pub fn is_container(classes: &[String]) -> bool {
    classes.is_empty() || place(classes) != Place::Object
}

/// What the ACE bears on, seen from the object that holds it. For an object that is not a
/// container, only the object counts: « on this object » (`portee`).
fn scope(ace: &Ace, classes: &[String], nomenclature: Option<&Nomenclature>) -> String {
    let where_ = place_text(place(classes));
    let creation = sd::translate_generic(ace.mask()) & !CC_DC == 0;
    let on = fill(
        &if creation {
            tr("in {lieu}")
        } else {
            tr("on {lieu}")
        },
        &[("lieu", &where_)],
    );
    if !is_container(classes) || !s::transmitted(ace) {
        return on;
    }
    let inherited = ace.inherited_object_type();
    let class = class_of(inherited.as_ref(), nomenclature);
    let children = ace.flags & sd::NO_PROPAGATE_INHERIT_ACE != 0;
    let here = ace.flags & sd::INHERIT_ONLY_ACE == 0
        && match (&inherited, nomenclature) {
            (None, _) | (_, None) => true,
            (Some(g), Some(n)) => n.class_guids(classes).contains(g),
        };
    if inherited.is_some() {
        let aimed = fill(
            &if children {
                tr("the {classe} objects placed directly in {lieu}")
            } else {
                tr("the {classe} objects of {lieu}")
            },
            &[("classe", &class), ("lieu", &where_)],
        );
        if here {
            return fill(
                &tr("{sur} and for {vise}"),
                &[("sur", &on), ("vise", &aimed)],
            );
        }
        return fill(&tr("for {vise}"), &[("vise", &aimed)]);
    }
    if !here {
        return fill(
            &if children {
                tr("on the objects placed directly in {lieu}")
            } else {
                tr("on the descendant objects of {lieu}")
            },
            &[("lieu", &where_)],
        );
    }
    fill(
        &if children {
            tr("{sur} and its direct children")
        } else {
            tr("{sur} and all its descendants")
        },
        &[("sur", &on)],
    )
}

// --- Conditional ACEs and resource attributes (reading) ------------------------------------

fn relation(code: u8) -> Option<String> {
    Some(match code {
        0x80 => tr("{a} equals {b}"),
        0x81 => tr("{a} does not equal {b}"),
        0x82 => tr("{a} < {b}"),
        0x83 => tr("{a} ≤ {b}"),
        0x84 => tr("{a} > {b}"),
        0x85 => tr("{a} ≥ {b}"),
        0x86 => tr("{a} contains {b}"),
        0x88 => tr("{a} contains any of {b}"),
        0x8E => tr("{a} does not contain {b}"),
        0x8F => tr("{a} contains none of {b}"),
        _ => return None,
    })
}

fn unary(code: u8) -> Option<String> {
    Some(match code {
        0x87 => tr("{a} is set"),
        0x8D => tr("{a} is not set"),
        0x89 => tr("the account is a member of {a}"),
        0x8A => tr("the device is a member of {a}"),
        0x8B => tr("the account is a member of any of {a}"),
        0x8C => tr("the device is a member of any of {a}"),
        0x90 => tr("the account is not a member of {a}"),
        0x91 => tr("the device is not a member of {a}"),
        0x92 => tr("the account is a member of none of {a}"),
        0x93 => tr("the device is a member of none of {a}"),
        _ => return None,
    })
}

fn attribute_scope(scope: u8) -> String {
    match scope {
        0xF9 => tr("the user attribute “{nom}”"),
        0xFA => tr("the resource attribute “{nom}”"),
        0xFB => tr("the device attribute “{nom}”"),
        _ => tr("the attribute “{nom}”"),
    }
}

fn clear(node: &Node, names: Option<&Names>, root: bool) -> String {
    match node {
        Node::Integer {
            value, sign, base, ..
        } => condition::integer_to_sddl(*value, *sign, *base).unwrap_or_else(|_| value.to_string()),
        Node::String(text) => fill(&tr("“{texte}”"), &[("texte", text)]),
        Node::Octets(octets) => annuaire_core::schema::hex(octets),
        Node::Sid(sid) => sid_name(sid, names),
        Node::Composite(elements) if elements.is_empty() => tr("(empty list)"),
        Node::Composite(elements) => list(
            &elements
                .iter()
                .map(|e| clear(e, names, false))
                .collect::<Vec<_>>(),
        ),
        Node::Attribute { scope, name } => fill(&attribute_scope(*scope), &[("nom", name)]),
        Node::Operation { code, operands } => match operands.as_slice() {
            [only] if *code == condition::NOT => {
                fill(&tr("not ({a})"), &[("a", &clear(only, names, true))])
            }
            [only] => unary(*code).map_or_else(
                || condition::node_to_sddl(node).unwrap_or_default(),
                |t| fill(&t, &[("a", &clear(only, names, false))]),
            ),
            [left, right] if *code == condition::AND || *code == condition::OR => {
                let template = if *code == condition::AND {
                    tr("{a} and {b}")
                } else {
                    tr("{a} or {b}")
                };
                let text = fill(
                    &template,
                    &[
                        ("a", &clear(left, names, false)),
                        ("b", &clear(right, names, false)),
                    ],
                );
                if root { text } else { format!("({text})") }
            }
            [left, right] => relation(*code).map_or_else(
                || condition::node_to_sddl(node).unwrap_or_default(),
                |t| {
                    fill(
                        &t,
                        &[
                            ("a", &clear(left, names, false)),
                            ("b", &clear(right, names, false)),
                        ],
                    )
                },
            ),
            _ => condition::node_to_sddl(node).unwrap_or_default(),
        },
    }
}

/// What tells apart two conditional ACEs otherwise alike (grouping).
fn raw_condition(ace: &Ace) -> Vec<u8> {
    if s::is_conditional(ace.ace_type) {
        ace.data().to_vec()
    } else {
        Vec::new()
    }
}

/// The condition of a callback ACE as a sentence; None for an ACE without condition, or if
/// it is unreadable (`condition_en_clair`).
fn condition_in_clear(ace: &Ace, names: Option<&Names>) -> Option<String> {
    if !s::is_conditional(ace.ace_type) || ace.ace_type == sd::SYSTEM_RESOURCE_ATTRIBUTE {
        return None;
    }
    condition::read_condition(ace.data())
        .ok()
        .map(|node| clear(&node, names, true))
}

/// An ACE `RA`: « Resource attribute “Project” (TS): “Alpha”, “Beta”. »
/// (`attribut_ressource_en_clair`).
fn resource_attribute_in_clear(ace: &Ace) -> String {
    let Ok(attribute) = condition::read_resource_attribute(ace.data()) else {
        return fill(
            &tr("Unreadable resource attribute ({n} bytes)."),
            &[("n", &ace.data().len().to_string())],
        );
    };
    let values: Vec<String> = attribute
        .values
        .iter()
        .map(|v| match v {
            ResourceValue::String(text) => fill(&tr("“{texte}”"), &[("texte", text)]),
            ResourceValue::Sid(sid) => sid_name(sid, None),
            other => condition::resource_value_to_sddl(&attribute, other),
        })
        .collect();
    let values = list(&values);
    fill(
        &tr("Resource attribute “{nom}” ({type}): {valeurs}."),
        &[
            ("nom", &attribute.name),
            ("type", &attribute.type_code()),
            (
                "valeurs",
                &if values.is_empty() {
                    tr("no value")
                } else {
                    values
                },
            ),
        ],
    )
}

// --- Sentences ----------------------------------------------------------------------------

/// A sentence for ACEs of the same kind, the same SID, the same scope and the same
/// condition (`phrase`).
fn sentence(
    who: &str,
    aces: &[&Ace],
    classes: &[String],
    nomenclature: Option<&Nomenclature>,
    names: Option<&Names>,
) -> String {
    let Some(first) = aces.first() else {
        return String::new();
    };
    if first.ace_type == sd::SYSTEM_RESOURCE_ATTRIBUTE {
        return resource_attribute_in_clear(first);
    }
    let text = plain_sentence(who, aces, classes, nomenclature);
    match condition_in_clear(first, names) {
        None => text,
        Some(condition) => fill(
            &tr("{phrase}, if {condition}."),
            &[
                ("phrase", text.trim_end_matches('.')),
                ("condition", &condition),
            ],
        ),
    }
}

fn plain_sentence(
    who: &str,
    aces: &[&Ace],
    classes: &[String],
    nomenclature: Option<&Nomenclature>,
) -> String {
    let Some(first) = aces.first() else {
        return String::new();
    };
    let deny = first.is_deny();
    let audit = !deny && !first.is_allow();
    let where_ = scope(first, classes, nomenclature);
    let without_guid = aces.iter().all(|a| a.object_type().is_none());
    let mask = aces
        .iter()
        .fold(0, |m, a| m | sd::translate_generic(a.mask()));
    let missing = sd::DS_FULL_CONTROL & !mask;
    let mut all: Vec<Fact> = Vec::new();
    for ace in aces {
        for fact in facts(ace, nomenclature) {
            if !all.contains(&fact) {
                all.push(fact);
            }
        }
    }
    let fields = |extra: &[(&str, &str)]| -> Vec<(String, String)> {
        let mut v = vec![
            ("qui".to_owned(), who.to_owned()),
            ("lieu".to_owned(), where_.clone()),
        ];
        v.extend(
            extra
                .iter()
                .map(|(k, x)| ((*k).to_owned(), (*x).to_owned())),
        );
        v
    };
    let say_with = |template: String, extra: &[(&str, &str)]| {
        let owned = fields(extra);
        let pairs: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        fill(&template, &pairs)
    };
    if audit {
        return say_with(
            tr("Auditing: {qui} — {faits}, {lieu}."),
            &[("faits", &say(&all, false))],
        );
    }
    if without_guid && missing == 0 {
        return say_with(
            if deny {
                tr("{qui} is denied full control {lieu}.")
            } else {
                tr("{qui} has full control {lieu}.")
            },
            &[],
        );
    }
    if without_guid && !deny && missing.count_ones() <= 3 && mask & !sd::DS_FULL_CONTROL == 0 {
        // Almost everything: what is missing is said (« except delete the subtree »).
        let absent = Ace::simple(sd::ACCESS_ALLOWED, missing, &sd::everyone(), 0)
            .map(|a| facts(&a, None))
            .unwrap_or_default();
        return say_with(
            tr("{qui} has full control {lieu}, except: {absents}."),
            &[("absents", &say(&absent, false))],
        );
    }
    if all.is_empty() {
        return say_with(tr("{qui}: no rights ({lieu})."), &[]);
    }
    if deny && all.len() > 1 {
        return say_with(
            tr("{qui} cannot do any of the following {lieu}: {faits}."),
            &[("faits", &say(&all, true))],
        );
    }
    if deny {
        return say_with(
            tr("{qui} cannot {faits} {lieu}."),
            &[("faits", &say(&all, false))],
        );
    }
    say_with(
        tr("{qui} can {faits} {lieu}."),
        &[("faits", &say(&all, false))],
    )
}

/// An ACE in clear; its raw form if it has no readable SID (`phrase_ace`).
pub fn ace_sentence(
    ace: &Ace,
    classes: &[String],
    nomenclature: Option<&Nomenclature>,
    names: Option<&Names>,
) -> String {
    match ace.sid() {
        None => fill(
            &tr("Entry of type {type} ({n} bytes), kept as is."),
            &[
                ("type", &ace.ace_type.to_string()),
                ("n", &(ace.body.len() + 4).to_string()),
            ],
        ),
        Some(sid) => sentence(&sid_name(&sid, names), &[ace], classes, nomenclature, names),
    }
}

pub fn ace_sddl(ace: &Ace, domain: Option<&Sid>) -> String {
    sddl::ace_to_sddl(ace, domain).unwrap_or_else(|_| {
        fill(
            &tr("(type {type}, no SDDL form)"),
            &[("type", &ace.ace_type.to_string())],
        )
    })
}

pub fn descriptor_sddl(descriptor: &SecurityDescriptor, domain: Option<&Sid>) -> String {
    sddl::sd_to_sddl(descriptor, domain).unwrap_or_else(|e| {
        fill(
            &tr("No SDDL form: {raison}"),
            &[("raison", &codec_message(&e.to_string()))],
        )
    })
}

// --- The tab ------------------------------------------------------------------------------

/// A row of the view in clear (`LigneDroit`). The ACEs, whether they can be removed and the
/// delegation serve the removal.
#[derive(Debug, Clone)]
pub struct RightLine {
    pub text: String,
    pub detail: String,
    pub aces: Vec<Ace>,
    /// Explicit and outside of the default descriptor of the class: removed from here.
    pub removable: bool,
    /// Title of the delegation template recognised, if any.
    pub delegation: String,
}

/// Which section (`SectionDroits.titre`): the interface has a list for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Deny,
    Delegations,
    Explicit,
    Inherited,
    Audit,
}

#[derive(Debug, Clone)]
pub struct RightsSection {
    pub section: Section,
    pub lines: Vec<RightLine>,
}

/// A row of the detail (`LigneAce`); the ACE and whether it can be removed serve the removal.
#[derive(Debug, Clone)]
pub struct AceLine {
    pub sddl: String,
    pub text: String,
    pub detail: String,
    pub ace: Ace,
    pub removable: bool,
}

pub fn template_title(template: Template) -> String {
    match template {
        Template::ResetPasswords => {
            tr("Reset user passwords and force password change at next logon")
        }
        Template::GroupMembers => tr("Modify the membership of a group"),
        Template::JoinComputers => {
            tr("Join computers to the domain (create and delete computer accounts)")
        }
        Template::ReadUsers => tr("Read all user information"),
        Template::ManageUsers => tr("Create, delete, and manage user accounts"),
    }
}

fn origin_text(ace: &Ace, reading: &SecurityReading) -> String {
    match s::origin(ace, &reading.ancestors) {
        None => tr("Inherited (origin not found)"),
        Some(found) => fill(
            &tr("Inherited from {nom} ({dn})"),
            &[("nom", &name_from_dn(&found.dn)), ("dn", &found.dn)],
        ),
    }
}

fn explicit_detail(ace: &Ace, defaults: &std::collections::HashSet<Ace>) -> String {
    if s::is_default(ace, defaults) {
        tr("Explicit, from the default security descriptor of the class")
    } else {
        tr("Explicit")
    }
}

/// The rights of the object in clear (`VueSecurite`).
#[derive(Debug, Clone)]
pub struct SecurityView {
    pub sections: Vec<RightsSection>,
    /// ACEs that do not apply to the object (inherit only, other class): shown in the detail
    /// only, and only for an object that is not a container.
    pub without_effect: usize,
}

/// The rights of the object in clear: denials, delegations, explicit permissions, inherited
/// permissions (sorted by origin, from the nearest to the farthest), auditing. For an object
/// that is not a container, only what applies to it (`sections`).
pub fn sections(reading: &SecurityReading, nomenclature: Option<&Nomenclature>) -> SecurityView {
    let descriptor = &reading.descriptor;
    let classes = &reading.classes;
    let container = is_container(classes);
    let class_guids = nomenclature
        .map(|n| n.class_guids(classes))
        .unwrap_or_default();
    let applies = |ace: &Ace| {
        if container {
            return true;
        }
        if ace.flags & sd::INHERIT_ONLY_ACE != 0 {
            return false;
        }
        ace.inherited_object_type()
            .is_none_or(|g| class_guids.is_empty() || class_guids.contains(&g))
    };
    let all: Vec<&Ace> = descriptor.dacl.iter().flat_map(|a| a.aces.iter()).collect();
    let aces: Vec<&Ace> = all.iter().copied().filter(|a| applies(a)).collect();
    let defaults = nomenclature
        .map(|n| s::default_aces(n, classes))
        .unwrap_or_default();
    let names = Some(&reading.names);
    let rank: HashMap<String, usize> = reading
        .ancestors
        .iter()
        .enumerate()
        .filter_map(|(i, x)| dn_key(&x.dn).ok().map(|k| (k, i)))
        .collect();
    let provenance = |ace: &Ace| {
        if ace.is_inherited() {
            origin_text(ace, reading)
        } else {
            explicit_detail(ace, &defaults)
        }
    };
    let by_origin = |ace: &Ace| match s::origin(ace, &reading.ancestors) {
        Some(found) => dn_key(&found.dn)
            .ok()
            .and_then(|k| rank.get(&k).copied())
            .unwrap_or(rank.len()),
        None => rank.len() + 1,
    };
    let group = |list: &[&Ace], audit: bool| -> Vec<RightLine> {
        type Key = (bool, Option<Sid>, String, String, Vec<u8>);
        let mut groups: Vec<(Key, Vec<&Ace>)> = Vec::new();
        for ace in list {
            let key = (
                ace.is_deny(),
                ace.sid(),
                scope(ace, classes, nomenclature),
                provenance(ace),
                raw_condition(ace),
            );
            match groups.iter_mut().find(|(k, _)| *k == key) {
                Some((_, members)) => members.push(ace),
                None => groups.push((key, vec![ace])),
            }
        }
        groups
            .into_iter()
            .map(|((_, sid, _, detail, _), members)| {
                let explicit = members.first().is_some_and(|a| !a.is_inherited())
                    && !members.iter().any(|a| s::is_default(a, &defaults));
                let text = match sid {
                    Some(sid) => sentence(
                        &sid_name(&sid, names),
                        &members,
                        classes,
                        nomenclature,
                        names,
                    ),
                    None => members
                        .first()
                        .map(|a| ace_sentence(a, &[], None, None))
                        .unwrap_or_default(),
                };
                RightLine {
                    text,
                    detail,
                    aces: members.into_iter().cloned().collect(),
                    removable: explicit && !audit,
                    delegation: String::new(),
                }
            })
            .collect()
    };
    let mut out = Vec::new();
    let mut denials: Vec<&Ace> = aces.iter().copied().filter(|a| a.is_deny()).collect();
    if !denials.is_empty() {
        denials.sort_by_key(|a| {
            (
                a.is_inherited(),
                if a.is_inherited() {
                    i64::try_from(by_origin(a)).unwrap_or(i64::MAX)
                } else {
                    -1
                },
            )
        });
        out.push(RightsSection {
            section: Section::Deny,
            lines: group(&denials, false),
        });
    }
    let found = s::delegations(descriptor);
    let in_delegations: Vec<&Ace> = found.iter().flat_map(|d| d.aces.iter()).collect();
    if !found.is_empty() {
        out.push(RightsSection {
            section: Section::Delegations,
            lines: found
                .iter()
                .map(|d| {
                    let title = template_title(d.template);
                    RightLine {
                        text: fill(
                            &tr("{qui}: {tache}."),
                            &[("qui", &sid_name(&d.sid, names)), ("tache", &title)],
                        ),
                        detail: fill(
                            &tr("Delegation of Control Wizard template ({reference})"),
                            &[("reference", d.template.reference())],
                        ),
                        aces: d.aces.clone(),
                        removable: true,
                        delegation: title,
                    }
                })
                .collect(),
        });
    }
    let explicit: Vec<&Ace> = aces
        .iter()
        .copied()
        .filter(|a| !a.is_inherited() && !a.is_deny() && !in_delegations.contains(a))
        .collect();
    if !explicit.is_empty() {
        out.push(RightsSection {
            section: Section::Explicit,
            lines: group(&explicit, false),
        });
    }
    let mut inherited: Vec<&Ace> = aces
        .iter()
        .copied()
        .filter(|a| a.is_inherited() && !a.is_deny())
        .collect();
    inherited.sort_by_key(|a| by_origin(a));
    if !inherited.is_empty() {
        out.push(RightsSection {
            section: Section::Inherited,
            lines: group(&inherited, false),
        });
    }
    if let Some(sacl) = descriptor.sacl.as_ref().filter(|s| !s.aces.is_empty()) {
        let audit: Vec<&Ace> = sacl.aces.iter().filter(|a| applies(a)).collect();
        if !audit.is_empty() {
            out.push(RightsSection {
                section: Section::Audit,
                lines: group(&audit, true),
            });
        }
    }
    SecurityView {
        sections: out,
        without_effect: all.len() - aces.len(),
    }
}

/// The detail, ACE by ACE, in the order of the DACL then of the SACL (`lignes_aces`).
pub fn ace_lines(reading: &SecurityReading, nomenclature: Option<&Nomenclature>) -> Vec<AceLine> {
    let descriptor = &reading.descriptor;
    let domain = nomenclature.and_then(|n| n.domain_sid);
    let defaults = nomenclature
        .map(|n| s::default_aces(n, &reading.classes))
        .unwrap_or_default();
    let mut lines = Vec::new();
    for (acl, audit) in [(&descriptor.dacl, false), (&descriptor.sacl, true)] {
        for ace in acl.iter().flat_map(|a| a.aces.iter()) {
            let mut detail = if ace.is_inherited() {
                origin_text(ace, reading)
            } else {
                explicit_detail(ace, &defaults)
            };
            if audit {
                detail = fill(&tr("Auditing — {detail}"), &[("detail", &detail)]);
            }
            lines.push(AceLine {
                sddl: ace_sddl(ace, domain.as_ref()),
                text: ace_sentence(ace, &reading.classes, nomenclature, Some(&reading.names)),
                detail,
                ace: ace.clone(),
                removable: !audit && !ace.is_inherited() && !s::is_default(ace, &defaults),
            });
        }
    }
    lines
}

/// Name and SID of the owner (`proprietaire`).
pub fn owner(reading: &SecurityReading) -> (String, String) {
    match &reading.descriptor.owner {
        None => (tr("Not read"), String::new()),
        Some(sid) => (sid_name(sid, Some(&reading.names)), sid.to_string()),
    }
}

/// `etat_sacl`.
pub fn sacl_state(reading: &SecurityReading) -> String {
    if reading.sacl_read {
        let n = reading.descriptor.sacl.as_ref().map_or(0, |s| s.aces.len());
        fill(&tr("Read: {n} audit entry(ies)."), &[("n", &n.to_string())])
    } else {
        tr("Not read: the account is not allowed to manage auditing.")
    }
}

/// The wizard can delegate on this object (`peut_deleguer`).
pub fn can_delegate(classes: &[String]) -> bool {
    classes
        .iter()
        .any(|c| s::TARGET_CLASSES.iter().any(|t| t.eq_ignore_ascii_case(c)))
}

// --- Delegation wizard -------------------------------------------------------------------

/// Groups and user accounts whose name or logon name starts with the input
/// (`filtre_delegues`).
pub fn delegates_filter(input: &str) -> Option<String> {
    use annuaire_core::search::{self as q, Value};
    let text = input.trim();
    if text.is_empty() {
        return None;
    }
    let classes = q::or(&[
        q::eq("objectClass", Value::Text("group")).ok()?,
        q::and(&[
            q::eq("objectCategory", Value::Text("person")).ok()?,
            q::eq("objectClass", Value::Text("user")).ok()?,
        ])
        .ok()?,
    ])
    .ok()?;
    let names: Vec<String> = ["name", "sAMAccountName", "displayName"]
        .iter()
        .filter_map(|a| q::starts_with(a, text).ok())
        .collect();
    q::and(&[classes, q::or(&names).ok()?]).ok()
}

/// What the wizard will write: SDDL of each ACE, and these ACEs in clear
/// (`apercu_delegation`).
pub fn delegation_preview(
    who: &str,
    sid: &Sid,
    templates: &[Template],
    classes: &[String],
    nomenclature: Option<&Nomenclature>,
) -> (Vec<String>, Vec<String>) {
    let domain = nomenclature.and_then(|n| n.domain_sid);
    let aces = annuaire_core::actions::template_aces(templates, sid);
    (
        aces.iter().map(|a| ace_sddl(a, domain.as_ref())).collect(),
        aces.iter()
            .map(|a| sentence(who, &[a], classes, nomenclature, None))
            .collect(),
    )
}

/// What the common preview says besides the diff: the task and the guarantee of the undo
/// (`remarques_delegation`).
pub fn delegation_remarks(
    who: &str,
    templates: &[Template],
    dn_text: &str,
    removal: bool,
) -> Vec<String> {
    let tasks: Vec<String> = templates.iter().map(|t| template_title(*t)).collect();
    let head = if removal {
        tr("Removal of the delegation to {qui} on {dn}: {taches}.")
    } else {
        tr("Delegation to {qui} on {dn}: {taches}.")
    };
    vec![
        fill(
            &head,
            &[("qui", who), ("dn", dn_text), ("taches", &tasks.join("; "))],
        ),
        undo_remark(),
    ]
}

pub fn undo_remark() -> String {
    tr(
        "Undoing restores the original security descriptor, if the object has not changed in the meantime.",
    )
}

// --- Entry typed in SDDL -----------------------------------------------------------------

/// What can be added to the DACL: allow and deny, simple, object or conditional
/// (`TYPES_SAISIE`). Auditing (`AU`, `OU`, `XU`) and resource attributes (`RA`) go in the SACL,
/// that the tool does not write.
const INPUT_TYPES: [u8; 7] = [
    sd::ACCESS_ALLOWED,
    sd::ACCESS_DENIED,
    sd::ACCESS_ALLOWED_OBJECT,
    sd::ACCESS_DENIED_OBJECT,
    sd::ACCESS_ALLOWED_CALLBACK,
    sd::ACCESS_DENIED_CALLBACK,
    sd::ACCESS_ALLOWED_CALLBACK_OBJECT,
];

/// An ACE typed (`AceSaisie`).
#[derive(Debug, Clone)]
pub struct AceInput {
    pub ace: Ace,
    /// The form the tool will write and read back (Samba's).
    pub sddl: String,
    /// The ACE in clear, condition included.
    pub text: String,
    pub remarks: Vec<String>,
}

/// Reads an ACE typed in SDDL (Samba's or Windows' form) to add it to the DACL; a clear
/// message if it cannot be read or added from here (`ace_saisie`). A condition that cites
/// `SID(DA)`, `SID(DU)`… (abbreviation relative to the domain) is written as a full SID: the
/// same bytes as Windows', and Samba 4.22 crashes reading the abbreviation back in a
/// condition. The remark says so.
pub fn ace_input(
    input: &str,
    nomenclature: Option<&Nomenclature>,
    classes: &[String],
    names: &Names,
) -> Result<AceInput, String> {
    let mut text = input.trim().to_owned();
    if text.is_empty() {
        return Err(tr(
            "Type an entry in parentheses, for example (A;;RP;;;AU).",
        ));
    }
    if !text.starts_with('(') {
        text = format!("({text})");
    }
    let domain = nomenclature.and_then(|n| n.domain_sid);
    let abbreviations = if text.contains(';') {
        condition::domain_abbreviations(text.splitn(7, ';').last().unwrap_or(""))
    } else {
        Vec::new()
    };
    let codes = abbreviations
        .iter()
        .map(|c| format!("SID({c})"))
        .collect::<Vec<_>>()
        .join(", ");
    if !abbreviations.is_empty() && domain.is_none() {
        return Err(fill(
            &tr("Unknown domain SID: {codes} cannot be written as full SIDs."),
            &[("codes", &codes)],
        ));
    }
    let ace = sddl::ace_from_sddl(&text, domain.as_ref(), false).map_err(|e| {
        fill(
            &tr("Invalid SDDL: {raison}"),
            &[("raison", &codec_message(&e.to_string()))],
        )
    })?;
    if !INPUT_TYPES.contains(&ace.ace_type) {
        return Err(tr(
            "Only allow and deny entries can be added here (A, D, OA, OD, XA, XD, ZA): auditing and resource attributes belong in the SACL.",
        ));
    }
    if ace.is_inherited() {
        return Err(tr(
            "The ID (inherited) flag is set by the domain controller, not by the administrator.",
        ));
    }
    let mut remarks = Vec::new();
    if let (false, Some(domain)) = (abbreviations.is_empty(), domain.as_ref()) {
        remarks.push(fill(
            &tr("{codes}: written as a full SID ({sid}-…), the form Windows writes; Samba 4.22 cannot read these abbreviations back in a condition."),
            &[("codes", &codes), ("sid", &domain.to_string())],
        ));
    }
    if s::is_conditional(ace.ace_type) {
        remarks.push(tr(
            "Conditional entry: the domain controller evaluates it on each access (Windows Server 2012 and later, Samba 4.20 and later); an older controller ignores it.",
        ));
    }
    Ok(AceInput {
        sddl: ace_sddl(&ace, domain.as_ref()),
        text: ace_sentence(&ace, classes, nomenclature, Some(names)),
        ace,
        remarks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(text: &str) -> Sid {
        text.parse().unwrap()
    }

    #[test]
    fn names_of_sids() {
        assert_eq!(sid_name(&sid("S-1-5-11"), None), "Authenticated Users");
        assert_eq!(sid_name(&sid("S-1-5-21-1-2-3-512"), None), "Domain Admins");
        assert_eq!(
            sid_name(&sid("S-1-5-21-1-2-3-1105"), None),
            "S-1-5-21-1-2-3-1105"
        );
    }

    #[test]
    fn sentences() {
        let everyone = sd::everyone();
        let full = Ace::simple(sd::ACCESS_ALLOWED, sd::DS_FULL_CONTROL, &everyone, 0).unwrap();
        let object = ["top".to_owned(), "user".to_owned()];
        assert_eq!(
            ace_sentence(&full, &object, None, None),
            "Everyone has full control on this object."
        );
        let read = Ace::simple(sd::ACCESS_DENIED, sd::READ_CONTROL, &everyone, 0).unwrap();
        assert_eq!(
            ace_sentence(&read, &object, None, None),
            "Everyone cannot read permissions on this object."
        );
        let reset = Ace::object(
            sd::ACCESS_ALLOWED_OBJECT,
            sd::ADS_RIGHT_DS_CONTROL_ACCESS,
            &everyone,
            sd::CONTAINER_INHERIT_ACE | sd::INHERIT_ONLY_ACE,
            Some(s::right_reset_password()),
            Some(s::class_user()),
        )
        .unwrap();
        let ou = ["top".to_owned(), "organizationalUnit".to_owned()];
        assert_eq!(
            ace_sentence(&reset, &ou, None, None),
            "Everyone can reset the password for the User objects of this OU."
        );
    }

    /// Vectors `kind|SDDL` of `ANNUAIRE_VECTEURS_SDDL`, printed as `secu_py.py` prints them
    /// from the Python view (English catalogue): `cargo test -- --ignored --nocapture`.
    #[test]
    #[ignore = "comparison with the Python application, by hand"]
    fn vectors() {
        let Ok(path) = std::env::var("ANNUAIRE_VECTEURS_SDDL") else {
            return;
        };
        let domain: Sid = "S-1-5-21-1-2-3".parse().unwrap();
        let python = |b: bool| if b { "True" } else { "False" };
        for line in std::fs::read_to_string(path).unwrap().lines() {
            let (kind, text) = line.split_once('|').unwrap();
            let classes: Vec<String> = match kind {
                "ou" => vec!["top".into(), "organizationalUnit".into()],
                _ => ["top", "person", "organizationalPerson", "user"]
                    .map(String::from)
                    .to_vec(),
            };
            let descriptor = sddl::sd_from_sddl(text, Some(&domain), false).unwrap();
            let reading = SecurityReading {
                dn: "OU=X,DC=lab,DC=test".into(),
                classes,
                raw: Vec::new(),
                sacl_read: descriptor.sacl.is_some(),
                descriptor: descriptor.clone(),
                ancestors: Vec::new(),
                names: HashMap::new(),
                dc: "dc1".into(),
            };
            println!("== {kind} {text}");
            let view = sections(&reading, None);
            println!("sans effet {}", view.without_effect);
            for section in &view.sections {
                let title = match section.section {
                    Section::Deny => "Deny",
                    Section::Delegations => "Delegations",
                    Section::Explicit => "Explicit permissions",
                    Section::Inherited => "Inherited permissions",
                    Section::Audit => "Auditing (SACL)",
                };
                println!("[{title}]");
                for l in &section.lines {
                    println!(
                        "  {} | {} | {} | {}",
                        l.text,
                        l.detail,
                        python(l.removable),
                        l.delegation
                    );
                }
            }
            for l in ace_lines(&reading, None) {
                println!(
                    "  ACE {} | {} | {} | {}",
                    l.sddl,
                    l.text,
                    l.detail,
                    python(l.removable)
                );
            }
            println!("SDDL {}", descriptor_sddl(&descriptor, Some(&domain)));
        }
    }
}

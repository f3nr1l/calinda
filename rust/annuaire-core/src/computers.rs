// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Computer accounts and contacts (J9.2, ADR 0024), as the Windows console (ADUC) makes them.
//!
//! A computer is created in one add request: `sAMAccountName` `NAME$`, `userAccountControl`
//! `WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD` (4128, the value of ADUC) and an initial
//! password: the name in lower case, 14 characters at most, when the account is « assigned as
//! a pre-Windows 2000 computer » (the password an old system, or a join without credentials,
//! expects), otherwise a random one that nobody knows (a join with credentials sets its own).
//! The « user or group that can join this computer » gets four ACEs on the object, those of
//! ADUC: reset password, write account restrictions, validated writes of `dNSHostName` and of
//! the SPNs. They are written once the account exists (`allow_join`, on the descriptor the DC
//! gave it, as the protection of a new OU): an add with a descriptor would replace the default
//! one of the class.
//!
//! « Reset Account » gives the account its default password again (the name in lower case),
//! as ADUC: the computer loses its secure channel until it is joined again.
//!
//! The default password is not always writable (measured 2026-10-28): Samba 4.22 exempts the
//! computer accounts from the password policy of the domain, Windows Server 2025 does not, by
//! LDAP as by SAMR (`net user`, ADSI): with complexity required, it refuses the name in lower
//! case (`0000052D`). [`PasswordRule`] says what the DC will accept; a « pre-Windows 2000 »
//! account it would refuse is refused before the preview, and the reset then draws a random
//! password, which the preview says.

use annuaire_codecs::Sid;
use annuaire_codecs::sd::{self, Ace};
use annuaire_codecs::uac::UserAccountControl;

use crate::actions::{self, ActionError, ReadObject, encode_password};
use crate::changes::{AttributeMap, Change, Changeset, Operation};
use crate::dn::{self, Component};
use crate::security;

/// Characters of a NetBIOS name, at most.
pub const NETBIOS_LIMIT: usize = 15;
/// Characters of the default password of a computer account (`LM20_PWLEN`).
pub const DEFAULT_PASSWORD_LIMIT: usize = 14;
/// Characters of the random initial password (the length Windows draws at a join).
pub const RANDOM_PASSWORD_LENGTH: usize = 120;
/// `userAccountControl` of a new computer account (ADUC).
pub const COMPUTER_UAC: u32 =
    UserAccountControl::WORKSTATION_TRUST_ACCOUNT | UserAccountControl::PASSWD_NOTREQD;

/// What a new computer account is made of.
#[derive(Debug, Clone, Default)]
pub struct NewComputer {
    /// The name of the object (`cn`).
    pub name: String,
    /// The pre-Windows 2000 name, without the final `$`; empty: from the name.
    pub identifier: String,
    pub description: String,
    /// « Assign this computer account as a pre-Windows 2000 computer »: the password is the
    /// name in lower case.
    pub pre_windows_2000: bool,
    /// The user or group that can join this computer to the domain (its SID).
    pub joiner: Option<Sid>,
}

/// The pre-Windows 2000 name proposed for `name`: upper case, 15 characters at most.
pub fn proposed_identifier(name: &str) -> String {
    name.trim()
        .chars()
        .take(NETBIOS_LIMIT)
        .collect::<String>()
        .to_uppercase()
}

/// A NetBIOS name: 1 to 15 characters, none of those Windows refuses (a dot neither: ADUC
/// refuses it in the name of a computer).
pub fn identifier_valid(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.chars().count() <= NETBIOS_LIMIT
        && !identifier
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || "\"/\\[]:;|=,+*?<>@.$".contains(c))
}

/// The default password of a computer account: its pre-Windows 2000 name in lower case,
/// without the `$`, 14 characters at most.
pub fn default_password(identifier: &str) -> String {
    identifier
        .trim()
        .trim_end_matches('$')
        .chars()
        .take(DEFAULT_PASSWORD_LIMIT)
        .collect::<String>()
        .to_lowercase()
}

/// A random password of printable characters, drawn from the system OpenSSL.
pub fn random_password() -> Result<String, ActionError> {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.:!#%&()*+,/;<=>?@[]^{|}~";
    let mut bytes = vec![0u8; RANDOM_PASSWORD_LENGTH];
    openssl::rand::rand_bytes(&mut bytes).map_err(|e| ActionError::Change(e.to_string()))?;
    Ok(bytes
        .iter()
        .map(|b| {
            char::from(
                ALPHABET
                    .get(usize::from(*b) % ALPHABET.len())
                    .copied()
                    .unwrap_or(b'x'),
            )
        })
        .collect())
}

/// What the DC of the domain does with the default password of a computer account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordRule {
    /// Samba: the computer accounts are not held to the policy.
    pub samba: bool,
    /// `pwdProperties` bit 0 (`DOMAIN_PASSWORD_COMPLEX`).
    pub complex: bool,
    pub min_length: usize,
}

impl PasswordRule {
    /// The default password of `identifier` will be accepted. Complexity asks three kinds of
    /// characters among four; a name in lower case has two at most (letters, digits, plus a
    /// hyphen as a symbol): refused as soon as it is required.
    pub fn accepts_default(&self, identifier: &str) -> bool {
        self.samba
            || (!self.complex && default_password(identifier).chars().count() >= self.min_length)
    }
}

/// Reads the rule on the DC of `connection`: its vendor (RootDSE), `pwdProperties` and
/// `minPwdLength` of the domain (blocking).
pub fn read_rule(
    connection: &crate::Connection,
) -> Result<PasswordRule, crate::connection::Failure> {
    connection.run(true, |link| {
        let samba = link.state.root_dse.samba();
        let base = link.state.root_dse.default_naming_context.clone();
        let entry = crate::search::read_entry(
            link.session.as_mut(),
            &base,
            &["pwdProperties".to_owned(), "minPwdLength".to_owned()],
            "(objectClass=*)",
            None,
            Some(link.timeout),
        )?;
        let number = |name: &str| {
            entry
                .as_ref()
                .and_then(|e| e.values(name).first().cloned())
                .and_then(|v| String::from_utf8_lossy(&v).trim().parse::<i64>().ok())
                .unwrap_or(0)
        };
        Ok(PasswordRule {
            samba,
            complex: number("pwdProperties") & 1 != 0,
            min_length: usize::try_from(number("minPwdLength")).unwrap_or(0),
        })
    })
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

fn cn(name: &str) -> Result<String, ActionError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(ActionError::EmptyName);
    }
    dn::compose(&[Component::new("CN", name)]).map_err(|e| ActionError::Change(e.to_string()))
}

/// A computer account, in one creation; the ACEs of the joiner follow (`allow_join`).
pub fn create_computer(
    parent: &str,
    computer: &NewComputer,
    rule: &PasswordRule,
) -> Result<Changeset, ActionError> {
    let identifier = if computer.identifier.trim().is_empty() {
        proposed_identifier(&computer.name)
    } else {
        computer.identifier.trim().trim_end_matches('$').to_owned()
    };
    if !identifier_valid(&identifier) {
        return Err(ActionError::InvalidIdentifier(identifier));
    }
    let password = if computer.pre_windows_2000 {
        if !rule.accepts_default(&identifier) {
            return Err(ActionError::DefaultPasswordRefused(identifier));
        }
        default_password(&identifier)
    } else {
        random_password()?
    };
    let mut attributes: AttributeMap = vec![
        (
            "objectClass".into(),
            ["top", "person", "organizationalPerson", "user", "computer"]
                .iter()
                .map(|c| bytes(c))
                .collect(),
        ),
        (
            "sAMAccountName".into(),
            vec![bytes(&format!("{identifier}$"))],
        ),
        (
            "userAccountControl".into(),
            vec![bytes(&COMPUTER_UAC.to_string())],
        ),
        ("unicodePwd".into(), vec![encode_password(&password)?]),
    ];
    if !computer.description.trim().is_empty() {
        attributes.push((
            "description".into(),
            vec![bytes(computer.description.trim())],
        ));
    }
    let dn_text = format!("{},{parent}", cn(&computer.name)?);
    Ok(Changeset {
        operations: vec![Operation::add(&dn_text, attributes)?],
        remarks: Vec::new(),
    })
}

/// The ACEs that let `sid` join the computer to the domain, on the object itself (ADUC):
/// reset password, write account restrictions, validated writes of the DNS host name and of
/// the service principal names.
pub fn join_aces(sid: &Sid) -> Vec<Ace> {
    let ace = |mask, object_type| {
        Ace::object(
            sd::ACCESS_ALLOWED_OBJECT,
            mask,
            sid,
            0,
            Some(object_type),
            None,
        )
        .ok()
    };
    [
        ace(
            sd::ADS_RIGHT_DS_CONTROL_ACCESS,
            security::right_reset_password(),
        ),
        ace(
            sd::ADS_RIGHT_DS_READ_PROP | sd::ADS_RIGHT_DS_WRITE_PROP,
            security::set_account_restrictions(),
        ),
        ace(sd::ADS_RIGHT_DS_SELF, security::write_dns_name()),
        ace(sd::ADS_RIGHT_DS_SELF, security::write_spn()),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// The ACEs of the joiner added to the descriptor of the new account (read by
/// `actions::read_descriptors`); empty changeset if they are there.
pub fn allow_join(object: &ReadObject, sid: &Sid) -> Result<Changeset, ActionError> {
    actions::add_aces(object, &join_aces(sid))
}

/// The SIDs that every ACE of the join is given to, in a descriptor (to say who may join an
/// account read).
pub fn joiners(descriptor: &sd::SecurityDescriptor) -> Vec<Sid> {
    let Some(dacl) = &descriptor.dacl else {
        return Vec::new();
    };
    let explicit: Vec<&Ace> = dacl.aces.iter().filter(|a| !a.is_inherited()).collect();
    let mut out: Vec<Sid> = Vec::new();
    for ace in &explicit {
        let Some(sid) = ace.sid() else { continue };
        if out.contains(&sid) {
            continue;
        }
        if join_aces(&sid)
            .iter()
            .all(|wanted| explicit.contains(&wanted))
        {
            out.push(sid);
        }
    }
    out
}

/// « Reset Account » of a computer: its default password again (`unicodePwd` replaced), or a
/// random one when the DC would refuse it (the second value: true if the default one).
/// Never journaled nor shown.
pub fn reset_computer(
    object: &ReadObject,
    rule: &PasswordRule,
) -> Result<(Changeset, bool), ActionError> {
    let identifier = object.text("sAMAccountName");
    if identifier.trim().is_empty() {
        return Err(ActionError::InvalidIdentifier(object.dn.clone()));
    }
    let default = rule.accepts_default(&identifier);
    let password = if default {
        default_password(&identifier)
    } else {
        random_password()?
    };
    Ok((
        Changeset {
            operations: vec![Operation::modify(
                &object.dn,
                vec![Change::new(
                    "unicodePwd",
                    Vec::new(),
                    vec![encode_password(&password)?],
                )?],
                Some(object.read.clone()),
            )?],
            remarks: Vec::new(),
        },
        default,
    ))
}

/// What a new contact is made of (the « New Object - Contact » of ADUC, with the address and
/// the telephone of its sheet).
#[derive(Debug, Clone, Default)]
pub struct NewContact {
    pub full_name: String,
    pub given_name: String,
    pub initials: String,
    pub surname: String,
    pub display_name: String,
    pub mail: String,
    pub telephone: String,
    pub street: String,
    pub postal_code: String,
    pub city: String,
    pub description: String,
}

/// A contact (`objectClass: contact`), in one creation; the empty fields write nothing.
pub fn create_contact(parent: &str, contact: &NewContact) -> Result<Changeset, ActionError> {
    let mut attributes: AttributeMap = vec![(
        "objectClass".into(),
        ["top", "person", "organizationalPerson", "contact"]
            .iter()
            .map(|c| bytes(c))
            .collect(),
    )];
    for (name, value) in [
        ("givenName", &contact.given_name),
        ("initials", &contact.initials),
        ("sn", &contact.surname),
        ("displayName", &contact.display_name),
        ("mail", &contact.mail),
        ("telephoneNumber", &contact.telephone),
        ("streetAddress", &contact.street),
        ("postalCode", &contact.postal_code),
        ("l", &contact.city),
        ("description", &contact.description),
    ] {
        if !value.trim().is_empty() {
            attributes.push((name.into(), vec![bytes(value.trim())]));
        }
    }
    let dn_text = format!("{},{parent}", cn(&contact.full_name)?);
    Ok(Changeset {
        operations: vec![Operation::add(&dn_text, attributes)?],
        remarks: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::changes::Read;

    fn added(changeset: &Changeset) -> (&str, &AttributeMap) {
        match changeset.operations.first() {
            Some(Operation::Add { dn, attributes }) => (dn, attributes),
            _ => panic!("one creation expected"),
        }
    }

    fn value<'a>(attributes: &'a AttributeMap, name: &str) -> Option<&'a [u8]> {
        attributes
            .iter()
            .find(|(a, _)| a == name)
            .and_then(|(_, v)| v.first())
            .map(Vec::as_slice)
    }

    #[test]
    fn names_and_default_password() {
        assert_eq!(
            proposed_identifier(" Poste-Compta-Nantes-2 "),
            "POSTE-COMPTA-NA"
        );
        assert_eq!(default_password("POSTE-COMPTA-NA$"), "poste-compta-n");
        assert_eq!(default_password("PC1"), "pc1");
        assert!(identifier_valid("PC-01"));
        for bad in ["", "PC 01", "PC.01", "PC*", "ABCDEFGHIJKLMNOP", "PC$"] {
            assert!(!identifier_valid(bad), "{bad}");
        }
        let a = random_password().unwrap();
        assert_eq!(a.chars().count(), RANDOM_PASSWORD_LENGTH);
        assert_ne!(a, random_password().unwrap());
    }

    const SAMBA: PasswordRule = PasswordRule {
        samba: true,
        complex: true,
        min_length: 7,
    };
    const WINDOWS: PasswordRule = PasswordRule {
        samba: false,
        complex: true,
        min_length: 7,
    };

    #[test]
    fn rule_of_the_dc() {
        assert!(SAMBA.accepts_default("PC1"));
        assert!(!WINDOWS.accepts_default("POSTE-COMPTA-12"));
        let simple = PasswordRule {
            complex: false,
            ..WINDOWS
        };
        assert!(simple.accepts_default("POSTE-12"));
        assert!(!simple.accepts_default("PC1"), "shorter than minPwdLength");
    }

    #[test]
    fn computer_as_aduc() {
        let computer = NewComputer {
            name: "Poste-12".into(),
            pre_windows_2000: true,
            ..NewComputer::default()
        };
        let changeset = create_computer("OU=Postes,DC=lab,DC=test", &computer, &SAMBA).unwrap();
        let (dn, attributes) = added(&changeset);
        assert_eq!(dn, "CN=Poste-12,OU=Postes,DC=lab,DC=test");
        assert_eq!(value(attributes, "sAMAccountName"), Some(&b"POSTE-12$"[..]));
        assert_eq!(value(attributes, "userAccountControl"), Some(&b"4128"[..]));
        assert_eq!(
            value(attributes, "unicodePwd").map(<[u8]>::to_vec),
            Some(encode_password("poste-12").unwrap())
        );
        // Not « pre-Windows 2000 »: a random password, nobody knows it.
        let random = create_computer(
            "OU=Postes,DC=lab,DC=test",
            &NewComputer {
                pre_windows_2000: false,
                identifier: "p12".into(),
                ..computer.clone()
            },
            &WINDOWS,
        )
        .unwrap();
        let (_, attributes) = added(&random);
        assert_eq!(value(attributes, "sAMAccountName"), Some(&b"p12$"[..]));
        assert_ne!(
            value(attributes, "unicodePwd").map(<[u8]>::to_vec),
            Some(encode_password("p12").unwrap())
        );
        assert!(matches!(
            create_computer("OU=Postes,DC=lab,DC=test", &computer, &WINDOWS),
            Err(ActionError::DefaultPasswordRefused(_))
        ));
        assert!(matches!(
            create_computer(
                "OU=X,DC=x",
                &NewComputer {
                    name: "PC 1".into(),
                    ..NewComputer::default()
                },
                &SAMBA,
            ),
            Err(ActionError::InvalidIdentifier(_))
        ));
    }

    #[test]
    fn join_aces_found_again() {
        let sid: Sid = "S-1-5-21-1-2-3-1105".parse().unwrap();
        let other: Sid = "S-1-5-21-1-2-3-1106".parse().unwrap();
        let aces = join_aces(&sid);
        assert_eq!(aces.len(), 4);
        let domain: Sid = "S-1-5-21-1-2-3".parse().unwrap();
        let mut descriptor = annuaire_codecs::sddl::sd_from_sddl(
            "O:DAG:DUD:(A;;RPLCLORC;;;AU)",
            Some(&domain),
            false,
        )
        .unwrap();
        descriptor = descriptor.add_aces(&aces).unwrap();
        // Three of the four for another account: not a joiner.
        descriptor = descriptor.add_aces(&join_aces(&other)[..3]).unwrap();
        assert_eq!(joiners(&descriptor), vec![sid]);
    }

    #[test]
    fn reset_and_contact() {
        let object = ReadObject {
            dn: "CN=PC1,OU=X,DC=x".into(),
            attributes: vec![("sAMAccountName".into(), vec![bytes("PC1$")])],
            read: Read {
                dc: "dc1".into(),
                usn: 3,
            },
        };
        let (reset, default) = reset_computer(&object, &SAMBA).unwrap();
        assert!(default);
        assert!(!reset_computer(&object, &WINDOWS).unwrap().1);
        let Some(Operation::Modify { changes, .. }) = reset.operations.first() else {
            panic!("one modification expected");
        };
        assert_eq!(changes.len(), 1);
        let contact = NewContact {
            full_name: "Jeanne Dupré".into(),
            given_name: "Jeanne".into(),
            surname: "Dupré".into(),
            telephone: "+596 596 00 00 00".into(),
            city: "Fort-de-France".into(),
            ..NewContact::default()
        };
        let changeset = create_contact("OU=Contacts,DC=x", &contact).unwrap();
        let (dn, attributes) = added(&changeset);
        assert_eq!(dn, "CN=Jeanne Dupré,OU=Contacts,DC=x");
        assert_eq!(
            value(attributes, "objectClass"),
            Some(&b"top"[..]),
            "classes first"
        );
        assert_eq!(value(attributes, "l"), Some("Fort-de-France".as_bytes()));
        assert!(value(attributes, "mail").is_none());
    }
}

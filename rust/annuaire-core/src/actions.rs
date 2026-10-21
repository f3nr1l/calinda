// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Common actions on the accounts (J2.6), turned into changesets (`annuaire.core.actions`).
//!
//! No action writes: each returns a `Changeset` that the interface shows as a preview and
//! applies by `writer::apply`. The builders are pure and take the state read (`ReadObject`);
//! `read_objects` reads it on the write connection, so that the versions are those of the DC
//! where the write goes (ADR 0006, 2). An action on a selection gives **one** changeset,
//! applied « all or nothing ».
//!
//! Choices checked on the lab (Samba 4.22): a user is created in **one** add request with
//! `unicodePwd`, `pwdLastSet=0` and `userAccountControl=512`; the reset of a password is a
//! « replace » of `unicodePwd`; the protection of an OU against accidental deletion is the
//! one of the Windows console: deny « delete » and « delete subtree » to Everyone on the OU,
//! **and** deny « delete children » on its parent.

use annuaire_codecs::sd::{self, Ace, Acl, SecurityDescriptor};
use annuaire_codecs::uac::{GroupType, Scope as GroupScope, UserAccountControl};

use crate::changes::{
    AttributeMap, Change, ChangeError, Changeset, Operation, Read, dn_key, parent_dn,
};
use crate::connection::{Connection, Failure};
use crate::dn::{self, Component};
use crate::error::{LdapError, code};
use crate::search::{self, SD_DACL};
use crate::session::Entry;

pub const STATE_ATTRIBUTES: [&str; 8] = [
    "objectClass",
    "cn",
    "name",
    "sAMAccountName",
    "displayName",
    "userAccountControl",
    "lockoutTime",
    "pwdLastSet",
];
pub const SD: &str = "nTSecurityDescriptor";

/// Deny « delete children » to Everyone, set on the parent of a protected OU.
pub fn parent_ace() -> Ace {
    Ace::simple(sd::ACCESS_DENIED, 0x0000_0002, &sd::everyone(), 0).unwrap_or(Ace {
        ace_type: sd::ACCESS_DENIED,
        flags: 0,
        body: Vec::new(),
    })
}

/// The state of an object read on the write DC, and its version (`ObjetLu`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadObject {
    pub dn: String,
    pub attributes: AttributeMap,
    pub read: Read,
}

impl ReadObject {
    pub fn values(&self, attribute: &str) -> Vec<Vec<u8>> {
        self.attributes
            .iter()
            .find(|(a, _)| a.eq_ignore_ascii_case(attribute))
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    pub fn text(&self, attribute: &str) -> String {
        self.values(attribute)
            .first()
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default()
    }
}

/// Why an action cannot be built (a message for the user, in the language of the caller's
/// catalogue: the interface says it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    EmptyPassword,
    EmptyName,
    ActiveWithoutPassword,
    InvalidIdentifier(String),
    UnreadableDescriptor(String),
    NoUserAccountControl(String),
    UnderItself(String),
    /// No delegation template chosen.
    NoTemplate,
    /// An inherited permission is removed on the object it comes from.
    InheritedRemoval,
    Change(String),
}

impl From<ChangeError> for ActionError {
    fn from(e: ChangeError) -> Self {
        Self::Change(e.to_string())
    }
}

fn usn(entry: &Entry) -> Result<i64, LdapError> {
    entry
        .values("uSNChanged")
        .first()
        .and_then(|v| {
            annuaire_codecs::integer::decode(v, annuaire_codecs::integer::Width::Bits64).ok()
        })
        .ok_or_else(|| LdapError::new(code::DECODING_ERROR, "uSNChanged absent"))
}

fn read_with(
    connection: &Connection,
    dns: &[String],
    attributes: Vec<String>,
    sd_flags: Option<i64>,
) -> Result<Vec<ReadObject>, Failure> {
    let dns = dns.to_vec();
    connection.run(true, move |link| {
        let mut out = Vec::new();
        for dn_text in &dns {
            let entry = search::read_entry(
                link.session.as_mut(),
                dn_text,
                &attributes,
                "(objectClass=*)",
                sd_flags,
                Some(link.timeout),
            )?;
            if let Some(entry) = entry {
                out.push(ReadObject {
                    read: Read {
                        dc: link.state.dc.clone(),
                        usn: usn(&entry)?,
                    },
                    dn: entry.dn,
                    attributes: entry.attributes,
                });
            }
        }
        Ok(out)
    })
}

/// Reads the objects (one round trip each); those that no longer exist are left out
/// (`lire_objets`). Blocking.
pub fn read_objects(
    connection: &Connection,
    dns: &[String],
    attributes: &[&str],
) -> Result<Vec<ReadObject>, Failure> {
    let names = std::iter::once("uSNChanged")
        .chain(attributes.iter().copied())
        .map(str::to_owned)
        .collect();
    read_with(connection, dns, names, None)
}

/// As `read_objects`, for the DACL alone (SD flags control = DACL) (`lire_descripteurs`).
pub fn read_descriptors(
    connection: &Connection,
    dns: &[String],
) -> Result<Vec<ReadObject>, Failure> {
    read_with(
        connection,
        dns,
        vec!["uSNChanged".into(), SD.into()],
        Some(SD_DACL),
    )
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

// --- Creation ------------------------------------------------------------------------------------

/// Value of `unicodePwd`: the password between quotes, in UTF-16LE (MS-ADTS 3.1.1.3.1.5)
/// (`encoder_mot_de_passe`).
pub fn encode_password(password: &str) -> Result<Vec<u8>, ActionError> {
    if password.is_empty() {
        return Err(ActionError::EmptyPassword);
    }
    Ok(format!("\"{password}\"")
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect())
}

fn rdn(attribute: &str, value: &str) -> Result<String, ActionError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(ActionError::EmptyName);
    }
    dn::compose(&[Component::new(attribute, value)]).map_err(|e| ActionError::Change(e.to_string()))
}

/// What a new user is made of (`creer_utilisateur`).
#[derive(Debug, Clone, Default)]
pub struct NewUser {
    pub full_name: String,
    pub identifier: String,
    pub upn: String,
    pub given_name: String,
    pub surname: String,
    pub password: Option<String>,
    pub change_at_next_logon: bool,
    pub enable: bool,
}

/// A user account, in one creation (atomic). Without a password, the account stays disabled.
pub fn create_user(parent: &str, user: &NewUser) -> Result<Changeset, ActionError> {
    if user.enable && user.password.is_none() {
        return Err(ActionError::ActiveWithoutPassword);
    }
    let identifier = user.identifier.trim();
    if identifier.is_empty()
        || identifier.chars().count() > 20
        || identifier.chars().any(|c| "\"/\\[]:;|=,+*?<>@".contains(c))
    {
        return Err(ActionError::InvalidIdentifier(identifier.to_owned()));
    }
    let mut attributes: AttributeMap = vec![
        (
            "objectClass".into(),
            ["top", "person", "organizationalPerson", "user"]
                .iter()
                .map(|c| bytes(c))
                .collect(),
        ),
        ("sAMAccountName".into(), vec![bytes(identifier)]),
        ("displayName".into(), vec![bytes(user.full_name.trim())]),
    ];
    for (name, value) in [
        ("userPrincipalName", &user.upn),
        ("givenName", &user.given_name),
        ("sn", &user.surname),
    ] {
        if !value.trim().is_empty() {
            attributes.push((name.into(), vec![bytes(value.trim())]));
        }
    }
    if let Some(password) = &user.password {
        attributes.push(("unicodePwd".into(), vec![encode_password(password)?]));
        if user.change_at_next_logon {
            attributes.push(("pwdLastSet".into(), vec![bytes("0")]));
        }
    }
    let mut uac = UserAccountControl::NORMAL_ACCOUNT;
    if !user.enable {
        uac |= UserAccountControl::ACCOUNTDISABLE;
    }
    attributes.push(("userAccountControl".into(), vec![bytes(&uac.to_string())]));
    let dn_text = format!("{},{parent}", rdn("CN", &user.full_name)?);
    Ok(Changeset {
        operations: vec![Operation::add(&dn_text, attributes)?],
        remarks: Vec::new(),
    })
}

/// A group (`creer_groupe`).
pub fn create_group(
    parent: &str,
    name: &str,
    identifier: &str,
    scope: GroupScope,
    security: bool,
    description: &str,
) -> Result<Changeset, ActionError> {
    let sam = if identifier.trim().is_empty() {
        name.trim()
    } else {
        identifier.trim()
    };
    let group_type =
        GroupType::encode(scope, security).map_err(|e| ActionError::Change(e.to_string()))?;
    let mut attributes: AttributeMap = vec![
        ("objectClass".into(), vec![bytes("top"), bytes("group")]),
        ("sAMAccountName".into(), vec![bytes(sam)]),
        ("groupType".into(), vec![bytes(&group_type.to_string())]),
    ];
    if !description.trim().is_empty() {
        attributes.push(("description".into(), vec![bytes(description.trim())]));
    }
    let dn_text = format!("{},{parent}", rdn("CN", name)?);
    Ok(Changeset {
        operations: vec![Operation::add(&dn_text, attributes)?],
        remarks: Vec::new(),
    })
}

/// An OU. Its protection is set afterwards (`protect_ou`): the descriptor the DC gave it must
/// be read (`creer_ou`).
pub fn create_ou(parent: &str, name: &str, description: &str) -> Result<Changeset, ActionError> {
    let mut attributes: AttributeMap = vec![(
        "objectClass".into(),
        vec![bytes("top"), bytes("organizationalUnit")],
    )];
    if !description.trim().is_empty() {
        attributes.push(("description".into(), vec![bytes(description.trim())]));
    }
    let dn_text = format!("{},{parent}", rdn("OU", name)?);
    Ok(Changeset {
        operations: vec![Operation::add(&dn_text, attributes)?],
        remarks: Vec::new(),
    })
}

// --- Protection against accidental deletion ---------------------------------------------------

fn descriptor(object: &ReadObject) -> Result<(Vec<u8>, SecurityDescriptor), ActionError> {
    let raw = object
        .values(SD)
        .into_iter()
        .next()
        .ok_or_else(|| ActionError::UnreadableDescriptor(object.dn.clone()))?;
    let sd = SecurityDescriptor::decode(&raw)
        .map_err(|_| ActionError::UnreadableDescriptor(object.dn.clone()))?;
    Ok((raw, sd))
}

/// Compared in structure: Windows orders the parts otherwise than the encoder
/// (`_changer_sd`).
fn change_sd(
    object: &ReadObject,
    new: &SecurityDescriptor,
) -> Result<Option<Operation>, ActionError> {
    let (old_raw, old) = descriptor(object)?;
    if *new == old {
        return Ok(None);
    }
    let new_raw = new
        .encode()
        .map_err(|e| ActionError::Change(e.to_string()))?;
    Ok(Some(Operation::modify(
        &object.dn,
        vec![Change::new(SD, vec![old_raw], vec![new_raw])?],
        Some(object.read.clone()),
    )?))
}

pub fn parent_protected(descriptor: &SecurityDescriptor) -> bool {
    let wanted = parent_ace();
    descriptor.dacl.as_ref().is_some_and(|d| {
        d.aces
            .iter()
            .any(|a| a.ace_type == sd::ACCESS_DENIED && !a.is_inherited() && a.body == wanted.body)
    })
}

pub fn is_protected(object: &ReadObject) -> Result<bool, ActionError> {
    Ok(descriptor(object)?.1.is_protected())
}

/// Deny of deletion on the OU, deny of deleting its children on the parent (`proteger_ou`).
pub fn protect_ou(ou: &ReadObject, parent: &ReadObject) -> Result<Changeset, ActionError> {
    let mut operations = Vec::new();
    let protected = descriptor(ou)?
        .1
        .protect()
        .map_err(|e| ActionError::Change(e.to_string()))?;
    operations.extend(change_sd(ou, &protected)?);
    let (_, parent_sd) = descriptor(parent)?;
    if !parent_protected(&parent_sd)
        && let Some(dacl) = &parent_sd.dacl
    {
        let mut aces = vec![parent_ace()];
        aces.extend(dacl.aces.iter().cloned());
        let new = SecurityDescriptor {
            dacl: Some(Acl {
                revision: dacl.revision,
                aces,
            }),
            ..parent_sd.clone()
        };
        operations.extend(change_sd(parent, &new)?);
    }
    Ok(Changeset {
        operations,
        remarks: Vec::new(),
    })
}

/// Removes the deny set on the OU. The one of the parent stays, as under Windows
/// (`deproteger_ou`).
pub fn unprotect_ou(ou: &ReadObject) -> Result<Changeset, ActionError> {
    let new = descriptor(ou)?.1.unprotect();
    Ok(Changeset {
        operations: change_sd(ou, &new)?.into_iter().collect(),
        remarks: Vec::new(),
    })
}

// --- Delegation and entries of the DACL (`annuaire.core.delegation`) ---------------------------

/// The ACEs to write for these templates, without duplicate, in the order of the templates
/// (`aces_de`).
pub fn template_aces(
    templates: &[crate::security::Template],
    sid: &annuaire_codecs::Sid,
) -> Vec<Ace> {
    let mut out: Vec<Ace> = Vec::new();
    for ace in templates.iter().flat_map(|t| t.aces(sid)) {
        if !out.contains(&ace) {
            out.push(ace);
        }
    }
    out
}

fn add_to_dacl(object: &ReadObject, aces: &[Ace]) -> Result<Changeset, ActionError> {
    let new = descriptor(object)?
        .1
        .add_aces(aces)
        .map_err(|e| ActionError::Change(e.to_string()))?;
    Ok(Changeset {
        operations: change_sd(object, &new)?.into_iter().collect(),
        remarks: Vec::new(),
    })
}

/// Adds to the DACL of `object` (read by `read_descriptors`) the ACEs of the templates for
/// `sid`; those already there are not doubled. Empty changeset if nothing changes
/// (`deleguer`).
pub fn delegate(
    object: &ReadObject,
    sid: &annuaire_codecs::Sid,
    templates: &[crate::security::Template],
) -> Result<Changeset, ActionError> {
    if templates.is_empty() {
        return Err(ActionError::NoTemplate);
    }
    add_to_dacl(object, &template_aces(templates, sid))
}

/// Adds these explicit ACEs to the DACL, in the canonical order (an ACE typed in SDDL,
/// conditional or not). Empty changeset if they are there (`ajouter`).
pub fn add_aces(object: &ReadObject, aces: &[Ace]) -> Result<Changeset, ActionError> {
    add_to_dacl(object, aces)
}

/// Removes these explicit ACEs from the DACL (a delegation, or ACEs chosen one by one)
/// (`retirer`).
pub fn remove_aces(object: &ReadObject, aces: &[Ace]) -> Result<Changeset, ActionError> {
    if aces.iter().any(Ace::is_inherited) {
        return Err(ActionError::InheritedRemoval);
    }
    let new = descriptor(object)?.1.remove_aces(aces);
    Ok(Changeset {
        operations: change_sd(object, &new)?.into_iter().collect(),
        remarks: Vec::new(),
    })
}

// --- States of the account -----------------------------------------------------------------------

fn uac(object: &ReadObject) -> Result<i64, ActionError> {
    object
        .text("userAccountControl")
        .trim()
        .parse()
        .map_err(|_| ActionError::NoUserAccountControl(object.dn.clone()))
}

fn change_uac(object: &ReadObject, new: i64) -> Result<Option<Operation>, ActionError> {
    let old = uac(object)?;
    if new == old {
        return Ok(None);
    }
    Ok(Some(Operation::modify(
        &object.dn,
        vec![Change::new(
            "userAccountControl",
            vec![bytes(&old.to_string())],
            vec![bytes(&new.to_string())],
        )?],
        Some(object.read.clone()),
    )?))
}

/// Enables or disables the accounts (`ACCOUNTDISABLE`); those already in the state wanted are
/// left aside (`activer`).
pub fn enable(objects: &[ReadObject], active: bool) -> Result<Changeset, ActionError> {
    let flag = i64::from(UserAccountControl::ACCOUNTDISABLE);
    let mut operations = Vec::new();
    for o in objects {
        let present = uac(o)?;
        let new = if active {
            present & !flag
        } else {
            present | flag
        };
        operations.extend(change_uac(o, new)?);
    }
    Ok(Changeset {
        operations,
        remarks: Vec::new(),
    })
}

/// `lockoutTime` to 0 for the accounts that were locked out; the others left aside
/// (`deverrouiller`).
pub fn unlock(objects: &[ReadObject]) -> Result<Changeset, ActionError> {
    let mut operations = Vec::new();
    for o in objects {
        let present = o.values("lockoutTime");
        let Some(first) = present.first() else {
            continue;
        };
        if first.as_slice() == b"0" {
            continue;
        }
        operations.push(Operation::modify(
            &o.dn,
            vec![Change::new(
                "lockoutTime",
                vec![first.clone()],
                vec![bytes("0")],
            )?],
            Some(o.read.clone()),
        )?);
    }
    Ok(Changeset {
        operations,
        remarks: Vec::new(),
    })
}

/// New password (« replace » `unicodePwd`) and, by choice, change required (`pwdLastSet` to 0),
/// in the same request (`reinitialiser_mot_de_passe`). The password is neither journaled nor
/// shown.
pub fn reset_password(
    object: &ReadObject,
    password: &str,
    change_at_next_logon: bool,
) -> Result<Changeset, ActionError> {
    let mut changes = vec![Change::new(
        "unicodePwd",
        Vec::new(),
        vec![encode_password(password)?],
    )?];
    let present: Vec<Vec<u8>> = object.values("pwdLastSet").into_iter().take(1).collect();
    let zero = present.first().is_some_and(|v| v.as_slice() == b"0");
    if change_at_next_logon && !zero {
        changes.push(Change::new("pwdLastSet", present, vec![bytes("0")])?);
    } else if !change_at_next_logon && zero {
        changes.push(Change::new("pwdLastSet", present, vec![bytes("-1")])?);
    }
    Ok(Changeset {
        operations: vec![Operation::modify(
            &object.dn,
            changes,
            Some(object.read.clone()),
        )?],
        remarks: Vec::new(),
    })
}

// --- Move, rename, delete ----------------------------------------------------------------------

/// Moves the objects under `parent`; those already there are left aside (`deplacer`).
pub fn move_to(objects: &[ReadObject], parent: &str) -> Result<Changeset, ActionError> {
    let target = dn_key(parent)?;
    let mut operations = Vec::new();
    for o in objects {
        if dn_key(&parent_dn(&o.dn)?)? == target {
            continue;
        }
        let k = dn_key(&o.dn)?;
        if k == target || target.ends_with(&format!(",{k}")) {
            return Err(ActionError::UnderItself(o.dn.clone()));
        }
        let first = dn::split(&o.dn)
            .map_err(|e| ActionError::Change(e.to_string()))?
            .into_iter()
            .next()
            .ok_or(ActionError::EmptyName)?;
        operations.push(Operation::rename(
            &o.dn,
            first,
            Some(parent.to_owned()),
            Some(o.read.clone()),
        )?);
    }
    Ok(Changeset {
        operations,
        remarks: Vec::new(),
    })
}

/// New RDN (`CN=` or `OU=`, after the object) and, by choice, `displayName` and
/// `sAMAccountName` updated in the same changeset (`renommer`).
pub fn rename(
    object: &ReadObject,
    new_name: &str,
    display_name: Option<&str>,
    identifier: Option<&str>,
) -> Result<Changeset, ActionError> {
    let old = dn::split(&object.dn)
        .map_err(|e| ActionError::Change(e.to_string()))?
        .into_iter()
        .next()
        .ok_or(ActionError::EmptyName)?;
    let new_rdn = Component::new(old.attribute.clone(), new_name.trim());
    if new_rdn.value.is_empty() {
        return Err(ActionError::EmptyName);
    }
    let mut operations = Vec::new();
    let mut dn_text = object.dn.clone();
    if new_rdn.value != old.value {
        let op = Operation::rename(&object.dn, new_rdn, None, Some(object.read.clone()))?;
        dn_text = op.dn_after()?;
        operations.push(op);
    }
    let mut changes = Vec::new();
    for (attribute, wanted) in [
        ("displayName", display_name),
        ("sAMAccountName", identifier),
    ] {
        let Some(wanted) = wanted.map(str::trim).filter(|w| !w.is_empty()) else {
            continue;
        };
        let present: Vec<Vec<u8>> = object.values(attribute).into_iter().take(1).collect();
        if present != vec![bytes(wanted)] {
            changes.push(Change::new(attribute, present, vec![bytes(wanted)])?);
        }
    }
    if !changes.is_empty() {
        operations.push(Operation::modify(
            &dn_text,
            changes,
            Some(object.read.clone()),
        )?);
    }
    Ok(Changeset {
        operations,
        remarks: Vec::new(),
    })
}

/// `supprimer`.
pub fn delete(objects: &[ReadObject]) -> Result<Changeset, ActionError> {
    let mut operations = Vec::new();
    for o in objects {
        operations.push(Operation::delete(&o.dn, Some(o.read.clone()), Vec::new())?);
    }
    Ok(Changeset {
        operations,
        remarks: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(dn_text: &str, attributes: &[(&str, &str)]) -> ReadObject {
        ReadObject {
            dn: dn_text.into(),
            attributes: attributes
                .iter()
                .map(|(a, v)| ((*a).to_owned(), vec![bytes(v)]))
                .collect(),
            read: Read {
                dc: "dc1".into(),
                usn: 7,
            },
        }
    }

    #[test]
    fn password_in_utf16() {
        assert_eq!(
            encode_password("é1").unwrap(),
            [0x22, 0, 0xe9, 0, 0x31, 0, 0x22, 0]
        );
        assert!(encode_password("").is_err());
    }

    #[test]
    fn user_created_disabled_without_password() {
        let user = NewUser {
            full_name: "Alice Martin".into(),
            identifier: "alice.martin".into(),
            ..NewUser::default()
        };
        let changeset = create_user("OU=X,DC=lab,DC=test", &user).unwrap();
        let Some(Operation::Add { dn, attributes }) = changeset.operations.first() else {
            panic!("one creation expected");
        };
        assert_eq!(dn, "CN=Alice Martin,OU=X,DC=lab,DC=test");
        assert!(attributes.contains(&("userAccountControl".into(), vec![bytes("514")])));
        let mut active = user.clone();
        active.enable = true;
        assert_eq!(
            create_user("OU=X,DC=lab,DC=test", &active),
            Err(ActionError::ActiveWithoutPassword)
        );
    }

    #[test]
    fn states_and_moves() {
        let a = object(
            "CN=a,OU=X,DC=x",
            &[("userAccountControl", "514"), ("lockoutTime", "0")],
        );
        let b = object(
            "CN=b,OU=Y,DC=x",
            &[("userAccountControl", "512"), ("lockoutTime", "133")],
        );
        assert_eq!(
            enable(&[a.clone(), b.clone()], true)
                .unwrap()
                .operations
                .len(),
            1
        );
        assert_eq!(unlock(&[a.clone(), b.clone()]).unwrap().operations.len(), 1);
        assert_eq!(
            move_to(&[a.clone(), b], "OU=X,DC=x")
                .unwrap()
                .operations
                .len(),
            1
        );
        assert_eq!(
            move_to(&[object("OU=X,DC=x", &[])], "OU=Z,OU=X,DC=x"),
            Err(ActionError::UnderItself("OU=X,DC=x".into()))
        );
        let renamed = rename(&a, "a2", Some("a2"), None).unwrap();
        assert_eq!(renamed.operations.len(), 2);
        assert_eq!(
            renamed.operations.get(1).map(Operation::dn),
            Some("CN=a2,OU=X,DC=x")
        );
    }
}

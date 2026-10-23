// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The texts of the core in the language of the interface: the preview of a changeset and the
//! remarks of an inverse (`Msg`), the messages of the writer (`WriteMsg`) and its LDAP errors.
//! The English source is the one the Python version 1.0 had in `po/en.po`, so that the French
//! came back word for word.

use annuaire_core::changes::ErrorRecord;
use annuaire_core::error::LdapError;
use annuaire_core::messages::{Catalog, Msg};
use annuaire_core::sysvol::SysvolError;
use annuaire_core::writer::{WriteCatalog, WriteMsg};

use crate::errors;
use crate::i18n::{fill, tr, tr_n};

/// The catalogue of the application, for the core.
#[derive(Debug, Clone, Copy, Default)]
pub struct AppCatalog;

impl Catalog for AppCatalog {
    fn text(&self, msg: &Msg) -> String {
        match msg {
            Msg::Masked => tr("<hidden>"),
            Msg::QuotedWithDate { text, date } => fill(
                &tr("“{texte}” ({date})"),
                &[("texte", text), ("date", date)],
            ),
            Msg::Quoted { text } => fill(&tr("“{texte}”"), &[("texte", text)]),
            Msg::Hex { bytes, more, n } => fill(
                &tr("0x{octets}{suite} ({n} bytes)"),
                &[("octets", bytes), ("suite", more), ("n", &n.to_string())],
            ),
            Msg::Never => tr("never"),
            Msg::Ttl { ttl } => fill(&tr("TTL {ttl}"), &[("ttl", &ttl.to_string())]),
            Msg::Serial { serial } => {
                fill(&tr("serial {serie}"), &[("serie", &serial.to_string())])
            }
            Msg::Rank { rank } => fill(&tr("rank {rang}"), &[("rang", rank)]),
            Msg::Dynamic => tr("dynamic"),
            Msg::Replace {
                attribute,
                before,
                after,
            } => fill(
                &tr("{attribut}: {avant} → {apres}"),
                &[("attribut", attribute), ("avant", before), ("apres", after)],
            ),
            Msg::Removed { attribute, value } => fill(
                &tr("{attribut}: − {valeur}"),
                &[("attribut", attribute), ("valeur", value)],
            ),
            Msg::Added { attribute, value } => fill(
                &tr("{attribut}: + {valeur}"),
                &[("attribut", attribute), ("valeur", value)],
            ),
            Msg::Bytes { n } => fill(&tr("{n} bytes"), &[("n", &n.to_string())]),
            Msg::CreateFolder { path } => fill(&tr("Create folder {chemin}"), &[("chemin", path)]),
            Msg::DeleteFolder { path } => fill(&tr("Delete folder {chemin}"), &[("chemin", path)]),
            Msg::CreateFile { path } => fill(&tr("Create file {chemin}"), &[("chemin", path)]),
            Msg::ReplaceFile { path } => fill(&tr("Replace file {chemin}"), &[("chemin", path)]),
            Msg::DeleteFile { path } => fill(&tr("Delete file {chemin}"), &[("chemin", path)]),
            Msg::SetPermissions { path } => {
                fill(&tr("Change permissions of {chemin}"), &[("chemin", path)])
            }
            Msg::AddShare { unc } => fill(&tr("Create share {partage}"), &[("partage", unc)]),
            Msg::ChangeShare { unc } => fill(&tr("Change share {partage}"), &[("partage", unc)]),
            Msg::DeleteShare { unc } => fill(&tr("Delete share {partage}"), &[("partage", unc)]),
            Msg::DeleteShareKeepsFolder => tr("The folder and its content stay on the server."),
            Msg::Propagate { path } => fill(
                &tr("Propagate the inheritance under {chemin}"),
                &[("chemin", path)],
            ),
            Msg::PropagationCount { n } => fill(
                &tr_n(
                    "{n} element under the folder examined",
                    "{n} elements under the folder examined",
                    *n as u64,
                ),
                &[("n", &n.to_string())],
            ),
            Msg::PropagationReplace => tr(
                "The permissions of every descendant are replaced by the inherited ones (explicit entries removed, inheritance turned on again).",
            ),
            Msg::PropagateOwner { path } => {
                fill(&tr("Replace the owner under {chemin}"), &[("chemin", path)])
            }
            Msg::PropagationOwner { owner } => fill(
                &tr("owner of every element under the folder: {proprietaire}"),
                &[("proprietaire", owner)],
            ),
            Msg::PropagateAudit { path } => fill(
                &tr("Propagate the auditing entries under {chemin}"),
                &[("chemin", path)],
            ),
            Msg::PropagationAudit { replace: false } => {
                tr("auditing entries inherited computed again")
            }
            Msg::PropagationAudit { replace: true } => {
                tr("auditing entries of every descendant replaced by the inherited ones")
            }
            Msg::PropagationBackup { file } => fill(&tr("backup: {fichier}"), &[("fichier", file)]),
            Msg::PropagationRewrite { path, undo: true } => fill(
                &tr("Write back the permissions saved under {chemin}"),
                &[("chemin", path)],
            ),
            Msg::PropagationRewrite { path, undo: false } => fill(
                &tr("Write again the permissions propagated under {chemin}"),
                &[("chemin", path)],
            ),
            Msg::SharePath { path } => fill(&tr("path: {chemin}"), &[("chemin", path)]),
            Msg::ShareRemark { remark } => {
                fill(&tr("comment: {commentaire}"), &[("commentaire", remark)])
            }
            Msg::ShareMaxUses { n } => fill(
                &tr_n(
                    "at most {n} connection",
                    "at most {n} connections",
                    u64::from(*n),
                ),
                &[("n", &n.to_string())],
            ),
            Msg::ShareFlags { flags } => fill(
                &tr("options: {options}"),
                &[("options", &crate::share_views::flags_text(*flags))],
            ),
            Msg::Create { dn } => fill(&tr("Create {dn}"), &[("dn", dn)]),
            Msg::NoVersionCheck => tr("(without version check)"),
            Msg::Modify { dn } => fill(&tr("Modify {dn}"), &[("dn", dn)]),
            Msg::Rename { dn, new_dn } => fill(
                &tr("Rename or move {dn} → {nouveau}"),
                &[("dn", dn), ("nouveau", new_dn)],
            ),
            Msg::Delete { dn } => fill(&tr("Delete {dn}"), &[("dn", dn)]),
            Msg::DeleteIrreversible => tr(
                "Cannot be undone exactly: undoing recreates a new object (new objectGUID and objectSid, password and permissions not restored).",
            ),
            Msg::NoChange => tr("No change."),
            Msg::Remarks => tr("Notes:"),
            Msg::SecretNotRestored { attribute } => fill(
                &tr("{attribut}: previous value unknown (secret), not restored."),
                &[("attribut", attribute)],
            ),
            Msg::PwdLastSetNow => {
                tr("pwdLastSet: the previous date cannot be restored, it becomes “now”.")
            }
            Msg::RecreatedWithPermissions { dn } => fill(
                &tr(
                    "{dn} will be recreated as a new object (new objectGUID), with its original permissions.",
                ),
                &[("dn", dn)],
            ),
            Msg::RecreatedNew { dn } => fill(
                &tr(
                    "{dn} will be recreated as a new object: new objectGUID and objectSid; permissions that referred to the old SID, the security descriptor, the password and the primary group are not restored.",
                ),
                &[("dn", dn)],
            ),
            Msg::SecretNotJournaled { attribute } => fill(
                &tr("{attribut}: secret not logged, not restored."),
                &[("attribut", attribute)],
            ),
            Msg::RecreatedDisabled { dn } => fill(
                &tr("{dn} will be recreated disabled: its password is lost."),
                &[("dn", dn)],
            ),
            Msg::DnsZone { zone } => fill(&tr("Zone {zone}: "), &[("zone", zone)]),
            Msg::DnsSerial { before, after } => fill(
                &tr(
                    "serial number {avant} → {apres}. If it changes before the write (another write in the zone), the tool reads it again and starts over.",
                ),
                &[
                    ("avant", &before.to_string()),
                    ("apres", &after.to_string()),
                ],
            ),
            Msg::DnsSoaNotWritable { serial } => fill(
                &tr(
                    "your account cannot modify the SOA: the records are written without incrementing the serial number ({serie}). The DCs replicate the zone without using it; a conventional secondary server (zone transfer) will only see the change at an administrator's next write.",
                ),
                &[("serie", &serial.to_string())],
            ),
            Msg::DnsBackInService { name } => fill(
                &tr("{nom} was a tombstone: it is brought back into service."),
                &[("nom", name)],
            ),
            Msg::DnsTombstoned { name } => fill(
                &tr(
                    "{nom}: last record removed, the name becomes a tombstone (the object stays in the directory, as with the DNS server).",
                ),
                &[("nom", name)],
            ),
            Msg::DnsSoaNotRestored => {
                tr("The SOA serial number is not restored: it is incremented again.")
            }
            Msg::DnsUndoCreation { name } => fill(
                &tr(
                    "{nom}: undoing its creation turns it into a tombstone instead of deleting the object, which the Windows DNS server would not see disappear.",
                ),
                &[("nom", name)],
            ),
            Msg::GpoCreated { name, guid } => fill(
                &tr("GPO “{nom}”: {guid}, not linked; link it afterwards to a domain or an OU."),
                &[("nom", name), ("guid", guid)],
            ),
            Msg::GpoAclReset { name, n } => fill(
                &tr(
                    "Permissions of the “{nom}” folder reset from those of the GPO, on {n} item(s), like samba-tool ntacl sysvolreset.",
                ),
                &[("nom", name), ("n", &n.to_string())],
            ),
            Msg::GpoNobodyApplies => {
                tr("No account or group applies this GPO any more: it applies to nobody.")
            }
            Msg::GpoAuthenticatedUsersCannotRead => tr(
                "Authenticated Users can no longer read the GPO: since MS16-072, computers read user GPOs under their own account, and a GPO they cannot read is not applied. Leave them at least Read (or give it to Domain Computers).",
            ),
            Msg::GpoDeleted {
                name,
                guid,
                links,
                items,
            } => fill(
                &tr("GPO “{nom}” ({guid}): {n} link(s) removed, {k} SYSVOL item(s)."),
                &[
                    ("nom", name),
                    ("guid", guid),
                    ("n", &links.to_string()),
                    ("k", &items.to_string()),
                ],
            ),
            Msg::GpoFolderAbsent => tr("The GPO folder is missing from this DC's SYSVOL."),
            Msg::GpoOrphansRemoved { list } => fill(
                &tr(
                    "SYSVOL folders without a GPO in the directory (interrupted creation or deletion): {liste}. Undoing puts them back as they were.",
                ),
                &[("liste", list)],
            ),
            Msg::GpoOrphanDeleted { name, dc, items } => fill(
                &tr(
                    "Folder without a GPO “{nom}”: no Group Policy Object in the directory has this GUID (read again on {dc}). {k} item(s) deleted with their contents and permissions; undoing recreates them exactly.",
                ),
                &[("nom", name), ("dc", dc), ("k", &items.to_string())],
            ),
            Msg::GpoOrphanLinks { n } => fill(
                &tr(
                    "{n} container(s) keep a link to this GUID: they are not changed (link to a missing GPO).",
                ),
                &[("n", &n.to_string())],
            ),
            Msg::GpoCopy { name, old, guid } => fill(
                &tr("Copy of “{nom}” ({ancien}) under a new GUID: {guid}."),
                &[("nom", name), ("ancien", old), ("guid", guid)],
            ),
            Msg::GpoRecreated { name, guid, date } => fill(
                &tr("GPO “{nom}” recreated under its GUID {guid}, from the backup of {date}."),
                &[("nom", name), ("guid", guid), ("date", date)],
            ),
            Msg::GpoBackupLinks { links } => fill(
                &tr("Links at the time of the backup (not restored, like the GPMC): {liens}."),
                &[("liens", links)],
            ),
            Msg::GpoRestored {
                name,
                date,
                version,
                user,
                computer,
            } => {
                let detail = fill(
                    &tr("user {u}, computer {o}"),
                    &[("u", &user.to_string()), ("o", &computer.to_string())],
                );
                fill(
                    &tr(
                        "GPO “{nom}” brought back to its backup of {date}; version raised to {v} ({detail}) so that computers apply it again.",
                    ),
                    &[
                        ("nom", name),
                        ("date", date),
                        ("v", &version.to_string()),
                        ("detail", &detail),
                    ],
                )
            }
            Msg::GpoContentVersion {
                part,
                name,
                before,
                after,
            } => fill(
                &tr(
                    "{partie} of “{nom}”: version {avant} → {apres}, in the directory and GPT.INI.",
                ),
                &[
                    ("partie", &crate::preference_views::part_name(*part)),
                    ("nom", name),
                    ("avant", &before.to_string()),
                    ("apres", &after.to_string()),
                ],
            ),
            Msg::GpoPartDisabled { part } => fill(
                &tr(
                    "The {partie} of this GPO is disabled: this setting will not apply as long as it stays disabled.",
                ),
                &[(
                    "partie",
                    &crate::preference_views::part_name(*part).to_lowercase(),
                )],
            ),
            Msg::GpoVersionsDiffered { directory, sysvol } => {
                let versions = |v: i64| {
                    let v = annuaire_core::gpo::versions(v);
                    fill(
                        &tr("user {u}, computer {o}"),
                        &[("u", &v.user.to_string()), ("o", &v.computer.to_string())],
                    )
                };
                fill(
                    &tr(
                        "The directory version ({a}) and the GPT.INI version ({s}) differed: the higher one was used, both are equal again.",
                    ),
                    &[("a", &versions(*directory)), ("s", &versions(*sysvol))],
                )
            }
            Msg::GpoSecurityNotAtRoot => tr(
                "This GPO is not linked to the root of the domain: its password and lockout policy only governs the local accounts of the computers it applies to, not domain accounts.",
            ),
            Msg::GpoSecurityPdcApplies => tr(
                "Linked to the root of the domain: the PDC emulator will carry the account policy over to the domain object at its next security policy refresh.",
            ),
            Msg::GpoSecuritySamba => tr(
                "Samba does not apply a GPO's account policy by itself: the domain object receives the same values, as samba-tool domain passwordsettings set would do.",
            ),
            Msg::GpoSecurityPrior { names, keys } => fill(
                &tr(
                    "Also defined by a higher-precedence GPO linked to the domain ({noms}), these settings stay as the domain object has them: {reglages}.",
                ),
                &[
                    ("noms", names),
                    (
                        "reglages",
                        &keys
                            .iter()
                            .map(|k| crate::gpo_security_views::setting_title(k))
                            .collect::<Vec<_>>()
                            .join(", "),
                    ),
                ],
            ),
        }
    }
}

impl WriteCatalog for AppCatalog {
    fn write_text(&self, msg: &WriteMsg) -> String {
        match msg {
            WriteMsg::Missing { dn } => fill(&tr("“{dn}” does not exist."), &[("dn", dn)]),
            WriteMsg::ReadOnDc { dn, read, dc } => fill(
                &tr("“{dn}” was read on {lu}, the connection is on {dc}: read it again."),
                &[("dn", dn), ("lu", read), ("dc", dc)],
            ),
            WriteMsg::ChangedSincePreview { dn, read, usn } => fill(
                &tr("“{dn}” has been modified since the preview (uSNChanged {lu} → {usn})."),
                &[
                    ("dn", dn),
                    ("lu", &read.to_string()),
                    ("usn", &usn.to_string()),
                ],
            ),
            WriteMsg::ContainerMissing { parent } => fill(
                &tr("The container “{parent}” does not exist."),
                &[("parent", parent)],
            ),
            WriteMsg::ClassNotAllowed { class, parent } => fill(
                &tr("Creating a {classe} object in “{parent}” is not allowed."),
                &[("classe", class), ("parent", parent)],
            ),
            WriteMsg::AttributesRefused { attributes, dn } => fill(
                &tr("Write access denied on {attributs} of “{dn}”."),
                &[("attributs", attributes), ("dn", dn)],
            ),
            WriteMsg::AlreadyExists { dn } => fill(&tr("“{dn}” already exists."), &[("dn", dn)]),
            WriteMsg::ValuesNotAsExpected { dn } => fill(
                &tr(
                    "“{dn}”: a value to remove is no longer there, or a value to add is already there or is not valid for this attribute.",
                ),
                &[("dn", dn)],
            ),
            WriteMsg::NameTaken { dn } => fill(&tr("“{dn}” is already taken."), &[("dn", dn)]),
            WriteMsg::NotLeaf { dn } => fill(
                &tr("“{dn}” contains objects: delete them first."),
                &[("dn", dn)],
            ),
            WriteMsg::NothingWritten { n } => fill(
                &tr("Nothing was written: {n} problem(s) found before the first write."),
                &[("n", &n.to_string())],
            ),
            WriteMsg::ExistsOrSameIdentifier { dn } => fill(
                &tr("“{dn}” already exists, or another object has the same identifier."),
                &[("dn", dn)],
            ),
            WriteMsg::ChangedReadAgain { dn } => fill(
                &tr("“{dn}” has changed since the preview: read it again before trying again."),
                &[("dn", dn)],
            ),
            WriteMsg::ReadOnOtherDc { dn } => fill(
                &tr("“{dn}” was read on another domain controller: read it again."),
                &[("dn", dn)],
            ),
            WriteMsg::NoLongerExists { dn } => fill(&tr("“{dn}” no longer exists."), &[("dn", dn)]),
            WriteMsg::ModifiedReadAgain { dn } => fill(
                &tr("“{dn}” has been modified since the preview: read it again."),
                &[("dn", dn)],
            ),
            WriteMsg::NotInWantedState { dn } => fill(
                &tr(
                    "The server accepted the write, but “{dn}”, read again, is not in the expected state.",
                ),
                &[("dn", dn)],
            ),
            WriteMsg::StillExists { dn } => fill(
                &tr("The server accepted the deletion, but “{dn}” still exists."),
                &[("dn", dn)],
            ),
            WriteMsg::NoVersion => tr("The server does not report the object's version."),
            WriteMsg::JournalNotWritten => tr("The change log could not be written."),
            WriteMsg::JournalNothingModified => {
                tr("The change log could not be written: nothing was modified.")
            }
            WriteMsg::ReadOnly { domain } => fill(
                &tr("The profile of “{domaine}” is read-only: no writes."),
                &[("domaine", domain)],
            ),
            WriteMsg::NotOnPdc { pdc, dc } => fill(
                &tr(
                    "GPOs are written on the PDC emulator ({pdc}), which is not responding: the write connection has moved to {dc}, whose SYSVOL is not the PDC's. Try again when the PDC responds, or set a write DC in the profile.",
                ),
                &[("pdc", pdc), ("dc", dc)],
            ),
            WriteMsg::SysvolExists { path } => fill(&tr("“{c}” already exists."), &[("c", path)]),
            WriteMsg::SysvolFolderMissing { parent } => fill(
                &tr("The folder “SYSVOL\\{p}” does not exist."),
                &[("p", parent)],
            ),
            WriteMsg::SysvolMissing { path } => fill(&tr("“{c}” does not exist."), &[("c", path)]),
            WriteMsg::SysvolNotA { path, folder } => {
                let kind = if *folder { tr("folder") } else { tr("file") };
                fill(
                    &tr("“{c}” is not a {genre}."),
                    &[("c", path), ("genre", &kind)],
                )
            }
            WriteMsg::SysvolContentChanged { path } => fill(
                &tr("“{c}”: {quoi} has changed since the preview."),
                &[("c", path), ("quoi", &tr("the content"))],
            ),
            WriteMsg::SysvolPermissionsChanged { path } => fill(
                &tr("“{c}”: the permissions have changed since the preview."),
                &[("c", path)],
            ),
            WriteMsg::SysvolNotEmpty { path } => {
                fill(&tr("The folder “{c}” is not empty."), &[("c", path)])
            }
            WriteMsg::SysvolNotReread { path } => fill(
                &tr("The SYSVOL accepted the write, but “{c}” could not be read again."),
                &[("c", path)],
            ),
            WriteMsg::SysvolChangedReadAgain { path } => fill(
                &tr("“{c}” has changed since the preview: read it again before trying again."),
                &[("c", path)],
            ),
            WriteMsg::SysvolNotInState { path } => fill(
                &tr(
                    "The SYSVOL accepted the write, but “{c}”, read again, is not in the expected state.",
                ),
                &[("c", path)],
            ),
            WriteMsg::SysvolModified { path } => fill(
                &tr("“{c}” has been modified since the preview: read it again."),
                &[("c", path)],
            ),
            WriteMsg::SysvolNoLongerExists { path } => {
                fill(&tr("“{c}” no longer exists."), &[("c", path)])
            }
            WriteMsg::ShareExists { unc } => {
                fill(&tr("The share “{p}” already exists."), &[("p", unc)])
            }
            WriteMsg::ShareMissing { unc } => {
                fill(&tr("The share “{p}” no longer exists."), &[("p", unc)])
            }
            WriteMsg::ShareChanged { unc } => fill(
                &tr("The share “{p}” has changed since the preview: read it again."),
                &[("p", unc)],
            ),
            WriteMsg::ShareNotInState { unc } => fill(
                &tr(
                    "The server accepted the change, but the share “{p}”, read again, is not in the expected state.",
                ),
                &[("p", unc)],
            ),
            WriteMsg::ShareOptionsKept { unc } => fill(
                &tr(
                    "The server accepted the change of the share “{p}” but kept its own options or connection limit: this share is defined in smb.conf, which Calinda does not write (it writes those of Samba's registry configuration).",
                ),
                &[("p", unc)],
            ),
            WriteMsg::ShareRegistryIgnored { unc } => fill(
                &tr(
                    "Samba does not serve the share “{p}” written in its registry configuration: the server does not read its shares there (registry shares, include = registry). The key written was removed.",
                ),
                &[("p", unc)],
            ),
            WriteMsg::FileNotInState { path } => fill(
                &tr(
                    "The server accepted the change, but “{c}”, read again, does not have the expected permissions.",
                ),
                &[("c", path)],
            ),
            WriteMsg::BackupUnusable { file } => fill(
                &tr("The backup of the propagation “{f}” cannot be written or read."),
                &[("f", file)],
            ),
            WriteMsg::OwnerRefused { path, status } => crate::errors::owner_refusal(*status, path),
            WriteMsg::AuditRefused { path, status } => crate::errors::audit_refusal(*status, path),
        }
    }

    fn share_error(&self, error: &annuaire_core::srvsvc::Error, server: &str) -> ErrorRecord {
        let problem = errors::share_problem(error, server);
        ErrorRecord {
            class: "ErreurPartage".into(),
            message: problem.message,
            detail: problem.detail,
        }
    }

    fn ldap_error(&self, error: &LdapError, dc: &str) -> ErrorRecord {
        let problem = errors::ldap_problem(error, dc);
        ErrorRecord {
            class: "ErreurLDAP".into(),
            message: problem.message,
            detail: problem.detail,
        }
    }

    fn sysvol_error(&self, error: &SysvolError, dc: &str) -> ErrorRecord {
        let (class, problem) = errors::sysvol_problem(error, dc);
        ErrorRecord {
            class: class.into(),
            message: problem.message,
            detail: problem.detail,
        }
    }

    fn file_error(&self, error: &SysvolError, server: &str) -> ErrorRecord {
        let (class, _) = errors::sysvol_problem(error, server);
        let problem = errors::file_problem(error, server);
        ErrorRecord {
            class: class.into(),
            message: problem.message,
            detail: problem.detail,
        }
    }
}

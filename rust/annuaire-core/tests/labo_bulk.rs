// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Import, export and changes in bulk against the lab (J9.8, J9.9, ADR 0026), on LAB.TEST and
//! WIN.TEST, under `OU=Essais-J98,OU=Labo` (removed at the end):
//!
//! - `import_thousand`: a file of 1,000 users (accents, multivalued attribute, generated
//!   passwords, a tenth joining a group) checked, imported by batches, read back (values,
//!   `userAccountControl`, change at the next logon, group, passwords known to the KDC),
//!   exported and read again, then undone in one go from the journal. On WIN.TEST, the same
//!   file imported by `New-ADUser` in `OU=Essais-J98-PS,OU=Labo` and compared account by account;
//! - `import_errors`: a file with errors on purpose, the report expected line by line, nothing
//!   written; its valid lines (a user, a group, a contact, a computer) imported then undone;
//! - `bulk_five_hundred`: 500 accounts changed (description set, group joined, disabled,
//!   moved), each change stopped after two batches, resumed, then undone in one go; a series
//!   whose object disappeared stops on the refused batch and resumes without it.
//!
//! The times are printed (`MESURE`). Passwords never shown: given to `kinit` on its standard
//! input, or to PowerShell by `poste_secret`.

#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Instant;

use annuaire_core::actions;
use annuaire_core::bulk::{self, Control, End, Run};
use annuaire_core::changes::Issue;
use annuaire_core::computers;
use annuaire_core::export;
use annuaire_core::import::{self, Kind, Options, Problem, Unique};
use annuaire_core::mass::{self, Change};
use annuaire_core::schema::{self, AttributeDescription, Syntax};
use annuaire_core::session::Scope;
use annuaire_core::writer::{self, WriteCatalog};

use labo::{Kdc, Result, Trial, check, debug, entries, text};

const OU: &str = "Essais-J98";
const PS_OU: &str = "Essais-J98-PS";
const GROUP: &str = "J98-Groupe";

fn catalog() -> Arc<dyn WriteCatalog> {
    Arc::new(labo::Texts)
}

/// The reading of a value in the trials: integers and booleans checked, the rest as typed.
fn reader(d: &AttributeDescription, value: &str) -> std::result::Result<Vec<u8>, String> {
    match d.syntax {
        Syntax::Integer | Syntax::Enumeration | Syntax::LargeInteger => value
            .trim()
            .parse::<i64>()
            .map(|n| n.to_string().into_bytes())
            .map_err(|_| "integer expected".to_owned()),
        Syntax::Boolean => match value.trim().to_uppercase().as_str() {
            "TRUE" | "FALSE" => Ok(value.trim().to_uppercase().into_bytes()),
            _ => Err("TRUE or FALSE expected".into()),
        },
        _ => {
            let n = i64::try_from(value.chars().count()).unwrap_or(i64::MAX);
            if d.upper.is_some_and(|u| n > u) {
                return Err("too long".into());
            }
            Ok(value.as_bytes().to_vec())
        }
    }
}

fn user_line(n: usize, group: &str) -> Vec<String> {
    let given = ["Élodie", "Jérôme", "Maëlle", "François", "Anaïs"][n % 5];
    vec![
        format!("{given} Essai{n:04}"),
        format!("j98.u{n:04}"),
        given.to_owned(),
        format!("Essai{n:04}"),
        format!("j98.u{n:04}@{{domaine}}"),
        format!("Import J9.8 ; ligne {n}"),
        format!(
            "0596 00 {:02} {:02}|0696 00 {:02} {:02}",
            n / 100,
            n % 100,
            n / 100,
            n % 100
        ),
        format!("{}", 10_000 + n),
        if n % 10 == 0 {
            group.to_owned()
        } else {
            String::new()
        },
    ]
}

const USER_HEADER: [&str; 9] = [
    "Name",
    "SamAccountName",
    "GivenName",
    "sn",
    "UserPrincipalName",
    "description",
    "otherTelephone",
    "employeeNumber",
    "memberOf",
];

fn users_file(count: usize, domain: &str) -> String {
    let rows: Vec<Vec<String>> = (1..=count)
        .map(|n| {
            user_line(n, GROUP)
                .into_iter()
                .map(|f| f.replace("{domaine}", domain))
                .collect()
        })
        .collect();
    annuaire_codecs::csv::write(&USER_HEADER, &rows, ';', true)
}

/// Writes a run to its end; the series is stopped after `stop_after` batches if given.
fn write(trial: &Trial, run: &mut Run, stop_after: Option<usize>) -> End {
    let control = Control::new();
    if let Some(n) = stop_after {
        control.stop_after(n);
    }
    run.write(
        &trial.connection,
        &trial.profile,
        &trial.journal,
        &catalog(),
        &control,
    )
}

/// Undoes the series `id` from the journal, in one run; the time taken. The objects in
/// `changed` (written by the KDC since) are refused first, then written over.
fn undo_series(trial: &Trial, id: &str, changed: &[String]) -> Result<f64> {
    let reports = writer::read_journal(&trial.journal);
    let mut run =
        bulk::undo(&reports, &trial.profile.domain, id, "undo", &labo::Texts).map_err(debug)?;
    let start = Instant::now();
    let mut end = write(trial, &mut run, None);
    if matches!(end, End::Failed) && !changed.is_empty() {
        let named = run.changed_since();
        check(
            !named.is_empty() && named.iter().all(|n| changed.contains(n)),
            &format!("undo refused for accounts the KDC changed since the import ({named:?})"),
        )?;
        run.refresh(&trial.connection, &named).map_err(debug)?;
        end = write(trial, &mut run, None);
    }
    let seconds = start.elapsed().as_secs_f64();
    if let Some(last) = run
        .outcomes
        .last()
        .filter(|_| !matches!(end, End::Finished))
    {
        println!(
            "  {:?} {:?}",
            last.report.error,
            last.problems.iter().take(3).collect::<Vec<_>>()
        );
    }
    check(
        matches!(end, End::Finished),
        &format!("series {id} undone ({end:?})"),
    )?;
    let after = writer::read_journal(&trial.journal);
    let left = bulk::of_series(&after, &trial.profile.domain, id);
    check(left.is_empty(), "no batch of the series left to undo")?;
    Ok(seconds)
}

fn count(trial: &Trial, base: &str, filter: &str) -> Result<usize> {
    Ok(entries(&trial.connection, base, Scope::Subtree, filter, &["1.1"])?.len())
}

/// Removes `ou` and what it holds. The leaves go first by changesets of 200: Windows answers
/// at most 1,000 entries to a search that is not paged (`MaxPageSize`), and the check of a
/// deletion that is not a leaf would see more children than it may.
fn clear(trial: &Trial, ou: &str) -> Result<()> {
    if !trial.exists(ou)? {
        return Ok(());
    }
    let mut leaves: Vec<String> = entries(
        &trial.connection,
        ou,
        Scope::Subtree,
        "(!(objectClass=organizationalUnit))",
        &["1.1"],
    )?
    .into_iter()
    .map(|e| e.dn)
    .collect();
    leaves.sort_by_key(|d| std::cmp::Reverse(labo::depth(d)));
    for chunk in leaves.chunks(200) {
        let names: Vec<&str> = chunk.iter().map(String::as_str).collect();
        trial.apply(&actions::delete(&trial.read(&names)?).map_err(debug)?)?;
    }
    trial.remove_tree(ou)
}

/// The OU of the trials and its group, fresh.
fn prepare(trial: &Trial) -> Result<(String, String)> {
    let parent = format!("OU=Labo,{}", trial.base);
    clear(trial, &format!("OU={OU},{parent}"))?;
    let ou = trial.fresh_ou(&parent, OU)?;
    trial.apply(
        &actions::create_group(
            &ou,
            GROUP,
            GROUP,
            annuaire_codecs::uac::Scope::Global,
            true,
            "J9.8",
        )
        .map_err(debug)?,
    )?;
    Ok((ou.clone(), format!("CN={GROUP},{ou}")))
}

#[test]
#[ignore = "lab: needs the DCs of the lab and an administrator ticket"]
fn import_thousand() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j98-import")?;
    let trial = Trial::new(&lab, &scratch)?;
    let (ou, group) = prepare(&trial)?;
    let schema = schema::read_schema(&trial.connection).map_err(debug)?;
    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let file = users_file(1000, &lab.domain);
    let options = Options {
        parent: ou.clone(),
        ..Options::default()
    };

    let start = Instant::now();
    let checked = import::check(
        &trial.connection,
        file.as_bytes(),
        &schema,
        &HashMap::new(),
        &options,
        &reader,
        &rule,
    )
    .map_err(debug)?;
    let checking = start.elapsed().as_secs_f64();
    check(
        checked.lines.len() == 1000 && checked.refused() == 0,
        "1,000 lines, none refused",
    )?;
    check(checked.generated.len() == 1000, "1,000 passwords generated")?;
    let chosen: Vec<usize> = (0..checked.items.len()).collect();
    let batches = bulk::batches(&checked.items, &chosen, bulk::BATCH_SIZE, &[]).map_err(debug)?;
    check(batches.len() == 10, "ten batches")?;
    let mut run = Run::new("Import j98.csv", batches);
    let start = Instant::now();
    let end = write(&trial, &mut run, None);
    let importing = start.elapsed().as_secs_f64();
    check(
        matches!(end, End::Finished),
        &format!("import finished ({end:?})"),
    )?;
    println!(
        "MESURE {} : vérification de 1 000 lignes {checking:.1} s, import {importing:.1} s",
        lab.domain
    );

    // Read back.
    let users = count(&trial, &ou, "(&(objectCategory=person)(objectClass=user))")?;
    check(
        users == 1000,
        &format!("1,000 users under the OU ({users})"),
    )?;
    let members = entries(
        &trial.connection,
        &group,
        Scope::Base,
        "(objectClass=*)",
        &["member"],
    )?;
    let n = members.first().map_or(0, |e| e.values("member").len());
    check(n == 100, &format!("100 members of the group ({n})"))?;
    let sample = format!("CN=Anaïs Essai0004,{ou}");
    let e = labo::entry(
        &trial.connection,
        &sample,
        &[
            "userAccountControl",
            "pwdLastSet",
            "otherTelephone",
            "description",
            "givenName",
            "userPrincipalName",
        ],
        None,
    )?
    .ok_or("sample absent")?;
    check(
        text(&e, "userAccountControl") == "512",
        "enabled, as New-ADUser -Enabled",
    )?;
    check(text(&e, "pwdLastSet") == "0", "change at the next logon")?;
    check(
        e.values("otherTelephone").len() == 2,
        "two values of otherTelephone",
    )?;
    check(
        text(&e, "description") == "Import J9.8 ; ligne 4",
        "description with the separator",
    )?;
    // The passwords given to the administrator are those of the DC: expired (change required),
    // not refused.
    let kdc = Kdc::new(&lab, &trial.dc)?;
    for g in checked.generated.iter().take(3) {
        let refusal = kdc.refusal(&format!("{}@{}", g.identifier, lab.realm()), &g.password);
        let expired = refusal
            .as_deref()
            .is_some_and(|r| r.to_lowercase().contains("expired"));
        check(
            expired,
            &format!("password of {} known to the KDC (expired)", g.identifier),
        )?;
    }

    // Export of the OU, read again by the import's reader of files.
    let dns: Vec<String> = entries(
        &trial.connection,
        &ou,
        Scope::OneLevel,
        "(objectClass=user)",
        &["1.1"],
    )?
    .into_iter()
    .map(|e| e.dn)
    .collect();
    let columns: Vec<export::Column> = [
        "dn",
        "sAMAccountName",
        "objectSid",
        "whenCreated",
        "otherTelephone",
        "pwdLastSet",
    ]
    .iter()
    .map(|c| export::Column::named(c))
    .collect();
    let start = Instant::now();
    let names: Vec<String> = columns.iter().map(|c| c.attribute.clone()).collect();
    let read = export::read(&trial.connection, &dns, &names).map_err(debug)?;
    let out = export::write(
        &read,
        &columns,
        &schema,
        &export::Options::default(),
        &export::utc_date,
    );
    let exporting = start.elapsed().as_secs_f64();
    let table = annuaire_codecs::csv::read(out.text.as_bytes(), None).map_err(debug)?;
    check(
        table.records.len() == 1001,
        "export: a header and 1,000 rows",
    )?;
    check(
        table
            .records
            .iter()
            .skip(1)
            .all(|r| r.fields.get(2).is_some_and(|s| s.starts_with("S-1-5-21-"))),
        "export: SIDs readable",
    )?;
    println!(
        "MESURE {} : export de 1 000 comptes {exporting:.1} s",
        lab.domain
    );

    // On WIN.TEST, the accounts as `Get-ADUser` reads them, for the comparison with New-ADUser
    // once this import is undone (the identifiers and UPN must be free for it).
    let snapshot = if lab.windows() {
        Some(accounts(
            &labo::poste(&listing(&ou), &["--cible", "wdc"])?,
            &ou,
        ))
    } else {
        None
    };

    let tried: Vec<String> = checked
        .generated
        .iter()
        .take(3)
        .map(|g| g.dn.clone())
        .collect();
    let undoing = undo_series(&trial, &run.id, &tried)?;
    println!(
        "MESURE {} : annulation de l'import {undoing:.1} s",
        lab.domain
    );
    let users = count(&trial, &ou, "(objectClass=user)")?;
    check(users == 0, "every account of the import removed")?;
    let members = entries(
        &trial.connection,
        &group,
        Scope::Base,
        "(objectClass=*)",
        &["member"],
    )?;
    check(
        members
            .first()
            .is_some_and(|e| e.values("member").is_empty()),
        "group empty again",
    )?;
    if let Some(calinda) = snapshot {
        compare_new_aduser(&trial, &calinda, &file)?;
    }
    trial.remove_tree(&ou)
}

/// The PowerShell that lists the accounts of `base` as `COMPTE=base|sam|…`.
fn listing(base: &str) -> String {
    format!(
        r#"Get-ADUser -SearchBase '{base}' -SearchScope OneLevel -Filter * -Properties userAccountControl,pwdLastSet,otherTelephone,employeeNumber,description,givenName,sn,userPrincipalName,memberOf,objectClass |
  ForEach-Object {{ "COMPTE=$($_.SamAccountName)|$($_.userAccountControl)|$($_.pwdLastSet)|$(($_.otherTelephone | Sort-Object) -join ',')|$($_.employeeNumber)|$($_.description)|$($_.givenName)|$($_.sn)|$($_.userPrincipalName)|$($_.memberOf.Count)|$($_.objectClass -join ',')" }}
"#
    )
}

/// The accounts of a listing, by `sAMAccountName`.
fn accounts(output: &str, _base: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|l| l.trim().strip_prefix("COMPTE="))
        .filter_map(|l| l.split_once('|'))
        .map(|(sam, rest)| (sam.to_owned(), rest.to_owned()))
        .collect()
}

/// The same file by `Import-Csv | New-ADUser` (one password for all, the change required) in
/// its own OU, its accounts compared with those Calinda created (`calinda`), then removed.
fn compare_new_aduser(trial: &Trial, calinda: &BTreeMap<String, String>, file: &str) -> Result<()> {
    let ps_ou = format!("OU={PS_OU},OU=Labo,{}", trial.base);
    let csv = file.trim_start_matches('\u{feff}').replace('\'', "''");
    let script = format!(
        r#"$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory
$ou = '{ps_ou}'
if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ou'") {{
  Get-ADObject -SearchBase $ou -Filter * | Set-ADObject -ProtectedFromAccidentalDeletion $false
  Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false
}}
New-ADOrganizationalUnit -Name '{PS_OU}' -Path 'OU=Labo,{base}' -ProtectedFromAccidentalDeletion $false
$csv = @'
{csv}'@
$rows = $csv | ConvertFrom-Csv -Delimiter ';'
$pw = ConvertTo-SecureString '@MDP@' -AsPlainText -Force
$t = Measure-Command {{
  foreach ($r in $rows) {{
    $other = @{{ otherTelephone = @($r.otherTelephone -split '\|'); employeeNumber = $r.employeeNumber }}
    New-ADUser -Name $r.Name -SamAccountName $r.SamAccountName -GivenName $r.GivenName -Surname $r.sn `
      -UserPrincipalName $r.UserPrincipalName -Description $r.description -Path $ou `
      -AccountPassword $pw -Enabled $true -ChangePasswordAtLogon $true -OtherAttributes $other
    if ($r.memberOf) {{ Add-ADGroupMember -Identity $r.memberOf -Members $r.SamAccountName }}
  }}
}}
"SECONDES=$([math]::Round($t.TotalSeconds, 1))"
{listing}
Remove-ADOrganizationalUnit -Identity $ou -Recursive -Confirm:$false
"#,
        base = trial.base,
        listing = listing(&ps_ou),
    );
    let password = labo::password(20);
    let output = labo::poste_secret(&script, &password, &["--cible", "wdc"])?;
    let seconds = output
        .lines()
        .find_map(|l| l.trim().strip_prefix("SECONDES="))
        .unwrap_or("?")
        .to_owned();
    println!("MESURE win.test : import par New-ADUser {seconds} s");
    let powershell = accounts(&output, &ps_ou);
    check(
        calinda.len() == 1000 && powershell.len() == 1000,
        "1,000 accounts on each side",
    )?;
    let differing: Vec<_> = calinda
        .iter()
        .filter(|(sam, rest)| powershell.get(*sam) != Some(rest))
        .take(3)
        .map(|(sam, rest)| (sam.clone(), rest.clone(), powershell.get(sam).cloned()))
        .collect();
    check(
        differing.is_empty(),
        &format!("same attributes, account by account, as New-ADUser ({differing:?})"),
    )
}

#[test]
#[ignore = "lab: needs the DCs of the lab and an administrator ticket"]
fn import_errors() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j98-erreurs")?;
    let trial = Trial::new(&lab, &scratch)?;
    let (ou, group) = prepare(&trial)?;
    let schema = schema::read_schema(&trial.connection).map_err(debug)?;
    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let admin = if lab.windows() {
        "Administrateur"
    } else {
        "Administrator"
    };
    let lines = [
        "type;Name;SamAccountName;Path;countryCode;objectSid;couleur;memberOf;password;groupScope",
        // 2: valid user, password read and complex.
        ";Valide Un;j98.v1;;;;;J98-Groupe;Bonjour-J98-2026;",
        // 3: the identifier of line 2.
        ";Doublon Deux;j98.v1;;;;;;;",
        // 4: the identifier of the administrator.
        &format!(";Admin Copie;{admin};;;;;;;"),
        // 5: a column unknown to the schema, with a value.
        ";Couleur Cinq;j98.c5;;;;bleu;;;",
        // 6: a value refused by the syntax.
        ";Pays Six;j98.p6;;abc;;;;;",
        // 7: an attribute the DC keeps.
        ";Sid Sept;j98.s7;;;S-1-5-21-1;;;;",
        // 8: a container that does not exist.
        &format!(";Ailleurs Huit;j98.a8;OU=Nulle-Part,{};;;;;;", trial.base),
        // 9: an unknown kind.
        "imprimante;Imprimante Neuf;;;;;;;;",
        // 10: a group that does not exist.
        ";Groupe Dix;j98.g10;;;;;Groupe-Inexistant-J98;;",
        // 11: a password the policy refuses.
        ";Court Onze;j98.m11;;;;;;abc;",
        // 12: no name.
        ";;j98.n12;;;;;;;",
        // 13: a scope that does not exist, on a group.
        "groupe;Groupe Treize;;;;;;;;planétaire",
        // 14, 15, 16: a group, a contact, a computer, valid.
        "groupe;J98 Groupe Quatorze;;;;;;;;DomainLocal",
        "contact;J98 Contact Quinze;;;;;;;;",
        "ordinateur;J98PC16;;;;;;;;",
    ];
    let file = lines.join("\r\n");
    let options = Options {
        parent: ou.clone(),
        kind: Kind::User,
        ..Options::default()
    };
    let checked = import::check(
        &trial.connection,
        file.as_bytes(),
        &schema,
        &HashMap::new(),
        &options,
        &reader,
        &rule,
    )
    .map_err(debug)?;
    let at = |line: usize| {
        checked
            .lines
            .iter()
            .find(|l| l.line == line)
            .cloned()
            .ok_or("line absent")
    };
    let has = |line: usize, test: &dyn Fn(&Problem) -> bool| -> Result<bool> {
        Ok(at(line)?.problems.iter().any(test))
    };
    for l in &checked.lines {
        println!("  ligne {} : {:?} {:?}", l.line, l.problems, l.notes);
    }
    check(at(2)?.problems.is_empty(), "line 2 valid")?;
    check(
        has(3, &|p| {
            matches!(
                p,
                Problem::DuplicateInFile {
                    what: Unique::Identifier,
                    line: 2,
                    ..
                }
            )
        })?,
        "line 3: identifier of line 2",
    )?;
    check(
        has(4, &|p| {
            matches!(
                p,
                Problem::InDirectory {
                    what: Unique::Identifier,
                    ..
                }
            )
        })?,
        "line 4: identifier in the directory",
    )?;
    check(
        has(
            5,
            &|p| matches!(p, Problem::UnknownColumn(c) if c == "couleur"),
        )?,
        "line 5: unknown column",
    )?;
    check(
        has(
            6,
            &|p| matches!(p, Problem::Value { attribute, .. } if attribute == "countryCode"),
        )?,
        "line 6: value refused",
    )?;
    check(
        has(
            7,
            &|p| matches!(p, Problem::NotWritable(a) if a == "objectSid"),
        )?,
        "line 7: not writable",
    )?;
    check(
        has(8, &|p| matches!(p, Problem::PathMissing(_)))?,
        "line 8: container missing",
    )?;
    check(
        has(9, &|p| matches!(p, Problem::UnknownKind(_)))?,
        "line 9: unknown kind",
    )?;
    check(
        has(10, &|p| matches!(p, Problem::GroupMissing(_)))?,
        "line 10: group missing",
    )?;
    check(
        has(11, &|p| {
            matches!(
                p,
                Problem::PasswordTooShort { .. } | Problem::PasswordNotComplex
            )
        })?,
        "line 11: password refused",
    )?;
    check(
        has(12, &|p| matches!(p, Problem::NoName))?,
        "line 12: no name",
    )?;
    check(
        has(13, &|p| matches!(p, Problem::InvalidFlag { .. }))?,
        "line 13: scope refused",
    )?;
    for line in [14, 15, 16] {
        check(at(line)?.problems.is_empty(), &format!("line {line} valid"))?;
    }
    check(
        checked.items.len() == 4 && checked.refused() == 11,
        "4 lines to import, 11 refused",
    )?;
    check(
        count(&trial, &ou, "(!(objectClass=organizationalUnit))")? == 1,
        "nothing written by the check",
    )?;

    let chosen: Vec<usize> = (0..checked.items.len()).collect();
    let mut run = Run::new(
        "Import erreurs",
        bulk::batches(&checked.items, &chosen, bulk::BATCH_SIZE, &[]).map_err(debug)?,
    );
    let end = write(&trial, &mut run, None);
    check(
        matches!(end, End::Finished),
        &format!("valid lines imported ({end:?})"),
    )?;
    check(
        count(&trial, &ou, "(!(objectClass=organizationalUnit))")? == 5,
        "four objects created",
    )?;
    let g = labo::entry(
        &trial.connection,
        &format!("CN=J98 Groupe Quatorze,{ou}"),
        &["groupType"],
        None,
    )?
    .ok_or("group absent")?;
    check(
        text(&g, "groupType") == "-2147483644",
        "domain local security group",
    )?;
    let pc = labo::entry(
        &trial.connection,
        &format!("CN=J98PC16,{ou}"),
        &["userAccountControl", "sAMAccountName"],
        None,
    )?
    .ok_or("computer absent")?;
    check(
        text(&pc, "userAccountControl") == "4128" && text(&pc, "sAMAccountName") == "J98PC16$",
        "computer as ADUC",
    )?;
    let members = entries(
        &trial.connection,
        &group,
        Scope::Base,
        "(objectClass=*)",
        &["member"],
    )?;
    check(
        members
            .first()
            .is_some_and(|e| e.values("member").len() == 1),
        "line 2 in the group",
    )?;
    undo_series(&trial, &run.id, &[])?;
    check(
        count(&trial, &ou, "(!(objectClass=organizationalUnit))")? == 1,
        "import undone",
    )?;
    trial.remove_tree(&ou)
}

/// Reads the selection again and plans `change` on it.
fn plan(trial: &Trial, dns: &[String], change: &Change) -> Result<mass::Planned> {
    let objects = mass::read(&trial.connection, dns, &change.attributes()).map_err(debug)?;
    mass::plan(&objects, change).map_err(debug)
}

/// A change of the 500 accounts: stopped after two batches, resumed, checked, undone.
fn stop_resume_undo(
    trial: &Trial,
    name: &str,
    dns: &[String],
    change: &Change,
    applied: &dyn Fn(&Trial) -> Result<bool>,
    undone: &dyn Fn(&Trial) -> Result<bool>,
) -> Result<()> {
    let planned = plan(trial, dns, change)?;
    check(
        planned.items.len() == dns.len(),
        &format!("{name}: {} objects planned", dns.len()),
    )?;
    let chosen: Vec<usize> = (0..planned.items.len()).collect();
    let batches = bulk::batches(&planned.items, &chosen, bulk::BATCH_SIZE, &[]).map_err(debug)?;
    let mut run = Run::new(name, batches);
    let start = Instant::now();
    let end = write(trial, &mut run, Some(2));
    let first = start.elapsed().as_secs_f64();
    check(
        matches!(end, End::Stopped) && run.next == 2,
        &format!("{name}: stopped after two batches ({end:?}, {})", run.next),
    )?;
    let start = Instant::now();
    let end = write(trial, &mut run, None);
    let second = start.elapsed().as_secs_f64();
    check(
        matches!(end, End::Finished),
        &format!("{name}: resumed to the end ({end:?})"),
    )?;
    check(applied(trial)?, &format!("{name}: applied to the 500"))?;
    let undoing = undo_series(trial, &run.id, &[])?;
    check(undone(trial)?, &format!("{name}: undone in one go"))?;
    println!(
        "MESURE {} : {name} sur 500, {first:.1} s jusqu'à l'arrêt, {second:.1} s pour la reprise, annulation {undoing:.1} s",
        trial.profile.domain
    );
    Ok(())
}

#[test]
#[ignore = "lab: needs the DCs of the lab and an administrator ticket"]
fn bulk_five_hundred() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j98-masse")?;
    let trial = Trial::new(&lab, &scratch)?;
    let (ou, group) = prepare(&trial)?;
    let schema = schema::read_schema(&trial.connection).map_err(debug)?;
    let rule = computers::read_rule(&trial.connection).map_err(debug)?;
    let file = users_file(500, &lab.domain).replace(GROUP, "");
    let checked = import::check(
        &trial.connection,
        file.as_bytes(),
        &schema,
        &HashMap::new(),
        &Options {
            parent: ou.clone(),
            ..Options::default()
        },
        &reader,
        &rule,
    )
    .map_err(debug)?;
    let chosen: Vec<usize> = (0..checked.items.len()).collect();
    let mut setup = Run::new(
        "Comptes J9.9",
        bulk::batches(&checked.items, &chosen, bulk::BATCH_SIZE, &[]).map_err(debug)?,
    );
    check(
        matches!(write(&trial, &mut setup, None), End::Finished),
        "500 accounts created",
    )?;
    let mut dns: Vec<String> = entries(
        &trial.connection,
        &ou,
        Scope::OneLevel,
        "(objectClass=user)",
        &["1.1"],
    )?
    .into_iter()
    .map(|e| e.dn)
    .collect();
    dns.sort();
    check(dns.len() == 500, "500 accounts selected")?;
    let users = "(&(objectCategory=person)(objectClass=user))";

    let o = ou.clone();
    stop_resume_undo(
        &trial,
        "description posée",
        &dns,
        &Change::Set {
            attribute: "description".into(),
            values: vec![b"Masse J9.9".to_vec()],
        },
        &|t| Ok(count(t, &o, "(description=Masse J9.9)")? == 500),
        &|t| {
            Ok(count(t, &o, "(description=Masse J9.9)")? == 0
                && count(t, &o, "(description=Import J9.8*)")? == 500)
        },
    )?;
    let read = writer::read_version(&trial.connection, &group)
        .map_err(debug)?
        .ok_or("group absent")?;
    let g = group.clone();
    let members = move |t: &Trial| -> Result<usize> {
        Ok(entries(
            &t.connection,
            &g,
            Scope::Base,
            "(objectClass=*)",
            &["member"],
        )?
        .first()
        .map_or(0, |e| e.values("member").len()))
    };
    let m1 = members.clone();
    let m2 = members.clone();
    stop_resume_undo(
        &trial,
        "groupe rejoint",
        &dns,
        &Change::Group {
            group: group.clone(),
            read,
            join: true,
        },
        &move |t| Ok(m1(t)? == 500),
        &move |t| Ok(m2(t)? == 0),
    )?;
    let o = ou.clone();
    let o2 = ou.clone();
    stop_resume_undo(
        &trial,
        "désactivation",
        &dns,
        &Change::Enable(false),
        &|t| Ok(count(t, &o, &format!("(&{users}(userAccountControl=514))"))? == 500),
        &|t| Ok(count(t, &o2, &format!("(&{users}(userAccountControl=512))"))? == 500),
    )?;
    let target = trial.fresh_ou(&ou, "Destination")?;
    let t2 = target.clone();
    let o = ou.clone();
    stop_resume_undo(
        &trial,
        "déplacement",
        &dns,
        &Change::Move {
            parent: target.clone(),
        },
        &|t| Ok(count(t, &t2, users)? == 500),
        &|t| Ok(count(t, &o, users)? == 500 && count(t, &t2, users)? == 0),
    )?;

    // A refusal: an object of the selection disappears between the preview and the write.
    let planned = plan(&trial, &dns, &Change::MustChange(false))?;
    let gone = dns[250].clone();
    trial.apply(&actions::delete(&trial.read(&[gone.as_str()])?).map_err(debug)?)?;
    let chosen: Vec<usize> = (0..planned.items.len()).collect();
    let mut run = Run::new(
        "refus",
        bulk::batches(&planned.items, &chosen, bulk::BATCH_SIZE, &[]).map_err(debug)?,
    );
    let end = write(&trial, &mut run, None);
    let last = run.outcomes.last().ok_or("no outcome")?;
    let refused = bulk::refused_by_problems(&run.batches[run.next], &last.problems);
    check(
        matches!(end, End::Failed) && run.next == 2 && last.report.issue == Issue::Refused,
        &format!("series stopped on the third batch, refused ({end:?})"),
    )?;
    check(
        refused.len() == 1 && planned.items[refused[0]].label == gone,
        "the refusal names the object gone",
    )?;
    run.without(&planned.items, &refused, bulk::BATCH_SIZE)
        .map_err(debug)?;
    let end = write(&trial, &mut run, None);
    check(matches!(end, End::Finished), "resumed without it")?;
    check(
        count(&trial, &ou, "(pwdLastSet=0)")? == 0,
        "499 accounts changed",
    )?;
    undo_series(&trial, &run.id, &[])?;
    check(
        count(&trial, &ou, &format!("(&{users}(pwdLastSet=0))"))? == 499,
        "change undone",
    )?;
    trial.remove_tree(&ou)
}

/// Preparation and findings of the trial of the interface (`tests/interface/essais-masse.txt`),
/// on the domain aimed at: `ANNUAIRE_LABO_MASSE=preparer` makes `OU=Essais-J98-UI,OU=Labo` and
/// writes the file of the import (250 users, two lines in error) at `ANNUAIRE_LABO_MASSE_CSV`;
/// `importe` checks the 250 accounts and their description set by the change in bulk;
/// `annule` checks that the undo of the change and of the import left the OU empty;
/// `nettoyer` removes the OU.
#[test]
#[ignore = "lab: needs the DCs of the lab and an administrator ticket"]
fn bulk_interface() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("j98-ui")?;
    let trial = Trial::new(&lab, &scratch)?;
    let parent = format!("OU=Labo,{}", trial.base);
    let ou = format!("OU=Essais-J98-UI,{parent}");
    let users = "(&(objectCategory=person)(objectClass=user))";
    match std::env::var("ANNUAIRE_LABO_MASSE")
        .unwrap_or_default()
        .as_str()
    {
        "preparer" => {
            clear(&trial, &ou)?;
            trial.fresh_ou(&parent, "Essais-J98-UI")?;
            let mut file = users_file(250, &lab.domain).replace(GROUP, "");
            file.push_str("Doublon UI;j98.u0001;;;;;;;;\r\n");
            file.push_str("Sans Identifiant;;;;;;;;;\r\n");
            let path = std::env::var("ANNUAIRE_LABO_MASSE_CSV").map_err(debug)?;
            std::fs::write(&path, file)?;
            println!("  fichier {path}");
            Ok(())
        }
        "importe" => {
            check(
                count(&trial, &ou, users)? == 250,
                "250 accounts imported by the interface",
            )?;
            check(
                count(&trial, &ou, "(description=UI J9.9)")? == 250,
                "description set on the 250 by the change in bulk",
            )
        }
        "annule" => check(count(&trial, &ou, users)? == 0, "import undone by Ctrl+Z"),
        "nettoyer" => clear(&trial, &ou),
        other => {
            println!("  ANNUAIRE_LABO_MASSE={other:?}: nothing to do");
            Ok(())
        }
    }
}

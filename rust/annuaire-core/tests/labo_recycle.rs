// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Deleted objects and their restoration (J9.1, ADR 0024), on LAB.TEST (Samba, without the
//! Recycle Bin) or, with `ANNUAIRE_LABO_DOMAINE=win.test`, WIN.TEST (Windows, with or without
//! it: the trial reads which and expects accordingly).
//!
//! In `OU=Essais-J91,OU=Labo`: a user with a password, a group with two members, an OU with
//! a child and a child OU holding a grandchild, a computer. Each is deleted by Calinda, found
//! under `CN=Deleted Objects` with what the DC kept (compared to `ldbsearch --show-deleted` on
//! dc1, or `Get-ADObject -IncludeDeletedObjects` on wdc1), and brought back: the user by the
//! list, the group by the undo of its deletion from the journal (its members written back
//! from it without the Recycle Bin), the OU with the objects that were under it (a deleted
//! parent placed first), the computer under another OU, its name taken there refused with a
//! free one proposed. Same `objectGUID` and `objectSid` each time; the password comes back
//! with the Recycle Bin only (`kinit`). The undo of a restoration deletes the object again.
//! A user restored by the native tool (`ldbmodify` on dc1, `Restore-ADObject` on wdc1) gets
//! the same attributes as one restored by Calinda. The local copy sees the deletions and the
//! restorations by its delta. Everything under the OU is removed at the end (the objects stay
//! under `Deleted Objects`, as any deletion).
//!
//! ```text
//! KRB5CCNAME=FILE:… cargo test -p annuaire-core --all-features --test labo_recycle -- --ignored --nocapture --test-threads 1
//! ```

mod labo;

use std::collections::BTreeSet;

use annuaire_codecs::Guid;
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_core::actions::{self, NewUser};
use annuaire_core::changes::{self, Change, Changeset, Operation, Report, SENSITIVE, SYSTEM};
use annuaire_core::profile::Profile;
use annuaire_core::recycle::{self, Bin, Problem, Restoration};
use annuaire_core::session::{Entry, Scope};
use annuaire_core::store::Store;
use annuaire_core::writer;
use labo::{Kdc, Lab, Result, Texts, Trial, check, debug};

const OU_NAME: &str = "Essais-J91";

/// What a deleted object was, read before its deletion.
#[derive(Debug, Clone)]
struct Before {
    dn: String,
    guid: Guid,
    entry: Entry,
}

fn read_before(trial: &Trial, dn: &str) -> Result<Before> {
    let entry = trial
        .entry(dn, &["*", "memberOf", "objectGUID", "objectSid"])?
        .ok_or_else(|| format!("{dn} absent"))?;
    let guid = Guid::decode(entry.values("objectGUID").first().ok_or("objectGUID")?)?;
    Ok(Before {
        dn: dn.to_owned(),
        guid,
        entry,
    })
}

fn values(entry: &Entry, attribute: &str) -> BTreeSet<String> {
    entry
        .values(attribute)
        .iter()
        .map(|v| String::from_utf8_lossy(v).to_lowercase())
        .collect()
}

/// The attributes of an object that are neither the DC's nor secrets.
fn names(entry: &Entry) -> BTreeSet<String> {
    entry
        .attributes
        .iter()
        .map(|(a, _)| a.to_lowercase())
        .filter(|a| !SYSTEM.contains(&a.as_str()) && !SENSITIVE.contains(&a.as_str()))
        .collect()
}

fn rdn_value(dn: &str) -> Result<String> {
    Ok(annuaire_core::dn::split(dn)
        .map_err(debug)?
        .into_iter()
        .next()
        .ok_or("empty DN")?
        .value)
}

fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

fn user(trial: &Trial, ou: &str, name: &str, secret: Option<&str>) -> Result<String> {
    trial.apply(
        &actions::create_user(
            ou,
            &NewUser {
                full_name: name.into(),
                identifier: name.into(),
                given_name: "Essai".into(),
                surname: name.into(),
                password: secret.map(str::to_owned),
                enable: secret.is_some(),
                ..NewUser::default()
            },
        )
        .map_err(debug)?,
    )?;
    let dn = format!("CN={name},{ou}");
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(
                &dn,
                vec![
                    Change::new("description", vec![], vec![bytes("Essai J9.1")]).map_err(debug)?,
                    Change::new("mail", vec![], vec![bytes(&format!("{name}@example.org"))])
                        .map_err(debug)?,
                    Change::new("telephoneNumber", vec![], vec![bytes("+596 596 00 00 00")])
                        .map_err(debug)?,
                ],
                None,
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    Ok(dn)
}

/// Deletes `dn` and what is under it, leaves first, in one changeset (the protections against
/// deletion removed first); the report of the deletion.
fn delete_tree(trial: &Trial, dn: &str) -> Result<Report> {
    let mut dns: Vec<String> = labo::entries(
        &trial.connection,
        dn,
        Scope::Subtree,
        "(objectClass=*)",
        &["1.1"],
    )?
    .into_iter()
    .map(|e| e.dn)
    .collect();
    dns.sort_by_key(|d| std::cmp::Reverse(labo::depth(d)));
    let names: Vec<&str> = dns.iter().map(String::as_str).collect();
    for object in trial.descriptors(&names)? {
        if actions::is_protected(&object).map_err(debug)? {
            trial.apply(&actions::unprotect(&object).map_err(debug)?)?;
        }
    }
    trial.apply(&actions::delete(&trial.read(&names)?).map_err(debug)?)
}

fn delete(trial: &Trial, dn: &str) -> Result<Report> {
    trial.apply(&actions::delete(&[trial.read_one(dn)?]).map_err(debug)?)
}

fn read_bin(trial: &Trial) -> Result<Bin> {
    recycle::read_bin(&trial.connection).map_err(debug)
}

fn profile_on(lab: &Lab) -> Profile {
    let mut profile = Profile::new(lab.domain.clone());
    profile.preferred_dc = Some(lab.pdc_name());
    profile
}

fn in_copy(path: &std::path::Path, guid: &Guid) -> Result<bool> {
    Ok(Store::open(path)
        .map_err(debug)?
        .guids()
        .contains(&guid.encode()))
}

/// The restoration asked, applied; its report.
fn restore(trial: &Trial, bin: &Bin, choice: &Restoration) -> Result<(Changeset, Report)> {
    let changeset = recycle::prepare(&trial.connection, bin, choice, &Texts)
        .map_err(debug)?
        .map_err(|p| format!("restoration refused: {p:?}"))?;
    println!(
        "{}",
        changes::preview(&changeset, &Texts)
            .map_err(debug)?
            .lines()
            .map(|l| format!("     | {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let report = trial.apply(&changeset)?;
    Ok((changeset, report))
}

/// The same object, back: same GUID and SID, at `dn`.
fn same_object(trial: &Trial, before: &Before, dn: &str) -> Result<Entry> {
    let after = trial
        .entry(dn, &["*", "memberOf", "objectGUID", "objectSid"])?
        .ok_or_else(|| format!("{dn} not restored"))?;
    check(
        after.values("objectGUID") == before.entry.values("objectGUID")
            && after.values("objectSid") == before.entry.values("objectSid"),
        &format!("{dn}: same objectGUID and objectSid"),
    )?;
    Ok(after)
}

/// The deleted object as the native tool sees it: the names of the attributes kept.
fn oracle_kept(lab: &Lab, guid: &Guid) -> Result<BTreeSet<String>> {
    if lab.windows() {
        let script = format!(
            "$o = Get-ADObject -Filter \"objectGUID -eq '{guid}'\" -IncludeDeletedObjects -Properties *\n\
             $o.PSObject.Properties | ForEach-Object {{ if ($_.Value -ne $null -and \"$($_.Value)\" -ne '') {{ $_.Name }} }}\n"
        );
        let out = labo::poste(&script, &["--cible", "wdc"])?;
        // PowerShell names the properties of the module, some computed: those of LDAP only.
        Ok(out
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|l| !l.is_empty())
            .collect())
    } else {
        let script = format!(
            "sudo ldbsearch -H /var/lib/samba/private/sam.ldb --show-deleted --show-recycled \
             -b 'CN=Deleted Objects,{}' -s one '(objectGUID={guid})' '*' 2>/dev/null | \
             sed -n 's/^\\([A-Za-z-]*\\):.*/\\1/p' | sort -u\n",
            lab.base
        );
        Ok(labo::ssh("dc1", &script)?
            .lines()
            .map(|l| l.trim().to_lowercase())
            .filter(|a| !a.is_empty() && *a != "dn")
            .filter(|a| !SYSTEM.contains(&a.as_str()) && !SENSITIVE.contains(&a.as_str()))
            .filter(|a| !matches!(a.as_str(), "cn" | "ou" | "msds-lastknownrdn"))
            .collect())
    }
}

/// The native tool brings back `guid` at `dn`: `ldbmodify` (sam.ldb on dc1) or
/// `Restore-ADObject` (wdc1).
fn native_restore(lab: &Lab, guid: &Guid, deleted: &str, dn: &str) -> Result<()> {
    if lab.windows() {
        let name = rdn_value(dn)?;
        let parent = annuaire_core::dn::parent(dn).map_err(debug)?;
        labo::poste(
            &format!(
                "Restore-ADObject -Identity '{guid}' -NewName '{name}' -TargetPath '{parent}'\n"
            ),
            &["--cible", "wdc"],
        )?;
    } else {
        let ldif = format!(
            "dn: {deleted}\nchangetype: modify\ndelete: isDeleted\n-\nreplace: distinguishedName\ndistinguishedName: {dn}\n-\n"
        );
        labo::ssh(
            "dc1",
            &format!(
                "sudo ldbmodify -H /var/lib/samba/private/sam.ldb --controls=show_deleted:1 \
                 --controls=show_recycled:1 <<'FIN'\n{ldif}FIN\n"
            ),
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "lab"]
fn recycle_bin() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("corbeille")?;
    let trial = Trial::new(&lab, &scratch)?;
    let kdc = Kdc::new(&lab, &lab.pdc_name())?;
    let ou = trial.fresh_ou(&format!("OU=Labo,{}", trial.base), OU_NAME)?;
    let result = run(&lab, &trial, &kdc, &scratch, &ou);
    let removed = trial.remove_tree(&ou);
    trial.connection.join();
    result?;
    removed
}

fn run(lab: &Lab, trial: &Trial, kdc: &Kdc, scratch: &labo::Scratch, ou: &str) -> Result<()> {
    let bin = read_bin(trial)?;
    println!(
        "0. {}: Recycle Bin {}, Samba {}, {} objects under {}, tombstoneLifetime {:?}, \
         msDS-DeletedObjectLifetime {:?}",
        lab.domain,
        bin.enabled,
        bin.samba,
        bin.objects.len(),
        bin.container,
        bin.tombstone_days,
        bin.deleted_days
    );
    let enabled = bin.enabled;
    let recycled_before = bin.objects.iter().filter(|o| o.recycled).count();
    println!("   recycled among them: {recycled_before}");

    println!("1. objects to delete");
    let secret = labo::password(28);
    let user_dn = user(trial, ou, "rc-user", Some(&secret))?;
    let member_dn = user(trial, ou, "rc-member", Some(&labo::password(28)))?;
    let oracle_dn = user(trial, ou, "rc-oracle", Some(&labo::password(28)))?;
    trial.apply(
        &actions::create_group(ou, "rc-group", "", GroupScope::Global, true, "Groupe J9.1")
            .map_err(debug)?,
    )?;
    let group_dn = format!("CN=rc-group,{ou}");
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(
                &group_dn,
                vec![
                    Change::new("member", vec![], vec![bytes(&user_dn), bytes(&member_dn)])
                        .map_err(debug)?,
                ],
                None,
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    trial.apply(&actions::create_ou(ou, "rc-ou", "OU J9.1").map_err(debug)?)?;
    let tree_dn = format!("OU=rc-ou,{ou}");
    let child_dn = user(trial, &tree_dn, "rc-child", None)?;
    trial.apply(&actions::create_ou(&tree_dn, "rc-sub", "").map_err(debug)?)?;
    let sub_dn = format!("OU=rc-sub,{tree_dn}");
    let grand_dn = user(trial, &sub_dn, "rc-grand", None)?;
    trial.apply(&actions::create_ou(ou, "rc-other", "").map_err(debug)?)?;
    let other_dn = format!("OU=rc-other,{ou}");
    let pc_dn = format!("CN=rc-pc,{ou}");
    trial.apply(&Changeset {
        operations: vec![
            Operation::add(
                &pc_dn,
                vec![
                    (
                        "objectClass".into(),
                        ["top", "person", "organizationalPerson", "user", "computer"]
                            .map(bytes)
                            .to_vec(),
                    ),
                    ("sAMAccountName".into(), vec![bytes("RC-PC$")]),
                    ("userAccountControl".into(), vec![bytes("4096")]),
                    (
                        "dNSHostName".into(),
                        vec![bytes(&format!("rc-pc.{}", lab.domain))],
                    ),
                    ("description".into(), vec![bytes("Poste J9.1")]),
                ],
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    check(
        kdc.granted(&format!("rc-user@{}", lab.realm()), &secret),
        "rc-user logs on",
    )?;
    let before: Vec<Before> = [
        &user_dn, &member_dn, &oracle_dn, &group_dn, &tree_dn, &child_dn, &sub_dn, &grand_dn,
        &pc_dn,
    ]
    .into_iter()
    .map(|dn| read_before(trial, dn))
    .collect::<Result<_>>()?;
    let find = |dn: &str| before.iter().find(|b| b.dn == dn).cloned().ok_or("before");
    let (b_user, b_group, b_tree, b_child, b_sub, b_grand, b_pc, b_oracle) = (
        find(&user_dn)?,
        find(&group_dn)?,
        find(&tree_dn)?,
        find(&child_dn)?,
        find(&sub_dn)?,
        find(&grand_dn)?,
        find(&pc_dn)?,
        find(&oracle_dn)?,
    );
    let copy = scratch.path().join("copie.sqlite");
    let profile = profile_on(lab);
    let (reason, _, seconds) = labo::synchronize(&profile, &copy, false)?;
    println!("   copy made ({reason:?}, {seconds:.1} s)");
    check(in_copy(&copy, &b_user.guid)?, "rc-user in the copy")?;

    println!("2. deletions by Calinda");
    delete(trial, &user_dn)?;
    let group_deletion = delete(trial, &group_dn)?;
    delete(trial, &pc_dn)?;
    delete(trial, &oracle_dn)?;
    delete_tree(trial, &tree_dn)?;
    let (reason, _, _) = labo::synchronize(&profile, &copy, false)?;
    check(reason.is_none(), "delta after the deletions")?;
    for b in &before {
        if b.dn != member_dn {
            check(
                !in_copy(&copy, &b.guid)?,
                &format!("{} out of the copy", b.dn),
            )?;
        }
    }
    println!(
        "   ok: the delta takes the {} deletions out of the copy",
        before.len() - 1
    );

    println!("3. the deleted objects");
    let bin = read_bin(trial)?;
    for b in before.iter().filter(|b| b.dn != member_dn) {
        let o = bin
            .get(&b.guid)
            .ok_or_else(|| format!("{} not under Deleted Objects", b.dn))?;
        let name = rdn_value(&b.dn)?;
        check(o.name == name, &format!("name {} of {}", o.name, b.dn))?;
        let kept: BTreeSet<String> = o.kept().iter().map(|a| a.to_lowercase()).collect();
        let oracle = oracle_kept(lab, &b.guid)?;
        let missing: Vec<&String> = kept.iter().filter(|a| !oracle.contains(*a)).collect();
        check(
            missing.is_empty(),
            &format!("{name}: attributes kept {kept:?}, the native tool sees {missing:?} missing"),
        )?;
        println!(
            "   {name}: {}, recycled {}, last parent {:?}, kept {:?}",
            o.class,
            o.recycled,
            o.parent
                .as_deref()
                .map(|p| p.split(',').next().unwrap_or_default()),
            kept
        );
        if enabled {
            check(
                o.values("description").len() == b.entry.values("description").len(),
                &format!("{name}: description kept with the Recycle Bin"),
            )?;
        } else {
            check(
                o.values("description").is_empty(),
                &format!("{name}: description lost without the Recycle Bin"),
            )?;
        }
    }
    let o_grand = bin.get(&b_grand.guid).ok_or("rc-grand")?;
    check(
        o_grand.parent_guid == Some(b_sub.guid),
        "rc-grand: last known parent = rc-sub, deleted (by its GUID)",
    )?;
    check(
        bin.get(&b_user.guid)
            .and_then(|o| o.text("sAMAccountName"))
            .as_deref()
            == Some("rc-user"),
        "rc-user: sAMAccountName kept",
    )?;

    println!("4. rc-user brought back from the list");
    let (changeset, _) = restore(
        trial,
        &bin,
        &Restoration {
            selected: vec![b_user.guid],
            ..Restoration::default()
        },
    )?;
    check(
        changeset.operations.len() == 1
            && matches!(changeset.operations.first(), Some(Operation::Restore { dn, .. }) if *dn == user_dn),
        "one restoration, under its last parent",
    )?;
    let losses = if enabled {
        "comes back as it was deleted"
    } else {
        "only what the deletion kept"
    };
    check(
        changeset.remarks.iter().any(|r| r.contains(losses)),
        &format!("the preview says « {losses} »"),
    )?;
    let after = same_object(trial, &b_user, &user_dn)?;
    let logs_on = kdc.granted(&format!("rc-user@{}", lab.realm()), &secret);
    check(
        logs_on == enabled,
        &format!("rc-user logs on with its old password: {logs_on}"),
    )?;
    let description = values(&after, "description") == values(&b_user.entry, "description");
    check(
        description == enabled,
        &format!("description back: {description}"),
    )?;
    println!(
        "   ok: same GUID and SID; password {}, description {}",
        if logs_on { "kept" } else { "lost" },
        if description { "kept" } else { "lost" }
    );

    println!("5. rc-group brought back by the undo of its deletion (journal)");
    let journal = writer::read_journal(&trial.journal);
    let undo = recycle::undo(&trial.connection, &group_deletion, &journal, &Texts)
        .map_err(debug)?
        .ok_or("the undo of the deletion does not restore")?;
    println!(
        "{}",
        changes::preview(&undo, &Texts)
            .map_err(debug)?
            .lines()
            .map(|l| format!("     | {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    check(
        matches!(undo.operations.first(), Some(Operation::Restore { dn, .. }) if *dn == group_dn),
        "the undo restores rc-group (not a recreation)",
    )?;
    let outcome = trial.outcome(&undo, Some(group_deletion.id.clone()), None)?;
    check(
        outcome.report.issue == changes::Issue::Applied,
        &format!(
            "undo applied: {:?} {:?}",
            outcome.report.error, outcome.problems
        ),
    )?;
    let group = same_object(trial, &b_group, &group_dn)?;
    // rc-user was deleted before the group: without the Recycle Bin its membership went with
    // it, and the journal of the group's deletion has rc-member only.
    let mut expected = values(&b_group.entry, "member");
    if !enabled {
        expected.remove(&user_dn.to_lowercase());
    }
    check(
        values(&group, "member") == expected,
        &format!("rc-group: members back {:?}", values(&group, "member")),
    )?;
    check(
        values(&group, "description") == values(&b_group.entry, "description"),
        "rc-group: description back",
    )?;
    let user_groups = values(
        &trial.entry(&user_dn, &["memberOf"])?.ok_or("rc-user")?,
        "memberOf",
    );
    check(
        user_groups.contains(&group_dn.to_lowercase()) == enabled,
        &format!("rc-user member of rc-group again: {enabled}"),
    )?;
    println!("   ok: same GUID and SID, members and description as the deletion left them");

    println!("6. rc-ou with what was under it");
    let only_grand = recycle::plan(
        &bin,
        &Restoration {
            selected: vec![b_grand.guid],
            ..Restoration::default()
        },
    )
    .map_err(|p| format!("{p:?}"))?;
    let order: Vec<&str> = only_grand.iter().map(|p| p.dn.as_str()).collect();
    check(
        order == [tree_dn.as_str(), sub_dn.as_str(), grand_dn.as_str()]
            && only_grand.iter().take(2).all(|p| p.as_parent),
        &format!("a grandchild alone: its deleted parents first {order:?}"),
    )?;
    let (changeset, _) = restore(
        trial,
        &bin,
        &Restoration {
            selected: vec![b_tree.guid],
            children: true,
            ..Restoration::default()
        },
    )?;
    let order: Vec<&str> = changeset.operations.iter().map(Operation::dn).collect();
    check(
        order.len() == 4 && order.first() == Some(&tree_dn.as_str()),
        &format!("rc-ou first, then its children: {order:?}"),
    )?;
    for (b, dn) in [
        (&b_tree, &tree_dn),
        (&b_child, &child_dn),
        (&b_sub, &sub_dn),
        (&b_grand, &grand_dn),
    ] {
        same_object(trial, b, dn)?;
    }
    println!("   ok: four objects back, same GUIDs");

    println!("7. rc-pc under another OU, its name taken there");
    trial.apply(
        &actions::create_group(
            &other_dn,
            "rc-pc",
            "rc-pc-pris",
            GroupScope::Global,
            true,
            "",
        )
        .map_err(debug)?,
    )?;
    let choice = Restoration {
        selected: vec![b_pc.guid],
        target: Some(other_dn.clone()),
        ..Restoration::default()
    };
    let problems = recycle::prepare(&trial.connection, &bin, &choice, &Texts)
        .map_err(debug)?
        .err()
        .ok_or("a name taken is not refused")?;
    let free = match problems.as_slice() {
        [Problem::NameTaken { dn, free }]
            if dn.eq_ignore_ascii_case(&format!("CN=rc-pc,{other_dn}")) =>
        {
            free.clone()
        }
        other => return Err(format!("refusal {other:?}").into()),
    };
    check(
        free.eq_ignore_ascii_case(&format!("CN=rc-pc (2),{other_dn}")),
        &format!("free name proposed: {free}"),
    )?;
    let (_, pc_restore) = restore(
        trial,
        &bin,
        &Restoration {
            name: Some("rc-pc (2)".into()),
            ..choice
        },
    )?;
    let pc = same_object(trial, &b_pc, &free)?;
    check(
        values(&pc, "sAMAccountName") == values(&b_pc.entry, "sAMAccountName")
            && values(&pc, "dNSHostName") == values(&b_pc.entry, "dNSHostName"),
        "rc-pc: sAMAccountName and dNSHostName kept",
    )?;
    println!("   ok: refused under its name, restored as « rc-pc (2) »");

    println!("8. undo of a restoration: deleted again");
    let undone = trial.undo(&pc_restore)?;
    check(
        matches!(
            undone.changeset.operations.as_slice(),
            [Operation::Delete { .. }]
        ),
        "the inverse of a restoration is a deletion",
    )?;
    check(!trial.exists(&free)?, "rc-pc deleted again")?;
    check(
        read_bin(trial)?.get(&b_pc.guid).is_some(),
        "rc-pc under Deleted Objects again",
    )?;

    println!("9. the native tool on rc-oracle, compared to Calinda on rc-user");
    let o_oracle = bin.get(&b_oracle.guid).ok_or("rc-oracle")?;
    native_restore(lab, &b_oracle.guid, &o_oracle.dn, &oracle_dn)?;
    let native = trial
        .entry(&oracle_dn, &["*"])?
        .ok_or("rc-oracle not restored by the native tool")?;
    let calinda = trial.entry(&user_dn, &["*"])?.ok_or("rc-user")?;
    check(
        names(&native) == names(&calinda),
        &format!(
            "same attributes: native {:?}, Calinda {:?}",
            names(&native),
            names(&calinda)
        ),
    )?;
    println!("   ok: {:?}", names(&native));

    println!("10. the copy sees the restorations");
    let (reason, _, _) = labo::synchronize(&profile, &copy, false)?;
    check(reason.is_none(), "delta after the restorations")?;
    for b in [
        &b_user, &b_group, &b_tree, &b_child, &b_sub, &b_grand, &b_oracle,
    ] {
        check(
            in_copy(&copy, &b.guid)?,
            &format!("{} back in the copy", b.dn),
        )?;
    }
    check(
        !in_copy(&copy, &b_pc.guid)?,
        "rc-pc, deleted again, out of it",
    )?;
    println!("   ok");
    Ok(())
}

// --- Interface trial (tests/interface/essais-corbeille.txt) ----------------------------------

const UI_OU: &str = "Essais-J91-UI";

/// Where `preparer` keeps the GUIDs and SIDs that `verifier` compares.
fn ui_state() -> std::path::PathBuf {
    std::env::temp_dir().join("calinda-essai-corbeille.json")
}

/// The interface trial of the « Deleted Objects » window, on LAB.TEST, in three steps
/// (`ANNUAIRE_LABO_CORBEILLE`): `preparer` makes in `OU=Essais-J91-UI,OU=Labo` a user
/// `ui-user`, a group `ui-group` with it as member, an OU `ui-ou` with a user `ui-child`, a
/// computer `ui-pc`, then deletes `ui-user`, `ui-ou` (with its child) and `ui-pc` and puts a
/// group named `ui-pc` in its place; `verifier` checks what the scenarios restored (same GUIDs
/// and SIDs, `ui-pc (2)`, `ui-group` brought back by the history); `nettoyer` removes the OU.
#[test]
#[ignore = "lab"]
fn recycle_interface() -> Result<()> {
    let Ok(step) = std::env::var("ANNUAIRE_LABO_CORBEILLE") else {
        println!("  ANNUAIRE_LABO_CORBEILLE=preparer|verifier|nettoyer: skipped");
        return Ok(());
    };
    let lab = labo::lab();
    if !labo::samba_only(&lab) {
        return Ok(());
    }
    let scratch = labo::Scratch::new("corbeille-interface")?;
    let trial = Trial::new(&lab, &scratch)?;
    let parent = format!("OU=Labo,{}", trial.base);
    let ou = format!("OU={UI_OU},{parent}");
    let result = match step.as_str() {
        "preparer" => ui_prepare(&trial, &parent),
        "verifier" => ui_verify(&trial, &ou),
        "nettoyer" => trial.remove_tree(&ou),
        other => Err(format!("unknown step {other}").into()),
    };
    trial.connection.join();
    result
}

fn ui_prepare(trial: &Trial, parent: &str) -> Result<()> {
    let ou = trial.fresh_ou(parent, UI_OU)?;
    let user_dn = user(trial, &ou, "ui-user", Some(&labo::password(28)))?;
    trial.apply(
        &actions::create_group(
            &ou,
            "ui-group",
            "",
            GroupScope::Global,
            true,
            "Groupe J9.1 UI",
        )
        .map_err(debug)?,
    )?;
    let group_dn = format!("CN=ui-group,{ou}");
    trial.apply(&Changeset {
        operations: vec![
            Operation::modify(
                &group_dn,
                vec![Change::new("member", vec![], vec![bytes(&user_dn)]).map_err(debug)?],
                None,
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    trial.apply(&actions::create_ou(&ou, "ui-ou", "OU J9.1 UI").map_err(debug)?)?;
    let tree_dn = format!("OU=ui-ou,{ou}");
    let child_dn = user(trial, &tree_dn, "ui-child", None)?;
    let pc_dn = format!("CN=ui-pc,{ou}");
    trial.apply(&Changeset {
        operations: vec![
            Operation::add(
                &pc_dn,
                vec![
                    (
                        "objectClass".into(),
                        ["top", "person", "organizationalPerson", "user", "computer"]
                            .map(bytes)
                            .to_vec(),
                    ),
                    ("sAMAccountName".into(), vec![bytes("UI-PC$")]),
                    ("userAccountControl".into(), vec![bytes("4096")]),
                ],
            )
            .map_err(debug)?,
        ],
        remarks: Vec::new(),
    })?;
    let mut state = serde_json::Map::new();
    for dn in [&user_dn, &group_dn, &tree_dn, &child_dn, &pc_dn] {
        let b = read_before(trial, dn)?;
        state.insert(
            rdn_value(dn)?,
            serde_json::json!({
                "guid": b.guid.to_string(),
                "sid": b.entry.values("objectSid").first().map(|s| changes::base64_encode(s)),
            }),
        );
    }
    std::fs::write(ui_state(), serde_json::Value::Object(state).to_string())?;
    delete(trial, &user_dn)?;
    delete_tree(trial, &tree_dn)?;
    delete(trial, &pc_dn)?;
    trial.apply(
        &actions::create_group(&ou, "ui-pc", "ui-pc-pris", GroupScope::Global, true, "")
            .map_err(debug)?,
    )?;
    println!("   ok: ui-user, ui-ou (with ui-child) and ui-pc deleted, ui-pc taken");
    Ok(())
}

fn ui_verify(trial: &Trial, ou: &str) -> Result<()> {
    let state: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(ui_state())?)?;
    for (name, dn) in [
        ("ui-user", format!("CN=ui-user,{ou}")),
        ("ui-ou", format!("OU=ui-ou,{ou}")),
        ("ui-child", format!("CN=ui-child,OU=ui-ou,{ou}")),
        ("ui-pc", format!("CN=ui-pc (2),{ou}")),
        ("ui-group", format!("CN=ui-group,{ou}")),
    ] {
        let entry = trial
            .entry(&dn, &["objectGUID", "objectSid", "description"])?
            .ok_or_else(|| format!("{dn} not restored"))?;
        let guid = Guid::decode(entry.values("objectGUID").first().ok_or("objectGUID")?)?;
        check(
            state
                .pointer(&format!("/{name}/guid"))
                .and_then(|v| v.as_str())
                == Some(guid.to_string().as_str()),
            &format!("{dn}: the same object (objectGUID)"),
        )?;
        let sid = entry
            .values("objectSid")
            .first()
            .map(|s| changes::base64_encode(s));
        check(
            state
                .pointer(&format!("/{name}/sid"))
                .and_then(|v| v.as_str())
                == sid.as_deref(),
            &format!("{dn}: the same objectSid"),
        )?;
        if name == "ui-group" {
            check(
                values(&entry, "description").contains("groupe j9.1 ui"),
                "ui-group: description written back from the journal",
            )?;
        }
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Writes on the group policies and the PSOs against the lab (R4.8, port of
//! `test_gpo_ecriture_labo.py` and `test_gpo_orphelins_labo.py`, ADR 0020): an OU and a group
//! of trial, a GPO created on both halves, linked, its link disabled and enforced, the
//! inheritance blocked, its filtering changed, backed up, deleted, put back by undoing the
//! deletion, deleted again and restored from its archive, restored over itself and as a copy;
//! an orphan folder of trial removed alone; a PSO created, modified, deleted; the refusal of a
//! SYSVOL write on a DC that is not the PDC; the ascertaining of SYSVOL operations. Only
//! objects named `Essai-R48*` are written, and everything is removed at the end: the GPOs,
//! links, OUs, PSOs and orphan folders of the lab are left as they were. See `labo/mod.rs`.

mod labo;

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

use annuaire_codecs::Sid;
use annuaire_codecs::uac::Scope as GroupScope;
use annuaire_core::Connection;
use annuaire_core::actions;
use annuaire_core::changes::{self, Applied, Changeset, ErrorRecord, Issue, Operation, Report};
use annuaire_core::error::LdapError;
use annuaire_core::gpo::{self, Inventory};
use annuaire_core::gpo_backup;
use annuaire_core::gpo_write::{self as w, GpoError};
use annuaire_core::journal::Journal;
use annuaire_core::messages::{Catalog, English, Msg};
use annuaire_core::profile::Profile;
use annuaire_core::pso;
use annuaire_core::writer::{self, WriteCatalog, WriteMsg};

#[derive(Debug)]
struct Texts;

impl Catalog for Texts {
    fn text(&self, msg: &Msg) -> String {
        English.text(msg)
    }
}

impl WriteCatalog for Texts {
    fn write_text(&self, msg: &WriteMsg) -> String {
        format!("{msg:?}")
    }
    fn ldap_error(&self, error: &LdapError, _dc: &str) -> ErrorRecord {
        ErrorRecord {
            class: "ErreurLDAP".into(),
            message: error.to_string(),
            detail: String::new(),
        }
    }
}

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn gpo_error(e: GpoError) -> Box<dyn std::error::Error> {
    format!("{e:?}").into()
}

fn catalog() -> Arc<dyn Catalog + Send + Sync> {
    Arc::new(English)
}

fn check(condition: bool, what: &str) -> Result<()> {
    if condition {
        println!("  ok: {what}");
        Ok(())
    } else {
        Err(format!("FAILED: {what}").into())
    }
}

struct Trial {
    connection: Connection,
    profile: Profile,
    journal: Arc<Journal>,
}

impl Trial {
    fn apply(&self, changeset: &Changeset) -> Result<Report> {
        let t = Instant::now();
        let outcome = writer::apply(
            &self.connection,
            &self.profile,
            changeset,
            self.journal.clone(),
            Arc::new(Texts),
            None,
            None,
        )
        .map_err(|e| format!("{e:?}"))?;
        println!(
            "  applied: {:?} in {:.2} s ({} operation(s))",
            outcome.report.issue,
            t.elapsed().as_secs_f64(),
            changeset.operations.len()
        );
        if outcome.report.issue != Issue::Applied {
            return Err(format!(
                "not applied: {:?} {:?}",
                outcome.report.error, outcome.problems
            )
            .into());
        }
        Ok(outcome.report)
    }

    fn undo(&self, report: &Report) -> Result<Report> {
        let inverse = changes::inverse(report, &writer::read_journal(&self.journal), &Texts)
            .map_err(|e| format!("{e:?}"))?;
        self.apply(&inverse)
    }

    fn inventory(&self) -> Result<Inventory> {
        let t = Instant::now();
        let directory = gpo::read_directory(&self.connection).map_err(|e| format!("{e:?}"))?;
        let sysvol = gpo::read_pdc_sysvol(&self.connection).map_err(|e| format!("{e:?}"))?;
        println!(
            "  inventory: {} GPO, {} folders in {:.2} s ({} round trips)",
            directory.gpos.len(),
            sysvol.folders.len(),
            t.elapsed().as_secs_f64(),
            sysvol.round_trips
        );
        Ok(Inventory {
            directory,
            sysvol,
            others: Vec::new(),
        })
    }

    fn read_objects(&self, dns: &[String]) -> Result<Vec<actions::ReadObject>> {
        actions::read_objects(&self.connection, dns, &["objectClass"])
            .map_err(|e| format!("{e:?}").into())
    }
}

#[test]
#[ignore = "lab"]
#[allow(clippy::too_many_lines)]
fn gpo_writes() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let lab = labo::lab();
    let scratch = labo::Scratch::new("gpo")?;
    let domain = lab.domain.clone();
    let other_dc = lab.other_dc.clone();
    let folder = scratch.path().join("sauvegardes");
    std::fs::create_dir(&folder)?;
    let profile = lab.profile(true);
    let connection = annuaire_core::source::pdc_connection(&profile);
    let base = connection
        .run(true, |link| {
            Ok(link.state.root_dse.default_naming_context.clone())
        })
        .map_err(|e| format!("{e:?}"))?;
    let trial = Trial {
        connection,
        profile: profile.clone(),
        journal: scratch.journal(),
    };
    let before = trial.inventory()?;
    let names_before: HashSet<String> = before.directory.gpos.keys().cloned().collect();
    let orphans_before = before.orphans();
    println!("orphans before: {orphans_before:?}");

    println!("0. OU and group of trial");
    let ou = format!("OU=Essai-R48,{base}");
    trial.apply(&actions::create_ou(&base, "Essai-R48", "R4.8").map_err(|e| format!("{e:?}"))?)?;
    let group = format!("CN=G-Essai-R48,{ou}");
    trial.apply(
        &actions::create_group(&ou, "G-Essai-R48", "", GroupScope::Global, true, "R4.8")
            .map_err(|e| format!("{e:?}"))?,
    )?;

    println!("1. creation of a GPO");
    let guid = w::new_guid();
    let t = Instant::now();
    let created = w::prepare_creation(&trial.connection, "Essai-R48 GPO", Some(&guid), catalog())
        .map_err(gpo_error)?;
    println!("  prepared in {:.2} s", t.elapsed().as_secs_f64());
    trial.apply(&created)?;
    let gpo_dn = w::gpo_dn(&base, &guid);
    let inventory = trial.inventory()?;
    check(
        inventory.directory.gpos.contains_key(&guid),
        "GPO in the directory",
    )?;
    check(
        inventory.sysvol.folder(&guid).is_some_and(|f| f.present),
        "folder in the SYSVOL",
    )?;
    check(inventory.deviations(&guid).is_empty(), "versions equal")?;
    let aligned = w::prepare_alignment(&trial.connection, &gpo_dn, catalog()).map_err(gpo_error)?;
    check(
        aligned.operations.is_empty(),
        "ACL of the folder already aligned",
    )?;

    println!("2. links and inheritance");
    trial.apply(
        &w::prepare_links(
            &trial.connection,
            &ou,
            w::link_gpo(&gpo_dn, annuaire_codecs::gplink::ENFORCED),
        )
        .map_err(gpo_error)?,
    )?;
    trial.apply(
        &w::prepare_links(
            &trial.connection,
            &ou,
            w::link_options(&gpo_dn, Some(true), None),
        )
        .map_err(gpo_error)?,
    )?;
    check(
        matches!(
            w::prepare_links(&trial.connection, &ou, w::link_gpo(&gpo_dn, 0)),
            Err(GpoError::AlreadyLinked)
        ),
        "a second link refused",
    )?;
    let blocked =
        trial.apply(&w::prepare_inheritance(&trial.connection, &ou, true).map_err(gpo_error)?)?;
    let inventory = trial.inventory()?;
    let container = inventory
        .directory
        .containers
        .iter()
        .find(|c| c.dn.eq_ignore_ascii_case(&ou))
        .ok_or("OU of trial")?;
    check(container.inheritance_blocked(), "inheritance blocked")?;
    let link = container.gplink.links().next().ok_or("link")?;
    check(
        link.disabled() && link.enforced(),
        "link disabled and enforced",
    )?;
    trial.undo(&blocked)?;

    println!("3. security filtering");
    let domain_sid: Sid = {
        let read = actions::read_objects(
            &trial.connection,
            std::slice::from_ref(&base),
            &["objectSid"],
        )
        .map_err(|e| format!("{e:?}"))?;
        let raw = read.first().ok_or("domain")?.values("objectSid");
        Sid::decode(raw.first().ok_or("objectSid")?)?
    };
    let admins = domain_sid.with_rid(512)?;
    let filtering = w::prepare_filtering(
        &trial.connection,
        &gpo_dn,
        vec![admins],
        vec![w::authenticated_users()],
        catalog(),
    )
    .map_err(gpo_error)?;
    println!("  remarks: {:?}", filtering.remarks);
    check(filtering.remarks.len() == 1, "Authenticated Users remark")?;
    let filtered = trial.apply(&filtering)?;
    let inventory = trial.inventory()?;
    let rights = w::filter_rights(inventory.directory.gpos.get(&guid).ok_or("GPO")?);
    check(
        rights.iter().map(|r| r.sid).collect::<Vec<_>>() == [admins],
        "filtering: Domain Admins only",
    )?;
    check(
        inventory.directory.names.contains_key(&admins),
        "name of the SID read",
    )?;
    check(
        w::prepare_alignment(&trial.connection, &gpo_dn, catalog())
            .map_err(gpo_error)?
            .operations
            .is_empty(),
        "ACL aligned after the filtering",
    )?;
    trial.undo(&filtered)?;

    println!("4. backup");
    let t = Instant::now();
    let archive = gpo_backup::back_up(&trial.connection, &gpo_dn, &folder).map_err(gpo_error)?;
    println!(
        "  {} in {:.2} s",
        archive.display(),
        t.elapsed().as_secs_f64()
    );
    let saved = gpo_backup::read_archive(&archive).map_err(|e| format!("{e:?}"))?;
    check(
        saved.guid == guid && saved.links.len() == 1,
        "archive read back",
    )?;

    println!("5. deletion, undone, deleted again, restored");
    let t = Instant::now();
    let deletion = w::prepare_deletion(&trial.connection, &gpo_dn, catalog()).map_err(gpo_error)?;
    println!(
        "  prepared in {:.2} s: {:?}",
        t.elapsed().as_secs_f64(),
        deletion.remarks
    );
    let deleted = trial.apply(&deletion)?;
    let inventory = trial.inventory()?;
    check(
        !inventory.directory.gpos.contains_key(&guid)
            && inventory.sysvol.folder(&guid).is_some_and(|f| !f.present),
        "GPO deleted on both halves",
    )?;
    trial.undo(&deleted)?;
    let inventory = trial.inventory()?;
    check(
        inventory.directory.gpos.contains_key(&guid) && inventory.deviations(&guid).is_empty(),
        "GPO back by undoing",
    )?;
    check(
        inventory
            .directory
            .containers
            .iter()
            .any(|c| c.dn.eq_ignore_ascii_case(&ou) && c.gplink.links().count() == 1),
        "its link back",
    )?;
    trial.apply(&w::prepare_deletion(&trial.connection, &gpo_dn, catalog()).map_err(gpo_error)?)?;
    let restoration =
        gpo_backup::prepare_restoration(&trial.connection, &saved, false, None, catalog())
            .map_err(gpo_error)?;
    println!("  restoration: {:?}", restoration.remarks);
    trial.apply(&restoration)?;
    let inventory = trial.inventory()?;
    check(
        inventory.directory.gpos.contains_key(&guid) && inventory.deviations(&guid).is_empty(),
        "GPO restored from its archive",
    )?;
    let over = gpo_backup::prepare_restoration(&trial.connection, &saved, false, None, catalog())
        .map_err(gpo_error)?;
    println!(
        "  over itself: {} operation(s), {:?}",
        over.operations.len(),
        over.remarks
    );
    trial.apply(&over)?;
    let inventory = trial.inventory()?;
    let restored = inventory.directory.gpos.get(&guid).ok_or("GPO")?;
    check(
        restored.versions().user == 1
            && restored.versions().computer == 1
            && inventory.deviations(&guid).is_empty(),
        "version raised on both halves",
    )?;
    let copy = gpo_backup::prepare_restoration(
        &trial.connection,
        &saved,
        true,
        Some("Essai-R48 copie"),
        catalog(),
    )
    .map_err(gpo_error)?;
    trial.apply(&copy)?;
    let copy_dn = copy.operations.first().ok_or("copy")?.dn().to_owned();
    let copy_guid = w::guid_of(&copy_dn);
    let inventory = trial.inventory()?;
    check(
        inventory.directory.gpos.contains_key(&copy_guid)
            && inventory.deviations(&copy_guid).is_empty(),
        "copy under a new GUID",
    )?;
    check(
        w::prepare_alignment(&trial.connection, &copy_dn, catalog())
            .map_err(gpo_error)?
            .operations
            .is_empty(),
        "ACL of the copy aligned",
    )?;
    trial
        .apply(&w::prepare_deletion(&trial.connection, &copy_dn, catalog()).map_err(gpo_error)?)?;

    println!("6. an orphan folder of trial");
    let orphan = w::new_guid();
    let folder_path = w::gpo_folder(&domain, &orphan);
    let made = Changeset {
        operations: vec![
            Operation::CreateFolder {
                dn: w::gpo_dn(&base, &orphan),
                path: folder_path.clone(),
                descriptor: None,
            },
            Operation::WriteFile {
                dn: w::gpo_dn(&base, &orphan),
                path: format!("{folder_path}\\GPT.INI"),
                content: w::NEW_GPT_INI.to_vec(),
                old: None,
                descriptor: None,
            },
        ],
        remarks: Vec::new(),
    };
    trial.apply(&made)?;
    let inventory = trial.inventory()?;
    check(inventory.orphans().contains(&orphan), "orphan seen")?;
    let all = w::prepare_orphans_removal(&trial.connection, catalog()).map_err(gpo_error)?;
    let quoted: HashSet<String> = all.operations.iter().map(|o| w::guid_of(o.dn())).collect();
    check(
        quoted.contains(&orphan)
            && orphans_before
                .iter()
                .all(|o| quoted.contains(&o.to_uppercase())),
        "removal of all orphans prepared (not applied)",
    )?;
    check(
        matches!(
            w::prepare_orphan_deletion(&trial.connection, &guid, catalog()),
            Err(GpoError::NotOrphan { .. })
        ),
        "a GPO folder is not an orphan",
    )?;
    let one =
        w::prepare_orphan_deletion(&trial.connection, &orphan, catalog()).map_err(gpo_error)?;
    check(
        one.operations.len() == 2,
        "orphan alone: its file and itself",
    )?;
    trial.apply(&one)?;

    println!("7. ascertaining of SYSVOL operations");
    let gpt = format!("{}\\GPT.INI", w::gpo_folder(&domain, &guid));
    let current = Report {
        id: "essai".into(),
        timestamp: writer::timestamp(),
        domain: domain.clone(),
        dc: String::new(),
        user: String::new(),
        changeset: Changeset::default(),
        applied: Vec::new(),
        issue: Issue::Interrupted,
        error: None,
        rollback: None,
        origins: Vec::new(),
        rollback_applied: Vec::new(),
        rollback_error: None,
        doubtful: Some(Applied {
            operation: Operation::CreateFolder {
                dn: gpo_dn.clone(),
                path: w::gpo_folder(&domain, &guid),
                descriptor: None,
            },
            after: None,
            before: None,
        }),
        doubtful_rollback: Some(Applied {
            operation: Operation::DeleteFile {
                dn: gpo_dn.clone(),
                path: gpt,
                content: Vec::new(),
                descriptor: None,
            },
            after: None,
            before: None,
        }),
        resumes: None,
        resumed_by: None,
    };
    let settled = writer::ascertain(&trial.connection, &current).map_err(|e| format!("{e:?}"))?;
    check(
        settled.applied.len() == 1 && settled.doubtful.is_none(),
        "creation of a present folder: done",
    )?;
    check(
        settled.rollback_applied.is_empty() && settled.doubtful_rollback.is_none(),
        "deletion of a present file: not done",
    )?;

    println!("8. SYSVOL refused off the PDC");
    let mut on_other = profile.clone();
    on_other.preferred_dc = Some(other_dc.clone());
    let other = annuaire_core::source::connection_to(&on_other, Some(&other_dc));
    let refused = writer::apply(
        &other,
        &on_other,
        &created,
        trial.journal.clone(),
        Arc::new(Texts),
        None,
        None,
    )
    .map_err(|e| format!("{e:?}"))?;
    println!("  {:?}", refused.problems.first().map(|p| &p.message));
    check(
        refused.report.issue == Issue::Refused
            && refused
                .problems
                .first()
                .is_some_and(|p| p.message.starts_with("NotOnPdc")),
        "write on another DC refused before anything",
    )?;
    other.close();

    println!("9. a PSO");
    let domain_settings = pso::read_domain(&trial.connection).map_err(|e| format!("{e:?}"))?;
    let settings = pso::Settings {
        precedence: 77,
        ..domain_settings
    };
    let created_pso = pso::create(
        &base,
        "Essai-R48 PSO",
        &settings,
        std::slice::from_ref(&group),
        "R4.8",
    )
    .map_err(|e| format!("{e:?}"))?;
    trial.apply(&created_pso)?;
    let read = pso::read_psos(&trial.connection).map_err(|e| format!("{e:?}"))?;
    let mine = read
        .iter()
        .find(|p| p.name == "Essai-R48 PSO")
        .ok_or("PSO read")?;
    check(
        mine.targets.len() == 1 && mine.settings.precedence == 77,
        "PSO read back",
    )?;
    let changed = pso::Settings {
        min_length: 12,
        ..mine.settings
    };
    trial.apply(&pso::modify(mine, &changed, Some(&[]), None).map_err(|e| format!("{e:?}"))?)?;
    let again = pso::read_pso(&trial.connection, &mine.dn)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("PSO")?;
    check(
        again.settings.min_length == 12 && again.targets.is_empty(),
        "PSO modified",
    )?;
    trial.apply(&pso::delete(&again).map_err(|e| format!("{e:?}"))?)?;

    println!("10. cleaning");
    trial.apply(&w::prepare_deletion(&trial.connection, &gpo_dn, catalog()).map_err(gpo_error)?)?;
    let objects = trial.read_objects(&[group.clone(), ou.clone()])?;
    trial.apply(&actions::delete(&objects).map_err(|e| format!("{e:?}"))?)?;
    let after = trial.inventory()?;
    let names_after: HashSet<String> = after.directory.gpos.keys().cloned().collect();
    check(names_after == names_before, "same GPOs as before")?;
    check(
        after.orphans() == orphans_before,
        "same orphan folders as before",
    )?;
    check(
        pso::read_psos(&trial.connection)
            .map_err(|e| format!("{e:?}"))?
            .iter()
            .all(|p| !p.name.starts_with("Essai-R48")),
        "no PSO of trial left",
    )?;
    std::fs::remove_file(&archive)?;
    trial.connection.close();
    println!("done");
    Ok(())
}

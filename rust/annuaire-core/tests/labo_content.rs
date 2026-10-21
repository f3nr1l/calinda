// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Content of the GPOs against the lab (R4.9, port of `test_admx_labo.py`,
//! `test_securite_gpo_labo.py` and `test_preferences_labo.py` without the Windows station, ADR
//! 0020): the central store of the administrative templates read on the PDC, then from the
//! cache; a GPO of trial `Essai-R49 contenu` created, not linked; three ADMX policies set in
//! one changeset (computer part enabled, computer part disabled, user part enabled with its
//! default options), raw registry values in both parts; the security settings (password
//! length, a right, a restricted group), on a GPO linked nowhere: nothing written on the
//! domain object; preferences (a drive, a registry item); every one read again by the core;
//! one write undone and done again. Then the drive removed (file deleted, extension removed)
//! and the GPO of trial deleted, or only deleted if a step failed. See `labo/mod.rs`.

mod labo;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use annuaire_codecs::gpt_tmpl as gt;
use annuaire_codecs::registry_pol::{self as rp, Entry};
use annuaire_core::Connection;
use annuaire_core::admx::{Class, ElementKind, Store};
use annuaire_core::admx_store;
use annuaire_core::changes::{self, Changeset, ErrorRecord, Issue, Operation, Report};
use annuaire_core::error::LdapError;
use annuaire_core::gpo::Part;
use annuaire_core::gpo_content::{self as gc, Work};
use annuaire_core::gpo_preferences as gp;
use annuaire_core::gpo_write::{self as w, GpoError};
use annuaire_core::gpp::{self, Common, EditableFilter, Family, Filter, Target};
use annuaire_core::journal::Journal;
use annuaire_core::messages::{Catalog, English, Msg};
use annuaire_core::policies::{self as pol, Setting, State};
use annuaire_core::profile::Profile;
use annuaire_core::security_policy as sp;
use annuaire_core::sysvol;
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

    fn read(&self, dn: &str, part: Part, paths: &[String]) -> Result<gc::ContentRead> {
        gc::read_files(&self.connection, dn, vec![(part, paths.to_vec())])
            .map_err(gpo_error)?
            .into_iter()
            .next()
            .ok_or_else(|| "nothing read".into())
    }

    fn registry(&self, dn: &str, part: Part) -> Result<Vec<Entry>> {
        let read = self.read(dn, part, &[gc::REGISTRY_POL.to_owned()])?;
        gc::registry(&read).map_err(gpo_error)
    }
}

fn texts(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

/// Policies chosen in the store, deterministically: a simple one of the computer part, one of
/// the computer part to disable, one of the user part with options.
fn chosen(store: &Store) -> Result<(String, String, String)> {
    let mut policies: Vec<_> = store.policies.iter().collect();
    policies.sort_by(|a, b| a.ident.cmp(&b.ident));
    let simple = |class: Class, skip: usize| {
        policies
            .iter()
            .filter(|p| p.class == class && !p.value_name.is_empty() && p.elements.is_empty())
            .nth(skip)
            .map(|p| p.ident.clone())
    };
    let with_options = policies
        .iter()
        .find(|p| {
            p.class == Class::User
                && p.elements.len() >= 2
                && p.elements.iter().all(|e| {
                    matches!(
                        e.kind,
                        ElementKind::Boolean | ElementKind::Decimal | ElementKind::Enum
                    )
                })
                && p.elements.iter().any(|e| e.kind == ElementKind::Enum)
        })
        .map(|p| p.ident.clone());
    Ok((
        simple(Class::Machine, 0).ok_or("simple policy")?,
        simple(Class::Machine, 1).ok_or("second policy")?,
        with_options.ok_or("policy with options")?,
    ))
}

fn load_store(dc: &str, domain: &str, cache: &std::path::Path) -> Result<Store> {
    let preferred = texts(&["fr-FR"]);
    for round in ["first", "second"] {
        let t = Instant::now();
        let mut session =
            sysvol::Session::open(dc, sysvol::Protection::Encrypted, Duration::from_secs(30))?;
        let loading = admx_store::load_on(&mut session, dc, domain, &preferred, Some(cache))?;
        let store = loading.store.ok_or("no central store")?;
        println!(
            "  store ({round}): {} files, {} policies, {} categories, language {}, {} errors, \
from cache: {}, {:.2} s {:?}",
            store.files,
            store.policies.len(),
            store.categories.len(),
            store.language,
            store.errors.len(),
            loading.from_cache,
            t.elapsed().as_secs_f64(),
            loading.durations
        );
        if round == "second" {
            check(loading.from_cache, "second opening from the cache")?;
            return Ok(store);
        }
    }
    Err("unreachable".into())
}

fn entry(key: &str, name: &str, rtype: u32, data: Vec<u8>) -> Entry {
    Entry {
        key: key.into(),
        value_name: name.into(),
        rtype,
        data,
    }
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

const RAW_KEY: &str = "Software\\Annuaire\\EssaiR49";

#[allow(clippy::too_many_lines)]
fn write(
    trial: &Trial,
    base: &str,
    dc: &str,
    domain: &str,
    cache: PathBuf,
    guid: &str,
) -> Result<()> {
    println!("1. central store of the administrative templates");
    let store = Arc::new(load_store(dc, domain, &cache)?);
    let (simple, disabled, options) = chosen(&store)?;
    println!("  policies: {simple}, {disabled}, {options}");

    println!("2. GPO of trial");
    trial.apply(
        &w::prepare_creation(
            &trial.connection,
            "Essai-R49 contenu",
            Some(guid),
            catalog(),
        )
        .map_err(gpo_error)?,
    )?;
    let dn = w::gpo_dn(base, guid);
    println!("  GUID {guid}");

    println!("3. three ADMX policies and raw values, both parts, one changeset");
    let s = store.clone();
    let (a, b) = (simple.clone(), disabled.clone());
    let computer: Work = Arc::new(move |read| {
        let (p1, p2) = (
            s.policy(&a).ok_or_else(|| GpoError::Invalid(a.clone()))?,
            s.policy(&b).ok_or_else(|| GpoError::Invalid(b.clone()))?,
        );
        gc::modify_registry(read, &|entries| {
            let entries = pol::modify(&entries, p1, &Setting::new(State::Enabled));
            let entries = pol::modify(&entries, p2, &Setting::new(State::Disabled));
            let entries = rp::set(
                &entries,
                entry(RAW_KEY, "Texte", rp::REG_SZ, utf16("é r49")),
            );
            let entries = rp::set(
                &entries,
                entry(
                    RAW_KEY,
                    "Nombre",
                    rp::REG_DWORD,
                    0x49u32.to_le_bytes().to_vec(),
                ),
            );
            rp::disable(&entries, RAW_KEY, "Retiree")
        })
    });
    let s = store.clone();
    let c = options.clone();
    let user: Work = Arc::new(move |read| {
        let p = s.policy(&c).ok_or_else(|| GpoError::Invalid(c.clone()))?;
        let setting = Setting {
            state: State::Enabled,
            options: pol::default_options(p),
        };
        gc::modify_registry(read, &|entries| {
            let entries = pol::modify(&entries, p, &setting);
            let list = "a\0b\0\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            rp::set(&entries, entry(RAW_KEY, "Liste", rp::REG_MULTI_SZ, list))
        })
    });
    let t = Instant::now();
    let cs = gc::prepare_contents(
        &trial.connection,
        &dn,
        vec![
            (Part::Computer, vec![gc::REGISTRY_POL.into()], computer),
            (Part::User, vec![gc::REGISTRY_POL.into()], user),
        ],
        true,
        catalog(),
    )
    .map_err(gpo_error)?;
    println!(
        "  prepared in {:.2} s; remarks: {:?}",
        t.elapsed().as_secs_f64(),
        cs.remarks
    );
    check(cs.operations.len() == 4, "two files, GPT.INI, the object")?;
    let admx_report = trial.apply(&cs)?;
    let machine = trial.registry(&dn, Part::Computer)?;
    let user_entries = trial.registry(&dn, Part::User)?;
    let state =
        |ident: &str, entries: &[Entry]| store.policy(ident).map(|p| pol::read(p, entries).state);
    check(
        state(&simple, &machine) == Some(State::Enabled),
        "simple policy enabled",
    )?;
    check(
        state(&disabled, &machine) == Some(State::Disabled),
        "second policy disabled",
    )?;
    check(
        state(&options, &user_entries) == Some(State::Enabled),
        "user policy enabled",
    )?;
    let known = pol::store_footprint(&store, Class::Machine);
    let extra = pol::extra(&known, &machine);
    check(extra.len() == 3, "the raw values are extra settings")?;

    println!("4. undone, then done again");
    let undone = trial.undo(&admx_report)?;
    check(
        trial.registry(&dn, Part::Computer)?.is_empty(),
        "Registry.pol emptied by the undo",
    )?;
    trial.undo(&undone)?;
    check(
        trial.registry(&dn, Part::Computer)? == machine,
        "registry back",
    )?;

    println!("5. security settings on a GPO linked nowhere");
    let security = sp::read_security(&trial.connection, &dn).map_err(gpo_error)?;
    check(!security.exists, "no GptTmpl.inf yet")?;
    check(
        security.scope.reach == sp::Reach::Unlinked,
        "scope: linked nowhere",
    )?;
    println!(
        "  domain policy: {:?}; samba {}; {} PSO",
        security.domain.values,
        security.samba,
        security.psos.len()
    );
    let t = Instant::now();
    let cs = sp::prepare_security(
        &trial.connection,
        &dn,
        Arc::new(|inf: &gt::Inf| {
            let r = sp::setting("MinimumPasswordLength")
                .ok_or(sp::SecurityProblem::MinimumAge { min: 0, max: 0 })?;
            let inf = sp::set(inf, r, Some(10))?;
            let inf = inf.set_right("SeShutdownPrivilege", Some(&["*S-1-5-32-544".to_owned()]));
            Ok(inf.set_group("*S-1-5-32-547", &["*S-1-5-32-544".to_owned()], &[]))
        }),
        true,
        catalog(),
    )
    .map_err(gpo_error)?;
    println!(
        "  prepared in {:.2} s; remarks: {:?}",
        t.elapsed().as_secs_f64(),
        cs.remarks
    );
    check(
        !cs.operations
            .iter()
            .any(|o| matches!(o, Operation::Modify { dn: d, .. } if d.eq_ignore_ascii_case(base))),
        "domain object untouched",
    )?;
    trial.apply(&cs)?;
    let security = sp::read_security(&trial.connection, &dn).map_err(gpo_error)?;
    check(
        sp::value(
            &security.inf,
            sp::setting("MinimumPasswordLength").ok_or("setting")?,
        ) == Some(10),
        "password length read again",
    )?;
    check(
        security.inf.right("SeShutdownPrivilege") == Some(texts(&["*S-1-5-32-544"])),
        "right read again",
    )?;

    println!("6. preferences: a drive (user), a registry item (computer)");
    let now = gpp::now();
    let drive = gpp::new_element(
        Family::Drives,
        "R:",
        "R:",
        &[
            ("action".into(), "U".into()),
            ("thisDrive".into(), "NOCHANGE".into()),
            ("allDrives".into(), "NOCHANGE".into()),
            ("userName".into(), String::new()),
            ("path".into(), "\\\\srv-r49\\partage".into()),
            ("label".into(), "Essai R49".into()),
            ("persistent".into(), "0".into()),
            ("useLetter".into(), "1".into()),
            ("letter".into(), "R".into()),
        ],
        &Common::default(),
        &[Filter::Editable(EditableFilter::new(
            Target::Computer,
            &[("name", "POSTE-R49")],
        ))],
        &w::new_guid(),
        now,
        &[],
    );
    let item = gpp::new_element(
        Family::Registry,
        "Essai",
        "Essai",
        &[
            ("action".into(), "U".into()),
            ("displayDecimal".into(), "0".into()),
            ("default".into(), "0".into()),
            ("hive".into(), "HKEY_LOCAL_MACHINE".into()),
            ("key".into(), RAW_KEY.into()),
            ("name".into(), "Essai".into()),
            ("type".into(), "REG_SZ".into()),
            ("value".into(), "préférence".into()),
        ],
        &Common::default(),
        &[],
        &w::new_guid(),
        now,
        &[],
    );
    let ops_user = vec![gp::Operation::Add(drive)];
    let ops_machine = vec![gp::Operation::Add(item)];
    let say = |r: &[gp::Remark]| r.iter().map(|x| format!("{x:?}")).collect::<Vec<_>>();
    let user: Work = Arc::new(move |read| gp::change(read, Family::Drives, &ops_user, &say));
    let computer: Work =
        Arc::new(move |read| gp::change(read, Family::Registry, &ops_machine, &say));
    let cs = gc::prepare_contents(
        &trial.connection,
        &dn,
        vec![
            (Part::Computer, vec![Family::Registry.path()], computer),
            (Part::User, vec![Family::Drives.path()], user),
        ],
        true,
        catalog(),
    )
    .map_err(gpo_error)?;
    println!("  remarks: {:?}", cs.remarks);
    trial.apply(&cs)?;
    let read = trial.read(&dn, Part::User, &gp::paths())?;
    let prefs = gp::from_read(&read).map_err(gpo_error)?;
    let drives = prefs.file(Family::Drives).ok_or("drives")?;
    check(
        drives
            .elements()
            .iter()
            .map(|e| e.name())
            .collect::<Vec<_>>()
            == ["R:"],
        "drive read again",
    )?;
    check(prefs.declared(Family::Drives), "drives extension declared")?;
    Ok(())
}

fn clean(trial: &Trial, base: &str, guid: &str) -> Result<()> {
    let dn = w::gpo_dn(base, guid);
    println!("7. drive removed, then the GPO deleted");
    let read = trial.read(&dn, Part::User, &gp::paths())?;
    let prefs = gp::from_read(&read).map_err(gpo_error)?;
    let uids: Vec<String> = prefs
        .file(Family::Drives)
        .ok_or("drives")?
        .elements()
        .iter()
        .map(|e| e.uid().to_owned())
        .collect();
    let ops: Vec<gp::Operation> = uids
        .into_iter()
        .map(|uid| gp::Operation::Remove { uid })
        .collect();
    let say = |r: &[gp::Remark]| r.iter().map(|x| format!("{x:?}")).collect::<Vec<_>>();
    let user: Work = Arc::new(move |read| gp::change(read, Family::Drives, &ops, &say));
    let cs = gc::prepare_contents(
        &trial.connection,
        &dn,
        vec![(Part::User, vec![Family::Drives.path()], user)],
        true,
        catalog(),
    )
    .map_err(gpo_error)?;
    println!("  remarks: {:?}", cs.remarks);
    check(
        matches!(cs.operations.first(), Some(Operation::DeleteFile { .. })),
        "file deleted",
    )?;
    trial.apply(&cs)?;
    let read = trial.read(&dn, Part::User, &gp::paths())?;
    check(
        !gp::from_read(&read)
            .map_err(gpo_error)?
            .declared(Family::Drives),
        "extension removed",
    )?;
    trial.apply(&w::prepare_deletion(&trial.connection, &dn, catalog()).map_err(gpo_error)?)?;
    Ok(())
}

#[test]
#[ignore = "lab"]
fn gpo_content() -> Result<()> {
    let lab = labo::lab();
    let scratch = labo::Scratch::new("contenu")?;
    let domain = lab.domain.clone();
    let profile = lab.profile(true);
    let connection = annuaire_core::source::pdc_connection(&profile);
    let (base, dc) = connection
        .run(true, |link| {
            Ok((
                link.state.root_dse.default_naming_context.clone(),
                link.state.dc.clone(),
            ))
        })
        .map_err(|e| format!("{e:?}"))?;
    let trial = Trial {
        connection,
        profile: profile.clone(),
        journal: scratch.journal(),
    };
    let guid = w::new_guid();
    let written = write(
        &trial,
        &base,
        &dc,
        &domain,
        scratch.path().join("cache"),
        &guid,
    );
    let cleaned = if written.is_ok() {
        clean(&trial, &base, &guid)
    } else {
        remove(&trial, &base, &guid)
    };
    trial.connection.join();
    written.and(cleaned)
}

/// After a failed step: the GPO of trial deleted, if it was created.
fn remove(trial: &Trial, base: &str, guid: &str) -> Result<()> {
    let directory =
        annuaire_core::gpo::read_directory(&trial.connection).map_err(|e| format!("{e:?}"))?;
    if directory.gpos.contains_key(guid) {
        let dn = w::gpo_dn(base, guid);
        trial.apply(&w::prepare_deletion(&trial.connection, &dn, catalog()).map_err(gpo_error)?)?;
    }
    Ok(())
}

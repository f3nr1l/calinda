// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! What the lab tests share (`tests/labo_*.rs`, ADR 0020): the domain aimed at, a catalogue
//! of texts, a checked condition, a private scratch folder and a paged search read whole.
//!
//! The lab tests are `#[ignore]`d: they run only when asked, against the domain controllers
//! of the lab, with the ticket of an administrator of the domain in `KRB5CCNAME`:
//!
//! ```text
//! KRB5CCNAME=FILE:… cargo test -p annuaire-core --all-features --test 'labo_*' -- --ignored --test-threads 1
//! ```
//!
//! `ANNUAIRE_LABO_DOMAINE` (default `lab.test`) names the domain, `ANNUAIRE_LABO_DC2` (default
//! `dc2.<domain>`) a DC that is not the PDC emulator. With `win.test`, the tests that also aim
//! at the Windows DC of the lab (`wdc1.win.test`) play against it; the others say they are
//! skipped.
//!
//! Beyond the connection, the trials share here their oracles: `ssh` to the Samba DCs
//! (`ANNUAIRE_LABO_SSH`, `ANNUAIRE_LABO_SSH_DC2`: `samba-tool`, `ldbsearch`), PowerShell on the
//! Windows station or DC of the lab (`labo/poste.py`, not published: `ANNUAIRE_LABO_POSTE`
//! replaces the command), tickets asked of one KDC (`kinit`, password on its standard input),
//! and a child process of the test binary for what an ordinary account does.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use annuaire_codecs::Sid;
use annuaire_core::Connection;
use annuaire_core::actions::{self, ReadObject};
use annuaire_core::changes::{self, Changeset, ErrorRecord, Issue, Report};
use annuaire_core::error::LdapError;
use annuaire_core::journal::{self, Journal};
use annuaire_core::messages::{Catalog, English, Msg};
use annuaire_core::profile::Profile;
use annuaire_core::search::{PAGE_SIZE, Search};
use annuaire_core::session::{Entry, Scope};
use annuaire_core::source;
use annuaire_core::writer::{self, Outcome, Retry, WriteCatalog, WriteMsg};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The domain of the lab aimed at.
#[derive(Debug, Clone)]
pub struct Lab {
    pub domain: String,
    /// `DC=lab,DC=test`.
    pub base: String,
    /// A DC that is not the PDC emulator.
    pub other_dc: String,
}

pub fn lab() -> Lab {
    let domain = std::env::var("ANNUAIRE_LABO_DOMAINE")
        .unwrap_or_else(|_| "lab.test".into())
        .to_lowercase();
    let base = domain
        .split('.')
        .map(|label| format!("DC={label}"))
        .collect::<Vec<_>>()
        .join(",");
    let other_dc = std::env::var("ANNUAIRE_LABO_DC2").unwrap_or_else(|_| format!("dc2.{domain}"));
    Lab {
        domain,
        base,
        other_dc,
    }
}

impl Lab {
    /// Profile of the domain, writes allowed or not.
    pub fn profile(&self, writes: bool) -> Profile {
        let mut profile = Profile::new(self.domain.clone());
        profile.read_only = !writes;
        profile
    }

    /// The connection of the writes: the PDC emulator first.
    pub fn pdc(&self) -> (Connection, Profile) {
        let profile = self.profile(true);
        (source::pdc_connection(&profile), profile)
    }

    /// The Windows DC of the lab (`win.test`), not Samba.
    pub fn windows(&self) -> bool {
        self.domain == "win.test"
    }

    pub fn realm(&self) -> String {
        self.domain.to_uppercase()
    }

    /// The PDC emulator, where the core and the GPMC write.
    pub fn pdc_name(&self) -> String {
        if self.windows() {
            format!("wdc1.{}", self.domain)
        } else {
            format!("dc1.{}", self.domain)
        }
    }

    /// Arguments of `labo/poste.py` for the GPMC of the domain: the Windows DC itself, or the
    /// station joined to LAB.TEST.
    pub fn gpmc_target(&self) -> &'static [&'static str] {
        if self.windows() {
            &["--cible", "wdc"]
        } else {
            &[]
        }
    }
}

/// A test that plays against LAB.TEST only: false (and said) when another domain is aimed at.
pub fn samba_only(lab: &Lab) -> bool {
    if lab.windows() {
        println!("  LAB.TEST only: skipped against {}", lab.domain);
        return false;
    }
    true
}

/// The texts of the core, in English; the writer's messages by their debug form, which the
/// tests compare.
#[derive(Debug)]
pub struct Texts;

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

pub fn catalog() -> Arc<dyn Catalog + Send + Sync> {
    Arc::new(English)
}

/// A condition of the trial, printed when it holds (`--nocapture`), an error otherwise.
pub fn check(condition: bool, what: &str) -> Result<()> {
    if condition {
        println!("  ok: {what}");
        Ok(())
    } else {
        Err(format!("FAILED: {what}").into())
    }
}

/// Any error by its debug form (the error types of the core are not all `Error`).
pub fn debug<E: std::fmt::Debug>(e: E) -> Box<dyn std::error::Error> {
    format!("{e:?}").into()
}

/// A private folder of the trial (mode 700), removed with everything in it at the end.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    pub fn new(name: &str) -> Result<Self> {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().join(format!("annuaire-{name}-{}", std::process::id()));
        if path.exists() {
            std::fs::remove_dir_all(&path)?;
        }
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    /// A journal of the changes in this folder.
    pub fn journal(&self) -> Arc<Journal> {
        Arc::new(Journal::new(
            Some(self.0.join("changes.jsonl")),
            journal::MAX_SIZE,
            journal::ARCHIVES,
        ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A trial of writes on the PDC emulator: its connection, profile and journal.
#[derive(Debug)]
pub struct Trial {
    pub connection: Connection,
    pub profile: Profile,
    pub journal: Arc<Journal>,
    /// Naming context of the domain.
    pub base: String,
    /// The DC bound (the PDC emulator).
    pub dc: String,
    /// The file of the journal.
    pub journal_file: PathBuf,
}

impl Trial {
    pub fn new(lab: &Lab, scratch: &Scratch) -> Result<Self> {
        Self::with_profile(lab, scratch, lab.profile(true))
    }

    /// A trial whose connection follows `profile` (an option of the profile, as
    /// `smb2_signing`); writes allowed.
    pub fn with_profile(lab: &Lab, scratch: &Scratch, profile: Profile) -> Result<Self> {
        let connection = source::pdc_connection(&profile);
        let (base, dc) = connection
            .run(true, |link| {
                Ok((
                    link.state.root_dse.default_naming_context.clone(),
                    link.state.dc.clone(),
                ))
            })
            .map_err(debug)?;
        check(
            dc == lab.pdc_name(),
            &format!("bound to the PDC emulator {dc}"),
        )?;
        Ok(Self {
            connection,
            profile,
            journal: scratch.journal(),
            base,
            dc,
            journal_file: scratch.path().join("changes.jsonl"),
        })
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_file
    }

    /// The application of a changeset as it went, applied or not.
    pub fn outcome(
        &self,
        changeset: &Changeset,
        resumes: Option<String>,
        retry: Option<Retry>,
    ) -> Result<Outcome> {
        writer::apply(
            &self.connection,
            &self.profile,
            changeset,
            self.journal.clone(),
            Arc::new(Texts),
            resumes,
            retry,
        )
        .map_err(debug)
    }

    /// Applies a changeset that must be applied whole.
    pub fn apply(&self, changeset: &Changeset) -> Result<Report> {
        let outcome = self.outcome(changeset, None, None)?;
        if outcome.report.issue != Issue::Applied {
            return Err(format!(
                "not applied: {:?} {:?} {:?}",
                outcome.report.issue, outcome.report.error, outcome.problems
            )
            .into());
        }
        Ok(outcome.report)
    }

    /// The inverse of a report, from the journal.
    pub fn inverse(&self, report: &Report) -> Result<Changeset> {
        changes::inverse(report, &writer::read_journal(&self.journal), &Texts).map_err(debug)
    }

    /// Undoes a report (its inverse, applied as the resumption of it).
    pub fn undo(&self, report: &Report) -> Result<Report> {
        let inverse = self.inverse(report)?;
        let outcome = self.outcome(&inverse, Some(report.id.clone()), None)?;
        if outcome.report.issue != Issue::Applied {
            return Err(format!("undo not applied: {:?}", outcome.report.error).into());
        }
        Ok(outcome.report)
    }

    /// The objects that exist among `dns`, with the attributes of state of the actions.
    pub fn read(&self, dns: &[&str]) -> Result<Vec<ReadObject>> {
        self.read_with(dns, &actions::STATE_ATTRIBUTES)
    }

    pub fn read_with(&self, dns: &[&str], attributes: &[&str]) -> Result<Vec<ReadObject>> {
        let dns: Vec<String> = dns.iter().map(|&d| d.to_owned()).collect();
        actions::read_objects(&self.connection, &dns, attributes).map_err(debug)
    }

    pub fn read_one(&self, dn: &str) -> Result<ReadObject> {
        self.read(&[dn])?
            .into_iter()
            .next()
            .ok_or_else(|| format!("{dn} absent").into())
    }

    /// The DACLs of the objects (`lire_descripteurs`).
    pub fn descriptors(&self, dns: &[&str]) -> Result<Vec<ReadObject>> {
        let dns: Vec<String> = dns.iter().map(|&d| d.to_owned()).collect();
        actions::read_descriptors(&self.connection, &dns).map_err(debug)
    }

    /// The descriptor of one object, as stored (DACL only).
    pub fn descriptor(&self, dn: &str) -> Result<Vec<u8>> {
        self.descriptors(&[dn])?
            .first()
            .and_then(|o| o.values(actions::SD).into_iter().next())
            .ok_or_else(|| format!("no descriptor for {dn}").into())
    }

    /// One object read on the PDC; None if absent.
    pub fn entry(&self, dn: &str, attributes: &[&str]) -> Result<Option<Entry>> {
        entry(&self.connection, dn, attributes, None)
    }

    pub fn exists(&self, dn: &str) -> Result<bool> {
        Ok(self.entry(dn, &["1.1"])?.is_some())
    }

    /// `objectSid` of an object.
    pub fn sid(&self, dn: &str) -> Result<Sid> {
        let entry = self.entry(dn, &["objectSid"])?.ok_or("object absent")?;
        Ok(Sid::decode(
            entry.values("objectSid").first().ok_or("no objectSid")?,
        )?)
    }

    /// Removes `dn` and everything under it, leaves first, in one changeset; the protection
    /// of OUs against deletion is removed first. Nothing if absent.
    pub fn remove_tree(&self, dn: &str) -> Result<()> {
        if !self.exists(dn)? {
            return Ok(());
        }
        let mut dns: Vec<String> = entries(
            &self.connection,
            dn,
            Scope::Subtree,
            "(objectClass=*)",
            &["1.1"],
        )?
        .into_iter()
        .map(|e| e.dn)
        .collect();
        dns.sort_by_key(|d| std::cmp::Reverse(depth(d)));
        let names: Vec<&str> = dns.iter().map(String::as_str).collect();
        for ou in self.descriptors(&names)? {
            if ou.dn.to_uppercase().starts_with("OU=")
                && actions::is_protected(&ou).map_err(debug)?
            {
                self.apply(&actions::unprotect_ou(&ou).map_err(debug)?)?;
            }
        }
        self.apply(&actions::delete(&self.read(&names)?).map_err(debug)?)?;
        check(!self.exists(dn)?, &format!("{dn} removed"))
    }

    /// Creates an OU (its trial), after removing what an interrupted trial left there.
    pub fn fresh_ou(&self, parent: &str, name: &str) -> Result<String> {
        let dn = format!("OU={name},{parent}");
        self.remove_tree(&dn)?;
        self.apply(&actions::create_ou(parent, name, "").map_err(debug)?)?;
        Ok(dn)
    }
}

/// Number of RDNs of a DN (leaves first: the deepest first).
pub fn depth(dn: &str) -> usize {
    annuaire_core::dn::split(dn).map_or(0, |c| c.len())
}

/// One object read by its DN on a connection; None if absent.
pub fn entry(
    connection: &Connection,
    dn: &str,
    attributes: &[&str],
    sd_flags: Option<i64>,
) -> Result<Option<Entry>> {
    let (dn, attributes): (String, Vec<String>) = (
        dn.to_owned(),
        attributes.iter().map(|&a| a.to_owned()).collect(),
    );
    connection
        .run(true, move |link| {
            annuaire_core::search::read_entry(
                link.session.as_mut(),
                &dn,
                &attributes,
                "(objectClass=*)",
                sd_flags,
                Some(link.timeout),
            )
        })
        .map_err(debug)
}

/// The first value of an attribute, as text.
pub fn text(entry: &Entry, attribute: &str) -> String {
    entry
        .values(attribute)
        .first()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default()
}

/// Waits until `condition` holds, `limit` at most; the seconds waited.
pub fn wait(
    limit: Duration,
    what: &str,
    mut condition: impl FnMut() -> Result<bool>,
) -> Result<f64> {
    let t = Instant::now();
    loop {
        if condition()? {
            return Ok(t.elapsed().as_secs_f64());
        }
        if t.elapsed() > limit {
            return Err(format!("FAILED after {} s: {what}", limit.as_secs()).into());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

// --- Oracles --------------------------------------------------------------------------------

/// The repository (scripts of `labo/`).
pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// SSH target of a Samba DC (`dc1`, `dc2` or its full name).
pub fn ssh_target(dc: &str) -> String {
    if dc.starts_with("dc2") {
        std::env::var("ANNUAIRE_LABO_SSH_DC2").unwrap_or_else(|_| "labadmin@192.168.1.28".into())
    } else {
        std::env::var("ANNUAIRE_LABO_SSH").unwrap_or_else(|_| "labadmin@192.168.1.27".into())
    }
}

/// A command with `input` on its standard input; its standard output, an error if it fails.
pub fn run(command: &mut Command, input: &[u8]) -> Result<String> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take().ok_or("stdin")?;
    let input = input.to_vec();
    let writer = std::thread::spawn(move || stdin.write_all(&input));
    let mut stderr = child.stderr.take().ok_or("stderr")?;
    let errors = std::thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });
    let mut out = Vec::new();
    child.stdout.take().ok_or("stdout")?.read_to_end(&mut out)?;
    let status = child.wait()?;
    let _ = writer.join();
    let errors = errors.join().unwrap_or_default();
    let out = String::from_utf8_lossy(&out).into_owned();
    if !status.success() {
        let tail: String = errors
            .chars()
            .rev()
            .take(1500)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        return Err(format!("{command:?}: {status}\n{out}\n{tail}").into());
    }
    Ok(out)
}

/// A bash script on a Samba DC (`ssh … bash -s`, script on the standard input).
pub fn ssh(dc: &str, script: &str) -> Result<String> {
    run(
        Command::new("ssh").args(["-o", "BatchMode=yes", &ssh_target(dc), "bash -s"]),
        script.as_bytes(),
    )
}

/// A Python script on a Samba DC, as root (`sudo python3 - args`, script on the standard
/// input).
pub fn ssh_python(dc: &str, script: &str, args: &[&str]) -> Result<String> {
    let quoted: Vec<String> = args.iter().map(|a| quote(a)).collect();
    run(
        Command::new("ssh").args([
            "-o",
            "BatchMode=yes",
            &ssh_target(dc),
            &format!("sudo python3 - {}", quoted.join(" ")),
        ]),
        script.as_bytes(),
    )
}

/// A value quoted for a shell.
pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// An object of `ldbsearch`: attributes in lower case, values as bytes.
pub type Ldif = BTreeMap<String, Vec<Vec<u8>>>;

/// `ldbsearch` in `sam.ldb` of a DC (as root): the records, LDIF read here.
pub fn ldbsearch(
    dc: &str,
    base: &str,
    scope: &str,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<Ldif>> {
    let script = format!(
        "sudo ldbsearch -H /var/lib/samba/private/sam.ldb -s {scope} -b {} {} {} 2>/dev/null\n",
        quote(base),
        quote(filter),
        attributes.join(" ")
    );
    let output = ssh(dc, &script).or_else(|e| {
        // No such object (or base): ldbsearch fails, nothing found.
        let text = e.to_string();
        if text.contains("exit status: 1\n") || text.contains("No such Base DN") {
            Ok(String::new())
        } else {
            Err(e)
        }
    })?;
    let mut lines: Vec<String> = Vec::new();
    for line in output.lines() {
        match (line.strip_prefix(' '), lines.last_mut()) {
            (Some(rest), Some(last)) => last.push_str(rest),
            _ => lines.push(line.to_owned()),
        }
    }
    let mut records = Vec::new();
    let mut current = Ldif::new();
    for line in lines {
        if line.starts_with('#') || line.trim().is_empty() {
            if current.contains_key("dn") {
                records.push(std::mem::take(&mut current));
            }
            current.clear();
            continue;
        }
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = match value.strip_prefix(':') {
            Some(b64) => changes::base64_decode(b64.trim()).map_err(debug)?,
            None => value.trim().as_bytes().to_vec(),
        };
        current.entry(key.to_lowercase()).or_default().push(value);
    }
    if current.contains_key("dn") {
        records.push(current);
    }
    Ok(records)
}

/// The first value of an attribute of an `ldbsearch` record, as text.
pub fn ldif_text(record: &Ldif, attribute: &str) -> Option<String> {
    record
        .get(&attribute.to_lowercase())
        .and_then(|v| v.first())
        .map(|v| String::from_utf8_lossy(v).into_owned())
}

/// `samba-tool drs showrepl --summary` of a DC, last line.
pub fn showrepl(dc: &str) -> Result<String> {
    Ok(ssh(
        dc,
        "sudo samba-tool drs showrepl --summary 2>&1 | tail -1\n",
    )?
    .trim()
    .to_owned())
}

/// PowerShell on a Windows machine of the lab by `labo/poste.py` (`options`: `--cible wdc`,
/// `--domaine`, `--session`…), replayed when the guest agent answers too late.
pub fn poste(script: &str, options: &[&str]) -> Result<String> {
    let command = std::env::var("ANNUAIRE_LABO_POSTE")
        .unwrap_or_else(|_| "timeout 1800 python3 labo/poste.py".into());
    let mut last = String::new();
    for attempt in 0..4u64 {
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("{command} \"$@\""))
            .arg("poste")
            .args(options)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(script.as_bytes())?;
                }
                child.wait_with_output()
            })?;
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
        }
        last = format!(
            "{script}\n{}\n{stderr}",
            String::from_utf8_lossy(&output.stdout)
        );
        let agent = stderr.contains("qga") || stderr.contains("guest agent");
        if output.status.code() != Some(255) || !agent {
            break;
        }
        std::thread::sleep(Duration::from_secs(30 + 15 * attempt));
    }
    Err(format!("poste.py failed: {last}").into())
}

/// The lines `KEY=value` of an output (key in upper case).
pub fn lines(output: &str) -> BTreeMap<String, String> {
    output
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let key_ok = !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
            key_ok.then(|| (key.to_owned(), value.trim().to_owned()))
        })
        .collect()
}

/// The SYSVOL of dc1 copied on dc2, where the station of the lab reads it (Samba does not
/// replicate the SYSVOL: `labo/copier-sysvol.sh`); replayed if another copy runs.
pub fn copy_sysvol() -> Result<()> {
    let script = repository().join("labo/copier-sysvol.sh");
    let mut last = None;
    for attempt in 1..=3u64 {
        let t = Instant::now();
        match run(
            Command::new("bash").arg(&script).current_dir(repository()),
            b"",
        ) {
            Ok(_) => {
                println!(
                    "  SYSVOL copied on dc2 in {:.1} s",
                    t.elapsed().as_secs_f64()
                );
                return Ok(());
            }
            Err(e) => last = Some(e),
        }
        std::thread::sleep(Duration::from_secs(20 * attempt));
    }
    Err(last.unwrap_or_else(|| "copier-sysvol.sh".into()))
}

// --- Kerberos ---------------------------------------------------------------------------------

/// A private folder whose `krb5.conf` asks only `kdc`: the account was just written on the PDC,
/// and another DC knows it (or its password) only after the replication (2 to 5 s).
#[derive(Debug)]
pub struct Kdc {
    pub folder: Scratch,
    pub conf: PathBuf,
}

impl Kdc {
    pub fn new(lab: &Lab, kdc: &str) -> Result<Self> {
        let folder = Scratch::new(&format!("kdc-{kdc}"))?;
        let conf = folder.path().join("krb5.conf");
        let realm = lab.realm();
        std::fs::write(
            &conf,
            format!(
                "[libdefaults]\n default_realm = {realm}\n dns_lookup_kdc = false\n \
dns_lookup_realm = false\n rdns = false\n udp_preference_limit = 1\n\
[realms]\n {realm} = {{\n  kdc = {kdc}\n }}\n"
            ),
        )?;
        Ok(Self { folder, conf })
    }

    /// The credential cache `name` of this folder.
    pub fn cache(&self, name: &str) -> String {
        format!("FILE:{}", self.folder.path().join(name).display())
    }

    /// Asks a ticket with this password, kept in the cache `cache`: None if granted, else
    /// the message of `kinit`.
    pub fn kinit_into(&self, principal: &str, secret: &str, cache: &str) -> Option<String> {
        let result = run(
            Command::new("kinit")
                .arg(principal)
                .env("KRB5_CONFIG", &self.conf)
                .env("KRB5CCNAME", self.cache(cache)),
            format!("{secret}\n").as_bytes(),
        );
        result.err().map(|e| e.to_string())
    }

    /// Asks a ticket and destroys it: None if granted, else the message of `kinit`.
    pub fn refusal(&self, principal: &str, secret: &str) -> Option<String> {
        let refused = self.kinit_into(principal, secret, "essai");
        self.destroy("essai");
        refused
    }

    pub fn granted(&self, principal: &str, secret: &str) -> bool {
        self.refusal(principal, secret).is_none()
    }

    pub fn destroy(&self, cache: &str) {
        let _ = Command::new("kdestroy")
            .env("KRB5_CONFIG", &self.conf)
            .env("KRB5CCNAME", self.cache(cache))
            .output();
    }

    /// The environment of a process that speaks only to this KDC, with the cache `cache`.
    pub fn env(&self, cache: &str) -> Vec<(String, String)> {
        vec![
            ("KRB5_CONFIG".into(), self.conf.display().to_string()),
            ("KRB5CCNAME".into(), self.cache(cache)),
        ]
    }
}

/// A random password of `length` characters (letters and digits after `Aa1-`), never shown.
pub fn password(length: usize) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut bytes = vec![0u8; length.saturating_sub(4)];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .expect("/dev/urandom");
    let tail: String = bytes
        .iter()
        .map(|b| {
            char::from(
                ALPHABET
                    .get(usize::from(*b) % ALPHABET.len())
                    .copied()
                    .unwrap_or(b'x'),
            )
        })
        .collect();
    format!("Aa1-{tail}")
}

/// The password of an account made by `labo/peupler.py` (and `peupler-windows.ps1`):
/// `Lb-` + 12 hex of HMAC-SHA256(seed, sAMAccountName) + `-Aa1`.
pub fn lab_password(seed: &str, sam: &str) -> Result<String> {
    use openssl::{hash::MessageDigest, pkey::PKey, sign::Signer};
    let key = PKey::hmac(seed.as_bytes())?;
    let mut signer = Signer::new(MessageDigest::sha256(), &key)?;
    signer.update(sam.as_bytes())?;
    let hex: String = signer
        .sign_to_vec()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok(format!("Lb-{}-Aa1", hex.get(..12).ok_or("hmac")?))
}

/// The seed of the passwords of the lab accounts (`peupler.py`, `peupler-windows.ps1`).
pub const SEED: &str = "20261013";

// --- A child process ---------------------------------------------------------------------------

/// Runs the test `name` of this binary in a process of its own, with `env` (another ticket)
/// and `input` on its standard input (`ANNUAIRE_LABO_ENFANT` set); the line `RESULT …` it
/// printed.
pub fn child(name: &str, env: &[(String, String)], input: &str) -> Result<String> {
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([
            "--ignored",
            "--exact",
            name,
            "--nocapture",
            "--test-threads",
            "1",
        ])
        .env("ANNUAIRE_LABO_ENFANT", "1");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = run(&mut command, input.as_bytes())?;
    output
        .lines()
        .find_map(|l| l.split_once("RESULT ").map(|(_, r)| r.to_owned()))
        .ok_or_else(|| format!("no result from {name}: {output}").into())
}

/// In a child: true (and its standard input read) only when run by [`child`].
pub fn child_input() -> Option<String> {
    std::env::var_os("ANNUAIRE_LABO_ENFANT")?;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).ok()?;
    Some(input)
}

// --- The local copy -------------------------------------------------------------------------

/// One synchronization of the copy at `path` (blocking, as the thread of the source runs it):
/// the reason of a complete one (None: a delta), the steps told, the seconds taken.
/// `check_deletions`: compare the GUIDs too if the account does not see `Deleted Objects`
/// (the first synchronization of a source).
#[cfg(feature = "local-copy")]
pub fn synchronize(
    profile: &Profile,
    path: &Path,
    check_deletions: bool,
) -> Result<(
    Option<annuaire_core::sync::Reason>,
    Vec<annuaire_core::sync::Progress>,
    f64,
)> {
    let store = annuaire_core::store::Store::open(path).map_err(debug)?;
    let mut synchronizer = annuaire_core::sync::Synchronizer::new(profile.clone());
    let mut steps = Vec::new();
    let t = Instant::now();
    let reason = synchronizer
        .synchronize(&store, &mut |p| steps.push(p), check_deletions, &|_| {
            std::collections::HashSet::new()
        })
        .map_err(debug);
    synchronizer.close();
    Ok((reason?, steps, t.elapsed().as_secs_f64()))
}

/// The source that reads the copy at `path` (and the DC of `profile` for the rest).
#[cfg(feature = "local-copy")]
pub fn cache_source(profile: &Profile, path: &Path) -> Result<annuaire_core::cache::CacheSource> {
    let direct = Arc::new(source::DirectSource::new(profile.clone()));
    let store = annuaire_core::store::Store::open(path).map_err(debug)?;
    Ok(annuaire_core::cache::CacheSource::new(direct, store))
}

/// Every object of a flux of the sources.
pub fn items(flux: &source::ObjectFlux) -> Result<Vec<source::Item>> {
    let mut all = Vec::new();
    while let Some(page) = flux.next_page() {
        all.extend(page.map_err(debug)?);
    }
    Ok(all)
}

/// The name (`name`) of an item of a list.
pub fn item_name(item: &source::Item) -> String {
    match item {
        source::Item::Object(object) => object.common().name.clone(),
        source::Item::Unreadable { name, .. } => name.clone(),
    }
}

/// A notifier that does nothing (the tests wait on the flux).
pub fn quiet() -> source::Notifier {
    Box::new(|| {})
}

/// A paged search, every page kept.
pub fn pages(
    connection: &Connection,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<Vec<Entry>>> {
    let search = Search {
        base: base.into(),
        scope,
        filter: filter.into(),
        attributes: attributes.iter().map(|&a| a.to_owned()).collect(),
        page_size: PAGE_SIZE,
        sd_flags: None,
        controls: Vec::new(),
    };
    let mut pages = Vec::new();
    source::search_blocking(connection, search, &mut |page| {
        pages.push(page);
        true
    })
    .map_err(debug)?;
    Ok(pages)
}

/// The entries of a paged search.
pub fn entries(
    connection: &Connection,
    base: &str,
    scope: Scope,
    filter: &str,
    attributes: &[&str],
) -> Result<Vec<Entry>> {
    Ok(pages(connection, base, scope, filter, attributes)?
        .into_iter()
        .flatten()
        .collect())
}

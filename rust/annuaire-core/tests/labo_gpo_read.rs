// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! The GPOs read against `samba-tool` and the SYSVOL of each DC of LAB.TEST (port of
//! `test_gpo_lecture_labo.py`, J5.1 and J5.2, ADR 0020). Read only. The core reads the
//! directory on the write connection (PDC emulator, dc1) and the SYSVOL of dc1 then of dc2 over
//! SMB; the oracle, on each DC as root through SSH (`labadmin`, sudo):
//!
//! - `samba-tool gpo listall`: the same GPOs (GUID, name, version, flags);
//! - `samba-tool gpo getlink` and `getinheritance` for each container that carries `gPLink`
//!   or `gPOptions`, and five others: the same links in the same order, the same options, the
//!   same blocked inheritance;
//! - the files under `/var/lib/samba/sysvol/<domain>/Policies`: the same GPO folders, files
//!   and sizes, the same `Version=` in each GPT.INI; on dc2 likewise, and the comparison of the
//!   SYSVOLs by the core says what the comparison of the files says.
//!
//! `ANNUAIRE_LABO_SSH` and `ANNUAIRE_LABO_SSH_DC2` give the SSH targets of dc1 and dc2. See
//! `labo/mod.rs` to run it.

// serde_json's indexing gives `Null` for what is missing: it does not panic.
#![allow(clippy::indexing_slicing)]

mod labo;

use std::collections::{BTreeMap, BTreeSet};

use annuaire_codecs::gplink;
use annuaire_core::gpo::{self, GpoDirectory, SysvolDc, read_gpt_ini};
use annuaire_core::sysvol;
use serde_json::Value;

use labo::{Result, check, debug};

const DC1: &str = "dc1.lab.test";
const DC2: &str = "dc2.lab.test";

/// Run on a DC (`python3 -`, as root): GPOs, links and inheritance by samba-tool, and the
/// content of the Policies folder of the SYSVOL. Arguments: DNs of the containers asked.
const DC_SCRIPT: &str = r#"
import json, os, re, subprocess, sys

def tool(*args):
    return subprocess.run(["samba-tool", "gpo", *args, "-P"], capture_output=True, text=True)

gpos, current = [], {}
for line in tool("listall").stdout.splitlines():
    key, sep, value = line.partition(":")
    if not sep:
        continue
    key, value = key.strip(), value.strip()
    if key == "GPO":
        current = {"guid": value}
        gpos.append(current)
    else:
        current[key] = value
links, inheritance = {}, {}
for dn in sys.argv[1:]:
    found, link = [], None
    for line in tool("getlink", dn).stdout.splitlines():
        key, sep, value = line.partition(":")
        if key.strip() == "GPO":
            link = {"guid": value.strip()}
            found.append(link)
        elif key.strip() == "Options" and link is not None:
            link["options"] = value.split()
    links[dn] = found
    inheritance[dn] = tool("getinheritance", dn).stdout.strip()
root = "/var/lib/samba/sysvol/lab.test/Policies"
files, gpt = {}, {}
guid = re.compile(r"^\{[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\}$")
for folder in sorted(os.listdir(root)):
    path = os.path.join(root, folder)
    if not os.path.isdir(path) or not guid.match(folder):
        continue
    for top, _d, names in os.walk(path):
        for name in names:
            full = os.path.join(top, name)
            relative = os.path.relpath(full, path).replace("/", "\\")
            files.setdefault(folder.upper(), {})[relative] = os.path.getsize(full)
            if relative.lower() == "gpt.ini":
                gpt[folder.upper()] = open(full, "rb").read().hex()
    files.setdefault(folder.upper(), {})
print(json.dumps({"gpos": gpos, "links": links, "inheritance": inheritance,
                  "files": files, "gpt": gpt}))
"#;

fn ssh_target(dc: &str) -> String {
    let (variable, default) = if dc == DC1 {
        ("ANNUAIRE_LABO_SSH", "labadmin@192.168.1.27")
    } else {
        ("ANNUAIRE_LABO_SSH_DC2", "labadmin@192.168.1.28")
    };
    std::env::var(variable).unwrap_or_else(|_| default.into())
}

fn oracle(dc: &str, containers: &[String]) -> Result<Value> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            &ssh_target(dc),
            "sudo",
            "python3",
            "-",
        ])
        .args(containers.iter().map(|c| format!("'{c}'")))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or("stdin")?
        .write_all(DC_SCRIPT.as_bytes())?;
    let output = child.wait_with_output()?;
    check(output.status.success(), &format!("oracle of {dc}"))?;
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn text(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The flags of a GPO as samba-tool writes them, as a set of bit names.
fn flag_names(flags: i64) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    if flags & 1 != 0 {
        names.insert("GPO_FLAG_USER_DISABLE".to_owned());
    }
    if flags & 2 != 0 {
        names.insert("GPO_FLAG_MACHINE_DISABLE".to_owned());
    }
    if names.is_empty() {
        names.insert("NONE".to_owned());
    }
    names
}

fn compare_gpos(directory: &GpoDirectory, dc1: &Value) -> Result<()> {
    let expected: BTreeMap<String, (String, i64, BTreeSet<String>)> = dc1["gpos"]
        .as_array()
        .ok_or("gpos")?
        .iter()
        .map(|x| {
            let flags = x
                .get("flags")
                .and_then(Value::as_str)
                .unwrap_or("NONE")
                .split_whitespace()
                .map(String::from)
                .collect();
            (
                text(x, "guid").to_uppercase(),
                (
                    text(x, "display name"),
                    text(x, "version").parse().unwrap_or(-1),
                    flags,
                ),
            )
        })
        .collect();
    let read: BTreeMap<String, (String, i64, BTreeSet<String>)> = directory
        .gpos
        .iter()
        .map(|(guid, g)| {
            (
                guid.to_uppercase(),
                (g.name.clone(), g.version, flag_names(g.flags)),
            )
        })
        .collect();
    println!("  {} GPO", read.len());
    check(read == expected, "GPOs as samba-tool gpo listall")
}

fn compare_links(directory: &GpoDirectory, dc1: &Value, containers: &[String]) -> Result<()> {
    for dn in containers {
        let container = directory
            .containers
            .iter()
            .find(|c| &c.dn == dn)
            .ok_or("container")?;
        let expected: Vec<(String, u64)> = dc1["links"][dn]
            .as_array()
            .ok_or("links")?
            .iter()
            .map(|x| {
                let options = x.get("options").and_then(Value::as_array).map_or(0, |o| {
                    o.iter()
                        .map(|v| match v.as_str() {
                            Some("GPLINK_OPT_DISABLE") => gplink::DISABLED,
                            Some("GPLINK_OPT_ENFORCE") => gplink::ENFORCED,
                            _ => 0,
                        })
                        .sum()
                });
                (text(x, "guid").to_uppercase(), options)
            })
            .collect();
        let read: Vec<(String, u64)> = container
            .gplink
            .links()
            .map(|l| (l.guid().unwrap_or_default().to_uppercase(), l.options))
            .collect();
        check(read == expected, &format!("links of {dn}"))?;
        let blocked = text(&dc1["inheritance"], dn).contains("GPO_BLOCK_INHERITANCE");
        check(
            container.inheritance_blocked() == blocked,
            &format!("inheritance of {dn}"),
        )?;
        let written = container.gplink.write();
        check(
            gplink::GpLink::parse(&written).write() == written,
            "exact round trip of gPLink",
        )?;
    }
    Ok(())
}

fn compare_sysvol(sysvol: &SysvolDc, disk: &Value) -> Result<()> {
    check(sysvol.error.is_none(), "SYSVOL read")?;
    let files = disk["files"].as_object().ok_or("files")?;
    let folders: BTreeSet<String> = sysvol.folders.keys().map(|g| g.to_uppercase()).collect();
    let on_disk: BTreeSet<String> = files.keys().cloned().collect();
    check(folders == on_disk, &format!("GPO folders of {}", sysvol.dc))?;
    for (guid, expected) in files {
        let folder = sysvol.folder(guid).ok_or("folder")?;
        let expected: BTreeMap<String, u64> = expected
            .as_object()
            .ok_or("files of a folder")?
            .iter()
            .map(|(name, size)| (name.clone(), size.as_u64().unwrap_or(u64::MAX)))
            .collect();
        let read: BTreeMap<String, u64> = folder.files.iter().cloned().collect();
        check(
            folder.present && read == expected,
            &format!("files of {guid}"),
        )?;
        let version = disk["gpt"]
            .get(guid)
            .and_then(Value::as_str)
            .and_then(|hex| {
                (0..hex.len())
                    .step_by(2)
                    .map(|i| {
                        hex.get(i..i + 2)
                            .and_then(|b| u8::from_str_radix(b, 16).ok())
                    })
                    .collect::<Option<Vec<u8>>>()
            })
            .and_then(|bytes| read_gpt_ini(&bytes).version);
        check(
            folder.gpt.as_ref().and_then(|g| g.version) == version,
            &format!("GPT.INI version of {guid}"),
        )?;
    }
    Ok(())
}

#[test]
#[ignore = "lab"]
fn gpo_reading() -> Result<()> {
    if !labo::samba_only(&labo::lab()) {
        return Ok(());
    }
    let lab = labo::lab();
    let (connection, _) = lab.pdc();
    let directory = gpo::read_directory(&connection).map_err(debug)?;
    let sysvol = gpo::read_pdc_sysvol(&connection).map_err(debug)?;
    check(sysvol.dc == DC1, "SYSVOL of the PDC emulator")?;
    let with: Vec<String> = directory
        .containers
        .iter()
        .filter(|c| !c.gplink.elements.is_empty() || c.gpoptions != 0)
        .map(|c| c.dn.clone())
        .collect();
    let containers: Vec<String> = with
        .iter()
        .cloned()
        .chain(
            directory
                .containers
                .iter()
                .filter(|c| !with.contains(&c.dn))
                .map(|c| c.dn.clone())
                .take(5),
        )
        .collect();
    let dc1 = oracle(DC1, &containers)?;
    compare_gpos(&directory, &dc1)?;
    compare_links(&directory, &dc1, &containers)?;
    compare_sysvol(&sysvol, &dc1)?;
    let inventory = gpo::Inventory {
        directory,
        sysvol,
        others: Vec::new(),
    };
    for guid in inventory.directory.gpos.keys() {
        check(
            inventory.deviations(guid).is_empty(),
            &format!("{guid}: directory and SYSVOL agree"),
        )?;
    }
    let others = gpo::compare_dcs(&inventory.directory, DC1, sysvol::Protection::Encrypted);
    let [dc2] = others.as_slice() else {
        return Err("one other DC".into());
    };
    check(dc2.dc == DC2, "the other DC")?;
    let disk = oracle(DC2, &[])?;
    compare_sysvol(dc2, &disk)?;
    let same = dc1["files"] == disk["files"] && dc1["gpt"] == disk["gpt"];
    check(
        inventory.dc_deviations(dc2).is_empty() == same,
        "comparison of the SYSVOLs as the files say",
    )?;
    connection.join();
    Ok(())
}

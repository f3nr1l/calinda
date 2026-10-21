// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Local journal of the changes (plan, 0.1): a JSON Lines file, one record per line.
//!
//! Port of `annuaire/core/journal.py`, same bytes on disk. Location:
//! `$XDG_STATE_HOME/calinda/changes.jsonl` (`~/.local/state/…` otherwise). File 0600,
//! directory 0700: it holds data of the directory, never a secret (`changes` hides them).
//! Each line is written by one append `write`, then `fsync`: the intention of a write is on
//! disk before the first request leaves. A line cut by a crash is skipped when reading.
//! Beyond `max_size`, the file becomes `changes.jsonl.1` (older archives move up one rank,
//! the last one goes).

use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

use serde_json::{Map, Value};

pub const FILE_NAME: &str = "changes.jsonl";
pub const MAX_SIZE: u64 = 10 * 1024 * 1024;
pub const ARCHIVES: u32 = 5;

/// `$XDG_STATE_HOME/calinda/changes.jsonl`, or `~/.local/state/calinda/changes.jsonl`.
pub fn default_path() -> PathBuf {
    crate::storage::state_home()
        .join(crate::storage::APP_DIR)
        .join(FILE_NAME)
}

/// One line of the journal, as `json.dumps(…, ensure_ascii=False, separators=(",", ":"))`.
pub fn line(record: &Map<String, Value>) -> String {
    let mut text = Value::Object(record.clone()).to_string();
    text.push('\n');
    text
}

/// The journal file, shared between threads (writes serialized).
#[derive(Debug)]
pub struct Journal {
    pub path: PathBuf,
    max_size: u64,
    archives: u32,
    lock: Mutex<()>,
}

impl Journal {
    pub fn new(path: Option<PathBuf>, max_size: u64, archives: u32) -> Self {
        Self {
            path: path.unwrap_or_else(default_path),
            max_size,
            archives,
            lock: Mutex::new(()),
        }
    }

    fn archive(&self, rank: u32) -> PathBuf {
        let mut name = self.path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".{rank}"));
        self.path.with_file_name(name)
    }

    fn rotate(&self) -> std::io::Result<()> {
        match std::fs::metadata(&self.path) {
            Ok(m) if m.len() < self.max_size => return Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        match std::fs::remove_file(self.archive(self.archives)) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        for rank in (1..self.archives).rev() {
            if self.archive(rank).exists() {
                std::fs::rename(self.archive(rank), self.archive(rank + 1))?;
            }
        }
        std::fs::rename(&self.path, self.archive(1))
    }

    /// Appends a record; an error if the disk refuses (the caller gives up then).
    pub fn write(&self, record: &Map<String, Value>) -> std::io::Result<()> {
        let text = line(record);
        let _guard = self.lock.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
        self.rotate()?;
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .open(&self.path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()
    }

    /// Every record, oldest first, archives included; unreadable lines skipped.
    pub fn read(&self) -> Vec<Map<String, Value>> {
        let mut files: Vec<PathBuf> = (1..=self.archives).rev().map(|r| self.archive(r)).collect();
        files.push(self.path.clone());
        let mut records = Vec::new();
        for path in files {
            read_file(&path, &mut records);
        }
        records
    }
}

fn read_file(path: &Path, records: &mut Vec<Map<String, Value>>) {
    let Ok(file) = File::open(path) else {
        return;
    };
    for line in BufReader::new(file).split(b'\n') {
        let Ok(line) = line else {
            return;
        };
        // A line cut by a crash, or not an object: skipped.
        if let Ok(Value::Object(record)) = serde_json::from_slice::<Value>(&line) {
            records.push(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn temporary() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "annuaire-journal-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn record(n: u32) -> Map<String, Value> {
        let Value::Object(m) =
            serde_json::json!({"id": n, "texte": "é\n\u{1f}", "liste": [1, null]})
        else {
            unreachable!()
        };
        m
    }

    #[test]
    fn writes_lines_like_python() {
        assert_eq!(
            line(&record(1)),
            "{\"id\":1,\"texte\":\"é\\n\\u001f\",\"liste\":[1,null]}\n"
        );
    }

    #[test]
    fn rotates_and_reads_back() {
        let dir = temporary();
        let journal = Journal::new(Some(dir.join("etat").join(FILE_NAME)), 60, 2);
        for n in 0..8 {
            journal.write(&record(n)).unwrap();
        }
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&journal.path), 0o600);
        assert_eq!(mode(&dir.join("etat")), 0o700);
        // 47 bytes a line: two lines a file, two archives kept, the oldest file gone.
        let ids: Vec<i64> = journal
            .read()
            .iter()
            .map(|r| r["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, [2, 3, 4, 5, 6, 7]);
        std::fs::write(&journal.path, b"{\"id\":9}\n{\"id\":\n[1]\n").unwrap();
        let ids: Vec<i64> = journal
            .read()
            .iter()
            .map(|r| r["id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids, [2, 3, 4, 5, 9]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

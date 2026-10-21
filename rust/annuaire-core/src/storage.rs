// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Local copy of a domain (JC, `annuaire.core.stockage`): where it lives and how it is
//! erased (R4.2). The SQLite store itself comes with R4.4.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Name of the application's directory under each XDG base (cache, state, data).
pub const APP_DIR: &str = "calinda";

/// `$VAR`, or `$HOME/<default>` when it is unset or empty (XDG Base Directory).
fn xdg_home(var: &str, default: &str) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map_or_else(PathBuf::new, PathBuf::from)
                .join(default)
        })
}

/// `$XDG_CACHE_HOME`, or `~/.cache`. Under Flatpak, it already belongs to the application.
pub fn cache_home() -> PathBuf {
    xdg_home("XDG_CACHE_HOME", ".cache")
}

/// `$XDG_STATE_HOME`, or `~/.local/state`.
pub fn state_home() -> PathBuf {
    xdg_home("XDG_STATE_HOME", ".local/state")
}

/// `$XDG_DATA_HOME`, or `~/.local/share`.
pub fn data_home() -> PathBuf {
    xdg_home("XDG_DATA_HOME", ".local/share")
}

/// `$XDG_CACHE_HOME/calinda` (`~/.cache/calinda` by default).
pub fn cache_dir() -> PathBuf {
    cache_home().join(APP_DIR)
}

/// One file per domain profile (the domain is a DNS name checked by the profile).
pub fn cache_path(domain: &str, dir: Option<&Path>) -> PathBuf {
    dir.map_or_else(cache_dir, Path::to_path_buf)
        .join(format!("{domain}.sqlite"))
}

fn files(path: &Path) -> [PathBuf; 4] {
    let with = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    [
        path.to_path_buf(),
        with("-wal"),
        with("-shm"),
        with("-journal"),
    ]
}

/// Erases the copy (base, WAL journal, shared memory); true if there was something.
pub fn erase(path: &Path) -> std::io::Result<bool> {
    let mut found = false;
    for file in files(path) {
        match std::fs::remove_file(&file) {
            Ok(()) => found = true,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn erase_a_copy() {
        let dir = std::env::temp_dir().join(format!("annuaire-storage-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = cache_path("lab.test", Some(&dir));
        assert_eq!(path, dir.join("lab.test.sqlite"));
        assert!(!erase(&path).unwrap());
        std::fs::write(&path, b"x").unwrap();
        std::fs::write(dir.join("lab.test.sqlite-wal"), b"x").unwrap();
        assert!(erase(&path).unwrap());
        assert!(!path.exists() && !dir.join("lab.test.sqlite-wal").exists());
        std::fs::remove_dir(&dir).unwrap();
    }
}

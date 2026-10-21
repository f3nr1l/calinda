#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
#
# Script de « meson dist » (R4.0, ADR 0018) : copie les crates de Cargo.lock dans l'archive
# (rust/vendor-cargo), pour une construction sans réseau (rpmbuild, mock, Flatpak). Seules les
# cibles Linux sont gardées : les crates propres à Windows sont vidées par cargo-vendor-filterer.
# Toutes les fonctions : sans elles, les crates d'une fonction facultative seraient vidées
# aussi. Pour le Flatpak, depuis la racine du dépôt (README) :
#   MESON_DIST_ROOT=. build-aux/vendre-crates.sh
set -eu
cd "$MESON_DIST_ROOT/rust"
cargo vendor-filterer --all-features --versioned-dirs \
    --platform=x86_64-unknown-linux-gnu --platform=aarch64-unknown-linux-gnu \
    vendor-cargo > /dev/null

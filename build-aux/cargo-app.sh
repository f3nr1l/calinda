#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
#
# L'application (ADR 0019), appelée par rust/annuaire-app/meson.build :
#   cargo-app.sh SORTIE MANIFESTE CIBLE VENDOR PROFIL
# construit le binaire `calinda` dans CIBLE et le copie en SORTIE. Les chemins d'installation
# arrivent par l'environnement (ANNUAIRE_PKGDATADIR, ANNUAIRE_LOCALEDIR), lus à la compilation.
# Si VENDOR existe (archive de « meson dist »), les crates y sont prises, sans réseau ; sinon
# cargo les télécharge, selon Cargo.lock.
set -eu
sortie=$1 manifeste=$2 cible=$3 vendor=$4 profil=$5

set -- build --manifest-path "$manifeste" --target-dir "$cible" --locked \
    -p annuaire-app --bin calinda --profile "$profil"
if [ -d "$vendor" ]; then
    set -- "$@" --offline \
        --config "source.crates-io.replace-with='vendored'" \
        --config "source.vendored.directory='$vendor'"
fi
cargo "$@"
case $profil in dev) dossier=debug ;; *) dossier=$profil ;; esac
cp "$cible/$dossier/calinda" "$sortie"

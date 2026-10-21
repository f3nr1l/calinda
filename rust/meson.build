# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

# L'application (ADR 0019) : cargo construit le binaire (build-aux/cargo-app.sh), meson les
# interfaces, les ressources et les catalogues.
cargo = find_program('cargo')

# Crates copiées dans l'archive de « meson dist », pour une construction sans réseau.
meson.add_dist_script('../build-aux/vendre-crates.sh')

subdir('annuaire-app')

# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

# .spec à la version du projet, déposé à la racine de l'archive de « meson dist »
# pour « rpmbuild -ta » (README, « Construire le RPM »).
spec_file = configure_file(
  input: 'calinda.spec.in',
  output: 'calinda.spec',
  configuration: {'VERSION': meson.project_version()},
)

meson.add_dist_script('sh', '-c', 'cp "$1" "$MESON_DIST_ROOT"', 'sh', spec_file)

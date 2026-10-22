# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

# Répertoire debian/ déposé à la racine de l'archive de « meson dist », pour
# dpkg-buildpackage (README, « Construire le paquet Debian »). Sa version doit suivre celle
# du projet : debian/changelog est tenu à la main, comme le %changelog du .spec.
deb_version = import('fs').read('debian/changelog').split('\n')[0].split('(')[1].split('-')[0]
if deb_version != meson.project_version()
  error('debian/changelog est en @0@, le projet en @1@'.format(deb_version, meson.project_version()))
endif

meson.add_dist_script(
  'sh', '-c', 'cp -R "$1" "$MESON_DIST_ROOT/debian"', 'sh',
  meson.current_source_dir() / 'debian',
)

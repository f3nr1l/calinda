# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

desktop_file = i18n.merge_file(
  input: 'io.github.f3nr1l.Calinda.desktop.in',
  output: 'io.github.f3nr1l.Calinda.desktop',
  type: 'desktop',
  po_dir: meson.project_source_root() / 'po',
  install: true,
  install_dir: datadir / 'applications',
)

metainfo_file = i18n.merge_file(
  input: 'io.github.f3nr1l.Calinda.metainfo.xml.in',
  output: 'io.github.f3nr1l.Calinda.metainfo.xml',
  po_dir: meson.project_source_root() / 'po',
  install: true,
  install_dir: datadir / 'metainfo',
)

# Icônes de l'application, sous CC-BY-SA-4.0 (en-têtes SPDX des fichiers).
install_subdir(
  'icons/hicolor',
  install_dir: datadir / 'icons',
)

install_data(
  'io.github.f3nr1l.Calinda.gschema.xml',
  install_dir: datadir / 'glib-2.0' / 'schemas',
)

# Schéma compilé dans le répertoire de build : « meson devenv » le donne à l'application
# sans installation (rust/annuaire-app/src/config.rs).
gnome.compile_schemas(
  build_by_default: true,
  depend_files: files('io.github.f3nr1l.Calinda.gschema.xml'),
)

devenv_schemas = environment()
devenv_schemas.set('GSETTINGS_SCHEMA_DIR', meson.current_build_dir())
meson.add_devenv(devenv_schemas)


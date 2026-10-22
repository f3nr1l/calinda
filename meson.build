# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

project(
  'calinda',
  version: '1.2.1',
  license: 'GPL-3.0-or-later',
  meson_version: '>= 1.1.0',
  default_options: ['warning_level=2'],
)

gnome = import('gnome')
i18n = import('i18n')

application_id = 'io.github.f3nr1l.Calinda'

# Chemins d'installation
prefix = get_option('prefix')
datadir = get_option('datadir')
pkgdatadir = datadir / application_id
localedir = prefix / get_option('localedir')

# blueprint-compiler : système s'il existe, sinon sous-projet (wrap) — aucune
# installation requise sur la machine de développement.
blueprint_compiler = find_program('blueprint-compiler')

subdir('data')
subdir('po')
subdir('rust')
subdir('packaging/rpm')
subdir('packaging/deb')

gnome.post_install(
  glib_compile_schemas: true,
  gtk_update_icon_cache: true,
  update_desktop_database: true,
)

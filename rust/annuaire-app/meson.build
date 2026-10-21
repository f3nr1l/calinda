# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

# L'application (ADR 0019) : Blueprint (data/ui) → ressource, binaire `calinda` par cargo
# (build-aux/cargo-app.sh) ; le catalogue est dans po/ à la racine.

# Un Blueprint par écran.
app_blueprints = [
  'accueil',
  'apercu',
  'attributs',
  'dialogue-ace',
  'dialogue-attribut',
  'dialogue-classes',
  'dialogue-delegation',
  'dialogue-deplacer',
  'dialogue-enregistrement-dns',
  'dialogue-gpo-filtrage',
  'dialogue-gpo-lier',
  'dialogue-gpo-nom',
  'dialogue-gpo-principaux',
  'dialogue-gpo-restaurer',
  'dialogue-gpo-sauvegarde',
  'dialogue-gpo-securite',
  'dialogue-groupe',
  'dialogue-membres',
  'dialogue-mot-de-passe',
  'dialogue-ou',
  'dialogue-pref-cible',
  'dialogue-pref-imprimante',
  'dialogue-pref-lecteur',
  'dialogue-pref-raccourci',
  'dialogue-pref-registre',
  'dialogue-profil',
  'dialogue-pso',
  'dialogue-registre-brut',
  'dialogue-renommer',
  'dialogue-strategie',
  'dialogue-ticket',
  'dialogue-utilisateur',
  'dns',
  'editeur-gpo',
  'editeur-modeles',
  'fenetre',
  'fiche',
  'gpo',
  'gpo-securite-comptes',
  'gpo-securite-droits',
  'gpo-securite-groupes',
  'historique',
  'ligne-profil',
  'preferences',
  'pso',
  'recherche',
  'sante-dns',
  'securite',
  'shortcuts-dialog',
  'strategie',
]

app_blp = []
app_ui = []
foreach nom : app_blueprints
  app_blp += files('data/ui' / nom + '.blp')
  app_ui += nom + '.ui'
endforeach

app_ui_targets = custom_target(
  'app-blueprints',
  input: app_blp,
  output: app_ui,
  command: [
    blueprint_compiler, 'batch-compile',
    '@OUTDIR@',
    '@CURRENT_SOURCE_DIR@/data/ui',
    '@INPUT@',
  ],
)

app_gresource = gnome.compile_resources(
  'calinda',
  'data/calinda.gresource.xml',
  dependencies: app_ui_targets,
  source_dir: [
    meson.current_build_dir(),
    meson.current_source_dir() / 'data' / 'icones',
  ],
  gresource_bundle: true,
  install: true,
  install_dir: pkgdatadir,
)

custom_target(
  'calinda-bin',
  output: 'calinda',
  command: [
    find_program('../../build-aux/cargo-app.sh'),
    '@OUTPUT@',
    meson.project_source_root() / 'rust' / 'Cargo.toml',
    meson.project_build_root() / 'rust' / 'target',
    meson.project_source_root() / 'rust' / 'vendor-cargo',
    get_option('buildtype') == 'debug' ? 'dev' : 'release',
  ],
  env: {
    'ANNUAIRE_PKGDATADIR': prefix / pkgdatadir,
    'ANNUAIRE_LOCALEDIR': localedir,
  },
  depends: app_gresource,
  console: true,
  build_by_default: true,
  build_always_stale: true,
  install: true,
  install_dir: get_option('bindir'),
)

app_devenv = environment()
app_devenv.set('ANNUAIRE_APP_RESOURCE', meson.current_build_dir() / 'calinda.gresource')
app_devenv.set('ANNUAIRE_APP_LOCALEDIR', meson.project_build_root() / 'po')
meson.add_devenv(app_devenv)

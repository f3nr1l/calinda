# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier

# Catalogue (ADR 0019 § 4) : l'anglais langue source, fr.po la traduction française, tenue à
# la main depuis la bascule. Mots-clés de i18n.rs en plus de ceux de GLib. Emplacements sans
# numéro de ligne : le .pot ne change qu'avec les messages.
i18n.gettext(meson.project_name(),
  preset: 'glib',
  args: [
    '--from-code=UTF-8',
    '--add-location=file',
    '--keyword=tr',
    '--keyword=tr_ctx:1c,2',
    '--keyword=tr_n:1,2',
  ],
)

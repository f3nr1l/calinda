#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
"""Audit d'accessibilité (J2.9) : contrôles interactifs sans nom dans l'arbre AT-SPI.

Lit, comme le ferait un lecteur d'écran, l'arbre d'accessibilité de l'application dont
le numéro de processus est donné, et relève chaque contrôle interactif montré à l'écran
(bouton, interrupteur, saisie, liste déroulante, onglet, ligne de liste, entrée de
menu…) qui n'a pas de nom accessible. Écrit le relevé en JSON :

    python3 audit_atspi.py PID SORTIE.json ETAPE

À lancer dans la même session D-Bus que l'application (bus d'accessibilité commun) et
hors de son processus : l'application doit pouvoir répondre pendant la lecture.
`essai_clavier.py` le lance à chaque étape de son parcours. Sortie : 0 si aucun contrôle
sans nom, 1 sinon.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import gi

gi.require_version("Atspi", "2.0")

from gi.repository import Atspi  # noqa: E402

R = Atspi.Role
INTERACTIFS = {
    R.PUSH_BUTTON,
    R.TOGGLE_BUTTON,
    R.CHECK_BOX,
    R.RADIO_BUTTON,
    R.SWITCH,
    R.MENU_ITEM,
    R.CHECK_MENU_ITEM,
    R.RADIO_MENU_ITEM,
    R.ENTRY,
    R.PASSWORD_TEXT,
    R.SPIN_BUTTON,
    R.COMBO_BOX,
    R.PAGE_TAB,
    R.SLIDER,
    R.LINK,
    R.LIST_ITEM,
    R.TABLE_ROW,
    R.TABLE_COLUMN_HEADER,
    R.TREE_ITEM,
    R.TABLE,
    R.TREE_TABLE,
    R.LIST_BOX,
    R.TREE,
}
"""Rôles qui demandent un nom (ARIA : widgets, et conteneurs composites où le focus se
déplace ; une simple liste, `LIST`, n'en demande pas)."""

LIGNES = {R.LIST_ITEM, R.TABLE_ROW, R.TREE_ITEM}
"""Une ligne de liste n'est un contrôle que si elle prend le focus ; sinon c'est du contenu,
que les lecteurs d'écran lisent par ses enfants (lignes de l'aide des raccourcis, par
exemple)."""

PROFONDEUR = 60


def application(pid: int) -> Atspi.Accessible | None:
    bureau = Atspi.get_desktop(0)
    for i in range(bureau.get_child_count()):
        app = bureau.get_child_at_index(i)
        if app is not None and app.get_process_id() == pid:
            return app
    return None


def nom_par_relation(noeud: Atspi.Accessible) -> str:
    """Nom donné par une relation « étiqueté par » (ARIA aria-labelledby), comme le calcule un
    lecteur d'écran quand le nom propre est vide : GTK 4.22 laisse vide celui des entrées de
    menu (GtkModelButton), étiquetées par leur libellé."""
    noms = []
    for relation in noeud.get_relation_set():
        if relation.get_relation_type() != Atspi.RelationType.LABELLED_BY:
            continue
        for i in range(relation.get_n_targets()):
            cible = relation.get_target(i)
            if cible is not None and (nom := (cible.get_name() or "").strip()):
                noms.append(nom)
    return " ".join(noms)


def chemin(noeud: Atspi.Accessible) -> str:
    parties = []
    courant: Atspi.Accessible | None = noeud
    while courant is not None and len(parties) < 8:
        nom = courant.get_name() or ""
        parties.append(f"{courant.get_role_name()}{f' « {nom} »' if nom else ''}")
        courant = courant.get_parent()
        if courant is not None and courant.get_role() == R.APPLICATION:
            break
    return " < ".join(parties)


def parcourir(
    noeud: Atspi.Accessible, profondeur: int, controles: list[dict[str, str]], vus: set[int]
) -> None:
    if profondeur > PROFONDEUR:
        return
    etats = noeud.get_state_set()
    if not etats.contains(Atspi.StateType.SHOWING):
        return
    role = noeud.get_role()
    if role in LIGNES and not etats.contains(Atspi.StateType.FOCUSABLE):
        pass
    elif role in INTERACTIFS:
        nom = (noeud.get_name() or "").strip()
        par_relation = "" if nom else nom_par_relation(noeud)
        controles.append(
            {
                "role": noeud.get_role_name(),
                "nom": nom or par_relation,
                "par_relation": bool(par_relation),
                "description": (noeud.get_description() or "").strip(),
                "chemin": chemin(noeud),
                "enfants": [
                    f"{e.get_role_name()} « {e.get_name() or ''} »"
                    for e in (noeud.get_child_at_index(i) for i in range(noeud.get_child_count()))
                    if e is not None
                ][:4],
                "relations": [
                    str(rel.get_relation_type().value_nick) for rel in noeud.get_relation_set()
                ],
            }
        )
    for i in range(noeud.get_child_count()):
        enfant = noeud.get_child_at_index(i)
        if enfant is not None and hash(enfant) not in vus:
            vus.add(hash(enfant))
            parcourir(enfant, profondeur + 1, controles, vus)


def main() -> int:
    pid, sortie, etape = int(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    Atspi.set_timeout(5000, 20000)
    app = application(pid)
    if app is None:
        print(f"application {pid} absente du bus d'accessibilité", file=sys.stderr)
        return 2
    controles: list[dict[str, str]] = []
    for i in range(app.get_child_count()):
        fenetre = app.get_child_at_index(i)
        if fenetre is not None:
            parcourir(fenetre, 0, controles, set())
    sans_nom = [c for c in controles if not c["nom"]]
    par_relation = [c["nom"] for c in controles if c["par_relation"]]
    sortie.write_text(
        json.dumps(
            {
                "etape": etape,
                "controles": len(controles),
                "sans_nom": sans_nom,
                "nommes_par_relation": par_relation,
            },
            ensure_ascii=False,
            indent=1,
        )
    )
    print(
        f"audit {etape} : {len(controles)} contrôles, {len(sans_nom)} sans nom"
        f" ({len(par_relation)} nommés par relation)",
        file=sys.stderr,
    )
    return 1 if sans_nom else 0


if __name__ == "__main__":
    sys.exit(main())

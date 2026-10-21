#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
"""Parité d'un écran entre l'application Python et l'application Rust (ADR 0019 § 7).

    python3 arbre_atspi.py releve PID SORTIE.txt [NOM…]   arbre d'accessibilité montré à
                                                          l'écran, après avoir activé, dans
                                                          l'ordre, les boutons (ou boutons et
                                                          entrées de menu) nommés ; un NOM
                                                          `choisir:LISTE>LIGNE` sélectionne
                                                          la ligne LIGNE de la liste ou de
                                                          l'arbre LISTE (interface Selection
                                                          d'AT-SPI, comme un lecteur d'écran) ;
                                                          `NOM#2` vise le deuxième élément
                                                          montré de ce nom ; `pause:S` attend
                                                          S secondes
    python3 arbre_atspi.py comparer A.txt B.txt [--gtk]  différences, code 1 s'il y en a ;
                                                          `--gtk` ramène à l'anglais les
                                                          libellés propres à GTK et
                                                          libadwaita, que l'application
                                                          Python ne traduit pas

Le relevé écrit une ligne par élément montré (état SHOWING), indentée selon la profondeur :
rôle, nom, description, et les états qui changent l'usage (sensible, focalisable, coché,
déplié, sélectionné). Les deux applications sont lancées dans la même langue, sur les mêmes
données, dans le même environnement privé que les autres essais (`essai_clavier.py`), et
relevées hors de leur processus, comme par un lecteur d'écran. Même parcours que
`audit_atspi.py`.
"""

from __future__ import annotations

import difflib
import sys
import time
import warnings
from pathlib import Path

import gi

gi.require_version("Atspi", "2.0")

from audit_atspi import PROFONDEUR, application  # noqa: E402
from gi.repository import Atspi  # noqa: E402

S = Atspi.StateType
ETATS = {
    S.SENSITIVE: "sensible",
    S.FOCUSABLE: "focalisable",
    S.CHECKED: "coché",
    S.EXPANDED: "déplié",
    S.SELECTED: "sélectionné",
}


def ligne(noeud: Atspi.Accessible, profondeur: int) -> str:
    etats = noeud.get_state_set()
    marques = ",".join(nom for etat, nom in ETATS.items() if etats.contains(etat))
    nom = (noeud.get_name() or "").strip()
    description = (noeud.get_description() or "").strip()
    texte = f"{'  ' * profondeur}{noeud.get_role_name()} « {nom} » [{marques}]"
    return texte + (f" — {description}" if description else "")


def parcourir(noeud: Atspi.Accessible, profondeur: int, lignes: list[str]) -> None:
    if profondeur > PROFONDEUR or not noeud.get_state_set().contains(S.SHOWING):
        return
    lignes.append(ligne(noeud, profondeur))
    for i in range(noeud.get_child_count()):
        enfant = noeud.get_child_at_index(i)
        if enfant is not None:
            parcourir(enfant, profondeur + 1, lignes)


BOUTONS = {
    Atspi.Role.PUSH_BUTTON,
    Atspi.Role.TOGGLE_BUTTON,
    Atspi.Role.MENU_ITEM,
    Atspi.Role.LIST_ITEM,
}
"""Ce qu'on active : boutons, boutons de menu (bascule), entrées de menu, lignes activables
(profil de l'accueil)."""


def actionnable(noeud: Atspi.Accessible) -> bool:
    """Vrai si l'élément a une action (un bouton de menu enveloppe son bouton bascule, qui
    porte le même nom et seul l'action). La ligne d'une liste de GTK n'a que
    `listitem.scroll-to`, sans effet : c'est son bouton de dépliage (arbre) qui agit."""
    try:
        n = Atspi.Action.get_n_actions(noeud)
        with warnings.catch_warnings():  # get_action_name est le seul nom lisible
            warnings.simplefilter("ignore", DeprecationWarning)
            premiere = Atspi.Action.get_action_name(noeud, 0) if n else ""
        return bool(n) and premiere != "listitem.scroll-to"
    except Exception:  # pas d'interface Action
        return False


def trouver(
    noeud: Atspi.Accessible, nom: str, profondeur: int = 0, trouves: list | None = None
) -> list[Atspi.Accessible]:
    """Les boutons montrés qui portent ce nom, dans l'ordre de l'arbre."""
    trouves = [] if trouves is None else trouves
    if profondeur > PROFONDEUR or not noeud.get_state_set().contains(S.SHOWING):
        return trouves
    if (
        noeud.get_role() in BOUTONS
        and (noeud.get_name() or "").strip() == nom
        and actionnable(noeud)
    ):
        trouves.append(noeud)
    for i in range(noeud.get_child_count()):
        enfant = noeud.get_child_at_index(i)
        if enfant is not None:
            trouver(enfant, nom, profondeur + 1, trouves)
    return trouves


def rang(nom: str) -> tuple[str, int]:
    """`NOM#N` : le N-ième élément de ce nom (1 par défaut)."""
    base, _diese, n = nom.rpartition("#")
    return (base, int(n) - 1) if base and n.isdigit() else (nom, 0)


LISTES = {Atspi.Role.LIST, Atspi.Role.TREE, Atspi.Role.TABLE, Atspi.Role.TREE_TABLE}


def trouver_liste(
    noeud: Atspi.Accessible, nom: str, profondeur: int = 0
) -> Atspi.Accessible | None:
    """La première liste (ou arbre, tableau) montrée qui porte ce nom."""
    if profondeur > PROFONDEUR or not noeud.get_state_set().contains(S.SHOWING):
        return None
    if noeud.get_role() in LISTES and (noeud.get_name() or "").strip() == nom:
        return noeud
    for i in range(noeud.get_child_count()):
        enfant = noeud.get_child_at_index(i)
        if enfant is not None and (trouve := trouver_liste(enfant, nom, profondeur + 1)):
            return trouve
    return None


def sous_listes(noeud: Atspi.Accessible, profondeur: int = 0) -> list[Atspi.Accessible]:
    """Les listes montrées sous `noeud`, à trois niveaux au plus."""
    trouvees: list[Atspi.Accessible] = []
    if profondeur >= 3:
        return trouvees
    for i in range(noeud.get_child_count()):
        enfant = noeud.get_child_at_index(i)
        if enfant is None or not enfant.get_state_set().contains(S.SHOWING):
            continue
        if enfant.get_role() in LISTES:
            trouvees.append(enfant)
        trouvees += sous_listes(enfant, profondeur + 1)
    return trouvees


def choisir(app: Atspi.Accessible, liste: str, ligne: str) -> bool:
    """Sélectionne la ligne `ligne` de la liste `liste` : AT-SPI ne sait pas activer une
    ligne d'arbre, mais sait la sélectionner (pages de l'éditeur de GPO)."""
    for i in range(app.get_child_count()):
        fenetre = app.get_child_at_index(i)
        trouvee = trouver_liste(fenetre, liste) if fenetre is not None else None
        if trouvee is None:
            continue
        ligne, n = rang(ligne)
        # Les lignes d'un tableau sont dans une liste sans nom, sous le tableau.
        for conteneur in [trouvee, *sous_listes(trouvee)]:
            for j in range(conteneur.get_child_count()):
                enfant = conteneur.get_child_at_index(j)
                if enfant is not None and (enfant.get_name() or "").strip() == ligne:
                    if n > 0:
                        n -= 1
                        continue
                    Atspi.Selection.select_child(conteneur, j)
                    time.sleep(1.5)
                    return True
        print(f"ligne « {ligne} » introuvable dans « {liste} »", file=sys.stderr)
        return False
    print(f"liste « {liste} » introuvable", file=sys.stderr)
    return False


def activer(app: Atspi.Accessible, nom: str) -> bool:
    """Active le bouton `nom` (action par défaut, comme une technologie d'assistance), ou
    sélectionne une ligne (`choisir:LISTE>LIGNE`)."""
    if nom.startswith("pause:"):
        time.sleep(float(nom.removeprefix("pause:")))
        return True
    if nom.startswith("choisir:") and ">" in nom:
        liste, ligne = nom.removeprefix("choisir:").split(">", 1)
        return choisir(app, liste, ligne)
    nom, n = rang(nom)
    boutons: list[Atspi.Accessible] = []
    for i in range(app.get_child_count()):
        fenetre = app.get_child_at_index(i)
        if fenetre is not None:
            trouver(fenetre, nom, 0, boutons)
    if len(boutons) > n:
        Atspi.Action.do_action(boutons[n], 0)
        time.sleep(1.5)
        return True
    print(f"bouton « {nom} » introuvable", file=sys.stderr)
    return False


def releve(pid: int, sortie: Path, boutons: list[str]) -> int:
    Atspi.set_timeout(5000, 20000)
    app = application(pid)
    if app is None:
        print(f"application {pid} absente du bus d'accessibilité", file=sys.stderr)
        return 2
    for nom in boutons:
        if not activer(app, nom):
            return 2
    lignes: list[str] = []
    for i in range(app.get_child_count()):
        fenetre = app.get_child_at_index(i)
        if fenetre is not None:
            parcourir(fenetre, 0, lignes)
    sortie.write_text("\n".join(lignes) + "\n", encoding="utf-8")
    print(f"relevé {sortie.name} : {len(lignes)} éléments", file=sys.stderr)
    return 0


GTK = [
    (
        "« Réduire » [sensible,focalisable] — Minimise la fenêtre",
        "« Minimize » [sensible,focalisable] — Minimize the window",
    ),
    (
        "« Maximiser » [sensible,focalisable] — Maximise la fenêtre",
        "« Maximize » [sensible,focalisable] — Maximize the window",
    ),
    (
        "« Restaurer » [sensible,focalisable] — Restaure la fenêtre",
        "« Restore » [sensible,focalisable] — Restore the window",
    ),
    (
        "« Fermer » [sensible,focalisable] — Ferme la fenêtre",
        "« Close » [sensible,focalisable] — Close the window",
    ),
    (
        "« Fermer » [sensible,focalisable] — Close the window",
        "« Close » [sensible,focalisable] — Close the window",
    ),
    ("« Afficher le mot de passe »", "« Show Password »"),
    ("dialog « Raccourcis clavier »", "dialog « Keyboard Shortcuts »"),
    ("« Échap. »", "« Escape »"),
    ("— Échap.", "— Escape"),
    ("— Maj ", "— Shift "),
    ("/ Maj ", "/ Shift "),
    ("« Maj+", "« Shift+"),
    ("« Maj »", "« Shift »"),
]
"""Libellés de GTK et de libadwaita en français (application Rust) et en anglais (application
Python, qui ne traduit que ses propres textes) : ADR 0019, R4.1."""


def sans_gtk(texte: str) -> str:
    for francais, anglais in GTK:
        texte = texte.replace(francais, anglais)
    return texte


def comparer(a: Path, b: Path, gtk: bool = False) -> int:
    lire = (
        (lambda p: sans_gtk(p.read_text(encoding="utf-8")))
        if gtk
        else (lambda p: p.read_text(encoding="utf-8"))
    )
    ecarts = list(
        difflib.unified_diff(
            lire(a).splitlines(),
            lire(b).splitlines(),
            str(a),
            str(b),
            lineterm="",
        )
    )
    print("\n".join(ecarts) if ecarts else f"{a.name} et {b.name} : mêmes arbres")
    return 1 if ecarts else 0


def main() -> int:
    if len(sys.argv) >= 4 and sys.argv[1] == "releve":
        return releve(int(sys.argv[2]), Path(sys.argv[3]), sys.argv[4:])
    if len(sys.argv) in (4, 5) and sys.argv[1] == "comparer":
        return comparer(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4:] == ["--gtk"])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())

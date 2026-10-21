#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
"""Comparaison R5 : les mêmes mesures, prises de la même façon, sur l'application Python et
sur l'application Rust (plan, R5 ; § 0.2).

    python3 mesures_r5.py SORTIE.json COMMANDE...

lance l'application (COMMANDE), puis mesure hors de son processus, comme le verrait un
lecteur d'écran, par D-Bus (actions de la fenêtre) et AT-SPI :

- démarrage : du lancement à la fenêtre publiée sur le bus de session ; à froid
  (`ESSAI_FROID`) : les fichiers que l'application a projetés à un lancement précédent
  (liste `ESSAI_FICHIERS`, écrite par ce lancement-là) et ceux des répertoires
  `ESSAI_REPERTOIRES` (modules Python) sont d'abord retirés du cache de pages
  (posix_fadvise, sans droits particuliers) ;
- mémoire (VmRSS, VmHWM de /proc) à l'accueil, après l'ouverture du domaine, après la liste
  complète ;
- ouverture de l'arborescence : de `win.ouvrir-profil` aux nœuds sous la racine ;
- recherche par texte, et liste de tous les utilisateurs du domaine, lancées depuis « Mes
  recherches » (recherches enregistrées dans les réglages, `ESSAI_RECHERCHE` et
  `ESSAI_LISTE` : AT-SPI ne sait pas valider une saisie), premières lignes et toutes,
  d'après le compteur de la barre d'état.

Le compteur est relu toutes les 5 ms ; une lecture est finie quand il n'a plus changé depuis
3 s (le temps retenu est celui de son dernier changement). Le domaine et le texte cherché
viennent de l'environnement (`ESSAI_DOMAINE`, et les noms des recherches) ; `ESSAI_IDENTIFIANT` est
l'identifiant D-Bus de l'application. À
lancer dans l'environnement privé des essais, jamais dans la session de l'utilisateur.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import gi

gi.require_version("Atspi", "2.0")

from gi.repository import Atspi, Gio, GLib  # noqa: E402

PAS = 0.005
LIMITE = 180.0


def attendre(condition, limite: float = LIMITE) -> float | None:  # noqa: ANN001
    debut = time.monotonic()
    while time.monotonic() - debut < limite:
        if condition():
            return time.monotonic() - debut
        time.sleep(PAS)
    return None


def memoire(pid: int) -> dict[str, int]:
    valeurs = {}
    for ligne in Path(f"/proc/{pid}/status").read_text().splitlines():
        cle, _deux, reste = ligne.partition(":")
        if cle in ("VmRSS", "VmHWM"):
            valeurs[cle] = int(reste.split()[0]) // 1024  # Mo
    return valeurs


def evincer(liste: Path, repertoires: list[str]) -> int:
    """Retire du cache de pages les fichiers de la liste et ceux des répertoires (modules
    Python, lus sans être projetés) : lancement « à froid »."""
    n = 0
    chemins = liste.read_text().splitlines()
    for repertoire in repertoires:
        chemins += [str(f) for f in Path(repertoire).rglob("*") if f.is_file()]
    for chemin in chemins:
        try:
            fd = os.open(chemin, os.O_RDONLY)
        except OSError:
            continue
        try:
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            n += 1
        finally:
            os.close(fd)
    return n


def fichiers_lus(pid: int) -> set[str]:
    """Fichiers projetés par le processus (bibliothèques, typelibs, ressources)."""
    vus = set()
    for ligne in Path(f"/proc/{pid}/maps").read_text().splitlines():
        champs = ligne.split(maxsplit=5)
        if len(champs) == 6 and champs[5].startswith("/"):
            vus.add(champs[5])
    return vus


class Fenetre:
    def __init__(self, identifiant: str) -> None:
        self.bus = Gio.bus_get_sync(Gio.BusType.SESSION)
        self.identifiant = identifiant
        self.chemin = "/" + identifiant.replace(".", "/") + "/window/1"

    def publiee(self) -> bool:
        try:
            self.bus.call_sync(
                self.identifiant,
                self.chemin,
                "org.freedesktop.DBus.Introspectable",
                "Introspect",
                None,
                None,
                Gio.DBusCallFlags.NONE,
                200,
                None,
            )
            return True
        except GLib.Error:
            return False

    def action(self, nom: str, parametre: GLib.Variant | None = None) -> None:
        self.bus.call_sync(
            self.identifiant,
            self.chemin,
            "org.gtk.Actions",
            "Activate",
            GLib.Variant("(sava{sv})", (nom, [parametre] if parametre else [], {})),
            None,
            Gio.DBusCallFlags.NONE,
            -1,
            None,
        )


def application(pid: int) -> Atspi.Accessible | None:
    bureau = Atspi.get_desktop(0)
    for i in range(bureau.get_child_count()):
        app = bureau.get_child_at_index(i)
        if app is not None and app.get_process_id() == pid:
            return app
    return None


def chercher(noeud: Atspi.Accessible, test, profondeur: int = 0) -> Atspi.Accessible | None:  # noqa: ANN001
    if noeud is None or profondeur > 60:
        return None
    if test(noeud):
        return noeud
    for i in range(noeud.get_child_count()):
        if (trouve := chercher(noeud.get_child_at_index(i), test, profondeur + 1)) is not None:
            return trouve
    return None


COMPTEUR = re.compile(r"^(\d[\d   ]*) (objets?|objects?)\b")


def nombre(noeud: Atspi.Accessible) -> int | None:
    m = COMPTEUR.match((noeud.get_name() or "").strip())
    return int(re.sub(r"\D", "", m.group(1))) if m else None


def main(sortie: Path, commande: list[str]) -> int:
    Atspi.set_timeout(5000, 20000)
    env = os.environ
    domaine = env.get("ESSAI_DOMAINE", "lab.test")
    fenetre = Fenetre(env["ESSAI_IDENTIFIANT"])
    resultat: dict[str, object] = {"commande": commande}
    liste = Path(env["ESSAI_FICHIERS"]) if env.get("ESSAI_FICHIERS") else None
    if liste is not None and liste.exists() and env.get("ESSAI_FROID"):
        repertoires = [r for r in env.get("ESSAI_REPERTOIRES", "").split(":") if r]
        resultat["fichiers_evinces"] = evincer(liste, repertoires)
        time.sleep(1)

    debut = time.monotonic()
    processus = subprocess.Popen(commande, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    resultat["demarrage_s"] = attendre(fenetre.publiee, 60)
    resultat["demarrage_total_s"] = time.monotonic() - debut
    time.sleep(3)
    # meson devenv lance l'application dans un processus enfant : le dernier descendant.
    pid = processus.pid
    enfants = subprocess.run(
        ["pgrep", "-P", str(pid)], capture_output=True, text=True, check=False
    ).stdout.split()
    while enfants:
        pid = int(enfants[-1])
        enfants = subprocess.run(
            ["pgrep", "-P", str(pid)], capture_output=True, text=True, check=False
        ).stdout.split()
    resultat["memoire_accueil"] = memoire(pid)

    attendre(lambda: application(pid) is not None, 20)
    app = application(pid)
    if app is None:
        resultat["erreur"] = "application absente du bus d'accessibilité"
        processus.terminate()
        sortie.write_text(json.dumps(resultat, indent=2, ensure_ascii=False))
        return 1
    montre = Atspi.StateType.SHOWING
    fenetre.action("ouvrir-profil", GLib.Variant("s", domaine))
    t0 = time.monotonic()
    arbre = None
    while arbre is None and time.monotonic() - t0 < 60:
        arbre = chercher(
            app,
            lambda n: (
                (n.get_name() or "") == "Arborescence du domaine"
                and n.get_state_set().contains(montre)
            ),
        )
    if arbre is not None and attendre(lambda: arbre.get_child_count() >= 2) is not None:
        resultat["arborescence_s"] = time.monotonic() - t0
        resultat["arborescence_lignes"] = arbre.get_child_count()
    time.sleep(4)
    resultat["memoire_domaine"] = memoire(pid)

    compteur = chercher(
        app,
        lambda n: (
            n.get_role() == Atspi.Role.LABEL
            and n.get_state_set().contains(montre)
            and nombre(n) is not None
        ),
    )

    def recherche_enregistree(nom: str) -> dict[str, object]:
        """Recherche lancée depuis « Mes recherches » (menu des requêtes enregistrées) :
        premières lignes quand le compteur montre un nombre de lignes nouveau, toutes à son
        dernier changement, quand il n'a plus bougé pendant 3 s."""
        bouton = chercher(
            app,
            lambda n: (
                n.get_role() == Atspi.Role.TOGGLE_BUTTON
                and (n.get_name() or "") == "Requêtes enregistrées"
                and n.get_state_set().contains(montre)
            ),
        )
        Atspi.Action.do_action(bouton, 0)
        entree = None
        debut = time.monotonic()
        while entree is None and time.monotonic() - debut < 10:
            entree = chercher(
                app,
                lambda n: (
                    n.get_role() == Atspi.Role.MENU_ITEM
                    and (n.get_name() or "") == nom
                    and n.get_state_set().contains(montre)
                ),
            )
        avant = nombre(compteur)
        t0 = time.monotonic()
        Atspi.Action.do_action(entree, 0)
        premieres = attendre(lambda: nombre(compteur) not in (None, 0, avant), 60)
        dernier, valeur = time.monotonic(), nombre(compteur)
        while time.monotonic() - dernier < 3 and time.monotonic() - t0 < LIMITE:
            time.sleep(PAS)
            if (n := nombre(compteur)) != valeur:
                dernier, valeur = time.monotonic(), n
        return {
            "recherche": nom,
            "lignes": valeur,
            "premieres_s": premieres,
            "toutes_s": dernier - t0,
        }

    if compteur is not None:
        resultat["recherche"] = recherche_enregistree(env.get("ESSAI_RECHERCHE", "Michel"))
        time.sleep(2)
        resultat["liste_complete"] = recherche_enregistree(
            env.get("ESSAI_LISTE", "Tous les utilisateurs")
        )
        time.sleep(3)
        resultat["memoire_liste"] = memoire(pid)
    else:
        resultat["erreur"] = "compteur introuvable"

    if liste is not None and not env.get("ESSAI_FROID"):
        liste.write_text("\n".join(sorted(fichiers_lus(pid))) + "\n")
    processus.terminate()
    try:
        processus.wait(10)
    except subprocess.TimeoutExpired:
        processus.kill()
    subprocess.run(["kill", str(pid)], check=False, capture_output=True)
    sortie.write_text(json.dumps(resultat, indent=2, ensure_ascii=False))
    print(json.dumps(resultat, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]), sys.argv[2:]))

#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
#
# Parcours court au labo avant une version (bascule, ADR 0019) : l'application, lancée dans un
# environnement privé comme par audit_ecrans.sh (bus de session et d'accessibilité à soi,
# mutter sans affichage, réglages par fichier de clés), se connecte à LAB.TEST, cherche
# « Michel », ouvre la fiche de l'administrateur, désactive le compte OBJET puis l'annulation
# par Ctrl+Z (action win.annuler-derniere, celle du raccourci) le réactive, ouvre la fenêtre DNS
# et celle des stratégies de groupe. Chaque écran est relevé par AT-SPI dans SORTIE ; le bilan
# est écrit dans SORTIE/bilan.txt et le code de sortie dit si tout a été vu.
#
#     KRB5CCNAME=FILE:… tests/interface/parcours.sh SORTIE OBJET
#
# OBJET : DN d'un compte actif du labo, que le parcours laisse actif. ANNUAIRE_BINAIRE désigne
# l'application installée (défaut : /usr/bin/calinda). Jamais dans la session de l'utilisateur.
set -u
RACINE=$(cd "$(dirname "$0")/../.." && pwd)
O=$(realpath -m "$1")
OBJET=$2
BINAIRE=${ANNUAIRE_BINAIRE:-/usr/bin/calinda}

if [ -z "${ESSAI_DANS_SESSION:-}" ]; then
    mkdir -p -m 700 "$O"/run "$O"/cache "$O"/etat "$O"/config/glib-2.0/settings
    cat > "$O"/config/glib-2.0/settings/keyfile <<EOF
[io/github/f3nr1l/Calinda]
profils=[{"domaine": <"lab.test">, "mode": <"gssapi-scelle">, "lecture-seule": <false>, "cache": <false>}]
window-maximized=true
EOF
    export GSETTINGS_BACKEND=keyfile XDG_CACHE_HOME=$O/cache XDG_STATE_HOME=$O/etat \
        XDG_CONFIG_HOME=$O/config XDG_DATA_HOME=$O/data XDG_RUNTIME_DIR=$O/run \
        GDK_DEBUG=no-portals GIO_USE_VFS=local LANG=fr_FR.UTF-8 LC_ALL=fr_FR.UTF-8 \
        ESSAI_DANS_SESSION=1
    unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS AT_SPI_BUS_ADDRESS
    exec dbus-run-session -- bash -c '
        /usr/libexec/at-spi-bus-launcher --launch-immediately >"$1"/atspi.log 2>&1 &
        sleep 1; /usr/libexec/at-spi2-registryd >>"$1"/atspi.log 2>&1 &
        mutter --headless --no-x11 --wayland-display=essai-parcours \
            --virtual-monitor 1600x1000 >"$1"/mutter.log 2>&1 &
        sleep 2; export WAYLAND_DISPLAY=essai-parcours; exec "$0" "$1" "$2"
    ' "$0" "$O" "$OBJET"
fi

A=$RACINE/tests/interface/arbre_atspi.py
DEST=io.github.f3nr1l.Calinda
OBJ=/io/github/f3nr1l/Calinda
APP_PID=
FAUTES=0

lancer() { # $1 = nom de l'étape (journal de l'application)
    "$BINAIRE" >"$O/app-$1.log" 2>&1 &
    for _ in $(seq 40); do
        sleep 0.5
        gdbus introspect --session --dest $DEST --object-path $OBJ/window/1 \
            >/dev/null 2>&1 && break
    done
    sleep 1
    APP_PID=$(pgrep -n -f "^$BINAIRE$")
}
win() { gdbus call --session --dest $DEST --object-path $OBJ/window/1 \
    --method org.gtk.Actions.Activate "$@" >/dev/null; }
domaine() { win ouvrir-profil '[<"lab.test">]' '{}'; sleep 6; }
releve() { python3 "$A" releve "$APP_PID" "$O/$1.txt" "${@:2}" 2>>"$O"/releve.log; }
arreter() { kill "$APP_PID" 2>/dev/null; sleep 2; }
constat() { # $1 = étape, $2 = vrai ou faux
    if [ "$2" = vrai ]; then echo "$1 : ok" >> "$O"/bilan.txt
    else echo "$1 : ÉCHEC" >> "$O"/bilan.txt; FAUTES=$((FAUTES + 1)); fi
}
vu() { grep -q -- "$2" "$O/$1" && echo vrai || echo faux; }
pas_vu() { grep -q -- "$2" "$O/$1" && echo faux || echo vrai; }

: > "$O"/bilan.txt

# Connexion et recherche : le crochet lance la recherche une fois le domaine ouvert.
ANNUAIRE_ESSAI_RECHERCHE=Michel lancer recherche
domaine; sleep 4
releve recherche
arreter
constat "connexion" "$(vu recherche.txt 'lab.test')"
constat "recherche" "$(vu app-recherche.log 'essai recherche')"

# Fiche d'un objet.
ANNUAIRE_ESSAI_FICHE="CN=Administrator,CN=Users,DC=lab,DC=test" lancer fiche
domaine; sleep 4
releve fiche
arreter
constat "fiche" "$(vu fiche.txt 'Administrator')"

# Une écriture : le compte désactivé, appliqué par l'aperçu.
ANNUAIRE_ESSAI_ETAPES="desactiver|$OBJET" lancer ecriture
domaine; sleep 8
arreter
constat "écriture" "$(vu app-ecriture.log 'essai étape desactiver : applique')"

# Ctrl+Z : l'action du raccourci propose l'inverse de la dernière écriture (aperçu relevé),
# appliqué par son bouton. L'état du compte se vérifie ensuite sur le DC.
lancer annulation
domaine
win annuler-derniere '[]' '{}'; sleep 4
releve annulation-apercu
releve annulation Appliquer pause:6
arreter
constat "annulation (Ctrl+Z) : aperçu" "$(vu annulation-apercu.txt 'userAccountControl')"
constat "annulation (Ctrl+Z) : aperçu fermé" "$(pas_vu annulation.txt 'Appliquer')"

# Fenêtres DNS et stratégies de groupe.
lancer dns
domaine
win dns '[]' '{}'; sleep 6
releve dns
arreter
constat "fenêtre DNS" "$(vu dns.txt '_msdcs.lab.test\|lab.test')"
lancer gpo
domaine
win gpo '[]' '{}'; sleep 6
releve gpo
arreter
constat "fenêtre GPO" "$(vu gpo.txt 'Default Domain Policy')"

# Ancré au début : le motif figure aussi dans la ligne de commande de dbus-run-session.
pkill -f "^mutter --headless --no-x11 --wayland-display=essai-parcours"
cat "$O"/bilan.txt
exit $((FAUTES > 0))

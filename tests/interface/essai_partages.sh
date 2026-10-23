#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
#
# Essai sans écran des fenêtres « Partages » et « Dossiers et droits NTFS » (J8, ADR 0023) :
# l'application, lancée dans un environnement privé comme par audit_ecrans.sh (bus de session
# et d'accessibilité à soi, mutter sans affichage, réglages par fichier de clés, état et caches
# dans SORTIE), déroule les étapes du crochet ANNUAIRE_ESSAI_PARTAGES (liste et syntaxe dans
# l'en-tête de `shares_trial`, rust/annuaire-app/src/trial.rs), puis s'arrête à « essai
# partages fin ». Les lignes « essai … » du journal de l'application sont recopiées à l'écran.
#
#     KRB5CCNAME=FILE:… tests/interface/essai_partages.sh SORTIE 'ÉTAPE;;ÉTAPE…' [AUDIT]
#     KRB5CCNAME=FILE:… tests/interface/essai_partages.sh SORTIE @NOM [AUDIT]
#
# @NOM prend les étapes du scénario NOM de essais-partages.txt (à côté de ce script). Avec
# AUDIT, l'arbre AT-SPI est relevé et audité à la fin des étapes (`audit_atspi.py`, contrôles
# sans nom), avant l'arrêt : finir le scénario sur le dialogue à auditer. Profils LAB.TEST et
# WIN.TEST, en écriture ; le ticket d'administrateur du domaine visé dans KRB5CCNAME. Les
# sauvegardes de propagation vont dans SORTIE/etat/calinda/propagations.
#
# Construction attendue dans build/ (meson devenv), ou ANNUAIRE_BUILD=DOSSIER pour une autre ;
# ANNUAIRE_BINAIRE=/usr/bin/calinda pour l'application installée. Jamais dans la session de
# l'utilisateur : le script lance la sienne.
set -u
RACINE=$(cd "$(dirname "$0")/../.." && pwd)
O=$(realpath -m "$1"); ETAPES=$2; AUDIT=${3:-}
case $ETAPES in
    @*)
        nom=${ETAPES#@}
        ETAPES=$(grep -v '^#' "$RACINE/tests/interface/essais-partages.txt" \
            | sed -n "s/^$nom|//p" | head -1)
        [ -n "$ETAPES" ] || { echo "scénario inconnu : $nom" >&2; exit 2; }
        ;;
esac
BUILD=${ANNUAIRE_BUILD:-$RACINE/build}

if [ -z "${ESSAI_DANS_SESSION:-}" ]; then
    rm -rf "$O"; mkdir -p -m 700 "$O"/run "$O"/cache "$O"/etat "$O"/config/glib-2.0/settings
    cat > "$O"/config/glib-2.0/settings/keyfile <<KF
[io/github/f3nr1l/Calinda]
profils=[{"domaine": <"lab.test">, "mode": <"gssapi-scelle">, "lecture-seule": <false>, "cache": <false>}, {"domaine": <"win.test">, "mode": <"gssapi-scelle">, "lecture-seule": <false>, "cache": <false>}]
window-maximized=true
KF
    export GSETTINGS_BACKEND=keyfile XDG_CACHE_HOME=$O/cache XDG_STATE_HOME=$O/etat \
        XDG_CONFIG_HOME=$O/config XDG_DATA_HOME=$O/data XDG_RUNTIME_DIR=$O/run \
        GDK_DEBUG=no-portals GIO_USE_VFS=local LANG=fr_FR.UTF-8 LC_ALL=fr_FR.UTF-8 \
        ESSAI_DANS_SESSION=1
    unset DISPLAY WAYLAND_DISPLAY DBUS_SESSION_BUS_ADDRESS AT_SPI_BUS_ADDRESS
    # L'activation D-Bus du bus d'accessibilité échoue sous dbus-run-session (EACCES) : il
    # est lancé à la main, avec son registre (ADR 0019 § 7).
    exec dbus-run-session -- bash -c '
        /usr/libexec/at-spi-bus-launcher --launch-immediately >"$1"/atspi.log 2>&1 &
        sleep 1; /usr/libexec/at-spi2-registryd >>"$1"/atspi.log 2>&1 &
        mutter --headless --no-x11 --wayland-display=essai-partages \
            --virtual-monitor 1600x1000 >"$1"/mutter.log 2>&1 &
        sleep 2; export WAYLAND_DISPLAY=essai-partages; exec "$0" "$1" "$2" "$3"
    ' "$0" "$O" "$ETAPES" "$AUDIT"
fi

if [ -n "${ANNUAIRE_BINAIRE:-}" ]; then
    ANNUAIRE_ESSAI_PARTAGES="$ETAPES" "$ANNUAIRE_BINAIRE" >"$O"/app.log 2>&1 &
    MOTIF="^$ANNUAIRE_BINAIRE$"
else
    ANNUAIRE_ESSAI_PARTAGES="$ETAPES" meson devenv -C "$BUILD" \
        "$BUILD"/rust/annuaire-app/calinda >"$O"/app.log 2>&1 &
    MOTIF="$BUILD/rust/annuaire-app/calinda$"
fi
# Au plus 15 minutes ; une étape inconnue, un élément introuvable ou une panique arrêtent tôt.
for _ in $(seq 900); do
    sleep 1
    grep -q "essai partages fin\|étape inconnue\|introuvable\|panicked" "$O"/app.log && break
done
sleep 1
PID=$(pgrep -n -f "$MOTIF")
if [ -n "$AUDIT" ] && [ -n "$PID" ]; then
    python3 "$RACINE"/tests/interface/arbre_atspi.py releve "$PID" "$O/releve.txt" \
        2>>"$O"/releve.log
    python3 "$RACINE"/tests/interface/audit_atspi.py "$PID" "$O/audit.json" "$AUDIT" \
        >>"$O"/audit.log 2>&1
    echo "audit : $?" >>"$O"/audit.log
    tail -2 "$O"/audit.log
fi
[ -n "$PID" ] && kill "$PID" 2>/dev/null
sleep 1
# Ancré au début : le motif figure aussi dans la ligne de commande de dbus-run-session.
pkill -f "^mutter --headless --no-x11 --wayland-display=essai-partages"
grep "^essai\|panicked\|CRITICAL" "$O"/app.log

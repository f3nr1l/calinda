#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
#
# Audit AT-SPI de tous les écrans (R4.10, ADR 0019 § 7) : pour chaque scénario de
# `ecrans.txt`, l'application est lancée dans un environnement privé (bus de session et
# d'accessibilité à soi, mutter sans affichage, réglages par fichier de clés, caches et état
# dans SORTIE), amenée à l'écran par ses actions D-Bus et AT-SPI, relevée
# (`arbre_atspi.py releve`) et auditée (`audit_atspi.py`). Avec REFERENCE, dossier d'un audit
# précédent, chaque relevé lui est comparé (`arbre_atspi.py comparer`).
#
#     KRB5CCNAME=FILE:… tests/interface/audit_ecrans.sh SORTIE [SCÉNARIOS]
#
# Construction attendue dans build/, ou ANNUAIRE_BINAIRE=/usr/bin/calinda pour l'application
# installée ; ticket d'administrateur du labo déjà dans KRB5CCNAME. Jamais dans la session de
# l'utilisateur : le script lance la sienne. Les fenêtres sont fermées sans rien écrire.
# Jusqu'à la bascule (1.1.0), le même script comparait l'application Python et l'application
# Rust écran par écran (ADR 0019, R4.10c).
#
# Un scénario par ligne : NOM|GESTE|GESTE… Gestes, dans l'ordre : `dom` (domaine du profil
# ouvert par win.ouvrir-profil), `win:ACTION[:PARAMÈTRE]`, `app:ACTION`, `wait:S`,
# `env:VAR=VALEUR` (crochets d'essai de l'application Rust) ; les autres sont donnés au
# relevé : nom d'un bouton, `NOM#N`, `choisir:LISTE>LIGNE`, `pause:S`.
set -u
RACINE=$(cd "$(dirname "$0")/../.." && pwd)
O=$(realpath -m "$1")
SC=$(realpath "${2:-$RACINE/tests/interface/ecrans.txt}")

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
    # L'activation D-Bus du bus d'accessibilité échoue sous dbus-run-session (EACCES) : il
    # est lancé à la main, avec son registre (ADR 0019 § 7).
    exec dbus-run-session -- bash -c '
        /usr/libexec/at-spi-bus-launcher --launch-immediately >"$1"/atspi.log 2>&1 &
        sleep 1; /usr/libexec/at-spi2-registryd >>"$1"/atspi.log 2>&1 &
        mutter --headless --no-x11 --wayland-display=essai-audit \
            --virtual-monitor 1600x1000 >"$1"/mutter.log 2>&1 &
        sleep 2; export WAYLAND_DISPLAY=essai-audit; exec "$0" "$1" "$2"
    ' "$0" "$O" "$SC"
fi

A=$RACINE/tests/interface/arbre_atspi.py
U=$RACINE/tests/interface/audit_atspi.py
APP_PID=
DEST=io.github.f3nr1l.Calinda
OBJ=/io/github/f3nr1l/Calinda

lancer() {
    if [ -n "${ANNUAIRE_BINAIRE:-}" ]; then
        "$ANNUAIRE_BINAIRE" >>"$O"/app.log 2>&1 &
        MOTIF="^$ANNUAIRE_BINAIRE$"
    else
        meson devenv -C "$RACINE"/build "$RACINE"/build/rust/annuaire-app/calinda \
            >>"$O"/app.log 2>&1 &
        MOTIF="build/rust/annuaire-app/calinda$"
    fi
    for _ in $(seq 40); do
        sleep 0.5
        gdbus introspect --session --dest $DEST --object-path "$OBJ"/window/1 \
            >/dev/null 2>&1 && break
    done
    sleep 1
    APP_PID=$(pgrep -n -f "$MOTIF")
}
win() { gdbus call --session --dest $DEST --object-path "$OBJ"/window/1 \
    --method org.gtk.Actions.Activate "$@" >/dev/null; }
app() { gdbus call --session --dest $DEST --object-path "$OBJ" \
    --method org.gtk.Actions.Activate "$@" >/dev/null; }
arreter() { kill "$APP_PID" 2>/dev/null; sleep 2; }

while IFS= read -r ligne; do
    [ -z "$ligne" ] && continue
    case $ligne in \#*) continue ;; esac
    nom=${ligne%%|*}
    IFS="|" read -ra gestes <<< "${ligne#*|}"
    envs=()
    for g in "${gestes[@]}"; do case $g in env:*) envs+=("${g#env:}") ;; esac; done
    for e in "${envs[@]}"; do export "${e?}"; done
    lancer
    for e in "${envs[@]}"; do unset "${e%%=*}"; done
    noms=()
    for g in "${gestes[@]}"; do
        case $g in
            env:*) ;;
            dom) win ouvrir-profil '[<"lab.test">]' '{}'; sleep 6 ;;
            win:*:*) x=${g#win:}; win "${x%%:*}" "[<\"${x#*:}\">]" '{}'; sleep 3 ;;
            win:*) win "${g#win:}" '[]' '{}'; sleep 3 ;;
            app:*) app "${g#app:}" '[]' '{}'; sleep 2 ;;
            wait:*) sleep "${g#wait:}" ;;
            *) noms+=("$g") ;;
        esac
    done
    python3 "$A" releve "$APP_PID" "$O/$nom.txt" "${noms[@]}" 2>>"$O"/releve.log
    python3 "$U" "$APP_PID" "$O/audit-$nom.json" "$nom" >>"$O/audit.log" 2>&1
    arreter
    if [ -n "${REFERENCE:-}" ]; then
        python3 "$A" comparer "$REFERENCE/$nom.txt" "$O/$nom.txt" > "$O/diff-$nom.txt"
        echo "$nom : $([ $? = 0 ] && echo identiques || echo DIFFÉRENTS)" >> "$O"/bilan.txt
    fi
done < "$SC"
# Ancré au début : le motif figure aussi dans la ligne de commande de dbus-run-session.
pkill -f "^mutter --headless --no-x11 --wayland-display=essai-audit"

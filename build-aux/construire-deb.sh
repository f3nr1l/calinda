#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
#
# Paquet Debian pour Ubuntu 26.04, construit dans un conteneur à partir de l'archive de
# « meson dist » (qui contient debian/ et les crates) :
#   build-aux/construire-deb.sh _dist/meson-dist/calinda-X.Y.Z.tar.xz [SORTIE]
# Les .deb arrivent dans SORTIE (par défaut, le répertoire de l'archive). podman, ou docker
# par CONTENEUR=docker ; IMAGE pour une autre version d'Ubuntu ou de Debian. Les montages
# portent l'option z : sous SELinux (Fedora), le conteneur ne lirait pas l'archive sans elle.
set -eu
archive=$(realpath "$1")
sortie=$(realpath "${2:-$(dirname "$archive")}")
conteneur=${CONTENEUR:-podman}
image=${IMAGE:-docker.io/library/ubuntu:26.04}

"$conteneur" run --rm \
    -v "$archive:/src/$(basename "$archive"):ro,z" -v "$sortie:/sortie:z" \
    "$image" sh -euc '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends dpkg-dev xz-utils > /dev/null
        mkdir /construction && cd /construction
        tar -xf /src/*.tar.xz && cd calinda-*
        apt-get build-dep -y -qq "$PWD" > /dev/null
        dpkg-buildpackage -b -us -uc
        cp ../*.deb /sortie/
    '

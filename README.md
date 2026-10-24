# Calinda

Calinda est un outil GNOME (GTK 4, libadwaita) d'administration Active Directory, pour les
domaines Samba AD et Windows AD. Il est écrit en Rust. Son nom est celui de la calinda, une danse
d'origine africaine passée par les Antilles, comme la samba en est une autre.

La version 1.3.1 couvre les comptes, le DNS, la sécurité des objets, les stratégies de groupe
jusqu'à leur contenu, et les partages des serveurs de fichiers avec les droits NTFS de leurs
dossiers ; l'interface existe en anglais et en français. Jusqu'à la version 1.1,
l'application s'appelait Annuaire. L'application est issue du port Rust d'une première version
écrite en Python (1.0).

Le mode d'emploi est dans [docs/utilisation.md](docs/utilisation.md) (en anglais :
[docs/utilisation.en.md](docs/utilisation.en.md)), les changements de chaque version dans
[CHANGELOG.md](CHANGELOG.md). Le cadrage initial est dans [docs/cadrage.md](docs/cadrage.md).
Les références aux ADR dans le code et le journal renvoient aux notes de décision du dépôt de
développement, qui ne sont pas publiées.

## Organisation

Les crates gardent le nom d'origine du projet.

- `rust/annuaire-codecs` : formats binaires et textuels d'Active Directory (SID, descripteurs
  et SDDL, enregistrements DNS, `gPLink`, `Registry.pol`, `GptTmpl.inf`…), sans dépendance.
- `rust/annuaire-core` : connexion aux contrôleurs (LDAP scellé par Kerberos, LDAPS,
  StartTLS), recherches, modèle, changesets et journal, SYSVOL en SMB 3 (ou en SMB 2 signé,
  sur option du profil), DNS, GPO, copie locale ; partages et droits NTFS des serveurs de
  fichiers (DCE/RPC sur SMB : srvsvc, samr, lsarpc, winreg).
- `rust/annuaire-app` : l'application, dont les interfaces sont décrites en Blueprint
  (`rust/annuaire-app/data/ui`).
- `data/` : fichier `.desktop`, metainfo, schéma GSettings, icônes.
- `po/` : catalogue de traduction.
- `packaging/rpm/` : le `.spec` ; `packaging/deb/` : le répertoire `debian/`.
- `build-aux/` : scripts de construction et manifeste Flatpak.

## Construire et lancer

Sur Fedora, il faut cargo, les paquets de développement de GTK 4 et de libadwaita,
blueprint-compiler et meson :

```sh
sudo dnf install meson cargo rust clang-devel krb5-devel openssl-devel sqlite-devel \
    gtk4-devel libadwaita-devel blueprint-compiler gettext desktop-file-utils
meson setup build
meson compile -C build
meson devenv -C build rust/annuaire-app/calinda
```

`meson devenv` fournit à l'application la ressource, le catalogue et le schéma GSettings du
répertoire de construction ; rien n'est installé.

## Tests

Les vérifications courantes se lancent depuis `rust/` : `cargo fmt --all --check`,
`cargo clippy --all-targets --all-features -- -D warnings` et `cargo test --all-features`, qui
n'a pas besoin du réseau. Les tests contre le laboratoire sont des tests `cargo` ignorés par
défaut ; ils supposent un laboratoire Samba et Windows et les scripts de `labo/`, qui ne sont
pas publiés :

```sh
KRB5CCNAME=FILE:… cargo test -p annuaire-core --all-features --test 'labo_*' -- --ignored --test-threads 1
```

Les essais de l'interface tournent dans un environnement privé, jamais dans la session de
l'utilisateur. `tests/interface/audit_ecrans.sh` relève et audite chaque écran par AT-SPI ;
`tests/interface/parcours.sh` fait un parcours court au laboratoire : connexion, recherche,
fiche, écriture annulée par Ctrl+Z, fenêtres DNS et GPO.

## Construire le RPM

Le RPM est le format de distribution principal. Le `.spec` est un modèle,
`packaging/rpm/calinda.spec.in`, que meson complète avec la version du projet et dépose à la
racine de l'archive source. Sur Fedora, depuis un dépôt git propre :

```sh
sudo dnf install meson rpm-build 'dnf5-command(builddep)' cargo-vendor-filterer
sed 's/@VERSION@/0/' packaging/rpm/calinda.spec.in > /tmp/calinda-deps.spec
sudo dnf builddep /tmp/calinda-deps.spec
meson setup _dist
meson dist -C _dist --no-tests --formats xztar
rpmbuild -ta _dist/meson-dist/calinda-*.tar.xz
```

Le paquet obtenu (`~/rpmbuild/RPMS/x86_64/`) ne dépend que de GTK, de libadwaita et des
bibliothèques que rpm détecte (Kerberos, OpenSSL, SQLite). Cargo y construit l'application
sans accès au réseau : `meson dist` a copié dans l'archive les crates de `rust/Cargo.lock`
(`build-aux/vendre-crates.sh`, cibles Linux seulement), et c'est la seule étape qui télécharge.
La section `%check` valide le fichier `.desktop` et la metainfo, puis lance `cargo test`. Le
paquet utilise le blueprint-compiler de Fedora ; le sous-projet meson ne sert qu'à la
construction de développement. La CI (job `rpm`) refait ces étapes dans `fedora:44`, installe
le RPM, le lance jusqu'à l'affichage de son aide et publie le SRPM et le RPM comme artefacts.

## Construire le paquet Debian

Le paquet `.deb` vise Ubuntu 26.04 et suivantes : Calinda demande GTK 4.18 et libadwaita 1.8,
et Debian 13 n'a que libadwaita 1.7. Le répertoire `debian/` est dans `packaging/deb/` ; `meson dist` le
dépose à la racine de l'archive source, avec les crates. Le paquet se construit dans un
conteneur Ubuntu (podman, ou docker par `CONTENEUR=docker`) :

```sh
meson setup _dist
meson dist -C _dist --no-tests --formats xztar
build-aux/construire-deb.sh _dist/meson-dist/calinda-*.tar.xz
```

`debian/rules` refait les contrôles du `%check` du RPM et lance `cargo test`. La version de
`debian/changelog` est tenue à la main ; meson refuse de configurer si elle diffère de celle du
projet.

## Construire le Flatpak

Le manifeste `build-aux/io.github.f3nr1l.Calinda.json` s'appuie sur GNOME 51 et sur les extensions
`rust-stable` et `llvm22` du SDK freedesktop 26.08 (libclang, pour bindgen). Les crates sont
copiées d'avance :

```sh
flatpak install --user flathub org.gnome.Sdk//51 \
    org.freedesktop.Sdk.Extension.rust-stable//26.08 org.freedesktop.Sdk.Extension.llvm22//26.08
MESON_DIST_ROOT=. build-aux/vendre-crates.sh
flatpak-builder --user --install --force-clean _flatpak build-aux/io.github.f3nr1l.Calinda.json
```

Dans le bac à sable, Kerberos passe par le cache de la session.

## Traductions

L'anglais est la langue source ; la traduction française est dans `po/fr.po`. Les chaînes
visibles passent par gettext : `tr()`, `tr_ctx()` et `tr_n()` dans le code, toujours avec une
chaîne littérale (`cargo test` le vérifie), `_("…")` dans les fichiers Blueprint, et les champs
traduisibles du `.desktop` et de la metainfo. Après avoir ajouté ou modifié une chaîne, ou un
fichier qui en contient (à déclarer dans `po/POTFILES.in`) :

```sh
meson compile -C build calinda-pot
msgmerge --no-wrap --no-fuzzy-matching -U po/fr.po po/calinda.pot
```

Il reste à traduire dans `po/fr.po` les messages restés vides. La CI (job `rust`) régénère le
`.pot`, le compare à celui du dépôt et refuse un `fr.po` incomplet ou contenant des entrées
« fuzzy ». Pour essayer l'interface anglaise depuis une session française :
`LANGUAGE=en calinda`.

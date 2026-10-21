# Annuaire — cadrage

Outil d'administration Active Directory pour GNOME, à la manière des RSAT de Windows.
Cible : domaines Samba AD (et Windows AD), administrés depuis un poste Linux.
Document de départ du 2026-10-12, à réviser au fil du projet.

## Pourquoi

Sous Linux, l'administration d'un domaine AD se fait aujourd'hui avec `samba-tool` (en ligne de
commande, sur le contrôleur), un navigateur LDAP générique (Apache Directory Studio) ou ADMC
(BaseALT, en Qt, non empaqueté pour Fedora). Aucun outil n'est natif GNOME. Le besoin concret vient
du domaine example.local, passé entièrement sous Samba le 2026-10-12 : il faut pouvoir gérer comptes,
groupes, OU, DNS et GPO sans poste Windows.

## Priorités

1. **Justesse** : ne jamais corrompre l'annuaire. Toute écriture est explicite, prévisualisable,
   et journalisée.
2. **Performance** : rester fluide sur un annuaire de quelques dizaines de milliers d'objets
   (chargement paresseux, pagination, aucune requête dans le fil de l'interface).
3. **Taille de distribution** : pas de dépendance lourde ; le paquet final doit tenir en quelques
   mégaoctets hors runtime GNOME.

## Stratégie : Python d'abord, Rust ensuite

Python + PyGObject permet d'avoir vite un outil utilisable et de stabiliser le modèle. Rust vient
ensuite pour la performance et la taille. Pour que le passage ne soit pas une réécriture, trois
règles valent dès le départ :

- **Pas de dépendance aux modules Python de Samba** (`samba.samdb`, `samba.ndr`, …). Ils sont
  pratiques mais lourds (toute la pile Samba à distribuer) et sans équivalent Rust. On s'appuie
  sur des briques qui existent dans les deux mondes :

  | Besoin | Python | Rust |
  |---|---|---|
  | LDAP | `python-ldap` (libldap ; retenu, ADR 0001) | crate `ldap3` |
  | Kerberos / GSSAPI | SASL GSSAPI de libldap, ou `gssapi` | `ldap3` avec la fonction `gssapi` (`cross-krb5`) |
  | Interface | PyGObject, GTK 4, libadwaita | `gtk4-rs`, `libadwaita-rs` |
  | SMB (SYSVOL) | `smbprotocol` (retenu, ADR 0002) | crate `smb` (authentification GSSAPI à brancher) |

  Samba reste l'**oracle de test** : ses outils servent à vérifier ce que nous écrivons.

- **Les formats binaires de Microsoft sont codés par nous**, en petits modules purs et testés :
  `dnsRecord` (enregistrements DNS), `nTSecurityDescriptor` (descripteurs de sécurité, SDDL),
  `Registry.pol` (GPO), GUID/SID. Chaque module a des vecteurs de test tirés d'un vrai annuaire ;
  le port Rust reprend les mêmes vecteurs.

- **Séparation stricte cœur / interface.** Le cœur (`annuaire.core`) ne connaît pas GTK : modèle
  d'objets, services (annuaire, DNS, GPO), codecs, journal des modifications. L'interface ne fait
  qu'afficher et appeler le cœur. Ordre de migration prévu : le cœur passe en Rust d'abord,
  exposé à l'interface Python par PyO3 ; l'interface passe en `gtk4-rs` ensuite.

## Périmètre par étapes

### Étape 1 — comptes (équivalent « Utilisateurs et ordinateurs AD »)
- Connexion Kerberos avec le ticket de la session (`kinit`), choix du contrôleur par SRV DNS ;
  jamais de mot de passe stocké.
- Arborescence des OU et conteneurs, chargée à la demande.
- Fiches utilisateur, groupe, ordinateur ; recherche ; requêtes enregistrées
  (ex. « inactifs depuis 6 mois », calculé comme le 12/10 : max de `lastLogonTimestamp` et des
  `lastLogon` de chaque DC).
- Créer, activer / désactiver, déplacer, renommer, supprimer ; appartenance aux groupes.
- Réinitialisation de mot de passe (`unicodePwd`, exige LDAPS ou LDAP signé et scellé).
- Journal local de chaque modification (avant / après), pour pouvoir revenir en arrière.

### Étape 2 — DNS
- Zones intégrées à l'AD, lecture et écriture des `dnsNode` par LDAP (codec `dnsRecord`).
- Repérage des enregistrements orphelins (DC disparus, NS obsolètes), cas vécu sur example.local.

### Étape 3 — GPO (gestion, sans éditeur de contenu)
- Lister, créer, lier / délier, ordonner, activer / désactiver, filtrage de sécurité.
- Sauvegarde / restauration d'une GPO (annuaire + SYSVOL).

### Étape 4 — éditeur de GPO (si les étapes précédentes servent vraiment)
- Lecture des modèles ADMX/ADML, écriture de `Registry.pol` et `GptTmpl.inf`, numéros de
  version (`GPT.INI`, `versionNumber`), `gPCMachineExtensionNames`. Gros morceau : le borner à
  une sélection de réglages utiles avant de viser l'exhaustivité.

Hors périmètre : sites et services, réplication, FSMO (`samba-tool` suffit).

## Environnement de test

Jamais contre un domaine client. Un contrôleur Samba de laboratoire (conteneur LXC ou VM sur
pve-bureau, domaine `LAB.TEST`), peuplé par un script reproductible (OU, quelques centaines de
comptes, zones DNS, GPO). Tests unitaires des codecs sans réseau ; tests d'intégration contre le
labo, marqués à part.

## Distribution

Flatpak sur le runtime GNOME (le runtime est partagé, l'application seule reste petite), plus un
RPM pour Fedora. En version Rust : un binaire unique de quelques mégaoctets.

## Licence

**GPL-3.0-or-later** (décidé par René le 2026-10-12). Texte dans `COPYING` ; chaque fichier source
porte l'en-tête SPDX `GPL-3.0-or-later`.

## Questions ouvertes

- Nom définitif (« Annuaire » est provisoire).
- ~~`python-ldap` ou `ldap3`~~ : tranché le 2026-10-13 par l'essai J0.6, **python-ldap**
  (ADR 0001).
- Faut-il gérer Windows AD dès le départ, ou Samba seulement ? (Le protocole est le même ; la
  différence tient surtout aux tests.)

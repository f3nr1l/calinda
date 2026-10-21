# Journal des changements

Ce journal retient ce qui change pour l'utilisateur d'une version à l'autre.

## 1.2.0 — 2026-10-17

Annuaire devient Calinda. Le paquet, la commande, l'identifiant de l'application
(`io.github.f3nr1l.Calinda`) et le catalogue de traduction changent de nom ; les écrans et les
gestes restent les mêmes (ADR 0022).

- Les contrôleurs qui ne connaissent que SMB 2 (Windows Server 2008 R2 et antérieurs) sont pris
  en charge pour le SYSVOL par une option du profil de domaine, « Autoriser SMB 2 avec
  signature seule (contrôleurs anciens) », désactivée par défaut. Avec elle, le contenu du
  SYSVOL circule non chiffré, mais authentifié par Kerberos et signé contre toute
  modification ; SMB 3 reste chiffré dans tous les cas. Sans elle, l'application refuse ces
  contrôleurs et indique l'option à activer
  (ADR 0021).
- La version Python est retirée : elle n'avait été gardée que pour ces contrôleurs anciens. La
  version 1.0, écrite en Python, reste accessible par l'étiquette `v1.0.0`
  (ADR 0018).

## 1.1.0 — 2026-10-16

L'application livrée est désormais celle du port Rust. Les écrans et les gestes sont les mêmes,
et les données de la version 1.0 (profils, recherches enregistrées, réglages, copie locale,
historique des modifications) sont reprises telles quelles.

- Le démarrage est dix fois plus rapide (0,03 s au lieu de 0,29 s à chaud) et l'application
  occupe 35 à 43 Mo de mémoire en moins ; la fin d'une longue recherche arrive plus tôt.
  L'ouverture du domaine et la première page d'une liste prennent le même temps qu'avant
  (comparaison R5 de l'ADR 0019).
- Le paquet n'a plus aucune dépendance Python : il ne demande que GTK 4, libadwaita et les
  bibliothèques Kerberos, OpenSSL et SQLite du système. Le RPM pèse 3,8 Mo, 11 Mo une fois
  installé.
- L'anglais devient la langue source et le français une traduction ; le `.desktop` et la
  metainfo sont traduits, de même que les messages liés aux formats d'Active Directory (SDDL,
  DNS, GPO…).
- Les libellés propres à GTK et à libadwaita sont traduits. Ctrl+Z fonctionne aussi dans les
  fenêtres des stratégies de groupe et des stratégies de mot de passe affinées.
- Le Flatpak est construit avec l'extension Rust du SDK GNOME 51, sans Python ni OpenLDAP.

### Cœur Rust (R4.0)

- Le cœur (connexion aux contrôleurs, recherches, modèle, changesets, journal, partage SYSVOL)
  est celui du port Rust. Il donne les mêmes résultats et demande 5 à 6 fois moins de calcul
  sur le SYSVOL (ADR 0018).
- Les recherches d'appartenance récursive confiées au contrôleur (membres et groupes « à toute
  profondeur » sans copie locale, administrateurs) attendent jusqu'à 180 s au lieu de 30 :
  Samba approche les 30 s sur un domaine de 20 000 comptes.
- Le RPM dépend désormais de l'architecture (x86_64).
- Les stratégies de groupe ne sont pas prises en charge sur les contrôleurs Windows Server
  2008 R2 et antérieurs, qui ne parlent que SMB 2. La version Python 1.0 (étiquette
  `v1.0.0`) négocie SMB 2 mais exige elle aussi le chiffrement du SYSVOL : en l'état, elle
  ne lit pas davantage les GPO de ces contrôleurs (limites dans l'ADR 0018). Limite levée en
  1.2.0.

## 1.0.0 — 2026-10-15

Éditeur du contenu des stratégies de groupe, stratégies de mot de passe affinées, autorisations
conditionnelles écrites. Fin de la version Python ; la suite est le port en Rust. Notes de
version : [docs/notes-1.0.0.md](docs/notes-1.0.0.md).

### J7 — Éditeur du contenu des GPO

- « Modifier le contenu… » (Ctrl+M dans la fenêtre « Stratégies de groupe ») : l'arbre de la
  GPMC, configuration ordinateur et utilisateur, un seul brouillon écrit par l'aperçu commun et
  annulable ; numéros de version de l'objet et de `GPT.INI`, listes d'extensions tenus comme la
  GPMC.
- Modèles d'administration lus dans le magasin central (ADMX et ADML dans la langue de la
  session, mis en cache) : catégories, recherche plein texte, filtre des stratégies
  configurées, fiche Non configuré / Activé / Désactivé avec ses options validées à la saisie ;
  écriture dans `Registry.pol`. Les entrées qu'aucun modèle ne décrit sont gardées et
  modifiables dans « Registre (brut) ».
- Paramètres de sécurité (`GptTmpl.inf`, Ctrl+T) : mots de passe et verrouillage, droits
  utilisateur, groupes restreints ; sur un domaine Samba, la politique du domaine est aussi
  écrite sur l'objet domaine, que Samba applique.
- Préférences : lecteurs mappés, imprimantes, raccourcis et registre, avec ciblage par groupe,
  OU, ordinateur ou utilisateur ; un `cpassword` (MS14-025) n'est jamais écrit.
- Vérifié contre la GPMC (relecture sans perte, aller-retour Annuaire → GPMC → Annuaire) et
  appliqué sur un poste Windows du labo, sur un domaine Samba et sur un domaine Windows.

### Autres apports

- DNS, Santé DNS, Stratégies de groupe et Historique en bas de la barre latérale, avec leurs
  raccourcis : Ctrl+D, Maj+Ctrl+D, Ctrl+G, Ctrl+H ; l'aide des raccourcis les cite, avec ceux
  des fenêtres DNS et Stratégies de groupe.
- Ctrl+Z répété annule l'une après l'autre plusieurs modifications d'un même objet.
- Éditeur d'attributs : « Classes auxiliaires… » ajoute ou retire une classe auxiliaire et ses
  attributs.
- Autorisations conditionnelles (contrôle d'accès dynamique) lues en clair et en SDDL ; l'aperçu
  commun nomme le délégué au lieu de son SID.
- Stratégie résultante : traitement en boucle (fusion, remplacement), calculé pour un
  ordinateur et pour un utilisateur sur l'ordinateur choisi.
- Messages d'erreur internes traduits dans l'interface anglaise.
- Onglet « Sécurité », vue « ACE et SDDL » : « Ajouter… » écrit une entrée saisie en SDDL,
  conditionnelle ou non, dite en clair à la frappe ; `SID(DA)` d'une condition écrit en SID
  complet (Samba 4.22 ne relit pas l'abréviation).
- Fenêtre « Stratégies de mot de passe » (Ctrl+M) : politique du domaine et stratégies de mot de
  passe affinées (PSO), créées, modifiées et supprimées par l'aperçu commun, durées saisies en
  clair, cibles cherchées comme dans l'assistant de délégation ; la fiche d'un utilisateur dit
  la stratégie qui s'applique à lui.
- Lecture du SDDL plus sûre : une valeur hors de sa largeur binaire ou une condition trop
  imbriquée est refusée par un message clair au lieu d'une erreur interne ; les chiffres non
  ASCII ne sont plus lus comme des chiffres.

## 0.5.0 — 2026-10-14

Stratégies de groupe sans éditeur de leur contenu, DNS, sécurité des objets, copie locale de
l'annuaire, interface en anglais. Notes de version : [docs/notes-0.5.0.md](docs/notes-0.5.0.md).

### J5 — Stratégies de groupe

- Fenêtre « Stratégies de groupe » : toutes les GPO, puis domaine, OU et GPO liées dans l'ordre
  des liens ; versions de l'annuaire et du SYSVOL comparées, SYSVOL de chaque DC comparé à celui
  de l'émulateur PDC, alertes en clair.
- Liens : lier, délier, monter, descendre, activer, appliquer (« Enforced »), bloquer
  l'héritage.
- Création et suppression d'une GPO comme la GPMC, autorisations du dossier SYSVOL alignées sur
  celles de l'objet. Une modification peut désormais mêler annuaire et SYSVOL, et s'annule en
  entier.
- Filtrage de sécurité, sauvegarde datée d'une GPO et restauration (à l'identique ou en copie).
- « Incohérences » : dossiers du SYSVOL sans GPO et GPO sans dossier ; un dossier orphelin, ou
  tous, se retirent par l'aperçu. Les GPO ne s'écrivent que sur l'émulateur PDC, et une
  connexion d'écriture restée inactive s'y rouvre au lieu de passer sur un autre contrôleur.
- Onglet « Stratégie » de la fiche : GPO appliquées à un compte ou un ordinateur, par
  priorité, et celles qui ne s'appliquent pas, avec leur raison. Concorde avec `gpresult`.
- Interface traduite en anglais (catalogue gettext), documentation utilisateur.

### J4 — Sécurité et éditeur avancé

- Onglet « Sécurité » : propriétaire, autorisations explicites et héritées en phrases claires,
  refus, audit, SDDL complet.
- Délégation de contrôle sur une OU, avec les modèles de l'assistant de Windows.
- Onglet « Attributs » : tous les attributs de l'objet selon le schéma, modification vérifiée
  selon la syntaxe, par l'aperçu commun.

### J3 — DNS

- Fenêtre DNS : zones intégrées à l'annuaire, noms et enregistrements, réglages de zone.
- Écriture des enregistrements A, AAAA, CNAME, PTR, MX, SRV et TXT, numéro de série du SOA
  incrémenté, pointeur inverse proposé.
- « Santé DNS » : serveurs de noms et localisateurs de DC disparus, machines retirées,
  pointeurs incohérents, enregistrements non rafraîchis, tombstones anciens ; correction
  proposée par l'aperçu.

### JC — Copie locale

- Copie locale de l'annuaire par profil, synchronisée par delta : la liste de 20 000 comptes
  s'affiche aussitôt à la seconde ouverture. Option par profil, effacement depuis l'interface.
- Appartenance récursive aux groupes calculée sur la copie.

## 0.1.0 — 2026-10-13

### J2 — Interface « comptes »

- Accueil : profils de domaine, état du ticket Kerberos, obtention d'un ticket.
- Fenêtre principale : arborescence du domaine, liste des objets en flux, colonnes au choix.
- Recherche dans le domaine et requêtes enregistrées (inactifs, désactivés, verrouillés,
  administrateurs récursifs…).
- Fiches utilisateur, groupe et ordinateur ; membres et appartenance.
- Création d'utilisateurs, de groupes et d'OU ; activer, désactiver, déverrouiller,
  réinitialiser le mot de passe, déplacer, renommer, supprimer.
- Aperçu de toute modification avant écriture, journal local, annulation.
- Navigation complète au clavier, messages d'erreur en clair.
- Paquet RPM pour Fedora.

### J1 — Cœur LDAP

- Découverte des contrôleurs par le DNS, liaison Kerberos (GSSAPI scellé par défaut, LDAPS ou
  StartTLS en option), bascule sur un autre DC.
- Recherches paginées en flux, codecs des types Active Directory, modèle objet, dernière
  activité relevée sur chaque DC.
- Modifications en changesets « tout ou rien », vérifiées par relecture, journalisées et
  inversibles.

### J0 — Fondations

- Squelette meson, intégration continue, laboratoire Samba à deux contrôleurs, choix des
  bibliothèques LDAP et SMB.

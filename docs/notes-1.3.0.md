# Calinda 1.3.0 — notes de version

23 octobre 2026. La 1.2 administrait les comptes, le DNS, la sécurité des objets et les
stratégies de groupe. La 1.3 ajoute les serveurs de fichiers du domaine : leurs partages, les
droits de ces partages et les droits NTFS des dossiers et fichiers qu'ils exposent. Le modèle est
celui de Windows : les onglets « Partage », « Sécurité », « Audit » et « Accès effectif » de
l'Explorateur se retrouvent sous les mêmes noms et avec les mêmes effets, sur un serveur Samba
comme sur un serveur Windows.

## Partages et droits

- **Fenêtre « Partages »** (Ctrl+P, ou l'entrée de la barre latérale). Le serveur se choisit
  parmi les contrôleurs de domaine, les ordinateurs de l'annuaire qui sont des serveurs, et ceux
  qu'on a déjà ouverts, que le profil retient ; il peut aussi se saisir. Les serveurs Samba
  membres, qui n'inscrivent pas leur système dans l'annuaire, sont reconnus à leur SPN `cifs/`
  ou à leur jonction ; les postes de travail restent à l'écart. Chaque partage montre son
  chemin, son commentaire, ses droits en clair (« Tout le monde : Lecture ») et ses options ;
  les partages administratifs et spéciaux sont repliés.
- **Droits d'un partage**, modifiés comme dans l'onglet « Partage » de Windows : Lecture,
  Modifier, Contrôle total, autorisés ou refusés, pour un compte ou un groupe de l'annuaire ou
  d'un clic pour Tout le monde, Utilisateurs authentifiés et Administrateurs.
- **Création, modification et suppression d'un partage** : nom contrôlé comme Windows le fait,
  dossier, commentaire, limite de connexions, mise en cache hors connexion, énumération basée sur
  l'accès. Une suppression laisse le dossier en place, et Ctrl+Z recrée le partage avec ses
  droits et ses options.
- **Partages Samba en registre.** Sur un serveur Samba dont les partages sont dans la
  configuration en registre (`net conf`), la limite de connexions et les options s'écrivent
  dans la clé du partage et prennent effet aussitôt ; la création, la modification et la
  suppression passent par cette clé quand le serveur n'a pas de commandes de partage. Calinda
  n'écrit que la clé du partage et ces paramètres, et Ctrl+Z la remet comme elle était.

## Dossiers et onglet « Sécurité »

Depuis un partage, la fenêtre « Dossiers et droits NTFS » parcourt l'arborescence au fil du
dépliage, et montre les fichiers sur demande. L'onglet « Sécurité » d'un dossier ou d'un
fichier reprend celui de Windows : propriétaire, entrées avec leur provenance (explicite, ou
héritée de tel dossier parent), ajout, modification avec les droits fins et la portée
(« s'applique à »), retrait, héritage désactivé ou réactivé, remplacement des autorisations
des enfants. Les groupes locaux du serveur sont nommés par le serveur lui-même.

- **Propagation sauvegardée.** Quand un changement doit descendre dans l'arborescence, Calinda
  compte d'abord les éléments touchés et demande confirmation, puis propage l'héritage comme
  Windows le ferait, en sauvegardant chaque descripteur avant de le réécrire. La progression
  s'affiche, la propagation s'arrête et reprend, et Ctrl+Z remet les descripteurs sauvegardés.
  Une propagation coupée par la fermeture de l'application est retrouvée à la réouverture du
  domaine et proposée à la reprise ou à l'annulation. La propagation tient 100 000 éléments sans
  que la mémoire croisse, à environ 2 000 éléments par seconde, et passe aussi en SMB 2.1 signé
  quand le profil l'autorise. Les sauvegardes que le journal ne nomme plus sont retirées au
  lancement après 30 jours, ou tout de suite depuis l'historique, qui dit la place qu'elles
  prennent.
- **Prise de possession.** « Modifier… » à côté du propriétaire donne la propriété à soi-même,
  aux Administrateurs, ou à un compte ou un groupe de l'annuaire ; pour un dossier, « Remplacer
  le propriétaire des sous-conteneurs et des objets » passe par la même propagation sauvegardée
  et annulable. Un refus dit quel privilège manque sur le serveur.
- **Audit.** Les entrées d'audit (SACL), de réussite et d'échec, se lisent et se modifient comme
  dans l'onglet « Audit » de Windows, héritage et remplacement chez les enfants compris, avec la
  même propagation. Sans le privilège SeSecurityPrivilege, l'onglet le dit et le reste demeure
  utilisable : aucune autre lecture ne demande l'audit.
- **Accès effectif.** Pour un compte ou un groupe, et pour un dossier, un fichier ou la racine
  d'un partage, Calinda calcule chacun des quinze droits de l'onglet « Accès effectif » de
  Windows : accordé ou non, ce qui le limite (le partage, les droits NTFS, ou les deux) et
  l'entrée qui en décide. Le calcul tient compte des groupes de l'annuaire et des groupes
  locaux du serveur ; sur un serveur membre, les groupes intégrés (`BUILTIN\…`) sont ceux du
  serveur.

Les écritures passent, comme partout dans Calinda, par l'aperçu commun, sont vérifiées par
relecture, journalisées sur le poste et annulables. Ces fonctions ont été comparées, élément par
élément, à ce que font Windows et Samba sur un serveur Samba membre et sur un serveur Windows
Server 2025.

## Correction

Sur un serveur Windows, un dossier de plus de quelques centaines de fichiers n'était lu qu'en
partie : Windows ne remplit pas sa réponse alors qu'il reste des noms, et Calinda s'arrêtait là.
Les versions 1.2 en souffraient déjà pour le SYSVOL des contrôleurs Windows, dans un magasin
central ou un dossier de GPO très fourni. Le dossier est désormais relu jusqu'au dernier nom,
dans le SYSVOL comme dans les dossiers des partages.

## Installation

Le RPM `calinda-1.3.0-1.fc44.x86_64.rpm` vise Fedora 44 et suivantes, le paquet Debian
`calinda_1.3.0-1_amd64.deb` Ubuntu 26.04 et suivantes (paquet proposé depuis la 1.2.1). L'un et
l'autre ne dépendent que des paquets de la distribution. Mode d'emploi :
[utilisation.md](utilisation.md) ([English](utilisation.en.md)), section « Les fenêtres »,
paragraphe « Partages ».

## Limites connues

- Les options d'un partage Samba défini dans smb.conf restent celles du fichier : Calinda ne
  l'écrit pas, et le dialogue le dit.
- Sur Samba, l'énumération basée sur l'accès masque le partage à qui n'y a pas droit, mais pas
  son contenu, contrairement au drapeau de Windows.
- Samba garde les entrées d'audit qu'on lui écrit, mais n'audite rien.
- À la racine d'un partage, le dossier parent n'est pas lisible : les entrées héritées de la
  racine sont gardées telles quelles.
- L'accès effectif signale, sans les évaluer, les entrées conditionnelles et les stratégies
  d'accès centrales.

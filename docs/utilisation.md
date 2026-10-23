# Utiliser Calinda

Calinda administre un domaine Active Directory ou Samba depuis GNOME, sans poste Windows :
comptes, groupes, unités d'organisation, DNS, stratégies de groupe, partages de fichiers et
leurs droits. Ce guide porte sur la version 1.3. Jusqu'à la version 1.1, l'application
s'appelait Annuaire.
English version: [utilisation.en.md](utilisation.en.md).

## Installer

Calinda est distribuée sous forme de RPM pour Fedora 44 et suivantes (x86_64). Le paquet ne
dépend que de paquets Fedora : GTK 4, libadwaita, et les bibliothèques Kerberos, OpenSSL et
SQLite, déjà présentes sur le système. Il n'existe pas encore de dépôt ; on installe le fichier
reçu, ou celui qu'on a construit soi-même (README, section « Construire le RPM ») :

```sh
sudo dnf install ./calinda-1.3.0-1.fc44.x86_64.rpm
```

L'application apparaît sous le nom « Calinda » dans le menu des applications ; en terminal, la
commande est `calinda`. Pour la désinstaller : `sudo dnf remove calinda`.

Le poste doit résoudre le DNS du domaine, car les contrôleurs sont trouvés par leurs
enregistrements SRV, et son horloge ne doit pas s'écarter de plus de quelques minutes de celle
des contrôleurs.

Les stratégies de groupe se lisent et s'écrivent sur le partage SYSVOL en SMB 3 chiffré, ce que
permettent Samba et Windows Server 2012 ou ultérieur. Les contrôleurs qui ne connaissent que
SMB 2 (Windows Server 2008 R2 et antérieurs) sont pris en charge pour le SYSVOL par une option du
profil de domaine, « Autoriser SMB 2 avec signature seule (contrôleurs anciens) », désactivée
par défaut. Avec elle, le contenu du SYSVOL circule non chiffré, mais authentifié par Kerberos et
signé contre toute modification ; SMB 3 reste chiffré dans tous les cas. Sans elle,
l'application refuse ces contrôleurs et indique l'option à activer.

## Kerberos

Calinda ne demande ni ne conserve aucun mot de passe de connexion : elle utilise le ticket
Kerberos de la session. Il y a deux façons d'obtenir ce ticket.

- Dans l'application, à l'accueil, « Obtenir un ticket… » : on saisit l'identifiant seul (le
  royaume est alors celui du domaine choisi) ou sous la forme `utilisateur@ROYAUME`, puis le mot
  de passe. Celui-ci sert uniquement à demander le ticket au contrôleur ; il n'est ni enregistré
  ni journalisé.
- En terminal : `kinit administrateur@EXEMPLE.LOCAL`, puis `klist` pour vérifier.

Sur Fedora, le cache est celui de la session (`KCM:`), partagé avec les autres outils. Si
`kinit` ne trouve pas le contrôleur, vérifier que `/etc/krb5.conf` contient
`dns_lookup_kdc = true`. Si la liaison échoue avec le message « Kerberos ne connaît pas le
service LDAP », ajouter `rdns = false` dans la section `[libdefaults]` du même fichier.

Les écritures se font avec les droits du compte qui détient le ticket. Un compte sans droits
d'administration peut lire l'essentiel de l'annuaire ; ce qu'il ne peut pas lire est signalé
comme tel, jamais présenté comme absent.

## Premier profil

À l'accueil, « Ajouter un domaine » (dans la barre d'en-tête, sous la liste, ou Ctrl+N) ouvre
le formulaire du profil :

- **Nom DNS du domaine** (`exemple.local`) : à la validation, les contrôleurs sont cherchés dans
  le DNS et listés.
- **Contrôleur préféré**, utilisé pour la lecture, et **contrôleur d'écriture**, par défaut
  l'émulateur PDC, celui qu'utilisent les consoles Windows.
- **Sécurité** : GSSAPI scellé par défaut, qui chiffre tout sans certificat ; LDAPS ou StartTLS
  si le domaine l'impose, avec le certificat de l'autorité de certification du domaine, dont on
  compare l'empreinte avec celle qu'affiche le contrôleur. « Autoriser SMB 2 avec signature
  seule » ne sert qu'aux contrôleurs anciens (voir « Installer »).
- **Lecture seule** : rien ne peut être écrit dans l'annuaire depuis ce profil. Un profil neuf
  est en lecture seule tant qu'on ne l'a pas modifié ; c'est voulu, pour qu'un premier passage
  sur un domaine de production ne risque rien.
- **Copie locale** : le poste garde les noms, comptes et appartenances lus (jamais un secret),
  ce qui rend l'affichage immédiat à l'ouverture suivante ; la copie se met à jour par delta.
  Elle n'est pas chiffrée : pour le domaine d'un client, mieux vaut un disque chiffré. La
  désactiver l'efface.

Un profil se modifie ou se supprime par le menu de sa ligne. « Effacer la copie locale » la
supprime ; elle est reconstruite à l'ouverture suivante.

## Les fenêtres

**Fenêtre principale.** À gauche figure l'arborescence du domaine ; les conteneurs système n'y
apparaissent qu'avec « Fonctionnalités avancées », dans le menu principal. À droite s'affichent
au fil de la lecture les objets du conteneur choisi, avec les colonnes sélectionnées dans le
menu principal.

La recherche (Ctrl+F) porte sur tout le domaine : nom, identifiant, courriel et description,
avec des filtres par type et par état. Des requêtes prêtes à l'emploi trouvent les comptes
inactifs depuis N jours, désactivés ou verrouillés, les mots de passe sans expiration, les
administrateurs par appartenance récursive et les objets en conflit ; on peut y ajouter les
siennes.

Le bouton « Nouveau » crée un utilisateur, un groupe ou une unité d'organisation. Le menu des
actions agit sur la sélection : activer, désactiver, déverrouiller, réinitialiser le mot de
passe, déplacer, renommer (F2), supprimer (Suppr), protéger une OU contre la suppression
accidentelle.

Le bas de la barre latérale donne accès aux autres fenêtres du domaine, chacune avec son
raccourci : DNS (Ctrl+D), Santé DNS (Maj+Ctrl+D), Stratégies de groupe (Ctrl+G), Stratégies de
mot de passe (Ctrl+M), Partages (Ctrl+P) et Historique des modifications (Ctrl+H). On les
retrouve dans le menu principal.

**Fiche.** Entrée ou un double clic ouvre la fiche de l'objet : onglets général, compte,
membres ou « Membre de », et, selon l'objet :

- « Sécurité » : propriétaire, autorisations décrites en phrases, audit, SDDL ; « Déléguer… »
  sur une OU ; dans la vue « ACE et SDDL », « Ajouter… » écrit une entrée saisie en SDDL,
  conditionnelle ou non (voir plus bas) ;
- « Attributs » : tous les attributs que prévoit le schéma, modifiables si le compte en a le
  droit ; « Classes auxiliaires… » ajoute ou retire une classe auxiliaire proposée par le
  schéma, avec les attributs qu'elle apporte ;
- « Stratégie » : les GPO appliquées au compte ou à l'ordinateur, par ordre de priorité, et
  celles qui ne s'appliquent pas, avec leur raison. Pour un ordinateur, la fiche indique son
  traitement en boucle ; pour un utilisateur, elle calcule la stratégie sur l'ordinateur saisi,
  traitement en boucle compris (fusion ou remplacement).

Les modifications s'accumulent dans la fiche et partent ensemble par « Appliquer… ».

**Aperçu commun.** Toute écriture, quelle que soit la fenêtre, passe par le même aperçu, qui
montre chaque objet, attribut ou fichier avant et après. « Appliquer » vérifie d'abord que rien
n'a changé depuis l'aperçu, écrit sur le contrôleur d'écriture, puis relit pour constater le
résultat. Les autorisations ajoutées ou retirées y sont décrites en clair, avec le nom du
délégué, et en SDDL ; une autorisation conditionnelle (contrôle d'accès dynamique) apparaît
avec sa condition. Une modification qui touche plusieurs objets se fait en entier ou pas du
tout : en cas d'échec, ce qui a déjà été écrit est défait.

**Historique.** Ctrl+H, ou « Historique des modifications », ouvre le journal local de toutes
les écritures faites depuis ce poste (`$XDG_STATE_HOME/calinda/changes.jsonl`), avec « Annuler
cette modification ». Ctrl+Z propose d'annuler la dernière modification, par l'aperçu ; un
nouveau Ctrl+Z propose la précédente, même sur le même objet, tant que personne d'autre ne l'a
modifié entre-temps. Une suppression ne peut se défaire qu'en recréant un objet neuf, avec de
nouveaux SID et GUID ; l'aperçu le signale avant.

**DNS.** Ctrl+D, ou « DNS », montre les zones intégrées à l'annuaire, leurs noms et leurs
enregistrements, ainsi que les réglages de chaque zone. Ctrl+N ajoute un enregistrement (A,
AAAA, CNAME, PTR, MX, SRV, TXT ; pour un A, le pointeur inverse est proposé), Entrée ou F2 le
modifie, Suppr le retire ; le numéro de série du SOA est mis à jour en conséquence.
« Santé DNS » (Ctrl+D dans la fenêtre DNS, Maj+Ctrl+D depuis la fenêtre principale) cherche les
anomalies courantes : serveurs de noms et localisateurs de contrôleurs disparus, machines
retirées, pointeurs incohérents, enregistrements non rafraîchis, tombstones anciens. Elle
propose de les corriger, par l'aperçu.

**Stratégies de groupe.** Ctrl+G, ou « Stratégies de groupe », liste toutes les GPO, puis le
domaine et ses OU avec les GPO liées, dans l'ordre des liens. Le détail d'une GPO donne son
état, ses versions dans l'annuaire et dans le SYSVOL (elles doivent être égales), ses liens et
son filtrage ; une alerte signale toute divergence, y compris entre les SYSVOL des contrôleurs.

Le menu de la fenêtre crée une GPO (Ctrl+N) ou lie une GPO existante (Ctrl+L). Sur un lien, il
le retire (Suppr), le monte ou le descend (Alt+Haut, Alt+Bas), l'active (Ctrl+D) ou le rend
appliqué (Ctrl+E). Il bloque aussi l'héritage d'une OU (Ctrl+B), règle le filtrage de sécurité
(Ctrl+I), sauvegarde une GPO (Ctrl+S) et la restaure (Ctrl+O). S'il y en a, la rubrique
« Incohérences » montre les dossiers du SYSVOL sans GPO et les GPO sans dossier. Suppr sur
un dossier orphelin le retire ; « Retirer les dossiers sans GPO du SYSVOL… », dans le
menu, les retire tous. Les deux passent par l'aperçu.

**Contenu d'une GPO.** Dans la fenêtre des stratégies de groupe, Ctrl+M ou « Modifier le
contenu… » sur une GPO ouvre son éditeur, construit comme celui de la GPMC. À gauche se trouvent
Configuration ordinateur et Configuration utilisateur, avec leurs stratégies et leurs
préférences ; à droite, la page du nœud choisi.

Sous « Modèles d'administration » apparaissent les catégories du magasin central du domaine
(`SYSVOL\<domaine>\Policies\PolicyDefinitions`), avec les textes dans la langue de la session,
ou en anglais à défaut. Une catégorie montre ses sous-dossiers et ses stratégies, chacune avec
son état : Non configuré, Activé ou Désactivé. Ctrl+F cherche dans toutes les stratégies de la
partie (titre, explication, clé de registre) et Entrée ouvre la première trouvée ; Maj+Ctrl+F
ne garde que les paramètres configurés ; « Tous les paramètres » les liste tous.

Entrée sur une stratégie ouvre sa fiche : l'état, les options du modèle, vérifiées à la saisie
(bornes, longueur, valeurs requises), « Pris en charge sur », la clé de registre et
l'explication. « Appliquer » (Ctrl+Entrée) range le réglage parmi les modifications en attente,
rappelées en bas de la fenêtre. Ctrl+S les présente dans l'aperçu commun, en clair
(« Stratégie « … » : Activé ; option = 3 ») et fichier par fichier, puis les écrit :
`Registry.pol`, version de la GPO dans l'annuaire et dans `GPT.INI`, extensions déclarées.
Ctrl+Z annule la dernière écriture.

Les valeurs du `Registry.pol` qu'aucun modèle ne décrit sont montrées sous « Paramètres
supplémentaires » et conservées telles quelles ; « Registre (brut) » montre le fichier entier.
Dans ces deux vues, Ctrl+N ou le bouton « + » ajoute une entrée. On y choisit la partie,
l'action (définir la valeur, supprimer la valeur, supprimer toutes les valeurs de la clé), la
clé sans la ruche, le nom, le type (REG_SZ, REG_EXPAND_SZ, REG_DWORD, REG_QWORD, REG_MULTI_SZ,
REG_BINARY) et les données, vérifiées à la saisie : entier en décimal ou en hexadécimal et dans
ses bornes, octets en hexadécimal, une chaîne par ligne. Entrée sur une entrée la modifie, Suppr
ou le bouton corbeille la retire. Tout passe par le même brouillon et le même aperçu.

Sans magasin central, l'éditeur le signale et ne montre que le registre brut. La première
ouverture lit le magasin (quelques secondes pour 200 modèles) ; les suivantes le reprennent du
cache local (`$XDG_CACHE_HOME/calinda/modeles`).

**Préférences.** Dans l'éditeur d'une GPO, la branche « Préférences » de chaque partie contient,
comme dans la GPMC, « Mappages de lecteurs » (partie utilisateur), « Raccourcis » et « Registre »
sous « Paramètres Windows », et « Imprimantes » (imprimantes partagées, partie utilisateur) sous
« Paramètres du Panneau de configuration ». Chaque page liste les éléments dans l'ordre où le
poste les traite : Ctrl+N en ajoute un, Entrée le modifie, Suppr le retire, Alt+Haut et
Alt+Bas le déplacent.

Le dialogue de chaque élément vérifie la saisie au fil de la frappe : chemin `\\serveur\partage`,
lettre de lecteur, clé et données de registre selon le type. Son onglet « Ciblage » restreint
l'élément à un groupe de sécurité, une OU, un nom d'ordinateur ou un utilisateur, avec la
négation (« n'est pas ») et le choix entre « ET » et « OU » ; les autres filtres posés par la
GPMC restent tels quels. Les options communes sont celles de la console. Rien n'est écrit avant
« Enregistrer… » (Ctrl+S), qui passe par l'aperçu commun ; les éléments créés par la GPMC sont
conservés à l'identique. Un mot de passe enregistré dans une préférence (MS14-025, lisible par
tout utilisateur du domaine) est signalé par une bannière ; l'outil n'en écrit jamais, et
modifier l'élément le supprime.

**Paramètres de sécurité d'une GPO.** Ctrl+T sur une GPO, ou « Paramètres de sécurité… », ouvre
la stratégie de mot de passe, la stratégie de verrouillage du compte, l'attribution des droits
utilisateur et les groupes restreints, tous enregistrés dans le fichier `GptTmpl.inf` de la
partie ordinateur. Chaque réglage a son interrupteur « Définir ce paramètre de stratégie »,
sa valeur et une explication ; la valeur que le domaine applique est rappelée à côté.

**Une politique de mots de passe ne vaut pour les comptes du domaine que si elle vient d'une GPO
liée à la racine du domaine**, en pratique la Default Domain Policy. Liée à une OU, elle ne
règle que les comptes locaux des ordinateurs, et la page le signale. Pour appliquer une
politique à certains utilisateurs seulement, le domaine offre les stratégies de mot de passe
affinées (PSO), décrites plus bas. Sur un domaine Samba, Samba n'applique pas lui-même la GPO :
à l'enregistrement, l'outil écrit aussi les valeurs sur l'objet domaine, dans la même écriture,
comme le ferait `samba-tool domain passwordsettings set`. Sous Windows, c'est l'émulateur PDC
qui s'en charge.

Les droits et les groupes restreints désignent les comptes par une recherche semblable à celle
de l'assistant de délégation, ou parmi les groupes intégrés (Administrateurs, Service
réseau…). « Enregistrer… » (Ctrl+S) mène à l'aperçu commun ; Ctrl+Z dans la fenêtre principale
défait l'écriture, objet domaine compris.

**Stratégies de mot de passe.** Ctrl+M dans la fenêtre principale, ou « Stratégies de mot de
passe », montre la politique du domaine (celle de la Default Domain Policy), puis les stratégies
de mot de passe affinées (PSO) par ordre de priorité, chacune avec ses réglages et les comptes
qu'elle vise. Une PSO remplace la politique du domaine pour les comptes et les groupes globaux
de sécurité qu'elle cite. Entre plusieurs PSO, celle dont la priorité a la plus petite valeur
l'emporte, et une PSO liée directement au compte l'emporte sur celles de ses groupes.

Ctrl+N crée une PSO, dont les réglages partent de la politique du domaine ; Entrée ou le bouton
crayon la modifie, le bouton corbeille la supprime. Le dialogue reprend les libellés de la
GPMC. Les durées se saisissent en clair (« 42 j », « 1 j 12 h », « 30 min », « 90 s »,
« jamais » ; les unités anglaises sont acceptées aussi). Un nombre seul compte en jours pour
les âges du mot de passe et en minutes pour le verrouillage. Une saisie invalide ou incohérente,
comme un âge minimal supérieur à l'âge maximal ou une réinitialisation du compteur plus longue
que le verrouillage, est signalée pendant la frappe et bloque « Continuer… ».

Les comptes et groupes visés se cherchent comme dans l'assistant de délégation ; un groupe qui
n'est pas un groupe global de sécurité, ou un ordinateur, est signalé comme sans effet. Tout
passe par l'aperçu commun, et Ctrl+Z défait l'opération (une PSO supprimée est recréée avec ses
cibles). Une PSO créée par `samba-tool` ou par PowerShell est relue sans perte, et une
modification n'écrit que ce qui change. La fiche d'un utilisateur indique, sous « État », la
stratégie de mot de passe qui s'applique à lui (`msDS-ResultantPSO`, calculée par le
contrôleur).

**Partages.** Ctrl+P, ou « Partages », ouvre les partages d'un serveur de fichiers du domaine
(Samba membre ou contrôleur, Windows). Le serveur se choisit dans la liste du bouton voisin du
champ : les contrôleurs de domaine, les ordinateurs dont le système est un serveur, et les
serveurs déjà ouverts sous ce profil, que Calinda retient ; un nom DNS peut aussi être saisi,
puis Entrée ou « Ouvrir ». Un serveur Samba membre n'inscrit en général pas son système dans
l'annuaire : Calinda le reconnaît à ce qu'il a été joint sans en déclarer (ou à un nom de
service `cifs/`) et le propose après les serveurs, avec la mention « Membre du domaine, système
non déclaré ». La liste montre pour chaque dossier partagé son
chemin sur le serveur, son commentaire, ses droits de partage nommés comme dans Windows
(« Tout le monde : Lecture », « Domain Users : Modifier refusé ») et ses options ; les partages
administratifs et spéciaux (`C$`, `ADMIN$`, `IPC$`, imprimantes) sont repliés à part. La
lecture passe par le service Serveur (`srvsvc`) dans la session SMB 3 chiffrée du ticket, comme
pour le SYSVOL, et l'option « Autoriser SMB 2 avec signature seule » du profil s'y applique.
Un refus du serveur est dit dans la fenêtre.

Le bouton « Autorisations » d'un partage ouvre l'équivalent de l'onglet « Partage » de
Windows : pour chaque groupe ou compte, ce qui est autorisé et ce qui est refusé (Lecture,
Modifier, Contrôle total). On ajoute un groupe ou un compte par recherche dans l'annuaire, ou
Tout le monde, Utilisateurs authentifiés et Administrateurs d'un clic. Un partage sans droits
posés vaut « Tout le monde : Contrôle total », sur Windows comme sous Samba ; le premier
enregistrement pose des droits explicites, et l'annulation y revient. Les droits NTFS du dossier
s'appliquent en plus : l'accès accordé est le plus restrictif des deux.

Ctrl+N crée un partage : nom (contrôlé comme Windows le fait), dossier sur le serveur, qui doit
exister (Calinda ne le crée pas ; Samba attend un chemin de la forme `C:\srv\partages\Commun`
pour `/srv/partages/Commun`), commentaire, limite de connexions, disponibilité hors connexion
et énumération basée sur l'accès. Entrée ou le bouton crayon modifie un partage, le bouton
corbeille le supprime : le dossier et son contenu restent sur le serveur. Tout passe par
l'aperçu commun, qui nomme le serveur de fichiers, et Ctrl+Z défait l'opération (un partage
supprimé est recréé avec ses droits et ses options).

Sous Samba, les droits du partage, la création, la modification et la suppression demandent au
compte le privilège `SeDiskOperatorPrivilege` (`net rpc rights grant`), que les administrateurs
du domaine n'ont pas par défaut. Un partage de la configuration en registre de Samba (ceux de
`net conf`, avec `registry shares = yes` ou `include = registry`) se gère entièrement : sa
limite de connexions, sa disponibilité hors connexion (`csc policy`) et l'énumération basée sur
l'accès (`access based share enum` : le partage n'apparaît pas dans la liste d'un compte que ses
droits de partage refusent, là où Windows masque les dossiers et fichiers illisibles) sont
écrites dans sa clé de registre et prennent effet aussitôt ; sa création, sa modification et sa
suppression passent par les commandes de partage du serveur (`add share command`, `change share
command`, `delete share command`) quand il en a, par la clé du partage sinon. Calinda n'écrit
que la clé du partage visé (`HKLM\Software\Samba\smbconf\<partage>`, jamais la section globale),
et dans cette clé que ces paramètres, plus le chemin, le commentaire, `read only = no` et `guest
ok = no` d'un partage créé comme le fait `net conf addshare` ; Ctrl+Z remet la clé comme elle
était. Un partage défini dans smb.conf, que Calinda n'écrit pas, garde ses options : le dialogue
l'annonce, et Calinda le dit après l'écriture. Un contrôleur Samba ne lit pas ses partages dans
le registre : un partage qu'on y crée sans commande de partage est refusé, sans rien laisser. Un
profil en lecture seule montre la liste sans rien proposer d'écrire.

**Dossiers et droits NTFS.** Le bouton dossier d'un partage ouvre ses dossiers dans une fenêtre
à part : l'arborescence à gauche, lue niveau par niveau à mesure qu'on la déplie, et à droite
le dossier choisi, son chemin `\\serveur\partage\…` et ses fichiers, lus seulement sur
« Afficher les fichiers » (un dossier peut en contenir des milliers). Une seule session SMB sert
toute la fenêtre ; F5 relit, Échap ferme.

« Sécurité… » (ou le bouton d'un fichier) ouvre l'équivalent de l'onglet « Sécurité » de
Windows : le propriétaire, l'état de l'héritage et chaque entrée, autorisée ou refusée, avec son
niveau (Contrôle total, Modification, Lecture et exécution, Lecture, Écriture, ou
« Autorisations spéciales » et la liste des droits fins), ce à quoi elle s'applique pour un
dossier, et sa provenance : explicite, ou héritée de tel dossier du partage, ou d'au-dessus du
partage. Les groupes et comptes sont nommés d'après l'annuaire, et ceux du serveur lui-même
(groupes locaux, `BUILTIN\…`) d'après le serveur. On ajoute une entrée par recherche dans
l'annuaire ou d'un clic (Tout le monde, Utilisateurs authentifiés, Utilisateurs,
Administrateurs, CREATEUR PROPRIETAIRE) ; la fenêtre d'entrée propose le type, « S'applique à »,
le niveau, les droits fins et « un seul niveau ». Une entrée explicite se modifie ou se retire ;
une entrée héritée se change sur le dossier d'où elle vient. « Désactiver l'héritage… » offre
les deux choix de Windows : convertir les entrées héritées en entrées explicites, ou les
supprimer ; « Activer l'héritage » recalcule les entrées héritées depuis le dossier parent.
Pour un dossier, « Remplacer toutes les entrées d'autorisation des objets enfants… » retire les
entrées explicites des descendants et réactive leur héritage.

**Propriétaire.** « Modifier… », à côté du propriétaire, le donne à soi-même, au groupe
Administrateurs ou à un compte ou un groupe cherché dans l'annuaire ; pour un dossier,
« Remplacer le propriétaire des sous-conteneurs et des objets » le donne aussi à tout ce qui est
dessous, y compris sous un dossier dont l'héritage est désactivé et aux éléments que le compte
ne peut pas lire (c'est ce qui permet ensuite de les ouvrir). Cela passe par le même comptage,
la même confirmation, la même sauvegarde et le même Ctrl+Z que la propagation de l'héritage ; un
élément qui n'a pas pu être lu avant n'a rien à réécrire et est signalé à l'annulation. Le
client SMB ne transmet aucun privilège : c'est le serveur qui décide d'après le compte. Se
donner la propriété demande l'autorisation « Appropriation » sur l'élément, ou le privilège
« Prendre possession de fichiers ou d'autres objets » (SeTakeOwnershipPrivilege) sur le
serveur ; la donner à un autre compte demande en plus « Restaurer des fichiers et des
répertoires » (SeRestorePrivilege). Les administrateurs du domaine les ont sur un contrôleur
Windows comme sur un Samba membre où `BUILTIN\Administrators` les tient ; un refus dit lequel
manque.

**Audit.** La section « Audit » de l'onglet montre les entrées d'audit (SACL) comme l'onglet
« Audit » des paramètres avancés de Windows : type (« Réussite », « Échec » ou « Tout »),
principal, droits audités, ce à quoi l'entrée s'applique et sa provenance. « Type d'entrée »,
au-dessus de la recherche, fait ajouter une entrée d'audit plutôt qu'une autorisation ; une
entrée explicite se modifie ou se retire, l'héritage des entrées d'audit se désactive ou se
réactive à part, et pour un dossier « Remplacer toutes les entrées d'audit des objets
enfants… » fait ce que fait son pendant pour les autorisations. La propagation, la sauvegarde
et Ctrl+Z sont les mêmes. Lire et écrire l'audit demande le privilège « Gérer le journal d'audit
et de sécurité » (SeSecurityPrivilege) sur le serveur ; sans lui, l'onglet le dit et reste
utilisable pour les autorisations et le propriétaire, et rien d'autre dans Calinda ne demande
la SACL. Samba garde les entrées d'audit mais n'en fait rien (il n'écrit aucun événement) ; une
modification des autorisations faite par un compte qui ne lit pas l'audit lui fait perdre, sous
Samba, sa protection (pas ses entrées).

Écrire les droits d'un dossier ne propage rien côté serveur, ni sous Windows ni sous Samba :
Calinda recalcule lui-même, comme Windows, les entrées héritées de chaque descendant dont
l'héritage n'est pas désactivé (et ne descend pas sous un dossier dont l'héritage l'est, sauf
avec « Remplacer »). Quand ce qu'héritent les enfants change, « Continuer… » compte d'abord les
dossiers et fichiers concernés et demande confirmation, en disant où leurs descripteurs seront
sauvegardés (`~/.local/state/calinda/propagations/`), avant l'aperçu commun. Pendant
l'écriture, l'aperçu montre la progression et un bouton « Arrêter » : ce qui est écrit reste
écrit et sauvegardé, « Reprendre » relance la propagation, qui n'écrit que ce qui n'est pas
encore à jour. Un élément refusé (compte sans droit, élément changé entre-temps) est signalé à
la fin sans interrompre les autres. Ctrl+Z, dans la fenêtre des dossiers comme ailleurs, remet
les descripteurs sauvegardés, chacun seulement s'il est encore tel que la propagation l'a
laissé, puis les droits du dossier.

Une sauvegarde que le journal nomme encore n'est jamais retirée, puisque Ctrl+Z, l'historique
et la reprise s'en servent. Celles dont l'entrée a quitté le journal (il garde 10 Mo et cinq
archives) sont retirées au lancement après 30 jours ; la durée se règle par
`gsettings set io.github.f3nr1l.Calinda jours-sauvegardes-propagation 90` (0 : jamais). Dans
l'historique, le bouton « Sauvegardes des propagations » dit combien il y en a et la place
qu'elles prennent, et retire tout de suite celles que le journal ne nomme plus.

Si l'application s'arrête pendant une propagation (fermeture forcée, panne), le domaine propose
à sa réouverture de régler la modification : Calinda constate d'après la sauvegarde ce qui a
été écrit et dit combien d'éléments elle contient ; « Terminer » relance la propagation, qui
n'écrit que ce qui n'est pas encore à jour, « Annuler ce qui a été fait » réécrit les
descripteurs sauvegardés.

Sous Samba, les droits NTFS ne sont fidèles qu'avec le module `acl_xattr` ; Samba garde les
droits génériques sous leur forme de droits de fichiers (un « GA » relu « FA »), ce que Calinda
tient pour identique. Avec `acl_xattr:ignore system acls`, seul le propriétaire Unix d'un
élément qui n'a pas encore de droits NT peut les écrire.

**Accès effectif.** « Accès effectif… », à côté de « Sécurité… » dans la fenêtre des dossiers
(ou le bouton d'un fichier, ou celui d'un partage dans la fenêtre « Partages » pour sa racine),
dit ce qu'un compte ou un groupe peut faire sur cet élément, comme l'onglet « Accès effectif »
de Windows. On cherche le compte ou le groupe dans l'annuaire ; Calinda lit ses groupes
(`tokenGroups`, ou pour un groupe ceux qui le contiennent), les groupes locaux du serveur qui le
comptent (par SAMR), les droits du partage et ceux de l'élément, et les évalue comme le
serveur. Le résultat donne le niveau obtenu (partage et NTFS combinés), puis chaque droit,
accordé ou non, avec ce qui le limite (le partage, les droits NTFS, ou les deux) et l'entrée
qui en décide de chaque côté : celle qui l'accorde, celle qui le refuse, ou aucune. Ce qui
n'est pas évalué est dit : groupes locaux illisibles, entrées conditionnelles, stratégie
d'accès centralisée, étiquette d'intégrité, et toujours les privilèges (sauvegarde,
restauration, prise de possession). La liste des identités prises en compte est repliée sous
le résultat. Rien n'est écrit.

**Entrée de contrôle d'accès en SDDL.** Dans l'onglet « Sécurité » d'une fiche, vue « ACE et
SDDL », « Ajouter… » ouvre un champ de saisie pour une autorisation ou un refus, simple, objet
ou conditionnel, sous la forme de Samba ou de Windows, par exemple
`(XA;;WP;;;AU;(Member_of {SID(S-1-5-21-…-1105)}))`. La saisie est analysée à chaque frappe :
le dialogue affiche l'entrée en clair (« Utilisateurs authentifiés peut écrire toutes les
propriétés sur cet objet, si le compte est membre de … », les groupes étant nommés d'après
l'annuaire) et la forme qui sera écrite, ou l'erreur.

Une condition qui cite `SID(DA)`, `SID(DU)` ou une autre abréviation relative au domaine est
écrite avec le SID complet, comme le fait Windows : Samba 4.22 ne relit pas ces abréviations
dans une condition et s'arrête net, ce que rappelle une remarque du dialogue. L'audit et les
attributs de ressource, qui relèvent de la SACL, ne s'ajoutent pas ici. L'entrée prend sa place
dans l'ordre canonique ; l'aperçu commun la montre et Ctrl+Z la retire.

**Raccourcis.** Ctrl+? affiche tous les raccourcis clavier ; toutes les fonctions sont
accessibles sans souris.

## Langue

L'interface suit la langue de la session : français si la session est en français, anglais
sinon. Pour lancer l'application en anglais depuis une session française :

```sh
LANGUAGE=en calinda
```

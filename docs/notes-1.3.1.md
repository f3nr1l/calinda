# Calinda 1.3.1 — notes de version

24 octobre 2026. Version corrective de la 1.3, née d'un incident réel : la propagation de
l'héritage à quelques milliers d'éléments sur un serveur Windows lent, au stockage saturé,
s'arrêtait à mi-chemin sur un délai dépassé, et le retour arrière ne remettait que la racine.
Elle corrige aussi les libellés des écritures sur les partages et la fusion des entrées NTFS
identiques.

## Corrections

- **Propagation sur un serveur lent.** Calinda attend une réponse tant que le serveur continue
  de répondre : le délai court depuis la dernière trame reçue et croît avec le nombre de
  requêtes en vol. Les lots rétrécissent quand le serveur est lent et grandissent de nouveau
  quand il répond vite, pour que l'arrêt reste rapide. Après un délai dépassé, la session est
  abandonnée et le retour arrière en ouvre une neuve ; il remet aussi, depuis la sauvegarde, ce
  que la propagation interrompue avait déjà écrit, et non plus la seule racine.
- **Libellés des écritures sur les partages.** Le compte rendu nomme les dossiers par leur
  chemin `\\serveur\partage\chemin`, et non plus « SYSVOL\… » ; la création, la modification
  et la suppression d'un partage et la propagation de l'héritage ont leur propre libellé.
- **Entrées NTFS fusionnées.** Dans l'onglet « Sécurité » des dossiers et fichiers, ajouter un
  compte déjà présent avec la même portée réunit ses droits dans l'entrée existante au lieu
  d'en créer une seconde, et les entrées explicites identiques (même compte, même type, même
  portée) sont fusionnées à l'écriture, comme le fait Windows.

## Installation

Le RPM `calinda-1.3.1-1.fc44.x86_64.rpm` vise Fedora 44 et suivantes, le paquet Debian
`calinda_1.3.1-1_amd64.deb` Ubuntu 26.04 et suivantes. L'un et l'autre ne dépendent que des
paquets de la distribution et remplacent la 1.3.0 sans autre geste. Mode d'emploi :
[utilisation.md](utilisation.md) ([English](utilisation.en.md)). Les limites connues de la 1.3.0
([notes-1.3.0.md](notes-1.3.0.md)) restent valables.

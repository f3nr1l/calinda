# Annuaire 0.5.0 — notes de version

14 octobre 2026. Version de travail, non publiée : elle se construit et s'installe en RPM sur
Fedora (README, « Construire le RPM »).

## Ce qu'apporte la 0.5

Annuaire administre un domaine Active Directory ou Samba depuis GNOME, sans poste Windows. La
0.1 couvrait les comptes, groupes et unités d'organisation ; la 0.5 ajoute :

- **les stratégies de groupe**, sans éditeur de leur contenu : inventaire et alertes de
  cohérence entre annuaire et SYSVOL, liens, création et suppression, filtrage de sécurité,
  sauvegarde et restauration, stratégie résultante d'un compte ou d'un ordinateur ;
- **le DNS** des zones intégrées à l'annuaire, en lecture et en écriture, et un diagnostic de
  leur santé qui propose ses corrections ;
- **la sécurité des objets** lue en phrases claires, la délégation de contrôle et l'éditeur
  d'attributs ;
- **une copie locale** de l'annuaire, synchronisée par delta, qui rend l'ouverture immédiate ;
- **l'anglais** : l'interface suit la langue de la session (français par défaut).

Toute écriture passe par le même aperçu, est vérifiée par relecture, journalisée sur le poste
et annulable. Un profil peut être mis en lecture seule.

## Installation

Le paquet `annuaire-0.5.0-1.fc44.noarch.rpm` ne dépend que de paquets Fedora. Il installe le
lanceur `/usr/bin/annuaire` et l'entrée « Annuaire » du menu des applications. Mode d'emploi :
[utilisation.md](utilisation.md) ([English](utilisation.en.md)).

## Taille

RPM, paquet installé et mémoire au repos sont mesurés à chaque version (plan, J6.3) : c'est la
référence que le futur port en Rust devra battre.

## Limites connues

- Pas d'éditeur du contenu des GPO (prévu pour la 1.0, jalon J7).
- Les filtres WMI et les liens de site ne sont pas évalués dans la stratégie résultante ; ils
  sont signalés comme tels.
- La copie locale n'est pas chiffrée : pour un domaine client, un disque chiffré est
  recommandé.
- Pas de Flatpak : le RPM est le format de distribution (voir ADR 0004 pour l'accès au cache
  Kerberos depuis un bac à sable).
- Les messages d'erreur internes (décodage d'une valeur mal formée, erreur de programmation)
  restent en français dans l'interface anglaise.

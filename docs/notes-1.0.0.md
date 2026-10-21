# Annuaire 1.0.0 — notes de version

15 octobre 2026. Version de travail, non publiée : elle se construit et s'installe en RPM sur
Fedora (README, « Construire le RPM »). C'est la dernière version de la lignée Python ; la suite
est le port en Rust (plan, section R), qui sera la version diffusée.

## Ce qu'apporte la 1.0

La 0.5 gérait les stratégies de groupe sans toucher à leur contenu. La 1.0 ajoute :

- **l'éditeur du contenu des GPO**, dans l'arbre de la GPMC : modèles d'administration lus dans
  le magasin central du domaine, registre brut, paramètres de sécurité (mots de passe et
  verrouillage, droits utilisateur, groupes restreints) et préférences (lecteurs mappés,
  imprimantes, raccourcis, registre, avec ciblage). Une GPO modifiée par Annuaire se relit dans
  la GPMC sans perte et s'applique sur les postes Windows ; l'aller-retour Annuaire → GPMC →
  Annuaire ne perd rien. Vérifié sur un domaine Samba et sur un domaine Windows Server 2025 ;
- **les stratégies de mot de passe affinées** (PSO), dans une fenêtre à part : création,
  modification, suppression, cibles et priorité ; la fiche d'un utilisateur dit celle qui
  s'applique à lui ;
- **les autorisations conditionnelles** (contrôle d'accès dynamique), lues en clair et écrites
  en SDDL dans l'onglet « Sécurité » ;
- un accès direct aux fenêtres DNS, Santé DNS, Stratégies de groupe et Historique, des
  annulations successives sur un même objet, les classes auxiliaires dans l'éditeur
  d'attributs, et des messages d'erreur internes traduits en anglais.

Comme avant, toute écriture passe par le même aperçu, est vérifiée par relecture, journalisée
sur le poste et annulable, et un profil peut être mis en lecture seule.

## Installation

Le paquet `annuaire-1.0.0-1.fc44.noarch.rpm` ne dépend que de paquets Fedora. Il installe le
lanceur `/usr/bin/annuaire` et l'entrée « Annuaire » du menu des applications. Mode d'emploi :
[utilisation.md](utilisation.md) ([English](utilisation.en.md)).

Les modèles d'administration de Microsoft ne sont pas fournis (licence) : l'éditeur lit ceux du
magasin central du domaine (`SYSVOL\<domaine>\Policies\PolicyDefinitions`). Sans magasin, seul
le registre brut est proposé.

## Taille

RPM, paquet installé et mémoire au repos sont mesurés à chaque version (plan, J6.3) : c'est la
référence que le port en Rust devra battre. Le premier crate de ce port, `annuaire-codecs`
(ADR 0015), est construit et testé contre les codecs Python, mais l'application ne l'utilise
pas encore.

## Limites connues

- Une PSO ne se renomme pas : il faut en créer une autre et supprimer l'ancienne.
- Pas d'assistant pour composer une condition : une ACE conditionnelle se saisit en SDDL, lue
  et dite en clair à la frappe.
- La fin de verrouillage affichée dans la fiche d'un utilisateur se calcule avec la durée de
  verrouillage du domaine, même quand une PSO lui en applique une autre.
- Préférences : quatre familles seulement (lecteurs, imprimantes, raccourcis, registre) ; les
  autres sont conservées sans être modifiables, comme les filtres de ciblage autres que groupe,
  OU, ordinateur et utilisateur.
- Les filtres WMI et les liens de site ne sont pas évalués dans la stratégie résultante ; ils
  sont signalés comme tels.
- La copie locale n'est pas chiffrée : pour un domaine client, un disque chiffré est
  recommandé.
- Pas de Flatpak : le RPM est le format de distribution (voir ADR 0004 pour l'accès au cache
  Kerberos depuis un bac à sable).

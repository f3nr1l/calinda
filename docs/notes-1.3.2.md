# Calinda 1.3.2 — notes de version

24 octobre 2026. Version corrective de la 1.3, qui règle un cas laissé sans issue : une
modification interrompue, que Calinda propose de reprendre au démarrage, alors que
l'administrateur l'a déjà terminée ou défaite par un autre moyen.

## Correction

- **Modification à régler : « Ignorer ».** Au démarrage, une modification à régler peut
  désormais être ignorée quand elle a été terminée ou défaite hors de Calinda. Après
  confirmation, elle n'est plus proposée ; rien n'est écrit dans l'annuaire ni sur les
  serveurs, et l'historique la montre « Ignorée », avec sa date et l'utilisateur. Une 1.3.1
  qui relit le même journal cesse aussi de la proposer.

## Installation

Le RPM `calinda-1.3.2-1.fc44.x86_64.rpm` vise Fedora 44 et suivantes, le paquet Debian
`calinda_1.3.2-1_amd64.deb` Ubuntu 26.04 et suivantes. L'un et l'autre ne dépendent que des
paquets de la distribution et remplacent la 1.3.1 sans autre geste. Mode d'emploi :
[utilisation.md](utilisation.md) ([English](utilisation.en.md)). Les limites connues de la 1.3.0
([notes-1.3.0.md](notes-1.3.0.md)) restent valables.

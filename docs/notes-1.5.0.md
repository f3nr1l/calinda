# Calinda 1.5.0 — notes de version

30 octobre 2026. La 1.4 a complété l'administration courante des comptes, dont l'onglet LAPS qui
lisait le mot de passe en clair. La 1.5 lit le mot de passe **chiffré**
(`msLAPS-EncryptedPassword`), le cas recommandé de Windows LAPS. Vérifié contre un domaine
Windows Server 2025.

## LAPS chiffré

- **Onglet « LAPS »** : un mot de passe d'administrateur local chiffré par Windows LAPS est
  maintenant lu comme le clair, avec les mêmes règles (montré sur demande, presse-papiers effacé
  après 30 secondes, jamais gardé dans la copie locale ni dans l'historique). Il n'est plus
  seulement signalé « chiffré ».
- Le déchiffrement demande la clé de groupe au contrôleur par le service de distribution de clés
  (MS-GKDI), sur une liaison DCE/RPC authentifiée par Kerberos et scellée (confidentialité au
  niveau paquet). La clé de chiffrement de clé est dérivée des graines du groupe (SP800-108) et,
  dans le cas courant où l'ordinateur n'a que la clé publique du groupe, par un accord de clés
  Diffie-Hellman ou ECDH ; le contenu est déchiffré en AES, par l'OpenSSL du système. Tout cela
  sans dépendance nouvelle.
- Le droit de lire reste celui du contrôleur : un compte qui n'est pas autorisé à déchiffrer le
  mot de passe le voit toujours signalé « chiffré », avec la raison.

## Installation

Le RPM `calinda-1.5.0-1.fc44.x86_64.rpm` vise Fedora 44 et suivantes, le paquet Debian
`calinda_1.5.0-1_amd64.deb` Ubuntu 26.04 et suivantes. L'un et l'autre ne dépendent que des
paquets de la distribution. Mode d'emploi : [utilisation.md](utilisation.md)
([English](utilisation.en.md)), section « Les fenêtres », paragraphe « Fiche », entrée « LAPS ».

## Limites connues

- Le mot de passe chiffré n'est lu que si le compte qui interroge a le droit de le déchiffrer
  (le descripteur de protection du mot de passe). Sinon il reste signalé « chiffré ».
- Les contrôleurs Samba du laboratoire ne servent pas LAPS chiffré au poste d'essai (le compte
  machine n'obtient pas de ticket Kerberos, cause indépendante de Calinda) ; la lecture est
  validée contre Windows Server 2025.
- L'accord de clés sur courbe elliptique (ECDH) est écrit et vérifié sur vecteur, mais le
  laboratoire n'a exercé en vrai que l'accord Diffie-Hellman à corps fini.

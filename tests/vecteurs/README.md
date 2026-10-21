# Vecteurs de test des codecs (J0.8)

Échantillons réels lus sur le DC Samba du labo (`dc1.lab.test`) — et, pour `sddlwin.json`,
sur le DC Windows `wdc1.win.test` —, avec leur valeur décodée par l'oracle Samba. Ils servent
de référence aux codecs purs de la version Python (`annuaire/core/codecs/`, J1.4, J3, J4, J5,
J7, étiquette `v1.0.0`) et, tels quels, au port Rust (R1), seul sur `main` depuis la 1.1.0
(tests de `rust/annuaire-codecs/tests/` et du cœur) : le format est neutre, JSON en UTF-8,
binaire en hexadécimal. Les extracteurs qui importaient la version Python
(`labo/comparer_sddl_windows.py`) et `tests/unitaires/test_vecteurs.py` sont sur cette branche.

Un fichier par codec :

| Fichier | Contenu | Échantillons |
|---|---|---|
| `sid.json` | `objectSid` : domaine, comptes (RID 500, 502, 512, 1000, > 1000), Builtin, SID bien connus des `ForeignSecurityPrincipals`, quatre SID construits | 16 |
| `guid.json` | `objectGUID`, `schemaIDGUID`, `attributeSecurityGUID`, `invocationId` | 7 |
| `temps.json` | FILETIME (`lastLogonTimestamp`, `pwdLastSet`, `accountExpires` 0, date, `0x7FFFFFFFFFFFFFFF`), durées négatives (`maxPwdAge`, `minPwdAge`, `lockoutDuration`, `lockOutObservationWindow`, `forceLogoff` = -2^63), un `GeneralizedTime` | 13 |
| `uac.json` | `userAccountControl`, `groupType` (trois portées × sécurité ou distribution, plus Builtin), `sAMAccountType` : une valeur distincte par vecteur | 22 |
| `sd.json` | `nTSecurityDescriptor` (domaine, OU, OU à virgule, utilisateur, Administrator, deux GPO, nœud DNS ; une fois avec la SACL) et ACL NT de deux dossiers de GPO du SYSVOL | 11 |
| `sddl.json` | SDDL (J4.1) : descripteurs **construits**, écrits et relus par Samba (chaque abréviation de SID, masques de fichiers, hexadécimaux et génériques, tous les drapeaux d'ACE, ACE objet à un seul GUID, SACL, ACL vide ou annoncée sans contenu, 60 tirés au hasard) ; produits par `labo/extraire_sddl.py` | 144 |
| `sddlwin.json` | `nTSecurityDescriptor` (SD flags 15) lus sur le **DC Windows** `wdc1.win.test` (validation croisée) : deux par famille d'objets, la racine et l'OU déléguée par `dsacls` ; `attendu` : SDDL de l'outil (`sddl`), de l'API Win32 (`sddl_windows`), de `Get-Acl` (`sddl_get_acl`, quand le fournisseur `AD:` accepte le DN) et SID du domaine ; `source` porte `windows` au lieu de `samba` ; produits par `labo/comparer_sddl_windows.py --vecteurs` | 23 |
| `dnsrecord.json` | `dnsRecord` : SOA, NS, A (statique et dynamique), AAAA, PTR, SRV, CNAME, MX, TXT, tombstone (type 0) | 14 |
| `dnsproperty.json` | `dNSProperty` des zones `lab.test` et `1.168.192.in-addr.arpa` | 14 |
| `gplink.json` | `gPLink` : un, deux, trois liens ; options 0, 1, 2, 3 ; domaine ; OU à virgule ; `gPOptions` 0 et 1 | 10 |
| `registrypol.json` | `Registry.pol` ordinateur et utilisateur d'une GPO de labo, plus un fichier vide | 3 |
| `registrypol_gpmc.json` | `Registry.pol` écrits par la GPMC de RSAT (`Set-GPRegistryValue`, J7.1) sur le SYSVOL Samba de dc1 : chaque type, `**del.`, `**delVals.`, `**DeleteValues`, `**DeleteKeys`, `**SecureKey` ; `attendu` : `entrees` (valeurs posées, dans l'ordre), `gpmc` (relecture par `Get-GPRegistryValue`), `version_gpo`, `extensions` ; produits par `labo/extraire_registrypol_gpmc.py poste` | 2 |
| `registrypol_win.json` | les mêmes, écrits par la GPMC du DC Windows `wdc1.win.test` ; `labo/extraire_registrypol_gpmc.py wdc` | 2 |
| `inf.json` | `GptTmpl.inf` : tel qu'écrit par samba-tool (UTF-8), au format de la GPMC (UTF-16LE), trois fichiers de Windows et un fichier réécrit par la GPMC (J7.5) | 6 |
| `sddl_conditionnel.json` | ACE conditionnelles (`XA`, `XD`, `ZA`, `XU` : chaque opérateur, attributs utilisateur, appareil, ressource et locaux, entiers dans les trois bases, chaînes, octets, listes, SID, `&&`, `||`, `!`) et d'attribut de ressource (`RA` : `TI`, `TU`, `TS`, `TD`, `TX`) construits par Samba depuis le SDDL de `description` ; `attendu` : `sddl` (écriture de Samba) ; produits par `labo/extraire_sddl_conditionnel.py` | 57 |
| `sddl_conditionnel_windows.json` | Les SDDL de `sddl_conditionnel.json` (entrée et écriture de Samba) et des formes propres à Windows (`SID(DA)`, casse libre, `&&` et `||` mêlés) lus par l'API Win32 du **DC Windows** `wdc1.win.test` (`ConvertStringSecurityDescriptorToSecurityDescriptorW`) ; `attendu` : `sddl_windows` (réécriture par la même API) et `sid_domaine` ; `source` porte `windows` ; produits par `labo/extraire_sddl_conditionnel_windows.py` | 105 |
| `fsacl.json` | `dsacl2fsacl` (J5.4) : descripteur de chaque GPO du labo et descripteurs construits (refus, audit, pré-Windows 2000, CREATEUR PROPRIETAIRE, héritées, objet, chaque droit seul, DACL vide), avec l'ACL que `sysvolreset` donne au dossier SYSVOL ; `attendu` : `sddl`, `fichier_sddl`, `fichier_dacl_hex` ; produits par `labo/extraire_fsacl.py` | 20 |
| `preferences.json` | Préférences de stratégie de groupe (J7.6, MS-GPPREF) : `Registry.xml` utilisateur et ordinateur écrits par la GPMC (module GroupPolicy, `Set-GPPrefRegistryValue`) sur LAB.TEST (poste Windows 11) et sur WIN.TEST (DC Windows), puis fichiers construits dans la forme de la console (lecteurs avec ciblage, `cpassword` factice, imprimantes partagée et TCP/IP, raccourcis, collection de registre et commentaire, racine vide, famille désactivée en LF) ; `attendu` : lecture par `System.Xml.XmlDocument` sur le poste (racine, attributs dans l'ordre, éléments, `Properties`, valeurs, filtres) et, pour la GPMC, `gPC*ExtensionNames` et `versionNumber` ; produits par `labo/vecteurs_preferences.py` | 11 |
| `dn.json` | DN : virgule échappée, conflits `CNF:` (`\0A`), apostrophe et accents, `LostAndFound`, accolades | 8 |

## Format

```json
{
  "format": 1,
  "famille": "sid",
  "description": "…",
  "source": {"dc": "dc1.lab.test", "domaine": "lab.test", "samba": "4.22.11-Debian-…"},
  "vecteurs": [
    {
      "id": "sid-administrator",
      "description": "RID 500",
      "provenance": {
        "objet": "CN=Administrator,CN=Users,DC=lab,DC=test",
        "attribut": "objectSid",
        "commande": "ldbsearch -H /var/lib/samba/private/sam.ldb -s base -b '…' objectSid",
        "preparation": "…"
      },
      "hex": "010500000000000515000000…",
      "texte": "…",
      "attendu": {"texte": "S-1-5-21-…-500", "…": "…"}
    }
  ]
}
```

- `format` : version du format de fichier, 1. `famille` : nom du fichier sans `.json`.
- `id` : unique dans le fichier, minuscules, chiffres, `.`, `_`, `-`. Stable d'une extraction à
  l'autre ; les tests des codecs peuvent y faire référence.
- `hex` : **les octets bruts**, tels que l'attribut LDAP les renvoie (ou le fichier tel qu'il est
  sur le SYSVOL), en hexadécimal minuscule sans séparateur. Pour les attributs de syntaxe texte
  (entiers, `gPLink`, DN, `GeneralizedTime`), ce sont les octets UTF-8 de la chaîne, et `texte`
  en donne la forme lisible (même contenu, redondant).
- `attendu` : la valeur décodée de référence (détail par famille ci-dessous). Les noms de
  constantes (`type_nom`, `drapeaux`, …) sont ceux de Samba, préfixe retiré (`UF_`, `DNS_TYPE_`,
  `SEC_ACE_TYPE_`, …).
- `provenance` : `objet` (DN, chemin du fichier, ou `(construit)` quand l'oracle a fabriqué la
  valeur), `attribut` (`(fichier)` ou `(NT ACL)` hors annuaire), `commande` (lecture équivalente,
  pour vérifier à la main), `preparation` facultatif (comment l'objet a été créé dans le labo).
- Les descripteurs de sécurité sont lus avec le contrôle *SD flags* = 7 (propriétaire, groupe,
  DACL), comme l'outil les lira (J1.3), sauf `sd-ou-labo-avec-sacl` (15).

Aucun secret : aucun attribut de mot de passe, rien de `secrets.ldb`. Le test
`tests/unitaires/test_vecteurs.py` vérifie la forme de chaque fichier (et refuse les attributs de
mot de passe) ; il ne décode rien. Le contenu est vérifié par les tests des codecs
(`test_codecs_sid_guid.py`, `test_codecs_temps_uac.py`, `test_dn_filtre.py`, depuis J1.4 ;
`test_codecs_sd.py`, J2.6 ; `test_codecs_dnsrecord.py` et `test_codecs_dnsproperty.py`, J3).
Le port Rust (R1, `rust/annuaire-codecs/tests/`) relit les mêmes fichiers par `cargo test`, sauf
`preferences.json` (codec XML pas encore porté) et `dn.json` (DN hors de `codecs/`).

### `attendu` par famille

| Famille | Champs |
|---|---|
| sid | `texte` (`S-1-…`), `revision`, `autorite` (entier, 48 bits gros-boutistes), `sous_autorites` (liste), `rid` (dernière sous-autorité d'un SID de domaine `S-1-5-21-a-b-c-RID`, sinon `null`) |
| guid | `texte` (forme canonique minuscule ; les trois premiers champs sont petit-boutistes dans le binaire) |
| temps | date : `nttime`, `jamais`, `iso` (UTC, 7 décimales), `unix` (`samba.nttime2unix`) ; durée : `centaines_ns` (négatif), `jamais`, `secondes`, `samba_tool` (ligne de `samba-tool domain passwordsettings show`) ; `GeneralizedTime` : `unix` (`ldb.string_to_time`), `iso` |
| uac | `valeur` (entier signé tel que stocké), `drapeaux` ; pour `groupType` : `non_signe`, `gtype` (constante `GTYPE_*`), `portee` (`builtin`, `global`, `domaine_local`, `universel`), `securite` ; pour `sAMAccountType` : `atype` |
| sd | `sddl` (`descriptor.as_sddl(SID du domaine)`, abréviations `DA`, `DU`… comprises), `sddl_samba_tool` (sortie de `samba-tool dsacl get` ou `ntacl get --as-sddl`, quand elle sert de référence), `structure` : `revision`, `controle` (+ `controle_noms`), `proprietaire`, `groupe`, `dacl` / `sacl` (`revision`, `aces` : `type`, `type_nom`, `drapeaux`, `drapeaux_noms`, `masque`, `sid`, et pour les ACE objet `objet` : `drapeaux`, `type`, `type_herite`) |
| sddl | `sddl` (`as_sddl(SID du domaine)`), `sddl_sans_domaine` (`as_sddl()`), `relu_hex` (`ndr_pack(from_sddl(sddl, SID du domaine))`) |
| dnsrecord | en-tête : `longueur_donnees`, `type`, `type_nom`, `version`, `rang`, `rang_nom`, `drapeaux`, `serie`, `ttl`, `reserve`, `horodatage` (heures depuis 1601, 0 = statique) ; `donnees` selon le type : chaîne (A, AAAA, PTR, NS, CNAME), `{priorite, cible}` (MX), `{priorite, poids, port, cible}` (SRV), `{serie, rafraichissement, nouvel_essai, expiration, minimum, serveur, responsable}` (SOA), liste de chaînes (TXT), `{nttime, iso}` (tombstone) ; `dNSTombstoned` pour le nœud en tombstone |
| dnsproperty | `longueur_donnees`, `longueur_nom`, `drapeau`, `version`, `id`, `id_nom` (`DSPROPERTY_ZONE_*`), `valeur` |
| gplink | `liens` dans l'ordre de la chaîne : `dn`, `guid`, `options`, `desactive` (bit 1), `applique` (bit 2) ; `gPOptions` : `valeur`, `heritage_bloque` |
| registrypol | `signature`, `version`, `entrees` : `cle`, `valeur`, `type`, `type_nom`, `taille` (octets, terminateurs compris), `donnees` (entier pour DWORD/QWORD, chaîne pour SZ/EXPAND_SZ, liste pour MULTI_SZ, hexadécimal pour BINARY) |
| inf | `encodage`, `bom`, `sections` dans l'ordre : liste de `[clé, valeur]`, de lignes brutes (`Registry Values`), de `[clé, [SID…]]` (`Privilege Rights`) ou de `[[SID, Memberof|Members], [SID…]]` (`Group Membership`) |
| dn | `composants` (`attribut`, `valeur` sans échappement, de la feuille à la racine), `name` (attribut `name` de l'objet) |

## Oracle

Le décodage est fait **sur le DC** par les bibliothèques de Samba, interdites dans `annuaire/` :
`samba.ndr.ndr_unpack` avec `samba.dcerpc.security` (`dom_sid`, `descriptor`), `misc.GUID`,
`dnsp.DnssrvRpcRecord`, `dnsp.DnsProperty`, `preg.file` ; `samba.netcmd.gpo.parse_gplink` ;
`samba.gp_parse.gp_inf.GptTmplInfParser` ; `ldb.Dn` ; `samba.ntacls.getntacl`. Deux écarts,
signalés dans les vecteurs : l'oracle rend les `REG_MULTI_SZ` en octets bruts (la liste est
découpée par le script : UTF-16LE, séparateur NUL, double NUL final), et les dates ISO sont
calculées par le script à partir du NTTIME (contrôlées par `samba.nttime2unix`).

## Régénérer

Les vecteurs sont extraits d'un laboratoire Samba par des scripts du répertoire `labo/`, qui
n'est pas publié avec ce dépôt : les fichiers sont donc figés ici. Après une reconstruction du
DC, SID, GUID, dates et descripteurs changeraient : on régénère alors tous les fichiers ensemble.

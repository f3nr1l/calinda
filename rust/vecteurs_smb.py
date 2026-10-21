# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: 2026 René Onier
"""Vecteurs de la cryptographie SMB du port Rust (ADR 0017), calculés par smbprotocol.

Les fonctions de smbprotocol que la version Python emploie (dérivation des clés, signature,
chiffrement), appliquées à des entrées fixes ; le résultat est écrit en Rust dans
`annuaire-core/src/smb/vectors.rs`, que lisent les tests de `smb/crypto.rs`.

    python3 rust/vecteurs_smb.py > rust/annuaire-core/src/smb/vectors.rs

Il faut smbprotocol (1.17.0 pour les vecteurs du dépôt) et `cryptography`.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
from types import SimpleNamespace
from unittest import mock

import smbprotocol
from smbprotocol.connection import Ciphers, Connection, Dialects, SigningAlgorithms
from smbprotocol.session import Session

CLE = b"0123456789abcdef"
PREAUTH = b"\x5a" * 64
NONCE = b"\x11" * 16


def message() -> bytes:
    """Le message des tests Rust : en-tête (CREATE, identifiant 42, session 7, arbre 3,
    drapeau SIGNED) puis un corps quelconque."""
    entete = b"\xfeSMB" + struct.pack(
        "<HHIHHIIQIIQ16s", 64, 0, 0, 5, 0, 0x8, 0, 42, 0, 3, 7, b"\x00" * 16
    )
    return entete + b"body of the message"


def kdf(etiquette: bytes, contexte: bytes) -> bytes:
    return Session._smb3kdf(None, CLE, etiquette, contexte)  # type: ignore[arg-type]


def signature(algorithme: int, dialecte: int = Dialects.SMB_3_1_1) -> bytes:
    faux = SimpleNamespace(dialect=dialecte, signing_algorithm_id=algorithme)
    m = message()
    return Connection._generate_signature(faux, m, CLE, 42, False, 5)  # type: ignore[arg-type]


def chiffrer(chiffre: int) -> bytes:
    faux = SimpleNamespace(dialect=Dialects.SMB_3_1_1, cipher_id=chiffre)
    session = SimpleNamespace(session_id=7, encryption_key=CLE)
    with mock.patch.object(os, "urandom", lambda n: NONCE[:n]):
        entete = Connection._encrypt(faux, message(), session)  # type: ignore[arg-type]
    return entete.pack()


def main() -> None:
    valeurs = {
        "SIGNING_311": kdf(b"SMBSigningKey\x00", PREAUTH),
        "ENCRYPTION_311": kdf(b"SMBC2SCipherKey\x00", PREAUTH),
        "DECRYPTION_311": kdf(b"SMBS2CCipherKey\x00", PREAUTH),
        "SIGNING_300": kdf(b"SMB2AESCMAC\x00", b"SmbSign\x00"),
        "ENCRYPTION_300": kdf(b"SMB2AESCCM\x00", b"ServerIn \x00"),
        "DECRYPTION_300": kdf(b"SMB2AESCCM\x00", b"ServerOut\x00"),
        "CMAC": signature(SigningAlgorithms.AES_CMAC),
        "GMAC": signature(SigningAlgorithms.AES_GMAC),
        # SMB 2.1 : HMAC-SHA256 avec la clé de session telle quelle (ADR 0021).
        "HMAC": signature(SigningAlgorithms.HMAC_SHA256, Dialects.SMB_2_1_0),
        "GCM": chiffrer(Ciphers.AES_128_GCM),
        "CCM": chiffrer(Ciphers.AES_128_CCM),
        "PREAUTH": hashlib.sha512(b"\x00" * 64 + b"negotiate").digest(),
    }
    sortie = sys.stdout
    sortie.write("// SPDX-License-Identifier: GPL-3.0-or-later\n")
    sortie.write("// SPDX-FileCopyrightText: 2026 René Onier\n\n")
    version = getattr(smbprotocol, "__version__", "1.17.0")
    sortie.write(f"// Written by rust/vecteurs_smb.py with smbprotocol {version}: do not edit.\n\n")
    for nom, valeur in valeurs.items():
        sortie.write(f'const {nom}: &str = "{valeur.hex()}";\n')


if __name__ == "__main__":
    main()

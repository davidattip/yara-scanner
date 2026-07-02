"""
Calcul d'empreintes cryptographiques de fichiers.

Le SHA-256 est l'identifiant standard d'un échantillon en analyse de
malware : il permet de désigner un fichier sans ambiguïté, de corréler
avec des bases externes (VirusTotal, MalwareBazaar…) et de prouver
qu'un rapport porte bien sur tel contenu exact.

⚠️ Lecture strictement statique : on lit le fichier par blocs pour
calculer son empreinte, jamais pour l'exécuter.
"""

from __future__ import annotations

import hashlib

# Taille des blocs de lecture (64 Kio) : évite de charger en mémoire
# l'intégralité d'un gros fichier.
_CHUNK_SIZE = 64 * 1024


def sha256_file(filepath: str) -> str | None:
    """
    Calcule le SHA-256 d'un fichier, en hexadécimal.

    Returns:
        L'empreinte hexadécimale, ou None si le fichier est illisible
        (le rapport reste généré, simplement sans hash pour ce fichier).
    """
    digest = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()

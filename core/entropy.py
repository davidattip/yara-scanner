"""
Détection avancée par entropie de Shannon (analyse statistique).

Complément aux règles YARA : au lieu de chercher des motifs connus, on
mesure le "désordre" des longues chaînes du fichier. Les charges utiles
encodées (base64), chiffrées ou compressées présentent une entropie
élevée, proche de l'aléatoire — un signal d'obfuscation même quand
aucune règle YARA ne matche.

Rappel : entropie de Shannon d'une chaîne, en bits par caractère
    H = - Σ p(c) * log2( p(c) )
où p(c) est la fréquence du caractère c. Plus H est haut, plus la
chaîne est "aléatoire" (base64 ≈ 5–6, texte/code courant ≈ 3–4).

⚠️ Analyse strictement statique : on ne fait que LIRE et mesurer,
jamais décoder ni exécuter le contenu.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter

# Longueur minimale d'une chaîne candidate (en caractères). En dessous,
# l'entropie n'est pas significative et on risque des faux positifs.
MIN_TOKEN_LEN = 40

# Seuil d'entropie (bits/caractère) au-delà duquel une longue chaîne
# est jugée suspecte. Calibré au-dessus de l'entropie du code courant
# (~4.1) pour ne pas générer de faux positifs.
ENTROPY_THRESHOLD = 4.3

# Seuils d'aggravation : au-delà, la détection passe de MEDIUM à HIGH.
HIGH_ENTROPY = 4.8
HIGH_LENGTH = 200

# Limite de taille pour éviter de charger des fichiers énormes en mémoire.
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 Mo

# Chaînes candidates : longues suites de caractères typiques d'un encodage
# (base64, hexadécimal, jetons…). On capture leur position pour le rapport.
_TOKEN_RE = re.compile(rf"[A-Za-z0-9+/=_-]{{{MIN_TOKEN_LEN},}}")

# Nom de "fichier de règle" affiché pour ces détections statistiques.
ENTROPY_SOURCE = "entropy (analyse statistique)"


def shannon_entropy(data: str) -> float:
    """Calcule l'entropie de Shannon (bits/caractère) d'une chaîne."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def _read_text(filepath: str) -> str | None:
    """Lit un fichier en texte, ou None s'il est trop gros / illisible."""
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return None
        with open(filepath, "rb") as f:
            raw = f.read()
    except OSError:
        return None
    return raw.decode("utf-8", errors="replace")


def analyze_file(filepath: str) -> list[dict]:
    """
    Analyse un fichier et renvoie les détections d'entropie élevée.

    Le format des détections est identique à celui du moteur YARA, afin
    que scoring, rapports et affichage les traitent de façon uniforme.
    """
    text = _read_text(filepath)
    if text is None:
        return []

    detections: list[dict] = []
    for match in _TOKEN_RE.finditer(text):
        token = match.group(0)
        entropy = shannon_entropy(token)
        if entropy < ENTROPY_THRESHOLD:
            continue

        severity = (
            "HIGH"
            if entropy >= HIGH_ENTROPY or len(token) >= HIGH_LENGTH
            else "MEDIUM"
        )
        detections.append({
            "rule_name": "High_Entropy_String",
            "rule_file": ENTROPY_SOURCE,
            "severity": severity,
            "category": "obfuscation",
            "description": (
                f"Chaîne à forte entropie ({entropy:.2f} bits/car, "
                f"{len(token)} caractères) — possible contenu encodé/chiffré."
            ),
            "matched_strings": [{
                "offset": match.start(),
                "identifier": "$high_entropy",
                "data": token[:80],
            }],
        })

    return detections

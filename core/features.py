"""
Extraction de caractéristiques statiques pour le module ML comportemental.

Ce module transforme le *texte* d'un script en un vecteur de nombres
(features) que le classifieur scikit-learn pourra apprendre. Il ne dépend
PAS de scikit-learn : il est donc utilisable et testable même sans le
module ML installé.

⚠️ Strictement statique : on ne fait que LIRE et mesurer le contenu.
Aucune feature ne nécessite d'exécuter le script analysé.
"""

from __future__ import annotations

import math
import re
from collections import Counter

# Longueur minimale d'un « token » candidat à l'analyse d'entropie.
_MIN_TOKEN_LEN = 20
_TOKEN_RE = re.compile(rf"[A-Za-z0-9+/=_-]{{{_MIN_TOKEN_LEN},}}")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{60,}={0,2}")

# Seuil d'entropie au-delà duquel un token est jugé « désordonné ».
_HIGH_ENTROPY = 4.3

# Mots-clés fréquemment associés à du code offensif (toutes plateformes).
# La casse est ignorée à l'extraction.
_SUSPICIOUS_KEYWORDS = (
    "eval", "exec", "compile", "marshal", "base64", "b64decode", "b64encode",
    "socket", "subprocess", "popen", "os.system", "connect", "recv", "send",
    "/dev/tcp", "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "invoke-expression", "iex", "downloadstring", "webclient", "tcpclient",
    "fromhex", "decode", "decompress", "chr(", "ord(", "xor", "^",
    "crontab", "winreg", "setvalueex", "currentversion\\run", "vssadmin",
    "encrypt", "decrypt", "fernet", "ransom", "bitcoin", "wallet",
    "stratum", "xmrig", "pynput", "keyboard", "urlopen", "requests.post",
)

# Imports qui, isolément, méritent l'attention du modèle.
_DANGEROUS_IMPORTS = (
    "import socket", "import subprocess", "import base64", "import ctypes",
    "import marshal", "import winreg", "from pynput", "import requests",
    "import hashlib", "import multiprocessing", "from cryptography",
)

# Ordre stable des features : le vecteur produit suit toujours cet ordre.
FEATURE_NAMES = [
    "file_length",
    "line_count",
    "avg_line_length",
    "max_line_length",
    "global_entropy",
    "max_token_entropy",
    "high_entropy_token_count",
    "long_base64_count",
    "suspicious_keyword_count",
    "suspicious_keyword_density",
    "dangerous_import_count",
    "non_ascii_ratio",
    "special_char_ratio",
]


def shannon_entropy(data: str) -> float:
    """Entropie de Shannon (bits/caractère) d'une chaîne."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def extract_features(text: str) -> list[float]:
    """Transforme le texte d'un script en vecteur de features (voir FEATURE_NAMES)."""
    length = len(text)
    lines = text.splitlines() or [""]
    line_lengths = [len(line) for line in lines]
    lower = text.lower()

    # --- Entropie ---
    global_entropy = shannon_entropy(text)
    tokens = _TOKEN_RE.findall(text)
    token_entropies = [shannon_entropy(tok) for tok in tokens]
    max_token_entropy = max(token_entropies, default=0.0)
    high_entropy_tokens = sum(1 for e in token_entropies if e >= _HIGH_ENTROPY)
    long_b64 = len(_B64_RE.findall(text))

    # --- Mots-clés / imports suspects ---
    keyword_hits = sum(lower.count(kw) for kw in _SUSPICIOUS_KEYWORDS)
    keyword_density = keyword_hits / (length / 1000) if length else 0.0
    import_hits = sum(1 for imp in _DANGEROUS_IMPORTS if imp in lower)

    # --- Composition des caractères ---
    non_ascii = sum(1 for c in text if ord(c) > 127)
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    non_ascii_ratio = non_ascii / length if length else 0.0
    special_ratio = special / length if length else 0.0

    return [
        float(length),
        float(len(lines)),
        sum(line_lengths) / len(lines),
        float(max(line_lengths)),
        global_entropy,
        max_token_entropy,
        float(high_entropy_tokens),
        float(long_b64),
        float(keyword_hits),
        keyword_density,
        float(import_hits),
        non_ascii_ratio,
        special_ratio,
    ]


def read_text(filepath: str) -> str:
    """Lit un fichier en texte de façon tolérante (jamais d'exécution)."""
    with open(filepath, "rb") as f:
        return f.read().decode("utf-8", errors="replace")


def extract_features_from_file(filepath: str) -> list[float]:
    """Extrait le vecteur de features directement depuis un fichier."""
    return extract_features(read_text(filepath))

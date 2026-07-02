"""
Tests du module ML comportemental (core/ml.py).

Ces tests sont ignorés (skip) si scikit-learn n'est pas installé : le
module ML est une dépendance optionnelle, la CLI de base doit fonctionner
sans lui.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# Ignore tout le fichier si scikit-learn/joblib manquent.
pytest.importorskip("sklearn")
pytest.importorskip("joblib")

from core.ml import (  # noqa: E402
    load_model,
    ml_verdict,
    predict_proba,
    save_model,
    train_model,
)

CLEAN_DIR = Path(__file__).parent.parent / "test_samples" / "clean"
MALICIOUS_DIR = Path(__file__).parent.parent / "test_samples" / "malicious"


def _load_dataset() -> tuple[list[str], list[int]]:
    texts, labels = [], []
    for path in sorted(CLEAN_DIR.iterdir()):
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
            labels.append(0)
    for path in sorted(MALICIOUS_DIR.iterdir()):
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
            labels.append(1)
    return texts, labels


@pytest.fixture(scope="module")
def trained_model():
    texts, labels = _load_dataset()
    return train_model(texts, labels)


def test_ml_verdict_threshold() -> None:
    assert ml_verdict(0.9) == "SUSPECT (ML)"
    assert ml_verdict(0.1) == "PROPRE (ML)"


def test_malicious_scored_higher_than_clean(trained_model) -> None:
    clean = (CLEAN_DIR / "01_calculatrice.py").read_text(encoding="utf-8")
    mal = (MALICIOUS_DIR / "02_reverse_shell.py").read_text(encoding="utf-8")
    assert predict_proba(trained_model, mal) > predict_proba(trained_model, clean)


def test_save_and_load_roundtrip(tmp_path, trained_model) -> None:
    path = tmp_path / "model.joblib"
    save_model(trained_model, str(path))
    reloaded = load_model(str(path))

    sample = (MALICIOUS_DIR / "02_reverse_shell.py").read_text(encoding="utf-8")
    # Le modèle rechargé produit exactement la même prédiction.
    assert predict_proba(reloaded, sample) == predict_proba(trained_model, sample)

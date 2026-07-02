#!/usr/bin/env python3
"""
Entraînement du module ML comportemental (bonus).

Apprend un classifieur à distinguer les scripts bénins des scripts
malveillants à partir du dataset `test_samples/` :
  - test_samples/clean/     -> label 0 (bénin)
  - test_samples/malicious/ -> label 1 (malveillant)

Le modèle entraîné est sérialisé dans models/ pour être réutilisé par
`scanner.py --ml`.

Usage :
    pip install scikit-learn joblib
    python train_ml.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Console Windows (cp1252) : force l'UTF-8 pour les caractères Unicode.
for _stream in (sys.stdout, sys.stderr):
    _reconfigure = getattr(_stream, "reconfigure", None)
    if _reconfigure is not None:
        try:
            _reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):
            pass

from core.config import SUPPORTED_EXTENSIONS
from core.features import extract_features, read_text
from core.ml import MLUnavailableError, MODEL_PATH, save_model, train_model

PROJECT_ROOT = Path(__file__).parent
CLEAN_DIR = PROJECT_ROOT / "test_samples" / "clean"
MALICIOUS_DIR = PROJECT_ROOT / "test_samples" / "malicious"


def _collect(directory: Path, label: int) -> tuple[list[str], list[int]]:
    """Lit tous les scripts supportés d'un dossier et leur attribue un label."""
    texts, labels = [], []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.suffix.lower() in SUPPORTED_EXTENSIONS:
            texts.append(read_text(str(path)))
            labels.append(label)
    return texts, labels


def main() -> None:
    clean_texts, clean_labels = _collect(CLEAN_DIR, 0)
    mal_texts, mal_labels = _collect(MALICIOUS_DIR, 1)

    texts = clean_texts + mal_texts
    labels = clean_labels + mal_labels

    if not texts:
        print("[ERREUR] Aucun échantillon trouvé dans test_samples/.")
        sys.exit(1)

    print(f"  Échantillons : {len(clean_texts)} bénins, {len(mal_texts)} malveillants")

    # --- Évaluation par validation croisée (avant l'entraînement final) ---
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score

        features = [extract_features(t) for t in texts]
        n_splits = min(5, len(clean_texts), len(mal_texts))
        if n_splits >= 2:
            model_cv = RandomForestClassifier(
                n_estimators=200, max_depth=6, random_state=42,
                class_weight="balanced",
            )
            scores = cross_val_score(model_cv, features, labels, cv=n_splits)
            print(
                f"  Validation croisée ({n_splits} plis) : "
                f"exactitude moyenne {scores.mean():.2%} "
                f"(± {scores.std():.2%})"
            )
    except MLUnavailableError as exc:
        print(f"\n[ERREUR] {exc}")
        sys.exit(1)

    # --- Entraînement final sur tout le dataset + sérialisation ---
    model = train_model(texts, labels)
    path = save_model(model, MODEL_PATH)
    print(f"  ✓ Modèle entraîné et sauvegardé : {path}")


if __name__ == "__main__":
    main()

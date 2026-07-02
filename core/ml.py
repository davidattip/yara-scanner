"""
Module ML comportemental (bonus) — détection statistique complémentaire.

Idée : là où YARA cherche des motifs *connus*, le modèle apprend à
distinguer « bénin » de « malveillant » à partir de caractéristiques
statiques globales (entropie, densité de mots-clés, longueur des lignes…).
Il peut ainsi lever un doute sur un script qu'aucune règle ne matche.

⚠️ Dépendance OPTIONNELLE. scikit-learn est importé de façon isolée : si le
paquet n'est pas installé, le reste de l'outil (CLI, YARA, entropie)
continue de fonctionner normalement. Les fonctions de ce module lèvent
alors une `MLUnavailableError` explicite.

⚠️ Strictement statique : le modèle ne consomme que des features mesurées
par lecture (voir core/features.py). Aucun script n'est jamais exécuté.
"""

from __future__ import annotations

import os

from core.features import FEATURE_NAMES, extract_features, read_text

# Chemin par défaut du modèle entraîné et sérialisé.
_MODELS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models"
)
MODEL_PATH = os.path.join(_MODELS_DIR, "behavioral_model.joblib")

# Seuil de probabilité au-delà duquel le modèle considère un fichier suspect.
ML_THRESHOLD = 0.5


class MLUnavailableError(RuntimeError):
    """Levée quand scikit-learn (ou le modèle entraîné) n'est pas disponible."""


# --- Import isolé de scikit-learn ------------------------------------------
try:
    import joblib
    from sklearn.ensemble import RandomForestClassifier

    SKLEARN_AVAILABLE = True
except ImportError:  # pragma: no cover - dépend de l'environnement
    SKLEARN_AVAILABLE = False


def _require_sklearn() -> None:
    if not SKLEARN_AVAILABLE:
        raise MLUnavailableError(
            "Le module ML nécessite scikit-learn et joblib.\n"
            "         Installe-les avec : pip install scikit-learn joblib"
        )


def train_model(
    texts: list[str], labels: list[int]
) -> "RandomForestClassifier":
    """Entraîne un classifieur sur des textes étiquetés (0 = bénin, 1 = malveillant).

    Returns:
        Le modèle scikit-learn entraîné.
    """
    _require_sklearn()
    features = [extract_features(t) for t in texts]
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=6,
        random_state=42,
        class_weight="balanced",
    )
    model.fit(features, labels)
    return model


def save_model(model, path: str = MODEL_PATH) -> str:
    """Sérialise le modèle sur le disque et renvoie son chemin."""
    _require_sklearn()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)
    return path


def load_model(path: str = MODEL_PATH):
    """Charge un modèle sérialisé.

    Raises:
        MLUnavailableError: si scikit-learn manque ou si le modèle est absent.
    """
    _require_sklearn()
    if not os.path.exists(path):
        raise MLUnavailableError(
            f"Modèle introuvable : {path}\n"
            "         Entraîne-le d'abord avec : python train_ml.py"
        )
    return joblib.load(path)


def predict_proba(model, text: str) -> float:
    """Probabilité (0.0–1.0) que le texte soit malveillant, selon le modèle."""
    _require_sklearn()
    features = [extract_features(text)]
    # Colonne de la classe positive (label 1 = malveillant).
    return float(model.predict_proba(features)[0][1])


def ml_verdict(proba: float) -> str:
    """Traduit une probabilité en verdict lisible."""
    return "SUSPECT (ML)" if proba >= ML_THRESHOLD else "PROPRE (ML)"


def analyze_files(paths: list[str], path: str = MODEL_PATH) -> list[dict]:
    """Prédit un score comportemental pour chaque fichier.

    Returns:
        Une liste de dicts {file, proba, verdict}, triée par probabilité
        décroissante. Charge le modèle une seule fois.
    """
    model = load_model(path)
    results = []
    for filepath in paths:
        try:
            proba = predict_proba(model, read_text(filepath))
        except OSError:
            continue
        results.append({
            "file": filepath,
            "proba": proba,
            "verdict": ml_verdict(proba),
        })
    results.sort(key=lambda r: r["proba"], reverse=True)
    return results

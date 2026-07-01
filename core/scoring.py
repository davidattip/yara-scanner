"""
Calcul du score de risque et du verdict par fichier.

Deux indicateurs complémentaires sont produits :

  1. le score BRUT (cumulé, non borné) — somme pondérée par sévérité.
     Il reflète la *quantité de preuves* : plus un fichier cumule de
     règles graves, plus il monte. C'est lui qui détermine le verdict.

  2. le score de RISQUE /100 (borné) — le score brut ramené sur une
     échelle 0–100 avec plafonnement. Indicateur lisible, pratique pour
     une barre de progression ou une lecture rapide.

    score_brut = 10*CRITICAL + 5*HIGH + 2*MEDIUM + 1*LOW
    risque     = min(100, round(score_brut / RISK_CEILING * 100))

Verdict (calculé sur le score brut) :

    score >= 10  -> MALVEILLANT
    score >=  3  -> SUSPECT
    score >=  1  -> À VÉRIFIER   (une détection faible : jamais "propre")
    score == 0   -> PROPRE

Le palier "À VÉRIFIER" évite l'incohérence d'un fichier qui déclenche
une règle mais serait affiché "PROPRE".
"""

from __future__ import annotations

from typing import NamedTuple

# Points attribués à chaque niveau de sévérité.
# INFO = 0 : les erreurs de scan (severity INFO) ne gonflent pas le score.
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# Score brut à partir duquel le risque est considéré comme maximal (100/100).
# 20 = deux règles CRITICAL (ou combinaison équivalente). Au-delà, on plafonne.
RISK_CEILING = 20

# Seuils de verdict (score brut minimal pour chaque niveau).
VERDICT_MALICIOUS = 10
VERDICT_SUSPECT = 3
VERDICT_REVIEW = 1

# Étiquettes de verdict (constantes réutilisables).
MALICIOUS = "MALVEILLANT"
SUSPECT = "SUSPECT"
REVIEW = "À VÉRIFIER"
CLEAN = "PROPRE"


class Assessment(NamedTuple):
    """Évaluation d'un fichier : score brut, risque /100, verdict."""

    score: int      # score brut cumulé (non borné)
    risk: int       # score de risque normalisé sur 0–100
    verdict: str    # verdict lisible dérivé du score brut


def compute_score(matches: list[dict]) -> int:
    """Calcule le score brut (cumulé) à partir des détections d'un fichier."""
    return sum(
        SEVERITY_WEIGHTS.get(m.get("severity", "INFO"), 0)
        for m in matches
    )


def normalize_score(score: int) -> int:
    """Ramène un score brut sur une échelle 0–100 (avec plafonnement)."""
    return min(100, round(score / RISK_CEILING * 100))


def verdict_from_score(score: int) -> str:
    """Traduit un score brut en verdict lisible."""
    if score >= VERDICT_MALICIOUS:
        return MALICIOUS
    if score >= VERDICT_SUSPECT:
        return SUSPECT
    if score >= VERDICT_REVIEW:
        return REVIEW
    return CLEAN


def assess_file(matches: list[dict]) -> Assessment:
    """Renvoie l'évaluation complète (score, risque, verdict) d'un fichier."""
    score = compute_score(matches)
    return Assessment(
        score=score,
        risk=normalize_score(score),
        verdict=verdict_from_score(score),
    )

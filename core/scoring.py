"""
Calcul du score de risque et du verdict par fichier.

Approche : somme pondérée par sévérité. Chaque détection ajoute un
nombre de points fixé par sa sévérité ; le total détermine un verdict.
Transparent et facile à justifier (choix assumé pour la soutenance).

    score = 10*CRITICAL + 5*HIGH + 2*MEDIUM + 1*LOW

    score >= 10  -> MALVEILLANT
    score >=  3  -> SUSPECT
    score >=  1  -> À VÉRIFIER   (une détection faible : jamais "propre")
    score == 0   -> PROPRE

Le palier "À VÉRIFIER" évite l'incohérence d'un fichier qui déclenche
une règle mais serait affiché "PROPRE".
"""

from __future__ import annotations

# Points attribués à chaque niveau de sévérité.
# INFO = 0 : les erreurs de scan (severity INFO) ne gonflent pas le score.
SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 5,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}

# Seuils de verdict (score minimal pour chaque niveau).
VERDICT_MALICIOUS = 10
VERDICT_SUSPECT = 3
VERDICT_REVIEW = 1

# Étiquettes de verdict (constantes réutilisables).
MALICIOUS = "MALVEILLANT"
SUSPECT = "SUSPECT"
REVIEW = "À VÉRIFIER"
CLEAN = "PROPRE"


def compute_score(matches: list[dict]) -> int:
    """Calcule le score de risque d'un fichier à partir de ses détections."""
    return sum(
        SEVERITY_WEIGHTS.get(m.get("severity", "INFO"), 0)
        for m in matches
    )


def verdict_from_score(score: int) -> str:
    """Traduit un score numérique en verdict lisible."""
    if score >= VERDICT_MALICIOUS:
        return MALICIOUS
    if score >= VERDICT_SUSPECT:
        return SUSPECT
    if score >= VERDICT_REVIEW:
        return REVIEW
    return CLEAN


def assess_file(matches: list[dict]) -> tuple[int, str]:
    """Renvoie (score, verdict) pour la liste de détections d'un fichier."""
    score = compute_score(matches)
    return score, verdict_from_score(score)

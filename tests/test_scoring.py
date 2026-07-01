"""
Tests unitaires du module de scoring (score de risque + verdict).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scoring import (  # noqa: E402
    CLEAN,
    MALICIOUS,
    REVIEW,
    SUSPECT,
    assess_file,
    compute_score,
    normalize_score,
    verdict_from_score,
)


def _det(severity: str) -> dict:
    """Petite fabrique de détection factice pour les tests."""
    return {"severity": severity}


class TestComputeScore:

    def test_empty_is_zero(self) -> None:
        assert compute_score([]) == 0

    def test_weights_sum(self) -> None:
        matches = [_det("CRITICAL"), _det("HIGH"), _det("MEDIUM"), _det("LOW")]
        assert compute_score(matches) == 10 + 5 + 2 + 1

    def test_info_and_unknown_weigh_zero(self) -> None:
        assert compute_score([_det("INFO"), _det("BIDON")]) == 0


class TestVerdictThresholds:

    def test_clean_only_at_zero(self) -> None:
        assert verdict_from_score(0) == CLEAN

    def test_review_for_low_detection(self) -> None:
        # Une détection MEDIUM seule (score 2) ne doit jamais être "PROPRE".
        assert verdict_from_score(2) == REVIEW

    def test_suspect_threshold(self) -> None:
        assert verdict_from_score(3) == SUSPECT
        assert verdict_from_score(9) == SUSPECT

    def test_malicious_threshold(self) -> None:
        assert verdict_from_score(10) == MALICIOUS
        assert verdict_from_score(50) == MALICIOUS


class TestNormalizeScore:

    def test_zero_is_zero(self) -> None:
        assert normalize_score(0) == 0

    def test_ceiling_reaches_100(self) -> None:
        # RISK_CEILING = 20 → deux CRITICAL saturent la barre.
        assert normalize_score(20) == 100

    def test_beyond_ceiling_is_capped(self) -> None:
        assert normalize_score(50) == 100

    def test_single_critical_is_half(self) -> None:
        assert normalize_score(10) == 50


class TestAssessFile:

    def test_returns_score_risk_and_verdict(self) -> None:
        # Deux CRITICAL : score brut 20, risque 100/100, verdict MALVEILLANT.
        assert assess_file([_det("CRITICAL"), _det("CRITICAL")]) == (20, 100, MALICIOUS)

    def test_fields_are_named(self) -> None:
        a = assess_file([_det("CRITICAL")])
        assert a.score == 10
        assert a.risk == 50
        assert a.verdict == MALICIOUS

    def test_medium_only_is_review_not_clean(self) -> None:
        a = assess_file([_det("MEDIUM")])
        assert a.score == 2
        assert a.risk == 10
        assert a.verdict == REVIEW

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


class TestAssessFile:

    def test_returns_score_and_verdict(self) -> None:
        assert assess_file([_det("CRITICAL")]) == (10, MALICIOUS)

    def test_medium_only_is_review_not_clean(self) -> None:
        score, verdict = assess_file([_det("MEDIUM")])
        assert score == 2
        assert verdict == REVIEW

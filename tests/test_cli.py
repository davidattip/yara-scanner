"""
Tests du filtrage par sévérité minimale (option CLI --min-severity).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner import filter_by_severity


def _results() -> dict[str, list[dict]]:
    return {
        "a.py": [
            {"severity": "CRITICAL", "rule_name": "R1"},
            {"severity": "LOW", "rule_name": "R2"},
        ],
        "b.py": [
            {"severity": "MEDIUM", "rule_name": "R3"},
        ],
        "c.py": [
            {"severity": "INFO", "rule_name": "R4"},
        ],
    }


def test_keep_only_critical() -> None:
    filtered = filter_by_severity(_results(), "CRITICAL")
    # Seul a.py garde sa détection CRITICAL ; b.py et c.py disparaissent.
    assert set(filtered) == {"a.py"}
    assert [m["rule_name"] for m in filtered["a.py"]] == ["R1"]


def test_keep_medium_and_above() -> None:
    filtered = filter_by_severity(_results(), "MEDIUM")
    # a.py (CRITICAL) et b.py (MEDIUM) restent ; le LOW de a.py est retiré.
    assert set(filtered) == {"a.py", "b.py"}
    assert [m["rule_name"] for m in filtered["a.py"]] == ["R1"]


def test_info_threshold_keeps_everything() -> None:
    filtered = filter_by_severity(_results(), "INFO")
    assert set(filtered) == {"a.py", "b.py", "c.py"}

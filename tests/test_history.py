"""
Tests de la couche de persistance SQLite (core/history.py).

Chaque test utilise une base temporaire isolée (monkeypatch de DB_PATH).
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import history


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Redirige la base d'historique vers un fichier temporaire."""
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "test_history.db")
    history.init_db()
    return history


def _sample():
    all_results = {
        "evil.py": [
            {"rule_name": "Python_Reverse_Shell", "severity": "CRITICAL",
             "category": "reverse_shell", "description": "x", "matched_strings": []},
        ],
    }
    assessments = {"evil.py": {"score": 10, "risk": 50, "verdict": "MALVEILLANT"}}
    return all_results, assessments


def test_save_and_get(temp_db) -> None:
    all_results, assessments = _sample()
    scan_id = temp_db.save_scan(
        "evil.py", 1, 0.12, all_results, assessments,
        ml_scores={"evil.py": {"proba": 0.9, "verdict": "SUSPECT (ML)"}},
    )
    record = temp_db.get_scan(scan_id)
    assert record["verdict"] == "MALVEILLANT"
    assert record["total_detections"] == 1
    assert record["detail"]["all_results"]["evil.py"][0]["rule_name"] == "Python_Reverse_Shell"
    assert record["detail"]["ml_scores"]["evil.py"]["proba"] == 0.9


def test_list_orders_recent_first(temp_db) -> None:
    all_results, assessments = _sample()
    first = temp_db.save_scan("a.py", 1, 0.1, all_results, assessments)
    second = temp_db.save_scan("b.py", 1, 0.1, all_results, assessments)
    scans = temp_db.list_scans()
    assert [s["id"] for s in scans] == [second, first]


def test_overall_verdict_takes_worst(temp_db) -> None:
    all_results = {
        "a.py": [{"rule_name": "R", "severity": "LOW", "category": "c",
                  "description": "", "matched_strings": []}],
        "b.py": [{"rule_name": "R2", "severity": "CRITICAL", "category": "c",
                  "description": "", "matched_strings": []}],
    }
    assessments = {
        "a.py": {"score": 1, "risk": 5, "verdict": "À VÉRIFIER"},
        "b.py": {"score": 10, "risk": 50, "verdict": "MALVEILLANT"},
    }
    scan_id = temp_db.save_scan("2 fichiers", 2, 0.2, all_results, assessments)
    assert temp_db.get_scan(scan_id)["verdict"] == "MALVEILLANT"


def test_stats_aggregation(temp_db) -> None:
    all_results, assessments = _sample()
    temp_db.save_scan("evil.py", 1, 0.1, all_results, assessments)
    stats = temp_db.stats()
    assert stats["totals"]["scans"] == 1
    assert stats["by_severity"]["CRITICAL"] == 1
    assert stats["by_category"]["reverse_shell"] == 1
    assert stats["top_rules"][0]["rule_name"] == "Python_Reverse_Shell"


def test_delete(temp_db) -> None:
    all_results, assessments = _sample()
    scan_id = temp_db.save_scan("evil.py", 1, 0.1, all_results, assessments)
    temp_db.delete_scan(scan_id)
    assert temp_db.get_scan(scan_id) is None
    assert temp_db.list_scans() == []

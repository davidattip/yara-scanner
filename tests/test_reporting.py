"""
Tests des rapports (JSON / CSV) et du hachage SHA-256.

On vérifie que :
  - le rapport JSON contient bien l'empreinte SHA-256 attendue et le verdict ;
  - le rapport CSV expose la colonne SHA-256 ;
  - le hash calculé correspond au SHA-256 réel du fichier.
"""

import csv
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.hashing import sha256_file
from core.reporting import generate_csv_report, generate_json_report

MALICIOUS_DIR = Path(__file__).parent.parent / "test_samples" / "malicious"


def _reference_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_sha256_file_matches_reference() -> None:
    sample = MALICIOUS_DIR / "02_reverse_shell.py"
    assert sha256_file(str(sample)) == _reference_sha256(sample)


def test_sha256_file_missing_returns_none() -> None:
    assert sha256_file("chemin/inexistant/nope.py") is None


def test_json_report_contains_hash_and_verdict(tmp_path: Path) -> None:
    sample = MALICIOUS_DIR / "02_reverse_shell.py"
    matches = [{
        "rule_name": "Python_Reverse_Shell",
        "rule_file": "reverse_shell.yar",
        "severity": "CRITICAL",
        "category": "reverse_shell",
        "description": "test",
        "matched_strings": [],
    }]
    all_results = {sample.name: matches}

    path = generate_json_report(
        all_results, files_scanned=1,
        output_dir=str(tmp_path), base_dir=str(MALICIOUS_DIR),
    )
    data = json.loads(Path(path).read_text(encoding="utf-8"))

    entry = data["detections"][sample.name]
    assert entry["sha256"] == _reference_sha256(sample)
    assert entry["verdict"] == "MALVEILLANT"  # score 10 (1 x CRITICAL)


def test_csv_report_has_sha256_column(tmp_path: Path) -> None:
    sample = MALICIOUS_DIR / "02_reverse_shell.py"
    matches = [{
        "rule_name": "Python_Reverse_Shell",
        "rule_file": "reverse_shell.yar",
        "severity": "CRITICAL",
        "category": "reverse_shell",
        "description": "test",
        "matched_strings": [],
    }]
    all_results = {sample.name: matches}

    path = generate_csv_report(
        all_results, files_scanned=1,
        output_dir=str(tmp_path), base_dir=str(MALICIOUS_DIR),
    )
    with open(path, newline="", encoding="utf-8") as f:
        rows = list(csv.reader(f))

    assert "SHA-256" in rows[0]
    sha_index = rows[0].index("SHA-256")
    assert rows[1][sha_index] == _reference_sha256(sample)

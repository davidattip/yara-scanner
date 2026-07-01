"""
Tests unitaires du module de détection par entropie.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.entropy import (  # noqa: E402
    ENTROPY_THRESHOLD,
    MIN_TOKEN_LEN,
    analyze_file,
    shannon_entropy,
)

CLEAN_DIR = Path(__file__).parent.parent / "test_samples" / "clean"
MALICIOUS_DIR = Path(__file__).parent.parent / "test_samples" / "malicious"


class TestShannonEntropy:

    def test_empty_string_is_zero(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_repeated_char_is_zero(self) -> None:
        # Aucune incertitude → entropie nulle.
        assert shannon_entropy("aaaaaaaa") == 0.0

    def test_uniform_two_symbols_is_one_bit(self) -> None:
        # Deux symboles équiprobables → 1 bit/caractère.
        assert shannon_entropy("abababab") == 1.0

    def test_random_base64_is_high(self) -> None:
        blob = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gSGVsbG8gV29ybGQnKQ=="
        assert shannon_entropy(blob) > ENTROPY_THRESHOLD


class TestAnalyzeFile:

    def test_clean_files_have_no_entropy_alerts(self) -> None:
        false_positives = {
            f.name: analyze_file(str(f))
            for f in CLEAN_DIR.iterdir()
            if f.is_file() and analyze_file(str(f))
        }
        assert not false_positives, (
            f"Faux positifs d'entropie : {false_positives}"
        )

    def test_entropy_only_sample_is_detected(self) -> None:
        # Échantillon conçu pour échapper à YARA mais pas à l'entropie.
        sample = MALICIOUS_DIR / "10_high_entropy_blob.py"
        if not sample.exists():
            import pytest
            pytest.skip("échantillon 10_high_entropy_blob.py absent")

        detections = analyze_file(str(sample))
        assert detections, "Le blob à forte entropie n'a pas été détecté"
        assert detections[0]["rule_name"] == "High_Entropy_String"

    def test_short_high_entropy_token_is_ignored(self, tmp_path: Path) -> None:
        # Un token court (< MIN_TOKEN_LEN) ne doit pas être flaggé.
        short = "aB3+" * 2  # 8 caractères
        assert len(short) < MIN_TOKEN_LEN
        f = tmp_path / "court.py"
        f.write_text(f'x = "{short}"\n', encoding="utf-8")
        assert analyze_file(str(f)) == []

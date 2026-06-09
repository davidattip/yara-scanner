"""
Tests de non-régression — YARA Static Code Analyzer.

Règles :
  - Aucun fichier de test_samples/clean/ ne doit déclencher d'alerte.
  - Chaque fichier de test_samples/malicious/ doit être détecté.
"""

import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from scanner import YaraScanner

RULES_DIR    = Path(__file__).parent.parent / "rules"
CLEAN_DIR    = Path(__file__).parent.parent / "test_samples" / "clean"
MALICIOUS_DIR = Path(__file__).parent.parent / "test_samples" / "malicious"


@pytest.fixture(scope="module")
def scanner() -> YaraScanner:
    return YaraScanner(rules_dir=str(RULES_DIR))


# ─── Chargement des règles ────────────────────────────────────────────────────

class TestRulesLoading:

    def test_rules_loaded(self, scanner: YaraScanner) -> None:
        assert scanner.total_rules_count > 0, "Aucune règle chargée"

    def test_expected_rule_files_present(self, scanner: YaraScanner) -> None:
        expected = {
            "dangerous_imports.yar",
            "encoding_tricks.yar",
            "obfuscation.yar",
            "reverse_shell.yar",
        }
        missing = expected - set(scanner.rule_files)
        assert not missing, f"Fichiers de règles manquants : {missing}"


# ─── Fichiers propres — zéro faux positif ────────────────────────────────────

class TestCleanFiles:

    def test_no_false_positives(self, scanner: YaraScanner) -> None:
        clean_files = [f for f in CLEAN_DIR.iterdir() if f.is_file()]
        assert clean_files, "Aucun fichier clean trouvé"

        false_positives: dict[str, list[str]] = {}
        for filepath in clean_files:
            matches = scanner.scan_file(filepath)
            if matches:
                false_positives[filepath.name] = [m["rule_name"] for m in matches]

        assert not false_positives, (
            "Faux positifs détectés :\n"
            + "\n".join(f"  {f}: {r}" for f, r in false_positives.items())
        )


# ─── Fichiers malveillants — 100 % détectés ──────────────────────────────────

class TestMaliciousFiles:

    def test_all_malicious_detected(self, scanner: YaraScanner) -> None:
        malicious_files = [f for f in MALICIOUS_DIR.iterdir() if f.is_file()]
        assert malicious_files, "Aucun fichier malveillant trouvé"

        missed = [f.name for f in malicious_files if not scanner.scan_file(f)]
        assert not missed, f"Fichiers malveillants non détectés : {missed}"

    @pytest.mark.parametrize("filename,expected_rule", [
        ("02_reverse_shell.py",      "Python_Reverse_Shell"),
        ("06_bash_reverse_shell.sh", "Bash_Reverse_Shell"),
        ("03_chr_obfuscation.py",    "Chr_Obfuscation"),
        ("01_obfuscated_payload.py", None),
        ("05_encoded_dropper.py",    None),
    ])
    def test_specific_rules_triggered(
        self,
        scanner: YaraScanner,
        filename: str,
        expected_rule: str | None,
    ) -> None:
        filepath = MALICIOUS_DIR / filename
        if not filepath.exists():
            pytest.skip(f"{filename} introuvable")

        matches = scanner.scan_file(filepath)
        assert matches, f"{filename} n'a déclenché aucune règle"

        if expected_rule:
            rule_names = [m["rule_name"] for m in matches]
            assert expected_rule in rule_names, (
                f"{filename} : règle '{expected_rule}' attendue, obtenu : {rule_names}"
            )

    def test_severity_critical_for_reverse_shells(self, scanner: YaraScanner) -> None:
        for filename in ("02_reverse_shell.py", "06_bash_reverse_shell.sh"):
            filepath = MALICIOUS_DIR / filename
            if not filepath.exists():
                continue
            matches = scanner.scan_file(filepath)
            severities = [m["severity"] for m in matches]
            assert "CRITICAL" in severities, (
                f"{filename} : sévérité CRITICAL attendue, obtenu : {severities}"
            )

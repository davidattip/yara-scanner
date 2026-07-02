"""
Tests du chargement de la base de règles YARA.

Vérifie la robustesse face aux cas d'erreur :
  - dossier de règles inexistant  -> FileNotFoundError ;
  - dossier sans fichier .yar      -> ValueError ;
  - fichier .yar syntaxiquement invalide -> avertissement non bloquant.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.rule_loader import load_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def test_load_rules_nominal() -> None:
    loaded = load_rules(str(RULES_DIR))
    assert loaded.total_rules_count > 0
    assert loaded.rule_files


def test_missing_dir_raises() -> None:
    with pytest.raises(FileNotFoundError):
        load_rules("dossier/qui/nexiste/pas")


def test_empty_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        load_rules(str(tmp_path))


def test_invalid_rule_collected_as_warning(tmp_path: Path) -> None:
    # Une règle valide et une règle syntaxiquement cassée dans le même dossier.
    (tmp_path / "ok.yar").write_text(
        'rule Ok { strings: $a = "x" condition: $a }', encoding="utf-8"
    )
    (tmp_path / "casse.yar").write_text(
        "rule Casse { condition: ??? }", encoding="utf-8"
    )

    loaded = load_rules(str(tmp_path))

    # La règle valide est chargée, la cassée est signalée sans tout bloquer.
    assert "ok.yar" in loaded.rule_files
    assert "casse.yar" not in loaded.rule_files
    assert any(name == "casse.yar" for name, _msg in loaded.warnings)

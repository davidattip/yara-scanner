"""
Moteur de scan — classe `YaraScanner`.

Applique les règles YARA compilées à des fichiers ou des dossiers.
Le moteur ne fait AUCUN affichage : il renvoie des structures de données
exploitées ensuite par la couche présentation (CLI, web) ou les tests.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.config import RULES_DIR, SEVERITY_ORDER, SUPPORTED_EXTENSIONS
from core.rule_loader import LoadedRules, load_rules


class YaraScanner:
    """Moteur d'analyse statique basé sur YARA."""

    def __init__(self, rules_dir: str = RULES_DIR) -> None:
        self.rules_dir = rules_dir
        self._loaded: LoadedRules = load_rules(rules_dir)

    # --- Accès aux métadonnées de la base de règles ------------------------

    @property
    def compiled_rules(self) -> list[tuple[str, object]]:
        return self._loaded.compiled_rules

    @property
    def rule_files(self) -> list[str]:
        return self._loaded.rule_files

    @property
    def rules_by_file(self) -> dict[str, list[str]]:
        return self._loaded.rules_by_file

    @property
    def total_rules_count(self) -> int:
        return self._loaded.total_rules_count

    @property
    def load_warnings(self) -> list[tuple[str, str]]:
        """Avertissements de chargement (fichier, message)."""
        return self._loaded.warnings

    # --- Scan ---------------------------------------------------------------

    def scan_file(self, filepath: str | Path) -> list[dict]:
        """
        Scanne un fichier avec toutes les règles YARA chargées.

        Returns:
            Liste de détections triées par sévérité (plus grave en premier).
            Liste vide si aucune règle ne matche.
        """
        results: list[dict] = []
        filepath = str(filepath)

        for rule_file, compiled in self._loaded.compiled_rules:
            try:
                matches = compiled.match(filepath)
            except Exception as exc:  # yara.Error, fichier illisible…
                results.append({
                    "rule_name": "SCAN_ERROR",
                    "rule_file": rule_file,
                    "severity": "INFO",
                    "category": "error",
                    "description": f"Erreur lors du scan : {exc}",
                    "matched_strings": [],
                })
                continue

            for match in matches:
                results.append(self._build_detection(rule_file, match))

        results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        return results

    @staticmethod
    def _build_detection(rule_file: str, match) -> dict:
        """Construit un dict de détection à partir d'un match YARA."""
        meta = match.meta
        matched_strings = []
        for string_match in match.strings:
            for instance in string_match.instances:
                matched_strings.append({
                    "offset": instance.offset,
                    "identifier": string_match.identifier,
                    "data": instance.matched_data.decode(
                        "utf-8", errors="replace"
                    )[:80],
                })

        return {
            "rule_name": match.rule,
            "rule_file": rule_file,
            "severity": meta.get("severity", "MEDIUM"),
            "category": meta.get("category", "unknown"),
            "description": meta.get("description", "Pas de description"),
            "matched_strings": matched_strings,
        }

    def scan_directory(
        self, target_dir: str
    ) -> tuple[dict[str, list[dict]], int, int]:
        """
        Scanne récursivement un dossier.

        Returns:
            (résultats, nb_fichiers_scannés, nb_fichiers_ignorés).
            `résultats` mappe chemin_relatif -> liste de détections.
        """
        all_results: dict[str, list[dict]] = {}
        files_scanned = 0
        files_skipped = 0

        for root, _dirs, files in os.walk(target_dir):
            for filename in files:
                filepath = os.path.join(root, filename)
                ext = os.path.splitext(filename)[1].lower()

                if ext not in SUPPORTED_EXTENSIONS:
                    files_skipped += 1
                    continue

                files_scanned += 1
                matches = self.scan_file(filepath)
                if matches:
                    rel_path = os.path.relpath(filepath, target_dir)
                    all_results[rel_path] = matches

        return all_results, files_scanned, files_skipped

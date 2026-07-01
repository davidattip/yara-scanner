#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          YARA STATIC CODE ANALYZER v1.0                       ║
║          Projet Annuel — David ATTIPOUPOU                     ║
║          M1 Cybersécurité                                     ║
╚══════════════════════════════════════════════════════════════╝

Point d'entrée CLI. Ce fichier est un orchestrateur léger : il ne fait
qu'assembler les briques du package `core` (moteur de scan, rapports,
affichage). Toute la logique métier vit dans `core/`.

Les symboles publics (`YaraScanner`, `generate_json_report`, …) sont
ré-exportés ici pour compatibilité avec le code existant (app.py, tests).
"""

from __future__ import annotations

import argparse
import os
import sys
import time

from core.config import REPORTS_DIR, RULES_DIR, SEVERITY_ORDER, SUPPORTED_EXTENSIONS
from core.display import (
    print_banner,
    print_load_warnings,
    print_report_saved,
    print_results,
    print_rules,
)
from core.engine import YaraScanner
from core.reporting import generate_csv_report, generate_json_report

# Ré-exports pour compatibilité (app.py et tests importent depuis `scanner`).
__all__ = [
    "YaraScanner",
    "generate_json_report",
    "generate_csv_report",
    "RULES_DIR",
    "REPORTS_DIR",
    "SUPPORTED_EXTENSIONS",
    "SEVERITY_ORDER",
]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="YARA Static Code Analyzer — Outil d'analyse statique de scripts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples :
  python scanner.py --scan test_samples/
  python scanner.py --scan script_suspect.py
  python scanner.py --scan test_samples/ --report json
  python scanner.py --scan test_samples/ --report csv
  python scanner.py --list-rules
        """,
    )
    parser.add_argument("--scan", metavar="CIBLE",
                        help="Fichier ou dossier à scanner")
    parser.add_argument("--report", choices=["json", "csv"],
                        help="Générer un rapport (json ou csv)")
    parser.add_argument("--list-rules", action="store_true",
                        help="Afficher toutes les règles YARA chargées")
    parser.add_argument("--no-banner", action="store_true",
                        help="Ne pas afficher la bannière")
    return parser


def main() -> None:
    args = _build_parser().parse_args()

    if not args.no_banner:
        print_banner()

    # --- Initialisation du moteur ---
    try:
        scanner = YaraScanner()
    except (FileNotFoundError, ValueError) as exc:
        print(f"\n  [ERREUR] {exc}")
        sys.exit(1)

    print_load_warnings(scanner.load_warnings)
    print(
        f"  ✓ {scanner.total_rules_count} règles YARA chargées "
        f"depuis {len(scanner.rule_files)} fichiers"
    )

    if args.list_rules:
        print_rules(scanner.rules_by_file, scanner.total_rules_count)
        return

    if not args.scan:
        _build_parser().print_help()
        return

    target = args.scan
    if not os.path.exists(target):
        print(f"\n  [ERREUR] Cible introuvable : {target}")
        sys.exit(1)

    # --- Scan ---
    print(f"\n  🔍 Scan en cours : {target}")
    start_time = time.time()

    if os.path.isfile(target):
        matches = scanner.scan_file(target)
        all_results = {target: matches} if matches else {}
        files_scanned, files_skipped = 1, 0
    else:
        all_results, files_scanned, files_skipped = scanner.scan_directory(target)

    scan_time = time.time() - start_time

    print_results(all_results, files_scanned, files_skipped, scan_time)

    # --- Rapport optionnel ---
    if args.report and all_results:
        if args.report == "json":
            print_report_saved(generate_json_report(all_results, files_scanned))
        elif args.report == "csv":
            print_report_saved(generate_csv_report(all_results, files_scanned))


if __name__ == "__main__":
    main()

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
    print_ml_results,
    print_report_saved,
    print_results,
    print_rules,
)
from core.engine import YaraScanner
from core.reporting import generate_csv_report, generate_json_report

__version__ = "1.0.0"

# Ré-exports pour compatibilité (app.py et tests importent depuis `scanner`).
__all__ = [
    "YaraScanner",
    "generate_json_report",
    "generate_csv_report",
    "filter_by_severity",
    "RULES_DIR",
    "REPORTS_DIR",
    "SUPPORTED_EXTENSIONS",
    "SEVERITY_ORDER",
]


def filter_by_severity(
    all_results: dict[str, list[dict]], min_severity: str
) -> dict[str, list[dict]]:
    """Ne conserve que les détections d'une sévérité >= au seuil demandé.

    L'ordre de gravité est donné par SEVERITY_ORDER (0 = CRITICAL, le plus
    grave). Un fichier qui n'a plus aucune détection après filtrage est retiré
    du résultat.
    """
    threshold = SEVERITY_ORDER.get(min_severity, len(SEVERITY_ORDER))
    filtered: dict[str, list[dict]] = {}
    for filepath, matches in all_results.items():
        kept = [
            m for m in matches
            if SEVERITY_ORDER.get(m["severity"], 99) <= threshold
        ]
        if kept:
            filtered[filepath] = kept
    return filtered


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
    parser.add_argument("--rules", metavar="DOSSIER", default=RULES_DIR,
                        help="Dossier de règles YARA à utiliser "
                             "(défaut : rules/)")
    parser.add_argument("--min-severity",
                        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                        help="N'afficher que les détections d'au moins ce "
                             "niveau de sévérité")
    parser.add_argument("--report", choices=["json", "csv"],
                        help="Générer un rapport (json ou csv)")
    parser.add_argument("--list-rules", action="store_true",
                        help="Afficher toutes les règles YARA chargées")
    parser.add_argument("--no-banner", action="store_true",
                        help="Ne pas afficher la bannière")
    parser.add_argument("--no-entropy", action="store_true",
                        help="Désactiver la détection avancée par entropie")
    parser.add_argument("--ml", action="store_true",
                        help="Activer l'analyse ML comportementale "
                             "(bonus, nécessite scikit-learn + modèle entraîné)")
    parser.add_argument("--version", action="version",
                        version=f"YARA Static Code Analyzer {__version__}")
    return parser


def _collect_supported_files(target: str) -> list[str]:
    """Liste les fichiers d'extension supportée sous une cible (fichier ou dossier)."""
    if os.path.isfile(target):
        return [target]
    collected = []
    for root, _dirs, files in os.walk(target):
        for filename in files:
            if os.path.splitext(filename)[1].lower() in SUPPORTED_EXTENSIONS:
                collected.append(os.path.join(root, filename))
    return collected


def main() -> None:
    args = _build_parser().parse_args()

    if not args.no_banner:
        print_banner()

    # --- Initialisation du moteur ---
    try:
        scanner = YaraScanner(rules_dir=args.rules, use_entropy=not args.no_entropy)
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
        # La clé du résultat est déjà le chemin réel : pas de base à préfixer.
        base_dir = ""
    else:
        all_results, files_scanned, files_skipped = scanner.scan_directory(target)
        # Les clés sont relatives au dossier scanné : on le garde pour le hash.
        base_dir = target

    scan_time = time.time() - start_time

    # Filtrage optionnel par sévérité minimale (réduit le bruit).
    if args.min_severity:
        all_results = filter_by_severity(all_results, args.min_severity)

    print_results(all_results, files_scanned, files_skipped, scan_time)

    # --- Analyse ML comportementale optionnelle (bonus) ---
    if args.ml:
        from core.ml import MLUnavailableError, analyze_files
        try:
            predictions = analyze_files(_collect_supported_files(target))
            print_ml_results(predictions)
        except MLUnavailableError as exc:
            print(f"\n  [ML indisponible] {exc}")

    # --- Rapport optionnel ---
    if args.report and all_results:
        if args.report == "json":
            print_report_saved(
                generate_json_report(all_results, files_scanned, base_dir=base_dir)
            )
        elif args.report == "csv":
            print_report_saved(
                generate_csv_report(all_results, files_scanned, base_dir=base_dir)
            )

    # --- Code de sortie ---
    # Sortie 1 si au moins une menace est détectée : permet d'utiliser le
    # scanner dans un pipeline CI/CD (le job échoue si un fichier est suspect).
    if all_results:
        sys.exit(1)


if __name__ == "__main__":
    main()

"""
Package `core` — cœur de l'analyseur statique YARA.

Découpage en modules (architecture cible du projet) :
  - config      : constantes et chemins.
  - rule_loader : chargement et compilation des règles YARA.
  - engine      : moteur de scan (classe YaraScanner).
  - reporting   : génération des rapports JSON / CSV.
  - display     : affichage terminal (bannière, couleurs, résultats).

Le fichier `scanner.py` à la racine reste un orchestrateur CLI léger
qui assemble ces briques.
"""

from core.config import (
    REPORTS_DIR,
    RULES_DIR,
    SEVERITY_ORDER,
    SUPPORTED_EXTENSIONS,
)
from core.engine import YaraScanner
from core.reporting import generate_csv_report, generate_json_report
from core.scoring import assess_file, compute_score, verdict_from_score

__all__ = [
    "YaraScanner",
    "generate_json_report",
    "generate_csv_report",
    "assess_file",
    "compute_score",
    "verdict_from_score",
    "RULES_DIR",
    "REPORTS_DIR",
    "SUPPORTED_EXTENSIONS",
    "SEVERITY_ORDER",
]

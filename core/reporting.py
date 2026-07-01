"""
Génération de rapports de scan (JSON et CSV).

Ces fonctions n'affichent rien à l'écran : elles écrivent un fichier
et renvoient son chemin. La couche présentation se charge d'informer
l'utilisateur.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime

from core.config import REPORTS_DIR
from core.scoring import assess_file


def _file_entry(matches: list[dict]) -> dict:
    """Construit l'entrée d'un fichier (score, risque, verdict, détections)."""
    assessment = assess_file(matches)
    return {
        "score": assessment.score,
        "risk": assessment.risk,
        "verdict": assessment.verdict,
        "matches": [
            {
                "rule": m["rule_name"],
                "severity": m["severity"],
                "category": m["category"],
                "description": m["description"],
                "matched_strings": [
                    {
                        "offset": s["offset"],
                        "identifier": s["identifier"],
                        "data": s["data"],
                    }
                    for s in m["matched_strings"]
                ],
            }
            for m in matches
        ],
    }


def generate_json_report(
    all_results: dict[str, list[dict]],
    files_scanned: int,
    output_dir: str = REPORTS_DIR,
) -> str:
    """Génère un rapport au format JSON et renvoie son chemin."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"scan_report_{timestamp}.json")

    report = {
        "scan_info": {
            "date": datetime.now().isoformat(),
            "tool": "YARA Static Code Analyzer v1.0",
            "author": "David ATTIPOUPOU",
            "files_scanned": files_scanned,
            "total_detections": sum(len(m) for m in all_results.values()),
        },
        "detections": {
            filepath: _file_entry(matches)
            for filepath, matches in all_results.items()
        },
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path


def generate_csv_report(
    all_results: dict[str, list[dict]],
    files_scanned: int,
    output_dir: str = REPORTS_DIR,
) -> str:
    """Génère un rapport au format CSV et renvoie son chemin."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = os.path.join(output_dir, f"scan_report_{timestamp}.csv")

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            ["Fichier", "Score", "Risque/100", "Verdict", "Règle", "Sévérité",
             "Catégorie", "Description", "Strings Matchées"]
        )
        for filepath, matches in all_results.items():
            assessment = assess_file(matches)
            for m in matches:
                strings_str = " | ".join(
                    f"{s['identifier']}={s['data'][:40]}"
                    for s in m["matched_strings"][:5]
                )
                writer.writerow([
                    filepath, assessment.score, assessment.risk,
                    assessment.verdict, m["rule_name"], m["severity"],
                    m["category"], m["description"], strings_str,
                ])

    return output_path

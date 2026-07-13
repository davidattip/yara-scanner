"""
Persistance de l'historique des scans (SQLite).

L'interface web garde en mémoire le dernier scan uniquement ; ce module
ajoute une vraie couche de données pour conserver l'historique entre les
sessions et alimenter le tableau de bord statistique.

Deux tables :
  - `scans`      : une ligne de synthèse par scan (date, cible, verdict…),
                   plus le détail complet sérialisé en JSON (pour rejouer
                   l'affichage des résultats).
  - `detections` : une ligne par détection, pour les agrégations rapides
                   du tableau de bord (par sévérité, catégorie, règle).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path

from core.config import DATA_DIR

# Chemin issu de la config centrale : en exécutable PyInstaller, la base vit
# à côté de l'exe (et non dans le dossier temporaire, effacé à la fermeture).
DB_PATH = Path(DATA_DIR) / "history.db"

# Rang des verdicts pour déterminer le pire d'un lot (0 = plus grave).
_VERDICT_RANK = {
    "MALVEILLANT": 0,
    "SUSPECT": 1,
    "À VÉRIFIER": 2,
    "PROPRE": 3,
}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,
    target          TEXT    NOT NULL,
    files_scanned   INTEGER NOT NULL,
    total_detections INTEGER NOT NULL,
    verdict         TEXT    NOT NULL,
    score           INTEGER NOT NULL,
    scan_time       REAL    NOT NULL,
    results_json    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS detections (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    filepath  TEXT    NOT NULL,
    rule_name TEXT    NOT NULL,
    severity  TEXT    NOT NULL,
    category  TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_det_scan ON detections(scan_id);
"""


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    """Crée les tables si elles n'existent pas encore."""
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _overall_verdict(assessments: dict[str, dict]) -> tuple[str, int]:
    """Verdict le plus grave et score cumulé d'un lot de fichiers."""
    if not assessments:
        return "PROPRE", 0
    worst = min(
        (a["verdict"] for a in assessments.values()),
        key=lambda v: _VERDICT_RANK.get(v, 99),
    )
    total_score = sum(a["score"] for a in assessments.values())
    return worst, total_score


def save_scan(
    target: str,
    files_scanned: int,
    scan_time: float,
    all_results: dict[str, list[dict]],
    assessments: dict[str, dict],
    ml_scores: dict[str, dict] | None = None,
) -> int:
    """Enregistre un scan et renvoie son identifiant."""
    init_db()
    total_detections = sum(len(m) for m in all_results.values())
    verdict, score = _overall_verdict(assessments)

    payload = json.dumps({
        "all_results": all_results,
        "assessments": assessments,
        "ml_scores": ml_scores or {},
    }, ensure_ascii=False)

    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO scans (ts, target, files_scanned, total_detections, "
            "verdict, score, scan_time, results_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (datetime.now().isoformat(timespec="seconds"), target,
             files_scanned, total_detections, verdict, score,
             scan_time, payload),
        )
        scan_id = int(cur.lastrowid)
        for filepath, matches in all_results.items():
            for m in matches:
                conn.execute(
                    "INSERT INTO detections (scan_id, filepath, rule_name, "
                    "severity, category) VALUES (?, ?, ?, ?, ?)",
                    (scan_id, filepath, m["rule_name"],
                     m["severity"], m["category"]),
                )
    return scan_id


def list_scans(limit: int = 100) -> list[dict]:
    """Renvoie la synthèse des scans, du plus récent au plus ancien."""
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, ts, target, files_scanned, total_detections, "
            "verdict, score, scan_time FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    """Renvoie un scan complet (synthèse + détail désérialisé), ou None."""
    init_db()
    with _connect() as conn:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["detail"] = json.loads(record.pop("results_json"))
    return record


def delete_scan(scan_id: int) -> None:
    """Supprime un scan et ses détections."""
    init_db()
    with _connect() as conn:
        conn.execute("DELETE FROM detections WHERE scan_id = ?", (scan_id,))
        conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))


def stats() -> dict:
    """Agrège les données de tous les scans pour le tableau de bord."""
    init_db()
    with _connect() as conn:
        totals = conn.execute(
            "SELECT COUNT(*) AS scans, "
            "COALESCE(SUM(files_scanned), 0) AS files, "
            "COALESCE(SUM(total_detections), 0) AS detections "
            "FROM scans"
        ).fetchone()

        by_severity = conn.execute(
            "SELECT severity, COUNT(*) AS n FROM detections "
            "GROUP BY severity"
        ).fetchall()

        by_category = conn.execute(
            "SELECT category, COUNT(*) AS n FROM detections "
            "GROUP BY category ORDER BY n DESC"
        ).fetchall()

        top_rules = conn.execute(
            "SELECT rule_name, COUNT(*) AS n FROM detections "
            "GROUP BY rule_name ORDER BY n DESC LIMIT 10"
        ).fetchall()

        by_verdict = conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM scans "
            "GROUP BY verdict"
        ).fetchall()

    return {
        "totals": dict(totals),
        "by_severity": {r["severity"]: r["n"] for r in by_severity},
        "by_category": {r["category"]: r["n"] for r in by_category},
        "top_rules": [dict(r) for r in top_rules],
        "by_verdict": {r["verdict"]: r["n"] for r in by_verdict},
    }

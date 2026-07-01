#!/usr/bin/env python3
"""
Interface web Flask — YARA Static Code Analyzer.
Lancer avec : python app.py  →  http://localhost:5000
"""

import os
import time
from collections import Counter
from pathlib import Path

from flask import Flask, flash, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename

from core.scoring import assess_file
from scanner import (
    REPORTS_DIR,
    SUPPORTED_EXTENSIONS,
    YaraScanner,
    generate_csv_report,
    generate_json_report,
)

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

scanner = YaraScanner()

# Stockage du dernier scan (mono-utilisateur — usage scolaire)
_last_scan: dict = {"results": {}, "files_scanned": 0}


@app.route("/")
def index() -> str:
    return render_template(
        "index.html",
        rule_count=scanner.total_rules_count,
        rule_files=scanner.rule_files,
        supported_ext=sorted(SUPPORTED_EXTENSIONS),
    )


@app.route("/scan", methods=["POST"])
def scan():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for("index"))

    filename = secure_filename(uploaded.filename)
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        flash(
            f"Extension non supportée : {ext}. "
            f"Acceptés : {', '.join(sorted(SUPPORTED_EXTENSIONS))}",
            "danger",
        )
        return redirect(url_for("index"))

    filepath = UPLOAD_FOLDER / filename
    uploaded.save(str(filepath))

    start = time.time()
    matches = scanner.scan_file(filepath)
    scan_time = time.time() - start

    all_results = {filename: matches} if matches else {}
    _last_scan["results"] = all_results
    _last_scan["files_scanned"] = 1

    total_detections = sum(len(m) for m in all_results.values())
    severity_counts: dict[str, int] = Counter()
    for file_matches in all_results.values():
        for m in file_matches:
            severity_counts[m["severity"]] += 1

    # Score de risque + verdict par fichier : {filepath: {"score", "verdict"}}
    assessments = {
        filepath: dict(zip(("score", "verdict"), assess_file(matches)))
        for filepath, matches in all_results.items()
    }

    return render_template(
        "results.html",
        all_results=all_results,
        assessments=assessments,
        files_scanned=1,
        scan_time=scan_time,
        target=filename,
        total_detections=total_detections,
        severity_counts=severity_counts,
    )


@app.route("/report/<fmt>")
def download_report(fmt: str):
    all_results = _last_scan.get("results", {})
    files_scanned = _last_scan.get("files_scanned", 0)

    if not all_results:
        flash("Aucun scan récent à exporter.", "warning")
        return redirect(url_for("index"))

    if fmt == "json":
        path = generate_json_report(all_results, files_scanned)
        return send_file(path, as_attachment=True)
    if fmt == "csv":
        path = generate_csv_report(all_results, files_scanned)
        return send_file(path, as_attachment=True)

    flash("Format inconnu.", "danger")
    return redirect(url_for("index"))


@app.route("/rules")
def list_rules() -> str:
    # Les noms de règles proviennent directement du moteur (API YARA),
    # plus fiable qu'un parsing texte des fichiers .yar.
    rules_data = [
        {"file": filename, "rules": scanner.rules_by_file[filename]}
        for filename in sorted(scanner.rules_by_file)
    ]
    return render_template(
        "rules.html",
        rules_data=rules_data,
        total_rules=scanner.total_rules_count,
    )


if __name__ == "__main__":
    print("\n  [YARA Scanner] Interface web → http://localhost:5000\n")
    app.run(debug=True, port=5000)

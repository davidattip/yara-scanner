#!/usr/bin/env python3
"""
Interface web Flask — YARA Static Code Analyzer.
Lancer avec : python app.py  →  http://localhost:5000
"""

import shutil
import time
import zipfile
from collections import Counter
from pathlib import Path

from flask import (
    Flask, abort, flash, redirect, render_template, request, send_file, url_for,
)
from werkzeug.utils import secure_filename

from core import history
from core.scoring import assess_file
from scanner import (
    SUPPORTED_EXTENSIONS,
    YaraScanner,
    generate_csv_report,
    generate_json_report,
)

app = Flask(__name__)
app.secret_key = "yara-scanner-dev-key"  # usage scolaire, mono-utilisateur

UPLOAD_FOLDER = Path(__file__).parent / "uploads"
UPLOAD_FOLDER.mkdir(exist_ok=True)

# Garde-fous pour l'extraction d'archives ZIP (jamais d'exécution, lecture seule).
MAX_ZIP_UNCOMPRESSED = 50 * 1024 * 1024   # 50 Mo décompressés max
MAX_ZIP_MEMBERS = 500

scanner = YaraScanner()

# Dernier scan en mémoire (pour l'export du rapport de la vue courante).
_last_scan: dict = {"results": {}, "files_scanned": 0}


# --- Utilitaires -----------------------------------------------------------

def _purge_uploads() -> None:
    """Vide uploads/ (sauf .gitkeep) avant un nouveau scan.

    Évite d'accumuler des échantillons potentiellement malveillants ; on ne
    garde sur le disque que le lot en cours (nécessaire au SHA-256 du rapport).
    """
    for item in UPLOAD_FOLDER.iterdir():
        if item.name == ".gitkeep":
            continue
        try:
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()
        except OSError:
            pass


def _safe_zip_members(zf: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    """Sélectionne les membres sûrs et supportés d'une archive (anti zip-bomb / traversal)."""
    selected: list[zipfile.ZipInfo] = []
    total_size = 0
    for info in zf.infolist():
        if info.is_dir() or len(selected) >= MAX_ZIP_MEMBERS:
            continue
        name = info.filename
        parts = Path(name).parts
        # Rejette les chemins absolus ou remontant hors du dossier (path traversal).
        if name.startswith(("/", "\\")) or ".." in parts:
            continue
        if Path(name).suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        total_size += info.file_size
        if total_size > MAX_ZIP_UNCOMPRESSED:
            break
        selected.append(info)
    return selected


def _expand_zip(zip_path: Path, display_prefix: str) -> list[tuple[str, str]]:
    """Extrait les fichiers supportés d'un ZIP et renvoie (nom_affiché, chemin_disque)."""
    targets: list[tuple[str, str]] = []
    dest = UPLOAD_FOLDER / (secure_filename(zip_path.stem) + "_extracted")
    dest.mkdir(exist_ok=True)
    with zipfile.ZipFile(zip_path) as zf:
        for i, info in enumerate(_safe_zip_members(zf)):
            flat = f"{i}_{secure_filename(Path(info.filename).name)}"
            out_path = dest / flat
            with zf.open(info) as src, open(out_path, "wb") as dst:
                shutil.copyfileobj(src, dst)
            display = f"{display_prefix}/{info.filename}"
            targets.append((display, str(out_path)))
    return targets


def _gather_targets(uploaded_files) -> tuple[list[tuple[str, str]], list[str]]:
    """Sauvegarde les fichiers uploadés et renvoie la liste des cibles à scanner.

    Gère les fichiers isolés, les uploads de dossier (chemins relatifs) et les
    archives ZIP (extraites de façon statique). Renvoie (cibles, rejetés) où
    chaque cible est un couple (nom_affiché, chemin_sur_disque).
    """
    targets: list[tuple[str, str]] = []
    rejected: list[str] = []

    for uploaded in uploaded_files:
        original = uploaded.filename
        name = secure_filename(original)
        ext = Path(name).suffix.lower()

        if ext == ".zip":
            zip_path = UPLOAD_FOLDER / name
            uploaded.save(str(zip_path))
            extracted = _expand_zip(zip_path, Path(original).name)
            if extracted:
                targets.extend(extracted)
            else:
                rejected.append(f"{original} (aucun fichier supporté dans l'archive)")
            continue

        if ext not in SUPPORTED_EXTENSIONS:
            rejected.append(f"{original} ({ext or 'sans extension'})")
            continue

        disk_path = UPLOAD_FOLDER / name
        uploaded.save(str(disk_path))
        # Nom affiché : chemin relatif d'origine (utile pour un upload de dossier).
        targets.append((original, str(disk_path)))

    return targets, rejected


def _compute_ml(targets: list[tuple[str, str]]) -> tuple[dict[str, dict], bool]:
    """Calcule la probabilité ML par fichier, si le module ML est disponible."""
    try:
        from core.ml import load_model, ml_verdict, predict_proba
        from core.features import read_text

        model = load_model()
    except Exception:
        # scikit-learn absent ou modèle non entraîné : on dégrade proprement.
        return {}, False

    scores: dict[str, dict] = {}
    for display, disk_path in targets:
        try:
            proba = predict_proba(model, read_text(disk_path))
        except OSError:
            continue
        scores[display] = {"proba": proba, "verdict": ml_verdict(proba)}
    return scores, True


# --- Routes ----------------------------------------------------------------

@app.route("/")
def index() -> str:
    return render_template(
        "index.html",
        rule_count=scanner.total_rules_count,
        rule_files=scanner.rule_files,
        supported_ext=sorted(SUPPORTED_EXTENSIONS),
        recent_scans=history.list_scans(limit=5),
    )


@app.route("/scan", methods=["POST"])
def scan():
    uploaded_files = request.files.getlist("files") or request.files.getlist("file")
    uploaded_files = [f for f in uploaded_files if f and f.filename]
    if not uploaded_files:
        flash("Aucun fichier sélectionné.", "danger")
        return redirect(url_for("index"))

    _purge_uploads()
    targets, rejected = _gather_targets(uploaded_files)

    if not targets:
        flash(
            "Aucun fichier au format supporté. "
            f"Acceptés : {', '.join(sorted(SUPPORTED_EXTENSIONS))} (ou .zip).",
            "danger",
        )
        return redirect(url_for("index"))

    start = time.time()
    all_results: dict[str, list[dict]] = {}
    for display, disk_path in targets:
        matches = scanner.scan_file(disk_path)
        if matches:
            all_results[display] = matches
    scan_time = time.time() - start

    ml_scores, ml_available = _compute_ml(targets)

    if rejected:
        flash("Fichiers ignorés (extension non supportée) : "
              + ", ".join(rejected), "warning")

    files_scanned = len(targets)
    _last_scan["results"] = all_results
    _last_scan["files_scanned"] = files_scanned

    assessments = {
        filepath: assess_file(matches)._asdict()
        for filepath, matches in all_results.items()
    }

    target_label = (
        targets[0][0] if files_scanned == 1 else f"{files_scanned} fichiers"
    )

    # Persistance dans l'historique.
    history.save_scan(
        target=target_label,
        files_scanned=files_scanned,
        scan_time=scan_time,
        all_results=all_results,
        assessments=assessments,
        ml_scores=ml_scores,
    )

    return render_template(
        "results.html",
        all_results=all_results,
        assessments=assessments,
        ml_scores=ml_scores,
        ml_available=ml_available,
        files_scanned=files_scanned,
        scan_time=scan_time,
        target=target_label,
        total_detections=sum(len(m) for m in all_results.values()),
        severity_counts=_severity_counts(all_results),
        from_history=False,
    )


def _severity_counts(all_results: dict[str, list[dict]]) -> Counter:
    counts: Counter = Counter()
    for matches in all_results.values():
        for m in matches:
            counts[m["severity"]] += 1
    return counts


@app.route("/report/<fmt>")
def download_report(fmt: str):
    all_results = _last_scan.get("results", {})
    files_scanned = _last_scan.get("files_scanned", 0)
    if not all_results:
        flash("Aucun scan récent à exporter.", "warning")
        return redirect(url_for("index"))

    base_dir = str(UPLOAD_FOLDER)
    if fmt == "json":
        return send_file(
            generate_json_report(all_results, files_scanned, base_dir=base_dir),
            as_attachment=True,
        )
    if fmt == "csv":
        return send_file(
            generate_csv_report(all_results, files_scanned, base_dir=base_dir),
            as_attachment=True,
        )
    flash("Format inconnu.", "danger")
    return redirect(url_for("index"))


@app.route("/history")
def scan_history() -> str:
    return render_template("history.html", scans=history.list_scans())


@app.route("/history/<int:scan_id>")
def history_detail(scan_id: int) -> str:
    record = history.get_scan(scan_id)
    if record is None:
        abort(404)

    detail = record["detail"]
    all_results = detail["all_results"]
    assessments = detail["assessments"]

    # La vue courante devient ce scan : l'export de rapport le reflète.
    _last_scan["results"] = all_results
    _last_scan["files_scanned"] = record["files_scanned"]

    return render_template(
        "results.html",
        all_results=all_results,
        assessments=assessments,
        ml_scores=detail.get("ml_scores", {}),
        ml_available=bool(detail.get("ml_scores")),
        files_scanned=record["files_scanned"],
        scan_time=record["scan_time"],
        target=record["target"],
        total_detections=record["total_detections"],
        severity_counts=_severity_counts(all_results),
        from_history=True,
        scan_ts=record["ts"],
    )


@app.route("/history/<int:scan_id>/delete", methods=["POST"])
def history_delete(scan_id: int):
    history.delete_scan(scan_id)
    flash(f"Scan #{scan_id} supprimé de l'historique.", "success")
    return redirect(url_for("scan_history"))


@app.route("/dashboard")
def dashboard() -> str:
    return render_template("dashboard.html", stats=history.stats())


@app.route("/rules")
def list_rules() -> str:
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
    history.init_db()
    print("\n  [YARA Scanner] Interface web → http://localhost:5000\n")
    app.run(debug=True, port=5000)

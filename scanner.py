#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          YARA STATIC CODE ANALYZER v1.0                     ║
║          Projet Annuel — David ATTIPOUPOU                   ║
║          M1 Cybersécurité                                   ║
╚══════════════════════════════════════════════════════════════╝

Outil d'analyse statique de code utilisant le moteur YARA
pour détecter des scripts potentiellement malveillants.
"""

import argparse
import json
import csv
import os
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    import yara
except ImportError:
    print("\n[ERREUR] La librairie yara-python n'est pas installée.")
    print("         Installe-la avec : pip install yara-python")
    sys.exit(1)

# --- Tentative d'import de colorama pour les couleurs (optionnel) ---
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False
    # Fallback sans couleurs
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = DIM = ""


# ============================================================
#  CONFIGURATION
# ============================================================

RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
SUPPORTED_EXTENSIONS = {".py", ".sh", ".bash", ".ps1", ".bat", ".cmd", ".js", ".vbs", ".rb", ".pl"}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}


# ============================================================
#  CLASSE PRINCIPALE : YaraScanner
# ============================================================

class YaraScanner:
    """Moteur d'analyse statique basé sur YARA."""

    def __init__(self, rules_dir=RULES_DIR):
        self.rules_dir = rules_dir
        self.compiled_rules = []
        self.rule_files = []
        self.total_rules_count = 0
        self._load_rules()

    def _load_rules(self):
        """Charge et compile toutes les règles YARA du dossier rules/."""
        if not os.path.isdir(self.rules_dir):
            print(f"{Fore.RED}[ERREUR] Dossier de règles introuvable : {self.rules_dir}")
            sys.exit(1)

        yar_files = list(Path(self.rules_dir).glob("*.yar"))
        if not yar_files:
            print(f"{Fore.RED}[ERREUR] Aucun fichier .yar trouvé dans {self.rules_dir}")
            sys.exit(1)

        for yar_file in yar_files:
            try:
                compiled = yara.compile(filepath=str(yar_file))
                self.compiled_rules.append((yar_file.name, compiled))
                self.rule_files.append(yar_file.name)

                # Compter les règles dans le fichier
                with open(yar_file, "r") as f:
                    content = f.read()
                    count = content.count("\nrule ") + (1 if content.startswith("rule ") else 0)
                    # Fallback: compter les "rule X" après commentaires
                    if count == 0:
                        count = sum(1 for line in content.split("\n")
                                    if line.strip().startswith("rule "))
                    self.total_rules_count += count

            except yara.SyntaxError as e:
                print(f"{Fore.YELLOW}[ATTENTION] Erreur de syntaxe dans {yar_file.name}: {e}")
            except Exception as e:
                print(f"{Fore.YELLOW}[ATTENTION] Impossible de charger {yar_file.name}: {e}")

    def scan_file(self, filepath):
        """Scanne un fichier avec toutes les règles YARA chargées."""
        results = []
        filepath = str(filepath)

        for rule_file, compiled in self.compiled_rules:
            try:
                matches = compiled.match(filepath)
                for match in matches:
                    # Extraire les métadonnées
                    meta = match.meta
                    severity = meta.get("severity", "MEDIUM")
                    category = meta.get("category", "unknown")
                    description = meta.get("description", "Pas de description")

                    # Extraire les chaînes matchées
                    matched_strings = []
                    for string_match in match.strings:
                        for instance in string_match.instances:
                            matched_strings.append({
                                "offset": instance.offset,
                                "identifier": string_match.identifier,
                                "data": instance.matched_data.decode("utf-8", errors="replace")[:80]
                            })

                    results.append({
                        "rule_name": match.rule,
                        "rule_file": rule_file,
                        "severity": severity,
                        "category": category,
                        "description": description,
                        "matched_strings": matched_strings,
                    })

            except Exception as e:
                results.append({
                    "rule_name": "SCAN_ERROR",
                    "rule_file": rule_file,
                    "severity": "INFO",
                    "category": "error",
                    "description": f"Erreur lors du scan: {str(e)}",
                    "matched_strings": [],
                })

        # Trier par sévérité
        results.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
        return results

    def scan_directory(self, target_dir):
        """Scanne récursivement un dossier et retourne tous les résultats."""
        all_results = {}
        files_scanned = 0
        files_skipped = 0

        for root, dirs, files in os.walk(target_dir):
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

    def list_rules(self):
        """Affiche toutes les règles chargées."""
        print(f"\n{Fore.CYAN}{'═' * 60}")
        print(f"  RÈGLES YARA CHARGÉES")
        print(f"{'═' * 60}{Style.RESET_ALL}\n")

        for yar_file in sorted(Path(self.rules_dir).glob("*.yar")):
            print(f"  {Fore.GREEN}📄 {yar_file.name}{Style.RESET_ALL}")
            with open(yar_file, "r") as f:
                content = f.read()
                for line in content.split("\n"):
                    stripped = line.strip()
                    if stripped.startswith("rule ") and not stripped.startswith("rule_"):
                        rule_name = stripped.replace("rule ", "").replace("{", "").strip()
                        print(f"     ├── {rule_name}")
            print()

        print(f"  {Style.BRIGHT}Total : {self.total_rules_count} règles dans {len(self.rule_files)} fichiers{Style.RESET_ALL}\n")


# ============================================================
#  AFFICHAGE DES RÉSULTATS
# ============================================================

def print_banner():
    """Affiche la bannière du programme."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗ █████╗ ██████╗  █████╗                          ║
║   ╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗                         ║
║    ╚████╔╝ ███████║██████╔╝███████║                          ║
║     ╚██╔╝  ██╔══██║██╔══██╗██╔══██║                          ║
║      ██║   ██║  ██║██║  ██║██║  ██║                          ║
║      ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝                          ║
║                                                              ║
║   Static Code Analyzer v1.0                                  ║
║   David ATTIPOUPOU — M1 Cybersécurité                        ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_results(all_results, files_scanned, files_skipped, scan_time):
    """Affiche les résultats du scan dans le terminal."""
    total_detections = sum(len(matches) for matches in all_results.values())
    files_infected = len(all_results)

    # Résumé
    print(f"\n{Fore.CYAN}{'═' * 60}")
    print(f"  RÉSULTATS DU SCAN")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")
    print(f"  ⏱  Durée du scan      : {scan_time:.2f}s")
    print(f"  📁 Fichiers scannés   : {files_scanned}")
    print(f"  ⏭  Fichiers ignorés   : {files_skipped}")

    if total_detections == 0:
        print(f"\n  {Fore.GREEN}✅ AUCUNE MENACE DÉTECTÉE — Tous les fichiers sont propres.{Style.RESET_ALL}\n")
        return

    print(f"  {Fore.RED}🚨 Fichiers suspects    : {files_infected}")
    print(f"  🔍 Détections totales  : {total_detections}{Style.RESET_ALL}")

    # Compteur par sévérité
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for matches in all_results.values():
        for match in matches:
            sev = match["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print(f"\n  Par sévérité :")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = severity_counts.get(sev, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "")
            print(f"    {color}■ {sev:10s} : {count}{Style.RESET_ALL}")

    # Détails par fichier
    print(f"\n{'─' * 60}")
    for filepath, matches in sorted(all_results.items()):
        max_severity = matches[0]["severity"] if matches else "INFO"
        color = SEVERITY_COLORS.get(max_severity, "")
        print(f"\n  {color}📄 {filepath}{Style.RESET_ALL}")

        for match in matches:
            sev_color = SEVERITY_COLORS.get(match["severity"], "")
            print(f"     {sev_color}[{match['severity']:8s}]{Style.RESET_ALL} "
                  f"{match['rule_name']}")
            print(f"              {Style.DIM}{match['description']}{Style.RESET_ALL}")

            # Afficher les strings matchées (max 3)
            for ms in match["matched_strings"][:3]:
                data_preview = ms["data"][:50]
                print(f"              → offset {ms['offset']}: "
                      f"{Fore.YELLOW}{ms['identifier']}{Style.RESET_ALL} = "
                      f"\"{data_preview}\"")

    print(f"\n{'═' * 60}\n")


# ============================================================
#  GÉNÉRATION DE RAPPORTS
# ============================================================

def generate_json_report(all_results, files_scanned, output_dir=REPORTS_DIR):
    """Génère un rapport au format JSON."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)

    report = {
        "scan_info": {
            "date": datetime.now().isoformat(),
            "tool": "YARA Static Code Analyzer v1.0",
            "author": "David ATTIPOUPOU",
            "files_scanned": files_scanned,
            "total_detections": sum(len(m) for m in all_results.values()),
        },
        "detections": {}
    }

    for filepath_key, matches in all_results.items():
        report["detections"][filepath_key] = [
            {
                "rule": m["rule_name"],
                "severity": m["severity"],
                "category": m["category"],
                "description": m["description"],
                "matched_strings": [
                    {"offset": s["offset"], "identifier": s["identifier"], "data": s["data"]}
                    for s in m["matched_strings"]
                ]
            }
            for m in matches
        ]

    output_path = os.path.join(output_dir, filename)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"  {Fore.GREEN}📊 Rapport JSON généré : {output_path}{Style.RESET_ALL}")
    return output_path


def generate_csv_report(all_results, files_scanned, output_dir=REPORTS_DIR):
    """Génère un rapport au format CSV."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.csv"
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Fichier", "Règle", "Sévérité", "Catégorie", "Description", "Strings Matchées"])

        for filepath_key, matches in all_results.items():
            for m in matches:
                strings_str = " | ".join(
                    f"{s['identifier']}={s['data'][:40]}" for s in m["matched_strings"][:5]
                )
                writer.writerow([
                    filepath_key, m["rule_name"], m["severity"],
                    m["category"], m["description"], strings_str
                ])

    print(f"  {Fore.GREEN}📊 Rapport CSV généré : {filepath}{Style.RESET_ALL}")
    return filepath


# ============================================================
#  POINT D'ENTRÉE
# ============================================================

def main():
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
        """
    )
    parser.add_argument("--scan", metavar="CIBLE",
                        help="Fichier ou dossier à scanner")
    parser.add_argument("--report", choices=["json", "csv"],
                        help="Générer un rapport (json ou csv)")
    parser.add_argument("--list-rules", action="store_true",
                        help="Afficher toutes les règles YARA chargées")
    parser.add_argument("--no-banner", action="store_true",
                        help="Ne pas afficher la bannière")

    args = parser.parse_args()

    if not args.no_banner:
        print_banner()

    # Initialiser le scanner
    scanner = YaraScanner()
    print(f"  {Fore.GREEN}✓ {scanner.total_rules_count} règles YARA chargées "
          f"depuis {len(scanner.rule_files)} fichiers{Style.RESET_ALL}")

    if args.list_rules:
        scanner.list_rules()
        return

    if not args.scan:
        parser.print_help()
        return

    target = args.scan

    if not os.path.exists(target):
        print(f"\n  {Fore.RED}[ERREUR] Cible introuvable : {target}{Style.RESET_ALL}")
        sys.exit(1)

    # Lancer le scan
    print(f"\n  🔍 Scan en cours : {target}")
    start_time = time.time()

    if os.path.isfile(target):
        matches = scanner.scan_file(target)
        all_results = {target: matches} if matches else {}
        files_scanned = 1
        files_skipped = 0
    else:
        all_results, files_scanned, files_skipped = scanner.scan_directory(target)

    scan_time = time.time() - start_time

    # Afficher les résultats
    print_results(all_results, files_scanned, files_skipped, scan_time)

    # Générer un rapport si demandé
    if args.report and all_results:
        if args.report == "json":
            generate_json_report(all_results, files_scanned)
        elif args.report == "csv":
            generate_csv_report(all_results, files_scanned)


if __name__ == "__main__":
    main()

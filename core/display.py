"""
Couche présentation terminal.

Regroupe tout ce qui touche à l'affichage : gestion des couleurs
(colorama, avec fallback si absent), bannière, résultats de scan,
liste des règles. Le moteur reste ainsi totalement silencieux.
"""

from __future__ import annotations

import sys

from core.scoring import CLEAN, MALICIOUS, REVIEW, SUSPECT, assess_file

# --- Encodage de sortie ----------------------------------------------------
# La bannière et les résumés utilisent des emojis / caractères Unicode.
# Sur une console Windows par défaut (cp1252), ces caractères provoquent
# une UnicodeEncodeError. On force donc l'UTF-8 quand c'est possible.
for _stream in (sys.stdout, sys.stderr):
    reconfigure = getattr(_stream, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # flux non reconfigurable
            pass

# --- Couleurs (colorama optionnel) -----------------------------------------
try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

    class Fore:  # type: ignore[no-redef]
        RED = GREEN = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""

    class Style:  # type: ignore[no-redef]
        BRIGHT = RESET_ALL = DIM = ""


SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}

VERDICT_COLORS = {
    MALICIOUS: Fore.RED + Style.BRIGHT,
    SUSPECT: Fore.YELLOW,
    REVIEW: Fore.CYAN,
    CLEAN: Fore.GREEN,
}


# --- Bannière --------------------------------------------------------------

def print_banner() -> None:
    """Affiche la bannière ASCII du programme."""
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


def print_load_warnings(warnings: list[tuple[str, str]]) -> None:
    """Affiche les avertissements de chargement des règles, s'il y en a."""
    for filename, message in warnings:
        print(f"{Fore.YELLOW}[ATTENTION] {filename} : {message}{Style.RESET_ALL}")


# --- Résultats de scan -----------------------------------------------------

def print_results(
    all_results: dict[str, list[dict]],
    files_scanned: int,
    files_skipped: int,
    scan_time: float,
) -> None:
    """Affiche les résultats du scan dans le terminal."""
    total_detections = sum(len(matches) for matches in all_results.values())
    files_infected = len(all_results)

    print(f"\n{Fore.CYAN}{'═' * 60}")
    print("  RÉSULTATS DU SCAN")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")
    print(f"  ⏱  Durée du scan      : {scan_time:.2f}s")
    print(f"  📁 Fichiers scannés   : {files_scanned}")
    print(f"  ⏭  Fichiers ignorés   : {files_skipped}")

    if total_detections == 0:
        print(
            f"\n  {Fore.GREEN}✅ AUCUNE MENACE DÉTECTÉE — "
            f"Tous les fichiers sont propres.{Style.RESET_ALL}\n"
        )
        return

    print(f"  {Fore.RED}🚨 Fichiers suspects    : {files_infected}")
    print(f"  🔍 Détections totales  : {total_detections}{Style.RESET_ALL}")

    # Compteur par sévérité
    severity_counts: dict[str, int] = {}
    for matches in all_results.values():
        for match in matches:
            sev = match["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

    print("\n  Par sévérité :")
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
        assessment = assess_file(matches)
        verdict_color = VERDICT_COLORS.get(assessment.verdict, "")
        print(f"\n  {color}📄 {filepath}{Style.RESET_ALL}")
        print(
            f"     {verdict_color}⚖  Verdict : {assessment.verdict} "
            f"(score {assessment.score} · risque {assessment.risk}/100)"
            f"{Style.RESET_ALL}"
        )

        for match in matches:
            sev_color = SEVERITY_COLORS.get(match["severity"], "")
            print(
                f"     {sev_color}[{match['severity']:8s}]{Style.RESET_ALL} "
                f"{match['rule_name']}"
            )
            print(f"              {Style.DIM}{match['description']}{Style.RESET_ALL}")

            for ms in match["matched_strings"][:3]:
                data_preview = ms["data"][:50]
                print(
                    f"              → offset {ms['offset']}: "
                    f"{Fore.YELLOW}{ms['identifier']}{Style.RESET_ALL} = "
                    f"\"{data_preview}\""
                )

    print(f"\n{'═' * 60}\n")


# --- Liste des règles ------------------------------------------------------

def print_rules(rules_by_file: dict[str, list[str]], total_rules: int) -> None:
    """Affiche toutes les règles chargées, groupées par fichier."""
    print(f"\n{Fore.CYAN}{'═' * 60}")
    print("  RÈGLES YARA CHARGÉES")
    print(f"{'═' * 60}{Style.RESET_ALL}\n")

    for filename in sorted(rules_by_file):
        print(f"  {Fore.GREEN}📄 {filename}{Style.RESET_ALL}")
        for rule_name in rules_by_file[filename]:
            print(f"     ├── {rule_name}")
        print()

    print(
        f"  {Style.BRIGHT}Total : {total_rules} règles "
        f"dans {len(rules_by_file)} fichiers{Style.RESET_ALL}\n"
    )


def print_report_saved(path: str) -> None:
    """Confirme l'écriture d'un rapport."""
    print(f"  {Fore.GREEN}📊 Rapport généré : {path}{Style.RESET_ALL}")

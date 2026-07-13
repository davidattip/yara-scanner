"""
Configuration centrale de l'analyseur.

Ce module ne contient que des constantes pures (chemins, extensions,
ordre de sévérité). Il n'a aucune dépendance vers les autres modules,
ce qui évite les imports circulaires.
"""

import os
import sys

# --- Chemins ---------------------------------------------------------------
if getattr(sys, "frozen", False):
    # Exécutable PyInstaller : les ressources en lecture seule (les règles)
    # sont extraites dans un dossier temporaire (sys._MEIPASS), tandis que les
    # sorties (rapports) doivent être écrites à côté de l'exécutable.
    _BUNDLE_DIR = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
    PROJECT_ROOT = os.path.dirname(sys.executable)
    RULES_DIR = os.path.join(_BUNDLE_DIR, "rules")
    REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
else:
    # Exécution normale : racine du projet = dossier parent de `core/`.
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
    REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

# Données persistantes (base d'historique) et uploads de l'interface web.
# Toujours à côté du projet/exécutable — jamais dans le dossier temporaire
# PyInstaller, qui est effacé à la fermeture.
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
UPLOADS_DIR = os.path.join(PROJECT_ROOT, "uploads")

# --- Extensions de fichiers analysés ---------------------------------------
SUPPORTED_EXTENSIONS = {
    ".py", ".sh", ".bash", ".ps1", ".bat", ".cmd",
    ".js", ".vbs", ".rb", ".pl",
}

# --- Sévérité --------------------------------------------------------------
# Ordre de tri (0 = plus grave). Sert au tri des détections.
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

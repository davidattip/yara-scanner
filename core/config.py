"""
Configuration centrale de l'analyseur.

Ce module ne contient que des constantes pures (chemins, extensions,
ordre de sévérité). Il n'a aucune dépendance vers les autres modules,
ce qui évite les imports circulaires.
"""

import os

# --- Chemins ---------------------------------------------------------------
# Racine du projet = dossier parent de `core/`.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(PROJECT_ROOT, "rules")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")

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

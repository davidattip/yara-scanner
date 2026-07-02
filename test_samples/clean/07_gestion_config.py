# Script legitime - Gestionnaire de configuration JSON
# Ce fichier ne devrait PAS declencher d'alerte YARA.
# Lecture, modification et sauvegarde d'un fichier de configuration.

import json
import os
from pathlib import Path

CONFIG_PATH = Path.home() / ".monapp" / "config.json"

DEFAULTS = {
    "theme": "clair",
    "langue": "fr",
    "notifications": True,
    "max_resultats": 50,
}


def charger_config() -> dict:
    """Charge la configuration, ou renvoie les valeurs par defaut."""
    if not CONFIG_PATH.exists():
        return dict(DEFAULTS)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        donnees = json.load(f)
    # Complete les cles manquantes avec les valeurs par defaut.
    return {**DEFAULTS, **donnees}


def sauvegarder_config(config: dict) -> None:
    """Ecrit la configuration sur le disque au format JSON."""
    os.makedirs(CONFIG_PATH.parent, exist_ok=True)
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def main() -> None:
    config = charger_config()
    print(f"Theme actuel : {config['theme']}")
    config["theme"] = "sombre"
    sauvegarder_config(config)
    print("Configuration mise a jour.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Lanceur "appli web" — point d'entrée de l'exécutable autonome.

Utilisé par la recette PyInstaller `yara_scanner_web.spec` pour produire
`dist/yara-scanner-web.exe` : un double-clic démarre le serveur waitress
en local et ouvre l'interface dans le navigateur par défaut.

Différences avec `wsgi.py` (déploiement serveur) :
  - écoute par défaut sur 127.0.0.1 (poste local uniquement, pas d'exposition
    réseau — c'est une appli de bureau, pas un service) ;
  - ouverture automatique du navigateur une fois le serveur prêt.

Fonctionne aussi en mode développement : python web_launcher.py
"""

from __future__ import annotations

import os
import threading
import webbrowser

from app import app
from core import history


def _open_browser_when_ready(url: str, delay: float = 1.0) -> None:
    """Ouvre le navigateur après un court délai (le temps que waitress écoute)."""
    threading.Timer(delay, webbrowser.open, args=(url,)).start()


def main() -> None:
    from waitress import serve

    # La base d'historique est créée si besoin dès le démarrage (idempotent).
    history.init_db()

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5000"))
    url = f"http://{host}:{port}"

    print(f"\n  [YARA Scanner] Interface web → {url}")
    print("  Pour arrêter l'application : ferme cette fenêtre.\n")

    _open_browser_when_ready(url)
    serve(app, host=host, port=port)


if __name__ == "__main__":
    main()

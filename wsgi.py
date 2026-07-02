#!/usr/bin/env python3
"""
Point d'entrée WSGI pour le déploiement en production.

Le serveur intégré de Flask (`app.run(debug=True)`) est réservé au
développement. En production, on sert l'application via un serveur WSGI :

  - **waitress** (utilisé ici) : serveur WSGI pur Python, multi-plateforme.
    Il fonctionne aussi bien sous Linux que sous Windows, ce qui évite de
    maintenir deux configurations différentes.
  - **gunicorn** : alternative standard sous Linux (utilisée dans l'image
    Docker), non disponible sous Windows.

Lancement direct (multi-plateforme) :
    pip install waitress
    python wsgi.py

Lancement via un serveur externe (l'objet WSGI exposé est `app`) :
    waitress-serve --listen=0.0.0.0:5000 wsgi:app
    gunicorn --bind 0.0.0.0:5000 wsgi:app
"""

from __future__ import annotations

import os

from app import app
from core import history

# La base d'historique est créée si besoin dès le démarrage (idempotent),
# car sous un serveur WSGI le bloc __main__ de app.py n'est pas exécuté.
history.init_db()


def main() -> None:
    from waitress import serve

    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    print(f"\n  [YARA Scanner] Serveur de production (waitress) "
          f"→ http://{host}:{port}\n")
    serve(app, host=host, port=port)


if __name__ == "__main__":
    main()

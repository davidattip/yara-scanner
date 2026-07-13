# -*- mode: python ; coding: utf-8 -*-
#
# Recette PyInstaller pour produire l'exécutable "appli web" autonome.
#
#   Build :  pyinstaller yara_scanner_web.spec
#   Sortie : dist/yara-scanner-web.exe (Windows) — aucun Python requis.
#
# Un double-clic lance le serveur waitress en local (127.0.0.1:5000) et ouvre
# l'interface dans le navigateur. L'exe embarque le moteur YARA, l'entropie,
# Flask + waitress, les templates et le dossier `rules/`.
#
# Le module ML (scikit-learn) est volontairement EXCLU : il ferait passer
# l'exe d'environ 15 Mo à plus de 150 Mo, et l'interface web dégrade
# proprement sans lui (la colonne "Score ML" disparaît simplement).
#
# Données persistantes (créées à côté de l'exe au premier lancement) :
#   data/     — historique des scans (SQLite)
#   uploads/  — fichiers du scan en cours
#   reports/  — rapports JSON/CSV exportés

from PyInstaller.utils.hooks import collect_all

# yara-python embarque une extension compilée : on collecte tout ce qu'elle
# nécessite (binaires + métadonnées) pour un fonctionnement fiable une fois figé.
yara_datas, yara_binaries, yara_hiddenimports = collect_all("yara")

a = Analysis(
    ["web_launcher.py"],
    pathex=[],
    binaries=yara_binaries,
    datas=yara_datas + [
        ("rules", "rules"),          # règles YARA (lecture seule)
        ("templates", "templates"),  # vues Jinja2 de l'interface web
    ],
    hiddenimports=yara_hiddenimports + [
        # waitress démarre ses composants par import dynamique.
        "waitress",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Dépendances optionnelles exclues (le module ML dégrade proprement).
    excludes=[
        "sklearn", "scipy", "numpy", "joblib", "pandas", "matplotlib",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="yara-scanner-web",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,          # la fenêtre console sert de bouton "arrêt" visible
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

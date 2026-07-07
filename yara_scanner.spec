# -*- mode: python ; coding: utf-8 -*-
#
# Recette PyInstaller pour produire un exécutable CLI autonome.
#
#   Build :  pyinstaller yara_scanner.spec
#   Sortie : dist/yara-scanner.exe (Windows) — aucun Python requis chez l'ami.
#
# L'exe embarque le moteur YARA + entropie et le dossier `rules/`. Le module
# ML (scikit-learn) est volontairement EXCLU : il alourdirait fortement l'exe
# et l'app dégrade proprement sans lui (l'option --ml affiche un message clair).

from PyInstaller.utils.hooks import collect_all

# yara-python embarque une extension compilée : on collecte tout ce qu'elle
# nécessite (binaires + métadonnées) pour un fonctionnement fiable une fois figé.
yara_datas, yara_binaries, yara_hiddenimports = collect_all("yara")

a = Analysis(
    ["scanner.py"],
    pathex=[],
    binaries=yara_binaries,
    datas=yara_datas + [("rules", "rules")],
    hiddenimports=yara_hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Dépendances optionnelles non nécessaires au chemin CLI de base.
    excludes=[
        "sklearn", "scipy", "numpy", "joblib", "pandas",
        "flask", "werkzeug", "jinja2", "waitress", "matplotlib",
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
    name="yara-scanner",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,          # outil en ligne de commande
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

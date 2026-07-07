@echo off
REM ============================================================
REM  YARA Scanner - Interface web
REM
REM  Double-clique sur ce fichier pour lancer l'interface web.
REM  Elle s'ouvre dans ton navigateur sur http://localhost:5000
REM  Pour l'arreter : ferme cette fenetre noire.
REM ============================================================

cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe.
    echo Telecharge-le sur https://www.python.org/downloads/
    echo Pense a cocher "Add Python to PATH" pendant l'installation.
    pause
    exit /b 1
)

if not exist ".venv" (
    echo Premiere utilisation : installation en cours, patiente un instant...
    python -m venv .venv
    call ".venv\Scripts\activate.bat"
    python -m pip install --quiet --upgrade pip
    pip install --quiet -r requirements.txt
) else (
    call ".venv\Scripts\activate.bat"
)

REM Sert uniquement en local (127.0.0.1), via le serveur de production waitress.
set "HOST=127.0.0.1"
set "PORT=5000"

echo.
echo Ouverture de http://localhost:5000 dans le navigateur...
start "" http://localhost:5000
python wsgi.py

pause

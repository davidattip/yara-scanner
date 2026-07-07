@echo off
REM ============================================================
REM  YARA Scanner - Analyse d'un dossier ou d'un fichier
REM
REM  UTILISATION : glisse un dossier (ou un fichier) sur ce
REM  fichier .bat, ou double-clique pour analyser le dossier
REM  courant. L'analyse est STATIQUE : rien n'est execute.
REM ============================================================

cd /d "%~dp0"

REM --- Verifie que Python est installe ---
where python >nul 2>nul
if errorlevel 1 (
    echo [ERREUR] Python n'est pas installe.
    echo Telecharge-le sur https://www.python.org/downloads/
    echo Pense a cocher "Add Python to PATH" pendant l'installation.
    pause
    exit /b 1
)

REM --- Cree l'environnement et installe les dependances au 1er lancement ---
if not exist ".venv" (
    echo Premiere utilisation : installation en cours, patiente un instant...
    python -m venv .venv
    call ".venv\Scripts\activate.bat"
    python -m pip install --quiet --upgrade pip
    pip install --quiet yara-python colorama
) else (
    call ".venv\Scripts\activate.bat"
)

REM --- Cible : l'argument glisse-depose, ou le dossier courant par defaut ---
set "CIBLE=%~1"
if "%CIBLE%"=="" set "CIBLE=."

echo.
python scanner.py --scan "%CIBLE%"

echo.
pause

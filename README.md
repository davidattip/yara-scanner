# 🔍 YARA Static Code Analyzer
### Projet Annuel — David ATTIPOUPOU — M1 Cybersécurité

Outil d'analyse statique de code utilisant le moteur YARA pour détecter
des scripts potentiellement malveillants (Python, Bash, PowerShell).

---

## Installation (Windows / Mac / Linux)

### Étape 1 : Installer Python
1. Va sur https://www.python.org/downloads/
2. Télécharge Python 3.10+ et installe-le
3. **IMPORTANT (Windows)** : Coche la case "Add Python to PATH" pendant l'installation

### Étape 2 : Installer les dépendances
Ouvre un terminal (ou PowerShell sur Windows) et tape :

```bash
pip install yara-python colorama
```

Si ça ne marche pas, essaie :
```bash
pip3 install yara-python colorama
```

### Étape 3 : Lancer le scanner
```bash
python scanner.py --scan test_samples/
```

---

## Utilisation

### Scanner un dossier
```bash
python scanner.py --scan <chemin_du_dossier>
```

### Scanner un fichier unique
```bash
python scanner.py --scan <chemin_du_fichier>
```

### Générer un rapport JSON
```bash
python scanner.py --scan test_samples/ --report json
```

### Générer un rapport CSV
```bash
python scanner.py --scan test_samples/ --report csv
```

### Afficher les règles chargées
```bash
python scanner.py --list-rules
```

### Désactiver la détection par entropie
En complément des règles YARA, le scanner mesure l'entropie de Shannon des
longues chaînes : les charges utiles encodées/chiffrées (entropie élevée)
sont repérées même sans règle dédiée. Pour ne garder que YARA :
```bash
python scanner.py --scan test_samples/ --no-entropy
```

---

## Structure du projet

```
yara_scanner/
├── scanner.py              # Moteur de scan principal
├── rules/                  # Règles YARA de détection
│   ├── obfuscation.yar     # Détection d'obfuscation de code
│   ├── reverse_shell.yar   # Détection de reverse shells
│   ├── dangerous_imports.yar # Imports suspects
│   └── encoding_tricks.yar # Techniques d'encodage malveillant
├── test_samples/           # Échantillons de test
│   ├── malicious/          # Scripts suspects (pour tester la détection)
│   └── clean/              # Scripts légitimes (pour vérifier les faux positifs)
├── reports/                # Rapports générés
└── README.md
```

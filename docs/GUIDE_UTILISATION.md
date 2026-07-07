# 🚀 Guide d'utilisation — YARA Scanner

Ce guide explique comment installer et utiliser l'outil sur ton PC pour
analyser tes propres fichiers. L'outil est un **analyseur statique** : il
*lit* les fichiers pour y détecter des éléments suspects, il ne les
**exécute jamais**. Rien de risqué à scanner ton propre ordinateur.

---

## Option 1 — La plus simple (avec Python)

### Étape 1 — Installer Python (une seule fois)

1. Va sur https://www.python.org/downloads/
2. Télécharge Python 3.10 ou plus récent.
3. **Important** : pendant l'installation, coche la case **« Add Python to PATH »**.

### Étape 2 — Récupérer le projet

- **Via GitHub** : télécharge le dépôt (bouton vert « Code » → « Download ZIP »)
  puis décompresse-le ; ou en ligne de commande :
  ```
  git clone https://github.com/davidattip/yara-scanner.git
  ```
- **Via une archive** : décompresse simplement le `.zip` qu'on t'a envoyé.

### Étape 3 — Lancer l'outil

Deux fichiers à **double-cliquer** sont fournis (aucune commande à taper) :

| Fichier | Ce qu'il fait |
| --- | --- |
| **`Analyser_un_dossier.bat`** | Glisse un dossier ou un fichier dessus → il l'analyse. |
| **`Interface_web.bat`** | Ouvre l'interface graphique dans ton navigateur. |

Au tout premier lancement, l'outil installe ce dont il a besoin (patiente
quelques secondes) ; les fois suivantes, c'est instantané.

> 💡 Tu peux aussi glisser-déposer **directement un dossier** sur
> `Analyser_un_dossier.bat` pour scanner tout son contenu d'un coup.

### En ligne de commande (si tu préfères)

```bash
pip install -r requirements.txt
python scanner.py --scan "C:\chemin\vers\ton\dossier"
```

---

## Option 2 — Sans rien installer (l'exécutable)

Si on t'a fourni le fichier **`yara-scanner.exe`**, tu n'as **pas besoin de
Python**. Ouvre une invite de commande dans le dossier de l'exe et tape :

```
yara-scanner.exe --scan "C:\chemin\vers\ton\dossier"
```

Ou glisse un dossier sur l'exe pour l'analyser.

---

## Comment lire les résultats

Pour chaque fichier suspect, l'outil affiche :

- un **verdict** : `PROPRE`, `À VÉRIFIER`, `SUSPECT` ou `MALVEILLANT` ;
- un **score de risque** sur 100 ;
- les **règles déclenchées** (ex. « reverse shell », « obfuscation »)
  avec la portion de code concernée.

Un fichier `PROPRE` n'a déclenché aucune règle. Un verdict `SUSPECT` ou
`MALVEILLANT` mérite que tu regardes le fichier de plus près.

> ⚠️ Comme tout outil de ce type, il peut se tromper (faux positif ou fichier
> malveillant non détecté). C'est une **aide à l'analyse**, pas un verdict
> définitif.

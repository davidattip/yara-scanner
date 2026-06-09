# CLAUDE.md — Outil d'analyse statique de code (YARA Scanner)

## Contexte du projet

Projet Annuel — Master 1 Cybersécurité (David ATTIPOUPOU, projet individuel).

Outil d'analyse statique de code écrit en **Python 3**. Il scanne des fichiers de
scripts (Python, Bash, PowerShell, etc.) pour détecter automatiquement des éléments
suspects ou malveillants, en s'appuyant sur le moteur **YARA**.

## ⚠️ Contrainte fondamentale — à respecter absolument

**Le code analysé ne doit JAMAIS être exécuté.** C'est un analyseur *statique*.
Toute détection se fait par lecture des fichiers et application de règles YARA.
N'introduis jamais `exec()`, `eval()`, `subprocess.run()` sur le contenu cible,
ni aucun mécanisme qui ferait tourner les échantillons. Les échantillons malveillants
de `test_samples/malicious/` sont là pour être *lus*, pas lancés.

## Stack technique

- **Python 3** — langage principal.
- **yara-python** — binding officiel du moteur YARA (cœur de la détection).
- **Flask** — interface web de visualisation (optionnel, phase tardive).
- **scikit-learn** — module ML comportemental (optionnel, bonus).

Garde les dépendances optionnelles isolées : le scanner doit fonctionner en CLI pure
sans Flask ni scikit-learn installés.

## Structure du projet

```
yara_scanner/
├── scanner.py              # Point d'entrée CLI + moteur de scan
├── rules/                  # Règles YARA (écrites par l'étudiant)
│   ├── dangerous_imports.yar
│   ├── encoding_tricks.yar
│   ├── obfuscation.yar
│   └── reverse_shell.yar
├── test_samples/
│   ├── clean/              # Scripts bénins (ne doivent PAS déclencher d'alerte)
│   └── malicious/          # Scripts malveillants de test (doivent être détectés)
└── README.md
```

À mesure que le projet grandit, vise une séparation en modules :
moteur de scan, chargement de la base de règles, détection avancée,
générateur de rapport, interface (CLI / web). Garde `scanner.py` comme orchestrateur léger.

## Modules attendus (architecture cible)

| Module | Rôle |
| --- | --- |
| Moteur de scan | Parcourt répertoires/fichiers, applique les règles via yara-python. |
| Base de règles YARA | Règles couvrant : obfuscation, imports dangereux, chaînes suspectes, reverse shells, encodage suspect. |
| Détection avancée | Obfuscation, chaînes encodées, patterns d'évasion classiques. |
| Générateur de rapport | Rapport JSON et/ou CSV : détections, niveau de risque, règle déclenchée. |
| Interface | CLI avec options de config ; interface web Flask simple (optionnel). |
| Module ML | Détection comportementale complémentaire (optionnel). |

## Conventions

### Règles YARA
- Chaque règle inclut un bloc `meta` avec `description`, `author = "David ATTIPOUPOU"`,
  `severity` et `category`.
- Privilégie `nocase` pour les chaînes de détection quand c'est pertinent.
- Une règle = une intention de détection claire. Documente la logique de la `condition`.
- Avant d'ajouter une règle, vérifie qu'elle ne génère pas de faux positifs sur
  `test_samples/clean/`.

### Python
- Code lisible et commenté (le projet est évalué et soutenu à l'oral).
- Type hints sur les fonctions publiques.
- Gestion d'erreurs propre (fichier illisible, règle YARA invalide, chemin inexistant).
- Pas de dépendance lourde imposée pour le chemin CLI de base.

## Commandes utiles

```bash
# Installer les dépendances
pip install yara-python

# Lancer un scan sur un dossier
python scanner.py <chemin_cible>

# Test de non-régression : aucun fichier de clean/ ne doit être flaggé,
# tous ceux de malicious/ doivent l'être
python scanner.py test_samples/clean
python scanner.py test_samples/malicious
```

## Workflow Git

- Commits atomiques, messages clairs et en français.
- Une fonctionnalité ou une règle = un commit.
- Push régulier sur le dépôt GitHub.

## Livrables (rappel projet)

- Code source Python complet et documenté.
- Jeu de règles YARA créées par l'étudiant.
- Dataset de scripts testés (bénins et malveillants).
- Rapport technique détaillé.
- Soutenance avec démonstration en direct.

## Planning indicatif

1. Sem. 1-2 — Prise en main YARA / yara-python, tests basiques.
2. Sem. 3-4 — Moteur de scan (parcours fichiers, application des règles).
3. Sem. 5-6 — Écriture et test du jeu de règles.
4. Sem. 7-8 — Rapports JSON/CSV + interface CLI / web.
5. Sem. 9-10 — Tests complets, documentation, préparation soutenance.

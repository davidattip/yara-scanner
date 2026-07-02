# Rapport technique — YARA Static Code Analyzer

**Projet Annuel — M1 Cybersécurité**
**Auteur : David ATTIPOUPOU**

---

## 1. Introduction

### 1.1 Objectif

Le projet consiste à concevoir un **outil d'analyse statique de code** capable
de détecter automatiquement des scripts potentiellement malveillants (Python,
Bash, PowerShell, JavaScript…). L'outil s'appuie sur le moteur **YARA**,
standard de l'industrie pour la détection à base de signatures, complété par
deux couches d'analyse maison : une **détection statistique par entropie** et
un **module d'apprentissage automatique comportemental**.

### 1.2 Contrainte fondamentale : analyse strictement statique

La règle absolue du projet est que **le code analysé n'est jamais exécuté**.
Toutes les détections reposent sur la *lecture* des fichiers :

- YARA applique des motifs sur le contenu binaire/texte ;
- l'analyse d'entropie mesure le désordre statistique des chaînes ;
- le module ML calcule des caractéristiques par lecture uniquement.

Aucun `exec()`, `eval()`, ni `subprocess` n'est appliqué au contenu cible.
Les échantillons malveillants du dataset sont là pour être *lus*, pas lancés.

---

## 2. Architecture logicielle

### 2.1 Vue d'ensemble

L'outil suit une architecture **modulaire** en couches, avec une séparation
stricte entre la logique métier (package `core/`) et les couches de
présentation (CLI, web). Le moteur ne produit **aucun affichage** : il renvoie
des structures de données que les couches supérieures exploitent.

```
                ┌──────────────┐     ┌──────────────┐
                │  scanner.py  │     │    app.py    │
                │    (CLI)     │     │ (web Flask)  │
                └──────┬───────┘     └──────┬───────┘
                       │                    │
                       └─────────┬──────────┘
                                 ▼
        ┌──────────────────────────────────────────────┐
        │                  core/                        │
        │  rule_loader → engine → (entropy) → scoring   │
        │       reporting · hashing · features · ml     │
        │                  display                      │
        └──────────────────────────────────────────────┘
```

### 2.2 Rôle de chaque module

| Module | Responsabilité |
| --- | --- |
| `config.py` | Constantes pures : chemins, extensions supportées, ordre de sévérité. Aucune dépendance interne (évite les imports circulaires). |
| `rule_loader.py` | Recherche, compilation et inventaire des règles YARA. Collecte les erreurs de compilation sans bloquer le chargement des autres règles. |
| `engine.py` | Classe `YaraScanner` : applique les règles à un fichier/dossier, renvoie les détections normalisées. |
| `entropy.py` | Détection avancée par entropie de Shannon. |
| `scoring.py` | Score de risque et verdict par fichier. |
| `hashing.py` | Empreintes SHA-256 des fichiers (identification d'échantillon). |
| `reporting.py` | Génération des rapports JSON et CSV. |
| `features.py` | Extraction des caractéristiques statiques pour le ML (pur Python). |
| `ml.py` | Classifieur comportemental scikit-learn (dépendance isolée). |
| `history.py` | Persistance SQLite de l'historique des scans (interface web). |
| `display.py` | Couche présentation terminal (couleurs, bannière, résultats). |

### 2.3 Isolation des dépendances optionnelles

Le **chemin CLI de base** ne requiert que `yara-python` (et `colorama` pour
les couleurs). `flask` (web) et `scikit-learn` (ML) sont importés de façon
**isolée** : leur absence n'empêche jamais le scanner de fonctionner. Par
exemple, `core/ml.py` capture l'`ImportError` de scikit-learn et lève une
`MLUnavailableError` explicite si l'utilisateur tente d'utiliser `--ml`.

---

## 3. Couche 1 — Détection par règles YARA

### 3.1 Base de règles

La base compte **25 règles** réparties en **8 familles thématiques**. Chaque
règle porte un bloc `meta` normalisé (`description`, `author`, `severity`,
`category`).

| Fichier | Règles | Intention |
| --- | --- | --- |
| `reverse_shell.yar` | Python / Bash / PowerShell reverse shells | Connexion inversée vers un attaquant. |
| `obfuscation.yar` | Base64+exec, chr(), hex, compile+exec | Dissimulation du code. |
| `encoding_tricks.yar` | Base64, ROT13, XOR, eval+decode | Encodage de charge utile. |
| `dangerous_imports.yar` | Keylogger, exfiltration, vol d'identifiants | Combinaisons d'imports offensives. |
| `network_c2.yar` | Beaconing HTTP, tunneling DNS, socket brute | Communication Command & Control. |
| `persistence.yar` | Registre, crontab, dossier de démarrage | Maintien d'accès. |
| `ransomware.yar` | Boucle de chiffrement, note de rançon, suppression des sauvegardes | Comportement rançongiciel. |
| `cryptomining.yar` | Pool de minage (Stratum), épuisement CPU | Minage non autorisé. |

### 3.2 Principe de conception

Chaque règle vise **une intention de détection claire** et privilégie des
**conditions combinées** plutôt que des chaînes isolées, afin de limiter les
faux positifs. Exemple — le reverse shell Python n'est déclenché que si l'on
trouve *à la fois* un import `socket`, un `.connect((`, un mécanisme
d'exécution (`subprocess` ou `os.dup2`) **et** une référence à un shell
(`/bin/sh`, `cmd.exe`…) :

```yara
condition:
    $import_socket and $connect and
    (($import_subprocess and ($popen or $call)) or ($import_os and $dup2)) and
    ($bin_sh or $bin_bash or $cmd_exe)
```

Cette exigence de co-occurrence est ce qui permet aux scripts légitimes qui
utilisent `socket` (par exemple un serveur HTTP) de **ne pas** être flaggés.

---

## 4. Couche 2 — Détection statistique par entropie

### 4.1 Principe

Là où YARA cherche des motifs *connus*, l'analyse d'entropie détecte
l'**inconnu obfusqué**. On mesure l'entropie de Shannon (bits par caractère)
des longues chaînes du fichier :

$$ H = - \sum_{c} p(c) \cdot \log_2 p(c) $$

où *p(c)* est la fréquence du caractère *c*. Plus *H* est élevée, plus la
chaîne est « aléatoire » : le code source courant tourne autour de 3–4
bits/caractère, tandis qu'une charge base64 ou chiffrée atteint 5–6.

### 4.2 Calibrage des seuils

| Paramètre | Valeur | Justification |
| --- | --- | --- |
| `MIN_TOKEN_LEN` | 40 | En dessous, l'entropie n'est pas statistiquement significative (faux positifs). |
| `ENTROPY_THRESHOLD` | 4.3 | Calibré **au-dessus** de l'entropie du code courant (~4.1) pour éviter les faux positifs sur du code normal. |
| `HIGH_ENTROPY` | 4.8 | Au-delà, la détection passe de MEDIUM à HIGH. |
| `HIGH_LENGTH` | 200 | Une très longue chaîne encodée est plus préoccupante. |

Le format de sortie de l'analyse d'entropie est **identique** à celui de YARA,
ce qui permet au scoring, aux rapports et à l'affichage de traiter les deux
sources de façon uniforme.

---

## 5. Couche 3 — Module ML comportemental (bonus)

### 5.1 Motivation

Le module ML apprend à distinguer « bénin » de « malveillant » à partir de
caractéristiques **statiques globales**, offrant un troisième avis capable de
lever un doute sur un script qu'aucune règle ne matche.

### 5.2 Ingénierie des caractéristiques (`features.py`)

13 features numériques sont extraites par **lecture seule** de chaque script :

- **Structurelles** : taille du fichier, nombre de lignes, longueur moyenne et
  maximale des lignes.
- **Entropie** : entropie globale, entropie maximale des tokens, nombre de
  tokens à forte entropie, nombre de longues chaînes base64.
- **Sémantiques** : nombre et densité de mots-clés suspects (`eval`, `exec`,
  `socket`, `base64`, `invoke-expression`…), nombre d'imports dangereux.
- **Composition** : ratio de caractères non-ASCII, ratio de caractères
  spéciaux.

Ce module ne dépend pas de scikit-learn : il est testable indépendamment.

### 5.3 Modèle et entraînement (`ml.py`, `train_ml.py`)

- **Algorithme** : `RandomForestClassifier` (200 arbres, profondeur max 6,
  `class_weight="balanced"`, graine fixée à 42 pour la reproductibilité).
- **Dataset** : 7 scripts bénins + 11 scripts malveillants (`test_samples/`).
- **Évaluation** : validation croisée à 5 plis → exactitude moyenne ≈ **75 %**.
- **Sérialisation** : le modèle est sauvegardé via `joblib` dans `models/`.

### 5.4 Résultats et honnêteté méthodologique

Sur le dataset, la séparation est nette : les 11 échantillons malveillants
scorent tous **> 70 %** de probabilité, les 7 bénins tous **< 21 %**.

⚠️ Ces probabilités mesurées sur les fichiers d'entraînement sont
**optimistes**. C'est la validation croisée (~75 %) qui donne l'estimation
honnête de la capacité de généralisation. Le dataset est volontairement réduit
(usage pédagogique) : le module a une valeur **démonstrative**, il illustre la
faisabilité d'une approche ML complémentaire, pas un détecteur de production.

---

## 6. Score de risque et verdict

Deux indicateurs complémentaires sont produits par fichier (`scoring.py`).

### 6.1 Score brut (cumulé)

Somme pondérée par sévérité, reflétant la *quantité de preuves* :

```
score_brut = 10 × CRITICAL + 5 × HIGH + 2 × MEDIUM + 1 × LOW
```

(les détections INFO, comme les erreurs de scan, valent 0 pour ne pas gonfler
le score.)

### 6.2 Score de risque normalisé /100

Le score brut ramené sur une échelle lisible, avec plafonnement :

```
risque = min(100, round(score_brut / 20 × 100))
```

Le plafond `RISK_CEILING = 20` correspond à deux règles CRITICAL : au-delà,
on considère le risque maximal.

### 6.3 Verdict

| Score brut | Verdict |
| --- | --- |
| ≥ 10 | MALVEILLANT |
| ≥ 3 | SUSPECT |
| ≥ 1 | À VÉRIFIER |
| 0 | PROPRE |

Le palier « À VÉRIFIER » évite l'incohérence d'un fichier qui déclenche une
règle faible mais serait affiché « PROPRE ».

---

## 7. Génération de rapports

Deux formats sont proposés (`reporting.py`), tous deux enrichis de
l'**empreinte SHA-256** de chaque fichier — standard d'identification
d'échantillon en analyse de malware (corrélation VirusTotal, MalwareBazaar…).

- **JSON** : rapport structuré (métadonnées de scan, puis par fichier :
  hash, score, risque, verdict, détections détaillées avec offsets).
- **CSV** : une ligne par détection, exploitable dans un tableur.

---

## 8. Interfaces

### 8.1 CLI

L'entrée principale (`scanner.py`) est un orchestrateur léger offrant :
`--scan`, `--rules` (base personnalisée), `--min-severity` (filtre de bruit),
`--report json|csv`, `--list-rules`, `--no-entropy`, `--ml`, `--version`.

Le scanner renvoie le **code de sortie 1** si une menace est détectée, `0`
sinon : il est directement intégrable dans un pipeline d'intégration continue.

### 8.2 Interface web (Flask, optionnelle)

L'interface web va au-delà d'un simple scan one-shot :

- **Upload multiple, dossier ou archive `.zip`** : scan d'un projet entier en
  une fois. L'extraction ZIP est **strictement statique et sécurisée**
  (protection anti path-traversal, plafonds de taille décompressée et de
  nombre de membres) — les fichiers sont lus, jamais exécutés.
- **Score ML par fichier** affiché dans les résultats (cohérent avec `--ml`).
- **Historique persistant (SQLite)** : chaque scan est enregistré (module
  `core/history.py`) et consultable via la page `/history` (vue détail
  rejouable, suppression). Le dossier d'upload est purgé avant chaque scan.
- **Tableau de bord** (`/dashboard`) : graphiques agrégés (détections par
  sévérité et catégorie, verdicts, top des règles déclenchées).

La couche de données comporte deux tables : `scans` (synthèse + détail
sérialisé pour rejouer l'affichage) et `detections` (une ligne par détection,
pour les agrégations rapides du tableau de bord).

---

## 9. Déploiement

L'application est packagée pour un déploiement automatisé et reproductible.

- **Serveur WSGI de production** : le serveur intégré de Flask
  (`app.run(debug=True)`) est réservé au développement. En production,
  l'application est servie par **waitress** (`wsgi.py`), serveur WSGI pur
  Python **multi-plateforme**.
- **Conteneurisation Docker** : `Dockerfile` + `docker-compose.yml` permettent
  un déploiement en une commande (`docker compose up -d`). L'historique SQLite
  est persisté via un volume.
- **Publication automatique** : un workflow GitHub Actions construit l'image et
  la publie sur GitHub Container Registry (GHCR) à chaque push et tag de version.

### Différences Windows / Linux

Le déploiement natif diffère selon le système : sous Linux on utilise
`gunicorn` + `systemd`, sous Windows `waitress` + un service (NSSM ou tâche
planifiée) ; l'encodage console (UTF-8 vs cp1252) et les fins de ligne
(LF vs CRLF) divergent aussi. **La conteneurisation neutralise ces
différences** : le conteneur s'exécute sous Linux quelle que soit la machine
hôte, donc une seule configuration de déploiement suffit.

---

## 10. Qualité, tests et intégration continue

### 10.1 Suite de tests

**54 tests** pytest couvrent :

- **non-régression détection** : zéro faux positif sur `clean/`, 100 % de
  détection sur `malicious/` ;
- **chargement des règles** : dossier absent/vide, règle YARA invalide ;
- **rapports et hachage** : SHA-256, verdict de bout en bout, colonnes CSV ;
- **filtrage CLI** par sévérité ;
- **persistance** : enregistrement, relecture, agrégations et suppression de
  l'historique (base SQLite temporaire isolée) ;
- **features et ML** (ces derniers ignorés si scikit-learn est absent).

### 10.2 Intégration continue

Un workflow **GitHub Actions** exécute la suite de tests sur Python 3.10, 3.11
et 3.12 à chaque push, et vérifie les codes de sortie (clean = 0, malicious
≠ 0). Comme la CI n'installe pas les dépendances optionnelles, elle valide
aussi que l'outil fonctionne **sans** scikit-learn. Un second workflow
construit et publie l'image Docker.

---

## 11. Limites et perspectives

- **Dataset réduit** : les performances ML sont démonstratives ; un dataset
  plus large et diversifié améliorerait la généralisation.
- **Signatures statiques** : comme tout outil à base de règles, il peut être
  contourné par de l'obfuscation avancée ou du polymorphisme — d'où l'intérêt
  des couches entropie et ML en complément.
- **Pistes d'évolution** : extraction de features syntaxiques (AST) sans
  exécution, extension du jeu de règles, export d'un rapport HTML autonome,
  authentification pour un usage multi-utilisateurs.

---

## 12. Conclusion

L'outil répond à l'objectif : un analyseur statique modulaire, testé et
documenté, combinant **trois approches complémentaires** de détection (règles
YARA, statistique par entropie, apprentissage automatique) tout en respectant
la contrainte fondamentale de **ne jamais exécuter** le code analysé. Son
architecture en couches, sa couverture de tests et son intégration continue en
font une base saine et défendable en soutenance.

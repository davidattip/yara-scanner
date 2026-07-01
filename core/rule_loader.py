"""
Chargement et compilation des règles YARA.

Ce module isole toute la logique liée à la base de règles :
  - recherche des fichiers .yar,
  - compilation via yara-python,
  - collecte des noms de règles et des éventuelles erreurs.

Aucun affichage ici : les avertissements sont renvoyés à l'appelant,
qui décide comment les présenter (CLI, web, tests…).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yara
except ImportError:  # pragma: no cover - dépendance obligatoire
    print("\n[ERREUR] La librairie yara-python n'est pas installée.")
    print("         Installe-la avec : pip install yara-python")
    sys.exit(1)


@dataclass
class LoadedRules:
    """Résultat du chargement de la base de règles YARA."""

    compiled_rules: list[tuple[str, "yara.Rules"]] = field(default_factory=list)
    rule_files: list[str] = field(default_factory=list)
    # Noms de règles par fichier : {"obfuscation.yar": ["Base64_Exec_Pattern", ...]}
    rules_by_file: dict[str, list[str]] = field(default_factory=dict)
    # Avertissements non bloquants : [(nom_fichier, message), ...]
    warnings: list[tuple[str, str]] = field(default_factory=list)

    @property
    def total_rules_count(self) -> int:
        """Nombre total de règles chargées, calculé via l'API YARA."""
        return sum(len(names) for names in self.rules_by_file.values())


def _extract_rule_names(compiled: "yara.Rules") -> list[str]:
    """
    Extrait les noms de règles depuis un objet compilé via l'API YARA.

    Plus fiable que de parser le texte : yara-python expose directement
    l'identifiant de chaque règle compilée.
    """
    return [rule.identifier for rule in compiled]


def load_rules(rules_dir: str) -> LoadedRules:
    """
    Charge et compile tous les fichiers .yar d'un dossier.

    Args:
        rules_dir: chemin du dossier contenant les règles YARA.

    Returns:
        Un objet `LoadedRules`. Les erreurs de compilation d'un fichier
        n'interrompent pas le chargement des autres : elles sont collectées
        dans `warnings`.

    Raises:
        FileNotFoundError: si le dossier de règles n'existe pas.
        ValueError: si aucun fichier .yar n'est trouvé.
    """
    result = LoadedRules()

    rules_path = Path(rules_dir)
    if not rules_path.is_dir():
        raise FileNotFoundError(f"Dossier de règles introuvable : {rules_dir}")

    yar_files = sorted(rules_path.glob("*.yar"))
    if not yar_files:
        raise ValueError(f"Aucun fichier .yar trouvé dans {rules_dir}")

    for yar_file in yar_files:
        try:
            compiled = yara.compile(filepath=str(yar_file))
            names = _extract_rule_names(compiled)

            result.compiled_rules.append((yar_file.name, compiled))
            result.rule_files.append(yar_file.name)
            result.rules_by_file[yar_file.name] = names

        except yara.SyntaxError as exc:
            result.warnings.append(
                (yar_file.name, f"Erreur de syntaxe YARA : {exc}")
            )
        except OSError as exc:
            result.warnings.append(
                (yar_file.name, f"Fichier illisible : {exc}")
            )

    return result

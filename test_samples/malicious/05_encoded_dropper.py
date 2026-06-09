# FICHIER DE TEST - Dropper avec encodage XOR simulé
# Ce fichier est un EXEMPLE pour tester la détection YARA

import base64
import zlib

# Payload doublement encodé (base64 + compression)
encoded = "eJzLSM3JyVcozy/KSQEAGgsEHQ=="
payload = zlib.decompress(base64.b64decode(encoded))
exec(payload.decode("utf-8"))

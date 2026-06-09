# FICHIER DE TEST - Script malveillant simulé
# Ce fichier est un EXEMPLE pour tester la détection YARA
# Il ne fait rien de dangereux, c'est juste du texte

import base64
import os

# Payload encodé en base64 (simulé)
encoded_payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gSGVsbG8gV29ybGQnKQ=="
decoded = base64.b64decode(encoded_payload)
exec(decoded)

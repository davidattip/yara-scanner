# FICHIER DE TEST - Obfuscation par chr() simulée
# Ce fichier est un EXEMPLE pour tester la détection YARA

# Construction caractère par caractère pour masquer "import os"
hidden = chr(105) + chr(109) + chr(112) + chr(111) + chr(114) + chr(116)
module = chr(111) + chr(115)
command = chr(115) + chr(121) + chr(115) + chr(116) + chr(101) + chr(109)

# exec(hidden + " " + module)

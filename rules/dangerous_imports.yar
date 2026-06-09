/*
    Règle YARA : Détection d'imports dangereux
    Auteur : David ATTIPOUPOU
    Description : Détecte les combinaisons d'imports qui suggèrent
                  une activité malveillante dans les scripts Python.
*/

rule Keylogger_Pattern
{
    meta:
        description = "Detecte les patterns typiques d'un keylogger Python"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "dangerous_imports"

    strings:
        $pynput = "from pynput" nocase
        $keyboard = "pynput.keyboard" nocase
        $listener = "Listener(" nocase
        $on_press = "on_press" nocase
        $log_file = /open\(.+,\s*['"]a['"]\)/

    condition:
        ($pynput or $keyboard) and ($listener or $on_press) and $log_file
}

rule Data_Exfiltration_Pattern
{
    meta:
        description = "Detecte des patterns d'exfiltration de donnees (lecture fichiers + envoi reseau)"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "dangerous_imports"

    strings:
        $import_requests = "import requests" nocase
        $import_urllib = "import urllib" nocase
        $import_http = "import http.client" nocase
        $read_file = /open\(.+\)\.read\(\)/
        $glob = "import glob" nocase
        $walk = "os.walk" nocase
        $post = "requests.post" nocase
        $send = ".send(" nocase

    condition:
        ($import_requests or $import_urllib or $import_http) and
        ($read_file or $glob or $walk) and
        ($post or $send)
}

rule Credential_Theft_Pattern
{
    meta:
        description = "Detecte la lecture de fichiers sensibles (mots de passe, cookies, clefs SSH)"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "dangerous_imports"

    strings:
        $chrome_cookies = "Cookies" nocase
        $chrome_login = "Login Data" nocase
        $ssh_key = ".ssh/id_rsa" nocase
        $shadow = "/etc/shadow" nocase
        $passwd = "/etc/passwd" nocase
        $wallet = "wallet.dat" nocase
        $env_file = ".env" nocase
        $aws_creds = ".aws/credentials" nocase

    condition:
        any of them and filesize < 50KB
}

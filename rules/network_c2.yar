/*
    Règle YARA : Détection de communications Command & Control (C2)
    Auteur : David ATTIPOUPOU
    Description : Détecte les patterns réseau caractéristiques d'un implant C2 :
                  beaconing HTTP périodique, tunneling DNS, socket brute.
*/

rule HTTP_Beaconing
{
    meta:
        description = "Detecte un beaconing HTTP periodique (boucle infinie + sleep + requete reseau)"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "network_c2"

    strings:
        $sleep        = "time.sleep" nocase
        $while_true   = "while True" nocase
        $while_1      = "while 1:" nocase
        $req_get      = "requests.get(" nocase
        $req_post     = "requests.post(" nocase
        $urllib_open  = "urllib.request.urlopen" nocase

    condition:
        ($while_true or $while_1) and $sleep and
        ($req_get or $req_post or $urllib_open)
}

rule DNS_Tunneling
{
    meta:
        description = "Detecte un usage suspect de DNS pour exfiltrer des donnees (DNS tunneling)"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "network_c2"

    strings:
        $dns_resolver  = "dns.resolver" nocase
        $dns_import    = "import dns" nocase
        $from_dns      = "from dns" nocase
        $socket_dns    = "socket.gethostbyname" nocase
        $b64_in_dns    = /base64.*decode.*gethostbyname/ nocase

    condition:
        ($dns_import or $from_dns) and ($dns_resolver or $socket_dns or $b64_in_dns)
}

rule Raw_Socket_C2
{
    meta:
        description = "Detecte une connexion socket brute vers une IP distante (pattern implant C2)"
        author = "David ATTIPOUPOU"
        severity = "MEDIUM"
        category = "network_c2"

    strings:
        $import_socket = "import socket" nocase
        $connect       = ".connect((" nocase
        $recv          = ".recv(" nocase
        $send          = ".send(" nocase
        $raw_ip        = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

    condition:
        $import_socket and $connect and ($recv or $send) and $raw_ip
}

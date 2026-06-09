/*
    Règle YARA : Détection de cryptominage non autorisé
    Auteur : David ATTIPOUPOU
    Description : Détecte les scripts qui exploitent les ressources CPU/GPU
                  de la victime pour miner des cryptomonnaies.
*/

rule Mining_Pool_Connection
{
    meta:
        description = "Detecte une connexion a un pool de minage via le protocole Stratum"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "cryptomining"

    strings:
        $stratum     = "stratum+" nocase
        $stratum_tcp = "stratum+tcp://" nocase
        $xmrig       = "xmrig" nocase
        $minexmr     = "minexmr" nocase
        $monero_pool = /pool\.(monero|xmr)/ nocase
        $nanopool    = "nanopool.org" nocase

    condition:
        any of them
}

rule CPU_Exhaustion_Mining
{
    meta:
        description = "Detecte un minage local par force brute sur tous les coeurs CPU"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "cryptomining"

    strings:
        $hashlib         = "import hashlib" nocase
        $multiprocessing = "import multiprocessing" nocase
        $cpu_count       = "cpu_count()" nocase
        $while_mine      = "while True" nocase
        $proof_of_work   = "proof_of_work" nocase
        $nonce           = "nonce" nocase

    condition:
        $hashlib and $multiprocessing and $cpu_count and
        ($while_mine or $proof_of_work or $nonce)
}

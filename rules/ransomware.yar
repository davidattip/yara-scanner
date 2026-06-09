/*
    Règle YARA : Détection de comportements ransomware
    Auteur : David ATTIPOUPOU
    Description : Détecte les patterns caractéristiques d'un ransomware :
                  boucle de chiffrement, note de rançon, suppression des sauvegardes.
*/

rule File_Encryption_Loop
{
    meta:
        description = "Detecte une boucle de chiffrement de fichiers (pattern ransomware)"
        author = "David ATTIPOUPOU"
        severity = "CRITICAL"
        category = "ransomware"

    strings:
        $walk         = "os.walk" nocase
        $glob_glob    = "glob.glob" nocase
        $cipher_aes   = "AES" nocase
        $cipher_fernet = "Fernet" nocase
        $encrypt_call = "encrypt(" nocase
        $write_bin    = /open\(.+,\s*['"]wb['"]\)/
        $rename       = ".rename(" nocase

    condition:
        ($walk or $glob_glob) and
        ($cipher_aes or $cipher_fernet or $encrypt_call) and
        ($write_bin or $rename)
}

rule Ransom_Note_Creation
{
    meta:
        description = "Detecte la creation d'un fichier de rancon avec demande de paiement"
        author = "David ATTIPOUPOU"
        severity = "CRITICAL"
        category = "ransomware"

    strings:
        $readme   = "README" nocase
        $ransom   = "ransom" nocase
        $decrypt  = "decrypt" nocase
        $bitcoin  = "bitcoin" nocase
        $btc      = "BTC"
        $wallet   = "wallet" nocase
        $payment  = "payment" nocase
        $write_w  = /open\(.+,\s*['"]w['"]\)/

    condition:
        $write_w and ($readme or $ransom) and
        ($bitcoin or $btc or $wallet or $payment or $decrypt)
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Detecte la suppression des cliches instantanes Windows (technique anti-recovery)"
        author = "David ATTIPOUPOU"
        severity = "CRITICAL"
        category = "ransomware"

    strings:
        $vssadmin  = "vssadmin delete shadows" nocase
        $wmic      = "wmic shadowcopy delete" nocase
        $bcdedit   = "bcdedit /set {default} recoveryenabled no" nocase
        $wbadmin   = "wbadmin delete catalog" nocase

    condition:
        any of them
}

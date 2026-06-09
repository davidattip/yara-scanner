/*
    Règle YARA : Détection de techniques d'encodage malveillant
    Auteur : David ATTIPOUPOU
    Description : Détecte les techniques d'encodage utilisées pour
                  dissimuler du code malveillant dans les scripts.
*/

rule Base64_Encoded_Payload
{
    meta:
        description = "Detecte une longue chaine base64 suspecte (potentiel payload encode)"
        author = "David ATTIPOUPOU"
        severity = "MEDIUM"
        category = "encoding"

    strings:
        $long_b64 = /[A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        $long_b64
}

rule ROT13_Obfuscation
{
    meta:
        description = "Detecte l'utilisation de ROT13 pour masquer du code"
        author = "David ATTIPOUPOU"
        severity = "LOW"
        category = "encoding"

    strings:
        $codecs_rot13 = "codecs.decode" nocase
        $rot_13 = "'rot_13'" nocase
        $rot13 = "'rot13'" nocase
        $maketrans = "str.maketrans" nocase

    condition:
        ($codecs_rot13 and ($rot_13 or $rot13)) or
        ($maketrans and ($rot_13 or $rot13))
}

rule XOR_Encoding
{
    meta:
        description = "Detecte un pattern de chiffrement XOR utilise pour masquer du code"
        author = "David ATTIPOUPOU"
        severity = "MEDIUM"
        category = "encoding"

    strings:
        $xor_loop = /for\s+\w+\s+in\s+.*:\s*\n\s*.*\^/
        $xor_lambda = /lambda\s+\w+\s*:\s*.*\^/
        $xor_bytes = /bytes\(\[?\s*\w+\s*\^\s*\w+/
        $xor_chr = /chr\(\s*ord\(\w+\)\s*\^\s*\d+/

    condition:
        any of them
}

rule Eval_With_Decode
{
    meta:
        description = "Detecte l'utilisation d'eval/exec avec un decodage (pattern de dropper)"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "encoding"

    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $decode = ".decode(" nocase
        $decompress = "zlib.decompress" nocase
        $b64 = "b64decode" nocase
        $unquote = "urllib.parse.unquote" nocase

    condition:
        ($eval or $exec) and ($decode or $decompress or $b64 or $unquote)
}

/*
    Règle YARA : Détection d'obfuscation de code
    Auteur : David ATTIPOUPOU
    Description : Détecte les techniques courantes d'obfuscation
                  utilisées dans les scripts malveillants Python.
*/

rule Base64_Exec_Pattern
{
    meta:
        description = "Detecte un script qui decode du base64 puis execute le resultat"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "obfuscation"

    strings:
        $b64_import = "import base64" nocase
        $b64_decode = "base64.b64decode" nocase
        $b64_b64 = "b64decode" nocase
        $exec_call = "exec(" nocase
        $eval_call = "eval(" nocase

    condition:
        ($b64_import or $b64_decode or $b64_b64) and ($exec_call or $eval_call)
}

rule Chr_Obfuscation
{
    meta:
        description = "Detecte la construction de chaines via chr() pour masquer du code"
        author = "David ATTIPOUPOU"
        severity = "MEDIUM"
        category = "obfuscation"

    strings:
        $chr_chain = /chr\(\d+\)\s*\+\s*chr\(\d+\)\s*\+\s*chr\(\d+\)/

    condition:
        #chr_chain > 2
}

rule Hex_String_Obfuscation
{
    meta:
        description = "Detecte l'utilisation de chaines hexadecimales pour masquer du code"
        author = "David ATTIPOUPOU"
        severity = "MEDIUM"
        category = "obfuscation"

    strings:
        $hex_decode = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){5,}/
        $fromhex = ".fromhex(" nocase
        $bytes_fromhex = "bytes.fromhex" nocase

    condition:
        $hex_decode or $fromhex or $bytes_fromhex
}

rule Compile_Exec_Pattern
{
    meta:
        description = "Detecte l'utilisation de compile() suivie de exec() pour executer du code dynamique"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "obfuscation"

    strings:
        $compile = "compile(" nocase
        $exec = "exec(" nocase
        $marshal = "marshal.loads" nocase

    condition:
        ($compile and $exec) or $marshal
}

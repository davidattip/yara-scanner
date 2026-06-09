/*
    Règle YARA : Détection de reverse shells
    Auteur : David ATTIPOUPOU
    Description : Détecte les patterns caractéristiques de reverse shells
                  dans les scripts Python, Bash et PowerShell.
*/

rule Python_Reverse_Shell
{
    meta:
        description = "Detecte un reverse shell Python classique (socket + subprocess + connect)"
        author = "David ATTIPOUPOU"
        severity = "CRITICAL"
        category = "reverse_shell"

    strings:
        $import_socket = "import socket" nocase
        $import_subprocess = "import subprocess" nocase
        $import_os = "import os" nocase
        $connect = ".connect((" nocase
        $popen = "subprocess.Popen" nocase
        $call = "subprocess.call" nocase
        $dup2 = "os.dup2" nocase
        $bin_sh = "/bin/sh" nocase
        $bin_bash = "/bin/bash" nocase
        $cmd_exe = "cmd.exe" nocase

    condition:
        $import_socket and $connect and
        (($import_subprocess and ($popen or $call)) or ($import_os and $dup2)) and
        ($bin_sh or $bin_bash or $cmd_exe)
}

rule Bash_Reverse_Shell
{
    meta:
        description = "Detecte un reverse shell Bash (redirection vers /dev/tcp)"
        author = "David ATTIPOUPOU"
        severity = "CRITICAL"
        category = "reverse_shell"

    strings:
        $dev_tcp = "/dev/tcp/" nocase
        $bash_i = "bash -i" nocase
        $nc_exec = /nc\s+(-e|-c)\s+\/bin\/(sh|bash)/
        $ncat = /ncat\s.*(-e|-c)\s+\/bin\/(sh|bash)/
        $mkfifo = "mkfifo" nocase

    condition:
        ($dev_tcp and $bash_i) or $nc_exec or $ncat or ($mkfifo and $dev_tcp)
}

rule PowerShell_Reverse_Shell
{
    meta:
        description = "Detecte un reverse shell PowerShell"
        author = "David ATTIPOUPOU"
        severity = "CRITICAL"
        category = "reverse_shell"

    strings:
        $tcp_client = "Net.Sockets.TCPClient" nocase
        $ps_stream = "GetStream()" nocase
        $ps_invoke = "Invoke-Expression" nocase
        $ps_iex = "IEX(" nocase
        $ps_download = "DownloadString(" nocase
        $ps_webclient = "Net.WebClient" nocase
        

    condition:
        ($tcp_client and $ps_stream) or
        (($ps_invoke or $ps_iex) and ($ps_download or $ps_webclient))
}

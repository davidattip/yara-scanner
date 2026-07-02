# Script legitime - Sauvegarde de dossiers vers une archive datee
# Ce fichier ne devrait PAS declencher d'alerte YARA.
# Administration systeme courante : compression + rotation des sauvegardes.

param(
    [string]$Source = "C:\Data",
    [string]$Destination = "D:\Backups"
)

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message"
}

if (-not (Test-Path $Destination)) {
    New-Item -ItemType Directory -Path $Destination | Out-Null
}

$date = Get-Date -Format "yyyyMMdd_HHmmss"
$archive = Join-Path $Destination "backup_$date.zip"

Write-Log "Compression de $Source vers $archive"
Compress-Archive -Path $Source -DestinationPath $archive -CompressionLevel Optimal

# Rotation : on ne garde que les 7 sauvegardes les plus recentes.
$backups = Get-ChildItem -Path $Destination -Filter "backup_*.zip" |
    Sort-Object LastWriteTime -Descending

if ($backups.Count -gt 7) {
    $backups | Select-Object -Skip 7 | ForEach-Object {
        Write-Log "Suppression de l'ancienne sauvegarde $($_.Name)"
        Remove-Item $_.FullName
    }
}

Write-Log "Sauvegarde terminee avec succes."

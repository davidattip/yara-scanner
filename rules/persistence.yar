/*
    Règle YARA : Détection de mécanismes de persistance
    Auteur : David ATTIPOUPOU
    Description : Détecte les techniques utilisées pour maintenir un accès
                  persistant sur un système (registre, crontab, startup).
*/

rule Registry_Persistence
{
    meta:
        description = "Detecte une tentative de persistance via le registre Windows (clef Run)"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "persistence"

    strings:
        $run_key    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $runonce    = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $winreg     = "import winreg" nocase
        $reg_set    = "SetValueEx" nocase
        $reg_open   = "OpenKey" nocase

    condition:
        ($winreg or $reg_open or $reg_set) and ($run_key or $runonce)
}

rule Crontab_Persistence
{
    meta:
        description = "Detecte une modification de crontab ou des repertoires cron.d pour persister"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "persistence"

    strings:
        $crontab_l     = "crontab -l" nocase
        $crontab_write = /crontab\s+-/ nocase
        $etc_cron      = "/etc/cron.d/" nocase
        $cron_hourly   = "/etc/cron.hourly/" nocase
        $cron_daily    = "/etc/cron.daily/" nocase

    condition:
        any of them
}

rule Startup_Script_Persistence
{
    meta:
        description = "Detecte une ecriture dans un dossier ou fichier de demarrage automatique"
        author = "David ATTIPOUPOU"
        severity = "HIGH"
        category = "persistence"

    strings:
        $startup_win  = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" nocase
        $bashrc       = ".bashrc" nocase
        $bash_profile = ".bash_profile" nocase
        $zshrc        = ".zshrc" nocase
        $profile      = "/.profile" nocase
        $write_append = /open\(.+,\s*['"]a['"]\)/

    condition:
        ($startup_win or $bashrc or $bash_profile or $zshrc or $profile) and $write_append
}

#!/bin/bash
# Script legitime - Deploiement d'une application web
# Ce fichier ne devrait PAS declencher d'alerte YARA.
# Operations d'integration continue classiques.

set -euo pipefail

APP_DIR="/var/www/monapp"
BRANCH="main"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

log "Recuperation des dernieres modifications ($BRANCH)"
cd "$APP_DIR"
git fetch origin
git checkout "$BRANCH"
git pull origin "$BRANCH"

log "Installation des dependances"
npm ci --production

log "Construction des assets"
npm run build

log "Redemarrage du service applicatif"
systemctl restart monapp.service

log "Verification de l'etat du service"
systemctl is-active monapp.service

log "Deploiement termine."

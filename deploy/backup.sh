#!/bin/bash
# Ежедневная копия базы. Добавьте в cron root:
#   15 3 * * *  /opt/registry/deploy/backup.sh
set -euo pipefail
DEST=/var/backups/registry
mkdir -p "$DEST"
sqlite3 /opt/registry/instance/registry.db ".backup '$DEST/registry-$(date +%F).db'"
# храним 30 последних копий
ls -1t "$DEST"/registry-*.db | tail -n +31 | xargs -r rm --

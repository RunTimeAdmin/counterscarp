#!/bin/bash
# Backup Counterscarp data stores (users.json, licenses.json, audit_log.jsonl)
#
# Usage: ./scripts/backup_data.sh
# Cron example (daily at 02:00):
#   0 2 * * * /opt/counterscarp-engine/scripts/backup_data.sh >> /var/log/counterscarp-backup.log 2>&1
#
# Environment overrides:
#   BACKUP_DIR   Destination directory (default: /opt/counterscarp-engine/backups)
#   DATA_DIR     Source data directory  (default: /opt/counterscarp-engine/data)
#   KEEP_DAYS    Retention period in days (default: 30)

set -euo pipefail

BACKUP_DIR="${BACKUP_DIR:-/opt/counterscarp-engine/backups}"
DATA_DIR="${DATA_DIR:-/opt/counterscarp-engine/data}"
KEEP_DAYS="${KEEP_DAYS:-30}"

if [ ! -d "$DATA_DIR" ]; then
    echo "[backup] ERROR: DATA_DIR does not exist: $DATA_DIR" >&2
    exit 1
fi

mkdir -p "$BACKUP_DIR"

TIMESTAMP=$(date -u +%Y%m%d_%H%M%SZ)
BACKUP_FILE="$BACKUP_DIR/counterscarp_data_${TIMESTAMP}.tar.gz"

tar -czf "$BACKUP_FILE" \
    --exclude="*.tmp" \
    -C "$(dirname "$DATA_DIR")" \
    "$(basename "$DATA_DIR")"

echo "[backup] Created: $BACKUP_FILE ($(du -sh "$BACKUP_FILE" | cut -f1))"

# Remove backups older than KEEP_DAYS
find "$BACKUP_DIR" -name "counterscarp_data_*.tar.gz" -mtime +"$KEEP_DAYS" -delete
echo "[backup] Retention: removed backups older than ${KEEP_DAYS} days"

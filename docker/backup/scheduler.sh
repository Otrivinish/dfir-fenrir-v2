#!/bin/sh
# DFIR-FENRIR v2 — backup scheduler (container entrypoint).
#
# Runs backup.sh whenever the last SUCCESSFUL run is more than 23 h old, checked
# every hour. The old loop slept 24 h *before* its first run, so every restart
# reset the clock and backups silently stopped (2026-09 finding). With this loop
# a restart can never skip a day, and a missing marker triggers a run at once.
set -u

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# Shared /backups: root owns it, the backend's group (1001) may write, setgid keeps
# new files in that group and the sticky bit stops either side deleting the
# other's files. Only touch it when wrong — chmod without CAP_FSETID would
# silently clear setgid once capabilities are dropped.
if [ "$(stat -c '%u:%g %a' /backups)" != "0:1001 3770" ]; then
    chown root:1001 /backups && chmod 3770 /backups \
        && echo "[$(ts)] fixed /backups ownership/mode → root:1001 3770"
fi

while true; do
    # .last_success mtime is the schedule: missing or older than 23 h (1380 min) → run.
    if [ -z "$(find /backups/.last_success -mmin -1380 2>/dev/null)" ]; then
        sh /usr/local/bin/backup.sh || echo "[$(ts)] ERROR: backup run failed — retrying next hour"
    fi
    sleep 3600
done

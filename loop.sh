#!/bin/bash
cd /var/www/dashboard.plainsightsecurity.co.uk
while true; do
  php scripts/sync_knowledge_base.php
  STATUS=$(mysql -u root vulndash -N -e "SELECT JSON_EXTRACT(state_json, '\$.backfill_complete') FROM sync_state WHERE sync_type='knowledge_base';")
  if [ "$STATUS" = "true" ]; then
    echo "Backfill complete."
    break
  fi
  sleep 2
done

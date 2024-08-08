#!/bin/bash

SCRIPT_LOG="~/fluent/script_output.log"

declare -A LOG_FILES
LOG_FILES["cowrie"]="/var/lib/docker/volumes/cowrie-var/_data/log/cowrie/cowrie.json"
LOG_FILES["honeytrap"]="/var/lib/docker/volumes/honeytrap/_data/honeytrap.log"
LOG_FILES["elasticpot"]="/var/lib/docker/volumes/elasticpot/_data/elasticpot.json"
LOG_FILES["rdpy"]="/var/lib/docker/volumes/rdpy/_data/rdpy.log"
LOG_FILES["ews"]="~/ewsposter_data/json/ews.json"
LOG_FILES["dionaea"]="/var/lib/docker/volumes/dionaea/_data/var/lib/dionaea/dionaea.json"
LOG_FILES["conpot"]="/var/lib/docker/volumes/conpot/_data/conpot.json"

TEMP_LOG_DIR="/home/intelnuc/fluent/tmplog"
OFFSET_DIR="/home/intelnuc/fluent/offset"
mkdir -p $TEMP_LOG_DIR
mkdir -p $OFFSET_DIR

check_fluentd() {
  ps aux | grep -v grep | grep -q fluentd
  STATUS=$?
  return $STATUS
}

save_logs_to_temp() {
  if ! check_fluentd; then
    echo "[$(date)] Fluentd is inactive. Preparing to process logs..." >> $SCRIPT_LOG
    for HONEYPOT in "${!LOG_FILES[@]}"; do
      LOG_FILE=${LOG_FILES[$HONEYPOT]}
      TEMP_LOG_FILE="$TEMP_LOG_DIR/${HONEYPOT}_temp.json"
      OFFSET_FILE="$OFFSET_DIR/${HONEYPOT}.offset"

      if [ -f $OFFSET_FILE ]; then
        OFFSET=$(cat $OFFSET_FILE)
      else
        OFFSET=0
      fi

      CURRENT_COUNT=$(jq -c '.' $LOG_FILE | wc -l)
      if [ $CURRENT_COUNT -gt $OFFSET ]; then
        jq -c '.' $LOG_FILE | tail -n +$((OFFSET + 1)) > $TEMP_LOG_FILE
        echo "[$(date)] New data from $LOG_FILE saved to $TEMP_LOG_FILE." >> $SCRIPT_LOG
      else
        echo "[$(date)] No new data for $HONEYPOT." >> $SCRIPT_LOG
      fi

      echo $CURRENT_COUNT > $OFFSET_FILE
    done
  else
    echo "[$(date)] Fluentd is active. Starting to append temporary logs to the main logs." >> $SCRIPT_LOG
    for HONEYPOT in "${!LOG_FILES[@]}"; do
      LOG_FILE=${LOG_FILES[$HONEYPOT]}
      TEMP_LOG_FILE="$TEMP_LOG_DIR/${HONEYPOT}_temp.json"
      if [ -s $TEMP_LOG_FILE ]; then
        echo "[$(date)] Appending data from $TEMP_LOG_FILE to $LOG_FILE..." >> $SCRIPT_LOG
        cat $TEMP_LOG_FILE >> $LOG_FILE
        echo "[$(date)] Data appended successfully." >> $SCRIPT_LOG
        > $TEMP_LOG_FILE
      fi
    done
  fi
}

process_logs() {
  save_logs_to_temp
}

process_logs


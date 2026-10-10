#!/bin/bash
mkdir -p /data/tgapi /data/apps

# ئەگەر API_ID و API_HASH دانرابێت ← فایلی گەورە (تا 4GB) چالاک دەبێت
if [ -n "$API_ID" ] && [ -n "$API_HASH" ] && [ -n "$BOT_TOKEN" ]; then
  FLAG="/data/.loggedout_$(echo -n "$BOT_TOKEN" | md5sum | cut -c1-8)"
  if [ ! -f "$FLAG" ]; then
    curl -s "https://api.telegram.org/bot$BOT_TOKEN/logOut"; echo
    touch "$FLAG"
    sleep 2
  fi
  telegram-bot-api --local --api-id="$API_ID" --api-hash="$API_HASH" \
    --http-port=8081 --dir=/data/tgapi &
  sleep 3
  export LOCAL_API="http://127.0.0.1:8081"
fi

exec /venv/bin/python bot.py

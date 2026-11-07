#!/bin/sh
# Запуск cron и веб-приложения в одном контейнере.
set -e

# Восстанавливаем задание cron из текущего состояния (на случай пересборки).
python -c "from app.cron import sync_cron; sync_cron()" || true

# Демон cron в фоне.
cron || true

exec uvicorn app.main:app --host 0.0.0.0 --port 8090 --proxy-headers

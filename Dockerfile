# Менеджер сертификатов Let's Encrypt (DNS-01, ручные TXT-записи)
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DATA_DIR=/data

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates cron \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY entrypoint.sh ./entrypoint.sh

RUN chmod +x ./entrypoint.sh \
    && mkdir -p /data/certs /data/work /data/accounts /data/logs

EXPOSE 8090

CMD ["./entrypoint.sh"]

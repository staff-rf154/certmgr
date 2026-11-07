"""Создание задания cron для планового продления сертификатов."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from . import storage

log = logging.getLogger("certmgr.cron")

CRON_FILE = Path("/etc/cron.d/certmgr")
RENEW_TIME = os.environ.get("CERTMGR_CRON_TIME", "17 3").strip() or "17 3"


def has_issued_certificates() -> bool:
    state = storage.load_state()
    return any(
        entry.get("status") in {"issued", "expired"}
        for entry in state.get("certificates", {}).values()
    )


def sync_cron() -> bool:
    """Создать или удалить /etc/cron.d/certmgr в зависимости от состояния."""
    if not Path("/etc/cron.d").is_dir():
        return False
    file = CRON_FILE
    if not has_issued_certificates():
        try:
            file.unlink(missing_ok=True)
        except OSError:
            pass
        return False

    command = (
        f"{RENEW_TIME} * * root cd /app && "
        f"DATA_DIR={storage.DATA_DIR} RENEW_DAYS={os.environ.get('RENEW_DAYS', '30')} "
        f"ACME_POLL_SECONDS={os.environ.get('ACME_POLL_SECONDS', '180')} "
        f"/usr/local/bin/python -m app.renew >> {storage.LOGS_DIR}/renew.log 2>&1"
    )
    content = (
        "# Плановое продление сертификатов (управляется приложением certmgr)\n"
        + command
        + "\n"
    )
    try:
        file.write_text(content, encoding="utf-8")
        os.chmod(file, 0o644)
        os.chown(file, 0, 0)
        log.info("Задание cron обновлено: %s", file)
        return True
    except OSError as exc:
        log.warning("Не удалось записать задание cron: %s", exc)
        return False


def status() -> dict[str, object]:
    return {
        "enabled": CRON_FILE.is_file(),
        "path": str(CRON_FILE),
        "time": RENEW_TIME,
    }

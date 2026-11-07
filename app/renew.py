"""Плановое продление сертификатов (запускается cron).

При ручном DNS-01 продление тоже требует двух шагов: cron создаёт новый заказ
и публикует TXT-значения в интерфейсе, после чего нужно добавить записи в DNS
и нажать «Проверить и выпустить». Полностью автоматического продления без API
DNS-провайдера быть не может.
"""

from __future__ import annotations

import datetime as dt
import logging
import sys

from . import acme_service, cron, storage

log = logging.getLogger("certmgr.renew")


def _parse(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        result = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    return result


def run(only_domain: str | None = None) -> int:
    state = storage.load_state()
    now = acme_service.utcnow()
    renew_before = acme_service.renew_days()
    changed = 0

    for domain, entry in list(state.get("certificates", {}).items()):
        if only_domain and domain != only_domain:
            continue
        status = entry.get("status")
        if status == "issuing":
            continue

        if status == "pending_dns":
            order_expires = _parse(entry.get("order_expires_at"))
            if order_expires and order_expires < now:
                log.info("Заказ для %s истёк, создаём новый", domain)
                if _start(domain, entry, renewal=bool(entry.get("renewal"))):
                    changed += 1
            continue

        if status not in {"issued", "expired"}:
            continue

        expires = _parse(entry.get("expires_at"))
        if not expires:
            continue
        days = (expires - now).days
        if days > renew_before:
            continue

        log.info("Продление %s: осталось %s дн.", domain, days)
        if _start(domain, entry, renewal=True):
            changed += 1

    cron.sync_cron()
    state = storage.load_state()
    for domain, entry in state.get("certificates", {}).items():
        if entry.get("status") == "issued" and (acme_service.days_left(entry.get("expires_at")) or 0) < 0:
            with storage.mutate() as fresh:
                current = fresh["certificates"].get(domain)
                if current and current.get("status") == "issued":
                    current["status"] = "expired"
                    current["status_message"] = "Срок действия истёк"
                    current["updated_at"] = storage.utcnow()

    return changed


def _start(domain: str, entry: dict[str, object], renewal: bool) -> bool:
    try:
        certificate = acme_service.start_order(
            domain=domain,
            email=str(entry.get("email") or ""),
            include_wildcard=bool(entry.get("include_wildcard")),
            staging=bool(entry.get("staging")),
            renewal=renewal,
        )
    except Exception as exc:  # noqa: BLE001 — cron не должен падать целиком
        log.exception("Не удалось начать продление %s: %s", domain, exc)
        return False

    # Let's Encrypt может переиспользовать уже подтверждённые авторизации.
    # В этом случае TXT-записи не нужны и сертификат выпускается сразу.
    if certificate.get("status") == "pending_dns" and not certificate.get("challenges"):
        log.info("Авторизации для %s уже подтверждены, выпускаем сразу", domain)
        acme_service._run_complete(domain)  # noqa: SLF001 — внутренний сценарий cron
    return True


def main() -> int:
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    only = None
    if len(sys.argv) >= 3 and sys.argv[1] == "--domain":
        only = sys.argv[2]
    changed = run(only)
    log.info("Проверка продления завершена, запущено заказов: %s", changed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

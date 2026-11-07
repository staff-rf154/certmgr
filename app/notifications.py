"""Отправка email-уведомлений через SMTP."""

from __future__ import annotations

import html
import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import Any

from . import storage

log = logging.getLogger("certmgr.notify")

TIMEOUT = 20


def _recipient(entry: dict[str, Any], settings: dict[str, Any]) -> str:
    return str(entry.get("email") or settings.get("notify_to") or "").strip()


def _send(
    to: str,
    subject: str,
    text: str,
    html_body: str | None = None,
    settings: dict[str, Any] | None = None,
) -> bool:
    settings = settings if settings is not None else storage.load_smtp()
    if not settings.get("enabled"):
        log.info("Уведомления отключены, письмо «%s» не отправлено", subject)
        return False
    host = str(settings.get("host") or "").strip()
    username = str(settings.get("username") or "").strip()
    password = str(settings.get("password") or "")
    sender = str(settings.get("sender") or "").strip() or username
    recipient = (to or str(settings.get("notify_to") or "")).strip()
    if not host or not username or not password or not recipient:
        log.warning("SMTP настроен не полностью, письмо не отправлено")
        return False
    try:
        port = int(settings.get("port") or 465)
    except (TypeError, ValueError):
        port = 465

    message = EmailMessage()
    message["From"] = formataddr(("Certmgr", sender))
    message["To"] = recipient
    message["Subject"] = subject
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid()
    message.set_content(text)
    if html_body:
        message.add_alternative(html_body, subtype="html")

    context = ssl.create_default_context()
    if settings.get("use_ssl", True):
        server: smtplib.SMTP = smtplib.SMTP_SSL(
            host, port, timeout=TIMEOUT, context=context
        )
    else:
        server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        server.starttls(context=context)
    try:
        server.login(username, password)
        server.send_message(message)
    finally:
        try:
            server.quit()
        except Exception:  # noqa: BLE001
            pass
    log.info("Отправлено письмо «%s» на %s", subject, recipient)
    return True


def send_test(to: str) -> None:
    """Синхронная отправка тестового письма (для API). Ошибки пробрасываются."""
    settings = storage.load_smtp()
    if not settings.get("enabled"):
        raise RuntimeError("Уведомления отключены в настройках SMTP")
    text = (
        "Это тестовое письмо от Certmgr.\n\n"
        "Если вы его получили, значит SMTP настроен правильно.\n"
    )
    html_body = (
        "<h2>Certmgr</h2>"
        "<p>Это тестовое письмо. SMTP настроен правильно.</p>"
    )
    _send(to, "Certmgr: тестовое письмо", text, html_body, settings)


def _send_async(
    to: str,
    subject: str,
    text: str,
    html_body: str | None = None,
) -> None:
    def worker() -> None:
        try:
            _send(to, subject, text, html_body)
        except Exception as exc:  # noqa: BLE001 — уведомление не должно ломать выпуск
            log.exception("Не удалось отправить письмо «%s»: %s", subject, exc)

    threading.Thread(target=worker, name="smtp", daemon=True).start()


def _link(settings: dict[str, Any]) -> str:
    url = str(settings.get("public_url") or "").strip()
    if url:
        return f'\nВеб-интерфейс: {url}\n'
    return "\nОткройте веб-интерфейс Certmgr.\n"


def _records_rows(entry: dict[str, Any]) -> str:
    rows = []
    for item in entry.get("challenges") or []:
        rows.append(
            "<tr>"
            f"<td style=\"padding:6px 10px;border:1px solid #ddd\">{html.escape(str(item.get('record', '')))}</td>"
            f"<td style=\"padding:6px 10px;border:1px solid #ddd;font-family:monospace;word-break:break-all\">{html.escape(str(item.get('value', '')))}</td>"
            "</tr>"
        )
    if not rows:
        return ""
    return (
        '<table style="border-collapse:collapse;margin:12px 0">'
        "<tr><th style=\"padding:6px 10px;border:1px solid #ddd;text-align:left\">Имя TXT</th>"
        "<th style=\"padding:6px 10px;border:1px solid #ddd;text-align:left\">Значение</th></tr>"
        + "".join(rows)
        + "</table>"
    )


def notify_action_required(entry: dict[str, Any]) -> None:
    settings = storage.load_smtp()
    to = _recipient(entry, settings)
    if not to:
        return
    domain = str(entry.get("domain") or "")
    staging = " (staging)" if entry.get("staging") else ""
    subject = f"Certmgr: для {domain}{staging} нужны TXT-записи в DNS"
    records = entry.get("challenges") or []
    text_lines = [
        f"Для домена {domain}{staging} создан запрос сертификата Let's Encrypt.",
        "",
        "Добавьте в DNS следующие TXT-записи:",
        "",
    ]
    for item in records:
        text_lines.append(f"{item.get('record')}  TXT  {item.get('value')}")
    if not records:
        text_lines.append(
            "Авторизации уже подтверждены, дополнительные TXT-записи не нужны."
        )
        text_lines.append("Нажмите «Проверить и выпустить» в веб-интерфейсе.")
    text_lines.append(_link(settings))
    html_body = (
        f"<h2>Certmgr</h2>"
        f"<p>Для домена <b>{html.escape(domain)}</b>{html.escape(staging)} "
        "создан запрос сертификата Let's Encrypt.</p>"
        "<p>Добавьте в DNS следующие TXT-записи:</p>"
        f"{_records_rows(entry)}"
        "<p>После добавления нажмите «Проверить и выпустить» в веб-интерфейсе.</p>"
        + (f'<p><a href="{html.escape(str(settings.get("public_url") or ""))}">Открыть Certmgr</a></p>' if settings.get("public_url") else "")
    )
    _send_async(to, subject, "\n".join(text_lines), html_body)


def notify_issued(entry: dict[str, Any]) -> None:
    settings = storage.load_smtp()
    to = _recipient(entry, settings)
    if not to:
        return
    domain = str(entry.get("domain") or "")
    staging = " (staging)" if entry.get("staging") else ""
    expires = str(entry.get("expires_at") or "")
    subject = f"Certmgr: сертификат для {domain}{staging} выпущен"
    text = (
        f"Сертификат для {domain}{staging} успешно выпущен.\n\n"
        f"Действует до: {expires}\n"
        f"Файлы: fullchain.pem и privkey.pem в веб-интерфейсе.\n"
        f"{_link(settings)}"
    )
    html_body = (
        f"<h2>Certmgr</h2>"
        f"<p>Сертификат для <b>{html.escape(domain)}</b>{html.escape(staging)} "
        "успешно выпущен.</p>"
        f"<p>Действует до: <b>{html.escape(expires)}</b></p>"
        "<p>Файлы <code>fullchain.pem</code> и <code>privkey.pem</code> "
        "доступны в веб-интерфейсе.</p>"
        + (f'<p><a href="{html.escape(str(settings.get("public_url") or ""))}">Открыть Certmgr</a></p>' if settings.get("public_url") else "")
    )
    _send_async(to, subject, text, html_body)


def notify_error(entry: dict[str, Any], error: str) -> None:
    settings = storage.load_smtp()
    to = _recipient(entry, settings)
    if not to:
        return
    domain = str(entry.get("domain") or "")
    subject = f"Certmgr: ошибка выпуска сертификата для {domain}"
    text = (
        f"Не удалось выпустить сертификат для {domain}.\n\n"
        f"Ошибка: {error}\n"
        f"{_link(settings)}"
    )
    html_body = (
        f"<h2>Certmgr</h2>"
        f"<p>Не удалось выпустить сертификат для <b>{html.escape(domain)}</b>.</p>"
        f"<pre style=\"white-space:pre-wrap;background:#f6f6f6;padding:10px\">{html.escape(error)}</pre>"
        + (f'<p><a href="{html.escape(str(settings.get("public_url") or ""))}">Открыть Certmgr</a></p>' if settings.get("public_url") else "")
    )
    _send_async(to, subject, text, html_body)

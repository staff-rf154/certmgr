"""Хранение состояния, ключей и сертификатов.

Все изменяемые данные лежат в DATA_DIR (по умолчанию /data):
- state.json       — состояние сертификатов и аккаунтов ACME;
- accounts/        — приватные ключи аккаунтов ACME;
- certs/<домен>/   — выпущенные fullchain.pem и privkey.pem;
- work/<домен>/    — ключ и CSR текущего запроса;
- logs/            — журнал cron-продления;
- admin_password   — сгенерированный пароль, если он не задан в окружении.
"""

from __future__ import annotations

import fcntl
import json
import os
import secrets
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
STATE_FILE = DATA_DIR / "state.json"
SMTP_FILE = DATA_DIR / "smtp.json"
STATE_LOCK_FILE = DATA_DIR / "state.lock"
OPERATION_LOCK_FILE = DATA_DIR / "acme.lock"
CERTS_DIR = DATA_DIR / "certs"
WORK_DIR = DATA_DIR / "work"
ACCOUNTS_DIR = DATA_DIR / "accounts"
LOGS_DIR = DATA_DIR / "logs"

_thread_lock = threading.RLock()


class BusyError(RuntimeError):
    """Другая операция ACME уже выполняется."""


def _default_state() -> dict[str, Any]:
    return {"version": 1, "default_email": "", "accounts": {}, "certificates": {}}


def init_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for path in (CERTS_DIR, WORK_DIR, ACCOUNTS_DIR, LOGS_DIR):
        path.mkdir(parents=True, exist_ok=True)
    for path in (DATA_DIR, CERTS_DIR, WORK_DIR, ACCOUNTS_DIR, LOGS_DIR):
        try:
            path.chmod(0o700)
        except OSError:
            pass


def load_state() -> dict[str, Any]:
    init_dirs()
    if not STATE_FILE.exists():
        return _default_state()
    try:
        with STATE_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return _default_state()
    if not isinstance(data, dict):
        return _default_state()
    data.setdefault("version", 1)
    data.setdefault("default_email", "")
    data.setdefault("accounts", {})
    data.setdefault("certificates", {})
    if not isinstance(data["accounts"], dict):
        data["accounts"] = {}
    if not isinstance(data["certificates"], dict):
        data["certificates"] = {}
    return data


def save_state(state: dict[str, Any]) -> None:
    init_dirs()
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, STATE_FILE)


@contextmanager
def mutate() -> Iterator[dict[str, Any]]:
    """Атомарно прочитать, изменить и сохранить состояние."""
    init_dirs()
    with _thread_lock:
        with STATE_LOCK_FILE.open("a+") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                state = load_state()
                yield state
                save_state(state)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)


@contextmanager
def operation_lock(nonblocking: bool = False) -> Iterator[None]:
    """Блокировка на время сетевых операций с ACME (между процессами)."""
    init_dirs()
    with OPERATION_LOCK_FILE.open("a+") as lock_file:
        flags = fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0)
        try:
            fcntl.flock(lock_file, flags)
        except BlockingIOError as exc:
            raise BusyError("Другая операция с ACME уже выполняется") from exc
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def write_private(path: Path, data: str | bytes) -> None:
    """Записать файл с правами 0600, не оставляя недописанных данных."""
    init_dirs()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    payload = data.encode("utf-8") if isinstance(data, str) else data
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(payload)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def install_certificate(domain: str, fullchain_pem: str, private_key_pem: str) -> None:
    """Установить выпущенный сертификат и ключ в certs/<домен>/."""
    target = CERTS_DIR / domain
    target.mkdir(parents=True, exist_ok=True)
    try:
        target.chmod(0o700)
    except OSError:
        pass
    write_private(target / "privkey.pem", private_key_pem)
    cert_tmp = target / "fullchain.pem.tmp"
    cert_tmp.write_text(fullchain_pem, encoding="utf-8")
    os.chmod(cert_tmp, 0o644)
    os.replace(cert_tmp, target / "fullchain.pem")


def cert_paths(domain: str) -> tuple[Path, Path]:
    return CERTS_DIR / domain / "fullchain.pem", CERTS_DIR / domain / "privkey.pem"


def work_paths(domain: str) -> tuple[Path, Path]:
    return WORK_DIR / domain / "privkey.pem", WORK_DIR / domain / "csr.pem"


def account_key_path(environment: str) -> Path:
    return ACCOUNTS_DIR / environment / "account.key"


def admin_credentials() -> tuple[str, str]:
    """Логин и пароль веб-интерфейса. Пароль генерируется, если не задан."""
    user = (os.environ.get("CERTMGR_USER") or "admin").strip() or "admin"
    password = (os.environ.get("CERTMGR_PASSWORD") or "").strip()
    if password:
        return user, password
    password_file = DATA_DIR / "admin_password"
    try:
        if password_file.is_file():
            saved = password_file.read_text(encoding="utf-8").strip()
            if saved:
                return user, saved
        generated = secrets.token_urlsafe(12)
        write_private(password_file, generated + "\n")
        return user, generated
    except OSError:
        return user, ""


DEFAULT_SMTP: dict[str, Any] = {
    "enabled": False,
    "host": "smtp.mail.ru",
    "port": 465,
    "username": "",
    "password": "",
    "sender": "",
    "use_ssl": True,
    "notify_to": "",
    "public_url": "",
}


def _smtp_from_env() -> dict[str, Any]:
    """Начальные настройки SMTP из окружения (если smtp.json ещё нет)."""
    settings = dict(DEFAULT_SMTP)
    if os.environ.get("SMTP_ENABLED"):
        settings["enabled"] = os.environ["SMTP_ENABLED"].strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if os.environ.get("SMTP_HOST"):
        settings["host"] = os.environ["SMTP_HOST"].strip()
    if os.environ.get("SMTP_PORT"):
        try:
            settings["port"] = int(os.environ["SMTP_PORT"])
        except ValueError:
            pass
    if os.environ.get("SMTP_USER"):
        settings["username"] = os.environ["SMTP_USER"].strip()
        settings["sender"] = settings["username"]
    if os.environ.get("SMTP_PASSWORD"):
        settings["password"] = os.environ["SMTP_PASSWORD"]
    if os.environ.get("SMTP_SENDER"):
        settings["sender"] = os.environ["SMTP_SENDER"].strip()
    if os.environ.get("SMTP_USE_SSL"):
        settings["use_ssl"] = os.environ["SMTP_USE_SSL"].strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
    if os.environ.get("SMTP_NOTIFY_TO"):
        settings["notify_to"] = os.environ["SMTP_NOTIFY_TO"].strip()
    if os.environ.get("SMTP_PUBLIC_URL"):
        settings["public_url"] = os.environ["SMTP_PUBLIC_URL"].strip()
    return settings


def load_smtp() -> dict[str, Any]:
    init_dirs()
    if not SMTP_FILE.exists():
        return _smtp_from_env()
    try:
        with SMTP_FILE.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return _smtp_from_env()
    settings = dict(DEFAULT_SMTP)
    if isinstance(data, dict):
        settings.update({key: data[key] for key in DEFAULT_SMTP if key in data})
    return settings


def save_smtp(settings: dict[str, Any]) -> None:
    init_dirs()
    payload = dict(DEFAULT_SMTP)
    payload.update({key: settings[key] for key in DEFAULT_SMTP if key in settings})
    write_private(
        SMTP_FILE, json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    )


def public_smtp(settings: dict[str, Any] | None = None) -> dict[str, Any]:
    """Настройки для веб-интерфейса: пароль наружу не отдаётся."""
    data = dict(settings if settings is not None else load_smtp())
    password = str(data.pop("password", "") or "")
    data["password_set"] = bool(password)
    return data


def utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()

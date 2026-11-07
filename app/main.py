"""Веб-интерфейс менеджера сертификатов Let's Encrypt."""

from __future__ import annotations

import base64
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from . import acme_service, cron, notifications, storage

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
log = logging.getLogger("certmgr")

BASE_DIR = Path(__file__).resolve().parent
AUTH_USER, AUTH_PASSWORD = storage.admin_credentials()
if not os.environ.get("CERTMGR_PASSWORD"):
    log.warning(
        "CERTMGR_PASSWORD не задан. Сгенерирован пароль: %s (файл %s)",
        AUTH_PASSWORD,
        storage.DATA_DIR / "admin_password",
    )

app = FastAPI(title="Certmgr", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class IssueRequest(BaseModel):
    domain: str
    email: str = ""
    include_wildcard: bool = False
    staging: bool = False


class SmtpRequest(BaseModel):
    enabled: bool = False
    host: str = ""
    port: int = 465
    username: str = ""
    password: str | None = None
    sender: str = ""
    use_ssl: bool = True
    notify_to: str = ""
    public_url: str = ""


class SmtpTestRequest(BaseModel):
    to: str = ""


@app.middleware("http")
async def basic_auth(request: Request, call_next):
    path = request.url.path
    if path == "/health" or path.startswith("/static/") or path == "/favicon.ico":
        return await call_next(request)
    header = request.headers.get("authorization", "")
    allowed = False
    if header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
            user, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            user, password = "", ""
        allowed = secrets.compare_digest(user, AUTH_USER) and secrets.compare_digest(
            password, AUTH_PASSWORD
        )
    if not allowed:
        return Response(
            status_code=401,
            content="Требуется авторизация",
            headers={"WWW-Authenticate": 'Basic realm="certmgr", charset="UTF-8"'},
        )
    return await call_next(request)


@app.on_event("startup")
def startup() -> None:
    storage.init_dirs()
    enabled = cron.sync_cron()
    log.info("Cron продления: %s", "включён" if enabled else "выключен")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    state = storage.load_state()
    return templates.TemplateResponse(
        request,
        "index.html",
        {"default_email": state.get("default_email", "")},
    )


@app.get("/api/state")
def api_state() -> dict[str, Any]:
    state = storage.load_state()
    return {
        "certificates": acme_service.list_certificates(),
        "default_email": state.get("default_email", ""),
        "cron": cron.status(),
        "renew_days": acme_service.renew_days(),
        "smtp": storage.public_smtp(),
        "staging_warning": "Сертификаты staging не считаются доверенными браузерами",
    }


@app.get("/api/smtp")
def api_smtp() -> dict[str, Any]:
    return storage.public_smtp()


@app.put("/api/smtp")
def api_smtp_save(payload: SmtpRequest) -> dict[str, Any]:
    if not 1 <= payload.port <= 65535:
        raise HTTPException(400, "Некорректный порт SMTP")
    settings = storage.load_smtp()
    settings.update(
        {
            "enabled": payload.enabled,
            "host": payload.host.strip(),
            "port": payload.port,
            "username": payload.username.strip(),
            "sender": payload.sender.strip() or payload.username.strip(),
            "use_ssl": payload.use_ssl,
            "notify_to": payload.notify_to.strip(),
            "public_url": payload.public_url.strip(),
        }
    )
    if payload.password:
        settings["password"] = payload.password
    storage.save_smtp(settings)
    return storage.public_smtp(settings)


@app.post("/api/smtp/test")
def api_smtp_test(payload: SmtpTestRequest) -> dict[str, str]:
    settings = storage.load_smtp()
    to = payload.to.strip() or str(settings.get("notify_to") or "") or str(
        settings.get("username") or ""
    )
    if not to or "@" not in to:
        raise HTTPException(400, "Укажите email для тестового письма")
    try:
        notifications.send_test(to)
    except Exception as exc:  # noqa: BLE001 — показываем причину в интерфейсе
        raise HTTPException(400, f"Не удалось отправить письмо: {exc}") from exc
    return {"status": "sent", "to": to}


@app.post("/api/issue")
def api_issue(payload: IssueRequest) -> dict[str, Any]:
    try:
        certificate = acme_service.start_order(
            domain=payload.domain,
            email=payload.email,
            include_wildcard=payload.include_wildcard,
            staging=payload.staging,
        )
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"certificate": certificate}


@app.post("/api/certs/{domain}/check")
def api_check(domain: str) -> dict[str, Any]:
    try:
        normalized, _ = acme_service.normalize_domain(domain)
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    certificate = acme_service.get_certificate(normalized)
    if not certificate:
        raise HTTPException(404, "Сертификат не найден")
    report = acme_service.check_dns(certificate.get("challenges") or [])
    return report


@app.post("/api/certs/{domain}/verify")
def api_verify(domain: str) -> dict[str, Any]:
    try:
        return acme_service.request_issue(domain)
    except acme_service.DnsCheckError as exc:
        return JSONResponse(
            status_code=409,
            content={"detail": str(exc), "report": exc.report},
        )
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    except storage.BusyError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.post("/api/certs/{domain}/renew")
def api_renew(domain: str) -> dict[str, Any]:
    try:
        normalized, _ = acme_service.normalize_domain(domain)
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    certificate = acme_service.get_certificate(normalized)
    if not certificate:
        raise HTTPException(404, "Сертификат не найден")
    try:
        updated = acme_service.start_order(
            domain=normalized,
            email=certificate.get("email") or "",
            include_wildcard=bool(certificate.get("include_wildcard")),
            staging=bool(certificate.get("staging")),
            renewal=True,
        )
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"certificate": updated}


@app.delete("/api/certs/{domain}")
def api_delete(domain: str) -> dict[str, str]:
    try:
        acme_service.delete_certificate(domain)
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {"status": "deleted"}


@app.get("/api/certs/{domain}/download/{kind}")
def api_download(domain: str, kind: str):
    try:
        normalized, _ = acme_service.normalize_domain(domain)
    except acme_service.AcmeError as exc:
        raise HTTPException(400, str(exc)) from exc
    cert_file, key_file = storage.cert_paths(normalized)
    if kind == "fullchain" and cert_file.is_file():
        return FileResponse(cert_file, media_type="application/x-pem-file", filename="fullchain.pem")
    if kind == "privkey" and key_file.is_file():
        return FileResponse(key_file, media_type="application/x-pem-file", filename="privkey.pem")
    raise HTTPException(404, "Файл не найден")

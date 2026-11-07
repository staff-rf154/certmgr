"""Работа с Let's Encrypt по протоколу ACME (DNS-01, ручные TXT-записи).

Сценарий выпуска состоит из двух шагов:
1. start_order создаёт заказ и возвращает TXT-записи, которые нужно добавить в DNS;
2. complete_order проверяет, что записи видны в DNS, отвечает на challenge
   и забирает готовый сертификат.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import re
import threading
from typing import Any

import dns.exception
import dns.resolver
import josepy as jose
from acme import challenges, client, crypto_util, messages
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import notifications, storage

log = logging.getLogger("certmgr.acme")

PRODUCTION = "production"
STAGING = "staging"

DIRECTORIES = {
    PRODUCTION: os.environ.get(
        "ACME_DIRECTORY_PRODUCTION",
        "https://acme-v02.api.letsencrypt.org/directory",
    ),
    STAGING: os.environ.get(
        "ACME_DIRECTORY_STAGING",
        "https://acme-staging-v02.api.letsencrypt.org/directory",
    ),
}

USER_AGENT = "certmgr/1.0"
PUBLIC_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


class AcmeError(RuntimeError):
    """Ошибка выпуска или проверки сертификата."""


class DnsCheckError(AcmeError):
    """TXT-записи ещё не видны в DNS."""

    def __init__(self, message: str, report: dict[str, Any]) -> None:
        super().__init__(message)
        self.report = report


def renew_days() -> int:
    try:
        return max(1, int(os.environ.get("RENEW_DAYS", "30")))
    except ValueError:
        return 30


def poll_seconds() -> int:
    try:
        return max(30, int(os.environ.get("ACME_POLL_SECONDS", "180")))
    except ValueError:
        return 180


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def normalize_domain(raw: str) -> tuple[str, bool]:
    """Привести домен к ASCII и определить, запрошен ли wildcard."""
    value = (raw or "").strip().lower().rstrip(".")
    wildcard = value.startswith("*.")
    if wildcard:
        value = value[2:]
    if not value:
        raise AcmeError("Укажите домен")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise AcmeError("Некорректный домен") from exc
    for label in value.split("."):
        if not label or label.startswith("-") or label.endswith("-"):
            raise AcmeError("Некорректный домен")
    if not DOMAIN_RE.fullmatch(value):
        raise AcmeError("Некорректный домен")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise AcmeError("IP-адрес не поддерживается, укажите домен")
    return value, wildcard


def _load_account(environment: str) -> dict[str, Any] | None:
    state = storage.load_state()
    account = state.get("accounts", {}).get(environment)
    key_path = storage.account_key_path(environment)
    if not account or not key_path.is_file():
        return None
    return account


def get_client(environment: str, email: str) -> tuple[client.ClientV2, jose.JWKRSA]:
    """Вернуть ACME-клиент, при необходимости зарегистрировав аккаунт."""
    directory_url = DIRECTORIES[environment]
    account = _load_account(environment)
    key_path = storage.account_key_path(environment)

    if account:
        key_pem = key_path.read_bytes()
        account_key = serialization.load_pem_private_key(key_pem, password=None)
        jwk = jose.JWKRSA(key=account_key)
        regr = messages.RegistrationResource(
            body=messages.Registration.from_json(account["body"]),
            uri=account["uri"],
        )
        net = client.ClientNetwork(jwk, account=regr, user_agent=USER_AGENT)
        directory = messages.Directory.from_json(net.get(directory_url).json())
        acme_client = client.ClientV2(directory, net=net)
        if email and account.get("email") != email:
            try:
                updated = acme_client.update_registration(
                    regr, messages.Registration.from_data(email=email)
                )
                with storage.mutate() as state:
                    saved = state.setdefault("accounts", {}).setdefault(environment, {})
                    saved["body"] = updated.body.to_json()
                    saved["email"] = email
                    saved["updated_at"] = storage.utcnow()
            except Exception as exc:  # noqa: BLE001 — обновление email не критично
                log.warning("Не удалось обновить email ACME-аккаунта: %s", exc)
        return acme_client, jwk

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = jose.JWKRSA(key=private_key)
    net = client.ClientNetwork(jwk, user_agent=USER_AGENT)
    directory = messages.Directory.from_json(net.get(directory_url).json())
    acme_client = client.ClientV2(directory, net=net)
    registration = acme_client.new_account(
        messages.NewRegistration.from_data(
            email=email or None, terms_of_service_agreed=True
        )
    )
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    storage.write_private(key_path, key_pem)
    with storage.mutate() as state:
        state.setdefault("accounts", {})[environment] = {
            "uri": registration.uri,
            "body": registration.body.to_json(),
            "email": email,
            "created_at": storage.utcnow(),
        }
    log.info("Зарегистрирован новый ACME-аккаунт (%s)", environment)
    return acme_client, jwk


def _challenge_record(identifier: str) -> str:
    value = identifier[2:] if identifier.startswith("*.") else identifier
    return f"_acme-challenge.{value}"


def _new_certificate_key() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _public_certificate(entry: dict[str, Any]) -> dict[str, Any]:
    domain = entry.get("domain", "")
    cert_file, key_file = storage.cert_paths(domain) if domain else (None, None)
    result = {
        "domain": domain,
        "has_files": bool(cert_file and key_file and cert_file.is_file() and key_file.is_file()),
        "include_wildcard": bool(entry.get("include_wildcard")),
        "email": entry.get("email", ""),
        "staging": bool(entry.get("staging")),
        "status": entry.get("status", ""),
        "status_message": entry.get("status_message", ""),
        "challenges": entry.get("challenges", []),
        "issued_at": entry.get("issued_at"),
        "expires_at": entry.get("expires_at"),
        "created_at": entry.get("created_at"),
        "updated_at": entry.get("updated_at"),
        "last_error": entry.get("last_error", ""),
        "renewal": bool(entry.get("renewal")),
        "days_left": days_left(entry.get("expires_at")),
    }
    return result


def days_left(expires_at: str | None) -> int | None:
    if not expires_at:
        return None
    try:
        expires = dt.datetime.fromisoformat(expires_at)
    except ValueError:
        return None
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=dt.timezone.utc)
    return (expires - utcnow()).days


def certificate_expiry(fullchain_pem: str) -> str:
    certificate = x509.load_pem_x509_certificate(fullchain_pem.encode("utf-8"))
    expires = getattr(certificate, "not_valid_after_utc", None)
    if expires is None:  # запас для старых версий cryptography
        expires = certificate.not_valid_after.replace(tzinfo=dt.timezone.utc)
    return expires.isoformat()


def start_order(
    domain: str,
    email: str,
    include_wildcard: bool,
    staging: bool,
    renewal: bool = False,
) -> dict[str, Any]:
    """Создать ACME-заказ и вернуть TXT-записи для добавления в DNS."""
    domain, wildcard_from_input = normalize_domain(domain)
    wildcard = bool(include_wildcard or wildcard_from_input)
    environment = STAGING if staging else PRODUCTION
    email = (email or "").strip()
    if not email:
        email = str(storage.load_state().get("default_email") or "")
    if not email or "@" not in email:
        raise AcmeError("Укажите корректный email")

    now = storage.utcnow()
    with storage.mutate() as state:
        entry = state["certificates"].get(domain, {})
        entry.update(
            {
                "domain": domain,
                "include_wildcard": wildcard,
                "email": email,
                "staging": staging,
                "status": "creating",
                "status_message": "Создаём запрос в Let's Encrypt",
                "last_error": "",
                "challenges": [],
                "created_at": entry.get("created_at") or now,
                "updated_at": now,
            }
        )
        state["certificates"][domain] = entry
        state["default_email"] = email

    try:
        with storage.operation_lock():
            acme_client, jwk = get_client(environment, email)

            private_key_pem = _new_certificate_key()
            names = [domain] + ([f"*.{domain}"] if wildcard else [])
            csr_pem = crypto_util.make_csr(private_key_pem, names)

            key_path, csr_path = storage.work_paths(domain)
            storage.write_private(key_path, private_key_pem)
            storage.write_private(csr_path, csr_pem)

            order = acme_client.new_order(csr_pem)
            challenges_out: list[dict[str, Any]] = []
            for authorization in order.authorizations:
                body = authorization.body
                if body.status == messages.STATUS_VALID:
                    continue
                dns01 = next(
                    (c for c in body.challenges if isinstance(c.chall, challenges.DNS01)),
                    None,
                )
                if dns01 is None:
                    raise AcmeError("Let's Encrypt не предложил DNS-01 challenge")
                _, value = dns01.chall.response_and_validation(jwk)
                challenges_out.append(
                    {
                        "identifier": body.identifier.value,
                        "record": _challenge_record(body.identifier.value),
                        "value": value,
                        "authz_uri": authorization.uri,
                        "challenge_uri": dns01.uri,
                    }
                )

        order_expires = getattr(order.body, "expires", None)
        if challenges_out:
            status_message = "Добавьте TXT-записи в DNS и нажмите «Проверить и выпустить»"
        else:
            status_message = (
                "Все авторизации уже подтверждены. Нажмите «Проверить и выпустить»."
            )
        with storage.mutate() as state:
            entry = state["certificates"][domain]
            entry.update(
                {
                    "status": "pending_dns",
                    "status_message": status_message,
                    "challenges": challenges_out,
                    "order_uri": order.uri,
                    "order_expires_at": order_expires.isoformat() if order_expires else None,
                    "last_error": "",
                    "renewal": bool(renewal),
                    "updated_at": storage.utcnow(),
                }
            )
            certificate = _public_certificate(entry)
        notifications.notify_action_required(certificate)
        return certificate
    except Exception as exc:  # noqa: BLE001 — ошибку показываем в интерфейсе
        log.exception("Не удалось создать заказ для %s", domain)
        with storage.mutate() as state:
            entry = state["certificates"].setdefault(domain, {"domain": domain})
            entry.update(
                {
                    "status": "error",
                    "status_message": "Не удалось создать запрос",
                    "last_error": str(exc),
                    "updated_at": storage.utcnow(),
                }
            )
            error_entry = _public_certificate(entry)
        notifications.notify_error(error_entry, str(exc))
        if isinstance(exc, AcmeError):
            raise
        raise AcmeError(str(exc)) from exc


def _txt_values(nameservers: list[str] | None, name: str, timeout: float = 5.0) -> set[str]:
    resolver = dns.resolver.Resolver(configure=not nameservers)
    if nameservers:
        resolver.nameservers = list(nameservers)
        resolver.lifetime = timeout
        resolver.timeout = max(1.0, timeout / 2)
    values: set[str] = set()
    try:
        answer = resolver.resolve(name, "TXT", lifetime=timeout)
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return values
    except Exception:  # noqa: BLE001 — сбой DNS не должен ломать проверку
        return values
    for record in answer:
        strings = getattr(record, "strings", None)
        if strings is not None:
            values.add(b"".join(strings).decode("utf-8", "replace"))
        else:
            values.add(str(record).strip('"'))
    return values


def _authoritative_nameservers(name: str) -> list[str]:
    labels = name.rstrip(".").split(".")
    for index in range(len(labels) - 1):
        zone = ".".join(labels[index:])
        try:
            answer = dns.resolver.resolve(zone, "NS", lifetime=4)
        except Exception:  # noqa: BLE001
            continue
        addresses: list[str] = []
        for record in answer:
            host = str(record.target).rstrip(".")
            for record_type in ("A", "AAAA"):
                try:
                    for address in dns.resolver.resolve(host, record_type, lifetime=4):
                        value = str(address)
                        if value not in addresses:
                            addresses.append(value)
                except Exception:  # noqa: BLE001
                    continue
        if addresses:
            return addresses
    return []


def check_dns(challenges_list: list[dict[str, Any]]) -> dict[str, Any]:
    """Проверить наличие всех ожидаемых TXT-записей в DNS."""
    grouped: dict[str, set[str]] = {}
    for item in challenges_list:
        record = str(item.get("record") or "")
        value = str(item.get("value") or "")
        if record and value:
            grouped.setdefault(record, set()).add(value)

    report: dict[str, Any] = {"ok": True, "records": []}
    for record, expected in grouped.items():
        found: set[str] = set()
        sources: list[str] = []
        authoritative = _authoritative_nameservers(record)
        checks: list[tuple[str, list[str] | None]] = []
        if authoritative:
            checks.append(("authoritative", authoritative))
        checks.append(("public", PUBLIC_RESOLVERS))
        checks.append(("system", None))
        for source, nameservers in checks:
            values = _txt_values(nameservers, record)
            if values:
                sources.append(source)
            found |= values
            if expected <= found:
                break
        missing = expected - found
        report["records"].append(
            {
                "record": record,
                "expected": sorted(expected),
                "found": sorted(found),
                "missing": sorted(missing),
                "sources": sources,
            }
        )
        if missing:
            report["ok"] = False
    return report


def _fetch_order(acme_client: client.ClientV2, order_uri: str, csr_pem: bytes) -> messages.OrderResource:
    response = acme_client._post_as_get(order_uri)  # noqa: SLF001 — публичного API нет
    body = messages.Order.from_json(response.json())
    authorizations = []
    for url in body.authorizations:
        authz_response = acme_client._post_as_get(url)  # noqa: SLF001
        authorizations.append(
            messages.AuthorizationResource(
                body=messages.Authorization.from_json(authz_response.json()),
                uri=url,
            )
        )
    return messages.OrderResource(
        body=body, uri=order_uri, authorizations=authorizations, csr_pem=csr_pem
    )


def _complete_order(domain: str) -> None:
    state = storage.load_state()
    entry = state["certificates"].get(domain)
    if not entry:
        raise AcmeError("Запрос для домена не найден")
    order_uri = entry.get("order_uri")
    if not order_uri:
        raise AcmeError("Заказ Let's Encrypt не найден, создайте запрос заново")

    environment = STAGING if entry.get("staging") else PRODUCTION
    email = str(entry.get("email") or state.get("default_email") or "")
    acme_client, jwk = get_client(environment, email)

    key_path, csr_path = storage.work_paths(domain)
    if not csr_path.is_file() or not key_path.is_file():
        raise AcmeError("Файлы запроса утеряны, создайте запрос заново")
    csr_pem = csr_path.read_bytes()
    private_key_pem = key_path.read_text(encoding="utf-8")

    order = _fetch_order(acme_client, order_uri, csr_pem)
    answered = 0
    for authorization in order.authorizations:
        body = authorization.body
        if body.status == messages.STATUS_VALID:
            continue
        dns01 = next(
            (c for c in body.challenges if isinstance(c.chall, challenges.DNS01)), None
        )
        if dns01 is None:
            raise AcmeError("В заказе нет DNS-01 challenge")
        response, _ = dns01.chall.response_and_validation(jwk)
        acme_client.answer_challenge(dns01, response)
        answered += 1
    log.info("Отправлено ответов на challenge для %s: %s", domain, answered)

    # acme сравнивает deadline с наивным datetime.now(), поэтому передаём UTC без tzinfo.
    deadline = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None) + dt.timedelta(
        seconds=poll_seconds()
    )
    finished = acme_client.poll_and_finalize(order, deadline)
    fullchain_pem = finished.fullchain_pem
    if not fullchain_pem:
        raise AcmeError("Let's Encrypt не вернул сертификат")

    expiry = certificate_expiry(fullchain_pem)
    storage.install_certificate(domain, fullchain_pem, private_key_pem)

    with storage.mutate() as fresh:
        current = fresh["certificates"].get(domain, {})
        current.update(
            {
                "status": "issued",
                "status_message": "Сертификат выпущен",
                "challenges": [],
                "order_uri": None,
                "order_expires_at": None,
                "issued_at": storage.utcnow(),
                "expires_at": expiry,
                "last_error": "",
                "renewal": False,
                "updated_at": storage.utcnow(),
            }
        )
        fresh["certificates"][domain] = current
        issued_entry = _public_certificate(current)
    log.info("Сертификат для %s выпущен, действует до %s", domain, expiry)
    notifications.notify_issued(issued_entry)

    try:
        from . import cron

        cron.sync_cron()
    except Exception as exc:  # noqa: BLE001
        log.warning("Не удалось обновить задание cron: %s", exc)


def request_issue(domain: str) -> dict[str, Any]:
    """Проверить DNS и запустить выпуск в фоне."""
    domain, _ = normalize_domain(domain)
    state = storage.load_state()
    entry = state["certificates"].get(domain)
    if not entry:
        raise AcmeError("Сначала создайте запрос для домена")
    if entry.get("status") not in {"pending_dns", "error"}:
        raise AcmeError("Для этого домена выпуск уже выполняется или завершён")
    challenges_list = entry.get("challenges") or []
    report = check_dns(challenges_list)
    if not report["ok"]:
        missing = []
        for item in report["records"]:
            if item["missing"]:
                missing.append(f"{item['record']} ({len(item['missing'])} знач.)")
        raise DnsCheckError(
            "TXT-записи ещё не видны в DNS: " + ", ".join(missing), report
        )

    with storage.mutate() as fresh:
        current = fresh["certificates"].get(domain)
        if not current:
            raise AcmeError("Запрос для домена не найден")
        if current.get("status") not in {"pending_dns", "error"}:
            raise AcmeError("Выпуск уже выполняется")
        current.update(
            {
                "status": "issuing",
                "status_message": "Проверяем DNS и выпускаем сертификат",
                "updated_at": storage.utcnow(),
            }
        )

    thread = threading.Thread(
        target=_run_complete, args=(domain,), name=f"issue-{domain}", daemon=True
    )
    thread.start()
    return {
        "domain": domain,
        "status": "issuing",
        "message": "Проверка запущена, это может занять до нескольких минут",
    }


def _run_complete(domain: str) -> None:
    try:
        with storage.operation_lock():
            _complete_order(domain)
    except storage.BusyError:
        _mark_error(domain, "Другая операция с ACME уже выполняется, попробуйте позже")
    except Exception as exc:  # noqa: BLE001 — ошибка показывается в интерфейсе
        log.exception("Ошибка выпуска сертификата для %s", domain)
        _mark_error(domain, str(exc))


def _mark_error(domain: str, message: str) -> None:
    error_entry: dict[str, Any] | None = None
    with storage.mutate() as state:
        entry = state["certificates"].get(domain)
        if entry:
            entry.update(
                {
                    "status": "error",
                    "status_message": "Не удалось выпустить сертификат",
                    "last_error": message,
                    "updated_at": storage.utcnow(),
                }
            )
            error_entry = _public_certificate(entry)
    if error_entry:
        notifications.notify_error(error_entry, message)


def list_certificates() -> list[dict[str, Any]]:
    state = storage.load_state()
    result = [_public_certificate(entry) for entry in state["certificates"].values()]
    result.sort(key=lambda item: item.get("domain", ""))
    return result


def get_certificate(domain: str) -> dict[str, Any] | None:
    state = storage.load_state()
    entry = state["certificates"].get(domain)
    return _public_certificate(entry) if entry else None


def delete_certificate(domain: str) -> None:
    domain, _ = normalize_domain(domain)
    with storage.mutate() as state:
        state["certificates"].pop(domain, None)
    for path in (storage.CERTS_DIR / domain, storage.WORK_DIR / domain):
        if path.is_dir():
            import shutil

            shutil.rmtree(path, ignore_errors=True)
    try:
        from . import cron

        cron.sync_cron()
    except Exception:  # noqa: BLE001
        pass
